mod capture;
mod parser;

use crate::error::RpcError;
use crate::types::{ErrorSeverity, ErrorTag, RpcErrorType};

/// A parsed NETCONF `<rpc-reply>` response.
#[derive(Debug)]
pub enum RpcReply {
    /// Success with data (from `<get>`, `<get-config>`).
    Data(String),
    /// Success with data, but the device also returned warnings.
    DataWithWarnings(String, Vec<RpcErrorInfo>),
    /// Success with no data (`<ok/>`).
    Ok,
    /// Success (`<ok/>`), but the device also returned warnings.
    OkWithWarnings(Vec<RpcErrorInfo>),
}

/// A fully parsed `<rpc-error>` from the device.
#[derive(Debug, Clone)]
pub struct RpcErrorInfo {
    pub error_type: Option<RpcErrorType>,
    pub tag: ErrorTag,
    pub severity: Option<ErrorSeverity>,
    pub app_tag: Option<String>,
    pub path: Option<String>,
    pub message: String,
    pub info: Option<String>,
}

// Strip any namespace prefix from a qualified element name, returning the
// bare local name (e.g. `nc:rpc-reply` -> `rpc-reply`).
fn local_name_of(qname: &[u8]) -> &[u8] {
    match qname.iter().position(|&byte| byte == b':') {
        Some(colon_idx) => &qname[colon_idx + 1..],
        None => qname,
    }
}

// Repair malformed chassis-cluster replies with unclosed <routing-engine> tags.
//
// Junos chassis clusters return validate/commit-check responses where each
// routing-engine block is opened but never closed. Use quick-xml in tolerant
// mode to auto-close them before the parent closes.
fn repair_unclosed_routing_engine(xml: &str) -> Option<String> {
    use quick_xml::events::{BytesEnd, Event};
    use quick_xml::Reader;
    use quick_xml::Writer;

    let mut reader = Reader::from_str(xml);
    reader.config_mut().check_end_names = false; // tolerant mode

    let mut writer = Writer::new(Vec::new());
    // Stack of open element qualified names (as bytes).
    let mut stack: Vec<Vec<u8>> = Vec::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref tag)) => {
                let tag_name = tag.name();
                let local_name = tag_name.local_name();

                // If we're opening a routing-engine and the top of the stack is
                // also routing-engine, auto-close the previous sibling.
                if local_name.as_ref() == b"routing-engine" {
                    if let Some(top_qname) = stack.last() {
                        if local_name_of(top_qname) == b"routing-engine" {
                            // Close the previous routing-engine
                            if writer
                                .write_event(Event::End(BytesEnd::new(
                                    std::str::from_utf8(top_qname).unwrap_or("routing-engine"),
                                )))
                                .is_err()
                            {
                                return None;
                            }
                            stack.pop();
                        }
                    }
                }

                // Push this tag's qualified name onto the stack.
                stack.push(tag_name.as_ref().to_vec());

                // Emit the Start event verbatim.
                if writer.write_event(Event::Start(tag.clone())).is_err() {
                    return None;
                }
            }
            Ok(Event::End(ref tag)) => {
                let tag_name = tag.name();
                let local_name = tag_name.local_name();

                // Close any dangling routing-engine elements before closing parent.
                while let Some(top_qname) = stack.last() {
                    let top_local = local_name_of(top_qname);

                    // If stack top doesn't match this End tag's local name, and
                    // the stack top is routing-engine, auto-close it.
                    if top_local != local_name.as_ref() && top_local == b"routing-engine" {
                        if writer
                            .write_event(Event::End(BytesEnd::new(
                                std::str::from_utf8(top_qname).unwrap_or("routing-engine"),
                            )))
                            .is_err()
                        {
                            return None;
                        }
                        stack.pop();
                    } else {
                        break;
                    }
                }

                // Now the stack top should match this End tag.
                let top_qname = stack.last()?;
                if local_name_of(top_qname) == local_name.as_ref() {
                    stack.pop();
                    if writer.write_event(Event::End(tag.clone())).is_err() {
                        return None;
                    }
                } else {
                    // Unexpected end tag — refuse to repair.
                    return None;
                }
            }
            Ok(Event::Empty(ref tag)) => {
                if writer.write_event(Event::Empty(tag.clone())).is_err() {
                    return None;
                }
            }
            Ok(Event::Text(ref text)) => {
                if writer.write_event(Event::Text(text.clone())).is_err() {
                    return None;
                }
            }
            Ok(Event::CData(ref cdata)) => {
                if writer.write_event(Event::CData(cdata.clone())).is_err() {
                    return None;
                }
            }
            Ok(Event::GeneralRef(ref entity)) => {
                if writer
                    .write_event(Event::GeneralRef(entity.clone()))
                    .is_err()
                {
                    return None;
                }
            }
            Ok(Event::Comment(ref comment)) => {
                if writer.write_event(Event::Comment(comment.clone())).is_err() {
                    return None;
                }
            }
            Ok(Event::Decl(ref decl)) => {
                if writer.write_event(Event::Decl(decl.clone())).is_err() {
                    return None;
                }
            }
            Ok(Event::PI(ref pi)) => {
                if writer.write_event(Event::PI(pi.clone())).is_err() {
                    return None;
                }
            }
            Ok(Event::DocType(ref doctype)) => {
                if writer.write_event(Event::DocType(doctype.clone())).is_err() {
                    return None;
                }
            }
            Ok(Event::Eof) => {
                // A legitimate cluster repair balances fully: the real device
                // reply still contains `</rpc-reply>`, so only the dangling
                // `<routing-engine>` elements are ever synthesized (in the End
                // handling above). If any element is still open at EOF, the
                // reply was genuinely truncated — refuse to repair so the caller
                // sees the original parse error rather than a fabricated
                // success from force-closing whatever was left open.
                if !stack.is_empty() {
                    return None;
                }
                break;
            }
            Err(_) => return None,
        }
    }

    String::from_utf8(writer.into_inner()).ok()
}

/// Parse an `<rpc-reply>` XML response.
///
/// Returns `Ok(RpcReply)` for successful responses, or `Err(RpcError)` if
/// the reply contains `<rpc-error>` elements.
///
/// This parser normally requires well-formed XML. On Junos chassis clusters,
/// validate/commit-check replies contain unclosed `<routing-engine>` elements
/// (a device bug). If the strict parse fails with a parse error and the reply
/// contains `routing-engine`, the parser attempts to repair the malformed XML
/// by auto-closing the dangling elements, then re-parses. Well-formed replies
/// are unaffected (no repair attempt unless strict parsing fails).
pub fn parse_rpc_reply(xml: &str, expected_message_id: &str) -> Result<RpcReply, RpcError> {
    // Try strict parse first (the common well-formed path).
    match parser::parse_strict(xml, expected_message_id) {
        Ok(reply) => Ok(reply),
        Err(RpcError::ParseError(ref e)) if xml.contains("routing-engine") => {
            // Looks like a chassis-cluster reply with unclosed routing-engine.
            // Attempt repair.
            if let Some(repaired) = repair_unclosed_routing_engine(xml) {
                // Re-parse the repaired XML.
                parser::parse_strict(&repaired, expected_message_id)
            } else {
                // Repair failed; return the original parse error.
                Err(RpcError::ParseError(e.clone()))
            }
        }
        Err(other) => Err(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::validate_xml_fragment;

    #[test]
    fn test_parse_ok_reply() {
        let xml = r#"<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1">
  <ok/>
</rpc-reply>"#;
        let result = parse_rpc_reply(xml, "1").unwrap();
        assert!(matches!(result, RpcReply::Ok));
    }

    #[test]
    fn test_parse_data_reply() {
        let xml = r#"<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="2">
  <data>
    <configuration><interfaces><interface><name>ge-0/0/0</name></interface></interfaces></configuration>
  </data>
</rpc-reply>"#;
        let result = parse_rpc_reply(xml, "2").unwrap();
        match result {
            RpcReply::Data(data) => {
                assert!(data.contains("ge-0/0/0"));
                assert!(data.contains("<configuration>"));
            }
            _ => panic!("expected Data reply"),
        }
    }

    #[test]
    fn test_parse_rpc_error() {
        let xml = r#"<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="3">
  <rpc-error>
    <error-type>application</error-type>
    <error-tag>invalid-value</error-tag>
    <error-severity>error</error-severity>
    <error-path>/configuration/interfaces/interface[name='ge-0/0/0']</error-path>
    <error-message>invalid interface name</error-message>
  </rpc-error>
</rpc-reply>"#;
        let err = parse_rpc_reply(xml, "3").unwrap_err();
        match err {
            RpcError::ServerError {
                tag, message, path, ..
            } => {
                assert_eq!(tag, ErrorTag::InvalidValue);
                assert_eq!(message, "invalid interface name");
                assert!(path.unwrap().contains("ge-0/0/0"));
            }
            _ => panic!("expected ServerError, got {err:?}"),
        }
    }

    #[test]
    fn test_parse_message_id_mismatch() {
        let xml = r#"<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="99">
  <ok/>
</rpc-reply>"#;
        let err = parse_rpc_reply(xml, "1").unwrap_err();
        assert!(matches!(err, RpcError::MessageIdMismatch { .. }));
    }

    #[test]
    fn test_parse_lock_denied_error() {
        let xml = r#"<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="5">
  <rpc-error>
    <error-type>protocol</error-type>
    <error-tag>lock-denied</error-tag>
    <error-severity>error</error-severity>
    <error-message>Lock failed, lock is already held</error-message>
    <error-info>session-id: 42</error-info>
  </rpc-error>
</rpc-reply>"#;
        let err = parse_rpc_reply(xml, "5").unwrap_err();
        match err {
            RpcError::ServerError {
                tag, info, message, ..
            } => {
                assert_eq!(tag, ErrorTag::LockDenied);
                assert!(message.contains("Lock failed"));
                assert!(info.unwrap().contains("42"));
            }
            _ => panic!("expected ServerError"),
        }
    }

    #[test]
    fn test_parse_junos_custom_rpc_reply() {
        let xml = r#"<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="7">
  <software-information>
    <host-name>vsrx1</host-name>
    <product-model>vSRX</product-model>
    <product-name>vsrx</product-name>
    <junos-version>21.4R3.15</junos-version>
  </software-information>
</rpc-reply>"#;
        let result = parse_rpc_reply(xml, "7").unwrap();
        match result {
            RpcReply::Data(data) => {
                assert!(data.contains("<software-information>"));
                assert!(data.contains("vsrx1"));
                assert!(data.contains("21.4R3.15"));
            }
            _ => panic!("expected Data reply for Junos custom RPC"),
        }
    }

    #[test]
    fn test_parse_junos_multi_re_reply() {
        let xml = r#"<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="8">
  <multi-routing-engine-results>
    <multi-routing-engine-item>
      <re-name>node0</re-name>
      <software-information>
        <host-name>vsrx-node0</host-name>
      </software-information>
    </multi-routing-engine-item>
  </multi-routing-engine-results>
</rpc-reply>"#;
        let result = parse_rpc_reply(xml, "8").unwrap();
        match result {
            RpcReply::Data(data) => {
                assert!(data.contains("<multi-routing-engine-results>"));
                assert!(data.contains("node0"));
            }
            _ => panic!("expected Data reply for multi-RE response"),
        }
    }

    #[test]
    fn test_parse_warning_with_ok() {
        let xml = r#"<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="10">
  <rpc-error>
    <error-type>application</error-type>
    <error-tag>operation-failed</error-tag>
    <error-severity>warning</error-severity>
    <error-message>statement not found</error-message>
  </rpc-error>
  <ok/>
</rpc-reply>"#;
        let result = parse_rpc_reply(xml, "10").unwrap();
        match result {
            RpcReply::OkWithWarnings(warnings) => {
                assert_eq!(warnings.len(), 1);
                assert_eq!(warnings[0].severity, Some(ErrorSeverity::Warning));
                assert!(warnings[0].message.contains("statement not found"));
            }
            _ => panic!("expected OkWithWarnings, got {result:?}"),
        }
    }

    #[test]
    fn test_parse_warning_with_data() {
        let xml = r#"<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="11">
  <rpc-error>
    <error-type>application</error-type>
    <error-tag>operation-failed</error-tag>
    <error-severity>warning</error-severity>
    <error-message>some warning</error-message>
  </rpc-error>
  <data><configuration><system/></configuration></data>
</rpc-reply>"#;
        let result = parse_rpc_reply(xml, "11").unwrap();
        match result {
            RpcReply::DataWithWarnings(data, warnings) => {
                assert!(data.contains("<configuration>"));
                assert_eq!(warnings.len(), 1);
                assert!(warnings[0].message.contains("some warning"));
            }
            _ => panic!("expected DataWithWarnings, got {result:?}"),
        }
    }

    #[test]
    fn test_parse_mixed_warning_and_error() {
        let xml = r#"<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="12">
  <rpc-error>
    <error-type>application</error-type>
    <error-tag>operation-failed</error-tag>
    <error-severity>warning</error-severity>
    <error-message>just a warning</error-message>
  </rpc-error>
  <rpc-error>
    <error-type>application</error-type>
    <error-tag>invalid-value</error-tag>
    <error-severity>error</error-severity>
    <error-message>real error</error-message>
  </rpc-error>
</rpc-reply>"#;
        let err = parse_rpc_reply(xml, "12").unwrap_err();
        match err {
            RpcError::ServerError { tag, message, .. } => {
                assert_eq!(tag, ErrorTag::InvalidValue);
                assert_eq!(message, "real error");
            }
            _ => panic!("expected ServerError for hard error, got {err:?}"),
        }
    }

    #[test]
    fn test_parse_empty_rpc_reply_returns_ok() {
        let xml = r#"<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="42">
</rpc-reply>"#;
        let result = parse_rpc_reply(xml, "42").unwrap();
        assert!(matches!(result, RpcReply::Ok));
    }

    #[test]
    fn test_reconstructed_data_reescapes_special_chars() {
        // A device returns text containing XML special characters (encoded on
        // the wire). The reconstructed `data` must re-escape them so the result
        // is itself well-formed XML, not a corrupted string.
        let xml = r#"<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1">
  <data><description>a &amp; b &lt; c</description></data>
</rpc-reply>"#;
        let result = parse_rpc_reply(xml, "1").unwrap();
        let data = match result {
            RpcReply::Data(data) => data,
            other => panic!("expected Data, got {other:?}"),
        };
        // The raw `&` / `<` must NOT appear unescaped in element text.
        assert!(
            data.contains("a &amp; b &lt; c"),
            "special chars must be re-escaped: {data}"
        );
        // The reconstructed fragment must re-parse as well-formed XML.
        validate_xml_fragment(&data).expect("reconstructed data must be well-formed");
    }

    #[test]
    fn test_reconstructed_junos_inner_reescapes_special_chars() {
        // Same guarantee for the Junos custom-RPC path (no <data> wrapper).
        let xml = r#"<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="2">
  <output>value with &amp; ampersand</output>
</rpc-reply>"#;
        let result = parse_rpc_reply(xml, "2").unwrap();
        let data = match result {
            RpcReply::Data(data) => data,
            other => panic!("expected Data, got {other:?}"),
        };
        assert!(
            data.contains("&amp;"),
            "ampersand must stay escaped: {data}"
        );
        validate_xml_fragment(&data).expect("reconstructed inner content must be well-formed");
    }

    #[test]
    fn test_error_message_with_entities_is_fully_decoded() {
        // Junos error messages routinely contain <, >, & (e.g. quoting config
        // syntax). The decoded message must contain the full text, not a
        // truncated fragment around the entity.
        let xml = r#"<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="5">
  <rpc-error>
    <error-type>protocol</error-type>
    <error-tag>operation-failed</error-tag>
    <error-severity>error</error-severity>
    <error-message>syntax error before &lt;get&gt; &amp; after</error-message>
  </rpc-error>
</rpc-reply>"#;
        let err = parse_rpc_reply(xml, "5").unwrap_err();
        match err {
            RpcError::ServerError { message, .. } => {
                assert_eq!(message, "syntax error before <get> & after");
            }
            other => panic!("expected ServerError, got {other:?}"),
        }
    }

    #[test]
    fn test_data_text_with_char_ref_roundtrips() {
        // Numeric character references must survive data reconstruction.
        let xml = r#"<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="6">
  <data><description>A &#38; B &#x3C; C</description></data>
</rpc-reply>"#;
        let result = parse_rpc_reply(xml, "6").unwrap();
        let data = match result {
            RpcReply::Data(data) => data,
            other => panic!("expected Data, got {other:?}"),
        };
        validate_xml_fragment(&data).expect("reconstructed data must be well-formed");
        // Semantic check: independently unescaping the reconstructed XML must
        // yield the full original text (no truncation around the refs).
        let decoded = quick_xml::escape::unescape(&data).expect("must unescape");
        assert!(
            decoded.contains("A & B < C"),
            "char refs must round-trip: {decoded}"
        );
    }

    #[test]
    fn test_error_info_with_entities_stays_well_formed() {
        let xml = r#"<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="7">
  <rpc-error>
    <error-type>application</error-type>
    <error-tag>operation-failed</error-tag>
    <error-severity>error</error-severity>
    <error-message>bad element</error-message>
    <error-info><bad-element>a &amp; b</bad-element></error-info>
  </rpc-error>
</rpc-reply>"#;
        let err = parse_rpc_reply(xml, "7").unwrap_err();
        match err {
            RpcError::ServerError {
                info: Some(info), ..
            } => {
                validate_xml_fragment(&info).expect("error-info must stay well-formed");
                let decoded = quick_xml::escape::unescape(&info).expect("must unescape");
                assert!(
                    decoded.contains("a & b"),
                    "entity in error-info must round-trip: {decoded}"
                );
            }
            other => panic!("expected ServerError with info, got {other:?}"),
        }
    }

    #[test]
    fn test_data_preserves_namespace_prefixes() {
        // Prefixed elements must keep their prefix in reconstructed data;
        // stripping it detaches the element from its namespace.
        let xml = r#"<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="8">
  <data><if:interfaces xmlns:if="urn:ietf:params:xml:ns:yang:ietf-interfaces"><if:interface/></if:interfaces></data>
</rpc-reply>"#;
        let result = parse_rpc_reply(xml, "8").unwrap();
        let data = match result {
            RpcReply::Data(data) => data,
            other => panic!("expected Data, got {other:?}"),
        };
        assert!(
            data.contains("<if:interfaces") && data.contains("</if:interfaces>"),
            "namespace prefix must be preserved: {data}"
        );
        assert!(
            data.contains("<if:interface/>"),
            "prefix on empty element must be preserved: {data}"
        );
    }

    #[test]
    fn test_data_preserves_cdata_content() {
        let xml = r#"<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="9">
  <data><description><![CDATA[uplink & transit]]></description></data>
</rpc-reply>"#;
        let result = parse_rpc_reply(xml, "9").unwrap();
        let data = match result {
            RpcReply::Data(data) => data,
            other => panic!("expected Data, got {other:?}"),
        };
        validate_xml_fragment(&data).expect("reconstructed data must be well-formed");
        let decoded = quick_xml::escape::unescape(&data).expect("must unescape");
        assert!(
            decoded.contains("uplink & transit"),
            "CDATA content must not be dropped: {decoded}"
        );
    }

    #[test]
    fn test_error_message_cdata_is_captured() {
        let xml = r#"<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="10">
  <rpc-error>
    <error-type>application</error-type>
    <error-tag>operation-failed</error-tag>
    <error-severity>error</error-severity>
    <error-message><![CDATA[bad & input]]></error-message>
  </rpc-error>
</rpc-reply>"#;
        let err = parse_rpc_reply(xml, "10").unwrap_err();
        match err {
            RpcError::ServerError { message, .. } => {
                assert_eq!(message, "bad & input");
            }
            other => panic!("expected ServerError, got {other:?}"),
        }
    }

    #[test]
    fn test_data_escapes_double_quote_in_attribute() {
        // A single-quoted source attribute may contain a raw double quote;
        // reconstruction wraps attributes in double quotes, so it must be
        // escaped or the output is malformed.
        let xml = r#"<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="11">
  <data><x note='he said "up"'/></data>
</rpc-reply>"#;
        let result = parse_rpc_reply(xml, "11").unwrap();
        let data = match result {
            RpcReply::Data(data) => data,
            other => panic!("expected Data, got {other:?}"),
        };
        validate_xml_fragment(&data).expect("reconstructed data must be well-formed");
        assert!(
            data.contains("&quot;up&quot;"),
            "double quotes in attribute values must be escaped: {data}"
        );
    }

    #[test]
    fn test_top_level_empty_element_is_data() {
        // A Junos custom RPC can answer with a single empty element directly
        // under <rpc-reply>; that is data, not a bare <ok/>.
        let xml = r#"<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="12">
  <software-information/>
</rpc-reply>"#;
        let result = parse_rpc_reply(xml, "12").unwrap();
        match result {
            RpcReply::Data(data) => {
                assert!(
                    data.contains("<software-information/>"),
                    "empty element must be captured: {data}"
                );
            }
            other => panic!("expected Data, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_cluster_validate_unclosed_routing_engine() {
        // Real chassis cluster commit-check success with unclosed <routing-engine>.
        let xml = include_str!("../../../tests/fixtures/commit_check/cluster_validate_success.xml");
        let result = parse_rpc_reply(xml, "101").unwrap();
        // Should successfully parse as Ok-like (either Ok or OkWithWarnings).
        assert!(
            matches!(result, RpcReply::Ok | RpcReply::OkWithWarnings(_)),
            "cluster validate should parse as Ok, got {result:?}"
        );
    }

    #[test]
    fn test_repair_two_node_unclosed_routing_engine() {
        // Synthetic two-node cluster with two consecutive unclosed routing-engine blocks.
        let xml = r#"<nc:rpc-reply xmlns:junos="http://xml.juniper.net/junos/25.4R1.12/junos" xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="101">
<routing-engine junos:style="show-name">
<name>node0</name>
<commit-check-success/>
<routing-engine junos:style="show-name">
<name>node1</name>
<commit-check-success/>
<nc:ok/>
</nc:rpc-reply>"#;
        let result = parse_rpc_reply(xml, "101").unwrap();
        assert!(
            matches!(result, RpcReply::Ok | RpcReply::OkWithWarnings(_)),
            "two-node cluster validate should parse as Ok, got {result:?}"
        );
    }

    #[test]
    fn test_repair_cluster_commit_check_error() {
        // Cluster commit-check failure with unclosed routing-engine wrapping rpc-error.
        let xml = r#"<nc:rpc-reply xmlns:junos="http://xml.juniper.net/junos/25.4R1.12/junos" xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="101">
<routing-engine junos:style="show-name">
<name>node0</name>
<nc:rpc-error>
<nc:error-type>application</nc:error-type>
<nc:error-tag>operation-failed</nc:error-tag>
<nc:error-severity>error</nc:error-severity>
<nc:error-message>configuration check-out failed</nc:error-message>
</nc:rpc-error>
</nc:rpc-reply>"#;
        let err = parse_rpc_reply(xml, "101").unwrap_err();
        match err {
            RpcError::ServerError { tag, message, .. } => {
                assert_eq!(tag, ErrorTag::OperationFailed);
                assert!(
                    message.contains("configuration check-out failed"),
                    "error message should be preserved, got: {message}"
                );
            }
            other => panic!("expected ServerError, got {other:?}"),
        }
    }

    #[test]
    fn test_well_formed_reply_unaffected_by_repair_path() {
        // Well-formed replies should not be affected (never enter repair path).
        let ok_xml = r#"<nc:rpc-reply xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1">
  <nc:ok/>
</nc:rpc-reply>"#;
        let result = parse_rpc_reply(ok_xml, "1").unwrap();
        assert!(matches!(result, RpcReply::Ok));

        let multi_re_xml = r#"<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="8">
  <multi-routing-engine-results>
    <multi-routing-engine-item>
      <re-name>node0</re-name>
      <software-information>
        <host-name>vsrx-node0</host-name>
      </software-information>
    </multi-routing-engine-item>
  </multi-routing-engine-results>
</rpc-reply>"#;
        let result = parse_rpc_reply(multi_re_xml, "8").unwrap();
        assert!(matches!(result, RpcReply::Data(_)));
    }

    #[test]
    fn test_truncated_reply_not_masked_as_success() {
        // A genuinely truncated reply (missing </rpc-reply>) that also happens
        // to contain an unclosed <routing-engine> must NOT be repaired into a
        // fabricated success — the repair must leave the reply's own elements
        // open at EOF and bail, surfacing the original parse error instead.
        let truncated = r#"<nc:rpc-reply xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1"><outer><routing-engine><nc:ok/></outer>"#;
        let result = parse_rpc_reply(truncated, "1");
        assert!(
            result.is_err(),
            "truncated reply must not be repaired into success, got {result:?}"
        );
    }

    #[test]
    fn rejects_ambiguous_envelopes_and_payloads() {
        let cases = [
            ("missing message-id", r#"<rpc-reply><ok/></rpc-reply>"#),
            (
                "duplicate message-id",
                r#"<rpc-reply message-id="1" message-id="1"><ok/></rpc-reply>"#,
            ),
            (
                "malformed message-id",
                r#"<rpc-reply message-id=1><ok/></rpc-reply>"#,
            ),
            (
                "duplicate data",
                r#"<rpc-reply message-id="1"><data/><data/></rpc-reply>"#,
            ),
            (
                "ok and data",
                r#"<rpc-reply message-id="1"><ok/><data/></rpc-reply>"#,
            ),
            (
                "direct payload and data",
                r#"<rpc-reply message-id="1"><output/><data/></rpc-reply>"#,
            ),
            (
                "nested reply",
                r#"<rpc-reply message-id="1"><rpc-reply message-id="1"/></rpc-reply>"#,
            ),
            (
                "reply nested in direct vendor payload",
                r#"<rpc-reply message-id="1"><wrapper><rpc-reply message-id="1"/></wrapper></rpc-reply>"#,
            ),
            (
                "second reply",
                r#"<rpc-reply message-id="1"/><rpc-reply message-id="1"/>"#,
            ),
            (
                "significant trailing text",
                r#"<rpc-reply message-id="1"/>trailing"#,
            ),
            ("wrong root", r#"<notification message-id="1"/>"#),
        ];

        for (name, xml) in cases {
            let result = parse_rpc_reply(xml, "1");
            assert!(
                matches!(result, Err(RpcError::ParseError(_))),
                "{name} must be ParseError, got {result:?}"
            );
        }
    }

    #[test]
    fn wrong_message_id_keeps_typed_error() {
        let xml = r#"<rpc-reply message-id="actual"><ok/></rpc-reply>"#;
        let result = parse_rpc_reply(xml, "expected");
        assert!(matches!(
            result,
            Err(RpcError::MessageIdMismatch {
                expected,
                actual
            }) if expected == "expected" && actual == "actual"
        ));
    }
}
