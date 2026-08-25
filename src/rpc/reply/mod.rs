mod capture;
mod lexical;
mod parser;
mod repair;

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

/// Parse an `<rpc-reply>` XML response.
///
/// Returns `Ok(RpcReply)` for successful responses, or `Err(RpcError)` if
/// the reply contains `<rpc-error>` elements.
///
/// This parser normally requires well-formed XML. On Junos chassis clusters,
/// validate/commit-check replies contain unclosed `<routing-engine>` elements
/// (a device bug). If the strict parse fails with a parse error and the reply
/// contains a recognizable cluster commit-check result, the parser attempts
/// only the missing `routing-engine` closures, then re-parses. Well-formed
/// replies are unaffected (no repair attempt unless strict parsing fails).
pub fn parse_rpc_reply(xml: &str, expected_message_id: &str) -> Result<RpcReply, RpcError> {
    match parser::parse_strict(xml, expected_message_id) {
        Ok(reply) => Ok(reply),
        Err(original @ RpcError::ParseError(_)) => {
            let Some(repaired) = repair::repair_cluster_commit_check(xml) else {
                return Err(original);
            };
            match parser::parse_strict(&repaired, expected_message_id) {
                Err(RpcError::ParseError(_)) => Err(original),
                result => result,
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
                assert!(data.contains("<configuration"));
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
                assert!(data.contains("<software-information"));
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
                assert!(data.contains("<multi-routing-engine-results"));
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
                assert!(data.contains("<configuration"));
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
                    data.contains("<software-information"),
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
    fn parses_standalone_commit_check_with_ok_sibling() {
        // Captured off the wire from a standalone single-RE SRX345 running
        // Junos 21.2R3-S6.11. Unlike the chassis-cluster form, this reply is
        // well-formed: <commit-results> is closed, and <ok/> follows it as a
        // sibling. RFC 6241 does not allow both, but Junos sends both.
        let xml =
            include_str!("../../../tests/fixtures/commit_check/standalone_validate_success.xml");
        let result = parse_rpc_reply(xml, "101").unwrap();
        assert!(
            matches!(result, RpcReply::Ok | RpcReply::OkWithWarnings(_)),
            "standalone commit-check should parse as Ok, got {result:?}"
        );
    }

    #[test]
    fn ok_sibling_after_a_closed_direct_payload_is_not_a_conflict() {
        // The same shape with content in the payload, to pin that the verdict
        // survives regardless of what <commit-results> carries.
        let xml = r#"<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="7">
<commit-results>
<routing-engine><name>re0</name><commit-check-success/></routing-engine>
</commit-results>
<ok/>
</rpc-reply>"#;
        assert!(matches!(parse_rpc_reply(xml, "7"), Ok(RpcReply::Ok)));
    }

    #[test]
    fn ok_sibling_does_not_mask_a_device_error() {
        // A hard rpc-error must still win over the tolerated <ok/> sibling,
        // so a failed check is never reported as a passing one.
        let xml = r#"<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="8">
<commit-results>
</commit-results>
<rpc-error>
<error-type>protocol</error-type>
<error-tag>operation-failed</error-tag>
<error-severity>error</error-severity>
<error-message>configuration check-out failed</error-message>
</rpc-error>
<ok/>
</rpc-reply>"#;
        match parse_rpc_reply(xml, "8") {
            Err(RpcError::ServerError { message, .. }) => {
                assert_eq!(message, "configuration check-out failed");
            }
            other => panic!("expected ServerError, got {other:?}"),
        }
    }

    #[test]
    fn unrelated_direct_payload_with_ok_is_not_silently_discarded() {
        // An op-command payload followed by <ok/> must not resolve to Ok:
        // that would hand the caller an empty string and lose the response.
        let xml = r#"<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="4">
<software-information><host-name>srx345</host-name></software-information>
<ok/>
</rpc-reply>"#;
        assert!(matches!(
            parse_rpc_reply(xml, "4"),
            Err(RpcError::ParseError(_))
        ));
    }

    #[test]
    fn commit_results_plus_another_sibling_then_ok_still_conflicts() {
        // Direct siblings aggregate into one payload
        // (public_direct_payload_aggregates_siblings_contract). The <ok/>
        // exception is for a reply whose only direct root is
        // <commit-results>; once a second root joins it, resolving to Ok
        // would drop the aggregate.
        let xml = r#"<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="10">
<commit-results/>
<software-information><host-name>srx345</host-name></software-information>
<ok/>
</rpc-reply>"#;
        assert!(matches!(
            parse_rpc_reply(xml, "10"),
            Err(RpcError::ParseError(_))
        ));
    }

    #[test]
    fn commit_results_after_another_sibling_then_ok_still_conflicts() {
        let xml = r#"<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="11">
<software-information><host-name>srx345</host-name></software-information>
<commit-results/>
<ok/>
</rpc-reply>"#;
        assert!(matches!(
            parse_rpc_reply(xml, "11"),
            Err(RpcError::ParseError(_))
        ));
    }

    #[test]
    fn duplicate_ok_after_commit_results_still_conflicts() {
        let xml = r#"<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="5">
<commit-results>
</commit-results>
<ok/>
<ok/>
</rpc-reply>"#;
        assert!(matches!(
            parse_rpc_reply(xml, "5"),
            Err(RpcError::ParseError(_))
        ));
    }

    #[test]
    fn direct_sibling_after_the_tolerated_ok_still_conflicts() {
        let xml = r#"<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="6">
<commit-results>
</commit-results>
<ok/>
<software-information><host-name>srx345</host-name></software-information>
</rpc-reply>"#;
        assert!(matches!(
            parse_rpc_reply(xml, "6"),
            Err(RpcError::ParseError(_))
        ));
    }

    #[test]
    fn two_data_payloads_still_conflict() {
        // The tolerance is scoped to a direct payload followed by <ok/>. A
        // genuinely ambiguous reply must still be rejected.
        let xml = r#"<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="9">
<data><a/></data>
<ok/>
</rpc-reply>"#;
        assert!(matches!(
            parse_rpc_reply(xml, "9"),
            Err(RpcError::ParseError(_))
        ));
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
    fn does_not_repair_unrelated_direct_routing_engine() {
        let xml = r#"<rpc-reply message-id="1">
  <routing-engine><name>node0</name><ok/>
</rpc-reply>"#;
        assert!(matches!(
            parse_rpc_reply(xml, "1"),
            Err(RpcError::ParseError(_))
        ));
    }

    #[test]
    fn does_not_repair_marker_in_unsupported_placement() {
        let xml = r#"<rpc-reply message-id="1">
  <outer><routing-engine><commit-check-success/>
  </outer></rpc-reply>"#;
        assert!(matches!(
            parse_rpc_reply(xml, "1"),
            Err(RpcError::ParseError(_))
        ));
    }

    #[test]
    fn does_not_repair_non_routing_engine_mismatch() {
        let xml = r#"<rpc-reply message-id="1">
  <routing-engine><commit-check-success/></wrong>
</rpc-reply>"#;
        assert!(matches!(
            parse_rpc_reply(xml, "1"),
            Err(RpcError::ParseError(_))
        ));
    }

    #[test]
    fn does_not_repair_truncated_commit_check() {
        let xml = r#"<rpc-reply message-id="1">
  <routing-engine><commit-check-success/>"#;
        assert!(matches!(
            parse_rpc_reply(xml, "1"),
            Err(RpcError::ParseError(_))
        ));
    }

    #[test]
    fn does_not_repair_commit_check_marker_nested_in_data() {
        let xml = r#"<rpc-reply message-id="1">
  <routing-engine><data><commit-check-success/></data>
</rpc-reply>"#;
        assert!(matches!(
            parse_rpc_reply(xml, "1"),
            Err(RpcError::ParseError(_))
        ));
    }

    #[test]
    fn nested_rpc_reply_inside_data_does_not_authorize_direct_repair() {
        let cases = [
            (
                "unqualified nested rpc-reply",
                r#"<rpc-reply message-id="1"><data>
                  <rpc-reply><routing-engine><commit-check-success/><ok/>
                  </rpc-reply>
                </data></rpc-reply>"#,
            ),
            (
                "NETCONF-qualified nested rpc-reply",
                r#"<nc:rpc-reply
                  xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0"
                  message-id="1"><nc:data>
                    <nc:rpc-reply><routing-engine>
                      <commit-check-success/><nc:ok/>
                    </nc:rpc-reply>
                  </nc:data></nc:rpc-reply>"#,
            ),
        ];

        for (path, xml) in cases {
            let original = match parser::parse_strict(xml, "1") {
                Err(RpcError::ParseError(message)) => message,
                result => panic!("{path}: expected original ParseError, got {result:?}"),
            };
            let returned = match parse_rpc_reply(xml, "1") {
                Err(RpcError::ParseError(message)) => message,
                result => panic!("{path}: repair changed the outcome to {result:?}"),
            };
            assert_eq!(returned, original, "{path}");
        }
    }

    #[test]
    fn multiple_document_roots_preserve_the_original_parse_error() {
        let reply = r#"<rpc-reply message-id="1">
          <routing-engine><commit-check-success/><ok/>
        </rpc-reply>"#;
        let cases = [
            ("trailing root", format!("{reply}<outer/>")),
            ("preceding root", format!("<outer/>{reply}")),
            ("two rpc-reply roots", format!("{reply}{reply}")),
        ];

        for (path, xml) in cases {
            let original = match parser::parse_strict(&xml, "1") {
                Err(RpcError::ParseError(message)) => message,
                result => panic!("{path}: expected original ParseError, got {result:?}"),
            };
            let returned = match parse_rpc_reply(&xml, "1") {
                Err(RpcError::ParseError(message)) => message,
                result => panic!("{path}: repair changed the outcome to {result:?}"),
            };
            assert_eq!(returned, original, "{path}");
        }
    }

    #[test]
    fn content_outside_repair_envelope_preserves_the_original_parse_error() {
        let reply = r#"<rpc-reply message-id="1">
          <routing-engine><commit-check-success/><ok/>
        </rpc-reply>"#;
        let cases = [
            ("preceding significant text", format!("outside{reply}")),
            ("trailing significant text", format!("{reply}outside")),
            ("preceding CDATA", format!("<![CDATA[outside]]>{reply}")),
            ("trailing CDATA", format!("{reply}<![CDATA[outside]]>")),
            ("preceding entity reference", format!("&amp;{reply}")),
            ("trailing entity reference", format!("{reply}&amp;")),
            ("preceding DOCTYPE", format!("<!DOCTYPE rpc-reply>{reply}")),
            ("trailing DOCTYPE", format!("{reply}<!DOCTYPE rpc-reply>")),
        ];

        for (path, xml) in cases {
            let original = match parser::parse_strict(&xml, "1") {
                Err(RpcError::ParseError(message)) => message,
                result => panic!("{path}: expected original ParseError, got {result:?}"),
            };
            let returned = match parse_rpc_reply(&xml, "1") {
                Err(RpcError::ParseError(message)) => message,
                result => panic!("{path}: repair changed the outcome to {result:?}"),
            };
            assert_eq!(returned, original, "{path}");
        }
    }

    #[test]
    fn does_not_repair_vendor_namespace_rpc_error_lookalike() {
        let xml = r#"<rpc-reply xmlns:v="urn:vendor" message-id="1">
          <routing-engine><v:rpc-error/>
        </rpc-reply>"#;
        assert!(matches!(
            parse_rpc_reply(xml, "1"),
            Err(RpcError::ParseError(_))
        ));
    }

    #[test]
    fn repairs_routing_engine_within_multi_routing_engine_results() {
        let xml = r#"<rpc-reply message-id="1">
  <multi-routing-engine-results>
    <routing-engine><commit-check-success/><ok/>
  </multi-routing-engine-results>
</rpc-reply>"#;
        assert!(matches!(parse_rpc_reply(xml, "1"), Ok(RpcReply::Ok)));
    }

    #[test]
    fn unsupported_multi_re_descendants_return_the_original_parse_error() {
        let complete_error = "\
          <rpc-error>\
            <error-type>application</error-type>\
            <error-tag>operation-failed</error-tag>\
            <error-severity>error</error-severity>\
            <error-message>device failure</error-message>\
          </rpc-error>";
        let cases = [
            (
                "arbitrary wrapper with success marker",
                r#"<rpc-reply message-id="1"><multi-routing-engine-results>
                  <outer><routing-engine><commit-check-success/><ok/>
                  </outer>
                </multi-routing-engine-results></rpc-reply>"#
                    .to_string(),
            ),
            (
                "deep wrapper below multi-RE item",
                r#"<rpc-reply message-id="1"><multi-routing-engine-results>
                  <multi-routing-engine-item><outer>
                    <routing-engine><commit-check-success/><ok/>
                  </outer></multi-routing-engine-item>
                </multi-routing-engine-results></rpc-reply>"#
                    .to_string(),
            ),
            (
                "arbitrary wrapper with complete rpc-error",
                format!(
                    "<rpc-reply message-id=\"1\"><multi-routing-engine-results>\
                       <outer><routing-engine>{complete_error}\
                       </outer>\
                     </multi-routing-engine-results></rpc-reply>"
                ),
            ),
        ];

        for (path, xml) in cases {
            let original = match parser::parse_strict(&xml, "1") {
                Err(RpcError::ParseError(message)) => message,
                result => panic!("{path}: expected original ParseError, got {result:?}"),
            };
            let returned = match parse_rpc_reply(&xml, "1") {
                Err(RpcError::ParseError(message)) => message,
                result => panic!("{path}: repair changed the outcome to {result:?}"),
            };
            assert_eq!(returned, original, "{path}");
        }
    }

    #[test]
    fn repaired_semantic_failure_returns_original_structural_error() {
        let xml = r#"<rpc-reply message-id="1">
  <multi-routing-engine-results>
    <routing-engine><commit-check-success/><ok/>
  </multi-routing-engine-results>
  <rpc-error>
    <error-type>application</error-type>
  </rpc-error>
</rpc-reply>"#;
        let original = match parser::parse_strict(xml, "1") {
            Err(RpcError::ParseError(message)) => {
                assert!(
                    message.starts_with("XML parse error:"),
                    "fixture must fail strict parsing structurally: {message}"
                );
                message
            }
            other => panic!("fixture must produce a strict ParseError, got {other:?}"),
        };

        let returned = match parse_rpc_reply(xml, "1") {
            Err(RpcError::ParseError(message)) => message,
            other => panic!("expected ParseError, got {other:?}"),
        };

        assert_eq!(returned, original);
    }

    #[test]
    fn repaired_reply_keeps_typed_message_id_mismatch() {
        let xml = r#"<rpc-reply message-id="actual">
  <routing-engine><commit-check-success/><ok/>
</rpc-reply>"#;

        assert!(matches!(
            parse_rpc_reply(xml, "expected"),
            Err(RpcError::MessageIdMismatch {
                expected,
                actual
            }) if expected == "expected" && actual == "actual"
        ));
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

    #[test]
    fn rejects_prefixed_only_message_id() {
        let xml =
            r#"<rpc-reply xmlns:evil="urn:example:evil" evil:message-id="1"><ok/></rpc-reply>"#;
        let result = parse_rpc_reply(xml, "1");
        assert!(
            matches!(result, Err(RpcError::ParseError(_))),
            "a qualified attribute is not the NETCONF message-id: {result:?}"
        );
    }

    #[test]
    fn accepts_unqualified_message_id_with_qualified_attributes() {
        let xml = r#"<rpc-reply xmlns:evil="urn:example:evil" message-id="1" evil:message-id="ignored" evil:note="metadata"><ok/></rpc-reply>"#;
        let result = parse_rpc_reply(xml, "1");
        assert!(
            matches!(result, Ok(RpcReply::Ok)),
            "qualified attributes must not conflict with message-id: {result:?}"
        );
    }

    #[test]
    fn public_parser_rejects_quick_xml_lexical_gaps_with_bounded_errors() {
        let cases = [
            (
                "raw less-than in attribute",
                r#"<rpc-reply message-id="1"><data><x value="SENSITIVE<raw"/></data></rpc-reply>"#,
            ),
            (
                "CDATA terminator in text",
                r#"<rpc-reply message-id="1"><data><x>SENSITIVE]]></x></data></rpc-reply>"#,
            ),
            (
                "invalid comment",
                r#"<!--SENSITIVE--comment--><rpc-reply message-id="1"><ok/></rpc-reply>"#,
            ),
            (
                "invalid PI target",
                r#"<?1SENSITIVE?><rpc-reply message-id="1"><ok/></rpc-reply>"#,
            ),
            (
                "invalid declaration",
                r#"<?xml version="1.0" SENSITIVE="value"?><rpc-reply message-id="1"><ok/></rpc-reply>"#,
            ),
            (
                "missing ordinary attribute separator",
                r#"<rpc-reply message-id="1"probe="SENSITIVE"><ok/></rpc-reply>"#,
            ),
        ];

        for (path, xml) in cases {
            let RpcError::ParseError(message) =
                parse_rpc_reply(xml, "1").expect_err("lexically malformed XML must fail")
            else {
                panic!("{path}: expected ParseError");
            };
            assert!(message.len() < 128, "{path}: diagnostic is unbounded");
            assert!(
                !message.contains("SENSITIVE"),
                "{path}: diagnostic exposes input"
            );
        }

        let valid = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
          <!--before--><?a_b before?>
          <rpc-reply message-id="1"><!--inside--><?inside data?><ok/></rpc-reply>
          <!--after--><?after data?>"#;
        assert!(
            matches!(parse_rpc_reply(valid, "1"), Ok(RpcReply::Ok)),
            "valid lexical controls remain accepted"
        );
    }

    #[test]
    fn lexical_errors_in_repair_candidates_preserve_the_original_parse_error() {
        let cases = [
            (
                "raw less-than in ordinary attribute",
                r#"<rpc-reply message-id="1<raw">
                  <routing-engine><commit-check-success/><ok/>
                </rpc-reply>"#,
            ),
            (
                "CDATA terminator in text",
                r#"<rpc-reply message-id="1">
                  <routing-engine><commit-check-success/>bad]]><ok/>
                </rpc-reply>"#,
            ),
            (
                "invalid comment",
                r#"<!--bad--comment--><rpc-reply message-id="1">
                  <routing-engine><commit-check-success/><ok/>
                </rpc-reply>"#,
            ),
            (
                "invalid processing instruction",
                r#"<rpc-reply message-id="1"><?1bad?>
                  <routing-engine><commit-check-success/><ok/>
                </rpc-reply>"#,
            ),
            (
                "misplaced declaration",
                r#"<rpc-reply message-id="1">
                  <routing-engine><commit-check-success/><ok/>
                </rpc-reply><?xml version="1.0"?>"#,
            ),
        ];

        for (path, xml) in cases {
            let original = match parser::parse_strict(xml, "1") {
                Err(RpcError::ParseError(message)) => message,
                result => panic!("{path}: expected original ParseError, got {result:?}"),
            };
            let returned = match parse_rpc_reply(xml, "1") {
                Err(RpcError::ParseError(message)) => message,
                result => panic!("{path}: repair changed the outcome to {result:?}"),
            };
            assert_eq!(returned, original, "{path}");
        }
    }

    #[test]
    fn declaration_adjacency_does_not_authorize_repair() {
        let declarations = [
            r#"<?xml version="1.0"encoding='UTF-8'?>"#,
            r#"<?xml version='1.0'standalone="yes"?>"#,
            r#"<?xml version="1.0" encoding='UTF-8'standalone="no"?>"#,
        ];

        for declaration in declarations {
            let xml = format!(
                "{declaration}<rpc-reply message-id=\"1\">\
                   <routing-engine><commit-check-success/><ok/>\
                 </rpc-reply>"
            );
            let original = match parser::parse_strict(&xml, "1") {
                Err(RpcError::ParseError(message)) => message,
                result => panic!("expected original ParseError, got {result:?}"),
            };
            let returned = match parse_rpc_reply(&xml, "1") {
                Err(RpcError::ParseError(message)) => message,
                result => panic!("repair changed the outcome to {result:?}"),
            };
            assert_eq!(returned, original);
            assert_eq!(returned, "invalid XML declaration syntax");
        }
    }

    #[test]
    fn unsupported_juniper_namespace_families_do_not_authorize_repair() {
        let namespaces = [
            "http://xml.juniper.net/not-a-repository-family",
            "http://xml.juniper.net/junos bad",
            "http://xml.juniper.net/../vendor",
            "http://xml.juniper.net/junos/../junos",
            "http://xml.juniper.net/junos/%2G/junos",
        ];

        for namespace in namespaces {
            let xml = format!(
                "<rpc-reply xmlns:j=\"{namespace}\" message-id=\"1\">\
                   <routing-engine><j:commit-check-success/><ok/>\
                 </rpc-reply>"
            );
            let original = match parser::parse_strict(&xml, "1") {
                Err(RpcError::ParseError(message)) => message,
                result => panic!("{namespace}: expected original ParseError, got {result:?}"),
            };
            let returned = match parse_rpc_reply(&xml, "1") {
                Err(RpcError::ParseError(message)) => message,
                result => panic!("{namespace}: repair changed the outcome to {result:?}"),
            };
            assert_eq!(returned, original, "{namespace}");
        }
    }
}
