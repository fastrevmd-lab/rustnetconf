use super::capture::{namespace_declarations, NamespaceBindings};
use quick_xml::events::{BytesEnd, BytesStart, Event};
use quick_xml::{Reader, Writer};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MultiRePathElement {
    Other,
    Results,
    Item,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DocumentRootState {
    Before,
    Inside,
    After,
}

#[derive(Debug)]
struct OpenElement {
    qname: Vec<u8>,
    local: Vec<u8>,
    protocol_local: Option<Vec<u8>>,
    namespaces: NamespaceBindings,
    multi_re_path: MultiRePathElement,
    routing_engine_supported: bool,
    routing_engine_has_marker: bool,
}

impl OpenElement {
    fn ordinary(
        qname: &[u8],
        namespaces: NamespaceBindings,
        multi_re_path: MultiRePathElement,
    ) -> Self {
        Self {
            qname: qname.to_vec(),
            local: local_name(qname).to_vec(),
            protocol_local: netconf_local_name(qname, &namespaces).map(<[u8]>::to_vec),
            namespaces,
            multi_re_path,
            routing_engine_supported: false,
            routing_engine_has_marker: false,
        }
    }

    fn routing_engine(qname: &[u8], supported: bool, namespaces: NamespaceBindings) -> Self {
        Self {
            qname: qname.to_vec(),
            local: b"routing-engine".to_vec(),
            protocol_local: netconf_local_name(qname, &namespaces).map(<[u8]>::to_vec),
            namespaces,
            multi_re_path: MultiRePathElement::Other,
            routing_engine_supported: supported,
            routing_engine_has_marker: false,
        }
    }

    fn repairable(&self) -> bool {
        self.local == b"routing-engine"
            && self.routing_engine_supported
            && self.routing_engine_has_marker
    }
}

fn local_name(qname: &[u8]) -> &[u8] {
    qname.rsplit(|byte| *byte == b':').next().unwrap_or(qname)
}

fn netconf_local_name<'a>(
    qualified_name: &'a [u8],
    namespaces: &NamespaceBindings,
) -> Option<&'a [u8]> {
    let (namespace, local) = expanded_name(qualified_name, namespaces)?;
    match namespace {
        None => Some(local),
        Some(super::parser::NETCONF_NAMESPACE) => Some(local),
        _ => None,
    }
}

fn juniper_local_name<'a>(
    qualified_name: &'a [u8],
    namespaces: &NamespaceBindings,
) -> Option<&'a [u8]> {
    let (namespace, local) = expanded_name(qualified_name, namespaces)?;
    match namespace {
        None => Some(local),
        Some(namespace) if is_juniper_xml_namespace(namespace) => Some(local),
        _ => None,
    }
}

fn expanded_name<'name, 'namespace>(
    qualified_name: &'name [u8],
    namespaces: &'namespace NamespaceBindings,
) -> Option<(Option<&'namespace str>, &'name [u8])> {
    let mut parts = qualified_name.split(|byte| *byte == b':');
    let first = parts.next()?;
    let second = parts.next();
    if parts.next().is_some() {
        return None;
    }
    let (namespace, local) = if let Some(local) = second {
        let prefix = std::str::from_utf8(first).ok()?;
        (Some(namespaces.get(prefix)?.as_str()), local)
    } else {
        (namespaces.get("").map(String::as_str), first)
    };
    Some((namespace, local))
}

/// Junos reply namespaces in this repository use the exact
/// `http://xml.juniper.net/` authority followed by non-empty path segments.
/// Keeping the authority and scheme exact, and excluding query or fragment
/// syntax, rejects lookalike namespaces while allowing the repository's
/// versioned Junos, XNM, and NETCONF families.
fn is_juniper_xml_namespace(namespace: &str) -> bool {
    let Some(path) = namespace.strip_prefix("http://xml.juniper.net/") else {
        return false;
    };
    !path.contains(['?', '#']) && path.split('/').all(|segment| !segment.is_empty())
}

fn namespaces_for(
    tag: &quick_xml::events::BytesStart<'_>,
    stack: &[OpenElement],
) -> Option<NamespaceBindings> {
    let mut namespaces = stack
        .last()
        .map(|element| element.namespaces.clone())
        .unwrap_or_default();
    for (prefix, value) in namespace_declarations(tag).ok()? {
        if value.is_empty() {
            namespaces.remove(&prefix);
        } else {
            namespaces.insert(prefix, value);
        }
    }
    Some(namespaces)
}

fn supported_routing_engine_parent(stack: &[OpenElement]) -> bool {
    stack.last().is_some_and(|element| {
        (stack.len() == 1 && element.protocol_local.as_deref() == Some(b"rpc-reply"))
            || matches!(
                element.multi_re_path,
                MultiRePathElement::Results | MultiRePathElement::Item
            )
    })
}

fn mark_commit_check_result(stack: &mut [OpenElement]) {
    let Some(index) = stack
        .iter_mut()
        .rposition(|element| element.local == b"routing-engine")
    else {
        return;
    };
    if stack[index + 1..]
        .iter()
        .any(|element| element.protocol_local.as_deref() == Some(b"data"))
    {
        return;
    }
    stack[index].routing_engine_has_marker = true;
}

fn close_repairable(writer: &mut Writer<Vec<u8>>, stack: &mut Vec<OpenElement>) -> Option<()> {
    let top = stack.last()?;
    if !top.repairable() {
        return None;
    }
    let qname = std::str::from_utf8(&top.qname).ok()?;
    writer.write_event(Event::End(BytesEnd::new(qname))).ok()?;
    stack.pop();
    Some(())
}

fn handle_start(
    tag: BytesStart<'_>,
    writer: &mut Writer<Vec<u8>>,
    stack: &mut Vec<OpenElement>,
    repaired_any: &mut bool,
) -> Option<()> {
    let qname = tag.name();
    let local = local_name(qname.as_ref());
    let namespaces = namespaces_for(&tag, stack)?;

    if juniper_local_name(qname.as_ref(), &namespaces) == Some(b"commit-check-success")
        || netconf_local_name(qname.as_ref(), &namespaces) == Some(b"rpc-error")
    {
        mark_commit_check_result(stack);
    }

    if local == b"routing-engine" {
        if stack
            .last()
            .is_some_and(|element| element.local == b"routing-engine")
        {
            close_repairable(writer, stack)?;
            *repaired_any = true;
        }
        let supported = supported_routing_engine_parent(stack);
        stack.push(OpenElement::routing_engine(
            qname.as_ref(),
            supported,
            namespaces,
        ));
    } else {
        let vendor_local = juniper_local_name(qname.as_ref(), &namespaces);
        let multi_re_path = if vendor_local == Some(b"multi-routing-engine-results")
            && stack.len() == 1
            && stack
                .last()
                .is_some_and(|element| element.protocol_local.as_deref() == Some(b"rpc-reply"))
        {
            MultiRePathElement::Results
        } else if vendor_local == Some(b"multi-routing-engine-item")
            && stack
                .last()
                .is_some_and(|element| element.multi_re_path == MultiRePathElement::Results)
        {
            MultiRePathElement::Item
        } else {
            MultiRePathElement::Other
        };
        stack.push(OpenElement::ordinary(
            qname.as_ref(),
            namespaces,
            multi_re_path,
        ));
    }

    writer.write_event(Event::Start(tag.into_owned())).ok()
}

fn begin_document_root(
    tag: &BytesStart<'_>,
    stack: &[OpenElement],
    root_state: &mut DocumentRootState,
) -> Option<()> {
    if !stack.is_empty() {
        return Some(());
    }
    if *root_state != DocumentRootState::Before {
        return None;
    }
    let namespaces = namespaces_for(tag, stack)?;
    if netconf_local_name(tag.name().as_ref(), &namespaces) != Some(b"rpc-reply") {
        return None;
    }
    *root_state = DocumentRootState::Inside;
    Some(())
}

pub(super) fn repair_cluster_commit_check(xml: &str) -> Option<String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().check_end_names = false;

    let mut writer = Writer::new(Vec::new());
    let mut stack: Vec<OpenElement> = Vec::new();
    let mut repaired_any = false;
    let mut root_state = DocumentRootState::Before;

    loop {
        match reader.read_event() {
            Ok(Event::Start(tag)) => {
                begin_document_root(&tag, &stack, &mut root_state)?;
                handle_start(tag, &mut writer, &mut stack, &mut repaired_any)?;
            }
            Ok(Event::Empty(tag)) => {
                if stack.is_empty() {
                    return None;
                }
                let namespaces = namespaces_for(&tag, &stack)?;
                let qname = tag.name();
                if juniper_local_name(qname.as_ref(), &namespaces) == Some(b"commit-check-success")
                    || netconf_local_name(qname.as_ref(), &namespaces) == Some(b"rpc-error")
                {
                    mark_commit_check_result(&mut stack);
                }
                writer.write_event(Event::Empty(tag.into_owned())).ok()?;
            }
            Ok(Event::End(tag)) => {
                let end_name = tag.name();
                let end_local = local_name(end_name.as_ref());

                while stack
                    .last()
                    .is_some_and(|element| element.local.as_slice() != end_local)
                {
                    let parent_matches =
                        stack.len() >= 2 && stack[stack.len() - 2].local.as_slice() == end_local;
                    if !parent_matches {
                        return None;
                    }
                    close_repairable(&mut writer, &mut stack)?;
                    repaired_any = true;
                }

                let open = stack.pop()?;
                if open.local.as_slice() != end_local {
                    return None;
                }
                writer.write_event(Event::End(tag.into_owned())).ok()?;
                if stack.is_empty() {
                    if root_state != DocumentRootState::Inside
                        || open.protocol_local.as_deref() != Some(b"rpc-reply")
                    {
                        return None;
                    }
                    root_state = DocumentRootState::After;
                }
            }
            Ok(Event::Text(text)) => {
                writer.write_event(Event::Text(text.into_owned())).ok()?;
            }
            Ok(Event::CData(cdata)) => {
                writer.write_event(Event::CData(cdata.into_owned())).ok()?;
            }
            Ok(Event::GeneralRef(entity)) => {
                writer
                    .write_event(Event::GeneralRef(entity.into_owned()))
                    .ok()?;
            }
            Ok(Event::Comment(comment)) => {
                writer
                    .write_event(Event::Comment(comment.into_owned()))
                    .ok()?;
            }
            Ok(Event::Decl(declaration)) => {
                writer
                    .write_event(Event::Decl(declaration.into_owned()))
                    .ok()?;
            }
            Ok(Event::PI(instruction)) => {
                writer
                    .write_event(Event::PI(instruction.into_owned()))
                    .ok()?;
            }
            Ok(Event::DocType(doctype)) => {
                writer
                    .write_event(Event::DocType(doctype.into_owned()))
                    .ok()?;
            }
            Ok(Event::Eof) => {
                if !stack.is_empty() || root_state != DocumentRootState::After || !repaired_any {
                    return None;
                }
                break;
            }
            Err(_) => return None,
        }
    }

    String::from_utf8(writer.into_inner()).ok()
}

#[cfg(test)]
mod tests {
    use super::repair_cluster_commit_check;

    #[test]
    fn preserves_source_and_qualified_name_around_inserted_close() {
        let xml = r#"<nc:rpc-reply xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1"><j:routing-engine xmlns:j="http://xml.juniper.net/junos/25.4R1.12/junos" note="a&amp;b"><j:commit-check-success/><nc:ok/></nc:rpc-reply>"#;
        let expected = r#"<nc:rpc-reply xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1"><j:routing-engine xmlns:j="http://xml.juniper.net/junos/25.4R1.12/junos" note="a&amp;b"><j:commit-check-success/><nc:ok/></j:routing-engine></nc:rpc-reply>"#;

        assert_eq!(repair_cluster_commit_check(xml).as_deref(), Some(expected));
    }

    #[test]
    fn rejects_commit_check_markers_in_unrelated_namespaces() {
        let cases = [
            (
                "prefixed vendor marker",
                r#"<rpc-reply xmlns:v="urn:vendor" message-id="1">
                  <routing-engine><v:commit-check-success/><ok/>
                </rpc-reply>"#,
            ),
            (
                "unbound prefixed marker",
                r#"<rpc-reply message-id="1">
                  <routing-engine><v:commit-check-success/><ok/>
                </rpc-reply>"#,
            ),
            (
                "default vendor marker",
                r#"<rpc-reply message-id="1">
                  <routing-engine><commit-check-success xmlns="urn:vendor"/><ok/>
                </rpc-reply>"#,
            ),
            (
                "Juniper lookalike authority",
                r#"<rpc-reply
                  xmlns:j="http://xml.juniper.net.evil/junos/25.4R1/junos"
                  message-id="1"><routing-engine>
                    <j:commit-check-success/><ok/>
                  </rpc-reply>"#,
            ),
            (
                "unsupported Juniper HTTPS authority",
                r#"<rpc-reply
                  xmlns:j="https://xml.juniper.net/junos/25.4R1/junos"
                  message-id="1"><routing-engine>
                    <j:commit-check-success/><ok/>
                  </rpc-reply>"#,
            ),
        ];

        for (path, xml) in cases {
            assert_eq!(
                repair_cluster_commit_check(xml),
                None,
                "{path} must not authorize repair"
            );
        }
    }

    #[test]
    fn juniper_repair_namespaces_require_nonempty_path_segments_without_query_or_fragment() {
        fn marker_reply(namespace: &str) -> String {
            format!(
                "<rpc-reply xmlns:j=\"{namespace}\" message-id=\"1\">\
                   <routing-engine><j:commit-check-success/><ok/>\
                 </rpc-reply>"
            )
        }

        fn container_reply(namespace: &str) -> String {
            format!(
                "<rpc-reply xmlns:j=\"{namespace}\" message-id=\"1\">\
                   <j:multi-routing-engine-results>\
                     <routing-engine><commit-check-success/><ok/>\
                   </j:multi-routing-engine-results>\
                 </rpc-reply>"
            )
        }

        let invalid = [
            "http://xml.juniper.net/",
            "http://xml.juniper.net//",
            "http://xml.juniper.net//junos",
            "http://xml.juniper.net/?query-only",
            "http://xml.juniper.net/#fragment-only",
            "http://xml.juniper.net/junos?query",
            "http://xml.juniper.net/junos#fragment",
            "http://xml.juniper.net/junos//current",
            "http://xml.juniper.net/junos/current/",
        ];
        for namespace in invalid {
            assert_eq!(
                repair_cluster_commit_check(&marker_reply(namespace)),
                None,
                "invalid marker namespace authorized repair: {namespace}"
            );
            assert_eq!(
                repair_cluster_commit_check(&container_reply(namespace)),
                None,
                "invalid container namespace authorized repair: {namespace}"
            );
        }

        let valid = [
            "http://xml.juniper.net/junos/25.4R1.12/junos",
            "http://xml.juniper.net/xnm/1.1/xnm",
            "http://xml.juniper.net/netconf/junos/1.0",
        ];
        for namespace in valid {
            assert!(
                repair_cluster_commit_check(&marker_reply(namespace)).is_some(),
                "repository marker namespace was rejected: {namespace}"
            );
            assert!(
                repair_cluster_commit_check(&container_reply(namespace)).is_some(),
                "repository container namespace was rejected: {namespace}"
            );
        }
    }

    #[test]
    fn recognizes_only_top_level_unbound_or_juniper_multi_re_containers() {
        let cases = [
            (
                "prefixed vendor container",
                r#"<rpc-reply xmlns:v="urn:vendor" message-id="1">
                  <v:multi-routing-engine-results>
                    <routing-engine><commit-check-success/><ok/>
                  </v:multi-routing-engine-results>
                </rpc-reply>"#,
            ),
            (
                "unbound prefixed container",
                r#"<rpc-reply message-id="1">
                  <v:multi-routing-engine-results>
                    <routing-engine><commit-check-success/><ok/>
                  </v:multi-routing-engine-results>
                </rpc-reply>"#,
            ),
            (
                "default vendor container",
                r#"<rpc-reply message-id="1">
                  <multi-routing-engine-results xmlns="urn:vendor">
                    <routing-engine><commit-check-success/><ok/>
                  </multi-routing-engine-results>
                </rpc-reply>"#,
            ),
            (
                "arbitrarily nested container",
                r#"<rpc-reply message-id="1"><outer>
                  <multi-routing-engine-results>
                    <multi-routing-engine-item>
                      <routing-engine><commit-check-success/><ok/>
                    </multi-routing-engine-item>
                  </multi-routing-engine-results>
                </outer></rpc-reply>"#,
            ),
        ];

        for (path, xml) in cases {
            assert_eq!(
                repair_cluster_commit_check(xml),
                None,
                "{path} must not authorize repair"
            );
        }
    }

    #[test]
    fn rejects_routing_engines_below_unsupported_multi_re_descendant_chains() {
        let complete_error = "\
          <rpc-error>\
            <error-type>application</error-type>\
            <error-tag>operation-failed</error-tag>\
            <error-severity>error</error-severity>\
            <error-message>device failure</error-message>\
          </rpc-error>";
        let cases = [
            (
                "arbitrary wrapper directly below container",
                r#"<rpc-reply message-id="1"><multi-routing-engine-results>
                  <outer><routing-engine><commit-check-success/><ok/>
                  </outer>
                </multi-routing-engine-results></rpc-reply>"#
                    .to_string(),
            ),
            (
                "deep wrapper below recognized item",
                r#"<rpc-reply message-id="1"><multi-routing-engine-results>
                  <multi-routing-engine-item><outer>
                    <routing-engine><commit-check-success/><ok/>
                  </outer></multi-routing-engine-item>
                </multi-routing-engine-results></rpc-reply>"#
                    .to_string(),
            ),
            (
                "vendor item lookalike",
                r#"<rpc-reply xmlns:v="urn:vendor" message-id="1">
                  <multi-routing-engine-results><v:multi-routing-engine-item>
                    <routing-engine><commit-check-success/><ok/>
                  </v:multi-routing-engine-item></multi-routing-engine-results>
                </rpc-reply>"#
                    .to_string(),
            ),
            (
                "unbound-prefix item lookalike",
                r#"<rpc-reply message-id="1"><multi-routing-engine-results>
                  <v:multi-routing-engine-item>
                    <routing-engine><commit-check-success/><ok/>
                  </v:multi-routing-engine-item></multi-routing-engine-results>
                </rpc-reply>"#
                    .to_string(),
            ),
            (
                "complete rpc-error below arbitrary wrapper",
                format!(
                    "<rpc-reply message-id=\"1\"><multi-routing-engine-results>\
                       <outer><routing-engine>{complete_error}\
                       </outer>\
                     </multi-routing-engine-results></rpc-reply>"
                ),
            ),
        ];

        for (path, xml) in cases {
            assert_eq!(
                repair_cluster_commit_check(&xml),
                None,
                "{path} must not authorize repair"
            );
        }
    }

    #[test]
    fn accepts_unbound_and_juniper_qualified_repair_evidence() {
        let unbound = r#"<rpc-reply message-id="1">
          <multi-routing-engine-results><multi-routing-engine-item>
            <routing-engine><commit-check-success/><ok/>
          </multi-routing-engine-item></multi-routing-engine-results>
        </rpc-reply>"#;
        assert!(
            repair_cluster_commit_check(unbound).is_some(),
            "unbound compatibility names remain supported"
        );

        let qualified = r#"<nc:rpc-reply
          xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0"
          xmlns:j="http://xml.juniper.net/junos/25.4R1.12/junos"
          message-id="1"><j:multi-routing-engine-results>
            <j:multi-routing-engine-item>
              <j:routing-engine><j:commit-check-success/><nc:ok/>
            </j:multi-routing-engine-item>
          </j:multi-routing-engine-results>
        </nc:rpc-reply>"#;
        assert!(
            repair_cluster_commit_check(qualified).is_some(),
            "known Juniper XML namespaces remain supported"
        );
    }

    #[test]
    fn direct_routing_engine_requires_the_sole_root_rpc_reply() {
        let unsupported = [
            (
                "nested unqualified rpc-reply in data",
                r#"<rpc-reply message-id="1"><data>
                  <rpc-reply><routing-engine><commit-check-success/><ok/>
                  </rpc-reply>
                </data></rpc-reply>"#,
            ),
            (
                "nested qualified rpc-reply in data",
                r#"<nc:rpc-reply
                  xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0"
                  message-id="1"><nc:data><nc:rpc-reply>
                    <routing-engine><commit-check-success/><nc:ok/>
                  </nc:rpc-reply></nc:data></nc:rpc-reply>"#,
            ),
            (
                "rpc-reply below arbitrary document root",
                r#"<outer><rpc-reply><routing-engine>
                  <commit-check-success/><ok/>
                </rpc-reply></outer>"#,
            ),
            (
                "nested rpc-reply below arbitrary reply child",
                r#"<rpc-reply message-id="1"><outer><rpc-reply>
                  <routing-engine><commit-check-success/><ok/>
                </rpc-reply></outer></rpc-reply>"#,
            ),
        ];
        for (path, xml) in unsupported {
            assert_eq!(
                repair_cluster_commit_check(xml),
                None,
                "{path} must not authorize direct repair"
            );
        }

        let supported = [
            r#"<rpc-reply message-id="1">
              <routing-engine><commit-check-success/><ok/>
            </rpc-reply>"#,
            r#"<nc:rpc-reply
              xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0"
              xmlns:j="http://xml.juniper.net/junos/25.4R1.12/junos"
              message-id="1"><j:routing-engine>
                <j:commit-check-success/><nc:ok/>
            </nc:rpc-reply>"#,
        ];
        for xml in supported {
            assert!(
                repair_cluster_commit_check(xml).is_some(),
                "sole root rpc-reply must retain direct repair"
            );
        }
    }

    #[test]
    fn requires_exactly_one_top_level_rpc_reply_envelope() {
        let reply = r#"<rpc-reply message-id="1">
          <routing-engine><commit-check-success/><ok/>
        </rpc-reply>"#;
        let cases = [
            ("trailing empty element", format!("{reply}<outer/>")),
            ("preceding empty element", format!("<outer/>{reply}")),
            (
                "trailing non-empty element",
                format!("{reply}<outer></outer>"),
            ),
            (
                "preceding non-empty element",
                format!("<outer></outer>{reply}"),
            ),
            ("two rpc-reply roots", format!("{reply}{reply}")),
            (
                "empty rpc-reply before repair candidate",
                format!("<rpc-reply/>{reply}"),
            ),
            (
                "empty rpc-reply after repair candidate",
                format!("{reply}<rpc-reply/>"),
            ),
        ];

        for (path, xml) in cases {
            assert_eq!(
                repair_cluster_commit_check(&xml),
                None,
                "{path} must not cross a document-root boundary"
            );
        }
    }

    #[test]
    fn does_not_rewrite_a_well_formed_reply() {
        let xml = r#"<rpc-reply message-id="1"><routing-engine><commit-check-success/></routing-engine></rpc-reply>"#;

        assert_eq!(repair_cluster_commit_check(xml), None);
    }
}
