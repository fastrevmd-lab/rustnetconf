use super::capture::{namespace_declarations, NamespaceBindings};
use quick_xml::events::{BytesEnd, BytesStart, Event};
use quick_xml::{Reader, Writer};

#[derive(Debug)]
struct OpenElement {
    qname: Vec<u8>,
    local: Vec<u8>,
    protocol_local: Option<Vec<u8>>,
    namespaces: NamespaceBindings,
    supported_multi_re_container: bool,
    routing_engine_supported: bool,
    routing_engine_has_marker: bool,
}

impl OpenElement {
    fn ordinary(
        qname: &[u8],
        namespaces: NamespaceBindings,
        supported_multi_re_container: bool,
    ) -> Self {
        Self {
            qname: qname.to_vec(),
            local: local_name(qname).to_vec(),
            protocol_local: netconf_local_name(qname, &namespaces).map(<[u8]>::to_vec),
            namespaces,
            supported_multi_re_container,
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
            supported_multi_re_container: false,
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
/// `http://xml.juniper.net/` authority followed by a non-empty family path.
/// Keeping the authority and scheme exact rejects lookalike hosts and unrelated
/// default namespaces while allowing versioned Junos, XNM, and NETCONF URIs.
fn is_juniper_xml_namespace(namespace: &str) -> bool {
    namespace
        .strip_prefix("http://xml.juniper.net/")
        .is_some_and(|family| !family.is_empty())
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
    stack
        .last()
        .is_some_and(|element| element.protocol_local.as_deref() == Some(b"rpc-reply"))
        || (!stack
            .iter()
            .any(|element| element.protocol_local.as_deref() == Some(b"data"))
            && stack
                .iter()
                .any(|element| element.supported_multi_re_container))
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
        let supported_multi_re_container = juniper_local_name(qname.as_ref(), &namespaces)
            == Some(b"multi-routing-engine-results")
            && stack.len() == 1
            && stack
                .last()
                .is_some_and(|element| element.protocol_local.as_deref() == Some(b"rpc-reply"));
        stack.push(OpenElement::ordinary(
            qname.as_ref(),
            namespaces,
            supported_multi_re_container,
        ));
    }

    writer.write_event(Event::Start(tag.into_owned())).ok()
}

pub(super) fn repair_cluster_commit_check(xml: &str) -> Option<String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().check_end_names = false;

    let mut writer = Writer::new(Vec::new());
    let mut stack: Vec<OpenElement> = Vec::new();
    let mut repaired_any = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(tag)) => {
                handle_start(tag, &mut writer, &mut stack, &mut repaired_any)?;
            }
            Ok(Event::Empty(tag)) => {
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
                if !stack.is_empty() || !repaired_any {
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
    fn does_not_rewrite_a_well_formed_reply() {
        let xml = r#"<rpc-reply message-id="1"><routing-engine><commit-check-success/></routing-engine></rpc-reply>"#;

        assert_eq!(repair_cluster_commit_check(xml), None);
    }
}
