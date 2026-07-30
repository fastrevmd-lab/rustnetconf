use quick_xml::events::{BytesEnd, Event};
use quick_xml::{Reader, Writer};

#[derive(Debug)]
struct OpenElement {
    qname: Vec<u8>,
    local: Vec<u8>,
    routing_engine_supported: bool,
    routing_engine_has_marker: bool,
}

impl OpenElement {
    fn ordinary(qname: &[u8]) -> Self {
        Self {
            qname: qname.to_vec(),
            local: local_name(qname).to_vec(),
            routing_engine_supported: false,
            routing_engine_has_marker: false,
        }
    }

    fn routing_engine(qname: &[u8], supported: bool) -> Self {
        Self {
            qname: qname.to_vec(),
            local: b"routing-engine".to_vec(),
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

fn supported_routing_engine_parent(stack: &[OpenElement]) -> bool {
    stack
        .last()
        .is_some_and(|element| element.local == b"rpc-reply")
        || (!stack.iter().any(|element| element.local == b"data")
            && stack
                .iter()
                .any(|element| element.local == b"multi-routing-engine-results"))
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
        .any(|element| element.local == b"data")
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

pub(super) fn repair_cluster_commit_check(xml: &str) -> Option<String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().check_end_names = false;

    let mut writer = Writer::new(Vec::new());
    let mut stack: Vec<OpenElement> = Vec::new();
    let mut repaired_any = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(tag)) => {
                let qname = tag.name();
                let local = local_name(qname.as_ref());

                if matches!(local, b"commit-check-success" | b"rpc-error") {
                    mark_commit_check_result(&mut stack);
                }

                if local == b"routing-engine" {
                    if stack
                        .last()
                        .is_some_and(|element| element.local == b"routing-engine")
                    {
                        close_repairable(&mut writer, &mut stack)?;
                        repaired_any = true;
                    }
                    let supported = supported_routing_engine_parent(&stack);
                    stack.push(OpenElement::routing_engine(qname.as_ref(), supported));
                } else {
                    stack.push(OpenElement::ordinary(qname.as_ref()));
                }

                writer.write_event(Event::Start(tag.into_owned())).ok()?;
            }
            Ok(Event::Empty(tag)) => {
                if matches!(
                    local_name(tag.name().as_ref()),
                    b"commit-check-success" | b"rpc-error"
                ) {
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
        let xml = r#"<nc:rpc-reply xmlns:nc="urn:nc" message-id="1"><j:routing-engine xmlns:j="urn:j" note="a&amp;b"><j:commit-check-success/><nc:ok/></nc:rpc-reply>"#;
        let expected = r#"<nc:rpc-reply xmlns:nc="urn:nc" message-id="1"><j:routing-engine xmlns:j="urn:j" note="a&amp;b"><j:commit-check-success/><nc:ok/></j:routing-engine></nc:rpc-reply>"#;

        assert_eq!(repair_cluster_commit_check(xml).as_deref(), Some(expected));
    }

    #[test]
    fn does_not_rewrite_a_well_formed_reply() {
        let xml = r#"<rpc-reply message-id="1"><routing-engine><commit-check-success/></routing-engine></rpc-reply>"#;

        assert_eq!(repair_cluster_commit_check(xml), None);
    }
}
