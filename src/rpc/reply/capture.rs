use crate::error::RpcError;
use crate::rpc::operations::{escape_xml_attr, escape_xml_text};
use quick_xml::events::{BytesCData, BytesEnd, BytesRef, BytesStart, BytesText};
use std::str;

#[derive(Debug, Default)]
pub(super) struct FragmentCapture {
    xml: String,
}

impl FragmentCapture {
    pub(super) fn start(&mut self, tag: &BytesStart<'_>) -> Result<(), RpcError> {
        self.write_start_like(tag, false)
    }

    pub(super) fn empty(&mut self, tag: &BytesStart<'_>) -> Result<(), RpcError> {
        self.write_start_like(tag, true)
    }

    pub(super) fn end(&mut self, tag: &BytesEnd<'_>) -> Result<(), RpcError> {
        let binding = tag.name();
        let name = str::from_utf8(binding.as_ref())
            .map_err(|error| parse_error(format!("invalid end-tag name: {error}")))?;
        self.xml.push_str("</");
        self.xml.push_str(name);
        self.xml.push('>');
        Ok(())
    }

    pub(super) fn text(&mut self, text: &BytesText<'_>) -> Result<(), RpcError> {
        let decoded = text
            .decode()
            .map_err(|error| parse_error(format!("invalid text encoding: {error}")))?;
        self.xml.push_str(&escape_xml_text(&decoded));
        Ok(())
    }

    pub(super) fn cdata(&mut self, cdata: &BytesCData<'_>) -> Result<(), RpcError> {
        let decoded = cdata
            .decode()
            .map_err(|error| parse_error(format!("invalid CDATA encoding: {error}")))?;
        self.xml.push_str(&escape_xml_text(&decoded));
        Ok(())
    }

    pub(super) fn entity(&mut self, entity: &BytesRef<'_>) -> Result<(), RpcError> {
        let decoded = entity
            .decode()
            .map_err(|error| parse_error(format!("invalid entity encoding: {error}")))?;
        self.xml.push('&');
        self.xml.push_str(&decoded);
        self.xml.push(';');
        Ok(())
    }

    pub(super) fn finish(self) -> Result<String, RpcError> {
        Ok(self.xml)
    }

    fn write_start_like(&mut self, tag: &BytesStart<'_>, empty: bool) -> Result<(), RpcError> {
        let binding = tag.name();
        let name = str::from_utf8(binding.as_ref())
            .map_err(|error| parse_error(format!("invalid start-tag name: {error}")))?;
        self.xml.push('<');
        self.xml.push_str(name);

        for attribute in tag.attributes().with_checks(true) {
            let attribute = attribute
                .map_err(|error| parse_error(format!("invalid XML attribute: {error}")))?;
            let key = str::from_utf8(attribute.key.as_ref())
                .map_err(|error| parse_error(format!("invalid attribute name: {error}")))?;
            let value = decode_attribute(attribute.value.as_ref())?;

            self.xml.push(' ');
            self.xml.push_str(key);
            self.xml.push_str("=\"");
            self.xml.push_str(&escape_xml_attr(&value));
            self.xml.push('"');
        }

        if empty {
            self.xml.push_str("/>");
        } else {
            self.xml.push('>');
        }
        Ok(())
    }
}

pub(super) fn decode_attribute(raw: &[u8]) -> Result<String, RpcError> {
    let raw = str::from_utf8(raw)
        .map_err(|error| parse_error(format!("invalid attribute encoding: {error}")))?;
    quick_xml::escape::unescape(raw)
        .map(|value| value.into_owned())
        .map_err(|error| parse_error(format!("invalid attribute value: {error}")))
}

fn parse_error(message: String) -> RpcError {
    RpcError::ParseError(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use quick_xml::events::Event;
    use quick_xml::Reader;

    fn capture_children(xml: &str) -> Result<String, RpcError> {
        let mut reader = Reader::from_str(xml);
        let mut capture = FragmentCapture::default();
        let mut depth = 0usize;

        loop {
            match reader.read_event() {
                Ok(Event::Start(_tag)) if depth == 0 => depth = 1,
                Ok(Event::Start(tag)) => {
                    depth += 1;
                    capture.start(&tag)?;
                }
                Ok(Event::Empty(tag)) if depth > 0 => capture.empty(&tag)?,
                Ok(Event::Text(text)) if depth > 0 => capture.text(&text)?,
                Ok(Event::CData(cdata)) if depth > 0 => capture.cdata(&cdata)?,
                Ok(Event::GeneralRef(entity)) if depth > 0 => capture.entity(&entity)?,
                Ok(Event::End(_)) if depth == 1 => break,
                Ok(Event::End(tag)) if depth > 1 => {
                    capture.end(&tag)?;
                    depth -= 1;
                }
                Ok(Event::Eof) => {
                    return Err(RpcError::ParseError(
                        "test fragment ended before its root closed".to_string(),
                    ));
                }
                Ok(_) => {}
                Err(error) => {
                    return Err(RpcError::ParseError(format!(
                        "test XML parse error: {error}"
                    )));
                }
            }
        }

        capture.finish()
    }

    #[test]
    fn preserves_namespaces_attributes_entities_and_cdata() {
        let xml = r#"<root>
          <if:item xmlns:if="urn:example:if" note='core &amp; "edge"'>
            A &amp; B <![CDATA[<raw>]]>
          </if:item>
        </root>"#;

        let captured = capture_children(xml).expect("capture succeeds");
        assert!(captured.contains("<if:item"));
        assert!(captured.contains("xmlns:if=\"urn:example:if\""));
        assert!(captured.contains("note=\"core &amp; &quot;edge&quot;\""));
        assert!(captured.contains("A &amp; B"));
        assert!(captured.contains("&lt;raw&gt;"));
        crate::rpc::validate_xml_fragment(&captured).expect("captured XML is valid");
    }

    #[test]
    fn malformed_attribute_entity_is_an_error() {
        let xml = r#"<root><item note="bad &unknown; value"/></root>"#;
        let error = capture_children(xml).expect_err("unknown entity must fail");
        assert!(matches!(error, RpcError::ParseError(_)));
        assert!(error.to_string().contains("attribute"));
    }
}
