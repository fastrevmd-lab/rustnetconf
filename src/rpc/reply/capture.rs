use crate::error::RpcError;
use crate::rpc::operations::{escape_xml_attr, escape_xml_text};
use quick_xml::events::{BytesCData, BytesEnd, BytesRef, BytesStart, BytesText};
use std::collections::{BTreeMap, HashSet};
use std::str;

pub(super) type NamespaceBindings = BTreeMap<String, String>;

pub(super) const XML_NAMESPACE: &str = "http://www.w3.org/XML/1998/namespace";
const XMLNS_NAMESPACE: &str = "http://www.w3.org/2000/xmlns/";

#[derive(Debug, Clone, Copy)]
pub(super) struct ValidatedQName<'a> {
    pub(super) prefix: Option<&'a str>,
}

#[derive(Debug, Default)]
pub(super) struct FragmentCapture {
    xml: String,
    depth: usize,
    inherited_namespaces: NamespaceBindings,
}

impl FragmentCapture {
    pub(super) fn with_namespaces(inherited_namespaces: NamespaceBindings) -> Self {
        Self {
            inherited_namespaces,
            ..Self::default()
        }
    }

    pub(super) fn start(&mut self, tag: &BytesStart<'_>) -> Result<(), RpcError> {
        self.write_start_like(tag, false)?;
        self.depth += 1;
        Ok(())
    }

    pub(super) fn empty(&mut self, tag: &BytesStart<'_>) -> Result<(), RpcError> {
        self.write_start_like(tag, true)
    }

    pub(super) fn end(&mut self, tag: &BytesEnd<'_>) -> Result<(), RpcError> {
        if self.depth == 0 {
            return Err(parse_error(
                "captured XML fragment contains an unmatched end tag".to_string(),
            ));
        }
        let binding = tag.name();
        let name = str::from_utf8(binding.as_ref())
            .map_err(|error| parse_error(format!("invalid end-tag name: {error}")))?;
        self.xml.push_str("</");
        self.xml.push_str(name);
        self.xml.push('>');
        self.depth -= 1;
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
        crate::xml_entity::resolve_entity_ref(entity)
            .filter(|value| value.chars().all(is_valid_xml_char))
            .ok_or_else(|| parse_error("invalid entity reference".to_string()))?;
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
        let mut attributes = Vec::new();
        let mut explicit_namespaces = HashSet::new();
        for attribute in tag.attributes().with_checks(true) {
            let attribute = attribute
                .map_err(|error| parse_error(format!("invalid XML attribute: {error}")))?;
            let key = str::from_utf8(attribute.key.as_ref())
                .map_err(|error| parse_error(format!("invalid attribute name: {error}")))?;
            let value = decode_attribute(attribute.value.as_ref(), "captured XML attribute value")?;
            if let Some(prefix) = namespace_prefix(key)? {
                explicit_namespaces.insert(prefix.to_string());
            }
            attributes.push((key.to_string(), value));
        }

        self.xml.push('<');
        self.xml.push_str(name);

        if self.depth == 0 {
            for (prefix, value) in &self.inherited_namespaces {
                if explicit_namespaces.contains(prefix) {
                    continue;
                }
                self.xml.push(' ');
                self.xml.push_str("xmlns");
                if !prefix.is_empty() {
                    self.xml.push(':');
                    self.xml.push_str(prefix);
                }
                self.xml.push_str("=\"");
                self.xml.push_str(&escape_xml_attr(value));
                self.xml.push('"');
            }
        }

        for (key, value) in attributes {
            self.xml.push(' ');
            self.xml.push_str(&key);
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

pub(super) fn namespace_declarations(tag: &BytesStart<'_>) -> Result<NamespaceBindings, RpcError> {
    let mut declarations = NamespaceBindings::new();
    for attribute in tag.attributes().with_checks(true) {
        let attribute =
            attribute.map_err(|error| parse_error(format!("invalid XML attribute: {error}")))?;
        let key = str::from_utf8(attribute.key.as_ref())
            .map_err(|error| parse_error(format!("invalid attribute name: {error}")))?;
        let Some(prefix) = namespace_prefix(key)? else {
            continue;
        };
        let value = decode_attribute(attribute.value.as_ref(), "namespace declaration value")?;
        validate_namespace_binding(prefix, &value)?;
        if prefix != "xml" {
            declarations.insert(prefix.to_string(), value);
        }
    }
    Ok(declarations)
}

pub(super) fn validate_qname(raw: &[u8]) -> Result<ValidatedQName<'_>, RpcError> {
    let name =
        str::from_utf8(raw).map_err(|_| parse_error("invalid QName encoding".to_string()))?;
    let mut parts = name.split(':');
    let first = parts
        .next()
        .expect("split always yields at least one component");
    let second = parts.next();
    if parts.next().is_some() {
        return Err(parse_error(
            "QName contains more than one namespace separator".to_string(),
        ));
    }

    let (prefix, local) = if let Some(local) = second {
        (Some(first), local)
    } else {
        (None, first)
    };
    if let Some(prefix) = prefix {
        validate_ncname(prefix, "QName prefix")?;
    }
    validate_ncname(local, "QName local name")?;
    Ok(ValidatedQName { prefix })
}

pub(super) fn is_namespace_declaration(attribute_name: &[u8]) -> bool {
    attribute_name == b"xmlns" || attribute_name.starts_with(b"xmlns:")
}

fn namespace_prefix(attribute_name: &str) -> Result<Option<&str>, RpcError> {
    if attribute_name == "xmlns" {
        return Ok(Some(""));
    }
    let Some(prefix) = attribute_name.strip_prefix("xmlns:") else {
        return Ok(None);
    };
    validate_ncname(prefix, "namespace declaration prefix")?;
    Ok(Some(prefix))
}

fn validate_namespace_binding(prefix: &str, namespace: &str) -> Result<(), RpcError> {
    if prefix == "xmlns" {
        return Err(parse_error(
            "the xmlns namespace prefix cannot be declared".to_string(),
        ));
    }
    if prefix == "xml" && namespace != XML_NAMESPACE {
        return Err(parse_error(
            "the xml prefix has an invalid namespace binding".to_string(),
        ));
    }
    if prefix != "xml" && namespace == XML_NAMESPACE {
        return Err(parse_error(
            "only the xml prefix may use the reserved XML namespace".to_string(),
        ));
    }
    if namespace == XMLNS_NAMESPACE {
        return Err(parse_error(
            "the reserved xmlns namespace cannot be bound".to_string(),
        ));
    }
    if !prefix.is_empty() && namespace.is_empty() {
        return Err(parse_error(
            "a namespace prefix cannot have an empty binding".to_string(),
        ));
    }
    Ok(())
}

fn validate_ncname(name: &str, field: &str) -> Result<(), RpcError> {
    let mut chars = name.chars();
    if !chars.next().is_some_and(is_ncname_start) || !chars.all(is_ncname_char) {
        return Err(parse_error(format!("invalid {field}")));
    }
    Ok(())
}

fn is_ncname_start(value: char) -> bool {
    matches!(
        value as u32,
        0x41..=0x5A
            | 0x5F
            | 0x61..=0x7A
            | 0xC0..=0xD6
            | 0xD8..=0xF6
            | 0xF8..=0x2FF
            | 0x370..=0x37D
            | 0x37F..=0x1FFF
            | 0x200C..=0x200D
            | 0x2070..=0x218F
            | 0x2C00..=0x2FEF
            | 0x3001..=0xD7FF
            | 0xF900..=0xFDCF
            | 0xFDF0..=0xFFFD
            | 0x10000..=0xEFFFF
    )
}

fn is_ncname_char(value: char) -> bool {
    is_ncname_start(value)
        || matches!(
            value as u32,
            0x2D | 0x2E | 0x30..=0x39 | 0xB7 | 0x300..=0x36F | 0x203F..=0x2040
        )
}

fn is_valid_xml_char(value: char) -> bool {
    matches!(
        value as u32,
        0x9 | 0xA | 0xD | 0x20..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF
    )
}

pub(super) fn decode_attribute(raw: &[u8], field: &'static str) -> Result<String, RpcError> {
    let raw = str::from_utf8(raw).map_err(|_| parse_error(format!("invalid {field} encoding")))?;
    quick_xml::escape::unescape(raw)
        .map(|value| value.into_owned())
        .map_err(|_| parse_error(format!("invalid {field}")))
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
