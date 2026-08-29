use super::lexical::{
    decode_attribute, is_valid_xml_char, validate_ncname, validate_text_lexical, validate_xml_chars,
};
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
    pub(super) local: &'a str,
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
        let name = binding.as_ref();
        self.xml.push_str("</");
        self.xml.push_str(name);
        self.xml.push('>');
        self.depth -= 1;
        Ok(())
    }

    pub(super) fn text(&mut self, text: &BytesText<'_>) -> Result<(), RpcError> {
        validate_text_lexical(text.as_ref())?;
        let decoded = text.xml10_content();
        validate_xml_chars(&decoded, "text content")?;
        self.xml.push_str(&escape_xml_text(&decoded));
        Ok(())
    }

    pub(super) fn cdata(&mut self, cdata: &BytesCData<'_>) -> Result<(), RpcError> {
        let decoded = cdata.xml10_content();
        validate_xml_chars(&decoded, "CDATA content")?;
        self.xml.push_str(&escape_xml_text(&decoded));
        Ok(())
    }

    pub(super) fn entity(&mut self, entity: &BytesRef<'_>) -> Result<(), RpcError> {
        // quick-xml 0.42 decodes at the reader, so the event already holds
        // `str`; there is no per-event decode step and no encoding error to
        // surface here any more.
        let decoded: &str = entity;
        crate::xml_entity::resolve_entity_ref(entity)
            .filter(|value| value.chars().all(is_valid_xml_char))
            .ok_or_else(|| parse_error("invalid entity reference".to_string()))?;
        self.xml.push('&');
        self.xml.push_str(decoded);
        self.xml.push(';');
        Ok(())
    }

    pub(super) fn finish(self) -> Result<String, RpcError> {
        Ok(self.xml)
    }

    fn write_start_like(&mut self, tag: &BytesStart<'_>, empty: bool) -> Result<(), RpcError> {
        let binding = tag.name();
        let name = binding.as_ref();
        let mut attributes = Vec::new();
        let mut explicit_namespaces = HashSet::new();
        for attribute in tag.attributes().with_checks(true) {
            let attribute = attribute
                .map_err(|error| parse_error(format!("invalid XML attribute: {error}")))?;
            let key = attribute.key.as_ref();
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
                self.xml.push_str(&escape_captured_xml_attr(value));
                self.xml.push('"');
            }
        }

        for (key, value) in attributes {
            self.xml.push(' ');
            self.xml.push_str(&key);
            self.xml.push_str("=\"");
            self.xml.push_str(&escape_captured_xml_attr(&value));
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

fn escape_captured_xml_attr(value: &str) -> String {
    let escaped = escape_xml_attr(value);
    if !escaped.contains(['\t', '\n', '\r']) {
        return escaped;
    }

    let mut preserved = String::with_capacity(escaped.len());
    for value in escaped.chars() {
        match value {
            '\t' => preserved.push_str("&#x9;"),
            '\n' => preserved.push_str("&#xA;"),
            '\r' => preserved.push_str("&#xD;"),
            _ => preserved.push(value),
        }
    }
    preserved
}

pub(super) fn namespace_declarations(tag: &BytesStart<'_>) -> Result<NamespaceBindings, RpcError> {
    let mut declarations = NamespaceBindings::new();
    for attribute in tag.attributes().with_checks(true) {
        let attribute =
            attribute.map_err(|error| parse_error(format!("invalid XML attribute: {error}")))?;
        let key = attribute.key.as_ref();
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

pub(super) fn validate_qname(name: &str) -> Result<ValidatedQName<'_>, RpcError> {
    // quick-xml 0.42 decodes at the reader, so names arrive as `str` and the
    // UTF-8 check that used to guard this is unreachable rather than removed.
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
    Ok(ValidatedQName { prefix, local })
}

pub(super) fn is_namespace_declaration(attribute_name: &str) -> bool {
    attribute_name == "xmlns" || attribute_name.starts_with("xmlns:")
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
