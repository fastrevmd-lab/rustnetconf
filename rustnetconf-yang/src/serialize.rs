//! XML serialization helpers for YANG-generated types.
//!
//! Converts YANG-typed Rust structs into NETCONF-compatible XML for
//! use with `edit_config()` and deserializes XML responses back into
//! typed structs.

use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
pub use quick_xml::Writer;
pub use std::io::Cursor;

/// Trait for types that can serialize their child fields into an XML writer.
///
/// Implemented by the code generator for all YANG structs (containers and list
/// entries). This allows containers and list entries to embed their XML into a
/// parent writer without creating a standalone document.
pub trait WriteXmlFields {
    /// Write this value's child elements into `writer`.
    ///
    /// Does **not** write the surrounding element start/end tags — the caller
    /// is responsible for those. This makes it easy to compose nested XML.
    fn write_xml_fields(&self, writer: &mut Writer<Cursor<Vec<u8>>>) -> Result<(), XmlError>;
}

/// Trait for types that can be serialized to NETCONF XML.
///
/// Implemented by the code generator for each YANG container/list.
pub trait ToNetconfXml: WriteXmlFields {
    /// The YANG module namespace URI.
    fn namespace(&self) -> &str;

    /// The root element name.
    fn root_element(&self) -> &str;

    /// Serialize this value to NETCONF-compatible XML.
    fn to_xml(&self) -> Result<String, XmlError>;
}

/// Trait for types that can be deserialized from NETCONF XML.
pub trait FromNetconfXml: Sized {
    /// Deserialize from an XML string.
    fn from_xml(xml: &str) -> Result<Self, XmlError>;
}

/// XML serialization/deserialization error.
#[derive(Debug, thiserror::Error)]
pub enum XmlError {
    #[error("XML write error: {0}")]
    Write(String),

    #[error("XML parse error: {0}")]
    Parse(String),

    #[error("missing required field: {0}")]
    MissingField(String),

    #[error("invalid value for field '{field}': {message}")]
    InvalidValue { field: String, message: String },
}

/// Helper to write an XML element with text content.
pub fn write_text_element(
    writer: &mut Writer<Cursor<Vec<u8>>>,
    name: &str,
    value: &str,
) -> Result<(), XmlError> {
    let start = BytesStart::new(name);
    writer
        .write_event(Event::Start(start))
        .map_err(|e| XmlError::Write(e.to_string()))?;
    writer
        .write_event(Event::Text(BytesText::new(value)))
        .map_err(|e| XmlError::Write(e.to_string()))?;
    writer
        .write_event(Event::End(BytesEnd::new(name)))
        .map_err(|e| XmlError::Write(e.to_string()))?;
    Ok(())
}

/// Helper to write an XML element with a namespace attribute.
pub fn write_start_with_ns(
    writer: &mut Writer<Cursor<Vec<u8>>>,
    name: &str,
    namespace: &str,
) -> Result<(), XmlError> {
    let mut start = BytesStart::new(name);
    start.push_attribute(("xmlns", namespace));
    writer
        .write_event(Event::Start(start))
        .map_err(|e| XmlError::Write(e.to_string()))?;
    Ok(())
}

/// Helper to write a closing element.
pub fn write_end(
    writer: &mut Writer<Cursor<Vec<u8>>>,
    name: &str,
) -> Result<(), XmlError> {
    writer
        .write_event(Event::End(BytesEnd::new(name)))
        .map_err(|e| XmlError::Write(e.to_string()))?;
    Ok(())
}

/// Write a named XML element whose content comes from a [`WriteXmlFields`] value.
///
/// Writes `<name>`, calls `value.write_xml_fields()`, then writes `</name>`.
pub fn write_element_with_fields<T: WriteXmlFields>(
    writer: &mut Writer<Cursor<Vec<u8>>>,
    name: &str,
    value: &T,
) -> Result<(), XmlError> {
    writer
        .write_event(Event::Start(BytesStart::new(name)))
        .map_err(|e| XmlError::Write(e.to_string()))?;
    value.write_xml_fields(writer)?;
    writer
        .write_event(Event::End(BytesEnd::new(name)))
        .map_err(|e| XmlError::Write(e.to_string()))?;
    Ok(())
}

/// Create a new XML writer.
pub fn new_writer() -> Writer<Cursor<Vec<u8>>> {
    Writer::new_with_indent(Cursor::new(Vec::new()), b' ', 2)
}

/// Extract the XML string from a writer.
pub fn finish_writer(writer: Writer<Cursor<Vec<u8>>>) -> Result<String, XmlError> {
    let buf = writer.into_inner().into_inner();
    String::from_utf8(buf).map_err(|e| XmlError::Write(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_text_element() {
        let mut writer = new_writer();
        write_text_element(&mut writer, "host-name", "spine-01").unwrap();
        let xml = finish_writer(writer).unwrap();
        assert_eq!(xml, "<host-name>spine-01</host-name>");
    }

    #[test]
    fn test_write_start_with_ns() {
        let mut writer = new_writer();
        write_start_with_ns(&mut writer, "interfaces", "urn:ietf:params:xml:ns:yang:ietf-interfaces").unwrap();
        write_end(&mut writer, "interfaces").unwrap();
        let xml = finish_writer(writer).unwrap();
        assert!(xml.contains("xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""));
    }
}
