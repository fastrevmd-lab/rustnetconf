//! NETCONF RPC serialization and response parsing.
//!
//! Handles converting typed RPC operations into XML messages and
//! parsing XML responses back into typed results.

pub mod filter;
pub mod operations;

pub(crate) mod reply;

pub use reply::{parse_rpc_reply, RpcErrorInfo, RpcReply};

use crate::error::ProtocolError;

/// Validate that an XML fragment is well-formed before insertion into an RPC.
///
/// This library is a caller-controlled API — callers construct XML intentionally.
/// Validation here is not meant to sanitize untrusted content (callers bear that
/// responsibility), but to catch programming errors and malformed fragments early,
/// before they corrupt the framed NETCONF message on the wire.
///
/// The fragment is wrapped in a synthetic root element to allow multiple sibling
/// elements at the top level, and parsed with `check_end_names` enabled to catch
/// mismatched or unclosed tags.
///
/// An empty string passes validation (used to represent "no filter/content").
///
/// # Errors
///
/// Returns `ProtocolError::Xml` if the fragment contains XML parse errors such
/// as unclosed tags, mismatched element names, or invalid syntax.
///
/// # Examples
///
/// ```rust
/// use rustnetconf::rpc::validate_xml_fragment;
///
/// // Valid fragment
/// validate_xml_fragment("<interfaces><interface><name>ge-0/0/0</name></interface></interfaces>").unwrap();
///
/// // Empty string is allowed
/// validate_xml_fragment("").unwrap();
///
/// // Malformed fragment returns an error
/// assert!(validate_xml_fragment("<unclosed>").is_err());
/// ```
pub fn validate_xml_fragment(xml: &str) -> Result<(), ProtocolError> {
    if xml.is_empty() {
        return Ok(());
    }

    use quick_xml::events::Event;
    use quick_xml::Reader;

    // Wrap in a synthetic root so multi-sibling fragments parse as a single document.
    let wrapped = format!("<_>{xml}</_>");

    let mut reader = Reader::from_str(&wrapped);
    reader.config_mut().check_end_names = true;
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(ProtocolError::Xml(format!(
                    "XML fragment is not well-formed: {e}"
                )));
            }
            _ => {}
        }
        buf.clear();
    }

    Ok(())
}

#[cfg(test)]
mod xml_validate_tests {
    use super::*;

    #[test]
    fn test_valid_xml_fragment() {
        assert!(validate_xml_fragment(
            "<interfaces><interface><name>ge-0/0/0</name></interface></interfaces>"
        )
        .is_ok());
    }

    #[test]
    fn test_valid_self_closing() {
        assert!(validate_xml_fragment("<filter/>").is_ok());
    }

    #[test]
    fn test_valid_multiple_siblings() {
        assert!(validate_xml_fragment("<a/><b/><c/>").is_ok());
    }

    #[test]
    fn test_empty_string_is_valid() {
        assert!(validate_xml_fragment("").is_ok());
    }

    #[test]
    fn test_unclosed_tag_is_invalid() {
        let result = validate_xml_fragment("<unclosed>");
        assert!(result.is_err(), "unclosed tag should fail validation");
        let err = format!("{}", result.unwrap_err());
        assert!(
            err.contains("not well-formed"),
            "error should mention not well-formed: {err}"
        );
    }

    #[test]
    fn test_mismatched_tags_is_invalid() {
        let result = validate_xml_fragment("<a></b>");
        assert!(result.is_err(), "mismatched tags should fail validation");
    }

    #[test]
    fn test_malformed_attribute_is_invalid() {
        let result = validate_xml_fragment("<a b=broken>");
        assert!(
            result.is_err(),
            "malformed attribute should fail validation"
        );
    }
}
