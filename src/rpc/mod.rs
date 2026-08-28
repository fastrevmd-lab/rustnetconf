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
    // Depth inside the synthetic root. It must return to zero, and the check
    // cannot be left to the parser: quick-xml reports EOF without error when
    // elements are still open, because more input could always follow.
    //
    // A fragment ending in a bare `<` is why this matters. quick-xml reads
    // `<</b>` as the *start* of an element named `</b`, so the fragment eats
    // the closing tag of whatever encloses it. Under the `<_>` wrapper that
    // merely leaves something unclosed at EOF and looks fine; spliced into a
    // real envelope it corrupts the document:
    //
    //     <a><b>{fragment}</b></a>
    //     -> ill-formed document: expected `</</b>`, but `</a>` was found
    //
    // Found by the `fragment_embeds_cleanly` fuzz target in under a minute.
    let mut depth: i64 = 0;
    let mut saw_root_close = false;

    loop {
        // Anything after the synthetic root closes is outside it.
        if saw_root_close && depth == 0 {
            // Peek: only EOF may follow.
            match reader.read_event_into(&mut buf) {
                Ok(Event::Eof) => break,
                Ok(_) | Err(_) => {
                    return Err(ProtocolError::Xml(
                        "XML fragment closes an element it did not open; embedding it \
                         would leave an unmatched closing tag in the document"
                            .to_string(),
                    ));
                }
            }
        }
        match reader.read_event_into(&mut buf) {
            Ok(Event::Eof) => {
                // The synthetic root opens and closes, so a balanced fragment
                // returns to zero. A non-zero depth means the fragment left an
                // element open — including the case where a bare `<` ate the
                // wrapper's own closing tag.
                if depth != 0 {
                    return Err(ProtocolError::Xml(
                        "XML fragment is not balanced: it opens elements it does not \
                         close, so embedding it would consume the enclosing element's \
                         closing tag"
                            .to_string(),
                    ));
                }
                break;
            }
            Ok(Event::Start(_)) => depth += 1,
            Ok(Event::End(_)) => {
                depth -= 1;
                // Reaching zero before EOF means the fragment closed the
                // synthetic root itself. `</_>x<_>` is balanced overall, so a
                // net-depth check accepts it — but the closing tag it supplied
                // is unmatched once the fragment is spliced somewhere real, and
                // everything after it sits outside the wrapper entirely.
                //
                // This is the synthetic root leaking into the language being
                // validated: the fragment can name it and balance against it.
                // Found by the `fragment_embeds_cleanly` fuzz target.
                if depth == 0 {
                    saw_root_close = true;
                }
            }
            // A fragment is embedded inside an RPC we have already opened with
            // its own declaration. An `<?xml ...?>` here would put a second
            // declaration mid-document, which is malformed however well-formed
            // the fragment looked on its own — and the synthetic `<_>` root
            // above is exactly what hides that from the parser.
            Ok(Event::Decl(_)) => {
                return Err(ProtocolError::Xml(
                    "XML fragment must not contain a document declaration; strip the                      leading `<?xml ...?>` before embedding it"
                        .to_string(),
                ));
            }
            // Likewise a DOCTYPE, which additionally carries the entity
            // machinery behind XXE and entity-expansion attacks.
            Ok(Event::DocType(_)) => {
                return Err(ProtocolError::Xml(
                    "XML fragment must not contain a DOCTYPE declaration".to_string(),
                ));
            }
            // quick-xml does not police the `Char` production, so a C0 control
            // slips through Text/CDATA and produces a document a strict parser
            // rejects. Same validator/parser disagreement, different axis.
            Ok(Event::Text(ref t)) => {
                let decoded = t.decode().map_err(|e| {
                    ProtocolError::Xml(format!("XML fragment text is not decodable: {e}"))
                })?;
                if !decoded
                    .chars()
                    .all(crate::rpc::reply::lexical::is_valid_xml_char)
                {
                    return Err(ProtocolError::Xml(
                        "XML fragment contains a character XML 1.0 cannot represent".to_string(),
                    ));
                }
            }
            Ok(Event::CData(ref c)) => {
                let decoded = c.decode().map_err(|e| {
                    ProtocolError::Xml(format!("XML fragment CDATA is not decodable: {e}"))
                })?;
                if !decoded
                    .chars()
                    .all(crate::rpc::reply::lexical::is_valid_xml_char)
                {
                    return Err(ProtocolError::Xml(
                        "XML fragment contains a character XML 1.0 cannot represent".to_string(),
                    ));
                }
            }
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

#[cfg(test)]
mod fragment_validation_tests {
    use super::validate_xml_fragment;

    #[test]
    fn rejects_document_declaration() {
        let err = validate_xml_fragment("<?xml version=\"1.0\"?><system/>")
            .expect_err("a declaration cannot be embedded");
        assert!(err.to_string().contains("declaration"), "got {err}");
    }

    #[test]
    fn rejects_doctype() {
        assert!(validate_xml_fragment("<!DOCTYPE x><system/>").is_err());
    }

    #[test]
    fn rejects_a_trailing_bare_left_angle_bracket() {
        // The fuzz finding: quick-xml reads `<</b>` as a start tag named `</b`,
        // so the fragment consumes the closing tag of whatever encloses it.
        let err = validate_xml_fragment("<").expect_err("a bare < is unbalanced");
        assert!(err.to_string().contains("balanced"), "got {err}");
        assert!(validate_xml_fragment("\u{4}\n\n<").is_err());
        assert!(validate_xml_fragment("<a/>text<").is_err());
    }

    #[test]
    fn rejects_unbalanced_fragments() {
        assert!(validate_xml_fragment("<a>").is_err());
        assert!(validate_xml_fragment("<a><b></b>").is_err());
        // Balanced ones still pass.
        validate_xml_fragment("<a></a>").unwrap();
        validate_xml_fragment("<a/><b/>").unwrap();
    }

    #[test]
    fn rejects_characters_xml_cannot_represent() {
        assert!(validate_xml_fragment("<a>\u{4}</a>").is_err());
        assert!(validate_xml_fragment("<a>\u{fffe}</a>").is_err());
        assert!(validate_xml_fragment("<a><![CDATA[\u{1}]]></a>").is_err());
        // TAB/LF/CR are legal.
        validate_xml_fragment("<a>\t\n\r</a>").unwrap();
    }

    #[test]
    fn still_accepts_ordinary_fragments() {
        validate_xml_fragment("<system><host-name>r1</host-name></system>").unwrap();
        validate_xml_fragment("<a/><b/>").unwrap();
        validate_xml_fragment("<!-- a comment --><a/>").unwrap();
        validate_xml_fragment("").unwrap();
    }
}
