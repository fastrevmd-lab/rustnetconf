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
            Ok(Event::Start(ref e)) => {
                validate_name(e.name().as_ref())?;
                validate_attributes(e)?;
                depth += 1;
            }
            Ok(Event::Empty(ref e)) => {
                validate_name(e.name().as_ref())?;
                validate_attributes(e)?;
            }
            Ok(Event::End(ref e)) => {
                validate_name(e.name().as_ref())?;
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
                // XML 1.0 §2.4: a literal `]]>` may not appear in character
                // data — it would close a CDATA section early — and must be
                // written `]]&gt;`. quick-xml passes it through.
                if decoded.contains("]]>") {
                    return Err(ProtocolError::Xml(
                        "XML fragment contains a literal `]]>` in text; write `]]&gt;`".to_string(),
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
            // An entity reference the fragment relies on must actually resolve,
            // and to a character XML can represent. quick-xml streams these as
            // their own events and does not check either, so `&cmp;` (a typo of
            // `&amp;`) and `&#x4;` both pass through — and are then spliced into
            // the RPC verbatim for the *device* to reject. A conforming parser
            // refuses an undefined entity outright.
            //
            // Found by the `fragment_embeds_cleanly` fuzz target once its oracle
            // stopped being quick-xml, which is permissive here in the same way.
            // XML 1.0 §2.5: a comment's content may not contain `--`, and may
            // not end with `-`. quick-xml accepts `<!-->` and `<---->`; a
            // conforming parser rejects both.
            Ok(Event::Comment(ref c)) => {
                let body = std::str::from_utf8(c.as_ref()).map_err(|_| {
                    ProtocolError::Xml("XML fragment has a non-UTF-8 comment".to_string())
                })?;
                if body.contains("--") || body.ends_with('-') {
                    return Err(ProtocolError::Xml(
                        "XML fragment has a malformed comment: `--` may not appear \
                         inside one, nor `-` immediately before the close"
                            .to_string(),
                    ));
                }
                if !body
                    .chars()
                    .all(crate::rpc::reply::lexical::is_valid_xml_char)
                {
                    return Err(ProtocolError::Xml(
                        "XML fragment has a comment containing a character XML 1.0 \
                         cannot represent"
                            .to_string(),
                    ));
                }
            }
            // A processing instruction's target must be a Name, and may not be
            // `xml` in any case (XML 1.0 §2.6). quick-xml validates neither.
            Ok(Event::PI(ref pi)) => {
                let raw = pi.as_ref();
                let target_end = raw
                    .iter()
                    .position(|b| b.is_ascii_whitespace())
                    .unwrap_or(raw.len());
                let target = &raw[..target_end];
                // `Name`, not `NCName`. XML 1.0 §2.6 defines
                // `PITarget ::= Name - (('X'|'x')('M'|'m')('L'|'l'))`, and
                // `Name` permits a colon — the NCName constraint from
                // Namespaces in XML applies to element and attribute names, not
                // to PI targets. `<?a:b?>` is legal and roxmltree accepts it; an
                // earlier revision rejected it, which was a regression — twice:
                // first by requiring NCName, then by reusing `validate_name`,
                // which enforces QName and so still refused `<?a:b:c?>`.
                validate_pi_target(target)?;
                if target.eq_ignore_ascii_case(b"xml") {
                    return Err(ProtocolError::Xml(
                        "XML fragment has a processing instruction targeting `xml`, \
                         which is reserved"
                            .to_string(),
                    ));
                }
                let body = std::str::from_utf8(raw).map_err(|_| {
                    ProtocolError::Xml(
                        "XML fragment has a non-UTF-8 processing instruction".to_string(),
                    )
                })?;
                if !body
                    .chars()
                    .all(crate::rpc::reply::lexical::is_valid_xml_char)
                {
                    return Err(ProtocolError::Xml(
                        "XML fragment has a processing instruction containing a \
                         character XML 1.0 cannot represent"
                            .to_string(),
                    ));
                }
            }
            Ok(Event::GeneralRef(ref entity)) => {
                match crate::xml_entity::resolve_entity_ref(entity) {
                    Some(resolved) => {
                        if !resolved
                            .chars()
                            .all(crate::rpc::reply::lexical::is_valid_xml_char)
                        {
                            return Err(ProtocolError::Xml(
                                "XML fragment has a character reference outside the \
                                 range XML 1.0 permits"
                                    .to_string(),
                            ));
                        }
                    }
                    None => {
                        let name = entity.decode().unwrap_or_default();
                        let preview: String = name.chars().take(32).collect();
                        return Err(ProtocolError::Xml(format!(
                            "XML fragment references an undefined entity `&{preview};`; \
                             only the five predefined entities and numeric character \
                             references can be embedded"
                        )));
                    }
                }
            }
            Err(e) => {
                return Err(ProtocolError::Xml(format!(
                    "XML fragment is not well-formed: {e}"
                )));
            }
        }
        buf.clear();
    }

    Ok(())
}

/// Validate by attempting a *conforming* parse of the embedded document.
///
/// Enabled by the `strict-validation` feature. Where [`validate_xml_fragment`]
/// enforces a hand-written list of rules on top of quick-xml — which is a
/// permissive pull parser, not a validating one — this asks a conforming parser
/// whether the fragment actually embeds into a well-formed document. The
/// property then holds by construction rather than by enumeration.
///
/// That distinction is not theoretical. Fuzzing the rule list against exactly
/// this oracle found fourteen escapes (#80), and further rounds kept finding
/// more after the list was believed complete: attribute values are not
/// entity-checked, duplicate *expanded* attribute names pass, `<xmlns:a/>` is
/// accepted. Each was individually fixable; the process did not converge.
///
/// Off by default because it costs a dependency, and #77 is actively shrinking
/// the graph. See #89.
///
/// # Namespace binding
///
/// Deliberately not enforced. Whether a prefix resolves depends on declarations
/// the *envelope* supplies, which this layer cannot see — a fragment using
/// `nc:` is legitimate precisely because the caller's envelope declares it.
/// Prefixes are bound synthetically before parsing so that structural checking
/// is complete without demanding fragments be self-contained.
#[cfg(feature = "strict-validation")]
pub fn validate_xml_fragment_strict(xml: &str) -> Result<(), ProtocolError> {
    // The cheap structural rules run first: they give specific errors
    // ("not balanced", "undefined entity") where a conforming parser only
    // reports that the document is malformed.
    validate_xml_fragment(xml)?;

    if xml.is_empty() {
        return Ok(());
    }

    // The fragment is embedded verbatim. Nothing is rewritten and no bindings
    // are synthesised, which is a deliberate reversal of an earlier design.
    //
    // That version renamed the reserved `xml` prefix and bound every prefix it
    // found to a generated URI, so that structural checking continued past an
    // unresolved prefix. All of it was string surgery on the fragment, and
    // string surgery is defeatable by encoding: a URI spelling `xml:` literally
    // while another spells it `&#x78;ml:` had only one side rewritten, which
    // turned a genuine duplicate-expanded-name error into a pass. Chasing that
    // means decoding entities and tracking QName positions — reimplementing the
    // parser this function exists to delegate to.
    //
    // The cost is that a fragment relying on a prefix the *envelope* declares
    // stops being checked at that point, because roxmltree reports only the
    // first error. That is the safe direction for a validator: incomplete
    // checking never rejects valid configuration, whereas a rewriting bug does.
    // The rule list in `validate_xml_fragment` still applies to the whole
    // fragment regardless.
    let doc =
        format!("<_nc:rpc xmlns:_nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\">{xml}</_nc:rpc>");
    match roxmltree::Document::parse(&doc) {
        Ok(_) => Ok(()),
        // Binding is out of scope: whether a prefix resolves depends on
        // declarations the envelope supplies, which this layer cannot see. A
        // fragment using `nc:` is legitimate precisely because the caller's
        // envelope declares it.
        Err(roxmltree::Error::UnknownNamespace(..)) => Ok(()),
        Err(e) => Err(ProtocolError::Xml(format!(
            "XML fragment does not embed into a well-formed document: {e}"
        ))),
    }
}

/// XML 1.0 (5th ed.) `NameStartChar`.
///
/// The literal production. Approximating it does not work: a conservative
/// "reject the obvious delimiters" filter still accepted `<]nterfaces/>`, since
/// `]` is a perfectly legal XML character that simply cannot start a name. The
/// ranges are finite and cheap, so encode them rather than guess.
fn is_name_start_char(c: char) -> bool {
    matches!(c,
        ':' | '_'
        | 'A'..='Z' | 'a'..='z'
        | '\u{C0}'..='\u{D6}' | '\u{D8}'..='\u{F6}' | '\u{F8}'..='\u{2FF}'
        | '\u{370}'..='\u{37D}' | '\u{37F}'..='\u{1FFF}'
        | '\u{200C}'..='\u{200D}' | '\u{2070}'..='\u{218F}'
        | '\u{2C00}'..='\u{2FEF}' | '\u{3001}'..='\u{D7FF}'
        | '\u{F900}'..='\u{FDCF}' | '\u{FDF0}'..='\u{FFFD}'
        | '\u{10000}'..='\u{EFFFF}')
}

/// XML 1.0 (5th ed.) `NameChar` — `NameStartChar` plus the continuation set.
fn is_name_char(c: char) -> bool {
    is_name_start_char(c)
        || matches!(c,
            '-' | '.' | '0'..='9' | '\u{B7}'
            | '\u{300}'..='\u{36F}' | '\u{203F}'..='\u{2040}')
}

/// The XML 1.0 `Name` production, colons permitted anywhere.
///
/// Distinct from element names, which must additionally be `QName`s. A
/// processing-instruction target is only required to be a `Name`, so
/// `<?a:b:c?>`, `<?:a?>` and `<?a:?>` are all legal and a conforming parser
/// accepts them.
fn validate_pi_target(raw: &[u8]) -> Result<(), ProtocolError> {
    let name = std::str::from_utf8(raw).map_err(|_| {
        ProtocolError::Xml("XML fragment has a non-UTF-8 processing-instruction target".to_string())
    })?;
    let mut chars = name.chars();
    let ok = match chars.next() {
        None => false,
        Some(first) => is_name_start_char(first) && chars.all(is_name_char),
    };
    if !ok {
        let preview: String = name.chars().take(32).collect();
        return Err(ProtocolError::Xml(format!(
            "XML fragment has an invalid processing-instruction target \
             (first 32 chars: {preview:?})"
        )));
    }
    Ok(())
}

/// An XML `NCName`: a `Name` with no colon.
fn is_ncname(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        None => false,
        Some(first) => {
            first != ':' && is_name_start_char(first) && chars.all(|c| c != ':' && is_name_char(c))
        }
    }
}

/// Reject malformed attributes on a start tag.
///
/// The validator never looked at attributes, so `<a b/>` passed — quick-xml
/// reports `ExpectedEq` for a valueless attribute, but only if something
/// actually iterates them. A conforming parser rejects the document, and the
/// fragment would have gone onto the wire for the device to reject instead.
///
/// A CR inside what looks like a name reaches the same place by a different
/// route: quick-xml treats it as whitespace, so `<inte\rrfacE/>` becomes element
/// `inte` with a valueless attribute `rfacE`. Both were fuzz findings.
fn validate_attributes(tag: &quick_xml::events::BytesStart<'_>) -> Result<(), ProtocolError> {
    // XML requires whitespace before every attribute. quick-xml's iterator
    // happily yields both of `<a b="1"c="2"/>`, so the separator has to be
    // checked against the raw bytes: after a closing quote, only whitespace or
    // the end of the tag may follow.
    let raw = tag.attributes_raw();
    let mut quote: Option<u8> = None;
    for (i, &byte) in raw.iter().enumerate() {
        match quote {
            Some(q) if byte == q => {
                quote = None;
                match raw.get(i + 1) {
                    None => {}
                    Some(&next) if next.is_ascii_whitespace() || next == b'/' => {}
                    Some(_) => {
                        return Err(ProtocolError::Xml(
                            "XML fragment is missing whitespace between attributes".to_string(),
                        ));
                    }
                }
            }
            Some(_) => {}
            None if byte == b'"' || byte == b'\'' => quote = Some(byte),
            None => {}
        }
    }

    for attribute in tag.attributes().with_checks(true) {
        let attribute = attribute.map_err(|e| {
            ProtocolError::Xml(format!("XML fragment has an invalid attribute: {e}"))
        })?;
        validate_name(attribute.key.as_ref())?;
        // Namespaces in XML 1.0 §5: a *prefixed* declaration may not be
        // undeclared. `xmlns=""` is legal (it resets the default namespace);
        // `xmlns:p=""` is not. roxmltree 0.20 accepts it, so the strict
        // validator cannot catch it either — but the attribute iteration
        // needed to see it already happens here.
        if attribute.key.as_ref().starts_with(b"xmlns:") && attribute.value.is_empty() {
            return Err(ProtocolError::Xml(
                "XML fragment undeclares a prefixed namespace; only the default \
                 namespace may be set to an empty URI"
                    .to_string(),
            ));
        }
        let value = std::str::from_utf8(attribute.value.as_ref()).map_err(|_| {
            ProtocolError::Xml("XML fragment has a non-UTF-8 attribute value".to_string())
        })?;
        if !value
            .chars()
            .all(crate::rpc::reply::lexical::is_valid_xml_char)
        {
            return Err(ProtocolError::Xml(
                "XML fragment has an attribute value containing a character XML 1.0 \
                 cannot represent"
                    .to_string(),
            ));
        }
        // XML 1.0 §2.3 `AttValue`: a literal `<` may not appear in an attribute
        // value, only `&lt;`. quick-xml passes it through.
        if value.contains('<') {
            return Err(ProtocolError::Xml(
                "XML fragment has an attribute value containing a literal `<`; write \
                 `&lt;`"
                    .to_string(),
            ));
        }
    }
    Ok(())
}

/// Reject element names that are not a well-formed XML `Name`.
///
/// quick-xml does not check this — `<\0\0ing/>` and `<]nterfaces/>` both parse
/// happily — so a fragment could carry either straight into an RPC for the
/// device to choke on. Found by the `fragment_embeds_cleanly` fuzz target, twice:
/// first with control characters, then with a legal character in an illegal
/// position, which is what prompted encoding the real production.
fn validate_name(raw: &[u8]) -> Result<(), ProtocolError> {
    let name = std::str::from_utf8(raw)
        .map_err(|_| ProtocolError::Xml("XML fragment has a non-UTF-8 element name".to_string()))?;
    // NETCONF is namespace-based throughout, so the relevant standard is
    // QName, not the raw Name production. `:` is a legal NameStartChar, which
    // makes `<:/>` a valid Name and an invalid QName — a namespace-aware parser
    // rejects it. At most one colon, with a non-empty NCName either side.
    let mut parts = name.split(':');
    let bad = match (parts.next(), parts.next(), parts.next()) {
        (Some(local), None, _) => !is_ncname(local),
        (Some(prefix), Some(local), None) => !is_ncname(prefix) || !is_ncname(local),
        _ => true,
    };
    if bad {
        let preview: String = name.chars().take(32).collect();
        return Err(ProtocolError::Xml(format!(
            "XML fragment has an invalid element name (first 32 chars: {preview:?})"
        )));
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
        // Rejected either as unbalanced or as an invalid element name — the
        // stray `<` swallows the following `</_` into a tag name. Which rule
        // fires first is an implementation detail; that it is refused is not.
        assert!(validate_xml_fragment("<").is_err());
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
    fn rejects_undefined_entities() {
        // `&cmp;` is a typo of `&amp;`. quick-xml streams it as an unresolvable
        // reference; a conforming parser rejects the document outright.
        let err = validate_xml_fragment("<a>&cmp;&lt;</a>").expect_err("undefined entity");
        assert!(err.to_string().contains("undefined entity"), "got {err}");
        // `&nbsp;` is an HTML5 name, undefined in XML without a DTD. This must
        // hold regardless of whether some other crate in the graph enables
        // quick-xml's `escape-html` feature.
        assert!(validate_xml_fragment("<a>&nbsp;</a>").is_err());
        // The five predefined ones and numeric refs are fine.
        validate_xml_fragment("<a>&amp;&lt;&gt;&quot;&apos;</a>").unwrap();
        validate_xml_fragment("<a>&#38;&#x26;</a>").unwrap();
    }

    #[test]
    fn rejects_character_references_outside_the_xml_range() {
        assert!(validate_xml_fragment("<a>&#x4;</a>").is_err());
        assert!(validate_xml_fragment("<a>&#4;</a>").is_err());
    }

    #[test]
    fn rejects_invalid_element_names() {
        // quick-xml parses a NUL inside a tag name without complaint.
        assert!(validate_xml_fragment("<\u{0}ing/>").is_err());
        assert!(validate_xml_fragment("<a\u{10}b/>").is_err());
        assert!(validate_xml_fragment("<a\u{fffe}/>").is_err());
        // A legal XML character in an illegal position: `]` cannot start a name.
        assert!(validate_xml_fragment("<]nterfaces/>").is_err());
        // Valid Name, invalid QName: NETCONF is namespace-based.
        assert!(validate_xml_fragment("<:/>").is_err());
        assert!(validate_xml_fragment("<a:b:c/>").is_err());
        assert!(validate_xml_fragment("<a:/>").is_err());
        assert!(validate_xml_fragment("<:b/>").is_err());
        assert!(validate_xml_fragment("<1abc/>").is_err());
        // Ordinary names, including namespaced and hyphenated ones, still pass.
        validate_xml_fragment("<nc:get-config/>").unwrap();
        validate_xml_fragment("<host-name.0/>").unwrap();
        validate_xml_fragment("<_x/>").unwrap();
        validate_xml_fragment("<\u{e9}l\u{e9}ment/>").unwrap();
    }

    #[test]
    fn rejects_a_literal_cdata_terminator_in_text() {
        assert!(validate_xml_fragment("<a>]]></a>").is_err());
        assert!(validate_xml_fragment("a*]]>>b").is_err());
        validate_xml_fragment("<a>]]&gt;</a>").unwrap();
        validate_xml_fragment("<a>]]</a>").unwrap();
    }

    #[test]
    fn rejects_malformed_attributes() {
        // Valueless attribute; quick-xml only reports it if you iterate.
        assert!(validate_xml_fragment("<a b/>").is_err());
        // A CR reaches the same place: name `inte`, valueless attr `rfacE`.
        assert!(validate_xml_fragment("<inte\rrfacE/>").is_err());
        // Adjacent attributes with no separator; quick-xml yields both happily.
        assert!(validate_xml_fragment(r#"<a b="1"c="2"/>"#).is_err());
        assert!(validate_xml_fragment(r#"<p:a/><i n="1"x="2"/>"#).is_err());
        // Well-formed attributes still pass.
        // A literal `<` in an attribute value is forbidden.
        assert!(validate_xml_fragment(r#"<a b="x<y"/>"#).is_err());
        validate_xml_fragment(r#"<a b="1" xmlns:n="urn:x"/>"#).unwrap();
        validate_xml_fragment(r#"<a b="x&lt;y"/>"#).unwrap();
    }

    #[test]
    fn rejects_malformed_processing_instructions() {
        assert!(validate_xml_fragment("<?<a?>!").is_err());
        assert!(validate_xml_fragment("<?1bad?>").is_err());
        // `xml` is a reserved target in any case.
        assert!(validate_xml_fragment("<?xml-stylesheet?>").is_ok());
        assert!(validate_xml_fragment("<?XmL foo?>").is_err());
        // The body is validated too, not just the target.
        assert!(validate_xml_fragment("<?ok \u{10}?>").is_err());
        // A colon IS allowed in a PI target: XML 1.0 defines PITarget as a
        // Name, and the NCName rule applies to element/attribute names.
        validate_xml_fragment("<?a:b?>").unwrap();
        // PITarget is a Name, so colons may appear anywhere, unlike QName.
        validate_xml_fragment("<?a:b:c?>").unwrap();
        validate_xml_fragment("<?:a?>").unwrap();
        validate_xml_fragment("<?a:?>").unwrap();
    }

    #[test]
    fn rejects_malformed_comments() {
        assert!(validate_xml_fragment("<!-->").is_err());
        assert!(validate_xml_fragment("<---->").is_err());
        assert!(validate_xml_fragment("<!-- a -- b -->").is_err());
        assert!(validate_xml_fragment("<!--x--->").is_err()); // content `x-`
                                                              // Ordinary comments still pass.
        validate_xml_fragment("<!-- a comment --><a/>").unwrap();
    }

    #[cfg(feature = "strict-validation")]
    #[test]
    fn strict_catches_what_the_rule_list_documents_as_residual() {
        use super::{validate_xml_fragment, validate_xml_fragment_strict};

        // Every one of these is in fuzz/README.md's residual table: the rule
        // list accepts them, a conforming parser does not. This is the whole
        // argument of #89, as an assertion.
        for frag in [
            r#"<a b="&cmp;"/>"#, // undefined entity in an attribute
            r#"<a b="&#4;"/>"#,  // out-of-range char ref in an attribute
            r#"<a xmlns:p="urn:x" xmlns:q="urn:x" p:x="1" q:x="2"/>"#, // duplicate expanded names
        ] {
            assert!(
                validate_xml_fragment(frag).is_ok(),
                "rule list is expected to accept {frag:?} — if this fails the residual shrank"
            );
            assert!(
                validate_xml_fragment_strict(frag).is_err(),
                "strict validation must reject {frag:?}"
            );
        }
    }

    #[cfg(feature = "strict-validation")]
    #[test]
    fn strict_still_accepts_ordinary_netconf_fragments() {
        use super::validate_xml_fragment_strict;
        for frag in [
            "<system><host-name>r1</host-name></system>",
            "<interfaces/><routing/>",
            "<a><![CDATA[x]]></a>",
            "<a>&amp;&lt;</a>",
            "",
            // A prefix the *envelope* would declare: binding is out of scope.
            r#"<if:interfaces xmlns:if="urn:x"/>"#,
            "<nc:get-config/>",
            // Colons inside a URI must not be mistaken for prefix separators.
            // Scanning with `Name` rules instead of `NCName` synthesised a bogus
            // `xmlns:urn:ietf=` and rejected this — the most ordinary fragment
            // in NETCONF.
            r#"<filter xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"/>"#,
            // The reserved `xml` prefix, which roxmltree rejects even when
            // correctly declared, so it is renamed for the checked copy.
            r#"<a xml:lang="en"/>"#,
            r#"<a xml:space="preserve"/>"#,
            // PITarget is a Name: colons are legal anywhere in it.
            "<?a:b:c?>",
            // A fragment declaring what the synthetic URI stem would have been.
            // A fixed stem would bind an unrelated prefix to the same URI and
            // invent a duplicate expanded name.
            r#"<a xmlns:q="urn:rustnetconf:validate:0" p:x="1" q:x="2"/>"#,
            // `xmlns=""` resets the default namespace and is legal.
            r#"<a xmlns=""/>"#,
        ] {
            validate_xml_fragment_strict(frag).unwrap_or_else(|e| {
                panic!("strict validation rejected a valid fragment {frag:?}: {e}")
            });
        }
    }

    #[test]
    fn rejects_undeclaring_a_prefixed_namespace() {
        // Namespaces in XML §5 forbids it, and roxmltree 0.20 accepts it — so
        // this has to be caught here or not at all.
        assert!(validate_xml_fragment(r#"<a xmlns:p="" p:x="1"/>"#).is_err());
        // The default namespace may be reset to empty.
        validate_xml_fragment(r#"<a xmlns=""/>"#).unwrap();
    }

    #[test]
    fn still_accepts_ordinary_fragments() {
        validate_xml_fragment("<system><host-name>r1</host-name></system>").unwrap();
        validate_xml_fragment("<a/><b/>").unwrap();
        validate_xml_fragment("<!-- a comment --><a/>").unwrap();
        validate_xml_fragment("").unwrap();
    }
}
