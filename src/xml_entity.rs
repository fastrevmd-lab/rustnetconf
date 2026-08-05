//! Helpers for quick-xml 0.38+ entity-reference events.
//!
//! Since quick-xml 0.38, entity references (`&amp;`, `&#38;`, …) no longer
//! arrive inside `Event::Text` — they stream as separate `Event::GeneralRef`
//! events. Reader loops must resolve these and stitch them back into the
//! surrounding text, otherwise any value containing an entity is silently
//! truncated.

use quick_xml::events::BytesRef;

/// Resolve a general entity reference to its decoded text value.
///
/// Handles numeric character references (`&#38;`, `&#x26;`) and the five
/// predefined XML entities (`amp`, `lt`, `gt`, `apos`, `quot`). Returns
/// `None` for unknown user-defined entities, which callers should skip
/// (matching the old `unescape()` error behavior of not inventing content).
pub(crate) fn resolve_entity_ref(entity: &BytesRef<'_>) -> Option<String> {
    if let Ok(Some(ch)) = entity.resolve_char_ref() {
        return Some(ch.to_string());
    }
    let name = entity.decode().ok()?;
    quick_xml::escape::resolve_predefined_entity(&name).map(|s| s.to_string())
}
