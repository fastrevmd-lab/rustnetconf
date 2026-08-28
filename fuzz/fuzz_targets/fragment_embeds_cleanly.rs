#![no_main]
//! `validate_xml_fragment` accepting a fragment must mean the fragment can be
//! embedded in an RPC without breaking the document.
//!
//! The validator is a *validate-then-trust* guard: callers pass its output
//! straight into a `format!`-built envelope, so anything it accepts is spliced
//! in verbatim. If it can accept a string that then makes the surrounding
//! document unparseable, every caller inherits that.
//!
//! This is the property that matters, and the direction that is dangerous.
//! The reverse — the validator rejecting something a parser would accept — is a
//! usability question, not a safety one, and it is deliberately true today: the
//! validator refuses `<?xml ...?>` and `<!DOCTYPE ...>` precisely because they
//! parse fine alone and break things when embedded.

use libfuzzer_sys::fuzz_target;
use rustnetconf::rpc::validate_xml_fragment;

/// Parse a whole document with an independent, conforming parser.
///
/// Deliberately **not** quick-xml. The validator is built on quick-xml, and an
/// oracle sharing its parser also shares its blind spots: quick-xml reports EOF
/// without error when elements are still open, which is exactly how the
/// trailing-`<` escape went unnoticed. It is also permissive about illegal
/// character references and undefined entities, so a same-parser oracle cannot
/// see those disagreements at all.
/// Build the embedded document, with any extra namespace declarations placed on
/// the existing root rather than in a wrapper.
///
/// Wrapping would be simpler but is wrong: the envelope opens with an XML
/// declaration, and `<w><?xml ...?>` is invalid, so a wrapper turns every
/// document into a parse failure and the assertion fires on the oracle's own
/// mistake rather than on a real divergence.
fn embed(fragment: &str, extra_decls: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0"{extra_decls} message-id="1">
  <nc:edit-config>
    <nc:config>{fragment}</nc:config>
  </nc:edit-config>
</nc:rpc>"#
    )
}

/// Whether the fragment embeds into a well-formed document, ignoring namespace
/// *binding*.
///
/// Binding is out of scope deliberately: whether a prefix resolves depends on
/// what the surrounding envelope declared, and `validate_xml_fragment` cannot
/// know that — a fragment using `nc:` is legitimate precisely because the
/// envelope declares it.
///
/// Excluding it by treating `UnknownNamespace` as success would be wrong, and
/// was: roxmltree reports only the *first* error, so an unbound prefix early in
/// the document hid every structural problem after it. `<p:a/><i n="1"x="2"/>`
/// was declared valid without the missing attribute separator ever being
/// looked at. Binding the prefix and re-parsing keeps structural checking
/// complete and neutralises only binding.
/// XML `NCName` character rules, reimplemented here on purpose.
///
/// The oracle must not borrow the crate's own notion of a name: sharing that
/// would couple it to the code under test, the same mistake as using quick-xml
/// as the oracle's parser. An ASCII-only approximation is not enough either — a
/// legal prefix like `é` would go unbound, roxmltree would stop at
/// `UnknownNamespace`, and a malformed suffix after it would never be examined.
fn is_ncname_start(c: char) -> bool {
    matches!(c,
        '_' | 'A'..='Z' | 'a'..='z'
        | '\u{C0}'..='\u{D6}' | '\u{D8}'..='\u{F6}' | '\u{F8}'..='\u{2FF}'
        | '\u{370}'..='\u{37D}' | '\u{37F}'..='\u{1FFF}'
        | '\u{200C}'..='\u{200D}' | '\u{2070}'..='\u{218F}'
        | '\u{2C00}'..='\u{2FEF}' | '\u{3001}'..='\u{D7FF}'
        | '\u{F900}'..='\u{FDCF}' | '\u{FDF0}'..='\u{FFFD}'
        | '\u{10000}'..='\u{EFFFF}')
}

fn is_ncname_char(c: char) -> bool {
    is_ncname_start(c)
        || matches!(c,
            '-' | '.' | '0'..='9' | '\u{B7}'
            | '\u{300}'..='\u{36F}' | '\u{203F}'..='\u{2040}')
}

/// Prefixes `embed()` already binds on the envelope. Redeclaring one of these
/// puts two identical `xmlns:` attributes on the same element, which roxmltree
/// rejects — turning the most ordinary fragment there is, `<nc:get/>`, into a
/// false failure that halts fuzzing.
const ENVELOPE_PREFIXES: [&str; 1] = ["nc"];

/// roxmltree 0.20 does not know the implicitly-bound `xml` prefix, and reports
/// `UnknownNamespace("xml", ..)` even when `xmlns:xml` is declared to its one
/// legal URI — so binding it cannot satisfy the parser, and the error would stop
/// the parse before any later structure was examined.
///
/// Rename it to an ordinary prefix for the oracle's copy. Prefix *identity* has
/// no bearing on structural well-formedness, which is the only property this
/// target asserts, so the substitution preserves exactly what is being tested.
/// Occurrences in text are rewritten too; that changes text content and nothing
/// structural.
/// A token that does not occur in `fragment`.
///
/// Everything the oracle synthesises — the alias for the `xml` prefix, and the
/// namespace URIs it binds — has to be absent from the input, or it collides
/// with something the fragment declares itself and the oracle rejects a
/// document that embeds perfectly well. Both collisions were real:
///
/// - a fixed alias rewrote `xml:lang` and an existing `alias:lang` to the same
///   attribute name
/// - a fixed URI stem let `<a xmlns:q="urn:fuzz:synthetic:3" p:x="1" q:x="2"/>`
///   bind `p` to the URI `q` already had, making `p:x` and `q:x` duplicate
///   expanded attributes
///
/// Deriving both from the input closes the class rather than the instances.
fn fresh_token(fragment: &str, stem: &str) -> String {
    let mut token = stem.to_string();
    while fragment.contains(&token) {
        token.push('z');
    }
    token
}

fn defuse_xml_prefix(fragment: &str) -> String {
    let alias = fresh_token(fragment, "xmlfuzzalias");
    fragment.replace("xml:", &format!("{alias}:"))
}

fn embeds_cleanly(fragment: &str) -> bool {
    // Bind every prefix the fragment could use, up front, in one pass.
    //
    // An iterate-until-roxmltree-stops-complaining loop needs a cap, and a cap
    // is a blind spot: with more distinct unbound prefixes than the budget the
    // loop ends on `UnknownNamespace` and reports success without ever having
    // parsed, so anything malformed after them goes unexamined. Scanning once
    // removes the budget and the blind spot together.
    //
    // Over-binding is harmless: unused `xmlns:` declarations are legal, and each
    // prefix gets a *distinct* URI — binding two to the same namespace makes
    // `<a p:x="1" q:x="2"/>` a duplicate expanded attribute, a false positive.
    let fragment = &defuse_xml_prefix(fragment);
    let mut prefixes: Vec<String> = Vec::new();
    let chars: Vec<char> = fragment.chars().collect();
    for (i, &c) in chars.iter().enumerate() {
        if c != ':' {
            continue;
        }
        let mut start = i;
        while start > 0 && is_ncname_char(chars[start - 1]) {
            start -= 1;
        }
        if start == i || !is_ncname_start(chars[start]) {
            continue;
        }
        let prefix: String = chars[start..i].iter().collect();
        if prefix == "xmlns"
            || ENVELOPE_PREFIXES.contains(&prefix.as_str())
            || prefixes.contains(&prefix)
        {
            continue;
        }
        prefixes.push(prefix);
    }

    let uri_stem = fresh_token(fragment, "urn:fuzz:synthetic");
    let decl_for = |n: usize, p: &str| format!(" xmlns:{p}=\"{uri_stem}:{n}\"");
    let mut decls: Vec<String> = prefixes
        .iter()
        .enumerate()
        .map(|(n, p)| decl_for(n, p))
        .collect();

    // The scan above should have caught every prefix. If roxmltree still reports
    // one, that is a gap in the *oracle*, not an out-of-scope binding question —
    // so bind it and retry rather than declaring success. Silently accepting a
    // leftover `UnknownNamespace` is what let `<xml:a/>` hide a malformed
    // document twice over.
    for _ in 0..8 {
        match roxmltree::Document::parse(&embed(fragment, &decls.concat())) {
            Ok(_) => return true,
            Err(roxmltree::Error::UnknownNamespace(prefix, _)) => {
                let key = format!(" xmlns:{prefix}=");
                if decls.iter().any(|d| d.starts_with(&key)) {
                    // Bound and still complaining: genuinely a binding question.
                    return true;
                }
                decls.push(decl_for(decls.len(), &prefix));
            }
            Err(_) => return false,
        }
    }
    true
}

fuzz_target!(|data: &str| {
    if validate_xml_fragment(data).is_err() {
        return;
    }
    assert!(
        embeds_cleanly(data),
        "validate_xml_fragment accepted a fragment that does not embed cleanly:\n\
         fragment: {data:?}"
    );
});
