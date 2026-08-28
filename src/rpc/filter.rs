//! Subtree and XPath filter builders for NETCONF `<get>` and `<get-config>`.

use crate::error::{NetconfError, ProtocolError};
use crate::rpc::operations::{escape_xml_attr, escape_xml_attr_preserving_ws};

fn xml_err(message: String) -> NetconfError {
    NetconfError::Protocol(ProtocolError::Xml(message))
}

/// Conservative XML `NCName` check, restricted to ASCII.
///
/// Deliberately narrower than the XML production. Rust's `char::is_alphanumeric`
/// is true for the whole Unicode `N` category, which includes characters such as
/// `\u{b2}` (SUPERSCRIPT TWO) that an XML parser rejects in a name — so using it
/// would accept prefixes that produce unparseable output. Full Unicode NCName
/// validation needs the XML character tables; refusing non-ASCII prefixes costs
/// nothing here, since namespace prefixes in NETCONF are conventionally short
/// ASCII tokens.
fn is_valid_ncname(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
}

/// The one URI the `xml` prefix may be bound to (Namespaces in XML §3).
const XML_NAMESPACE_URI: &str = "http://www.w3.org/XML/1998/namespace";

/// Reserved; no prefix may be bound to it.
const XMLNS_NAMESPACE_URI: &str = "http://www.w3.org/2000/xmlns/";

/// Builder for constructing subtree filters.
///
/// # Examples
/// ```
/// use rustnetconf::rpc::filter::SubtreeFilter;
///
/// let filter = SubtreeFilter::new()
///     .add("<interfaces/>")
///     .add("<system><hostname/></system>")
///     .build();
/// assert!(filter.contains("<interfaces/>"));
/// ```
pub struct SubtreeFilter {
    elements: Vec<String>,
}

impl SubtreeFilter {
    /// Create an empty subtree filter.
    pub fn new() -> Self {
        Self {
            elements: Vec::new(),
        }
    }

    /// Add an XML element to the filter.
    #[allow(clippy::should_implement_trait)]
    pub fn add(mut self, xml: &str) -> Self {
        self.elements.push(xml.to_string());
        self
    }

    /// Build the filter into a single XML string.
    pub fn build(&self) -> String {
        self.elements.join("\n")
    }
}

impl Default for SubtreeFilter {
    fn default() -> Self {
        Self::new()
    }
}

/// Validate and render a set of `xmlns:` declarations for one element.
///
/// Shared by the XPath filter and by RFC 5717 partial-lock, which both let a
/// caller bind prefixes used in an XPath expression and therefore share every
/// way of getting that wrong.
///
/// `envelope_prefix` is the element-name prefix the declarations will sit
/// beside (`"nc:"` or `""`). Binding it is refused: an `xmlns:` declaration
/// applies to the element it sits on *including that element's own name*, so
/// rebinding the envelope prefix would silently move the element out of the
/// NETCONF namespace.
///
/// `what` names the caller in error messages.
pub(crate) fn render_namespace_bindings(
    namespaces: &[(String, String)],
    envelope_prefix: &str,
    what: &str,
) -> Result<String, NetconfError> {
    let envelope = envelope_prefix.strip_suffix(':').unwrap_or(envelope_prefix);

    // Emitting the same prefix twice produces duplicate attributes on one
    // element, which is malformed XML - the server cannot execute the request at
    // all. Callers combining bindings for several expressions hit this
    // naturally, so an identical repeat is folded away; a prefix bound to two
    // different URIs is a genuine ambiguity and is refused rather than silently
    // resolved to whichever came first.
    let mut seen: Vec<(&str, &str)> = Vec::new();
    let mut deduped: Vec<(&String, &String)> = Vec::new();
    for (p, uri) in namespaces {
        match seen.iter().find(|(sp, _)| *sp == p.as_str()) {
            Some((_, existing)) if *existing == uri.as_str() => continue,
            Some((_, existing)) => {
                return Err(xml_err(format!(
                    "{what} binds the prefix `{p}` to two different URIs: `{existing}` and `{uri}`"
                )));
            }
            None => {
                seen.push((p.as_str(), uri.as_str()));
                deduped.push((p, uri));
            }
        }
    }

    let mut xmlns = String::new();
    for (p, uri) in deduped {
        if !envelope.is_empty() && p == envelope {
            return Err(xml_err(format!(
                "{what} cannot bind the prefix `{p}`: it is the NETCONF envelope \
                 prefix, and rebinding it would move the element out of the NETCONF \
                 namespace"
            )));
        }
        if !is_valid_ncname(p) {
            return Err(xml_err(format!(
                "{what} namespace prefix `{p}` is not a valid XML name"
            )));
        }
        // Namespaces in XML §3 reserves these two prefixes.
        if p == "xmlns" {
            return Err(xml_err(
                "the `xmlns` prefix is reserved and cannot be declared".to_string(),
            ));
        }
        if p == "xml" && uri != XML_NAMESPACE_URI {
            return Err(xml_err(format!(
                "the `xml` prefix may only be bound to `{XML_NAMESPACE_URI}`"
            )));
        }
        // The reciprocal rules: the reserved URIs are equally restricted, not
        // just the reserved prefixes.
        if p != "xml" && uri == XML_NAMESPACE_URI {
            return Err(xml_err(format!(
                "`{XML_NAMESPACE_URI}` may only be bound to the `xml` prefix, not `{p}`"
            )));
        }
        if uri == XMLNS_NAMESPACE_URI {
            return Err(xml_err(format!(
                "`{XMLNS_NAMESPACE_URI}` is reserved and cannot be bound to any prefix, \
                 including `{p}`"
            )));
        }
        if uri.is_empty() {
            return Err(xml_err(format!(
                "{what} namespace prefix `{p}` cannot be bound to an empty URI"
            )));
        }
        let uri_esc = escape_xml_attr_preserving_ws(uri).ok_or_else(|| {
            xml_err(format!(
                "namespace URI for prefix `{p}` contains a control character that XML 1.0 \
                 cannot represent"
            ))
        })?;
        xmlns.push_str(&format!(" xmlns:{}=\"{}\"", escape_xml_attr(p), uri_esc));
    }
    Ok(xmlns)
}

/// Builder for an XPath filter (RFC 6241 §6.4).
///
/// An XPath filter is expressed as attributes on `<filter>` rather than as
/// child elements, so — unlike [`SubtreeFilter`] — it cannot be reduced to a
/// string of XML to be dropped inside the element. Pass it to
/// [`Client::get_xpath`](crate::Client::get_xpath) or
/// [`Client::get_config_xpath`](crate::Client::get_config_xpath), which render
/// it and check the device advertises `:xpath:1.0` first.
///
/// Prefixes used in the expression must be bound with [`namespace`]. NETCONF
/// gives the filter element no useful default namespace for this purpose, so
/// an unprefixed path will not match on most devices.
///
/// [`namespace`]: XPathFilter::namespace
///
/// # Examples
/// ```
/// use rustnetconf::rpc::filter::XPathFilter;
///
/// let filter = XPathFilter::new("/if:interfaces/if:interface[if:name='ge-0/0/0']")
///     .namespace("if", "urn:ietf:params:xml:ns:yang:ietf-interfaces");
/// assert_eq!(filter.select(), "/if:interfaces/if:interface[if:name='ge-0/0/0']");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XPathFilter {
    select: String,
    namespaces: Vec<(String, String)>,
}

impl XPathFilter {
    /// Create an XPath filter from a select expression.
    pub fn new(select: impl Into<String>) -> Self {
        Self {
            select: select.into(),
            namespaces: Vec::new(),
        }
    }

    /// Bind a namespace prefix used in the select expression.
    ///
    /// Re-binding a prefix replaces the previous URI rather than emitting a
    /// duplicate `xmlns:` attribute, which would be malformed XML.
    pub fn namespace(mut self, prefix: impl Into<String>, uri: impl Into<String>) -> Self {
        let prefix = prefix.into();
        let uri = uri.into();
        match self.namespaces.iter_mut().find(|(p, _)| *p == prefix) {
            Some(entry) => entry.1 = uri,
            None => self.namespaces.push((prefix, uri)),
        }
        self
    }

    /// The select expression, unescaped.
    pub fn select(&self) -> &str {
        &self.select
    }

    /// The bound prefixes, in binding order.
    pub fn namespaces(&self) -> &[(String, String)] {
        &self.namespaces
    }

    /// Render the `<filter>` element for this XPath expression.
    ///
    /// `prefix` is the element-name prefix used by the caller's RPC envelope
    /// (`"nc:"` for the namespaced envelope, `""` for a bare one).
    ///
    /// The select expression and every namespace URI are attribute-escaped.
    /// This matters more than usual here: the expression is the one part of a
    /// filter that is routinely built from user input (an interface name, a
    /// hostname), and it lands in an attribute value rather than in text.
    ///
    /// # Errors
    ///
    /// Rejects a binding that would shadow the envelope prefix. An `xmlns:`
    /// declaration applies to the element it sits on *including that element's
    /// own name*, so binding `nc` here would render
    /// `<nc:filter xmlns:nc="urn:something-else">` and move `filter` out of the
    /// NETCONF namespace. The device would then not see a filter at all — and
    /// the plausible outcome is not an error but an unfiltered reply carrying
    /// the whole datastore, which is exactly the silent over-fetch the
    /// capability gate exists to prevent.
    ///
    /// Also rejects prefixes that are not usable as XML names, which would
    /// produce malformed output rather than a wrong namespace.
    pub(crate) fn to_filter_element(&self, prefix: &str) -> Result<String, NetconfError> {
        let xmlns = render_namespace_bindings(&self.namespaces, prefix, "XPath filter")?;
        let select = escape_xml_attr_preserving_ws(&self.select).ok_or_else(|| {
            xml_err(
                "XPath select expression contains a control character that XML 1.0 \
                 cannot represent"
                    .to_string(),
            )
        })?;
        Ok(format!(
            "\n    <{prefix}filter type=\"xpath\"{xmlns} select=\"{select}\"/>"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xpath_renders_type_and_select() {
        let f = XPathFilter::new("/if:interfaces");
        let xml = f.to_filter_element("nc:").unwrap();
        assert!(xml.contains("type=\"xpath\""), "got {xml}");
        assert!(xml.contains("select=\"/if:interfaces\""), "got {xml}");
        assert!(xml.contains("<nc:filter"), "got {xml}");
    }

    #[test]
    fn xpath_binds_namespaces_in_order() {
        let xml = XPathFilter::new("/a:x/b:y")
            .namespace("a", "urn:a")
            .namespace("b", "urn:b")
            .to_filter_element("")
            .unwrap();
        let a = xml.find("xmlns:a=\"urn:a\"").expect("a bound");
        let b = xml.find("xmlns:b=\"urn:b\"").expect("b bound");
        assert!(a < b, "bindings should keep insertion order: {xml}");
        assert!(xml.contains("<filter"), "bare prefix: {xml}");
    }

    #[test]
    fn rebinding_a_prefix_replaces_it() {
        let f = XPathFilter::new("/a:x")
            .namespace("a", "urn:old")
            .namespace("a", "urn:new");
        assert_eq!(f.namespaces(), &[("a".to_string(), "urn:new".to_string())]);
        let xml = f.to_filter_element("").unwrap();
        assert!(!xml.contains("urn:old"), "stale binding kept: {xml}");
        assert_eq!(xml.matches("xmlns:a=").count(), 1, "duplicate xmlns: {xml}");
    }

    #[test]
    fn select_expression_is_attribute_escaped() {
        // A quote in the expression must not be able to close the attribute
        // and inject further attributes or elements.
        let xml = XPathFilter::new("/x[name=\"a\" onload=\"evil\"]/y")
            .to_filter_element("")
            .unwrap();
        assert!(!xml.contains("onload=\"evil\""), "injection escaped: {xml}");
        assert!(xml.contains("&quot;"), "quote not escaped: {xml}");
    }

    #[test]
    fn namespace_uri_is_attribute_escaped() {
        let xml = XPathFilter::new("/a:x")
            .namespace("a", "urn:a\"><evil")
            .to_filter_element("")
            .unwrap();
        assert!(!xml.contains("><evil"), "injection escaped: {xml}");
        assert!(xml.contains("&quot;"), "quote not escaped: {xml}");
    }

    #[test]
    fn ampersand_and_angle_brackets_escaped() {
        let xml = XPathFilter::new("/x[a='1' and b<'2' and c>'0' and d='&']")
            .to_filter_element("")
            .unwrap();
        assert!(xml.contains("&amp;"), "got {xml}");
        assert!(xml.contains("&lt;"), "got {xml}");
        assert!(xml.contains("&gt;"), "got {xml}");
    }

    #[test]
    fn binding_the_envelope_prefix_is_refused() {
        // <nc:filter xmlns:nc="urn:not-netconf"> would move the filter element
        // itself out of the NETCONF namespace, and the likely device response
        // is an *unfiltered* datastore rather than an error.
        let err = XPathFilter::new("/x")
            .namespace("nc", "urn:not-netconf")
            .to_filter_element("nc:")
            .expect_err("binding the envelope prefix must be refused");
        let msg = err.to_string();
        assert!(msg.contains("nc"), "got {msg}");
        assert!(msg.contains("NETCONF"), "got {msg}");
    }

    #[test]
    fn binding_envelope_prefix_is_fine_when_envelope_is_bare() {
        // With no envelope prefix there is nothing to shadow.
        let xml = XPathFilter::new("/x")
            .namespace("nc", "urn:anything")
            .to_filter_element("")
            .expect("no envelope prefix to collide with");
        assert!(xml.contains(r#"xmlns:nc="urn:anything""#), "got {xml}");
    }

    #[test]
    fn malformed_prefixes_are_refused() {
        for bad in ["", "a:b", "1abc", "-x", "x y"] {
            assert!(
                XPathFilter::new("/x")
                    .namespace(bad, "urn:u")
                    .to_filter_element("nc:")
                    .is_err(),
                "prefix {bad:?} should be refused"
            );
        }
    }

    #[test]
    fn ordinary_prefixes_are_accepted() {
        for ok in ["if", "_x", "a-b", "a.b", "A1"] {
            assert!(
                XPathFilter::new("/x")
                    .namespace(ok, "urn:u")
                    .to_filter_element("nc:")
                    .is_ok(),
                "prefix {ok:?} should be accepted"
            );
        }
    }

    #[test]
    fn whitespace_in_select_survives_attribute_normalization() {
        // An XML parser folds a literal TAB/LF/CR in an attribute to a space
        // (XML 1.0 3.3.3), which would silently rewrite the query.
        let xml = XPathFilter::new("/x[a='line1\nline2\ttabbed']")
            .to_filter_element("nc:")
            .unwrap();
        assert!(xml.contains("&#10;"), "newline not preserved: {xml}");
        assert!(xml.contains("&#9;"), "tab not preserved: {xml}");
        // Check the attribute value itself — the element is rendered with a
        // leading newline for indentation, which is not part of any attribute.
        let select = xml
            .split_once("select=\"")
            .and_then(|(_, rest)| rest.split_once('"'))
            .map(|(v, _)| v)
            .expect("select attribute present");
        assert!(
            !select.contains(['\n', '\t', '\r']),
            "raw whitespace inside the select attribute: {select:?}"
        );
    }

    #[test]
    fn control_characters_are_refused() {
        assert!(XPathFilter::new("/x[a='\u{1}']")
            .to_filter_element("nc:")
            .is_err());
        assert!(XPathFilter::new("/x")
            .namespace("a", "urn:\u{1}")
            .to_filter_element("nc:")
            .is_err());
    }

    #[test]
    fn reserved_prefixes_are_refused() {
        assert!(XPathFilter::new("/x")
            .namespace("xmlns", "urn:whatever")
            .to_filter_element("nc:")
            .is_err());
        assert!(XPathFilter::new("/x")
            .namespace("xml", "urn:wrong")
            .to_filter_element("nc:")
            .is_err());
        // `xml` bound to its one legal URI is fine.
        assert!(XPathFilter::new("/x")
            .namespace("xml", "http://www.w3.org/XML/1998/namespace")
            .to_filter_element("nc:")
            .is_ok());
    }

    #[test]
    fn empty_namespace_uri_is_refused() {
        assert!(XPathFilter::new("/x")
            .namespace("a", "")
            .to_filter_element("nc:")
            .is_err());
    }

    #[test]
    fn non_ascii_prefix_is_refused() {
        // `char::is_alphanumeric` would accept these; XML names do not.
        for bad in ["a\u{b2}", "\u{e9}x", "a\u{5b57}"] {
            assert!(
                XPathFilter::new("/x")
                    .namespace(bad, "urn:u")
                    .to_filter_element("nc:")
                    .is_err(),
                "prefix {bad:?} should be refused"
            );
        }
    }

    #[test]
    fn reserved_namespace_uris_are_refused() {
        // Reciprocal of the reserved-prefix rules.
        assert!(XPathFilter::new("/x")
            .namespace("notxml", "http://www.w3.org/XML/1998/namespace")
            .to_filter_element("nc:")
            .is_err());
        assert!(XPathFilter::new("/x")
            .namespace("a", "http://www.w3.org/2000/xmlns/")
            .to_filter_element("nc:")
            .is_err());
    }

    #[test]
    fn noncharacters_are_refused() {
        // U+FFFE and U+FFFF are excluded from XML 1.0's Char production; they
        // are not C0 controls, so a naive control-only check would let them by.
        for bad in ["/x[a='\u{fffe}']", "/x[a='\u{ffff}']"] {
            assert!(
                XPathFilter::new(bad).to_filter_element("nc:").is_err(),
                "{bad:?} should be refused"
            );
        }
        assert!(XPathFilter::new("/x")
            .namespace("a", "urn:\u{fffe}")
            .to_filter_element("nc:")
            .is_err());
        // A supplementary-plane character is perfectly legal, though.
        assert!(XPathFilter::new("/x[a='\u{1f600}']")
            .to_filter_element("nc:")
            .is_ok());
    }

    #[test]
    fn subtree_filter_still_builds() {
        let f = SubtreeFilter::new().add("<interfaces/>").build();
        assert_eq!(f, "<interfaces/>");
    }
}
