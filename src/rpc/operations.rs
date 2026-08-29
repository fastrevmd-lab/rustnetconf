//! NETCONF RPC operation XML serialization.
//!
//! Each function generates the XML for one NETCONF RPC operation,
//! ready to be framed and sent over the transport.
//!
//! All RPCs use a prefixed namespace (`nc:`) instead of a default namespace
//! to avoid `xmlns=""` on child elements, which Junos 24.4 rejects.

use crate::error::{NetconfError, ProtocolError};
use crate::rpc::filter::XPathFilter;
use crate::types::{
    ConfigLocation, CopySource, DeleteTarget, LockedNode, PartialLock, WithDefaults,
};
use crate::types::{
    Datastore, DefaultOperation, ErrorOption, LoadAction, LoadFormat, OpenConfigurationMode,
    TestOption,
};

/// Escape a string for safe inclusion in XML text content.
///
/// Replaces `&`, `<`, and `>` with their XML entity equivalents.
pub(crate) fn escape_xml_text(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

/// Escape for XML text content, preserving carriage returns exactly.
///
/// [`escape_xml_text`] is right for content we generate, but not for opaque
/// tokens we must round-trip byte-for-byte. XML 1.0 §2.11 applies *line-ending
/// normalization* to text content: a literal CR is turned into LF (and CRLF
/// into a single LF) before the application sees it. A `persist-id` minted by
/// another session and echoed back through a literal CR would come back
/// altered and no longer match, so cancellation would silently fail.
///
/// Returns `None` for characters XML 1.0 cannot represent at all.
pub(crate) fn escape_xml_text_exact(value: &str) -> Option<String> {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '\r' => escaped.push_str("&#13;"),
            c if !crate::rpc::reply::lexical::is_valid_xml_char(c) => return None,
            c => escaped.push(c),
        }
    }
    Some(escaped)
}

/// Escape for an XML attribute value, preserving significant whitespace.
///
/// [`escape_xml_attr`] is fine for values that contain no tabs or newlines, but
/// an XML parser applies *attribute-value normalization* (XML 1.0 §3.3.3) and
/// folds a literal TAB, LF, or CR in an attribute into a space before the value
/// is ever seen. For an XPath `select` expression that is not cosmetic: a
/// newline inside a string literal would silently become a different query.
/// Emitting them as numeric character references survives normalization.
///
/// Returns `None` if the value contains any character XML 1.0 cannot represent
/// — those cannot be escaped, only rejected. This uses the same
/// `is_valid_xml_char` the reply parser validates incoming documents with, so
/// the two directions cannot drift: C0 controls other than TAB/LF/CR, and also
/// `U+FFFE`/`U+FFFF`, which are excluded from the `Char` production.
pub(crate) fn escape_xml_attr_preserving_ws(value: &str) -> Option<String> {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            '\t' => escaped.push_str("&#9;"),
            '\n' => escaped.push_str("&#10;"),
            '\r' => escaped.push_str("&#13;"),
            c if !crate::rpc::reply::lexical::is_valid_xml_char(c) => return None,
            c => escaped.push(c),
        }
    }
    Some(escaped)
}

/// Escape a string for safe inclusion in an XML attribute value.
///
/// Replaces `&`, `<`, `>`, `"`, and `'` with their XML entity equivalents.
pub(crate) fn escape_xml_attr(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

/// Generate a `<get-config>` RPC request.
///
/// The `filter` parameter, if provided, must be well-formed XML (a subtree
/// filter element). It is inserted verbatim — do not pass untrusted user
/// input without validation.
pub fn get_config_xml(message_id: &str, source: Datastore, filter: Option<&str>) -> String {
    let filter_xml = match filter {
        Some(f) => format!("\n    <nc:filter type=\"subtree\">\n      {f}\n    </nc:filter>"),
        None => String::new(),
    };

    let safe_id = escape_xml_attr(message_id);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{safe_id}">
  <nc:get-config>
    <nc:source>
      <nc:{source}/>
    </nc:source>{filter_xml}
  </nc:get-config>
</nc:rpc>"#,
        source = source.as_xml_tag(),
    )
}

/// The `<with-defaults>` element (RFC 6243 §4.6.1).
///
/// Carries its own namespace because it is defined by RFC 6243's YANG module,
/// not the base NETCONF one — a bare `<with-defaults>` in the base namespace is
/// ignored by conforming servers.
fn with_defaults_element(mode: WithDefaults) -> String {
    format!(
        "\n    <with-defaults xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\">{}</with-defaults>",
        mode.as_str()
    )
}

/// Generate a `<get-config>` RPC with a subtree filter and a with-defaults mode.
pub fn get_config_with_defaults_xml(
    message_id: &str,
    source: Datastore,
    filter: Option<&str>,
    mode: WithDefaults,
) -> String {
    let filter_xml = match filter {
        Some(f) => format!("\n    <nc:filter type=\"subtree\">\n      {f}\n    </nc:filter>"),
        None => String::new(),
    };
    let wd = with_defaults_element(mode);
    let safe_id = escape_xml_attr(message_id);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{safe_id}">
  <nc:get-config>
    <nc:source>
      <nc:{source}/>
    </nc:source>{filter_xml}{wd}
  </nc:get-config>
</nc:rpc>"#,
        source = source.as_xml_tag(),
    )
}

/// Generate a `<get>` RPC with a subtree filter and a with-defaults mode.
pub fn get_with_defaults_xml(message_id: &str, filter: Option<&str>, mode: WithDefaults) -> String {
    let filter_xml = match filter {
        Some(f) => format!("\n    <nc:filter type=\"subtree\">\n      {f}\n    </nc:filter>"),
        None => String::new(),
    };
    let wd = with_defaults_element(mode);
    let safe_id = escape_xml_attr(message_id);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{safe_id}">
  <nc:get>{filter_xml}{wd}
  </nc:get>
</nc:rpc>"#
    )
}

/// Build a `<get-config>` RPC with an XPath filter (RFC 6241 §6.4).
///
/// Unlike the subtree form, the expression is carried in a `select` attribute
/// and is attribute-escaped by [`XPathFilter::to_filter_element`], so it does
/// not need to be pre-validated as an XML fragment.
pub fn get_config_xpath_xml(
    message_id: &str,
    source: Datastore,
    filter: &XPathFilter,
) -> Result<String, NetconfError> {
    let safe_id = escape_xml_attr(message_id);
    let filter_xml = filter.to_filter_element("nc:")?;
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{safe_id}">
  <nc:get-config>
    <nc:source>
      <nc:{source}/>
    </nc:source>{filter_xml}
  </nc:get-config>
</nc:rpc>"#,
        source = source.as_xml_tag(),
    ))
}

/// Build a `<get>` RPC with an XPath filter (RFC 6241 §6.4).
pub fn get_xpath_xml(message_id: &str, filter: &XPathFilter) -> Result<String, NetconfError> {
    let safe_id = escape_xml_attr(message_id);
    let filter_xml = filter.to_filter_element("nc:")?;
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{safe_id}">
  <nc:get>{filter_xml}
  </nc:get>
</nc:rpc>"#
    ))
}

/// Generate a `<get>` RPC request.
///
/// The `filter` parameter, if provided, must be well-formed XML (a subtree
/// filter element). It is inserted verbatim — do not pass untrusted user
/// input without validation.
pub fn get_xml(message_id: &str, filter: Option<&str>) -> String {
    let filter_xml = match filter {
        Some(f) => format!("\n    <nc:filter type=\"subtree\">\n      {f}\n    </nc:filter>"),
        None => String::new(),
    };

    let safe_id = escape_xml_attr(message_id);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{safe_id}">
  <nc:get>{filter_xml}
  </nc:get>
</nc:rpc>"#,
    )
}

/// Parameters for an `edit-config` operation.
pub struct EditConfigParams<'a> {
    pub target: Datastore,
    pub config: &'a str,
    pub default_operation: Option<DefaultOperation>,
    pub test_option: Option<TestOption>,
    pub error_option: Option<ErrorOption>,
}

/// Generate an `<edit-config>` RPC request.
///
/// The `config` field in `params` must be well-formed XML. It is inserted
/// verbatim — do not pass untrusted user input without validation.
pub fn edit_config_xml(message_id: &str, params: &EditConfigParams<'_>) -> String {
    let mut options = String::new();

    if let Some(ref default_op) = params.default_operation {
        options.push_str(&format!(
            "\n    <nc:default-operation>{}</nc:default-operation>",
            default_op.as_str()
        ));
    }

    if let Some(ref test_opt) = params.test_option {
        options.push_str(&format!(
            "\n    <nc:test-option>{}</nc:test-option>",
            test_opt.as_str()
        ));
    }

    if let Some(ref error_opt) = params.error_option {
        options.push_str(&format!(
            "\n    <nc:error-option>{}</nc:error-option>",
            error_opt.as_str()
        ));
    }

    let safe_id = escape_xml_attr(message_id);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{safe_id}">
  <nc:edit-config>
    <nc:target>
      <nc:{target}/>
    </nc:target>{options}
    <nc:config>
      {config}
    </nc:config>
  </nc:edit-config>
</nc:rpc>"#,
        target = params.target.as_xml_tag(),
        config = params.config,
    )
}

/// Generate a `<lock>` RPC request.
pub fn lock_xml(message_id: &str, target: Datastore) -> String {
    let safe_id = escape_xml_attr(message_id);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{safe_id}">
  <nc:lock>
    <nc:target>
      <nc:{target}/>
    </nc:target>
  </nc:lock>
</nc:rpc>"#,
        target = target.as_xml_tag(),
    )
}

/// Generate an `<unlock>` RPC request.
pub fn unlock_xml(message_id: &str, target: Datastore) -> String {
    let safe_id = escape_xml_attr(message_id);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{safe_id}">
  <nc:unlock>
    <nc:target>
      <nc:{target}/>
    </nc:target>
  </nc:unlock>
</nc:rpc>"#,
        target = target.as_xml_tag(),
    )
}

/// Generate a `<discard-changes>` RPC request.
///
/// Reverts the candidate configuration to match running.
pub fn discard_changes_xml(message_id: &str) -> String {
    let safe_id = escape_xml_attr(message_id);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{safe_id}">
  <nc:discard-changes/>
</nc:rpc>"#,
    )
}

/// Render a `<source>`/`<target>` body for a [`ConfigLocation`].
///
/// URLs are text content, so they use the text escaper; a datastore renders as
/// an empty element named for the datastore.
fn location_body(location: &ConfigLocation, indent: &str) -> String {
    match location {
        ConfigLocation::Datastore(ds) => format!("{indent}<nc:{}/>", ds.as_xml_tag()),
        ConfigLocation::Url(url) => {
            format!("{indent}<nc:url>{}</nc:url>", escape_xml_text(url))
        }
    }
}

/// Render a `<source>` body for a [`CopySource`].
///
/// The inline form is inserted verbatim and must have been validated by the
/// caller — same contract as `edit-config`'s config payload.
fn copy_source_body(source: &CopySource, indent: &str) -> String {
    match source {
        CopySource::Datastore(ds) => format!("{indent}<nc:{}/>", ds.as_xml_tag()),
        CopySource::Url(url) => format!("{indent}<nc:url>{}</nc:url>", escape_xml_text(url)),
        CopySource::Config(cfg) => format!("{indent}<nc:config>{cfg}</nc:config>"),
    }
}

/// Generate a `<copy-config>` RPC request (RFC 6241 §7.3).
///
/// Kept at three arguments: `rpc::operations` is public, so adding a parameter
/// here would break callers that never asked for RFC 6243. The with-defaults
/// form is [`copy_config_with_defaults_xml`].
pub fn copy_config_xml(message_id: &str, target: &ConfigLocation, source: &CopySource) -> String {
    copy_config_xml_inner(message_id, target, source, None)
}

/// Generate a `<copy-config>` RPC request carrying RFC 6243's
/// `<with-defaults>`, which that RFC augments onto `copy-config` as well as the
/// retrieval operations.
pub fn copy_config_with_defaults_xml(
    message_id: &str,
    target: &ConfigLocation,
    source: &CopySource,
    mode: WithDefaults,
) -> String {
    copy_config_xml_inner(message_id, target, source, Some(mode))
}

fn copy_config_xml_inner(
    message_id: &str,
    target: &ConfigLocation,
    source: &CopySource,
    mode: Option<WithDefaults>,
) -> String {
    let safe_id = escape_xml_attr(message_id);
    let target_body = location_body(target, "      ");
    let source_body = copy_source_body(source, "      ");
    let wd = mode.map(with_defaults_element).unwrap_or_default();
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{safe_id}">
  <nc:copy-config>
    <nc:target>
{target_body}
    </nc:target>
    <nc:source>
{source_body}
    </nc:source>{wd}
  </nc:copy-config>
</nc:rpc>"#
    )
}

/// Generate a `<delete-config>` RPC request (RFC 6241 §7.4).
pub fn delete_config_xml(message_id: &str, target: &DeleteTarget) -> String {
    let safe_id = escape_xml_attr(message_id);
    let target_body = match target {
        DeleteTarget::Startup => "      <nc:startup/>".to_string(),
        DeleteTarget::Url(url) => {
            format!("      <nc:url>{}</nc:url>", escape_xml_text(url))
        }
    };
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{safe_id}">
  <nc:delete-config>
    <nc:target>
{target_body}
    </nc:target>
  </nc:delete-config>
</nc:rpc>"#
    )
}

/// Generate a `<cancel-commit>` RPC request (RFC 6241 §8.4.4.1).
///
/// `persist_id` cancels a confirmed commit that was issued with a `<persist>`
/// token, possibly from a different session.
pub fn cancel_commit_xml(
    message_id: &str,
    persist_id: Option<&str>,
) -> Result<String, NetconfError> {
    let safe_id = escape_xml_attr(message_id);
    let body = match persist_id {
        Some(id) => {
            let escaped = escape_xml_text_exact(id).ok_or_else(|| {
                NetconfError::Protocol(crate::error::ProtocolError::Xml(
                    "persist-id contains a character XML 1.0 cannot represent".to_string(),
                ))
            })?;
            format!("\n    <nc:persist-id>{escaped}</nc:persist-id>\n  ")
        }
        None => String::new(),
    };
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{safe_id}">
  <nc:cancel-commit>{body}</nc:cancel-commit>
</nc:rpc>"#
    ))
}

/// RFC 5717's namespace for partial locking.
const PARTIAL_LOCK_NS: &str = "urn:ietf:params:xml:ns:netconf:partial-lock:1.0";

/// The base NETCONF XML namespace, which a reply's envelope normally declares
/// as the default. A device that omits RFC 5717's namespace on its output
/// elements leaves them inheriting this one.
///
/// There is exactly one. NETCONF 1.1 changed the capability URI
/// (`urn:ietf:params:netconf:base:1.1`) and the framing, but RFC 6241 keeps the
/// protocol XML namespace at `:base:1.0`; a `…xml:ns:netconf:base:1.1` does not
/// exist, and accepting it would let a foreign element be read as the lock id.
const BASE_XML_NS: &str = "urn:ietf:params:xml:ns:netconf:base:1.0";

/// Generate a `<partial-lock>` RPC request (RFC 5717 §2.4.1).
///
/// Each `select` is an XPath expression naming a subtree to lock. Prefixes used
/// in those expressions must be bound via `namespaces`; the declarations land on
/// `<partial-lock>` itself, where the expressions can see them.
///
/// The expressions are element *text* here, unlike the XPath filter's `select`
/// attribute, so they use the text escaper.
pub fn partial_lock_xml(
    message_id: &str,
    selects: &[String],
    namespaces: &[(String, String)],
) -> Result<String, NetconfError> {
    if selects.is_empty() {
        return Err(NetconfError::Protocol(ProtocolError::InvalidValue(
            "<partial-lock> requires at least one <select> expression".to_string(),
        )));
    }
    // The element is unprefixed (it carries PARTIAL_LOCK_NS as its default
    // namespace), so there is no envelope prefix a binding could shadow.
    let xmlns = crate::rpc::filter::render_namespace_bindings(namespaces, "", "partial-lock")?;

    let mut body = String::new();
    for select in selects {
        let escaped = escape_xml_text_exact(select).ok_or_else(|| {
            NetconfError::Protocol(ProtocolError::Xml(
                "partial-lock select expression contains a character XML 1.0 cannot \
                 represent"
                    .to_string(),
            ))
        })?;
        body.push_str(&format!("\n    <select>{escaped}</select>"));
    }

    let safe_id = escape_xml_attr(message_id);
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{safe_id}">
  <partial-lock xmlns="{PARTIAL_LOCK_NS}"{xmlns}>{body}
  </partial-lock>
</rpc>"#
    ))
}

/// Parse a `<partial-lock>` reply payload into a [`PartialLock`].
///
/// Deliberately crate-private. It runs on a payload `parse_rpc_reply` has
/// already validated — undeclared prefixes rejected, entity references
/// resolved, lexical checks applied. Exposed on its own it would accept input
/// that validation would have caught: `<lock-id>7&bogus;</lock-id>` reads as 7
/// once the unresolvable reference is dropped, and `<v:lock-id>` with an
/// undeclared `v` looks unqualified and so passes the namespace check.
pub(crate) fn parse_partial_lock_reply(payload: &str) -> Result<PartialLock, NetconfError> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    let wrapped = format!("<_>{payload}</_>");
    let mut reader = Reader::from_str(&wrapped);
    reader.config_mut().check_end_names = true;

    let mut lock_id: Option<u32> = None;
    let mut locked_nodes: Vec<LockedNode> = Vec::new();
    let mut current: Option<&'static str> = None;
    // Namespace declarations in scope, as a stack: a `<locked-node>` resolves
    // its prefixes against whatever is declared on it or on an enclosing
    // element of the payload.
    let mut scopes: Vec<Vec<(Option<String>, String)>> = Vec::new();
    // Accumulated across Text and GeneralRef: this quick-xml streams entity
    // references as their own events, so a loop reading only Text silently
    // truncates any value containing one (see `crate::xml_entity`). A locked
    // node path with an escaped `&` would otherwise come back cut in half.
    let mut text_buf = String::new();
    let mut buf = Vec::new();

    /// Namespace declarations on one start tag: `(Some(prefix), uri)` for a
    /// prefixed binding, `(None, uri)` for the default `xmlns`.
    ///
    /// Values go through the reply parser's own `decode_attribute`, which
    /// unescapes and validates them. Reading `attr.value` raw would store
    /// `urn:x?a=1&amp;b=2` instead of the actual URI, leaving the binding wrong
    /// and the prefixed path unresolvable.
    fn bindings_of(
        e: &quick_xml::events::BytesStart<'_>,
    ) -> Result<Vec<(Option<String>, String)>, NetconfError> {
        let mut out = Vec::new();
        for attr in e.attributes().with_checks(true) {
            // `with_checks(true)` reports duplicate attributes and other
            // malformedness. Swallowing that would let this public helper
            // return a lock from a document no conforming parser would accept.
            let attr = attr.map_err(|e| {
                NetconfError::Protocol(ProtocolError::Xml(format!(
                    "partial-lock reply has an invalid attribute: {e}"
                )))
            })?;
            let key: &str = attr.key.as_ref();
            // 0.42 decodes at the reader, so a prefix that is not valid UTF-8
            // fails the read rather than arriving here to be skipped.
            let prefix = if key == "xmlns" {
                None
            } else if let Some(p) = key.strip_prefix("xmlns:") {
                Some(p.to_string())
            } else {
                continue;
            };
            let value = crate::rpc::reply::lexical::decode_attribute(
                attr.value.as_ref(),
                "namespace declaration value",
            )
            .map_err(|e| NetconfError::Protocol(ProtocolError::Xml(e.to_string())))?;
            out.push((prefix, value));
        }
        Ok(out)
    }

    /// Resolve an element's namespace against the declarations in scope.
    fn resolve_ns(raw_name: &str, scopes: &[Vec<(Option<String>, String)>]) -> Option<String> {
        // `:` is ASCII, so splitting on the first one is the same operation it
        // was over bytes — no char boundary can fall inside it.
        let prefix = raw_name.find(':').map(|i| raw_name[..i].to_string());
        // `xml` is bound implicitly and never appears in a declaration, so it
        // must be resolved here; otherwise <xml:lock-id> looks unqualified and
        // would be wrongly accepted.
        if prefix.as_deref() == Some("xml") {
            return Some("http://www.w3.org/XML/1998/namespace".to_string());
        }

        for scope in scopes.iter().rev() {
            for (p, uri) in scope {
                if p.as_deref() == prefix.as_deref() {
                    // `xmlns=""` is an *undeclaration* (Namespaces in XML §6.2):
                    // the element is in NO namespace, not in one whose URI is
                    // empty. Returning Some("") would reject a valid unqualified
                    // <lock-id> — the costly direction, since the server has
                    // already granted the lock and the caller would be unable to
                    // release it.
                    return if uri.is_empty() {
                        None
                    } else {
                        Some(uri.clone())
                    };
                }
            }
        }
        None
    }

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(_)) if current.is_some() => {
                return Err(NetconfError::Protocol(ProtocolError::Xml(
                    "partial-lock reply has a nested element inside a scalar field".to_string(),
                )));
            }
            Ok(Event::Start(e)) => {
                scopes.push(bindings_of(&e)?);
                // Match on the *expanded* name. Matching the local name alone
                // would accept a `<v:lock-id>` from an unrelated namespace and
                // hand back a foreign id as a successful lock. An unqualified
                // element is accepted as well: RFC 5717 puts these in its own
                // namespace, but servers that omit it are common enough that
                // refusing them outright would be less useful than the risk it
                // removes.
                let ns = resolve_ns(e.name().as_ref(), &scopes);
                let in_scope = match ns.as_deref() {
                    Some(PARTIAL_LOCK_NS) => true,
                    // No namespace, or the base namespace inherited from the
                    // reply envelope. Devices that omit RFC 5717's namespace on
                    // their output elements are common, and their `<lock-id>`
                    // arrives carrying whatever `<rpc-reply>` declared as the
                    // default. Rejecting that would error out *after* the server
                    // granted the lock, leaving the caller unable to release it
                    // — much worse than the risk of accepting a stray element.
                    None => true,
                    Some(BASE_XML_NS) => true,
                    // A genuinely foreign namespace (a vendor extension, say) is
                    // still not RFC 5717 output.
                    Some(_) => false,
                };
                current = if in_scope {
                    match e.local_name().as_ref() {
                        "lock-id" => Some("lock-id"),
                        "locked-node" => Some("locked-node"),
                        _ => None,
                    }
                } else {
                    None
                };
                text_buf.clear();
            }
            Ok(Event::Empty(_)) if current.is_some() => {
                // `<lock-id>1<meta/>2</lock-id>` is well-formed but not valid
                // here. Ignoring the child would leave `current` set and
                // concatenate the surrounding text into "12" — a lock id the
                // device never sent.
                return Err(NetconfError::Protocol(ProtocolError::Xml(
                    "partial-lock reply has a nested element inside a scalar field".to_string(),
                )));
            }
            Ok(Event::Empty(_)) => {}
            Ok(Event::Text(ref text)) if current.is_some() => {
                text_buf.push_str(text);
            }
            Ok(Event::CData(ref cdata)) if current.is_some() => {
                text_buf.push_str(cdata);
            }
            Ok(Event::GeneralRef(ref entity)) if current.is_some() => {
                if let Some(resolved) = crate::xml_entity::resolve_entity_ref(entity) {
                    text_buf.push_str(&resolved);
                }
            }
            Ok(Event::End(_)) => {
                let text = text_buf.trim().to_string();
                match current {
                    Some("lock-id") if !text.is_empty() => {
                        // RFC 5717 permits exactly one. Taking the last would
                        // pick arbitrarily between them, and `partial_unlock`
                        // would then release a lock we do not hold while the
                        // real one stays held.
                        if lock_id.is_some() {
                            return Err(NetconfError::Protocol(ProtocolError::Xml(
                                "partial-lock reply carried more than one <lock-id>".to_string(),
                            )));
                        }
                        lock_id = Some(text.parse::<u32>().map_err(|_| {
                            // Bounded: the value is device-controlled and the
                            // reply cap is 100 MB, so formatting it whole would
                            // duplicate an arbitrarily large allocation into an
                            // error string and a log line.
                            let preview: String = text.chars().take(32).collect();
                            NetconfError::Protocol(ProtocolError::Xml(format!(
                                "<lock-id> is not a u32 (first 32 chars: {preview:?})"
                            )))
                        })?);
                    }
                    Some("locked-node") if !text.is_empty() => {
                        // Innermost binding wins for a repeated prefix. Only
                        // prefixed bindings are useful to a caller resolving the
                        // path, so the default xmlns is not reported.
                        let mut namespaces: Vec<(String, String)> = Vec::new();
                        for scope in scopes.iter() {
                            for (p, uri) in scope {
                                let Some(p) = p else { continue };
                                match namespaces.iter_mut().find(|(np, _)| np == p) {
                                    Some(entry) => entry.1 = uri.clone(),
                                    None => namespaces.push((p.clone(), uri.clone())),
                                }
                            }
                        }
                        locked_nodes.push(LockedNode {
                            path: text,
                            namespaces,
                        });
                    }
                    _ => {}
                }
                current = None;
                text_buf.clear();
                scopes.pop();
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(NetconfError::Protocol(ProtocolError::Xml(format!(
                    "partial-lock reply is not well-formed: {e}"
                ))));
            }
            _ => {}
        }
        buf.clear();
    }

    let lock_id = lock_id.ok_or_else(|| {
        NetconfError::Protocol(ProtocolError::Xml(
            "<partial-lock> reply carried no <lock-id>; the lock cannot be released \
             without it"
                .to_string(),
        ))
    })?;
    Ok(PartialLock {
        lock_id,
        locked_nodes,
    })
}

/// Generate a `<partial-unlock>` RPC request (RFC 5717 §2.4.2).
pub fn partial_unlock_xml(message_id: &str, lock_id: u32) -> String {
    let safe_id = escape_xml_attr(message_id);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{safe_id}">
  <partial-unlock xmlns="{PARTIAL_LOCK_NS}">
    <lock-id>{lock_id}</lock-id>
  </partial-unlock>
</rpc>"#
    )
}

/// Generate a `<commit>` RPC request.
pub fn commit_xml(message_id: &str) -> String {
    let safe_id = escape_xml_attr(message_id);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{safe_id}">
  <nc:commit/>
</nc:rpc>"#,
    )
}

/// Generate a confirmed `<commit>` RPC request (RFC 6241 §8.4).
///
/// The device will automatically rollback the commit if a confirming
/// `<commit>` is not received within `confirm_timeout` seconds.
pub fn confirmed_commit_xml(message_id: &str, confirm_timeout: u32) -> String {
    let safe_id = escape_xml_attr(message_id);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{safe_id}">
  <nc:commit>
    <nc:confirmed/>
    <nc:confirm-timeout>{confirm_timeout}</nc:confirm-timeout>
  </nc:commit>
</nc:rpc>"#,
    )
}

/// Generate a `<validate>` RPC request.
pub fn validate_xml(message_id: &str, source: Datastore) -> String {
    let safe_id = escape_xml_attr(message_id);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{safe_id}">
  <nc:validate>
    <nc:source>
      <nc:{source}/>
    </nc:source>
  </nc:validate>
</nc:rpc>"#,
        source = source.as_xml_tag(),
    )
}

/// Generate a `<close-session>` RPC request.
pub fn close_session_xml(message_id: &str) -> String {
    let safe_id = escape_xml_attr(message_id);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{safe_id}">
  <nc:close-session/>
</nc:rpc>"#,
    )
}

/// Generate a `<kill-session>` RPC request.
pub fn kill_session_xml(message_id: &str, session_id: u32) -> String {
    let safe_id = escape_xml_attr(message_id);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{safe_id}">
  <nc:kill-session>
    <nc:session-id>{session_id}</nc:session-id>
  </nc:kill-session>
</nc:rpc>"#,
    )
}

// ── Junos-specific operations ────────────────────────────────────────

/// Generate a Junos `<open-configuration>` RPC request.
///
/// Opens a private or exclusive configuration database. Required on
/// chassis-clustered Junos devices before loading configuration.
pub fn open_configuration_xml(message_id: &str, mode: OpenConfigurationMode) -> String {
    let mode_element = match mode {
        OpenConfigurationMode::Private => "<nc:private/>",
        OpenConfigurationMode::Exclusive => "<nc:exclusive/>",
    };
    let safe_id = escape_xml_attr(message_id);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{safe_id}">
  <nc:open-configuration>
    {mode_element}
  </nc:open-configuration>
</nc:rpc>"#,
    )
}

/// Generate a Junos `<close-configuration>` RPC request.
///
/// Closes a previously opened private or exclusive configuration database.
pub fn close_configuration_xml(message_id: &str) -> String {
    let safe_id = escape_xml_attr(message_id);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{safe_id}">
  <nc:close-configuration/>
</nc:rpc>"#,
    )
}

/// Generate a Junos `<commit-configuration>` RPC request.
///
/// This is the Junos-native commit RPC. Use this instead of standard
/// `<commit>` when working with Junos private/exclusive configuration
/// databases opened via `<open-configuration>`.
pub fn commit_configuration_xml(message_id: &str) -> String {
    build_commit_configuration_xml(message_id, None)
}

/// Generate a Junos `<commit-configuration>` RPC carrying a `<log>` comment.
///
/// The comment is visible in Junos `show system commit`. `log` is XML-escaped
/// here, so callers pass plain text and must not pre-escape it.
///
/// This is a separate function rather than an `Option` parameter on
/// [`commit_configuration_xml`] deliberately: this module is public API, so
/// changing that function's arity would break existing callers at source.
pub fn commit_configuration_with_log_xml(message_id: &str, log: &str) -> String {
    build_commit_configuration_xml(message_id, Some(log))
}

/// Shared builder for the two `<commit-configuration>` shapes above.
///
/// `None` emits the bare self-closing element, byte-identical to what
/// `commit_configuration_xml` produced before the log variant existed.
fn build_commit_configuration_xml(message_id: &str, log: Option<&str>) -> String {
    let safe_id = escape_xml_attr(message_id);
    let Some(text) = log else {
        return format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{safe_id}">
  <nc:commit-configuration/>
</nc:rpc>"#,
        );
    };
    // The log is element character data, not an attribute — escape_xml_text,
    // matching how load_configuration_xml escapes its Text-format payload.
    let escaped_log = escape_xml_text(text);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{safe_id}">
  <nc:commit-configuration>
    <nc:log>{escaped_log}</nc:log>
  </nc:commit-configuration>
</nc:rpc>"#,
    )
}

/// Generate a Junos `<load-configuration rollback="N"/>` RPC request.
///
/// Rolls back the candidate configuration to a previous commit.
/// `rollback` is the rollback index (0 = most recent commit).
pub fn rollback_configuration_xml(message_id: &str, rollback: u32) -> String {
    let safe_id = escape_xml_attr(message_id);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{safe_id}">
  <nc:load-configuration rollback="{rollback}"/>
</nc:rpc>"#,
    )
}

/// Generate a Junos `<get-configuration compare="rollback">` RPC request.
///
/// Returns the diff between the candidate configuration and a previous
/// commit. `rollback` is the rollback index (0 = most recent commit).
pub fn get_configuration_compare_xml(message_id: &str, rollback: u32) -> String {
    let safe_id = escape_xml_attr(message_id);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{safe_id}">
  <nc:get-configuration compare="rollback" rollback="{rollback}" format="text"/>
</nc:rpc>"#,
    )
}

/// Generate a Junos `<load-configuration>` RPC request.
///
/// The `config` parameter must be well-formed for the given format:
/// - `Text` format: Junos set/delete commands or curly-brace config —
///   XML-escaped automatically before insertion
/// - `Xml` format: Junos XML configuration elements — inserted verbatim;
///   do not pass untrusted user input without validation
pub fn load_configuration_xml(
    message_id: &str,
    action: LoadAction,
    format: LoadFormat,
    config: &str,
) -> String {
    let safe_id = escape_xml_attr(message_id);
    let wrapper = match format {
        LoadFormat::Text => match action {
            LoadAction::Set => "configuration-set",
            _ => "configuration-text",
        },
        LoadFormat::Xml => "configuration",
    };
    // Text-format config is character data and routinely contains `&`, `<`,
    // `>` (descriptions, login messages, URLs) — escape it so the generated
    // RPC stays well-formed. XML-format config is real XML: verbatim.
    let payload = match format {
        LoadFormat::Text => escape_xml_text(config),
        LoadFormat::Xml => config.to_string(),
    };
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{safe_id}">
  <nc:load-configuration action="{action}" format="{format}">
    <nc:{wrapper}>{payload}</nc:{wrapper}>
  </nc:load-configuration>
</nc:rpc>"#,
        action = action.as_str(),
        format = format.as_str(),
    )
}

/// Generate a `<create-subscription>` RPC request (RFC 5277).
///
/// All parameters are optional:
/// - `stream`: event stream name (device default if omitted, typically "NETCONF")
/// - `filter`: subtree filter XML (inserted verbatim)
/// - `start_time`: RFC 3339 timestamp to start replay
/// - `stop_time`: RFC 3339 timestamp to stop notifications
pub fn create_subscription_xml(
    message_id: &str,
    stream: Option<&str>,
    filter: Option<&str>,
    start_time: Option<&str>,
    stop_time: Option<&str>,
) -> String {
    let safe_id = escape_xml_attr(message_id);

    let stream_xml = match stream {
        Some(s) => {
            let safe = escape_xml_text(s);
            format!("\n    <stream>{safe}</stream>")
        }
        None => String::new(),
    };
    let filter_xml = match filter {
        Some(f) => format!("\n    <filter type=\"subtree\">\n      {f}\n    </filter>"),
        None => String::new(),
    };
    let start_xml = match start_time {
        Some(t) => {
            let safe = escape_xml_text(t);
            format!("\n    <startTime>{safe}</startTime>")
        }
        None => String::new(),
    };
    let stop_xml = match stop_time {
        Some(t) => {
            let safe = escape_xml_text(t);
            format!("\n    <stopTime>{safe}</stopTime>")
        }
        None => String::new(),
    };

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{safe_id}">
  <create-subscription xmlns="urn:ietf:params:xml:ns:netconf:notification:1.0">{stream_xml}{filter_xml}{start_xml}{stop_xml}
  </create-subscription>
</nc:rpc>"#,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_config_running_no_filter() {
        let xml = get_config_xml("1", Datastore::Running, None);
        assert!(xml.contains("message-id=\"1\""));
        assert!(xml.contains("<nc:running/>"));
        assert!(xml.contains("<nc:get-config>"));
        assert!(!xml.contains("<nc:filter"));
    }

    #[test]
    fn test_copy_config_datastore_to_datastore() {
        let xml = copy_config_xml(
            "1",
            &ConfigLocation::Datastore(Datastore::Startup),
            &CopySource::Datastore(Datastore::Running),
        );
        assert!(xml.contains("<nc:copy-config>"), "got {xml}");
        // Order matters: RFC 6241 puts <target> before <source>.
        let t = xml.find("<nc:target>").expect("target");
        let src = xml.find("<nc:source>").expect("source");
        assert!(t < src, "target must precede source: {xml}");
        assert!(xml.contains("<nc:startup/>"), "got {xml}");
        assert!(xml.contains("<nc:running/>"), "got {xml}");
    }

    #[test]
    fn test_copy_config_url_is_text_escaped() {
        let xml = copy_config_xml(
            "2",
            &ConfigLocation::Url("file:///tmp/a&b<c".to_string()),
            &CopySource::Datastore(Datastore::Running),
        );
        assert!(xml.contains("<nc:url>"), "got {xml}");
        assert!(xml.contains("file:///tmp/a&amp;b&lt;c"), "got {xml}");
        assert!(!xml.contains("a&b<c"), "unescaped url: {xml}");
    }

    #[test]
    fn test_copy_config_inline_config_source() {
        let xml = copy_config_xml(
            "9",
            &ConfigLocation::Datastore(Datastore::Candidate),
            &CopySource::Config("<system><host-name>r1</host-name></system>".to_string()),
        );
        assert!(xml.contains("<nc:config>"), "got {xml}");
        assert!(xml.contains("<host-name>r1</host-name>"), "got {xml}");
        assert!(!xml.contains("<nc:url>"), "got {xml}");
    }

    #[test]
    fn test_delete_config_url_is_text_escaped() {
        let xml = delete_config_xml("10", &DeleteTarget::Url("file:///t/a&b".to_string()));
        assert!(
            xml.contains("<nc:url>file:///t/a&amp;b</nc:url>"),
            "got {xml}"
        );
    }

    #[test]
    fn test_delete_config_targets_only() {
        let xml = delete_config_xml("3", &DeleteTarget::Startup);
        assert!(xml.contains("<nc:delete-config>"), "got {xml}");
        assert!(xml.contains("<nc:startup/>"), "got {xml}");
        assert!(
            !xml.contains("<nc:source>"),
            "delete takes no source: {xml}"
        );
    }

    #[test]
    fn test_cancel_commit_without_persist_id() {
        let xml = cancel_commit_xml("4", None).unwrap();
        assert!(
            xml.contains("<nc:cancel-commit></nc:cancel-commit>"),
            "got {xml}"
        );
        assert!(!xml.contains("persist-id"), "got {xml}");
    }

    #[test]
    fn test_cancel_commit_with_persist_id_escapes_it() {
        let xml = cancel_commit_xml("5", Some("token&<1")).unwrap();
        assert!(
            xml.contains("<nc:persist-id>token&amp;&lt;1</nc:persist-id>"),
            "got {xml}"
        );
    }

    #[test]
    fn test_cancel_commit_persist_id_preserves_cr() {
        // XML 1.0 line-ending normalization turns a literal CR in text content
        // into LF, which would corrupt an opaque token minted elsewhere.
        let xml = cancel_commit_xml("6", Some("a\rb")).unwrap();
        assert!(xml.contains("&#13;"), "got {xml}");
        let body = xml
            .split_once("<nc:persist-id>")
            .and_then(|(_, r)| r.split_once("</nc:persist-id>"))
            .map(|(v, _)| v)
            .expect("persist-id present");
        assert!(!body.contains('\r'), "raw CR survives: {body:?}");
    }

    #[test]
    fn test_cancel_commit_rejects_invalid_xml_chars() {
        assert!(cancel_commit_xml("7", Some("a\u{1}b")).is_err());
        assert!(cancel_commit_xml("7", Some("a\u{fffe}b")).is_err());
    }

    #[test]
    fn test_copy_config_carries_with_defaults() {
        let xml = copy_config_with_defaults_xml(
            "11",
            &ConfigLocation::Datastore(Datastore::Startup),
            &CopySource::Datastore(Datastore::Running),
            WithDefaults::ReportAll,
        );
        assert!(xml.contains(">report-all</with-defaults>"), "got {xml}");
        // RFC 6243 places it after <source>.
        let src = xml.find("</nc:source>").expect("source");
        let wd = xml.find("<with-defaults").expect("with-defaults");
        assert!(src < wd, "with-defaults follows source: {xml}");
    }

    #[test]
    fn test_copy_config_without_mode_has_no_with_defaults() {
        let xml = copy_config_xml(
            "12",
            &ConfigLocation::Datastore(Datastore::Startup),
            &CopySource::Datastore(Datastore::Running),
        );
        assert!(!xml.contains("with-defaults"), "got {xml}");
    }

    #[test]
    fn test_partial_lock_emits_selects_and_namespaces() {
        let xml = partial_lock_xml(
            "1",
            &["/if:interfaces/if:interface[if:name='ge-0/0/0']".to_string()],
            &[(
                "if".to_string(),
                "urn:ietf:params:xml:ns:yang:ietf-interfaces".to_string(),
            )],
        )
        .unwrap();
        assert!(
            xml.contains(
                r#"<partial-lock xmlns="urn:ietf:params:xml:ns:netconf:partial-lock:1.0""#
            ),
            "got {xml}"
        );
        assert!(
            xml.contains(r#"xmlns:if="urn:ietf:params:xml:ns:yang:ietf-interfaces""#),
            "got {xml}"
        );
        assert!(xml.contains("<select>/if:interfaces"), "got {xml}");
    }

    #[test]
    fn test_partial_lock_escapes_select_as_text() {
        // element text, not an attribute - so &, < and > matter and quotes do not
        let xml =
            partial_lock_xml("2", &["/x[a='1' and b<'2' and c='&']".to_string()], &[]).unwrap();
        assert!(xml.contains("&lt;"), "got {xml}");
        assert!(xml.contains("&amp;"), "got {xml}");
    }

    #[test]
    fn test_partial_lock_requires_at_least_one_select() {
        let err = partial_lock_xml("3", &[], &[]).unwrap_err();
        assert!(err.to_string().contains("at least one"), "got {err}");
    }

    #[test]
    fn test_partial_lock_rejects_bad_namespace_bindings() {
        // shared validation with the XPath filter
        assert!(partial_lock_xml(
            "4",
            &["/x".to_string()],
            &[("xmlns".into(), "urn:x".into())]
        )
        .is_err());
        assert!(partial_lock_xml(
            "4",
            &["/x".to_string()],
            &[("a\u{b2}".into(), "urn:x".into())]
        )
        .is_err());
        assert!(partial_lock_xml("4", &["/x".to_string()], &[("a".into(), "".into())]).is_err());
    }

    #[test]
    fn test_partial_unlock_carries_the_lock_id() {
        let xml = partial_unlock_xml("5", 127);
        assert!(xml.contains("<lock-id>127</lock-id>"), "got {xml}");
        assert!(
            xml.contains(
                r#"<partial-unlock xmlns="urn:ietf:params:xml:ns:netconf:partial-lock:1.0">"#
            ),
            "got {xml}"
        );
    }

    #[test]
    fn test_parse_partial_lock_reply() {
        let reply = r#"<lock-id xmlns="urn:ietf:params:xml:ns:netconf:partial-lock:1.0">127</lock-id>
<locked-node xmlns="urn:ietf:params:xml:ns:netconf:partial-lock:1.0">/interfaces/interface[name='eth0']</locked-node>"#;
        let got = parse_partial_lock_reply(reply).unwrap();
        assert_eq!(got.lock_id, 127);
        assert_eq!(got.locked_nodes.len(), 1);
        assert!(got.locked_nodes[0].path.contains("eth0"));
    }

    #[test]
    fn test_parse_partial_lock_reply_stitches_entities() {
        // Entities stream as their own events; a naive loop truncates here.
        let reply = r#"<lock-id>7</lock-id><locked-node>/a[n='x&amp;y']</locked-node>"#;
        let got = parse_partial_lock_reply(reply).unwrap();
        assert_eq!(got.lock_id, 7);
        assert_eq!(
            got.locked_nodes[0].path, "/a[n='x&y']",
            "entity must be stitched back, not dropped"
        );
    }

    #[test]
    fn test_parse_partial_lock_reply_captures_prefix_bindings() {
        // The server may use its own prefixes; the path is unusable without them.
        let reply = r#"<lock-id>9</lock-id><locked-node xmlns:x="urn:example:if">/x:interfaces</locked-node>"#;
        let got = parse_partial_lock_reply(reply).unwrap();
        assert_eq!(got.locked_nodes[0].path, "/x:interfaces");
        assert_eq!(
            got.locked_nodes[0].namespaces,
            vec![("x".to_string(), "urn:example:if".to_string())]
        );
    }

    #[test]
    fn test_partial_lock_folds_identical_duplicate_prefixes() {
        // Combining bindings for several selects naturally repeats them; a
        // duplicate xmlns attribute would be malformed XML.
        let xml = partial_lock_xml(
            "6",
            &["/a:x".to_string(), "/a:y".to_string()],
            &[
                ("a".to_string(), "urn:a".to_string()),
                ("a".to_string(), "urn:a".to_string()),
            ],
        )
        .unwrap();
        assert_eq!(xml.matches("xmlns:a=").count(), 1, "duplicate xmlns: {xml}");
    }

    #[test]
    fn test_partial_lock_rejects_conflicting_prefix_bindings() {
        let err = partial_lock_xml(
            "7",
            &["/a:x".to_string()],
            &[
                ("a".to_string(), "urn:one".to_string()),
                ("a".to_string(), "urn:two".to_string()),
            ],
        )
        .unwrap_err();
        assert!(err.to_string().contains("two different URIs"), "got {err}");
    }

    #[test]
    fn test_parse_partial_lock_reply_unescapes_namespace_uris() {
        let reply = r#"<lock-id>3</lock-id><locked-node xmlns:x="urn:example?a=1&amp;b=2">/x:i</locked-node>"#;
        let got = parse_partial_lock_reply(reply).unwrap();
        assert_eq!(
            got.locked_nodes[0].namespaces,
            vec![("x".to_string(), "urn:example?a=1&b=2".to_string())],
            "the stored URI must be the real one, not the escaped source"
        );
    }

    #[test]
    fn test_parse_partial_lock_reply_ignores_foreign_namespaces() {
        // A <v:lock-id> from an unrelated namespace is not RFC 5717 output;
        // accepting it would return someone else's id as our lock.
        let reply = r#"<v:lock-id xmlns:v="urn:vendor:private">999</v:lock-id>"#;
        let err = parse_partial_lock_reply(reply).unwrap_err();
        assert!(err.to_string().contains("lock-id"), "got {err}");
    }

    #[test]
    fn test_parse_partial_lock_reply_accepts_the_rfc_namespace_prefixed() {
        let reply = r#"<pl:lock-id xmlns:pl="urn:ietf:params:xml:ns:netconf:partial-lock:1.0">5</pl:lock-id>"#;
        assert_eq!(parse_partial_lock_reply(reply).unwrap().lock_id, 5);
    }

    #[test]
    fn test_parse_partial_lock_reply_accepts_undeclared_default_namespace() {
        // xmlns="" is an undeclaration: the element is in NO namespace, the
        // accepted unqualified form. Rejecting it would error out after the
        // server had already granted the lock.
        let reply = r#"<lock-id xmlns="">7</lock-id>"#;
        assert_eq!(parse_partial_lock_reply(reply).unwrap().lock_id, 7);
    }

    #[test]
    fn test_parse_partial_lock_reply_rejects_the_implicit_xml_prefix() {
        assert!(parse_partial_lock_reply("<xml:lock-id>7</xml:lock-id>").is_err());
    }

    #[test]
    fn test_parse_partial_lock_reply_default_namespace_scopes_correctly() {
        let ok = r#"<x xmlns="urn:ietf:params:xml:ns:netconf:partial-lock:1.0"><lock-id>4</lock-id></x>"#;
        assert_eq!(parse_partial_lock_reply(ok).unwrap().lock_id, 4);
        let foreign = r#"<x xmlns="urn:vendor:private"><lock-id>4</lock-id></x>"#;
        assert!(parse_partial_lock_reply(foreign).is_err());
    }

    #[test]
    fn test_parse_partial_lock_reply_accepts_inherited_base_namespace() {
        let reply =
            r#"<x xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><lock-id>7</lock-id></x>"#;
        assert_eq!(parse_partial_lock_reply(reply).unwrap().lock_id, 7);
    }

    #[test]
    fn test_parse_partial_lock_reply_rejects_malformed_attributes() {
        // Duplicate xmlns:x is not well-formed; returning a lock from it would
        // accept a document no conforming parser would.
        let reply = r#"<lock-id xmlns:x="urn:a" xmlns:x="urn:b">7</lock-id>"#;
        assert!(parse_partial_lock_reply(reply).is_err());
    }

    #[test]
    fn test_parse_partial_lock_reply_rejects_duplicate_lock_ids() {
        let reply = "<lock-id>1</lock-id><lock-id>2</lock-id>";
        let err = parse_partial_lock_reply(reply).unwrap_err();
        assert!(err.to_string().contains("more than one"), "got {err}");
    }

    #[test]
    fn test_parse_partial_lock_reply_rejects_mixed_content() {
        // Well-formed but schema-invalid; concatenating would invent id 12.
        assert!(parse_partial_lock_reply("<lock-id>1<meta/>2</lock-id>").is_err());
        assert!(parse_partial_lock_reply("<lock-id>1<m>x</m>2</lock-id>").is_err());
        assert!(parse_partial_lock_reply("<locked-node>/a<m/>/b</locked-node>").is_err());
    }

    #[test]
    fn test_parse_partial_lock_reply_rejects_the_invented_base_1_1_namespace() {
        // ...xml:ns:netconf:base:1.1 is not a real namespace; NETCONF 1.1 keeps
        // the protocol namespace at :base:1.0.
        let reply =
            r#"<x xmlns="urn:ietf:params:xml:ns:netconf:base:1.1"><lock-id>9</lock-id></x>"#;
        assert!(parse_partial_lock_reply(reply).is_err());
    }

    #[test]
    fn test_parse_partial_lock_reply_accepts_cdata() {
        let reply = "<lock-id><![CDATA[7]]></lock-id>";
        assert_eq!(parse_partial_lock_reply(reply).unwrap().lock_id, 7);
    }

    #[test]
    fn test_parse_partial_lock_reply_without_lock_id_is_an_error() {
        let err = parse_partial_lock_reply("<locked-node>/a</locked-node>").unwrap_err();
        assert!(err.to_string().contains("lock-id"), "got {err}");
    }

    #[test]
    fn test_with_defaults_uses_the_rfc6243_namespace() {
        let xml = get_config_with_defaults_xml("1", Datastore::Running, None, WithDefaults::Trim);
        assert!(
            xml.contains(
                r#"<with-defaults xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults">trim</with-defaults>"#
            ),
            "with-defaults must carry its own namespace: {xml}"
        );
    }

    #[test]
    fn test_with_defaults_modes_render_their_wire_tokens() {
        for (mode, token) in [
            (WithDefaults::ReportAll, "report-all"),
            (WithDefaults::ReportAllTagged, "report-all-tagged"),
            (WithDefaults::Trim, "trim"),
            (WithDefaults::Explicit, "explicit"),
        ] {
            let xml = get_with_defaults_xml("2", None, mode);
            assert!(
                xml.contains(&format!(">{token}</with-defaults>")),
                "got {xml}"
            );
        }
    }

    #[test]
    fn test_with_defaults_composes_with_a_filter() {
        let xml = get_config_with_defaults_xml(
            "3",
            Datastore::Running,
            Some("<interfaces/>"),
            WithDefaults::ReportAll,
        );
        let f = xml.find("<nc:filter").expect("filter");
        let w = xml.find("<with-defaults").expect("with-defaults");
        assert!(f < w, "filter precedes with-defaults per the RFC: {xml}");
    }

    #[test]
    fn test_get_config_xpath_emits_type_and_source() {
        let f = XPathFilter::new("/if:interfaces")
            .namespace("if", "urn:ietf:params:xml:ns:yang:ietf-interfaces");
        let xml = get_config_xpath_xml("7", Datastore::Running, &f).unwrap();
        assert!(xml.contains(r#"type="xpath""#), "got {xml}");
        assert!(xml.contains(r#"select="/if:interfaces""#), "got {xml}");
        assert!(xml.contains("<nc:running/>"), "got {xml}");
        assert!(xml.contains(r#"message-id="7""#), "got {xml}");
        // XPath filters are attribute-only: no child content in <filter>.
        assert!(xml.contains("/>"), "filter should be self-closing: {xml}");
        assert!(!xml.contains("type=\"subtree\""), "got {xml}");
    }

    #[test]
    fn test_get_xpath_has_no_source_element() {
        let xml = get_xpath_xml("8", &XPathFilter::new("/x")).unwrap();
        assert!(xml.contains("<nc:get>"), "got {xml}");
        assert!(!xml.contains("<nc:source>"), "get takes no source: {xml}");
        assert!(xml.contains(r#"type="xpath""#), "got {xml}");
    }

    #[test]
    fn test_get_config_with_filter() {
        let xml = get_config_xml("2", Datastore::Running, Some("<interfaces/>"));
        assert!(xml.contains("<nc:filter type=\"subtree\">"));
        assert!(xml.contains("<interfaces/>"));
    }

    #[test]
    fn test_edit_config_basic() {
        let params = EditConfigParams {
            target: Datastore::Candidate,
            config: "<interface><name>ge-0/0/0</name></interface>",
            default_operation: Some(DefaultOperation::Merge),
            test_option: None,
            error_option: None,
        };
        let xml = edit_config_xml("3", &params);
        assert!(xml.contains("<nc:candidate/>"));
        assert!(xml.contains("<nc:default-operation>merge</nc:default-operation>"));
        assert!(xml.contains("ge-0/0/0"));
    }

    #[test]
    fn test_edit_config_all_options() {
        let params = EditConfigParams {
            target: Datastore::Candidate,
            config: "<test/>",
            default_operation: Some(DefaultOperation::Replace),
            test_option: Some(TestOption::TestThenSet),
            error_option: Some(ErrorOption::RollbackOnError),
        };
        let xml = edit_config_xml("4", &params);
        assert!(xml.contains("<nc:default-operation>replace</nc:default-operation>"));
        assert!(xml.contains("<nc:test-option>test-then-set</nc:test-option>"));
        assert!(xml.contains("<nc:error-option>rollback-on-error</nc:error-option>"));
    }

    #[test]
    fn test_lock_candidate() {
        let xml = lock_xml("5", Datastore::Candidate);
        assert!(xml.contains("<nc:lock>"));
        assert!(xml.contains("<nc:candidate/>"));
    }

    #[test]
    fn test_unlock_candidate() {
        let xml = unlock_xml("6", Datastore::Candidate);
        assert!(xml.contains("<nc:unlock>"));
        assert!(xml.contains("<nc:candidate/>"));
    }

    #[test]
    fn test_commit() {
        let xml = commit_xml("7");
        assert!(xml.contains("<nc:commit/>"));
    }

    #[test]
    fn test_validate() {
        let xml = validate_xml("8", Datastore::Candidate);
        assert!(xml.contains("<nc:validate>"));
        assert!(xml.contains("<nc:candidate/>"));
    }

    #[test]
    fn test_close_session() {
        let xml = close_session_xml("9");
        assert!(xml.contains("<nc:close-session/>"));
    }

    #[test]
    fn test_kill_session() {
        let xml = kill_session_xml("10", 42);
        assert!(xml.contains("<nc:kill-session>"));
        assert!(xml.contains("<nc:session-id>42</nc:session-id>"));
    }

    #[test]
    fn test_message_ids_are_correct() {
        let xml = get_config_xml("101", Datastore::Running, None);
        assert!(xml.contains("message-id=\"101\""));
    }

    // ── Junos-specific operation tests ──

    #[test]
    fn test_open_configuration_private() {
        let xml = open_configuration_xml("20", OpenConfigurationMode::Private);
        assert!(xml.contains("<nc:open-configuration>"));
        assert!(xml.contains("<nc:private/>"));
        assert!(xml.contains("message-id=\"20\""));
    }

    #[test]
    fn test_open_configuration_exclusive() {
        let xml = open_configuration_xml("21", OpenConfigurationMode::Exclusive);
        assert!(xml.contains("<nc:open-configuration>"));
        assert!(xml.contains("<nc:exclusive/>"));
    }

    #[test]
    fn test_close_configuration() {
        let xml = close_configuration_xml("22");
        assert!(xml.contains("<nc:close-configuration/>"));
        assert!(xml.contains("message-id=\"22\""));
    }

    #[test]
    fn test_load_configuration_set_text() {
        let xml = load_configuration_xml(
            "23",
            LoadAction::Set,
            LoadFormat::Text,
            "set system host-name test123",
        );
        assert!(xml.contains(r#"action="set""#));
        assert!(xml.contains(r#"format="text""#));
        assert!(xml
            .contains("<nc:configuration-set>set system host-name test123</nc:configuration-set>"));
    }

    #[test]
    fn test_load_configuration_merge_text() {
        let xml = load_configuration_xml(
            "24",
            LoadAction::Merge,
            LoadFormat::Text,
            "system { host-name test123; }",
        );
        assert!(xml.contains(r#"action="merge""#));
        assert!(xml.contains("<nc:configuration-text>"));
    }

    #[test]
    fn test_load_configuration_text_escapes_special_chars() {
        // Junos text/set config legitimately contains &, <, > (descriptions,
        // login messages, URLs). It must be XML-escaped on the wire or the
        // generated RPC is malformed.
        let xml = load_configuration_xml(
            "26",
            LoadAction::Set,
            LoadFormat::Text,
            r#"set system login message "a & b <ok>""#,
        );
        assert!(
            xml.contains("a &amp; b &lt;ok&gt;"),
            "text config must be XML-escaped: {xml}"
        );
        // The generated RPC (minus the XML declaration) must parse as
        // well-formed XML.
        let body = xml
            .split_once('\n')
            .map(|(_, rest)| rest)
            .expect("body after declaration");
        crate::rpc::validate_xml_fragment(body).expect("generated RPC must be well-formed");
    }

    #[test]
    fn test_load_configuration_xml_format_stays_verbatim() {
        // XML-format config is real XML and must NOT be escaped.
        let xml = load_configuration_xml(
            "27",
            LoadAction::Merge,
            LoadFormat::Xml,
            "<system><host-name>a</host-name></system>",
        );
        assert!(xml.contains("<nc:configuration><system><host-name>a</host-name></system>"));
    }

    #[test]
    fn test_load_configuration_replace_xml() {
        let xml = load_configuration_xml(
            "25",
            LoadAction::Replace,
            LoadFormat::Xml,
            "<system><host-name>test123</host-name></system>",
        );
        assert!(xml.contains(r#"action="replace""#));
        assert!(xml.contains(r#"format="xml""#));
        assert!(xml.contains("<nc:configuration><system>"));
    }

    #[test]
    fn test_commit_configuration() {
        let xml = commit_configuration_xml("30");
        assert!(xml.contains("<nc:commit-configuration/>"));
        assert!(xml.contains("message-id=\"30\""));
        // Verify byte-identical to pre-log form
        let expected = r#"<?xml version="1.0" encoding="UTF-8"?>
<nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="30">
  <nc:commit-configuration/>
</nc:rpc>"#;
        assert_eq!(xml, expected, "None should produce exact pre-log output");
    }

    #[test]
    fn test_commit_configuration_with_log() {
        let xml = commit_configuration_with_log_xml("31", "reason for change");
        assert!(xml.contains("message-id=\"31\""));
        assert!(xml.contains("<nc:log>reason for change</nc:log>"));
        assert!(xml.contains("<nc:commit-configuration>"));
        assert!(!xml.contains("<nc:commit-configuration/>"));
    }

    #[test]
    fn test_commit_configuration_log_escaping() {
        let xml = commit_configuration_with_log_xml("32", "fix & update <critical> items");
        assert!(xml.contains("<nc:log>fix &amp; update &lt;critical&gt; items</nc:log>"));
        // Verify raw markup does not appear
        assert!(!xml.contains("fix & update <critical> items"));
    }

    #[test]
    fn test_commit_configuration_log_injection_defense() {
        let xml = commit_configuration_with_log_xml("33", "evil</nc:log><nc:rollback/>");
        // The injected markup must be escaped
        assert!(xml.contains("&lt;/nc:log&gt;&lt;nc:rollback/&gt;"));
        // The raw injection must NOT appear as live markup
        assert!(!xml.contains("</nc:log><nc:rollback/>"));
        // Exactly one <nc:log> open tag should exist
        assert_eq!(xml.matches("<nc:log>").count(), 1);
        assert_eq!(xml.matches("</nc:log>").count(), 1);
    }

    #[test]
    fn test_rollback_configuration() {
        let xml = rollback_configuration_xml("31", 0);
        assert!(xml.contains(r#"<nc:load-configuration rollback="0"/>"#));
        assert!(xml.contains("message-id=\"31\""));
    }

    #[test]
    fn test_rollback_configuration_index() {
        let xml = rollback_configuration_xml("32", 3);
        assert!(xml.contains(r#"<nc:load-configuration rollback="3"/>"#));
    }

    #[test]
    fn test_get_configuration_compare() {
        let xml = get_configuration_compare_xml("33", 0);
        assert!(xml.contains(r#"compare="rollback""#));
        assert!(xml.contains(r#"rollback="0""#));
        assert!(xml.contains(r#"format="text""#));
        assert!(xml.contains("message-id=\"33\""));
    }

    #[test]
    fn test_create_subscription_default() {
        let xml = create_subscription_xml("10", None, None, None, None);
        assert!(xml.contains("message-id=\"10\""));
        assert!(xml.contains(
            "<create-subscription xmlns=\"urn:ietf:params:xml:ns:netconf:notification:1.0\""
        ));
        assert!(xml.contains("</create-subscription>"));
        assert!(!xml.contains("<stream>"));
        assert!(!xml.contains("<filter"));
    }

    #[test]
    fn test_create_subscription_with_stream() {
        let xml = create_subscription_xml("11", Some("NETCONF"), None, None, None);
        assert!(xml.contains("<stream>NETCONF</stream>"));
    }

    #[test]
    fn test_create_subscription_with_all_params() {
        let xml = create_subscription_xml(
            "12",
            Some("NETCONF"),
            Some("<netconf-config-change/>"),
            Some("2026-01-01T00:00:00Z"),
            Some("2026-12-31T23:59:59Z"),
        );
        assert!(xml.contains("<stream>NETCONF</stream>"));
        assert!(xml.contains("<filter type=\"subtree\">"));
        assert!(xml.contains("<netconf-config-change/>"));
        assert!(xml.contains("<startTime>2026-01-01T00:00:00Z</startTime>"));
        assert!(xml.contains("<stopTime>2026-12-31T23:59:59Z</stopTime>"));
    }

    #[test]
    fn test_create_subscription_replay() {
        let xml = create_subscription_xml("13", None, None, Some("2026-01-01T00:00:00Z"), None);
        assert!(xml.contains("<startTime>2026-01-01T00:00:00Z</startTime>"));
        assert!(!xml.contains("<stopTime>"));
    }

    #[test]
    fn test_no_xmlns_empty() {
        // Verify that no generated XML contains xmlns=""
        let xml = load_configuration_xml("99", LoadAction::Set, LoadFormat::Text, "test");
        assert!(
            !xml.contains(r#"xmlns="""#),
            "xmlns=\"\" must not appear in output"
        );
        let xml2 = open_configuration_xml("99", OpenConfigurationMode::Private);
        assert!(
            !xml2.contains(r#"xmlns="""#),
            "xmlns=\"\" must not appear in output"
        );
        let xml3 = commit_configuration_xml("99");
        assert!(
            !xml3.contains(r#"xmlns="""#),
            "xmlns=\"\" must not appear in output"
        );
        let xml4 = rollback_configuration_xml("99", 0);
        assert!(
            !xml4.contains(r#"xmlns="""#),
            "xmlns=\"\" must not appear in output"
        );
        let xml5 = get_configuration_compare_xml("99", 0);
        assert!(
            !xml5.contains(r#"xmlns="""#),
            "xmlns=\"\" must not appear in output"
        );
    }

    #[test]
    fn test_nc_prefix_on_rpc() {
        // Verify all functions use nc: prefixed namespace
        let xml = get_config_xml("1", Datastore::Running, None);
        assert!(xml.contains(r#"<nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0""#));
        assert!(xml.contains("</nc:rpc>"));
    }
}
