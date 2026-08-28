//! NETCONF RPC operation XML serialization.
//!
//! Each function generates the XML for one NETCONF RPC operation,
//! ready to be framed and sent over the transport.
//!
//! All RPCs use a prefixed namespace (`nc:`) instead of a default namespace
//! to avoid `xmlns=""` on child elements, which Junos 24.4 rejects.

use crate::error::NetconfError;
use crate::rpc::filter::XPathFilter;
use crate::types::{ConfigLocation, CopySource, DeleteTarget, WithDefaults};
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
