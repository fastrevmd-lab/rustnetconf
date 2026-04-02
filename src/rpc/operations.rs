//! NETCONF RPC operation XML serialization.
//!
//! Each function generates the XML for one NETCONF RPC operation,
//! ready to be framed and sent over the transport.
//!
//! All RPCs use a prefixed namespace (`nc:`) instead of a default namespace
//! to avoid `xmlns=""` on child elements, which Junos 24.4 rejects.

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
        Some(f) => format!(
            "\n    <nc:filter type=\"subtree\">\n      {f}\n    </nc:filter>"
        ),
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

/// Generate a `<get>` RPC request.
///
/// The `filter` parameter, if provided, must be well-formed XML (a subtree
/// filter element). It is inserted verbatim — do not pass untrusted user
/// input without validation.
pub fn get_xml(message_id: &str, filter: Option<&str>) -> String {
    let filter_xml = match filter {
        Some(f) => format!(
            "\n    <nc:filter type=\"subtree\">\n      {f}\n    </nc:filter>"
        ),
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
    let safe_id = escape_xml_attr(message_id);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{safe_id}">
  <nc:commit-configuration/>
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
/// - `Text` format: Junos set/delete commands or curly-brace config
/// - `Xml` format: Junos XML configuration elements
///
/// `config` is inserted verbatim — do not pass untrusted user input
/// without validation.
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
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{safe_id}">
  <nc:load-configuration action="{action}" format="{format}">
    <nc:{wrapper}>{config}</nc:{wrapper}>
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
    fn test_get_config_with_filter() {
        let xml = get_config_xml(
            "2",
            Datastore::Running,
            Some("<interfaces/>"),
        );
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
        assert!(xml.contains("<nc:configuration-set>set system host-name test123</nc:configuration-set>"));
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
        assert!(xml.contains("<create-subscription xmlns=\"urn:ietf:params:xml:ns:netconf:notification:1.0\""));
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
        assert!(!xml.contains(r#"xmlns="""#), "xmlns=\"\" must not appear in output");
        let xml2 = open_configuration_xml("99", OpenConfigurationMode::Private);
        assert!(!xml2.contains(r#"xmlns="""#), "xmlns=\"\" must not appear in output");
        let xml3 = commit_configuration_xml("99");
        assert!(!xml3.contains(r#"xmlns="""#), "xmlns=\"\" must not appear in output");
        let xml4 = rollback_configuration_xml("99", 0);
        assert!(!xml4.contains(r#"xmlns="""#), "xmlns=\"\" must not appear in output");
        let xml5 = get_configuration_compare_xml("99", 0);
        assert!(!xml5.contains(r#"xmlns="""#), "xmlns=\"\" must not appear in output");
    }

    #[test]
    fn test_nc_prefix_on_rpc() {
        // Verify all functions use nc: prefixed namespace
        let xml = get_config_xml("1", Datastore::Running, None);
        assert!(xml.contains(r#"<nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0""#));
        assert!(xml.contains("</nc:rpc>"));
    }
}
