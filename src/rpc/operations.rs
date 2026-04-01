//! NETCONF RPC operation XML serialization.
//!
//! Each function generates the XML for one NETCONF RPC operation,
//! ready to be framed and sent over the transport.

use crate::types::{
    Datastore, DefaultOperation, ErrorOption, LoadAction, LoadFormat, OpenConfigurationMode,
    TestOption,
};

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
            "\n    <filter type=\"subtree\">\n      {f}\n    </filter>"
        ),
        None => String::new(),
    };

    let safe_id = escape_xml_attr(message_id);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{safe_id}">
  <get-config>
    <source>
      <{source}/>
    </source>{filter_xml}
  </get-config>
</rpc>"#,
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
            "\n    <filter type=\"subtree\">\n      {f}\n    </filter>"
        ),
        None => String::new(),
    };

    let safe_id = escape_xml_attr(message_id);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{safe_id}">
  <get>{filter_xml}
  </get>
</rpc>"#,
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
            "\n    <default-operation>{}</default-operation>",
            default_op.as_str()
        ));
    }

    if let Some(ref test_opt) = params.test_option {
        options.push_str(&format!(
            "\n    <test-option>{}</test-option>",
            test_opt.as_str()
        ));
    }

    if let Some(ref error_opt) = params.error_option {
        options.push_str(&format!(
            "\n    <error-option>{}</error-option>",
            error_opt.as_str()
        ));
    }

    let safe_id = escape_xml_attr(message_id);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{safe_id}">
  <edit-config>
    <target>
      <{target}/>
    </target>{options}
    <config>
      {config}
    </config>
  </edit-config>
</rpc>"#,
        target = params.target.as_xml_tag(),
        config = params.config,
    )
}

/// Generate a `<lock>` RPC request.
pub fn lock_xml(message_id: &str, target: Datastore) -> String {
    let safe_id = escape_xml_attr(message_id);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{safe_id}">
  <lock>
    <target>
      <{target}/>
    </target>
  </lock>
</rpc>"#,
        target = target.as_xml_tag(),
    )
}

/// Generate an `<unlock>` RPC request.
pub fn unlock_xml(message_id: &str, target: Datastore) -> String {
    let safe_id = escape_xml_attr(message_id);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{safe_id}">
  <unlock>
    <target>
      <{target}/>
    </target>
  </unlock>
</rpc>"#,
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
<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{safe_id}">
  <discard-changes/>
</rpc>"#,
    )
}

/// Generate a `<commit>` RPC request.
pub fn commit_xml(message_id: &str) -> String {
    let safe_id = escape_xml_attr(message_id);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{safe_id}">
  <commit/>
</rpc>"#,
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
<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{safe_id}">
  <commit>
    <confirmed/>
    <confirm-timeout>{confirm_timeout}</confirm-timeout>
  </commit>
</rpc>"#,
    )
}

/// Generate a `<validate>` RPC request.
pub fn validate_xml(message_id: &str, source: Datastore) -> String {
    let safe_id = escape_xml_attr(message_id);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{safe_id}">
  <validate>
    <source>
      <{source}/>
    </source>
  </validate>
</rpc>"#,
        source = source.as_xml_tag(),
    )
}

/// Generate a `<close-session>` RPC request.
pub fn close_session_xml(message_id: &str) -> String {
    let safe_id = escape_xml_attr(message_id);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{safe_id}">
  <close-session/>
</rpc>"#,
    )
}

/// Generate a `<kill-session>` RPC request.
pub fn kill_session_xml(message_id: &str, session_id: u32) -> String {
    let safe_id = escape_xml_attr(message_id);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{safe_id}">
  <kill-session>
    <session-id>{session_id}</session-id>
  </kill-session>
</rpc>"#,
    )
}

// ── Junos-specific operations ────────────────────────────────────────

/// Generate a Junos `<open-configuration>` RPC request.
///
/// Opens a private or exclusive configuration database. Required on
/// chassis-clustered Junos devices before loading configuration.
pub fn open_configuration_xml(message_id: &str, mode: OpenConfigurationMode) -> String {
    let mode_element = match mode {
        OpenConfigurationMode::Private => "<private/>",
        OpenConfigurationMode::Exclusive => "<exclusive/>",
    };
    let safe_id = escape_xml_attr(message_id);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{safe_id}">
  <open-configuration xmlns="">
    {mode_element}
  </open-configuration>
</rpc>"#,
    )
}

/// Generate a Junos `<close-configuration>` RPC request.
///
/// Closes a previously opened private or exclusive configuration database.
pub fn close_configuration_xml(message_id: &str) -> String {
    let safe_id = escape_xml_attr(message_id);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{safe_id}">
  <close-configuration xmlns=""/>
</rpc>"#,
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
<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{safe_id}">
  <commit-configuration xmlns=""/>
</rpc>"#,
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
<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{safe_id}">
  <load-configuration xmlns="" rollback="{rollback}"/>
</rpc>"#,
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
<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{safe_id}">
  <get-configuration xmlns="" compare="rollback" rollback="{rollback}" format="text"/>
</rpc>"#,
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
<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{safe_id}">
  <load-configuration xmlns="" action="{action}" format="{format}">
    <{wrapper}>{config}</{wrapper}>
  </load-configuration>
</rpc>"#,
        action = action.as_str(),
        format = format.as_str(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_config_running_no_filter() {
        let xml = get_config_xml("1", Datastore::Running, None);
        assert!(xml.contains("message-id=\"1\""));
        assert!(xml.contains("<running/>"));
        assert!(xml.contains("<get-config>"));
        assert!(!xml.contains("<filter"));
    }

    #[test]
    fn test_get_config_with_filter() {
        let xml = get_config_xml(
            "2",
            Datastore::Running,
            Some("<interfaces/>"),
        );
        assert!(xml.contains("<filter type=\"subtree\">"));
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
        assert!(xml.contains("<candidate/>"));
        assert!(xml.contains("<default-operation>merge</default-operation>"));
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
        assert!(xml.contains("<default-operation>replace</default-operation>"));
        assert!(xml.contains("<test-option>test-then-set</test-option>"));
        assert!(xml.contains("<error-option>rollback-on-error</error-option>"));
    }

    #[test]
    fn test_lock_candidate() {
        let xml = lock_xml("5", Datastore::Candidate);
        assert!(xml.contains("<lock>"));
        assert!(xml.contains("<candidate/>"));
    }

    #[test]
    fn test_unlock_candidate() {
        let xml = unlock_xml("6", Datastore::Candidate);
        assert!(xml.contains("<unlock>"));
        assert!(xml.contains("<candidate/>"));
    }

    #[test]
    fn test_commit() {
        let xml = commit_xml("7");
        assert!(xml.contains("<commit/>"));
    }

    #[test]
    fn test_validate() {
        let xml = validate_xml("8", Datastore::Candidate);
        assert!(xml.contains("<validate>"));
        assert!(xml.contains("<candidate/>"));
    }

    #[test]
    fn test_close_session() {
        let xml = close_session_xml("9");
        assert!(xml.contains("<close-session/>"));
    }

    #[test]
    fn test_kill_session() {
        let xml = kill_session_xml("10", 42);
        assert!(xml.contains("<kill-session>"));
        assert!(xml.contains("<session-id>42</session-id>"));
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
        assert!(xml.contains(r#"<open-configuration xmlns="">"#));
        assert!(xml.contains("<private/>"));
        assert!(xml.contains("message-id=\"20\""));
    }

    #[test]
    fn test_open_configuration_exclusive() {
        let xml = open_configuration_xml("21", OpenConfigurationMode::Exclusive);
        assert!(xml.contains(r#"<open-configuration xmlns="">"#));
        assert!(xml.contains("<exclusive/>"));
    }

    #[test]
    fn test_close_configuration() {
        let xml = close_configuration_xml("22");
        assert!(xml.contains(r#"<close-configuration xmlns=""/>"#));
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
        assert!(xml.contains(r#"xmlns="" action="set""#));
        assert!(xml.contains(r#"format="text""#));
        assert!(xml.contains("<configuration-set>set system host-name test123</configuration-set>"));
    }

    #[test]
    fn test_load_configuration_merge_text() {
        let xml = load_configuration_xml(
            "24",
            LoadAction::Merge,
            LoadFormat::Text,
            "system { host-name test123; }",
        );
        assert!(xml.contains(r#"xmlns="" action="merge""#));
        assert!(xml.contains("<configuration-text>"));
    }

    #[test]
    fn test_load_configuration_replace_xml() {
        let xml = load_configuration_xml(
            "25",
            LoadAction::Replace,
            LoadFormat::Xml,
            "<system><host-name>test123</host-name></system>",
        );
        assert!(xml.contains(r#"xmlns="" action="replace""#));
        assert!(xml.contains(r#"format="xml""#));
        assert!(xml.contains("<configuration><system>"));
    }

    #[test]
    fn test_commit_configuration() {
        let xml = commit_configuration_xml("30");
        assert!(xml.contains(r#"<commit-configuration xmlns=""/>"#));
        assert!(xml.contains("message-id=\"30\""));
    }

    #[test]
    fn test_rollback_configuration() {
        let xml = rollback_configuration_xml("31", 0);
        assert!(xml.contains(r#"<load-configuration xmlns="" rollback="0"/>"#));
        assert!(xml.contains("message-id=\"31\""));
    }

    #[test]
    fn test_rollback_configuration_index() {
        let xml = rollback_configuration_xml("32", 3);
        assert!(xml.contains(r#"<load-configuration xmlns="" rollback="3"/>"#));
    }

    #[test]
    fn test_get_configuration_compare() {
        let xml = get_configuration_compare_xml("33", 0);
        assert!(xml.contains(r#"xmlns="" compare="rollback""#));
        assert!(xml.contains(r#"rollback="0""#));
        assert!(xml.contains(r#"format="text""#));
        assert!(xml.contains("message-id=\"33\""));
    }
}
