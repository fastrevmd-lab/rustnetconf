//! NETCONF RPC operation XML serialization.
//!
//! Each function generates the XML for one NETCONF RPC operation,
//! ready to be framed and sent over the transport.

use crate::types::{Datastore, DefaultOperation, ErrorOption, TestOption};

/// Escape a string for safe inclusion in an XML attribute value.
///
/// Replaces `&`, `<`, `>`, `"`, and `'` with their XML entity equivalents.
fn escape_xml_attr(value: &str) -> String {
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
}
