//! Device facts — basic identification gathered after session establishment.
//!
//! Facts are populated automatically when `gather_facts(true)` is set on the
//! [`ClientBuilder`](crate::client::ClientBuilder) (the default). When
//! `gather_facts(false)` is used, the client connects without issuing any
//! facts-gathering RPCs — useful for clustered devices where those RPCs may
//! fail if a peer node is unreachable.
//!
//! Facts can also be gathered manually after connection via
//! [`Client::gather_facts()`](crate::client::Client::gather_facts).

/// Basic device identification facts.
///
/// All fields are optional because not every vendor exposes every field,
/// and facts may be empty when `gather_facts(false)` was used.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Facts {
    /// Device hostname.
    pub hostname: Option<String>,
    /// Hardware model (e.g., "vSRX3.0", "MX960").
    pub model: Option<String>,
    /// Software version string.
    pub version: Option<String>,
    /// Hardware serial number.
    pub serial_number: Option<String>,
}

impl Facts {
    /// Returns `true` if no facts have been populated.
    pub fn is_empty(&self) -> bool {
        self.hostname.is_none()
            && self.model.is_none()
            && self.version.is_none()
            && self.serial_number.is_none()
    }
}

/// Parse Junos `<get-system-information>` response into [`Facts`].
///
/// Expects the inner XML content of the `<rpc-reply>`, e.g.:
/// ```xml
/// <system-information>
///   <hardware-model>vSRX3.0</hardware-model>
///   <os-name>junos</os-name>
///   <os-version>23.2R1.14</os-version>
///   <serial-number>ABC123</serial-number>
///   <host-name>vsrx-lab</host-name>
/// </system-information>
/// ```
pub(crate) fn parse_junos_system_information(xml: &str) -> Facts {
    Facts {
        hostname: extract_element(xml, "host-name"),
        model: extract_element(xml, "hardware-model"),
        version: extract_element(xml, "os-version"),
        serial_number: extract_element(xml, "serial-number"),
    }
}

/// Extract the text content of a simple XML element by tag name.
///
/// This is intentionally simple — it handles flat elements like
/// `<host-name>value</host-name>` without needing a full XML parser.
fn extract_element(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");

    let start = xml.find(&open)?;
    let after = &xml[start + open.len()..];
    let end = after.find(&close)?;
    let value = after[..end].trim();

    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_junos_system_information() {
        let xml = r#"
<system-information>
  <hardware-model>vSRX3.0</hardware-model>
  <os-name>junos</os-name>
  <os-version>23.2R1.14</os-version>
  <serial-number>ABC123456</serial-number>
  <host-name>vsrx-lab</host-name>
</system-information>"#;

        let facts = parse_junos_system_information(xml);
        assert_eq!(facts.hostname.as_deref(), Some("vsrx-lab"));
        assert_eq!(facts.model.as_deref(), Some("vSRX3.0"));
        assert_eq!(facts.version.as_deref(), Some("23.2R1.14"));
        assert_eq!(facts.serial_number.as_deref(), Some("ABC123456"));
        assert!(!facts.is_empty());
    }

    #[test]
    fn test_parse_junos_partial_facts() {
        let xml = r#"
<system-information>
  <hardware-model>MX960</hardware-model>
  <os-name>junos</os-name>
  <host-name>core-rtr</host-name>
</system-information>"#;

        let facts = parse_junos_system_information(xml);
        assert_eq!(facts.hostname.as_deref(), Some("core-rtr"));
        assert_eq!(facts.model.as_deref(), Some("MX960"));
        assert!(facts.version.is_none());
        assert!(facts.serial_number.is_none());
    }

    #[test]
    fn test_parse_empty_xml() {
        let facts = parse_junos_system_information("");
        assert!(facts.is_empty());
    }

    #[test]
    fn test_facts_default_is_empty() {
        let facts = Facts::default();
        assert!(facts.is_empty());
    }

    #[test]
    fn test_extract_element_with_whitespace() {
        let xml = "<host-name>  my-router  </host-name>";
        assert_eq!(extract_element(xml, "host-name"), Some("my-router".to_string()));
    }

    #[test]
    fn test_extract_element_empty_value() {
        let xml = "<host-name></host-name>";
        assert_eq!(extract_element(xml, "host-name"), None);
    }

    #[test]
    fn test_extract_element_missing() {
        let xml = "<other-tag>value</other-tag>";
        assert_eq!(extract_element(xml, "host-name"), None);
    }
}
