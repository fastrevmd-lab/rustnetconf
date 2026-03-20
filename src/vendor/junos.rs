//! Juniper Junos vendor profile.
//!
//! Handles Junos-specific NETCONF quirks:
//! - Auto-detected via `http://xml.juniper.net/netconf/junos/1.0` capability
//! - Config wrapping: ensures `<configuration>` element is present for edit-config
//! - Response unwrapping: strips Junos-specific wrapper attributes
//! - Close sequence: discards uncommitted candidate changes before closing
//! - Capability normalization: Junos uses both `urn:ietf:params:netconf:` and
//!   `urn:ietf:params:xml:ns:netconf:` prefixes for the same capabilities

use super::{CloseSequence, VendorProfile};
use crate::capability::Capabilities;

/// Junos capability URI used for auto-detection.
const JUNOS_CAPABILITY: &str = "http://xml.juniper.net/netconf/junos/1.0";

/// Juniper Junos vendor profile.
#[derive(Debug, Default)]
pub struct JunosVendor;

impl JunosVendor {
    /// Detect Junos from device hello capabilities.
    ///
    /// Returns `Some(Box<JunosVendor>)` if the device advertises the Junos
    /// capability URI, `None` otherwise.
    pub fn detect(capabilities: &Capabilities) -> Option<Box<dyn VendorProfile>> {
        if capabilities.supports(JUNOS_CAPABILITY) {
            Some(Box::new(JunosVendor))
        } else {
            None
        }
    }
}

impl VendorProfile for JunosVendor {
    fn name(&self) -> &str {
        "junos"
    }

    fn wrap_config(&self, config: &str) -> String {
        let trimmed = config.trim();

        // If config already starts with <configuration, don't double-wrap
        if trimmed.starts_with("<configuration") {
            return config.to_string();
        }

        // Wrap bare config elements in <configuration>
        format!("<configuration>{trimmed}</configuration>")
    }

    fn unwrap_config(&self, response: &str) -> String {
        // Junos get-config responses come wrapped in:
        //   <configuration junos:commit-seconds="..." junos:commit-localtime="..." ...>
        //     ...actual config...
        //   </configuration>
        //
        // We strip the outer <configuration ...> wrapper and its attributes,
        // returning just the inner content. If no wrapper found, return as-is.
        let trimmed = response.trim();

        // Find the opening <configuration ...> tag
        let config_start = match trimmed.find("<configuration") {
            Some(pos) => pos,
            None => return response.to_string(),
        };

        // Find the end of the opening tag (the > after attributes)
        let tag_end = match trimmed[config_start..].find('>') {
            Some(pos) => config_start + pos + 1,
            None => return response.to_string(),
        };

        // Find the closing </configuration> tag
        let config_end = match trimmed.rfind("</configuration>") {
            Some(pos) => pos,
            None => return response.to_string(),
        };

        if tag_end >= config_end {
            return response.to_string();
        }

        trimmed[tag_end..config_end].trim().to_string()
    }

    fn normalize_capability(&self, uri: &str) -> Option<String> {
        // Junos advertises capabilities with both standard and legacy prefixes:
        //   urn:ietf:params:netconf:capability:candidate:1.0     (standard)
        //   urn:ietf:params:xml:ns:netconf:capability:candidate:1.0  (legacy/Junos)
        //
        // Normalize the legacy prefix to the standard one.
        const LEGACY_PREFIX: &str = "urn:ietf:params:xml:ns:netconf:";
        const STANDARD_PREFIX: &str = "urn:ietf:params:netconf:";

        uri.strip_prefix(LEGACY_PREFIX)
            .map(|suffix| format!("{STANDARD_PREFIX}{suffix}"))
    }

    fn close_sequence(&self) -> CloseSequence {
        // Junos may have uncommitted candidate changes. Discard before closing
        // to avoid leaving dirty state that blocks the next session's lock.
        CloseSequence::DiscardThenClose
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn junos_capabilities() -> Capabilities {
        let mut uris = HashSet::new();
        uris.insert("urn:ietf:params:netconf:base:1.0".to_string());
        uris.insert(JUNOS_CAPABILITY.to_string());
        uris.insert("urn:ietf:params:netconf:capability:candidate:1.0".to_string());
        Capabilities::new(uris, Some(42))
    }

    fn non_junos_capabilities() -> Capabilities {
        let mut uris = HashSet::new();
        uris.insert("urn:ietf:params:netconf:base:1.0".to_string());
        Capabilities::new(uris, Some(1))
    }

    #[test]
    fn test_detect_junos() {
        let caps = junos_capabilities();
        let vendor = JunosVendor::detect(&caps);
        assert!(vendor.is_some());
        assert_eq!(vendor.unwrap().name(), "junos");
    }

    #[test]
    fn test_detect_non_junos() {
        let caps = non_junos_capabilities();
        assert!(JunosVendor::detect(&caps).is_none());
    }

    #[test]
    fn test_wrap_config_bare_elements() {
        let vendor = JunosVendor;
        let config = "<system><host-name>test</host-name></system>";
        let wrapped = vendor.wrap_config(config);
        assert_eq!(
            wrapped,
            "<configuration><system><host-name>test</host-name></system></configuration>"
        );
    }

    #[test]
    fn test_wrap_config_already_wrapped() {
        let vendor = JunosVendor;
        let config = "<configuration><system><host-name>test</host-name></system></configuration>";
        let wrapped = vendor.wrap_config(config);
        assert_eq!(wrapped, config, "should not double-wrap");
    }

    #[test]
    fn test_wrap_config_with_xmlns() {
        let vendor = JunosVendor;
        let config = r#"<configuration xmlns="http://xml.juniper.net/xnm/1.1/xnm"><system/></configuration>"#;
        let wrapped = vendor.wrap_config(config);
        assert_eq!(wrapped, config, "should not wrap when <configuration already present");
    }

    #[test]
    fn test_unwrap_config_strips_wrapper() {
        let vendor = JunosVendor;
        let response = r#"
<configuration junos:commit-seconds="1773949021" junos:commit-localtime="2026-03-19 19:37:01 UTC" junos:commit-user="root">
    <system>
        <host-name>vSRX-rustnetconf</host-name>
    </system>
</configuration>"#;
        let unwrapped = vendor.unwrap_config(response);
        assert!(unwrapped.contains("<system>"));
        assert!(unwrapped.contains("vSRX-rustnetconf"));
        assert!(!unwrapped.contains("junos:commit-seconds"));
        assert!(!unwrapped.starts_with("<configuration"));
    }

    #[test]
    fn test_unwrap_config_no_wrapper() {
        let vendor = JunosVendor;
        let response = "<system><host-name>test</host-name></system>";
        let unwrapped = vendor.unwrap_config(response);
        assert_eq!(unwrapped, response, "should return as-is when no wrapper");
    }

    #[test]
    fn test_normalize_legacy_capability() {
        let vendor = JunosVendor;
        let legacy = "urn:ietf:params:xml:ns:netconf:capability:candidate:1.0";
        let normalized = vendor.normalize_capability(legacy);
        assert_eq!(
            normalized,
            Some("urn:ietf:params:netconf:capability:candidate:1.0".to_string())
        );
    }

    #[test]
    fn test_normalize_standard_capability() {
        let vendor = JunosVendor;
        let standard = "urn:ietf:params:netconf:capability:candidate:1.0";
        assert_eq!(vendor.normalize_capability(standard), None, "standard URIs need no normalization");
    }

    #[test]
    fn test_close_sequence() {
        assert_eq!(JunosVendor.close_sequence(), CloseSequence::DiscardThenClose);
    }
}
