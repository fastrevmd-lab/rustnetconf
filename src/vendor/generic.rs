//! Generic vendor profile — default RFC 6241 behavior.
//!
//! Used as the fallback when no vendor-specific profile is detected.
//! Passes config through unchanged and uses standard close sequence.

use super::{CloseSequence, VendorProfile};

/// Default vendor profile for any RFC 6241 compliant NETCONF device.
///
/// No config wrapping, no capability normalization, standard close.
#[derive(Debug, Default)]
pub struct GenericVendor;

impl VendorProfile for GenericVendor {
    fn name(&self) -> &str {
        "generic"
    }

    fn wrap_config(&self, config: &str) -> String {
        config.to_string()
    }

    fn unwrap_config(&self, response: &str) -> String {
        response.to_string()
    }

    fn normalize_capability(&self, _uri: &str) -> Option<String> {
        None
    }

    fn close_sequence(&self) -> CloseSequence {
        CloseSequence::Standard
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generic_name() {
        assert_eq!(GenericVendor.name(), "generic");
    }

    #[test]
    fn test_generic_wrap_passthrough() {
        let config = "<configuration><system><host-name>test</host-name></system></configuration>";
        assert_eq!(GenericVendor.wrap_config(config), config);
    }

    #[test]
    fn test_generic_unwrap_passthrough() {
        let response = "<data><configuration/></data>";
        assert_eq!(GenericVendor.unwrap_config(response), response);
    }

    #[test]
    fn test_generic_close_sequence() {
        assert_eq!(GenericVendor.close_sequence(), CloseSequence::Standard);
    }

    #[test]
    fn test_generic_normalize_returns_none() {
        assert_eq!(GenericVendor.normalize_capability("urn:ietf:params:netconf:base:1.0"), None);
    }
}
