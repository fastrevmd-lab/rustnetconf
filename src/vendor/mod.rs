//! Vendor profile abstraction for multi-vendor NETCONF support.
//!
//! Different vendors implement NETCONF with subtle quirks — namespace handling,
//! session termination, non-standard RPCs, capability URI formats. The
//! `VendorProfile` trait normalizes these differences behind a consistent API.
//!
//! ```text
//! Auto-detection flow:
//!   Device <hello> → capabilities → detect() → JunosVendor / GenericVendor
//! ```
//!
//! # Built-in vendors
//!
//! | Vendor | Auto-detected via |
//! |--------|-------------------|
//! | Junos | `http://xml.juniper.net/netconf/junos/1.0` capability |
//! | Generic | Fallback for any RFC 6241 compliant device |
//!
//! # Custom vendors
//!
//! Implement `VendorProfile` for your own devices:
//! ```rust,no_run
//! use rustnetconf::vendor::{VendorProfile, CloseSequence};
//! use rustnetconf::capability::Capabilities;
//!
//! struct MyVendor;
//!
//! impl VendorProfile for MyVendor {
//!     fn name(&self) -> &str { "my-vendor" }
//!     fn wrap_config(&self, config: &str) -> String { config.to_string() }
//!     fn unwrap_config(&self, response: &str) -> String { response.to_string() }
//!     fn normalize_capability(&self, uri: &str) -> Option<String> { None }
//!     fn close_sequence(&self) -> CloseSequence { CloseSequence::Standard }
//! }
//! ```

pub mod generic;
pub mod junos;

use crate::capability::Capabilities;
use crate::facts::Facts;

/// How the session should be closed for this vendor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseSequence {
    /// Standard RFC 6241: just send `<close-session/>`.
    Standard,
    /// Discard uncommitted candidate changes before closing.
    /// Used by Junos to avoid leaving dirty candidate state.
    DiscardThenClose,
}

/// Trait for vendor-specific NETCONF behavior normalization.
///
/// Implementors handle the quirks of a specific vendor's NETCONF implementation
/// so that user code doesn't need to know about namespace differences,
/// non-standard RPCs, or session termination sequences.
pub trait VendorProfile: Send + Sync {
    /// Vendor name for logging and debugging.
    fn name(&self) -> &str;

    /// Wrap a user's config XML in vendor-specific elements/namespaces.
    ///
    /// For example, Junos edit-config expects `<configuration>` with no
    /// explicit namespace, while some vendors need specific xmlns attributes.
    ///
    /// Called automatically by `Session::edit_config()`.
    fn wrap_config(&self, config: &str) -> String;

    /// Unwrap vendor-specific elements from a get-config response.
    ///
    /// Strips vendor-specific wrapper elements so the user gets clean
    /// configuration XML regardless of vendor.
    ///
    /// Called automatically by `Session::get_config()`.
    fn unwrap_config(&self, response: &str) -> String;

    /// Normalize a vendor-specific capability URI to its standard form.
    ///
    /// Some vendors use non-standard URIs for standard capabilities.
    /// Return `Some(normalized)` to map, or `None` to keep as-is.
    fn normalize_capability(&self, uri: &str) -> Option<String>;

    /// The session close sequence for this vendor.
    fn close_sequence(&self) -> CloseSequence;

    /// Return the RPC content for gathering device facts, if supported.
    ///
    /// The returned string is the inner XML to be wrapped in `<rpc>` tags.
    /// Return `None` if this vendor has no standard facts-gathering RPC.
    fn facts_rpc(&self) -> Option<&str> {
        None
    }

    /// Parse a facts-gathering RPC response into [`Facts`].
    ///
    /// Called with the raw XML response from the RPC returned by [`facts_rpc()`].
    fn parse_facts(&self, _response: &str) -> Facts {
        Facts::default()
    }

    /// Called after facts are gathered to allow vendor-specific post-processing.
    ///
    /// Receives the parsed facts and the raw XML response from the facts RPC.
    /// Vendors can use this to detect device characteristics (e.g., chassis
    /// cluster mode) that are only visible in the facts response.
    fn post_facts_hook(&mut self, _facts: &Facts, _raw_response: &str) {}

    /// Whether this device requires `<open-configuration>` before loading config.
    ///
    /// Returns `true` for Junos chassis-clustered devices, where configuration
    /// changes silently no-op without a private or exclusive edit session.
    fn requires_open_configuration(&self) -> bool {
        false
    }
}

/// Auto-detect the vendor from the device's hello capabilities.
///
/// Checks each built-in vendor's detection heuristic against the capabilities.
/// Returns the first match, or `GenericVendor` as the fallback.
pub fn detect_vendor(capabilities: &Capabilities) -> Box<dyn VendorProfile> {
    // Try Junos first
    if let Some(v) = junos::JunosVendor::detect(capabilities) {
        return v;
    }

    // Fallback to generic
    Box::new(generic::GenericVendor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::Capabilities;
    use std::collections::HashSet;

    #[test]
    fn test_detect_vendor_junos() {
        let mut uris = HashSet::new();
        uris.insert("urn:ietf:params:netconf:base:1.0".to_string());
        uris.insert("http://xml.juniper.net/netconf/junos/1.0".to_string());
        let caps = Capabilities::new(uris, Some(1));

        let vendor = detect_vendor(&caps);
        assert_eq!(vendor.name(), "junos");
    }

    #[test]
    fn test_detect_vendor_unknown_falls_back_to_generic() {
        let mut uris = HashSet::new();
        uris.insert("urn:ietf:params:netconf:base:1.0".to_string());
        let caps = Capabilities::new(uris, Some(1));

        let vendor = detect_vendor(&caps);
        assert_eq!(vendor.name(), "generic");
    }
}
