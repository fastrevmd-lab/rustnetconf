//! NETCONF capability URIs and negotiation logic.
//!
//! Handles parsing the `<hello>` message from the device, extracting
//! capability URIs, and determining which NETCONF version and optional
//! features are supported.

use std::collections::HashSet;

/// Well-known NETCONF capability URIs.
pub mod uri {
    /// NETCONF 1.0 base capability (RFC 4741).
    pub const BASE_1_0: &str = "urn:ietf:params:netconf:base:1.0";
    /// NETCONF 1.1 base capability (RFC 6241).
    pub const BASE_1_1: &str = "urn:ietf:params:netconf:base:1.1";
    /// Candidate datastore capability.
    pub const CANDIDATE: &str = "urn:ietf:params:netconf:capability:candidate:1.0";
    /// Confirmed commit capability.
    pub const CONFIRMED_COMMIT: &str = "urn:ietf:params:netconf:capability:confirmed-commit:1.0";
    /// Confirmed commit 1.1 capability.
    pub const CONFIRMED_COMMIT_1_1: &str = "urn:ietf:params:netconf:capability:confirmed-commit:1.1";
    /// Validate capability.
    pub const VALIDATE: &str = "urn:ietf:params:netconf:capability:validate:1.0";
    /// Validate 1.1 capability.
    pub const VALIDATE_1_1: &str = "urn:ietf:params:netconf:capability:validate:1.1";
    /// Startup datastore capability.
    pub const STARTUP: &str = "urn:ietf:params:netconf:capability:startup:1.0";
    /// Rollback on error capability.
    pub const ROLLBACK_ON_ERROR: &str = "urn:ietf:params:netconf:capability:rollback-on-error:1.0";
    /// Writable running capability.
    pub const WRITABLE_RUNNING: &str = "urn:ietf:params:netconf:capability:writable-running:1.0";
}

/// The negotiated NETCONF version for the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetconfVersion {
    /// NETCONF 1.0 — uses end-of-message (]]>]]>) framing.
    V1_0,
    /// NETCONF 1.1 — uses chunked framing.
    V1_1,
}

/// Parsed capabilities from a NETCONF `<hello>` exchange.
#[derive(Debug, Clone)]
pub struct Capabilities {
    /// Raw capability URIs advertised by the device.
    uris: HashSet<String>,
    /// The device's session-id (from the device's hello).
    session_id: Option<u32>,
}

impl Capabilities {
    /// Create a new Capabilities from a set of URI strings.
    pub fn new(uris: HashSet<String>, session_id: Option<u32>) -> Self {
        Self { uris, session_id }
    }

    /// Returns the device's session ID, if provided.
    pub fn session_id(&self) -> Option<u32> {
        self.session_id
    }

    /// Check if a specific capability URI is supported.
    ///
    /// Performs a prefix match to handle capability URIs with query parameters
    /// (e.g., `urn:ietf:params:netconf:base:1.0?revision=...`).
    pub fn supports(&self, capability_uri: &str) -> bool {
        self.uris.iter().any(|uri| uri.starts_with(capability_uri))
    }

    /// Negotiate the NETCONF version based on device and client capabilities.
    ///
    /// If both sides support 1.1, returns `V1_1`. Otherwise falls back to 1.0.
    /// Returns `None` if the device doesn't support even base 1.0.
    pub fn negotiate_version(&self) -> Option<NetconfVersion> {
        if self.supports(uri::BASE_1_1) {
            return Some(NetconfVersion::V1_1);
        }
        if self.supports(uri::BASE_1_0) {
            return Some(NetconfVersion::V1_0);
        }
        None
    }

    /// Returns all raw capability URIs.
    pub fn all_uris(&self) -> &HashSet<String> {
        &self.uris
    }

    /// Returns true if the `:candidate` capability is supported.
    pub fn has_candidate(&self) -> bool {
        self.supports(uri::CANDIDATE)
    }

    /// Returns true if the `:validate` capability is supported.
    pub fn has_validate(&self) -> bool {
        self.supports(uri::VALIDATE) || self.supports(uri::VALIDATE_1_1)
    }

    /// Returns true if the `:confirmed-commit` capability is supported.
    pub fn has_confirmed_commit(&self) -> bool {
        self.supports(uri::CONFIRMED_COMMIT) || self.supports(uri::CONFIRMED_COMMIT_1_1)
    }
}

/// Generate the client `<hello>` XML message.
///
/// The client advertises both base:1.0 and base:1.1 capabilities so the
/// device can choose the highest mutually supported version.
pub fn client_hello_xml() -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <capabilities>
    <capability>{}</capability>
    <capability>{}</capability>
  </capabilities>
</hello>"#,
        uri::BASE_1_0,
        uri::BASE_1_1,
    )
}

/// Parse a device `<hello>` message and extract capabilities and session-id.
pub fn parse_device_hello(xml: &str) -> Result<Capabilities, String> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    let mut reader = Reader::from_str(xml);
    let mut capabilities = HashSet::new();
    let mut session_id: Option<u32> = None;
    let mut in_capability = false;
    let mut in_session_id = false;
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref tag)) | Ok(Event::Empty(ref tag)) => {
                let local_name = tag.local_name();
                if local_name.as_ref() == b"capability" {
                    in_capability = true;
                } else if local_name.as_ref() == b"session-id" {
                    in_session_id = true;
                }
            }
            Ok(Event::Text(ref text)) => {
                if in_capability {
                    let cap_text = text.unescape().map_err(|e| e.to_string())?;
                    let trimmed = cap_text.trim().to_string();
                    if !trimmed.is_empty() {
                        capabilities.insert(trimmed);
                    }
                } else if in_session_id {
                    let id_text = text.unescape().map_err(|e| e.to_string())?;
                    session_id = id_text.trim().parse().ok();
                }
            }
            Ok(Event::End(ref tag)) => {
                let local_name = tag.local_name();
                if local_name.as_ref() == b"capability" {
                    in_capability = false;
                } else if local_name.as_ref() == b"session-id" {
                    in_session_id = false;
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(format!("XML parse error in hello: {e}")),
            _ => {}
        }
        buf.clear();
    }

    if capabilities.is_empty() {
        return Err("device hello contained no capabilities".to_string());
    }

    Ok(Capabilities::new(capabilities, session_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_device_hello_1_0_only() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <capabilities>
    <capability>urn:ietf:params:netconf:base:1.0</capability>
    <capability>urn:ietf:params:netconf:capability:candidate:1.0</capability>
  </capabilities>
  <session-id>42</session-id>
</hello>"#;
        let caps = parse_device_hello(xml).unwrap();
        assert_eq!(caps.negotiate_version(), Some(NetconfVersion::V1_0));
        assert_eq!(caps.session_id(), Some(42));
        assert!(caps.has_candidate());
        assert!(!caps.has_validate());
    }

    #[test]
    fn test_parse_device_hello_1_1() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <capabilities>
    <capability>urn:ietf:params:netconf:base:1.0</capability>
    <capability>urn:ietf:params:netconf:base:1.1</capability>
    <capability>urn:ietf:params:netconf:capability:candidate:1.0</capability>
    <capability>urn:ietf:params:netconf:capability:validate:1.1</capability>
  </capabilities>
  <session-id>99</session-id>
</hello>"#;
        let caps = parse_device_hello(xml).unwrap();
        assert_eq!(caps.negotiate_version(), Some(NetconfVersion::V1_1));
        assert!(caps.has_candidate());
        assert!(caps.has_validate());
    }

    #[test]
    fn test_parse_device_hello_no_capabilities() {
        let xml = r#"<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <capabilities></capabilities>
</hello>"#;
        assert!(parse_device_hello(xml).is_err());
    }

    #[test]
    fn test_parse_device_hello_no_base() {
        let xml = r#"<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <capabilities>
    <capability>urn:ietf:params:netconf:capability:candidate:1.0</capability>
  </capabilities>
</hello>"#;
        let caps = parse_device_hello(xml).unwrap();
        assert_eq!(caps.negotiate_version(), None);
    }

    #[test]
    fn test_client_hello_xml() {
        let hello = client_hello_xml();
        assert!(hello.contains(uri::BASE_1_0));
        assert!(hello.contains(uri::BASE_1_1));
        assert!(hello.contains("<hello"));
    }
}
