//! NETCONF message framing layer.
//!
//! Handles encoding outbound XML into framed bytes and decoding inbound
//! bytes back into complete XML messages. Two framing modes:
//!
//! - **EOM** (NETCONF 1.0): Messages terminated by `]]>]]>`
//! - **Chunked** (NETCONF 1.1): Messages split into length-prefixed chunks
//!
//! The framing mode is selected by the Session after the `<hello>` exchange.

pub mod chunked;
pub mod eom;

/// Trait for encoding/decoding NETCONF message frames.
///
/// Implementors handle the wire-level framing for one NETCONF version.
pub trait Framer: Send + Sync {
    /// Encode an XML message into framed bytes ready for the transport.
    fn encode(&self, message: &str) -> Vec<u8>;

    /// Attempt to decode a complete message from the input buffer.
    ///
    /// If a complete framed message is found, returns `Some((message, consumed))`
    /// where `consumed` is the number of bytes to drain from the buffer.
    /// Returns `None` if the buffer doesn't contain a complete message yet.
    fn decode(&self, buffer: &[u8]) -> Result<Option<(String, usize)>, crate::error::FramingError>;
}
