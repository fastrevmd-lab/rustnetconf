//! Layered error types for rustnetconf.
//!
//! Errors are organized by protocol layer so users can match on the category
//! first (Transport, Framing, Rpc, Protocol) then drill into specifics.
//!
//! ```rust,no_run
//! use rustnetconf::error::NetconfError;
//!
//! fn handle_error(err: NetconfError) {
//!     match err {
//!         NetconfError::Transport(e) => eprintln!("SSH issue: {e}"),
//!         NetconfError::Framing(e) => eprintln!("Framing issue: {e}"),
//!         NetconfError::Rpc(e) => eprintln!("Device rejected RPC: {e}"),
//!         NetconfError::Protocol(e) => eprintln!("Protocol issue: {e}"),
//!     }
//! }
//! ```

use crate::types::{ErrorSeverity, ErrorTag, RpcErrorType};
use thiserror::Error;

/// Top-level error type for all rustnetconf operations.
#[derive(Debug, Error)]
pub enum NetconfError {
    /// SSH or network transport errors.
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),

    /// NETCONF message framing errors.
    #[error("framing error: {0}")]
    Framing(#[from] FramingError),

    /// NETCONF RPC-level errors (device rejected the operation).
    #[error("RPC error: {0}")]
    Rpc(#[from] RpcError),

    /// NETCONF protocol-level errors (capability, session state).
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),
}

/// Transport layer errors (SSH connection, authentication, I/O).
#[derive(Debug, Error)]
pub enum TransportError {
    /// Failed to establish TCP/SSH connection.
    #[error("connection failed: {0}")]
    Connect(String),

    /// SSH authentication rejected.
    #[error("authentication failed: {0}")]
    Auth(String),

    /// SSH channel or subsystem error.
    #[error("channel error: {0}")]
    Channel(String),

    /// SSH channel was closed by the remote side (device reboot, SSH
    /// timeout, network interruption).
    ///
    /// This is the most common transport failure during an active session.
    /// Callers should [`reconnect()`](crate::Client::reconnect).
    #[error("channel closed: {0}")]
    ChannelClosed(String),

    /// General I/O error on the transport.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// SSH library error.
    #[error("SSH error: {0}")]
    Ssh(String),

    /// TLS handshake or certificate error.
    #[cfg(feature = "tls")]
    #[error("TLS error: {0}")]
    Tls(String),
}

/// Framing layer errors (EOM or chunked framing).
#[derive(Debug, Error)]
pub enum FramingError {
    /// Received malformed frame data.
    #[error("invalid frame: {0}")]
    Invalid(String),

    /// Received incomplete frame (connection may have dropped).
    #[error("incomplete frame: expected {expected} bytes, got {actual}")]
    Incomplete {
        expected: usize,
        actual: usize,
    },

    /// Device sent frames using a different framing than negotiated.
    #[error("framing mismatch: device advertised NETCONF {advertised} but sent {actual}-style frames. Try forcing the other version.")]
    Mismatch {
        advertised: String,
        actual: String,
    },
}

/// RPC layer errors — the device responded with `<rpc-error>`.
#[derive(Debug, Error)]
pub enum RpcError {
    /// Device returned a structured `<rpc-error>` response.
    /// All 7 RFC 6241 §4.3 fields are parsed and available.
    #[error("server error: [{tag:?}] {message}")]
    ServerError {
        /// The conceptual layer where the error occurred.
        error_type: Option<RpcErrorType>,
        /// The error condition tag.
        tag: ErrorTag,
        /// Error severity.
        severity: Option<ErrorSeverity>,
        /// Vendor-specific or implementation-specific error tag.
        app_tag: Option<String>,
        /// XPath expression identifying the element in error.
        path: Option<String>,
        /// Human-readable error message.
        message: String,
        /// Additional error information (raw XML).
        info: Option<String>,
    },

    /// RPC response was not received within the deadline.
    #[error("RPC timeout after {0:?}")]
    Timeout(std::time::Duration),

    /// Connection lost after `<commit>` was sent but before the response
    /// was received. The device MAY have committed the change.
    /// Callers should verify device state manually.
    #[error("commit status unknown: connection lost after sending <commit>. The device may have committed the change — verify device state.")]
    CommitUnknown,

    /// Failed to parse the RPC response XML.
    #[error("failed to parse RPC response: {0}")]
    ParseError(String),

    /// Response message-id does not match the request.
    #[error("message-id mismatch: expected {expected}, got {actual}")]
    MessageIdMismatch {
        expected: String,
        actual: String,
    },
}

/// Protocol layer errors (capability negotiation, session state).
#[derive(Debug, Error)]
pub enum ProtocolError {
    /// The requested operation requires a capability the device doesn't support.
    #[error("capability not supported: {0}")]
    CapabilityMissing(String),

    /// Operation attempted on a closed session.
    #[error("session is closed")]
    SessionClosed,

    /// Session expired — a keepalive probe detected the connection is dead.
    ///
    /// Callers should [`reconnect()`](crate::Client::reconnect) to
    /// re-establish the session.
    #[error("session expired: keepalive probe failed")]
    SessionExpired,

    /// The `<hello>` capability exchange failed.
    #[error("hello exchange failed: {0}")]
    HelloFailed(String),

    /// XML parsing error during protocol message handling.
    #[error("XML error: {0}")]
    Xml(String),
}
