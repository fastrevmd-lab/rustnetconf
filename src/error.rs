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

    /// Server presented a host key whose fingerprint does not match the one
    /// recorded in the known_hosts file for this host. Possible MITM attack
    /// or the device's host key was rotated — investigate before reconnecting.
    #[error("host key mismatch for {host}: known_hosts has {expected}, server presented {actual}")]
    HostKeyMismatch {
        host: String,
        expected: String,
        actual: String,
    },

    /// No entry for this host exists in the known_hosts file. Fail closed —
    /// pre-populate the file with `ssh-keyscan` before connecting.
    #[error("host {host}:{port} not found in known_hosts file {path}")]
    HostKeyNotInKnownHosts {
        host: String,
        port: u16,
        path: String,
    },

    /// The known_hosts file contains an `@revoked` entry for the host key
    /// presented by the server. Fail closed.
    #[error("host key for {host} is marked @revoked in known_hosts")]
    HostKeyRevoked { host: String },
}

/// Framing layer errors (EOM or chunked framing).
#[derive(Debug, Error)]
pub enum FramingError {
    /// Received malformed frame data.
    #[error("invalid frame: {0}")]
    Invalid(String),

    /// Received incomplete frame (connection may have dropped).
    #[error("incomplete frame: expected {expected} bytes, got {actual}")]
    Incomplete { expected: usize, actual: usize },

    /// Device sent frames using a different framing than negotiated.
    #[error("framing mismatch: device advertised NETCONF {advertised} but sent {actual}-style frames. Try forcing the other version.")]
    Mismatch { advertised: String, actual: String },
}

/// The parsed contents of a device's `<rpc-error>` response — all 7 fields
/// defined by RFC 6241 §4.3.
///
/// Carried behind a [`Box`] in [`RpcError::ServerError`] so that the error
/// enums stay small: at 128 bytes inline this struct made every
/// `Result<T, NetconfError>` in the crate a large-`Err` return.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcServerError {
    /// The conceptual layer where the error occurred.
    pub error_type: Option<RpcErrorType>,
    /// The error condition tag.
    pub tag: ErrorTag,
    /// Error severity.
    pub severity: Option<ErrorSeverity>,
    /// Vendor-specific or implementation-specific error tag.
    pub app_tag: Option<String>,
    /// XPath expression identifying the element in error.
    pub path: Option<String>,
    /// Human-readable error message.
    pub message: String,
    /// Additional error information (raw XML).
    pub info: Option<String>,
}

impl std::fmt::Display for RpcServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "server error: [{:?}] {}", self.tag, self.message)
    }
}

/// RPC layer errors — the device responded with `<rpc-error>`.
#[derive(Debug, Error)]
pub enum RpcError {
    /// Device returned a structured `<rpc-error>` response.
    /// All 7 RFC 6241 §4.3 fields are parsed and available on
    /// [`RpcServerError`].
    #[error("{0}")]
    ServerError(Box<RpcServerError>),

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
    MessageIdMismatch { expected: String, actual: String },
}

impl From<RpcServerError> for RpcError {
    /// Box the payload into [`RpcError::ServerError`].
    fn from(err: RpcServerError) -> Self {
        RpcError::ServerError(Box::new(err))
    }
}

impl From<RpcServerError> for NetconfError {
    /// Box the payload into [`RpcError::ServerError`] and wrap it.
    fn from(err: RpcServerError) -> Self {
        NetconfError::Rpc(err.into())
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_key_mismatch_display_includes_all_fields() {
        let err = TransportError::HostKeyMismatch {
            host: "device-a.lab".into(),
            expected: "SHA256:aaa".into(),
            actual: "SHA256:bbb".into(),
        };
        let s = err.to_string();
        assert!(s.contains("device-a.lab"), "got {s:?}");
        assert!(s.contains("SHA256:aaa"), "got {s:?}");
        assert!(s.contains("SHA256:bbb"), "got {s:?}");
    }

    #[test]
    fn host_key_not_in_known_hosts_display_includes_port_and_path() {
        let err = TransportError::HostKeyNotInKnownHosts {
            host: "device-a.lab".into(),
            port: 830,
            path: "/etc/jmcp/known_hosts".into(),
        };
        let s = err.to_string();
        assert!(s.contains("device-a.lab"), "got {s:?}");
        assert!(s.contains("830"), "got {s:?}");
        assert!(s.contains("/etc/jmcp/known_hosts"), "got {s:?}");
    }

    /// Guards the fix for #66. `RpcError::ServerError` carried its 7 fields
    /// inline at 128 bytes, which put both error enums exactly on clippy's
    /// `result_large_err` threshold and lit the lint at 71 call sites.
    /// Boxing the payload dropped them well under; these bounds keep a new
    /// inline `String` field from silently pushing them back over.
    #[test]
    fn error_enums_stay_well_under_the_large_err_threshold() {
        use std::mem::size_of;

        const CLIPPY_LARGE_ERR_THRESHOLD: usize = 128;

        for (name, size) in [
            ("NetconfError", size_of::<NetconfError>()),
            ("RpcError", size_of::<RpcError>()),
            ("TransportError", size_of::<TransportError>()),
            ("FramingError", size_of::<FramingError>()),
            ("ProtocolError", size_of::<ProtocolError>()),
        ] {
            assert!(
                size < CLIPPY_LARGE_ERR_THRESHOLD,
                "{name} is {size} bytes, at or over clippy's \
                 result_large_err threshold of {CLIPPY_LARGE_ERR_THRESHOLD} — \
                 box the variant that grew rather than re-adding the allow"
            );
        }
    }

    #[test]
    fn server_error_display_matches_the_pre_boxing_format() {
        let err: RpcError = RpcServerError {
            error_type: Some(RpcErrorType::Application),
            tag: ErrorTag::InvalidValue,
            severity: Some(ErrorSeverity::Error),
            app_tag: None,
            path: None,
            message: "invalid interface name".into(),
            info: None,
        }
        .into();
        assert_eq!(
            err.to_string(),
            "server error: [InvalidValue] invalid interface name"
        );
        assert_eq!(
            NetconfError::from(err).to_string(),
            "RPC error: server error: [InvalidValue] invalid interface name"
        );
    }

    #[test]
    fn host_key_revoked_display_includes_host() {
        let err = TransportError::HostKeyRevoked {
            host: "device-a.lab".into(),
        };
        assert!(err.to_string().contains("device-a.lab"));
        assert!(err.to_string().contains("revoked"));
    }
}
