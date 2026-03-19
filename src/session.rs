//! NETCONF session management.
//!
//! The `Session` owns all protocol state: message-id counter, device capabilities,
//! framing strategy, and RPC dispatch. It sits between the thin `Client` wrapper
//! and the transport/framing layers.
//!
//! ```text
//! Client (ergonomic API)
//!    │
//!    ▼
//! Session (msg-id, capabilities, framing, RPC dispatch)
//!    │              │
//!    ▼              ▼
//! RPC Layer    Framing Layer
//!                   │
//!                   ▼
//!              Transport (byte stream)
//! ```

use std::sync::atomic::{AtomicU32, Ordering};

use crate::capability::{self, Capabilities, NetconfVersion};
use crate::error::{FramingError, NetconfError, ProtocolError, TransportError};
use crate::framing::chunked::ChunkedFramer;
use crate::framing::eom::EomFramer;
use crate::framing::Framer;
use crate::rpc;
use crate::rpc::operations::{self, EditConfigParams};
use crate::rpc::RpcReply;
use crate::transport::Transport;
use crate::types::{Datastore, DefaultOperation, ErrorOption, TestOption};

/// Read buffer size for transport reads.
const READ_BUF_SIZE: usize = 65536;

/// Session states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Transport connected but hello not yet exchanged.
    Connected,
    /// Hello exchanged, session is operational.
    Established,
    /// Session has been closed.
    Closed,
}

/// A NETCONF session that owns all protocol state.
pub struct Session {
    transport: Box<dyn Transport>,
    framer: Box<dyn Framer>,
    capabilities: Option<Capabilities>,
    message_id: AtomicU32,
    state: SessionState,
    /// Buffer for accumulating incoming data from the transport.
    read_buffer: Vec<u8>,
    /// The negotiated NETCONF version.
    version: Option<NetconfVersion>,
}

impl Session {
    /// Create a new session over the given transport.
    ///
    /// The session starts in `Connected` state with EOM framing (used for
    /// the hello exchange). Call `establish()` to perform the hello handshake
    /// and negotiate the NETCONF version.
    pub fn new(transport: Box<dyn Transport>) -> Self {
        Self {
            transport,
            framer: Box::new(EomFramer::new()),
            capabilities: None,
            message_id: AtomicU32::new(1),
            state: SessionState::Connected,
            read_buffer: Vec::new(),
            version: None,
        }
    }

    /// Perform the NETCONF `<hello>` exchange and establish the session.
    ///
    /// Sends the client hello, receives the device hello, negotiates the
    /// NETCONF version, and switches framing if 1.1 is supported.
    pub async fn establish(&mut self) -> Result<(), NetconfError> {
        if self.state != SessionState::Connected {
            return Err(ProtocolError::HelloFailed(
                "session is not in Connected state".to_string(),
            )
            .into());
        }

        // Send client hello with EOM framing (always EOM for hello)
        let hello = capability::client_hello_xml();
        let framed = self.framer.encode(&hello);
        self.transport.write_all(&framed).await?;

        // Read device hello
        let device_hello = self.read_message().await?;
        let caps = capability::parse_device_hello(&device_hello)
            .map_err(|e| ProtocolError::HelloFailed(e))?;

        // Negotiate version and switch framing
        let version = caps
            .negotiate_version()
            .ok_or_else(|| ProtocolError::HelloFailed(
                "device does not support NETCONF base:1.0 or base:1.1".to_string(),
            ))?;

        if version == NetconfVersion::V1_1 {
            self.framer = Box::new(ChunkedFramer::new());
        }

        self.version = Some(version);
        self.capabilities = Some(caps);
        self.state = SessionState::Established;

        tracing::info!(
            version = ?version,
            session_id = ?self.capabilities.as_ref().and_then(|c| c.session_id()),
            "NETCONF session established"
        );

        Ok(())
    }

    /// Get the device's capabilities, if the session is established.
    pub fn capabilities(&self) -> Option<&Capabilities> {
        self.capabilities.as_ref()
    }

    /// Check if the device supports a specific capability URI.
    pub fn supports(&self, capability_uri: &str) -> bool {
        self.capabilities
            .as_ref()
            .map(|c| c.supports(capability_uri))
            .unwrap_or(false)
    }

    /// Get the negotiated NETCONF version.
    pub fn version(&self) -> Option<NetconfVersion> {
        self.version
    }

    /// Get the current session state.
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Send an RPC and wait for the reply.
    async fn send_rpc(&mut self, xml: &str, message_id: &str) -> Result<RpcReply, NetconfError> {
        self.ensure_established()?;

        let framed = self.framer.encode(xml);
        tracing::debug!(message_id, "sending RPC");

        self.transport.write_all(&framed).await?;
        let response = self.read_message().await?;

        tracing::debug!(message_id, "received RPC reply");

        let reply = rpc::parse_rpc_reply(&response, message_id)?;
        Ok(reply)
    }

    /// Allocate the next message-id.
    fn next_message_id(&self) -> String {
        self.message_id
            .fetch_add(1, Ordering::SeqCst)
            .to_string()
    }

    /// Read one complete framed message from the transport.
    async fn read_message(&mut self) -> Result<String, NetconfError> {
        let mut temp_buf = vec![0u8; READ_BUF_SIZE];

        loop {
            // Try to decode a complete message from the buffer
            match self.framer.decode(&self.read_buffer) {
                Ok(Some((message, consumed))) => {
                    self.read_buffer.drain(..consumed);
                    return Ok(message);
                }
                Ok(None) => {
                    // Need more data
                }
                Err(FramingError::Mismatch { .. }) => {
                    return Err(NetconfError::Framing(FramingError::Mismatch {
                        advertised: self.version.map(|v| format!("{v:?}")).unwrap_or_default(),
                        actual: "unknown".to_string(),
                    }));
                }
                Err(e) => return Err(e.into()),
            }

            // Read more data from transport
            let bytes_read = self.transport.read(&mut temp_buf).await?;
            if bytes_read == 0 {
                // Check if we're in the middle of a commit — CommitUnknown
                return Err(TransportError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed while waiting for RPC reply",
                ))
                .into());
            }
            self.read_buffer.extend_from_slice(&temp_buf[..bytes_read]);
        }
    }

    /// Ensure the session is established before sending RPCs.
    fn ensure_established(&self) -> Result<(), NetconfError> {
        match self.state {
            SessionState::Established => Ok(()),
            SessionState::Closed => Err(ProtocolError::SessionClosed.into()),
            SessionState::Connected => Err(ProtocolError::HelloFailed(
                "session not yet established — call establish() first".to_string(),
            )
            .into()),
        }
    }

    /// Ensure the device supports a capability, or return an error.
    fn require_capability(&self, uri: &str, operation: &str) -> Result<(), NetconfError> {
        if !self.supports(uri) {
            return Err(ProtocolError::CapabilityMissing(format!(
                "operation '{operation}' requires capability '{uri}'"
            ))
            .into());
        }
        Ok(())
    }

    // ── RPC Operations ──────────────────────────────────────────────

    /// Fetch the running, candidate, or startup configuration.
    pub async fn get_config(
        &mut self,
        source: Datastore,
        filter: Option<&str>,
    ) -> Result<String, NetconfError> {
        let msg_id = self.next_message_id();
        let xml = operations::get_config_xml(&msg_id, source, filter);
        let reply = self.send_rpc(&xml, &msg_id).await?;
        match reply {
            RpcReply::Data(data) => Ok(data),
            RpcReply::Ok => Ok(String::new()),
        }
    }

    /// Fetch operational and configuration data.
    pub async fn get(&mut self, filter: Option<&str>) -> Result<String, NetconfError> {
        let msg_id = self.next_message_id();
        let xml = operations::get_xml(&msg_id, filter);
        let reply = self.send_rpc(&xml, &msg_id).await?;
        match reply {
            RpcReply::Data(data) => Ok(data),
            RpcReply::Ok => Ok(String::new()),
        }
    }

    /// Edit the configuration of a datastore.
    pub async fn edit_config(
        &mut self,
        target: Datastore,
        config: &str,
        default_operation: Option<DefaultOperation>,
        test_option: Option<TestOption>,
        error_option: Option<ErrorOption>,
    ) -> Result<(), NetconfError> {
        let msg_id = self.next_message_id();
        let params = EditConfigParams {
            target,
            config,
            default_operation,
            test_option,
            error_option,
        };
        let xml = operations::edit_config_xml(&msg_id, &params);
        self.send_rpc(&xml, &msg_id).await?;
        Ok(())
    }

    /// Lock a datastore.
    pub async fn lock(&mut self, target: Datastore) -> Result<(), NetconfError> {
        let msg_id = self.next_message_id();
        let xml = operations::lock_xml(&msg_id, target);
        self.send_rpc(&xml, &msg_id).await?;
        Ok(())
    }

    /// Unlock a datastore.
    pub async fn unlock(&mut self, target: Datastore) -> Result<(), NetconfError> {
        let msg_id = self.next_message_id();
        let xml = operations::unlock_xml(&msg_id, target);
        self.send_rpc(&xml, &msg_id).await?;
        Ok(())
    }

    /// Commit the candidate configuration.
    ///
    /// Requires the `:candidate` capability.
    pub async fn commit(&mut self) -> Result<(), NetconfError> {
        self.require_capability(
            crate::capability::uri::CANDIDATE,
            "commit",
        )?;
        let msg_id = self.next_message_id();
        let xml = operations::commit_xml(&msg_id);
        self.send_rpc(&xml, &msg_id).await?;
        Ok(())
    }

    /// Validate a datastore configuration.
    ///
    /// Requires the `:validate` capability.
    pub async fn validate(&mut self, source: Datastore) -> Result<(), NetconfError> {
        let msg_id = self.next_message_id();
        let xml = operations::validate_xml(&msg_id, source);
        self.send_rpc(&xml, &msg_id).await?;
        Ok(())
    }

    /// Close the NETCONF session gracefully.
    pub async fn close_session(&mut self) -> Result<(), NetconfError> {
        if self.state == SessionState::Closed {
            return Ok(());
        }

        let msg_id = self.next_message_id();
        let xml = operations::close_session_xml(&msg_id);

        // Best-effort: send close-session but don't fail if transport is already gone
        let _ = self.send_rpc(&xml, &msg_id).await;
        let _ = self.transport.close().await;
        self.state = SessionState::Closed;

        tracing::info!("NETCONF session closed");
        Ok(())
    }

    /// Kill another NETCONF session.
    pub async fn kill_session(&mut self, session_id: u32) -> Result<(), NetconfError> {
        let msg_id = self.next_message_id();
        let xml = operations::kill_session_xml(&msg_id, session_id);
        self.send_rpc(&xml, &msg_id).await?;
        Ok(())
    }
}
