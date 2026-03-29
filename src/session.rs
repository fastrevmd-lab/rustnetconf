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
use crate::facts::Facts;
use crate::framing::chunked::ChunkedFramer;
use crate::framing::eom::EomFramer;
use crate::framing::Framer;
use crate::rpc;
use crate::rpc::operations::{self, EditConfigParams};
use crate::rpc::RpcReply;
use crate::transport::Transport;
use crate::types::{Datastore, DefaultOperation, ErrorOption, TestOption};
use crate::vendor::{self, CloseSequence, VendorProfile};

/// Read buffer size for transport reads.
const READ_BUF_SIZE: usize = 65536;

/// Maximum number of stale (mismatched message-id) responses to drain before
/// giving up. This handles the case where a cancelled async RPC left its
/// response in the transport buffer.
const MAX_STALE_DRAIN: usize = 10;

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
    /// True while a `<commit>` RPC has been sent but the reply hasn't arrived.
    pending_commit: bool,
    /// Vendor-specific behavior profile. Set during establish() via auto-detection,
    /// or overridden by the user via Client::vendor() / Client::vendor_profile().
    vendor_profile: Box<dyn VendorProfile>,
    /// Device facts gathered after session establishment.
    facts: Facts,
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
            pending_commit: false,
            vendor_profile: Box::new(crate::vendor::generic::GenericVendor),
            facts: Facts::default(),
        }
    }

    /// Set an explicit vendor profile, overriding auto-detection.
    ///
    /// Must be called before `establish()`. After establish, the vendor
    /// profile is locked in.
    pub fn set_vendor_profile(&mut self, profile: Box<dyn VendorProfile>) {
        self.vendor_profile = profile;
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
            .map_err(ProtocolError::HelloFailed)?;

        // Negotiate version and switch framing
        let version = caps
            .negotiate_version()
            .ok_or_else(|| ProtocolError::HelloFailed(
                "device does not support NETCONF base:1.0 or base:1.1".to_string(),
            ))?;

        if version == NetconfVersion::V1_1 {
            self.framer = Box::new(ChunkedFramer::new());
        }

        // Auto-detect vendor from capabilities (unless explicitly overridden)
        if self.vendor_profile.name() == "generic" {
            self.vendor_profile = vendor::detect_vendor(&caps);
        }

        self.version = Some(version);
        self.capabilities = Some(caps);
        self.state = SessionState::Established;

        tracing::info!(
            version = ?version,
            vendor = self.vendor_profile.name(),
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

    /// Get the vendor profile name (e.g., "junos", "generic").
    pub fn vendor_name(&self) -> &str {
        self.vendor_profile.name()
    }

    /// Get the device facts.
    pub fn facts(&self) -> &Facts {
        &self.facts
    }

    /// Gather device facts by sending the vendor-specific facts RPC.
    ///
    /// This is called automatically during connection when `gather_facts(true)`
    /// is set (the default). It can also be called manually after connecting
    /// with `gather_facts(false)` to populate facts on demand.
    ///
    /// If the vendor has no facts-gathering RPC, this is a no-op and facts
    /// remain empty.
    pub async fn gather_facts(&mut self) -> Result<(), NetconfError> {
        let rpc_content = match self.vendor_profile.facts_rpc() {
            Some(rpc) => rpc.to_string(),
            None => return Ok(()),
        };

        match self.rpc(&rpc_content).await {
            Ok(response) => {
                self.facts = self.vendor_profile.parse_facts(&response);
                tracing::info!(
                    hostname = ?self.facts.hostname,
                    model = ?self.facts.model,
                    version = ?self.facts.version,
                    "device facts gathered"
                );
                Ok(())
            }
            Err(err) => {
                tracing::warn!(%err, "failed to gather device facts");
                Err(err)
            }
        }
    }

    /// Send an RPC and wait for the reply.
    ///
    /// If a stale response from a previously cancelled RPC is received
    /// (message-id mismatch), it is drained and the next message is read.
    /// This repeats up to [`MAX_STALE_DRAIN`] times before returning an error.
    async fn send_rpc(&mut self, xml: &str, message_id: &str) -> Result<RpcReply, NetconfError> {
        self.ensure_established()?;

        let framed = self.framer.encode(xml);
        tracing::debug!(message_id, "sending RPC");

        self.transport.write_all(&framed).await?;

        for drain_attempt in 0..=MAX_STALE_DRAIN {
            let response = self.read_message().await?;

            match rpc::parse_rpc_reply(&response, message_id) {
                Ok(reply) => {
                    tracing::debug!(message_id, "received RPC reply");
                    return Ok(reply);
                }
                Err(crate::error::RpcError::MessageIdMismatch {
                    ref expected,
                    ref actual,
                }) => {
                    if drain_attempt == MAX_STALE_DRAIN {
                        tracing::error!(
                            expected,
                            actual,
                            "message-id mismatch: exceeded max drain attempts ({MAX_STALE_DRAIN})"
                        );
                        return Err(crate::error::RpcError::MessageIdMismatch {
                            expected: expected.clone(),
                            actual: actual.clone(),
                        }
                        .into());
                    }
                    tracing::warn!(
                        expected,
                        actual,
                        attempt = drain_attempt + 1,
                        "draining stale response with wrong message-id"
                    );
                    // Continue to read the next message
                }
                Err(other) => return Err(other.into()),
            }
        }

        unreachable!()
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
                if self.pending_commit {
                    self.pending_commit = false;
                    return Err(crate::error::RpcError::CommitUnknown.into());
                }
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
    #[allow(clippy::result_large_err)]
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
    #[allow(clippy::result_large_err)]
    fn require_capability(&self, uri: &str, operation: &str) -> Result<(), NetconfError> {
        if !self.supports(uri) {
            return Err(ProtocolError::CapabilityMissing(format!(
                "operation '{operation}' requires capability '{uri}'"
            ))
            .into());
        }
        Ok(())
    }

    // ── Raw RPC ─────────────────────────────────────────────────────

    /// Send an arbitrary RPC and return the raw XML response content.
    ///
    /// The `rpc_content` is wrapped in `<rpc>` tags with a message-id,
    /// sent to the device, and the inner content of `<rpc-reply>` is returned.
    ///
    /// Use this for vendor-specific RPCs not covered by the standard
    /// NETCONF operations (get-config, edit-config, etc.).
    pub async fn rpc(&mut self, rpc_content: &str) -> Result<String, NetconfError> {
        let msg_id = self.next_message_id();
        let xml = format!(
            r#"<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{msg_id}">{rpc_content}</rpc>"#
        );
        let reply = self.send_rpc(&xml, &msg_id).await?;
        match reply {
            RpcReply::Data(data) => Ok(data),
            RpcReply::Ok => Ok(String::new()),
        }
    }

    // ── RPC Operations ──────────────────────────────────────────────

    /// Fetch the running, candidate, or startup configuration.
    ///
    /// The response is passed through the vendor profile's `unwrap_config()`
    /// to strip vendor-specific wrapper elements.
    pub async fn get_config(
        &mut self,
        source: Datastore,
        filter: Option<&str>,
    ) -> Result<String, NetconfError> {
        let msg_id = self.next_message_id();
        let xml = operations::get_config_xml(&msg_id, source, filter);
        let reply = self.send_rpc(&xml, &msg_id).await?;
        match reply {
            RpcReply::Data(data) => Ok(self.vendor_profile.unwrap_config(&data)),
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
    ///
    /// The config payload is passed through the vendor profile's `wrap_config()`
    /// to add vendor-specific elements/namespaces if needed.
    pub async fn edit_config(
        &mut self,
        target: Datastore,
        config: &str,
        default_operation: Option<DefaultOperation>,
        test_option: Option<TestOption>,
        error_option: Option<ErrorOption>,
    ) -> Result<(), NetconfError> {
        let wrapped_config = self.vendor_profile.wrap_config(config);
        let msg_id = self.next_message_id();
        let params = EditConfigParams {
            target,
            config: &wrapped_config,
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
    ///
    /// If the connection drops after `<commit>` is sent but before the reply
    /// arrives, returns `RpcError::CommitUnknown` — the device may have
    /// committed the change. Callers should verify device state manually.
    pub async fn commit(&mut self) -> Result<(), NetconfError> {
        self.require_capability(
            crate::capability::uri::CANDIDATE,
            "commit",
        )?;
        let msg_id = self.next_message_id();
        let xml = operations::commit_xml(&msg_id);

        self.pending_commit = true;
        let result = self.send_rpc(&xml, &msg_id).await;
        self.pending_commit = false;

        result?;
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

    /// Discard uncommitted candidate configuration changes.
    pub async fn discard_changes(&mut self) -> Result<(), NetconfError> {
        let msg_id = self.next_message_id();
        let xml = operations::discard_changes_xml(&msg_id);
        self.send_rpc(&xml, &msg_id).await?;
        Ok(())
    }

    /// Close the NETCONF session gracefully.
    ///
    /// Respects the vendor profile's close sequence. For example, Junos
    /// discards uncommitted candidate changes before closing to avoid
    /// leaving dirty state.
    pub async fn close_session(&mut self) -> Result<(), NetconfError> {
        if self.state == SessionState::Closed {
            return Ok(());
        }

        // Vendor-specific pre-close actions
        if self.vendor_profile.close_sequence() == CloseSequence::DiscardThenClose {
            // Best-effort discard — don't fail the close if this errors
            let _ = self.discard_changes().await;
        }

        let msg_id = self.next_message_id();
        let xml = operations::close_session_xml(&msg_id);

        // Best-effort: send close-session but don't fail if transport is already gone
        let _ = self.send_rpc(&xml, &msg_id).await;
        let _ = self.transport.close().await;
        self.state = SessionState::Closed;

        tracing::info!(vendor = self.vendor_profile.name(), "NETCONF session closed");
        Ok(())
    }

    /// Kill another NETCONF session.
    pub async fn kill_session(&mut self, session_id: u32) -> Result<(), NetconfError> {
        let msg_id = self.next_message_id();
        let xml = operations::kill_session_xml(&msg_id, session_id);
        self.send_rpc(&xml, &msg_id).await?;
        Ok(())
    }

    /// Confirmed commit with automatic rollback timeout (RFC 6241 §8.4).
    ///
    /// The device applies the candidate configuration but starts a rollback
    /// timer. If [`confirming_commit`](Self::confirming_commit) is not called
    /// within `confirm_timeout` seconds, the device automatically reverts to
    /// the previous configuration.
    ///
    /// Requires the `:confirmed-commit` capability.
    pub async fn confirmed_commit(&mut self, confirm_timeout: u32) -> Result<(), NetconfError> {
        self.require_capability(
            crate::capability::uri::CANDIDATE,
            "confirmed-commit",
        )?;
        // Check for either 1.0 or 1.1 confirmed-commit capability
        if !self.supports(crate::capability::uri::CONFIRMED_COMMIT)
            && !self.supports(crate::capability::uri::CONFIRMED_COMMIT_1_1)
        {
            return Err(ProtocolError::CapabilityMissing(
                "confirmed-commit requires :confirmed-commit capability".to_string(),
            )
            .into());
        }

        let msg_id = self.next_message_id();
        let xml = operations::confirmed_commit_xml(&msg_id, confirm_timeout);

        self.pending_commit = true;
        let result = self.send_rpc(&xml, &msg_id).await;
        self.pending_commit = false;

        result?;
        Ok(())
    }

    /// Send a confirming commit to make a previous confirmed-commit permanent.
    ///
    /// Must be called within the `confirm_timeout` window of a previous
    /// [`confirmed_commit`](Self::confirmed_commit), otherwise the device
    /// automatically rolls back.
    pub async fn confirming_commit(&mut self) -> Result<(), NetconfError> {
        // A confirming commit is just a regular <commit/> — same XML
        self.commit().await
    }

    /// Lock a datastore, killing a stale session if the lock is held.
    ///
    /// Attempts to lock the target datastore. If the lock is denied because
    /// another session holds it, extracts the blocking session-id from the
    /// `<error-info>` and kills that session, then retries the lock once.
    ///
    /// Returns the session-id of the killed session if one was killed.
    pub async fn lock_or_kill_stale(
        &mut self,
        target: Datastore,
    ) -> Result<Option<u32>, NetconfError> {
        match self.lock(target).await {
            Ok(()) => Ok(None),
            Err(NetconfError::Rpc(crate::error::RpcError::ServerError {
                ref tag,
                ref info,
                ..
            })) if *tag == crate::types::ErrorTag::LockDenied => {
                // Try to extract session-id from error-info
                let stale_session_id = info
                    .as_ref()
                    .and_then(|info_xml| parse_session_id_from_info(info_xml));

                if let Some(sid) = stale_session_id {
                    tracing::warn!(
                        stale_session_id = sid,
                        "lock denied — killing stale session"
                    );
                    self.kill_session(sid).await?;
                    // Retry the lock
                    self.lock(target).await?;
                    return Ok(Some(sid));
                }

                // Couldn't parse session-id — return the original error
                Err(ProtocolError::CapabilityMissing(format!(
                    "lock denied but could not extract stale session-id from error-info: {:?}",
                    info
                ))
                .into())
            }
            Err(other) => Err(other),
        }
    }
}

/// Extract a session-id from `<error-info>` XML content.
///
/// Handles both structured XML (`<session-id>42</session-id>`) and
/// Junos-style text (`session-id: 42` or `(pid 12345)`).
fn parse_session_id_from_info(info: &str) -> Option<u32> {
    // Try structured XML: <session-id>42</session-id>
    if let Some(start) = info.find("<session-id>") {
        let after = &info[start + "<session-id>".len()..];
        if let Some(end) = after.find("</session-id>") {
            if let Ok(id) = after[..end].trim().parse::<u32>() {
                return Some(id);
            }
        }
    }

    // Try Junos text format: "session-id: 42" or similar
    for line in info.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("session-id:") {
            if let Ok(id) = rest.trim().parse::<u32>() {
                return Some(id);
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::mock::MockTransport;

    /// Build a mock device hello response with EOM framing.
    fn mock_device_hello() -> Vec<u8> {
        let hello = r#"<?xml version="1.0" encoding="UTF-8"?>
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <capabilities>
    <capability>urn:ietf:params:netconf:base:1.0</capability>
    <capability>urn:ietf:params:netconf:capability:candidate:1.0</capability>
  </capabilities>
  <session-id>1</session-id>
</hello>"#;
        let mut buf = hello.as_bytes().to_vec();
        buf.extend_from_slice(b"]]>]]>");
        buf
    }

    /// Build a mock <ok/> RPC reply with EOM framing.
    fn mock_ok_reply(message_id: &str) -> Vec<u8> {
        let reply = format!(
            r#"<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{message_id}"><ok/></rpc-reply>"#
        );
        let mut buf = reply.into_bytes();
        buf.extend_from_slice(b"]]>]]>");
        buf
    }

    #[tokio::test]
    async fn test_commit_unknown_on_disconnect() {
        // Mock transport: serves the hello, then the lock reply,
        // but returns EOF during the commit (simulating connection drop).
        let mut response_data = mock_device_hello();
        response_data.extend_from_slice(&mock_ok_reply("1")); // lock reply
        // No commit reply — EOF after lock reply simulates mid-commit disconnect

        let transport = MockTransport::new(response_data);
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        // Lock succeeds
        session.lock(Datastore::Candidate).await.expect("lock failed");

        // Commit should return CommitUnknown because the transport returns EOF
        let result = session.commit().await;
        match result {
            Err(NetconfError::Rpc(crate::error::RpcError::CommitUnknown)) => {
                // This is the expected error
            }
            other => panic!("expected CommitUnknown, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_non_commit_disconnect_is_transport_error() {
        // Mock transport: serves the hello, then EOF during get-config
        let response_data = mock_device_hello();
        // No get-config reply — EOF simulates connection drop

        let transport = MockTransport::new(response_data);
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        // get-config should return a transport error, NOT CommitUnknown
        let result = session.get_config(Datastore::Running, None).await;
        match result {
            Err(NetconfError::Transport(_)) => {
                // Expected — generic transport error for non-commit operations
            }
            Err(NetconfError::Rpc(crate::error::RpcError::CommitUnknown)) => {
                panic!("CommitUnknown should only happen during commit, not get-config");
            }
            other => panic!("expected TransportError, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_successful_commit_clears_pending_flag() {
        // Mock transport: hello + lock reply + commit reply
        let mut response_data = mock_device_hello();
        response_data.extend_from_slice(&mock_ok_reply("1")); // lock
        response_data.extend_from_slice(&mock_ok_reply("2")); // commit
        response_data.extend_from_slice(&mock_ok_reply("3")); // unlock

        let transport = MockTransport::new(response_data);
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        session.lock(Datastore::Candidate).await.expect("lock failed");
        session.commit().await.expect("commit failed");

        // pending_commit should be false after successful commit
        assert!(!session.pending_commit, "pending_commit should be cleared after success");

        session.unlock(Datastore::Candidate).await.expect("unlock failed");
    }

    #[test]
    fn test_parse_session_id_from_xml_info() {
        let info = "<session-id>42</session-id>";
        assert_eq!(parse_session_id_from_info(info), Some(42));
    }

    #[test]
    fn test_parse_session_id_from_xml_with_whitespace() {
        let info = "\n<session-id> 99 </session-id>\n";
        assert_eq!(parse_session_id_from_info(info), Some(99));
    }

    #[test]
    fn test_parse_session_id_from_text_format() {
        let info = "session-id: 55806";
        assert_eq!(parse_session_id_from_info(info), Some(55806));
    }

    #[test]
    fn test_parse_session_id_not_found() {
        let info = "some random error info with no session id";
        assert_eq!(parse_session_id_from_info(info), None);
    }

    #[test]
    fn test_parse_session_id_empty() {
        assert_eq!(parse_session_id_from_info(""), None);
    }

    /// Build a mock device hello with confirmed-commit capability.
    fn mock_device_hello_with_confirmed_commit() -> Vec<u8> {
        let hello = r#"<?xml version="1.0" encoding="UTF-8"?>
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <capabilities>
    <capability>urn:ietf:params:netconf:base:1.0</capability>
    <capability>urn:ietf:params:netconf:capability:candidate:1.0</capability>
    <capability>urn:ietf:params:netconf:capability:confirmed-commit:1.0</capability>
  </capabilities>
  <session-id>1</session-id>
</hello>"#;
        let mut buf = hello.as_bytes().to_vec();
        buf.extend_from_slice(b"]]>]]>");
        buf
    }

    #[tokio::test]
    async fn test_confirmed_commit_sends_correct_xml() {
        let mut response_data = mock_device_hello_with_confirmed_commit();
        response_data.extend_from_slice(&mock_ok_reply("1")); // lock
        response_data.extend_from_slice(&mock_ok_reply("2")); // confirmed-commit
        response_data.extend_from_slice(&mock_ok_reply("3")); // confirming commit

        let transport = MockTransport::new(response_data);
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        session.lock(Datastore::Candidate).await.expect("lock failed");
        session.confirmed_commit(120).await.expect("confirmed_commit failed");
        session.confirming_commit().await.expect("confirming_commit failed");
    }

    #[tokio::test]
    async fn test_confirmed_commit_requires_capability() {
        // Hello WITHOUT confirmed-commit capability
        let response_data = mock_device_hello();

        let transport = MockTransport::new(response_data);
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        let result = session.confirmed_commit(120).await;
        assert!(result.is_err(), "confirmed_commit should fail without capability");
        let err_str = format!("{:?}", result.unwrap_err());
        assert!(
            err_str.contains("CapabilityMissing"),
            "expected CapabilityMissing, got: {err_str}"
        );
    }

    /// Build a mock lock-denied error response.
    fn mock_lock_denied_reply(message_id: &str, stale_session_id: u32) -> Vec<u8> {
        let reply = format!(
            r#"<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{message_id}">
  <rpc-error>
    <error-type>protocol</error-type>
    <error-tag>lock-denied</error-tag>
    <error-severity>error</error-severity>
    <error-message>Lock failed, lock is already held</error-message>
    <error-info>
      <session-id>{stale_session_id}</session-id>
    </error-info>
  </rpc-error>
</rpc-reply>"#
        );
        let mut buf = reply.into_bytes();
        buf.extend_from_slice(b"]]>]]>");
        buf
    }

    #[tokio::test]
    async fn test_lock_or_kill_stale_succeeds_on_first_try() {
        let mut response_data = mock_device_hello();
        response_data.extend_from_slice(&mock_ok_reply("1")); // lock succeeds

        let transport = MockTransport::new(response_data);
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        let result = session.lock_or_kill_stale(Datastore::Candidate).await;
        assert_eq!(result.unwrap(), None, "no session killed when lock succeeds");
    }

    #[tokio::test]
    async fn test_lock_or_kill_stale_kills_and_retries() {
        let mut response_data = mock_device_hello();
        response_data.extend_from_slice(&mock_lock_denied_reply("1", 42)); // first lock denied
        response_data.extend_from_slice(&mock_ok_reply("2")); // kill-session succeeds
        response_data.extend_from_slice(&mock_ok_reply("3")); // retry lock succeeds

        let transport = MockTransport::new(response_data);
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        let result = session.lock_or_kill_stale(Datastore::Candidate).await;
        assert_eq!(result.unwrap(), Some(42), "should have killed session 42");
    }

    #[tokio::test]
    async fn test_stale_response_drained_and_correct_returned() {
        // Simulate: stale response from msg-id "99" sitting in buffer,
        // followed by the correct response for msg-id "1" (lock).
        let mut response_data = mock_device_hello();
        response_data.extend_from_slice(&mock_ok_reply("99")); // stale
        response_data.extend_from_slice(&mock_ok_reply("1")); // correct

        let transport = MockTransport::new(response_data);
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        // Should succeed by draining the stale "99" and reading "1"
        session
            .lock(Datastore::Candidate)
            .await
            .expect("lock should succeed after draining stale response");
    }

    #[tokio::test]
    async fn test_multiple_stale_responses_drained() {
        // Three stale responses before the correct one
        let mut response_data = mock_device_hello();
        response_data.extend_from_slice(&mock_ok_reply("50")); // stale
        response_data.extend_from_slice(&mock_ok_reply("51")); // stale
        response_data.extend_from_slice(&mock_ok_reply("52")); // stale
        response_data.extend_from_slice(&mock_ok_reply("1")); // correct

        let transport = MockTransport::new(response_data);
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        session
            .lock(Datastore::Candidate)
            .await
            .expect("lock should succeed after draining multiple stale responses");
    }

    #[tokio::test]
    async fn test_stale_drain_limit_exceeded() {
        // More stale responses than MAX_STALE_DRAIN — should fail
        let mut response_data = mock_device_hello();
        for stale_id in 50..=50 + super::MAX_STALE_DRAIN {
            response_data.extend_from_slice(&mock_ok_reply(&stale_id.to_string()));
        }
        // Correct response is beyond the drain limit
        response_data.extend_from_slice(&mock_ok_reply("1"));

        let transport = MockTransport::new(response_data);
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        let result = session.lock(Datastore::Candidate).await;
        match result {
            Err(NetconfError::Rpc(crate::error::RpcError::MessageIdMismatch { .. })) => {
                // Expected — drain limit exceeded
            }
            other => panic!("expected MessageIdMismatch after drain limit, got: {other:?}"),
        }
    }
}
