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

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::capability::{self, Capabilities, NetconfVersion};
use crate::error::{FramingError, NetconfError, ProtocolError, TransportError};
use crate::facts::Facts;
use crate::framing::chunked::ChunkedFramer;
use crate::framing::eom::EomFramer;
use crate::framing::Framer;
use crate::notification::{self, MessageKind, Notification};
use crate::rpc;
use crate::rpc::operations::{self, EditConfigParams};
use crate::rpc::RpcReply;
use crate::transport::Transport;
use crate::rpc::RpcErrorInfo;
use crate::types::{Datastore, DefaultOperation, ErrorOption, LoadAction, LoadFormat, OpenConfigurationMode, TestOption};
use crate::vendor::{self, CloseSequence, VendorProfile};

/// Read buffer size for transport reads.
const READ_BUF_SIZE: usize = 65536;

/// Maximum number of stale (mismatched message-id) responses to drain before
/// giving up. This handles the case where a cancelled async RPC left its
/// response in the transport buffer.
const MAX_STALE_DRAIN: usize = 10;

/// Maximum number of buffered notifications before oldest are dropped.
const MAX_NOTIFICATION_BUFFER: usize = 10_000;

/// Maximum read buffer size (100 MB). If the device sends more data than this
/// without completing a framed message, the read is aborted to prevent memory
/// exhaustion from a malformed or malicious device response.
const MAX_READ_BUFFER: usize = 100 * 1024 * 1024;

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
    message_id: u64,
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
    /// Keepalive interval — if set, a probe is sent before RPCs when idle
    /// longer than this duration.
    keepalive_interval: Option<Duration>,
    /// Timestamp of the last successful RPC or session establishment.
    last_activity: Option<Instant>,
    /// True when a Junos private/exclusive configuration database is open.
    private_config_open: bool,
    /// Buffered notifications received during RPC exchanges.
    notification_buffer: VecDeque<Notification>,
    /// True after a successful `create-subscription` RPC.
    has_subscription: bool,
    /// Maximum time to wait for an RPC reply. `None` means wait forever
    /// (backward-compatible default).
    rpc_timeout: Option<Duration>,
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
            message_id: 1u64,
            state: SessionState::Connected,
            read_buffer: Vec::new(),
            version: None,
            pending_commit: false,
            vendor_profile: Box::new(crate::vendor::generic::GenericVendor),
            facts: Facts::default(),
            keepalive_interval: None,
            last_activity: None,
            private_config_open: false,
            notification_buffer: VecDeque::new(),
            has_subscription: false,
            rpc_timeout: None,
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
        let mut caps = capability::parse_device_hello(&device_hello)
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

        // Normalize legacy capability URIs to their standard forms using the
        // detected vendor profile (e.g., Junos uses urn:ietf:params:xml:ns:netconf:
        // instead of the standard urn:ietf:params:netconf: prefix).
        caps.normalize_with(self.vendor_profile.as_ref());

        self.version = Some(version);
        self.capabilities = Some(caps);
        self.state = SessionState::Established;
        self.last_activity = Some(Instant::now());

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
                self.vendor_profile.post_facts_hook(&self.facts, &response);
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

    /// Set the keepalive interval.
    ///
    /// Must be called before `establish()` or after reconnect. When set,
    /// [`send_rpc()`] checks elapsed time and probes first if idle too long.
    pub fn set_keepalive_interval(&mut self, interval: Duration) {
        self.keepalive_interval = Some(interval);
    }

    /// Set the maximum time to wait for an RPC reply.
    ///
    /// When set, [`send_rpc_raw()`] wraps the read loop with
    /// [`tokio::time::timeout()`]. If the device does not reply within
    /// the deadline, `RpcError::Timeout` is returned.
    ///
    /// `None` (the default) means wait forever, preserving backward
    /// compatibility.
    pub fn set_rpc_timeout(&mut self, timeout: Option<Duration>) {
        self.rpc_timeout = timeout;
    }

    /// Check if the session is alive (established and not closed).
    ///
    /// Fast in-memory check — does not send any RPC.
    pub fn is_alive(&self) -> bool {
        self.state == SessionState::Established
    }

    /// Probe the session by sending a lightweight RPC.
    ///
    /// Sends `<get><filter/></get>` (returns empty data) to verify the
    /// transport is responsive. If the probe fails, the session is marked
    /// as closed.
    ///
    /// Returns `true` if the device responded.
    pub async fn probe(&mut self) -> bool {
        let msg_id = self.next_message_id();
        let xml = operations::get_xml(&msg_id, Some(""));
        match self.send_rpc_raw(&xml, &msg_id).await {
            Ok(_) => true,
            Err(err) => {
                tracing::warn!(%err, "session probe failed — marking session dead");
                self.state = SessionState::Closed;
                false
            }
        }
    }

    /// If a keepalive interval is configured and the idle time exceeds it,
    /// probe the session. Returns an error if the probe fails.
    async fn keepalive_check(&mut self) -> Result<(), NetconfError> {
        let interval = match self.keepalive_interval {
            Some(interval) => interval,
            None => return Ok(()),
        };

        let needs_probe = match self.last_activity {
            Some(last) => last.elapsed() >= interval,
            None => false,
        };

        if needs_probe {
            tracing::debug!("keepalive: idle timeout exceeded, probing session");
            if !self.probe().await {
                return Err(crate::error::ProtocolError::SessionExpired.into());
            }
        }

        Ok(())
    }

    /// Send an RPC and wait for the reply.
    ///
    /// Runs a keepalive check first (if configured), then delegates to
    /// [`send_rpc_raw`].
    async fn send_rpc(&mut self, xml: &str, message_id: &str) -> Result<RpcReply, NetconfError> {
        self.keepalive_check().await?;
        self.send_rpc_raw(xml, message_id).await
    }

    /// Send an RPC without keepalive check.
    ///
    /// If a stale response from a previously cancelled RPC is received
    /// (message-id mismatch), it is drained and the next message is read.
    /// This repeats up to [`MAX_STALE_DRAIN`] times before returning an error.
    ///
    /// When `rpc_timeout` is configured, the entire read loop is bounded by
    /// [`tokio::time::timeout()`]. If the device does not produce a matching
    /// reply within the deadline, `RpcError::Timeout` is returned.
    async fn send_rpc_raw(&mut self, xml: &str, message_id: &str) -> Result<RpcReply, NetconfError> {
        self.ensure_established()?;

        let framed = self.framer.encode(xml);
        tracing::debug!(message_id, "sending RPC");

        self.transport.write_all(&framed).await?;

        match self.rpc_timeout {
            Some(timeout) => {
                tokio::time::timeout(timeout, self.read_rpc_reply(message_id))
                    .await
                    .map_err(|_| crate::error::RpcError::Timeout(timeout))?
            }
            None => self.read_rpc_reply(message_id).await,
        }
    }

    /// Internal helper: read messages until a matching RPC reply arrives.
    ///
    /// Extracted from `send_rpc_raw` so that `tokio::time::timeout` can
    /// wrap the entire read loop.
    async fn read_rpc_reply(&mut self, message_id: &str) -> Result<RpcReply, NetconfError> {
        let mut drain_attempt = 0;
        loop {
            let response = self.read_message().await?;

            // Demux: if a notification arrives during RPC exchange, buffer it
            if notification::classify_message(&response) == Some(MessageKind::Notification) {
                match notification::parse_notification(&response) {
                    Ok(notif) => {
                        tracing::debug!(
                            event_time = %notif.event_time,
                            "buffered notification during RPC exchange"
                        );
                        self.buffer_notification(notif);
                    }
                    Err(e) => {
                        tracing::warn!("failed to parse notification: {e}");
                    }
                }
                // Do NOT increment drain_attempt — notifications are expected
                continue;
            }

            match rpc::parse_rpc_reply(&response, message_id) {
                Ok(reply) => {
                    tracing::debug!(message_id, "received RPC reply");
                    self.last_activity = Some(Instant::now());
                    return Ok(reply);
                }
                Err(crate::error::RpcError::MessageIdMismatch {
                    ref expected,
                    ref actual,
                }) => {
                    if drain_attempt >= MAX_STALE_DRAIN {
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
                    drain_attempt += 1;
                }
                Err(other) => return Err(other.into()),
            }
        }
    }

    /// Allocate the next message-id.
    fn next_message_id(&mut self) -> String {
        let id = self.message_id;
        self.message_id += 1;
        id.to_string()
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

            if self.read_buffer.len() > MAX_READ_BUFFER {
                return Err(TransportError::Io(std::io::Error::new(
                    std::io::ErrorKind::OutOfMemory,
                    format!(
                        "read buffer exceeded {} MB without completing a message",
                        MAX_READ_BUFFER / (1024 * 1024)
                    ),
                ))
                .into());
            }
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
    ///
    /// # Safety
    ///
    /// `rpc_content` must be well-formed XML. It is inserted verbatim into
    /// the `<rpc>` wrapper — do not pass untrusted user input without
    /// validation.
    pub async fn rpc(&mut self, rpc_content: &str) -> Result<String, NetconfError> {
        let msg_id = self.next_message_id();
        let safe_id = crate::rpc::operations::escape_xml_attr(&msg_id);
        let xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?><nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{safe_id}">{rpc_content}</nc:rpc>"#
        );
        let reply = self.send_rpc(&xml, &msg_id).await?;
        match reply {
            RpcReply::Data(data) | RpcReply::DataWithWarnings(data, _) => Ok(data),
            RpcReply::Ok | RpcReply::OkWithWarnings(_) => Ok(String::new()),
        }
    }

    /// Send an arbitrary RPC, returning both the response and any warnings.
    ///
    /// Like [`rpc()`](Self::rpc), but instead of discarding warnings, returns
    /// them alongside the response data. Useful for Junos `<load-configuration>`
    /// and other operations where warnings carry diagnostic value.
    pub async fn rpc_with_warnings(
        &mut self,
        rpc_content: &str,
    ) -> Result<(String, Vec<RpcErrorInfo>), NetconfError> {
        let msg_id = self.next_message_id();
        let safe_id = crate::rpc::operations::escape_xml_attr(&msg_id);
        let xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?><nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{safe_id}">{rpc_content}</nc:rpc>"#
        );
        let reply = self.send_rpc(&xml, &msg_id).await?;
        match reply {
            RpcReply::Data(data) => Ok((data, Vec::new())),
            RpcReply::DataWithWarnings(data, warnings) => Ok((data, warnings)),
            RpcReply::Ok => Ok((String::new(), Vec::new())),
            RpcReply::OkWithWarnings(warnings) => Ok((String::new(), warnings)),
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
            RpcReply::Data(data) | RpcReply::DataWithWarnings(data, _) => {
                Ok(self.vendor_profile.unwrap_config(&data))
            }
            RpcReply::Ok | RpcReply::OkWithWarnings(_) => Ok(String::new()),
        }
    }

    /// Fetch operational and configuration data.
    pub async fn get(&mut self, filter: Option<&str>) -> Result<String, NetconfError> {
        let msg_id = self.next_message_id();
        let xml = operations::get_xml(&msg_id, filter);
        let reply = self.send_rpc(&xml, &msg_id).await?;
        match reply {
            RpcReply::Data(data) | RpcReply::DataWithWarnings(data, _) => Ok(data),
            RpcReply::Ok | RpcReply::OkWithWarnings(_) => Ok(String::new()),
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

    // ── Junos-specific operations ────────────────────────────────────

    /// Open a private or exclusive configuration database (Junos).
    ///
    /// Required on chassis-clustered Junos devices before loading
    /// configuration. On standalone devices this is optional but harmless.
    ///
    /// Call [`close_configuration()`](Self::close_configuration) after committing.
    pub async fn open_configuration(
        &mut self,
        mode: OpenConfigurationMode,
    ) -> Result<(), NetconfError> {
        let msg_id = self.next_message_id();
        let xml = operations::open_configuration_xml(&msg_id, mode);
        self.send_rpc(&xml, &msg_id).await?;
        self.private_config_open = true;
        Ok(())
    }

    /// Close a previously opened private/exclusive configuration database (Junos).
    pub async fn close_configuration(&mut self) -> Result<(), NetconfError> {
        let msg_id = self.next_message_id();
        let xml = operations::close_configuration_xml(&msg_id);
        self.send_rpc(&xml, &msg_id).await?;
        self.private_config_open = false;
        Ok(())
    }

    /// Commit using the Junos-native `<commit-configuration/>` RPC.
    ///
    /// Use this instead of [`commit()`](Self::commit) on Junos devices,
    /// especially when a private/exclusive configuration database is open.
    pub async fn commit_configuration(&mut self) -> Result<(), NetconfError> {
        let msg_id = self.next_message_id();
        let xml = operations::commit_configuration_xml(&msg_id);
        self.send_rpc(&xml, &msg_id).await?;
        Ok(())
    }

    /// Rollback the candidate configuration to a previous commit (Junos).
    ///
    /// `rollback` is the rollback index (0 = most recent commit, up to 49).
    pub async fn rollback_configuration(&mut self, rollback: u32) -> Result<(), NetconfError> {
        let msg_id = self.next_message_id();
        let xml = operations::rollback_configuration_xml(&msg_id, rollback);
        self.send_rpc(&xml, &msg_id).await?;
        Ok(())
    }

    /// Get the diff between candidate and a previous commit (Junos).
    ///
    /// Returns the text-format diff. `rollback` is the rollback index
    /// (0 = most recent commit).
    pub async fn get_configuration_compare(
        &mut self,
        rollback: u32,
    ) -> Result<String, NetconfError> {
        let msg_id = self.next_message_id();
        let xml = operations::get_configuration_compare_xml(&msg_id, rollback);
        let reply = self.send_rpc(&xml, &msg_id).await?;
        match reply {
            RpcReply::Data(data) | RpcReply::DataWithWarnings(data, _) => Ok(data),
            RpcReply::Ok | RpcReply::OkWithWarnings(_) => Ok(String::new()),
        }
    }

    /// Load configuration using the Junos `<load-configuration>` RPC.
    ///
    /// This is the Junos-native way to apply configuration changes, supporting
    /// set commands, curly-brace text format, and XML format.
    ///
    /// On chassis-clustered devices, call
    /// [`open_configuration()`](Self::open_configuration) first.
    ///
    /// # Safety
    ///
    /// `config` is inserted verbatim into the XML — do not pass untrusted
    /// user input without validation.
    pub async fn load_configuration(
        &mut self,
        action: LoadAction,
        format: LoadFormat,
        config: &str,
    ) -> Result<String, NetconfError> {
        let msg_id = self.next_message_id();
        let xml = operations::load_configuration_xml(&msg_id, action, format, config);
        let reply = self.send_rpc(&xml, &msg_id).await?;
        match reply {
            RpcReply::Data(data) | RpcReply::DataWithWarnings(data, _) => Ok(data),
            RpcReply::Ok | RpcReply::OkWithWarnings(_) => Ok(String::new()),
        }
    }

    /// Whether this device requires `<open-configuration>` before loading config.
    ///
    /// Returns `true` for Junos chassis-clustered devices. Use this to decide
    /// whether to call [`open_configuration()`](Self::open_configuration).
    pub fn requires_open_configuration(&self) -> bool {
        self.vendor_profile.requires_open_configuration()
    }

    // ── Session lifecycle ─────────────────────────────────────────────

    /// Close the NETCONF session gracefully.
    ///
    /// Respects the vendor profile's close sequence. For example, Junos
    /// discards uncommitted candidate changes before closing to avoid
    /// leaving dirty state.
    pub async fn close_session(&mut self) -> Result<(), NetconfError> {
        if self.state == SessionState::Closed {
            return Ok(());
        }

        // Close private/exclusive config database if open
        if self.private_config_open {
            let _ = self.close_configuration().await;
            self.private_config_open = false;
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
/// Junos-style text (`session-id: 42` or similar).
fn parse_session_id_from_info(info: &str) -> Option<u32> {
    // Try structured XML parsing with quick_xml
    if info.contains('<') {
        use quick_xml::events::Event;
        use quick_xml::Reader;

        let mut reader = Reader::from_str(info);
        let mut buf = Vec::new();
        let mut in_session_id = false;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref tag)) => {
                    let local = tag.local_name();
                    let name = std::str::from_utf8(local.as_ref()).unwrap_or("");
                    if name == "session-id" {
                        in_session_id = true;
                    }
                }
                Ok(Event::Text(ref text)) if in_session_id => {
                    if let Ok(value) = text.unescape() {
                        if let Ok(id) = value.trim().parse::<u32>() {
                            return Some(id);
                        }
                    }
                    in_session_id = false;
                }
                Ok(Event::End(_)) => {
                    in_session_id = false;
                }
                Ok(Event::Eof) => break,
                Err(_) => break,
                _ => {}
            }
            buf.clear();
        }
    }

    // Fallback: Junos text format ("session-id: 42" or similar)
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

// ── Notification methods (RFC 5277) ──────────────────────────────────

impl Session {
    /// Create a notification subscription (RFC 5277).
    ///
    /// Requires the `:notification` capability. After a successful subscription,
    /// the device sends `<notification>` messages asynchronously. These are
    /// buffered during RPC calls and can be retrieved via
    /// [`drain_notifications()`](Self::drain_notifications) or
    /// [`recv_notification()`](Self::recv_notification).
    ///
    /// # Parameters
    /// - `stream`: event stream name (e.g., "NETCONF"). `None` uses the device default.
    /// - `filter`: optional subtree filter XML
    /// - `start_time`: optional RFC 3339 timestamp to start notification replay
    /// - `stop_time`: optional RFC 3339 timestamp to stop notifications
    pub async fn create_subscription(
        &mut self,
        stream: Option<&str>,
        filter: Option<&str>,
        start_time: Option<&str>,
        stop_time: Option<&str>,
    ) -> Result<(), NetconfError> {
        self.require_capability(
            capability::uri::NOTIFICATION,
            "create-subscription",
        )?;

        if !self.supports(capability::uri::INTERLEAVE) {
            tracing::info!(
                "device does not advertise :interleave capability — \
                 RPCs during active subscription may not be supported"
            );
        }

        let message_id = self.next_message_id();
        let xml = operations::create_subscription_xml(
            &message_id,
            stream,
            filter,
            start_time,
            stop_time,
        );

        let reply = self.send_rpc(&xml, &message_id).await?;
        match reply {
            RpcReply::Ok | RpcReply::OkWithWarnings(_) => {
                self.has_subscription = true;
                tracing::info!(
                    stream = stream.unwrap_or("(default)"),
                    "notification subscription created"
                );
                Ok(())
            }
            _ => Err(ProtocolError::Xml(
                "unexpected response to create-subscription".to_string(),
            )
            .into()),
        }
    }

    /// Drain all buffered notifications, returning them and clearing the buffer.
    ///
    /// Notifications are buffered when they arrive during RPC exchanges.
    /// Call this between RPCs to process accumulated notifications.
    pub fn drain_notifications(&mut self) -> Vec<Notification> {
        self.notification_buffer.drain(..).collect()
    }

    /// Wait for the next notification from the device.
    ///
    /// First checks the internal buffer. If empty, reads messages from the
    /// transport until a notification arrives. Any `<rpc-reply>` messages
    /// received while waiting are logged and discarded.
    ///
    /// Returns `Ok(None)` if the connection is closed (EOF).
    pub async fn recv_notification(&mut self) -> Result<Option<Notification>, NetconfError> {
        // Check buffer first
        if let Some(notif) = self.notification_buffer.pop_front() {
            return Ok(Some(notif));
        }

        // Read from transport until we get a notification or EOF
        loop {
            let response = match self.read_message().await {
                Ok(msg) => msg,
                Err(NetconfError::Transport(TransportError::Io(ref e)))
                    if e.kind() == std::io::ErrorKind::UnexpectedEof =>
                {
                    return Ok(None);
                }
                Err(e) => return Err(e),
            };

            match notification::classify_message(&response) {
                Some(MessageKind::Notification) => {
                    let notif = notification::parse_notification(&response)
                        .map_err(NetconfError::Rpc)?;
                    return Ok(Some(notif));
                }
                Some(MessageKind::RpcReply) => {
                    tracing::warn!(
                        "discarding unexpected rpc-reply while waiting for notification"
                    );
                    continue;
                }
                None => {
                    tracing::warn!(
                        "discarding unrecognized message while waiting for notification"
                    );
                    continue;
                }
            }
        }
    }

    /// Check if any notifications are buffered without blocking.
    pub fn has_notifications(&self) -> bool {
        !self.notification_buffer.is_empty()
    }

    /// Whether this session has an active notification subscription.
    pub fn has_subscription(&self) -> bool {
        self.has_subscription
    }

    /// Buffer a notification, dropping the oldest if the buffer is full.
    fn buffer_notification(&mut self, notif: Notification) {
        if self.notification_buffer.len() >= MAX_NOTIFICATION_BUFFER {
            tracing::warn!(
                max = MAX_NOTIFICATION_BUFFER,
                "notification buffer full, dropping oldest notification"
            );
            self.notification_buffer.pop_front();
        }
        self.notification_buffer.push_back(notif);
    }
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

    #[tokio::test]
    async fn test_session_alive_after_establish() {
        let response_data = mock_device_hello();
        let transport = MockTransport::new(response_data);
        let mut session = Session::new(Box::new(transport));

        assert!(!session.is_alive(), "not alive before establish");
        session.establish().await.expect("establish failed");
        assert!(session.is_alive(), "alive after establish");
    }

    #[tokio::test]
    async fn test_session_alive_false_after_close() {
        let mut response_data = mock_device_hello();
        // close_session sends discard_changes (best-effort) then close-session
        response_data.extend_from_slice(&mock_ok_reply("1")); // discard_changes
        response_data.extend_from_slice(&mock_ok_reply("2")); // close_session

        let transport = MockTransport::new(response_data);
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");
        assert!(session.is_alive());

        session.close_session().await.expect("close failed");
        assert!(!session.is_alive(), "not alive after close");
    }

    #[tokio::test]
    async fn test_probe_success() {
        let mut response_data = mock_device_hello();
        // probe sends a <get> with empty filter
        response_data.extend_from_slice(&mock_ok_reply("1")); // probe reply

        let transport = MockTransport::new(response_data);
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        assert!(session.probe().await, "probe should succeed");
        assert!(session.is_alive(), "session should still be alive");
    }

    #[tokio::test]
    async fn test_probe_failure_marks_session_dead() {
        // Only hello, no probe reply — EOF during probe
        let response_data = mock_device_hello();

        let transport = MockTransport::new(response_data);
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        assert!(!session.probe().await, "probe should fail (EOF)");
        assert!(!session.is_alive(), "session should be marked dead");
    }

    #[tokio::test]
    async fn test_last_activity_updated_after_rpc() {
        let mut response_data = mock_device_hello();
        response_data.extend_from_slice(&mock_ok_reply("1")); // lock reply

        let transport = MockTransport::new(response_data);
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        let before = session.last_activity;
        session.lock(Datastore::Candidate).await.expect("lock failed");
        let after = session.last_activity;

        assert!(after.is_some(), "last_activity should be set");
        assert!(
            after.unwrap() >= before.unwrap(),
            "last_activity should advance after RPC"
        );
    }

    // ── Notification tests ───────────────────────────────────────────

    /// Build a mock device hello with notification capability.
    fn mock_device_hello_with_notification() -> Vec<u8> {
        let hello = r#"<?xml version="1.0" encoding="UTF-8"?>
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <capabilities>
    <capability>urn:ietf:params:netconf:base:1.0</capability>
    <capability>urn:ietf:params:netconf:capability:candidate:1.0</capability>
    <capability>urn:ietf:params:netconf:capability:notification:1.0</capability>
    <capability>urn:ietf:params:netconf:capability:interleave:1.0</capability>
  </capabilities>
  <session-id>1</session-id>
</hello>"#;
        let mut buf = hello.as_bytes().to_vec();
        buf.extend_from_slice(b"]]>]]>");
        buf
    }

    /// Build a mock notification with EOM framing.
    fn mock_notification(event_time: &str, event_xml: &str) -> Vec<u8> {
        let notif = format!(
            r#"<notification xmlns="urn:ietf:params:xml:ns:netconf:notification:1.0">
  <eventTime>{event_time}</eventTime>
  {event_xml}
</notification>"#
        );
        let mut buf = notif.into_bytes();
        buf.extend_from_slice(b"]]>]]>");
        buf
    }

    #[tokio::test]
    async fn test_notification_buffered_during_rpc() {
        let mut response_data = mock_device_hello_with_notification();
        // notification arrives between lock request and reply
        response_data.extend_from_slice(&mock_notification(
            "2026-04-01T12:00:00Z",
            "<config-change/>",
        ));
        response_data.extend_from_slice(&mock_ok_reply("1")); // lock reply

        let transport = MockTransport::new(response_data);
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        // Lock should succeed despite interleaved notification
        session.lock(Datastore::Candidate).await.expect("lock failed");

        // Notification should be buffered
        let notifications = session.drain_notifications();
        assert_eq!(notifications.len(), 1);
        assert_eq!(notifications[0].event_time, "2026-04-01T12:00:00Z");
        assert!(notifications[0].event_xml.contains("config-change"));
    }

    #[tokio::test]
    async fn test_multiple_notifications_buffered_during_rpc() {
        let mut response_data = mock_device_hello_with_notification();
        response_data.extend_from_slice(&mock_notification("2026-04-01T12:00:00Z", "<event1/>"));
        response_data.extend_from_slice(&mock_notification("2026-04-01T12:01:00Z", "<event2/>"));
        response_data.extend_from_slice(&mock_notification("2026-04-01T12:02:00Z", "<event3/>"));
        response_data.extend_from_slice(&mock_ok_reply("1")); // lock reply

        let transport = MockTransport::new(response_data);
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        session.lock(Datastore::Candidate).await.expect("lock failed");

        let notifications = session.drain_notifications();
        assert_eq!(notifications.len(), 3);
        assert_eq!(notifications[0].event_time, "2026-04-01T12:00:00Z");
        assert_eq!(notifications[2].event_time, "2026-04-01T12:02:00Z");
    }

    #[tokio::test]
    async fn test_notifications_dont_count_toward_stale_drain() {
        // 15 notifications > MAX_STALE_DRAIN (10), but should NOT trigger drain limit
        let mut response_data = mock_device_hello_with_notification();
        for i in 0..15 {
            response_data.extend_from_slice(&mock_notification(
                &format!("2026-04-01T12:{i:02}:00Z"),
                &format!("<event{i}/>"),
            ));
        }
        response_data.extend_from_slice(&mock_ok_reply("1")); // lock reply

        let transport = MockTransport::new(response_data);
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        // Should succeed — notifications are not stale replies
        session.lock(Datastore::Candidate).await.expect("lock failed");

        let notifications = session.drain_notifications();
        assert_eq!(notifications.len(), 15);
    }

    #[tokio::test]
    async fn test_create_subscription_requires_capability() {
        // Hello WITHOUT notification capability
        let response_data = mock_device_hello();

        let transport = MockTransport::new(response_data);
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        let result = session.create_subscription(None, None, None, None).await;
        match result {
            Err(NetconfError::Protocol(ProtocolError::CapabilityMissing(_))) => {}
            other => panic!("expected CapabilityMissing, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_recv_notification_returns_buffered_first() {
        let mut response_data = mock_device_hello_with_notification();
        // Two notifications then EOF
        response_data.extend_from_slice(&mock_notification("2026-04-01T12:00:00Z", "<event1/>"));
        response_data.extend_from_slice(&mock_ok_reply("1")); // for an RPC
        response_data.extend_from_slice(&mock_notification("2026-04-01T12:01:00Z", "<event2/>"));

        let transport = MockTransport::new(response_data);
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        // Lock buffers the first notification
        session.lock(Datastore::Candidate).await.expect("lock failed");
        assert!(session.has_notifications());

        // recv_notification should return the buffered one first
        let notif = session.recv_notification().await.unwrap().unwrap();
        assert_eq!(notif.event_time, "2026-04-01T12:00:00Z");

        // Next should read from transport
        let notif2 = session.recv_notification().await.unwrap().unwrap();
        assert_eq!(notif2.event_time, "2026-04-01T12:01:00Z");
    }

    #[tokio::test]
    async fn test_recv_notification_eof_returns_none() {
        let response_data = mock_device_hello_with_notification();
        // No notifications, just EOF after hello

        let transport = MockTransport::new(response_data);
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        let result = session.recv_notification().await.unwrap();
        assert!(result.is_none(), "expected None on EOF");
    }

    #[tokio::test]
    async fn test_drain_clears_buffer() {
        let mut response_data = mock_device_hello_with_notification();
        response_data.extend_from_slice(&mock_notification("2026-04-01T12:00:00Z", "<event/>"));
        response_data.extend_from_slice(&mock_ok_reply("1"));

        let transport = MockTransport::new(response_data);
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        session.lock(Datastore::Candidate).await.expect("lock failed");
        assert_eq!(session.drain_notifications().len(), 1);
        assert_eq!(session.drain_notifications().len(), 0); // buffer cleared
    }
}
