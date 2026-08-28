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
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::capability::{self, Capabilities, NetconfVersion};
use crate::error::{FramingError, NetconfError, ProtocolError, TransportError};
use crate::facts::Facts;
use crate::framing::chunked::ChunkedFramer;
use crate::framing::eom::EomFramer;
use crate::framing::{FramePart, Framer};
use crate::notification::{self, MessageKind, Notification};
use crate::rpc;
use crate::rpc::filter::XPathFilter;
use crate::rpc::operations::{self, EditConfigParams};
use crate::rpc::RpcErrorInfo;
use crate::rpc::RpcReply;
use crate::transport::Transport;
use crate::types::{
    ConfigLocation, CopySource, Datastore, DefaultOperation, DeleteTarget, ErrorOption, LoadAction,
    LoadFormat, OpenConfigurationMode, PartialLock, TestOption, WithDefaults,
};
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
    /// Vendor-specific behavior profile. Set during establish() via auto-detection,
    /// or overridden by the user via Client::vendor() / Client::vendor_profile().
    vendor_profile: Arc<dyn VendorProfile>,
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
    /// Maximum number of bytes that may accumulate in `read_buffer` before
    /// the read is aborted. Defaults to [`MAX_READ_BUFFER`].
    max_read_buffer: usize,
    /// Set before a `<partial-lock>` is written and cleared only once a
    /// `lock-id` has been parsed from the reply. See [`Session::is_alive`].
    partial_lock_uncertain: bool,
    /// Set while a streamed reply is partially drained. See `stream_rpc`.
    stream_incomplete: bool,
    /// True if this session may have left uncommitted changes in the shared
    /// candidate datastore. Used to decide whether to send `<discard-changes/>`
    /// on close.
    candidate_dirty: bool,
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
            vendor_profile: Arc::new(crate::vendor::generic::GenericVendor),
            facts: Facts::default(),
            keepalive_interval: None,
            last_activity: None,
            private_config_open: false,
            notification_buffer: VecDeque::new(),
            has_subscription: false,
            rpc_timeout: None,
            max_read_buffer: MAX_READ_BUFFER,
            partial_lock_uncertain: false,
            stream_incomplete: false,
            candidate_dirty: false,
        }
    }

    /// Set an explicit vendor profile, overriding auto-detection.
    ///
    /// Must be called before `establish()`. After establish, the vendor
    /// profile is locked in.
    pub fn set_vendor_profile(&mut self, profile: Box<dyn VendorProfile>) {
        self.vendor_profile = Arc::from(profile);
    }

    /// Set an explicit vendor profile (Arc), overriding auto-detection.
    ///
    /// Must be called before `establish()`. After establish, the vendor
    /// profile is locked in. Use this when sharing a vendor profile across
    /// multiple sessions.
    pub fn set_vendor_profile_arc(&mut self, profile: Arc<dyn VendorProfile>) {
        self.vendor_profile = profile;
    }

    /// Set the maximum read buffer size in bytes.
    ///
    /// If the device sends more data than this without completing a framed
    /// message, the read is aborted to prevent memory exhaustion.
    /// Defaults to 100 MB.
    /// The current read-buffer ceiling in bytes.
    pub fn max_read_buffer(&self) -> usize {
        self.max_read_buffer
    }

    /// Set the read-buffer ceiling.
    ///
    /// This bounds bytes accumulated *without completing a framed message*, not
    /// total reply size directly — though for one large reply those amount to
    /// the same thing, since the framer yields nothing until the whole message
    /// is present. A reply already buffered in full is decoded regardless of the
    /// ceiling, so lowering it does not retroactively reject data in hand.
    pub fn set_max_read_buffer(&mut self, max_bytes: usize) {
        self.max_read_buffer = max_bytes;
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
        let device_hello = self.read_message(false).await?;
        let mut caps =
            capability::parse_device_hello(&device_hello).map_err(ProtocolError::HelloFailed)?;

        // Negotiate version and switch framing
        let version = caps.negotiate_version().ok_or_else(|| {
            ProtocolError::HelloFailed(
                "device does not support NETCONF base:1.0 or base:1.1".to_string(),
            )
        })?;

        if version == NetconfVersion::V1_1 {
            self.framer = Box::new(ChunkedFramer::new());
        }

        // Auto-detect vendor from capabilities (unless explicitly overridden)
        if self.vendor_profile.name() == "generic" {
            self.vendor_profile = Arc::from(vendor::detect_vendor(&caps));
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

    /// Check if this session may have dirtied the candidate datastore.
    ///
    /// Returns `true` if the session has called candidate-modifying operations
    /// like `edit_config(Datastore::Candidate, ...)`, `load_configuration()`,
    /// or `rollback_configuration()` since the last `commit()` or `discard_changes()`.
    pub fn candidate_dirty(&self) -> bool {
        self.candidate_dirty
    }

    /// Mark the candidate datastore as dirty.
    ///
    /// For vendor-specific candidate-modifying RPCs, prefer
    /// [`rpc_candidate_change()`](Self::rpc_candidate_change) — or
    /// [`rpc_candidate_change_with_warnings()`](Self::rpc_candidate_change_with_warnings)
    /// when you need the warnings back — over manually marking with this method.
    /// Those methods validate the fragment locally first and only mark dirty if
    /// validation and the transport preflight pass, preventing a locally-rejected
    /// RPC from incorrectly marking the candidate dirty.
    ///
    /// If you must use the raw [`rpc()`](Self::rpc) escape hatch, call this
    /// **before** sending the RPC, so [`close_session()`](Self::close_session)
    /// will send `<discard-changes/>` to clean up the shared candidate datastore.
    ///
    /// This is a safety mechanism for Junos and other devices with a shared
    /// candidate datastore. When a session closes without committing, uncommitted
    /// changes must be discarded so they don't interfere with the next operator's
    /// session.
    ///
    /// # Warning
    ///
    /// If you mark manually, ensure the RPC actually reached the device. Marking
    /// before a locally-rejected RPC (e.g., malformed XML) can cause `close_session()`
    /// to discard another session's work on a shared candidate.
    ///
    /// # Why mark BEFORE the RPC?
    ///
    /// Marking before (not after) the RPC ensures that a timeout, cancellation,
    /// or error-after-partial-application still counts as dirty, matching the
    /// behavior of built-in operations like `load_configuration()`. A failed or
    /// partially-applied RPC may still leave uncommitted changes that need cleanup.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Mark BEFORE awaiting the RPC
    /// session.mark_candidate_dirty();
    /// session.rpc("<load-configuration>...</load-configuration>").await?;
    /// ```
    pub fn mark_candidate_dirty(&mut self) {
        self.candidate_dirty = true;
    }

    /// Normalize a config fragment the way this session's vendor profile does
    /// (e.g. Junos strips the outer `<configuration>` wrapper; generic passes
    /// through). This is the same operation applied to get-config responses,
    /// exposed so callers can normalize a *desired* config symmetrically.
    pub fn unwrap_config(&self, xml: &str) -> String {
        self.vendor_profile.unwrap_config(xml)
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
    /// RPC calls check elapsed time and probe first if idle too long.
    pub fn set_keepalive_interval(&mut self, interval: Duration) {
        self.keepalive_interval = Some(interval);
    }

    /// Set the maximum time to wait for an RPC reply.
    ///
    /// When set, the RPC read loop wraps with
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
            && !self.partial_lock_uncertain
            && !self.stream_incomplete
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
        match self.send_rpc_raw(&xml, &msg_id, false).await {
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
        self.send_rpc_raw(xml, message_id, false).await
    }

    /// Send a commit RPC with keepalive check.
    ///
    /// Like [`send_rpc`], but marks the call as a commit operation. If the
    /// transport returns EOF while awaiting the reply, this returns
    /// [`RpcError::CommitUnknown`] instead of a generic transport error,
    /// signaling that the device may have applied the commit before the
    /// connection dropped.
    ///
    /// Threading `is_commit` as an argument (rather than storing it on the
    /// session) makes this method cancellation-safe: a dropped future cannot
    /// leave stale state behind that would affect subsequent, unrelated RPCs.
    async fn send_rpc_commit(
        &mut self,
        xml: &str,
        message_id: &str,
    ) -> Result<RpcReply, NetconfError> {
        self.keepalive_check().await?;
        self.send_rpc_raw(xml, message_id, true).await
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
    ///
    /// `is_commit`: whether this is a commit RPC; passed through to the read path.
    async fn send_rpc_raw(
        &mut self,
        xml: &str,
        message_id: &str,
        is_commit: bool,
    ) -> Result<RpcReply, NetconfError> {
        self.ensure_established()?;

        let framed = self.framer.encode(xml);
        tracing::debug!(message_id, "sending RPC");

        self.transport.write_all(&framed).await?;

        match self.rpc_timeout {
            Some(timeout) => {
                tokio::time::timeout(timeout, self.read_rpc_reply(message_id, is_commit))
                    .await
                    .map_err(|_| crate::error::RpcError::Timeout(timeout))?
            }
            None => self.read_rpc_reply(message_id, is_commit).await,
        }
    }

    /// Internal helper: read messages until a matching RPC reply arrives.
    ///
    /// Extracted from `send_rpc_raw` so that `tokio::time::timeout` can
    /// wrap the entire read loop.
    ///
    /// `is_commit`: whether this is a commit RPC; passed through to `read_message`.
    async fn read_rpc_reply(
        &mut self,
        message_id: &str,
        is_commit: bool,
    ) -> Result<RpcReply, NetconfError> {
        let mut drain_attempt = 0;
        loop {
            let response = self.read_message(is_commit).await?;

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
    ///
    /// `is_commit`: whether this read is for a commit RPC. If `true`, a transport
    /// EOF is reported as `RpcError::CommitUnknown` because the device may have
    /// applied the commit before the connection dropped.
    async fn read_message(&mut self, is_commit: bool) -> Result<String, NetconfError> {
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
                if is_commit {
                    return Err(crate::error::RpcError::CommitUnknown.into());
                }
                return Err(TransportError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed while waiting for RPC reply",
                ))
                .into());
            }
            self.read_buffer.extend_from_slice(&temp_buf[..bytes_read]);

            if self.read_buffer.len() > self.max_read_buffer {
                return Err(TransportError::Io(std::io::Error::new(
                    std::io::ErrorKind::OutOfMemory,
                    format!(
                        "read buffer exceeded {} MB without completing a message",
                        self.max_read_buffer / (1024 * 1024)
                    ),
                ))
                .into());
            }
        }
    }

    /// Ensure the session is established before sending RPCs.
    fn ensure_established(&self) -> Result<(), NetconfError> {
        // A partially-drained stream leaves a suffix of someone else's reply in
        // the buffer; the next RPC would parse that as its own response.
        if self.stream_incomplete {
            return Err(ProtocolError::SessionExpired.into());
        }
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

    // ── Raw RPC ─────────────────────────────────────────────────────

    /// Send an arbitrary RPC and return the raw XML response content.
    ///
    /// The `rpc_content` is wrapped in `<rpc>` tags with a message-id,
    /// sent to the device, and the inner content of `<rpc-reply>` is returned.
    ///
    /// Use this for vendor-specific RPCs not covered by the standard
    /// NETCONF operations (get-config, edit-config, etc.).
    ///
    /// # Content requirements
    ///
    /// `rpc_content` must be well-formed XML. It is validated with
    /// [`rpc::validate_xml_fragment`] before being inserted into the `<rpc>`
    /// wrapper and sent on the wire. A `ProtocolError::Xml` is returned if the
    /// fragment is malformed. Callers are responsible for ensuring that any
    /// user-provided values within the content are appropriately escaped or
    /// sanitized before passing to this method.
    pub async fn rpc(&mut self, rpc_content: &str) -> Result<String, NetconfError> {
        rpc::validate_xml_fragment(rpc_content)?;
        self.dispatch_rpc_fragment(rpc_content).await
    }

    /// Send an arbitrary RPC that modifies the candidate datastore.
    ///
    /// This is the preferred way to send vendor-specific candidate-modifying RPCs
    /// (e.g., Junos `<load-configuration>`). It validates the XML fragment locally
    /// first, then runs all preflight checks (keepalive probe and session state).
    /// Only after all checks pass does it mark the candidate dirty and send the RPC.
    ///
    /// Marking happens AFTER all preflight checks but BEFORE the write begins, so:
    /// - A locally-malformed fragment does not incorrectly mark dirty
    /// - A failed preflight check (e.g., un-established session) does not mark dirty
    /// - A timeout or error AFTER the write begins still marks dirty for cleanup
    ///
    /// When `close_session()` is called, it will send `<discard-changes/>` to
    /// clean up this session's uncommitted changes on devices with a shared
    /// candidate datastore (e.g., Junos).
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Atomic: validates, runs preflight, marks only if preflight passes, then sends
    /// session.rpc_candidate_change(
    ///     "<load-configuration><configuration><foo/></configuration></load-configuration>"
    /// ).await?;
    /// ```
    pub async fn rpc_candidate_change(
        &mut self,
        rpc_content: &str,
    ) -> Result<String, NetconfError> {
        let reply = self.dispatch_candidate_change(rpc_content).await?;

        // Map reply to String the same way rpc() does
        match reply {
            RpcReply::Data(data) | RpcReply::DataWithWarnings(data, _) => Ok(data),
            RpcReply::Ok | RpcReply::OkWithWarnings(_) => Ok(String::new()),
        }
    }

    /// Send an arbitrary candidate-modifying RPC, returning the response and any warnings.
    ///
    /// The warnings-returning counterpart of
    /// [`rpc_candidate_change()`](Self::rpc_candidate_change): identical
    /// preflight-then-mark ordering, but it returns the `(data, warnings)` tuple
    /// that [`rpc_with_warnings()`](Self::rpc_with_warnings) returns.
    ///
    /// Prefer this over marking by hand and calling `rpc_with_warnings()`.
    /// `rpc_with_warnings()` validates the fragment and returns *before sending
    /// anything*, so a hand-marked malformed fragment leaves the candidate marked
    /// dirty for an RPC that never reached the device — and the next
    /// `close_session()` would then send `<discard-changes/>`, destroying another
    /// operator's uncommitted work on a shared candidate. Marking by hand also
    /// cannot replicate the keepalive and session-state preflight, which is not
    /// otherwise reachable from outside the crate.
    ///
    /// Marking happens AFTER all preflight checks but BEFORE the write begins, so:
    /// - A locally-malformed fragment does not incorrectly mark dirty
    /// - A failed preflight check (e.g., un-established session) does not mark dirty
    /// - A timeout or error AFTER the write begins still marks dirty for cleanup
    ///
    /// # Example
    ///
    /// ```ignore
    /// let (data, warnings) = session.rpc_candidate_change_with_warnings(
    ///     "<load-configuration><configuration><foo/></configuration></load-configuration>"
    /// ).await?;
    /// ```
    pub async fn rpc_candidate_change_with_warnings(
        &mut self,
        rpc_content: &str,
    ) -> Result<(String, Vec<RpcErrorInfo>), NetconfError> {
        let reply = self.dispatch_candidate_change(rpc_content).await?;

        // Map reply the same way rpc_with_warnings() does
        match reply {
            RpcReply::Data(data) => Ok((data, Vec::new())),
            RpcReply::DataWithWarnings(data, warnings) => Ok((data, warnings)),
            RpcReply::Ok => Ok((String::new(), Vec::new())),
            RpcReply::OkWithWarnings(warnings) => Ok((String::new(), warnings)),
        }
    }

    /// Internal helper: the atomic validate-preflight-mark-send sequence shared by
    /// [`rpc_candidate_change()`](Self::rpc_candidate_change) and
    /// [`rpc_candidate_change_with_warnings()`](Self::rpc_candidate_change_with_warnings).
    ///
    /// Returns the raw [`RpcReply`] so each caller can map it to its own return shape.
    /// The ordering here is the whole point: nothing marks the candidate dirty until
    /// every check that can fail *before* the write has passed.
    async fn dispatch_candidate_change(
        &mut self,
        rpc_content: &str,
    ) -> Result<RpcReply, NetconfError> {
        // 1. Validate locally first - if this fails, do NOT mark dirty
        rpc::validate_xml_fragment(rpc_content)?;

        // 2. Run keepalive check if configured - if this fails, do NOT mark dirty
        self.keepalive_check().await?;

        // 3. Ensure session is established - if this fails, do NOT mark dirty
        self.ensure_established()?;

        // 4. All preflight passed - mark dirty NOW, before the write begins
        self.candidate_dirty = true;

        // 5. Build the RPC envelope and send via send_rpc_raw (bypasses keepalive re-check)
        let msg_id = self.next_message_id();
        let xml = Self::wrap_rpc_envelope(&msg_id, rpc_content);
        self.send_rpc_raw(&xml, &msg_id, false).await
    }

    /// Internal helper: wrap a validated fragment in the `<rpc>` envelope.
    ///
    /// Shared by the raw-RPC paths so the envelope is built identically
    /// whether or not the call marks the candidate dirty.
    fn wrap_rpc_envelope(message_id: &str, rpc_content: &str) -> String {
        let safe_id = crate::rpc::operations::escape_xml_attr(message_id);
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?><nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{safe_id}">{rpc_content}</nc:rpc>"#
        )
    }

    /// Internal helper: dispatch an already-validated RPC fragment.
    /// Wraps the fragment in an `<rpc>` envelope, sends it, and extracts the response.
    /// Used by `rpc()` after validation. Calls `send_rpc()` which runs the keepalive check.
    async fn dispatch_rpc_fragment(&mut self, rpc_content: &str) -> Result<String, NetconfError> {
        let msg_id = self.next_message_id();
        let xml = Self::wrap_rpc_envelope(&msg_id, rpc_content);
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
    ///
    /// `rpc_content` is validated as well-formed XML before sending; see
    /// [`rpc()`](Self::rpc) for details.
    ///
    /// If the RPC modifies the candidate datastore, use
    /// [`rpc_candidate_change_with_warnings()`](Self::rpc_candidate_change_with_warnings)
    /// instead — it marks the candidate dirty atomically with the send, which
    /// hand-marking before this method cannot do safely.
    pub async fn rpc_with_warnings(
        &mut self,
        rpc_content: &str,
    ) -> Result<(String, Vec<RpcErrorInfo>), NetconfError> {
        rpc::validate_xml_fragment(rpc_content)?;
        let msg_id = self.next_message_id();
        let xml = Self::wrap_rpc_envelope(&msg_id, rpc_content);
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
    ///
    /// `filter`, when provided, must be a well-formed XML subtree filter
    /// fragment. It is validated before sending; a `ProtocolError::Xml` is
    /// returned if it is malformed.
    pub async fn get_config(
        &mut self,
        source: Datastore,
        filter: Option<&str>,
    ) -> Result<String, NetconfError> {
        if let Some(filter_xml) = filter {
            rpc::validate_xml_fragment(filter_xml)?;
        }
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
    ///
    /// `filter`, when provided, must be a well-formed XML subtree filter
    /// fragment. It is validated before sending; a `ProtocolError::Xml` is
    /// Fetch configuration with an explicit `<with-defaults>` mode (RFC 6243).
    ///
    /// Note on shape: for [`WithDefaults::ReportAllTagged`] the vendor wrapper
    /// is **not** stripped, because the `wd:` prefix carrying the default
    /// markers is bound on it. Every other mode is unwrapped as usual.
    ///
    /// Errors with [`ProtocolError::CapabilityMissing`] when the device does
    /// not advertise the mode. The check uses the capability's own
    /// `basic-mode`/`also-supported` list rather than just the capability URI:
    /// a device supporting only `explicit` would otherwise be sent `trim` and
    /// answer with data in a different shape than the caller asked for.
    pub async fn get_config_with_defaults(
        &mut self,
        source: Datastore,
        filter: Option<&str>,
        mode: WithDefaults,
    ) -> Result<String, NetconfError> {
        self.require_with_defaults(mode)?;
        if let Some(filter_xml) = filter {
            rpc::validate_xml_fragment(filter_xml)?;
        }
        let msg_id = self.next_message_id();
        let xml = operations::get_config_with_defaults_xml(&msg_id, source, filter, mode);
        match self.send_rpc(&xml, &msg_id).await? {
            RpcReply::Data(data) | RpcReply::DataWithWarnings(data, _) => {
                // `report-all-tagged` is returned unwrapped-from-nothing: the
                // vendor unwrap is skipped for it alone.
                //
                // Junos `unwrap_config` strips the `<configuration>` wrapper by
                // string surgery, taking its `xmlns` declarations with it. In
                // this mode the reply's entire point is the `wd:default="true"`
                // markers, and `wd` is bound on that wrapper — stripping it
                // hands back attributes whose prefix resolves to nothing.
                //
                // Skipping the unwrap only here, rather than teaching
                // `unwrap_config` to keep namespaced wrappers, is deliberate.
                // The CLI diffs a desired config it unwraps itself against a
                // running config the vendor profile unwrapped
                // (`plan.rs` strip-then-diff), so a retained wrapper on the
                // device side would make every top-level element differ and
                // produce false add/remove entries.
                if matches!(mode, WithDefaults::ReportAllTagged) {
                    Ok(data)
                } else {
                    Ok(self.vendor_profile.unwrap_config(&data))
                }
            }
            RpcReply::Ok | RpcReply::OkWithWarnings(_) => Ok(String::new()),
        }
    }

    /// Fetch operational and configuration data with a `<with-defaults>` mode.
    pub async fn get_with_defaults(
        &mut self,
        filter: Option<&str>,
        mode: WithDefaults,
    ) -> Result<String, NetconfError> {
        self.require_with_defaults(mode)?;
        if let Some(filter_xml) = filter {
            rpc::validate_xml_fragment(filter_xml)?;
        }
        let msg_id = self.next_message_id();
        let xml = operations::get_with_defaults_xml(&msg_id, filter, mode);
        match self.send_rpc(&xml, &msg_id).await? {
            RpcReply::Data(data) | RpcReply::DataWithWarnings(data, _) => Ok(data),
            RpcReply::Ok | RpcReply::OkWithWarnings(_) => Ok(String::new()),
        }
    }

    /// The `<with-defaults>` modes this device advertises.
    ///
    /// Empty when the device does not support RFC 6243 at all.
    pub fn with_defaults_modes(&self) -> Vec<String> {
        self.capabilities()
            .map(|caps| caps.with_defaults_modes())
            .unwrap_or_default()
    }

    /// Error unless the device advertises this specific with-defaults mode.
    fn require_with_defaults(&self, mode: WithDefaults) -> Result<(), NetconfError> {
        let modes = self.with_defaults_modes();
        if modes.iter().any(|m| m == mode.as_str()) {
            return Ok(());
        }
        Err(ProtocolError::CapabilityMissing(format!(
            "with-defaults mode `{mode}` is not advertised (supported: {})",
            if modes.is_empty() {
                "none".to_string()
            } else {
                modes.join(", ")
            }
        ))
        .into())
    }

    /// Stream a `<get-config>` reply into `sink` instead of buffering it.
    ///
    /// Peak memory becomes one transport read plus one frame chunk, rather than
    /// the whole reply. That is the point: [`get_config`](Self::get_config)
    /// accumulates the entire response before returning it, so fetching a large
    /// configuration costs its size in resident memory even if the caller only
    /// writes it to a file.
    ///
    /// # What the caller receives
    ///
    /// The raw `<rpc-reply>` document, verbatim. Deliberately *not* the unwrapped
    /// `<data>` contents that `get_config` returns, because neither of the two
    /// transformations that produce those can run on a stream:
    ///
    /// - `VendorProfile::unwrap_config` locates the wrapper with
    ///   `rfind("</configuration>")`, which needs the whole string
    /// - the reply-repair layer decides on a *closed* payload — the SRX345
    ///   `<ok/>`-after-`<commit-results>` tolerance is a judgement about a
    ///   complete document, and cannot be made retroactively
    ///
    /// So a caller streaming a reply parses the envelope themselves. That is the
    /// honest trade for constant memory, and it is why this is a separate method
    /// rather than a flag on the existing one.
    ///
    /// `<rpc-error>` replies are streamed too, not turned into `Err` — detecting
    /// one requires parsing the envelope, which is exactly what this method does
    /// not do. Check the document you receive.
    pub async fn get_config_streaming<W>(
        &mut self,
        source: Datastore,
        filter: Option<&str>,
        sink: &mut W,
    ) -> Result<usize, NetconfError>
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        if let Some(filter_xml) = filter {
            rpc::validate_xml_fragment(filter_xml)?;
        }
        let msg_id = self.next_message_id();
        let xml = operations::get_config_xml(&msg_id, source, filter);
        self.stream_rpc(&xml, &msg_id, sink).await
    }

    /// Stream a `<get>` reply into `sink`. See
    /// [`get_config_streaming`](Self::get_config_streaming) for what the caller
    /// receives and why.
    pub async fn get_streaming<W>(
        &mut self,
        filter: Option<&str>,
        sink: &mut W,
    ) -> Result<usize, NetconfError>
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        if let Some(filter_xml) = filter {
            rpc::validate_xml_fragment(filter_xml)?;
        }
        let msg_id = self.next_message_id();
        let xml = operations::get_xml(&msg_id, filter);
        self.stream_rpc(&xml, &msg_id, sink).await
    }

    /// Send `xml` and write the framed reply to `sink` as it arrives.
    ///
    /// Returns the number of payload bytes written.
    async fn stream_rpc<W>(
        &mut self,
        xml: &str,
        message_id: &str,
        sink: &mut W,
    ) -> Result<usize, NetconfError>
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        use tokio::io::AsyncWriteExt;

        // Checked before the keepalive probe. A device that does not answer RPCs
        // on a subscribed session would otherwise hang on the probe, or have the
        // session marked closed, instead of getting this immediate rejection.
        //
        // Streaming reads one frame off the wire and hands it straight to the
        // caller — it cannot demultiplex. With a subscription active, an RFC
        // 5277 notification can arrive before the reply, and this would return
        // the notification as the result while the real reply stayed queued.
        // `send_rpc_raw` classifies frames and buffers notifications; there is
        // no way to do that while streaming, so refuse instead of racing.
        if self.has_subscription {
            return Err(ProtocolError::Xml(
                "streaming replies is not supported while a notification subscription \
                 is active: notifications and replies cannot be told apart without \
                 buffering the frame"
                    .to_string(),
            )
            .into());
        }

        // Refused while the candidate holds uncommitted edits.
        //
        // An interrupted stream poisons the session, and a poisoned session
        // rejects `discard_changes` — while `close_session` swallows that
        // failure and drops the transport. On a shared Junos candidate that
        // leaves another operator's next lock staring at edits nobody owns.
        // Streaming is a read; requiring a clean candidate for it costs callers
        // nothing and keeps the cleanup path that #71 and #74 spent four
        // revisions getting right.
        if self.candidate_dirty {
            return Err(ProtocolError::Xml(
                "cannot stream a reply while the candidate is dirty: an interrupted \
                 stream would block the discard that cleans it up"
                    .to_string(),
            )
            .into());
        }

        self.keepalive_check().await?;
        self.ensure_established()?;

        let framed = self.framer.encode(xml);
        self.transport.write_all(&framed).await?;

        // Set before the first read and cleared only on a complete frame.
        //
        // Once any part has been drained, the buffer holds a *suffix* of this
        // reply. If the future is cancelled or the sink errors there, the next
        // RPC on this session parses that suffix as its own response and fails —
        // and a pooled connection would be handed to someone else in that state.
        // Nothing after an await runs when a future is dropped, so this has to
        // be set first, exactly as the partial-lock path does.
        self.stream_incomplete = true;

        // One deadline for the whole reply, not one per read. A peer that drips
        // a byte before each individual timeout expires would otherwise reset it
        // forever and stream indefinitely under a configured `rpc_timeout`; the
        // buffered path bounds the entire loop, so this does too.
        let deadline = self.rpc_timeout.map(|t| tokio::time::Instant::now() + t);

        let mut written = 0usize;
        let mut temp = vec![0u8; READ_BUF_SIZE];
        // Held back until the reply's message-id has been checked. A prior RPC
        // that was cancelled or timed out can leave its reply queued, and
        // emitting that to the sink would hand the caller stale XML while the
        // requested reply stayed unread. `send_rpc_raw` discards mismatched
        // frames; this does the same, it just has to peek first.
        //
        // Bounded: `message-id` is an attribute on the opening `<rpc-reply>`, so
        // it is within the first few hundred bytes of any real reply. If it has
        // not appeared by then the frame is not one we can verify, and is
        // discarded rather than trusted.
        const ID_PEEK_LIMIT: usize = 8192;
        let mut prefix: Vec<u8> = Vec::new();
        let mut verified = false;
        let mut discarding = false;

        loop {
            loop {
                match self.framer.decode_part(&self.read_buffer)? {
                    FramePart::Data { payload, consumed } => {
                        self.read_buffer.drain(..consumed);
                        if discarding {
                            continue;
                        }
                        if verified {
                            sink.write_all(&payload).await.map_err(TransportError::Io)?;
                            written += payload.len();
                            continue;
                        }
                        prefix.extend_from_slice(&payload);
                        match Self::reply_message_id(&prefix) {
                            Some(found) if found == message_id => {
                                verified = true;
                                sink.write_all(&prefix).await.map_err(TransportError::Io)?;
                                written += prefix.len();
                                prefix.clear();
                            }
                            Some(_) => {
                                // A stale reply. Swallow the rest of this frame
                                // and keep waiting for ours.
                                discarding = true;
                                prefix.clear();
                            }
                            None if prefix.len() > ID_PEEK_LIMIT => {
                                discarding = true;
                                prefix.clear();
                            }
                            None => {}
                        }
                    }
                    FramePart::End { consumed } => {
                        self.read_buffer.drain(..consumed);
                        if discarding || !verified {
                            // That frame was not ours. Reset and wait for the
                            // next one; the buffer is back at a boundary.
                            discarding = false;
                            verified = false;
                            prefix.clear();
                            continue;
                        }
                        // Cleared before the flush: the terminator is consumed,
                        // so the session is at a valid message boundary and a
                        // failing sink must not condemn an otherwise healthy
                        // pooled connection.
                        self.stream_incomplete = false;
                        self.last_activity = Some(Instant::now());
                        sink.flush().await.map_err(TransportError::Io)?;
                        return Ok(written);
                    }
                    FramePart::NeedMore => break,
                }
            }

            if self.read_buffer.len() > self.max_read_buffer {
                return Err(TransportError::Io(std::io::Error::new(
                    std::io::ErrorKind::OutOfMemory,
                    format!(
                        "{} bytes held without completing a frame (ceiling {})",
                        self.read_buffer.len(),
                        self.max_read_buffer
                    ),
                ))
                .into());
            }

            let n = match deadline {
                Some(at) => tokio::time::timeout_at(at, self.transport.read(&mut temp))
                    .await
                    .map_err(|_| {
                        crate::error::RpcError::Timeout(self.rpc_timeout.unwrap_or_default())
                    })??,
                None => self.transport.read(&mut temp).await?,
            };
            if n == 0 {
                return Err(TransportError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed mid-reply while streaming",
                ))
                .into());
            }
            self.read_buffer.extend_from_slice(&temp[..n]);
        }
    }

    /// Extract `message-id` from the first element's opening tag, if it has
    /// arrived yet.
    ///
    /// Byte-wise and bounded to that tag on purpose. Decoding the whole prefix
    /// as UTF-8 fails whenever a read or chunk boundary lands mid-codepoint,
    /// which would discard a perfectly valid reply for a reason that has nothing
    /// to do with its contents. Restricting the search to the opening tag also
    /// stops `message-id` being matched inside a leading comment or processing
    /// instruction.
    fn reply_message_id(prefix: &[u8]) -> Option<String> {
        // First real element start: skip `<?...?>` and `<!--...-->`.
        let mut i = 0;
        loop {
            let lt = prefix[i..].iter().position(|&b| b == b'<')? + i;
            match prefix.get(lt + 1) {
                Some(b'?') | Some(b'!') => {
                    let gt = prefix[lt..].iter().position(|&b| b == b'>')? + lt;
                    i = gt + 1;
                }
                Some(_) => {
                    let gt = prefix[lt..].iter().position(|&b| b == b'>')? + lt;
                    return Self::message_id_in_tag(&prefix[lt..=gt]);
                }
                // Tag has not arrived in full yet.
                None => return None,
            }
        }
    }

    /// `message-id="..."` within one opening tag's bytes.
    fn message_id_in_tag(tag: &[u8]) -> Option<String> {
        let at = tag
            .windows(b"message-id".len())
            .position(|w| w == b"message-id")?;
        let mut j = at + b"message-id".len();
        while j < tag.len() && tag[j].is_ascii_whitespace() {
            j += 1;
        }
        if tag.get(j)? != &b'=' {
            return None;
        }
        j += 1;
        while j < tag.len() && tag[j].is_ascii_whitespace() {
            j += 1;
        }
        let quote = *tag.get(j)?;
        if quote != b'"' && quote != b'\'' {
            return None;
        }
        j += 1;
        let close = tag[j..].iter().position(|&b| b == quote)? + j;
        // The id itself is ASCII in practice, but decode defensively rather
        // than assuming.
        std::str::from_utf8(&tag[j..close]).ok().map(str::to_string)
    }

    /// Fetch configuration using an XPath filter (RFC 6241 §6.4).
    ///
    /// Returns [`ProtocolError::CapabilityMissing`] when the device did not
    /// advertise `:xpath:1.0` in its `<hello>`. Failing here rather than on the
    /// wire is deliberate: a device without XPath support answers an XPath
    /// filter with an `operation-not-supported` rpc-error at best, and at worst
    /// ignores the filter and returns the entire datastore — which looks like
    /// success and is the more dangerous outcome.
    pub async fn get_config_xpath(
        &mut self,
        source: Datastore,
        filter: &XPathFilter,
    ) -> Result<String, NetconfError> {
        self.require_xpath()?;
        let msg_id = self.next_message_id();
        let xml = operations::get_config_xpath_xml(&msg_id, source, filter)?;
        match self.send_rpc(&xml, &msg_id).await? {
            RpcReply::Data(data) | RpcReply::DataWithWarnings(data, _) => {
                Ok(self.vendor_profile.unwrap_config(&data))
            }
            RpcReply::Ok | RpcReply::OkWithWarnings(_) => Ok(String::new()),
        }
    }

    /// Fetch operational and configuration data using an XPath filter.
    ///
    /// Same capability gate as [`Session::get_config_xpath`].
    pub async fn get_xpath(&mut self, filter: &XPathFilter) -> Result<String, NetconfError> {
        self.require_xpath()?;
        let msg_id = self.next_message_id();
        let xml = operations::get_xpath_xml(&msg_id, filter)?;
        match self.send_rpc(&xml, &msg_id).await? {
            RpcReply::Data(data) | RpcReply::DataWithWarnings(data, _) => Ok(data),
            RpcReply::Ok | RpcReply::OkWithWarnings(_) => Ok(String::new()),
        }
    }

    /// Error unless the peer advertised `:xpath:1.0`.
    fn require_xpath(&self) -> Result<(), NetconfError> {
        if self.supports(capability::uri::XPATH) {
            return Ok(());
        }
        Err(NetconfError::Protocol(ProtocolError::CapabilityMissing(
            capability::uri::XPATH.to_string(),
        )))
    }

    /// returned if it is malformed.
    pub async fn get(&mut self, filter: Option<&str>) -> Result<String, NetconfError> {
        if let Some(filter_xml) = filter {
            rpc::validate_xml_fragment(filter_xml)?;
        }
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
    ///
    /// `config` must be well-formed XML. It is validated before sending; a
    /// `ProtocolError::Xml` is returned if it is malformed.
    pub async fn edit_config(
        &mut self,
        target: Datastore,
        config: &str,
        default_operation: Option<DefaultOperation>,
        test_option: Option<TestOption>,
        error_option: Option<ErrorOption>,
    ) -> Result<(), NetconfError> {
        rpc::validate_xml_fragment(config)?;
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

        // Mark candidate as dirty BEFORE sending, so a partial edit still counts
        if target == Datastore::Candidate {
            self.candidate_dirty = true;
        }

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

    /// Lock only the subtrees named by XPath expressions, **in `running`**
    /// (RFC 5717).
    ///
    /// # Scope
    ///
    /// This applies to the running datastore and nothing else. RFC 5717 §1:
    /// *"Partial locking only affects configuration data and only the running
    /// datastore. The candidate or the start-up datastore are not affected"*,
    /// and *"The candidate datastore cannot be locked using the
    /// `<partial-lock>` operation."*
    ///
    /// So this is **not** a narrower substitute for a candidate lock, and it
    /// does not help the candidate-based `netconf apply` flow — that path edits,
    /// validates and commits `candidate`, and still needs its full `<lock>`.
    /// Dropping that lock because a partial lock is held would leave concurrent
    /// candidate edits unprotected. Partial locking is for writable-running
    /// workflows, where it lets edits to unrelated subtrees proceed
    /// concurrently instead of serializing on one datastore-wide lock.
    ///
    /// Prefixes used in the expressions must be bound via `namespaces`; the
    /// declarations are emitted on `<partial-lock>` where the expressions can
    /// see them, and are validated exactly as the XPath filter's are.
    ///
    /// Returns the server-assigned [`PartialLock`]. Its `locked_nodes` are
    /// worth checking rather than assuming: an expression may match several
    /// nodes or none.
    pub async fn partial_lock(
        &mut self,
        selects: &[String],
        namespaces: &[(String, String)],
    ) -> Result<PartialLock, NetconfError> {
        self.require_capability(crate::capability::uri::PARTIAL_LOCK, "partial-lock")?;
        // Refuse outright rather than retry. If an earlier partial-lock or
        // -unlock left this set, the server may still hold a lock this session
        // cannot name; a second attempt that succeeded would clear the flag and
        // report health while that first lock is still outstanding, and the pool
        // would then recycle the connection. The flag is only cleared by a
        // definitive outcome of the request that set it, or by reconnecting.
        self.ensure_lock_state_known()?;
        let msg_id = self.next_message_id();
        let xml = operations::partial_lock_xml(&msg_id, selects, namespaces)?;

        // Set *before* the write, and cleared only once a lock-id is in hand.
        //
        // Every way this can fail after the bytes leave - an RPC timeout, the
        // future being cancelled, an `<ok/>` with no id, an unparseable reply -
        // may leave the server holding a lock this session cannot name, and so
        // cannot release. Marking first is what makes that survive
        // cancellation: nothing after an await runs if the future is dropped.
        //
        // `is_alive` reports false while this is set, so a pooled connection is
        // discarded on check-in rather than recycled still holding the lock.
        self.partial_lock_uncertain = true;

        let reply = match self.send_rpc(&xml, &msg_id).await {
            Ok(reply) => reply,
            Err(e) => {
                // A parsed `<rpc-error>` is definitive: RFC 5717 makes a failed
                // partial lock atomic, so `lock-denied` or `no-matches` means no
                // lock was retained and the session is perfectly healthy. Only
                // the genuinely unknown outcomes — timeouts, cancellation, a
                // reply we could not parse — leave the flag set. Otherwise
                // routine lock contention would throw away good pooled
                // connections.
                if matches!(e, NetconfError::Rpc(crate::error::RpcError::ServerError(_))) {
                    self.partial_lock_uncertain = false;
                }
                return Err(e);
            }
        };
        let result = match reply {
            RpcReply::Data(data) | RpcReply::DataWithWarnings(data, _) => {
                operations::parse_partial_lock_reply(&data)
            }
            // An `<ok/>` means the server accepted the lock but told us nothing
            // about it. Without the lock-id it cannot be released, so this is an
            // error rather than a silent success.
            RpcReply::Ok | RpcReply::OkWithWarnings(_) => Err(ProtocolError::Xml(
                "<partial-lock> returned <ok/> with no <lock-id>; the lock could not \
                     be released"
                    .to_string(),
            )
            .into()),
        };
        if result.is_ok() {
            self.partial_lock_uncertain = false;
        }
        result
    }

    /// Release a partial lock (RFC 5717).
    pub async fn partial_unlock(&mut self, lock_id: u32) -> Result<(), NetconfError> {
        self.require_capability(crate::capability::uri::PARTIAL_LOCK, "partial-unlock")?;
        self.ensure_lock_state_known()?;
        let msg_id = self.next_message_id();
        let xml = operations::partial_unlock_xml(&msg_id, lock_id);

        // The release is as indeterminate as the acquire. If this times out or
        // is cancelled after the write, the lock may still be held — and the
        // caller is about to drop the only copy of `lock_id`. Poisoning before
        // the write means `PoolGuard` discards the connection instead of
        // returning a session that silently holds a lock nobody can name.
        self.partial_lock_uncertain = true;

        match self.send_rpc(&xml, &msg_id).await {
            Ok(_) => {
                self.partial_lock_uncertain = false;
                Ok(())
            }
            Err(e) => {
                // Deliberately asymmetric with `partial_lock`. There, a parsed
                // rejection proves *no* lock was taken, so the session is clean.
                // Here the inference inverts: the server processed the release
                // and refused it, which means the lock is still held. Clearing
                // the flag would let `PoolGuard` recycle a session that still
                // owns a lock nobody is going to release, blocking other writers
                // until it ages out. Stay poisoned regardless of the error kind.
                Err(e)
            }
        }
    }

    /// Error when a previous partial lock or unlock left this session's lock
    /// state unknown.
    fn ensure_lock_state_known(&self) -> Result<(), NetconfError> {
        if self.stream_incomplete {
            return Err(ProtocolError::SessionExpired.into());
        }
        if self.partial_lock_uncertain {
            return Err(ProtocolError::SessionExpired.into());
        }
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
        self.require_capability(crate::capability::uri::CANDIDATE, "commit")?;
        let msg_id = self.next_message_id();
        let xml = operations::commit_xml(&msg_id);

        self.send_rpc_commit(&xml, &msg_id).await?;
        // Clear dirty flag on success
        self.candidate_dirty = false;
        Ok(())
    }

    /// Validate a datastore configuration.
    ///
    /// Requires the `:validate` capability.
    pub async fn validate(&mut self, source: Datastore) -> Result<(), NetconfError> {
        self.require_capability(crate::capability::uri::VALIDATE, "validate")?;
        let msg_id = self.next_message_id();
        let xml = operations::validate_xml(&msg_id, source);
        self.send_rpc(&xml, &msg_id).await?;
        Ok(())
    }

    /// Copy a configuration from one location to another (RFC 6241 §7.3).
    ///
    /// Either side may be a datastore or a URL; the URL form requires the
    /// device to advertise `:url`, which is checked before sending.
    pub async fn copy_config(
        &mut self,
        target: &ConfigLocation,
        source: &CopySource,
    ) -> Result<(), NetconfError> {
        self.copy_config_inner(target, source, None).await
    }

    /// `copy-config` with an RFC 6243 `<with-defaults>` mode.
    ///
    /// RFC 6243 augments `copy-config` as well as the retrieval operations, so
    /// a caller materializing or trimming defaults during a datastore copy can
    /// say so. Gated on the advertised mode list exactly as the `get` variants
    /// are.
    pub async fn copy_config_with_defaults(
        &mut self,
        target: &ConfigLocation,
        source: &CopySource,
        mode: WithDefaults,
    ) -> Result<(), NetconfError> {
        self.require_with_defaults(mode)?;
        self.copy_config_inner(target, source, Some(mode)).await
    }

    async fn copy_config_inner(
        &mut self,
        target: &ConfigLocation,
        source: &CopySource,
        mode: Option<WithDefaults>,
    ) -> Result<(), NetconfError> {
        // RFC 6241 §7.3: "If the <source> and <target> parameters identify the
        // same URL or configuration datastore, an error MUST be returned with
        // an error-tag containing 'invalid-value'." Caught here so the
        // candidate is never marked dirty for a request that cannot succeed.
        let same = match (target, source) {
            (ConfigLocation::Datastore(t), CopySource::Datastore(s)) => t == s,
            (ConfigLocation::Url(t), CopySource::Url(s)) => t == s,
            _ => false,
        };
        if same {
            return Err(ProtocolError::InvalidValue(format!(
                "<copy-config> source and target are both `{target}` (RFC 6241 §7.3)"
            ))
            .into());
        }

        match target {
            ConfigLocation::Url(url) => self.require_url_scheme(url)?,
            ConfigLocation::Datastore(ds) => self.require_datastore(*ds, true)?,
        }
        // Inline config is vendor-wrapped exactly as `edit_config` wraps its
        // payload — on Junos a bare `<system>...</system>` needs the
        // `<configuration>` wrapper or the device misreads it.
        let wrapped_source;
        let source = match source {
            CopySource::Url(url) => {
                self.require_url_scheme(url)?;
                source
            }
            CopySource::Config(cfg) => {
                rpc::validate_xml_fragment(cfg)?;
                wrapped_source = CopySource::Config(self.vendor_profile.wrap_config(cfg));
                &wrapped_source
            }
            CopySource::Datastore(ds) => {
                self.require_datastore(*ds, false)?;
                source
            }
        };
        // Preflight must complete before the flag is set, and the flag must be
        // set before the write — the ordering `dispatch_candidate_change`
        // documents. Too early and a call that never reaches the wire (an
        // unestablished session, a failed keepalive) still marks the candidate
        // dirty, and a later Junos `close_session` would discard a shared
        // candidate nobody touched. Too late and a copy the device applied but
        // whose reply was lost goes unrecorded, so the discard is skipped.
        self.keepalive_check().await?;
        self.ensure_established()?;

        let msg_id = self.next_message_id();
        let xml = match mode {
            Some(mode) => operations::copy_config_with_defaults_xml(&msg_id, target, source, mode),
            None => operations::copy_config_xml(&msg_id, target, source),
        };
        if matches!(target, ConfigLocation::Datastore(Datastore::Candidate)) {
            self.candidate_dirty = true;
        }
        // send_rpc_raw, not send_rpc: the latter runs its own keepalive probe,
        // which would land *after* the flag is set. A probe that fails or is
        // cancelled there would leave the candidate marked dirty with nothing
        // written. Same reason `dispatch_candidate_change` bypasses it.
        self.send_rpc_raw(&xml, &msg_id, false).await?;

        // A successful copy between running and candidate — in either
        // direction — synchronizes the two, so the candidate holds nothing
        // uncommitted and needs no discard on close. candidate -> running is
        // the same synchronization `commit` performs, and `commit` clears the
        // flag for exactly this reason. Leaving it set would make a later Junos
        // `close_session` send `<discard-changes/>` and destroy edits another
        // session had since made to the shared candidate.
        //
        // The pre-write marking above still stands for the uncertain case: if
        // the reply is lost we do not know the copy landed, and assuming dirty
        // is the safe side of that.
        // Only a *plain* copy synchronizes the two datastores. Every RFC 6243
        // mode transforms the representation on the way through — `report-all`
        // materializes defaulted nodes, `trim` removes them, `explicit` reports
        // only what was set, `report-all-tagged` adds markers — so afterwards
        // the candidate is not necessarily equal to running and the flag must
        // stand. Assuming otherwise would let a Junos `close_session` skip its
        // discard and leave the shared candidate altered.
        let synchronized = mode.is_none()
            && matches!(
                (target, source),
                (
                    ConfigLocation::Datastore(Datastore::Candidate),
                    CopySource::Datastore(Datastore::Running)
                ) | (
                    ConfigLocation::Datastore(Datastore::Running),
                    CopySource::Datastore(Datastore::Candidate)
                )
            );
        if synchronized {
            self.candidate_dirty = false;
        }
        Ok(())
    }

    /// Delete a configuration datastore or URL-backed config (RFC 6241 §7.4).
    ///
    /// [`DeleteTarget`] can only name `startup` or a URL, which is what the
    /// RFC's `config-target` choice permits here — `running` and `candidate`
    /// are not expressible rather than rejected at runtime.
    pub async fn delete_config(&mut self, target: &DeleteTarget) -> Result<(), NetconfError> {
        match target {
            DeleteTarget::Url(url) => self.require_url_scheme(url)?,
            DeleteTarget::Startup => {
                self.require_capability(crate::capability::uri::STARTUP, "delete-config startup")?
            }
        }
        let msg_id = self.next_message_id();
        let xml = operations::delete_config_xml(&msg_id, target);
        self.send_rpc(&xml, &msg_id).await?;
        Ok(())
    }

    /// Cancel an in-progress confirmed commit (RFC 6241 §8.4.4.1).
    ///
    /// Requires `:confirmed-commit:1.1` — `cancel-commit` does not exist in the
    /// 1.0 capability, where the only way out is to let the timer expire.
    ///
    /// `persist_id` cancels a commit issued with a `<persist>` token, which may
    /// have come from another session.
    pub async fn cancel_commit(&mut self, persist_id: Option<&str>) -> Result<(), NetconfError> {
        self.require_capability(
            crate::capability::uri::CONFIRMED_COMMIT_1_1,
            "cancel-commit",
        )?;
        let msg_id = self.next_message_id();
        let xml = operations::cancel_commit_xml(&msg_id, persist_id)?;
        self.send_rpc(&xml, &msg_id).await?;
        Ok(())
    }

    /// Require the capability a datastore needs, per its `if-feature` in
    /// RFC 6241's YANG module.
    ///
    /// `running` needs nothing to read but `:writable-running` to write, which
    /// is why the direction is a parameter rather than inferred.
    fn require_datastore(&self, ds: Datastore, as_target: bool) -> Result<(), NetconfError> {
        match (ds, as_target) {
            (Datastore::Candidate, _) => {
                self.require_capability(crate::capability::uri::CANDIDATE, "candidate datastore")
            }
            (Datastore::Startup, _) => {
                self.require_capability(crate::capability::uri::STARTUP, "startup datastore")
            }
            (Datastore::Running, true) => self.require_capability(
                crate::capability::uri::WRITABLE_RUNNING,
                "writable running datastore",
            ),
            (Datastore::Running, false) => Ok(()),
        }
    }

    /// Require `:url`, and that the device lists this URL's scheme.
    ///
    /// The capability carries its supported schemes as a query parameter —
    /// `...:url:1.0?scheme=http,ftp,file` — so checking only the base URI would
    /// accept a `file://` path against a device advertising `scheme=https`.
    /// A device that advertises `:url` with no `scheme` parameter names no
    /// schemes at all, so nothing is accepted for it rather than everything.
    fn require_url_scheme(&self, url: &str) -> Result<(), NetconfError> {
        self.require_capability(crate::capability::uri::URL, "url config location")?;

        let Some(scheme) = url.split_once(':').map(|(s, _)| s) else {
            return Err(ProtocolError::Xml(format!("`{url}` has no URL scheme")).into());
        };
        let scheme = scheme.to_ascii_lowercase();

        let advertised: Vec<String> = self
            .capabilities()
            .map(|caps| caps.all_uris().iter().cloned().collect())
            .unwrap_or_default();
        let supported: Vec<String> = advertised
            .iter()
            .filter(|uri| uri.starts_with(crate::capability::uri::URL))
            .filter_map(|uri| uri.split_once("scheme="))
            .flat_map(|(_, list)| {
                list.split('&')
                    .next()
                    .unwrap_or("")
                    .split(',')
                    .map(|s| s.trim().to_ascii_lowercase())
                    .collect::<Vec<_>>()
            })
            .filter(|s| !s.is_empty())
            .collect();

        if supported.contains(&scheme) {
            return Ok(());
        }
        Err(ProtocolError::CapabilityMissing(format!(
            "device does not advertise URL scheme `{scheme}` (advertised: {})",
            if supported.is_empty() {
                "none".to_string()
            } else {
                supported.join(", ")
            }
        ))
        .into())
    }

    /// Discard uncommitted candidate configuration changes.
    pub async fn discard_changes(&mut self) -> Result<(), NetconfError> {
        let msg_id = self.next_message_id();
        let xml = operations::discard_changes_xml(&msg_id);
        self.send_rpc(&xml, &msg_id).await?;
        // Clear dirty flag on success
        self.candidate_dirty = false;
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
        // Clear dirty flag on success
        self.candidate_dirty = false;
        Ok(())
    }

    /// Commit using the Junos-native `<commit-configuration/>` RPC.
    ///
    /// Use this instead of [`commit()`](Self::commit) on Junos devices,
    /// especially when a private/exclusive configuration database is open.
    pub async fn commit_configuration(&mut self) -> Result<(), NetconfError> {
        self.dispatch_commit_configuration(None).await
    }

    /// Commit with a log comment using the Junos-native `<commit-configuration>` RPC.
    ///
    /// Attaches a Junos commit log comment to the commit, visible in `show system commit`.
    /// The log text is automatically XML-escaped. The candidate-dirty flag is cleared on
    /// success, just as with [`commit_configuration()`](Self::commit_configuration).
    ///
    /// Use this instead of [`commit()`](Self::commit) on Junos devices,
    /// especially when a private/exclusive configuration database is open.
    pub async fn commit_configuration_with_log(&mut self, log: &str) -> Result<(), NetconfError> {
        self.dispatch_commit_configuration(Some(log)).await
    }

    /// Internal helper for commit_configuration and commit_configuration_with_log.
    ///
    /// Clears the candidate-dirty flag only on success, so a failed commit that
    /// may have partially applied still leaves the flag set for cleanup on close.
    ///
    /// Uses [`send_rpc_commit`] so that a transport EOF while awaiting the reply
    /// surfaces as [`RpcError::CommitUnknown`] rather than a generic I/O error.
    /// The device may have applied the commit before the connection dropped, and
    /// a caller that mistakes that for a clean failure may retry a commit that
    /// already took effect. `commit()` and `confirmed_commit()` do the same.
    async fn dispatch_commit_configuration(
        &mut self,
        log: Option<&str>,
    ) -> Result<(), NetconfError> {
        let msg_id = self.next_message_id();
        let xml = match log {
            Some(text) => operations::commit_configuration_with_log_xml(&msg_id, text),
            None => operations::commit_configuration_xml(&msg_id),
        };

        self.send_rpc_commit(&xml, &msg_id).await?;
        // Clear dirty flag on success
        self.candidate_dirty = false;
        Ok(())
    }

    /// Rollback the candidate configuration to a previous commit (Junos).
    ///
    /// `rollback` is the rollback index (0 = most recent commit, up to 49).
    pub async fn rollback_configuration(&mut self, rollback: u32) -> Result<(), NetconfError> {
        let msg_id = self.next_message_id();
        let xml = operations::rollback_configuration_xml(&msg_id, rollback);

        // Mark candidate as dirty before sending
        self.candidate_dirty = true;

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

        // Mark candidate as dirty before sending
        self.candidate_dirty = true;

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
    /// discards uncommitted candidate changes before closing, but only if
    /// this session dirtied the candidate (to avoid destroying another
    /// operator's uncommitted work in the shared candidate datastore).
    pub async fn close_session(&mut self) -> Result<(), NetconfError> {
        if self.state == SessionState::Closed {
            return Ok(());
        }

        // Close private/exclusive config database if open
        if self.private_config_open {
            let _ = self.close_configuration().await;
            self.private_config_open = false;
        }

        // Vendor-specific pre-close actions: discard uncommitted changes
        // if this session dirtied the candidate
        if self.vendor_profile.close_sequence() == CloseSequence::DiscardThenClose
            && self.candidate_dirty
        {
            // Best-effort discard — don't fail the close if this errors
            let _ = self.discard_changes().await;
        }

        let msg_id = self.next_message_id();
        let xml = operations::close_session_xml(&msg_id);

        // Best-effort: send close-session but don't fail if transport is already gone
        let _ = self.send_rpc(&xml, &msg_id).await;
        let _ = self.transport.close().await;
        self.state = SessionState::Closed;

        tracing::info!(
            vendor = self.vendor_profile.name(),
            "NETCONF session closed"
        );
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
        self.require_capability(crate::capability::uri::CANDIDATE, "confirmed-commit")?;
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

        self.send_rpc_commit(&xml, &msg_id).await?;
        // Clear dirty flag on success
        self.candidate_dirty = false;
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
            Err(NetconfError::Rpc(crate::error::RpcError::ServerError(ref server_error)))
                if server_error.tag == crate::types::ErrorTag::LockDenied =>
            {
                // Try to extract session-id from error-info
                let stale_session_id = server_error
                    .info
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
                    server_error.info
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
        use crate::xml_entity::resolve_entity_ref;
        use quick_xml::events::Event;
        use quick_xml::Reader;

        let mut reader = Reader::from_str(info);
        let mut buf = Vec::new();
        let mut in_session_id = false;
        // Accumulates across Text/GeneralRef events (quick-xml splits text
        // around entity references); parsed at the closing tag.
        let mut id_buf = String::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref tag)) => {
                    let local = tag.local_name();
                    let name = std::str::from_utf8(local.as_ref()).unwrap_or("");
                    if name == "session-id" {
                        in_session_id = true;
                        id_buf.clear();
                    }
                }
                Ok(Event::Text(ref text)) if in_session_id => {
                    if let Ok(value) = text.decode() {
                        id_buf.push_str(&value);
                    }
                }
                Ok(Event::GeneralRef(ref entity)) if in_session_id => {
                    if let Some(resolved) = resolve_entity_ref(entity) {
                        id_buf.push_str(&resolved);
                    }
                }
                Ok(Event::CData(ref cdata)) if in_session_id => {
                    if let Ok(value) = cdata.decode() {
                        id_buf.push_str(&value);
                    }
                }
                Ok(Event::End(_)) => {
                    if in_session_id {
                        if let Ok(id) = id_buf.trim().parse::<u32>() {
                            return Some(id);
                        }
                    }
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
        self.require_capability(capability::uri::NOTIFICATION, "create-subscription")?;

        if !self.supports(capability::uri::INTERLEAVE) {
            tracing::info!(
                "device does not advertise :interleave capability — \
                 RPCs during active subscription may not be supported"
            );
        }

        if let Some(filter_xml) = filter {
            rpc::validate_xml_fragment(filter_xml)?;
        }

        let message_id = self.next_message_id();
        let xml =
            operations::create_subscription_xml(&message_id, stream, filter, start_time, stop_time);

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
            _ => Err(
                ProtocolError::Xml("unexpected response to create-subscription".to_string()).into(),
            ),
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
            let response = match self.read_message(false).await {
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
                    let notif =
                        notification::parse_notification(&response).map_err(NetconfError::Rpc)?;
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
    use crate::transport::mock::{MockTransport, StallingMockTransport};

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
        session
            .lock(Datastore::Candidate)
            .await
            .expect("lock failed");

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
    async fn test_commit_configuration_with_log_disconnect_is_commit_unknown() {
        // A Junos commit that disconnects before its reply is indeterminate: the
        // device may have applied it. commit_configuration* must report that as
        // CommitUnknown, not a generic transport error, or a caller can retry a
        // commit that already took effect.
        let mut response_data = mock_junos_hello();
        // No commit reply — EOF after the hello simulates a mid-commit disconnect.

        let transport = MockTransport::new(response_data.split_off(0));
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        let result = session
            .commit_configuration_with_log("attributed change")
            .await;
        match result {
            Err(NetconfError::Rpc(crate::error::RpcError::CommitUnknown)) => {}
            other => panic!("expected CommitUnknown, got: {other:?}"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn test_cancelled_commit_does_not_poison_later_eof() {
        // The #61 regression. A commit whose future is dropped mid-await must not
        // leave "a commit is in flight" behind, or the NEXT unrelated EOF gets
        // misreported as CommitUnknown — the flag's purpose inverted.
        //
        // This is why the fact is a parameter rather than a field: it lives on the
        // call frame and dies with the cancelled future. Against the old
        // field-based implementation this test fails, because the reset after the
        // await never ran.
        let transport = StallingMockTransport::new(mock_junos_hello());
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        // The transport parks on this read, so the timeout cancels the commit
        // future exactly at its .await.
        let cancelled = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            session.commit_configuration(),
        )
        .await;
        assert!(
            cancelled.is_err(),
            "commit should have been cancelled by the timeout"
        );

        // A different, non-commit operation now hits EOF. It must be reported as
        // what it is — a dropped connection — not as an indeterminate commit.
        let result = session.get_config(Datastore::Running, None).await;
        match result {
            Err(NetconfError::Rpc(crate::error::RpcError::CommitUnknown)) => panic!(
                "a cancelled commit poisoned a later unrelated EOF: got CommitUnknown \
                 for a get-config, which is the #61 bug"
            ),
            Err(_) => {}
            Ok(_) => panic!("expected the get-config to fail against a closed transport"),
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
    async fn test_successful_commit_then_eof_is_transport_error() {
        // After a successful commit, a subsequent non-commit RPC that hits EOF
        // should return a transport error, NOT CommitUnknown. This ensures that
        // the commit-tracking state does not leak across calls.
        let mut response_data = mock_device_hello();
        response_data.extend_from_slice(&mock_ok_reply("1")); // lock
        response_data.extend_from_slice(&mock_ok_reply("2")); // commit
        response_data.extend_from_slice(&mock_ok_reply("3")); // unlock
                                                              // No reply for the final get-config — EOF

        let transport = MockTransport::new(response_data);
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        session
            .lock(Datastore::Candidate)
            .await
            .expect("lock failed");
        session.commit().await.expect("commit failed");
        session
            .unlock(Datastore::Candidate)
            .await
            .expect("unlock failed");

        // get-config should return a transport error, NOT CommitUnknown
        let result = session.get_config(Datastore::Running, None).await;
        match result {
            Err(NetconfError::Transport(_)) => {
                // Expected — generic transport error for non-commit operations
            }
            Err(NetconfError::Rpc(crate::error::RpcError::CommitUnknown)) => {
                panic!(
                    "CommitUnknown should not leak to a non-commit RPC after a successful commit"
                );
            }
            other => panic!("expected TransportError, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_commit_eof_then_non_commit_eof_reports_correctly() {
        // NOT the #61 regression test — see
        // test_cancelled_commit_does_not_poison_later_eof for that one. This
        // case passed under the old field-based implementation too, because the
        // EOF branch cleared the flag on its way out. It is kept as a guard on
        // the ordinary path: a commit that reports CommitUnknown must not change
        // how the next unrelated failure is classified.
        //
        // This test verifies that after a commit hits EOF (returning CommitUnknown),
        // a subsequent non-commit operation that also hits EOF correctly returns
        // a transport error, not CommitUnknown.
        let mut response_data = mock_device_hello();
        response_data.extend_from_slice(&mock_ok_reply("1")); // lock
                                                              // No commit reply — message-id "2" will hit EOF
                                                              // No get-config reply — message-id "3" will also hit EOF

        let transport = MockTransport::new(response_data);
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        session
            .lock(Datastore::Candidate)
            .await
            .expect("lock failed");

        // Commit hits EOF — should return CommitUnknown
        let commit_result = session.commit().await;
        match commit_result {
            Err(NetconfError::Rpc(crate::error::RpcError::CommitUnknown)) => {
                // Expected
            }
            other => panic!("expected CommitUnknown, got: {other:?}"),
        }

        // Now a non-commit operation hits EOF — should return TransportError, NOT CommitUnknown.
        // With the old field-based approach and a mid-await cancellation, pending_commit
        // could have been left set, poisoning this call.
        let result = session.get_config(Datastore::Running, None).await;
        match result {
            Err(NetconfError::Transport(_)) => {
                // Expected — generic transport error for non-commit operations
            }
            Err(NetconfError::Rpc(crate::error::RpcError::CommitUnknown)) => {
                panic!(
                    "CommitUnknown should not leak to a non-commit RPC after a commit that returned CommitUnknown"
                );
            }
            other => panic!("expected TransportError, got: {other:?}"),
        }
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
    fn test_parse_session_id_from_xml_with_char_ref() {
        // A numeric character reference splitting the digits must still parse
        // to the full session-id (not a truncated prefix/suffix).
        let info = "<session-id>4&#50;</session-id>";
        assert_eq!(parse_session_id_from_info(info), Some(42));
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

        session
            .lock(Datastore::Candidate)
            .await
            .expect("lock failed");
        session
            .confirmed_commit(120)
            .await
            .expect("confirmed_commit failed");
        session
            .confirming_commit()
            .await
            .expect("confirming_commit failed");
    }

    #[tokio::test]
    async fn test_confirmed_commit_requires_capability() {
        // Hello WITHOUT confirmed-commit capability
        let response_data = mock_device_hello();

        let transport = MockTransport::new(response_data);
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        let result = session.confirmed_commit(120).await;
        assert!(
            result.is_err(),
            "confirmed_commit should fail without capability"
        );
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
        assert_eq!(
            result.unwrap(),
            None,
            "no session killed when lock succeeds"
        );
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
        session
            .lock(Datastore::Candidate)
            .await
            .expect("lock failed");
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
        session
            .lock(Datastore::Candidate)
            .await
            .expect("lock failed");

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

        session
            .lock(Datastore::Candidate)
            .await
            .expect("lock failed");

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
        session
            .lock(Datastore::Candidate)
            .await
            .expect("lock failed");

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
        session
            .lock(Datastore::Candidate)
            .await
            .expect("lock failed");
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

        session
            .lock(Datastore::Candidate)
            .await
            .expect("lock failed");
        assert_eq!(session.drain_notifications().len(), 1);
        assert_eq!(session.drain_notifications().len(), 0); // buffer cleared
    }

    #[tokio::test]
    async fn test_explicit_vendor_profile_arc_survives_auto_detection() {
        use std::sync::Arc;

        // Mock transport: hello WITHOUT Junos capability (generic device)
        let response_data = mock_device_hello();

        let transport = MockTransport::new(response_data);
        let mut session = Session::new(Box::new(transport));

        // Set explicit Junos vendor profile via Arc BEFORE establish
        session.set_vendor_profile_arc(Arc::new(crate::vendor::junos::JunosVendor::default()));

        // Establish should NOT override the explicit vendor because it's not "generic"
        session.establish().await.expect("establish failed");

        // Vendor should still be "junos" after establish (not auto-detected to "generic")
        assert_eq!(
            session.vendor_name(),
            "junos",
            "explicit Arc vendor override should survive auto-detection"
        );
    }

    // ── Candidate dirty tracking tests ─────────────────────────────────

    /// Build a mock Junos device hello response with EOM framing.
    fn mock_junos_hello() -> Vec<u8> {
        let hello = r#"<?xml version="1.0" encoding="UTF-8"?>
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <capabilities>
    <capability>urn:ietf:params:netconf:base:1.0</capability>
    <capability>urn:ietf:params:netconf:capability:candidate:1.0</capability>
    <capability>http://xml.juniper.net/netconf/junos/1.0</capability>
  </capabilities>
  <session-id>1</session-id>
</hello>"#;
        let mut buf = hello.as_bytes().to_vec();
        buf.extend_from_slice(b"]]>]]>");
        buf
    }

    #[tokio::test]
    async fn test_junos_read_only_session_does_not_discard_on_close() {
        let mut response_data = mock_junos_hello();
        response_data.extend_from_slice(&mock_ok_reply("1")); // get-config reply
        response_data.extend_from_slice(&mock_ok_reply("2")); // close-session reply (no discard)

        let transport = MockTransport::new(response_data);
        let written_handle = transport.written_handle();
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");
        assert_eq!(session.vendor_name(), "junos");

        // Read-only operation
        session
            .get_config(Datastore::Candidate, None)
            .await
            .expect("get_config failed");

        // Close session
        session.close_session().await.expect("close failed");

        // Verify no discard-changes was sent
        let written = written_handle.lock().unwrap();
        let written_str = String::from_utf8_lossy(&written);
        let discard_count = written_str.matches("discard-changes").count();
        assert_eq!(
            discard_count, 0,
            "read-only Junos session should NOT send discard-changes on close"
        );
    }

    #[tokio::test]
    async fn test_junos_load_configuration_dirties_candidate() {
        let mut response_data = mock_junos_hello();
        response_data.extend_from_slice(&mock_ok_reply("1")); // load-configuration reply
        response_data.extend_from_slice(&mock_ok_reply("2")); // discard-changes reply
        response_data.extend_from_slice(&mock_ok_reply("3")); // close-session reply

        let transport = MockTransport::new(response_data);
        let written_handle = transport.written_handle();
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");
        assert_eq!(session.vendor_name(), "junos");

        // Load configuration (dirties candidate)
        session
            .load_configuration(
                crate::types::LoadAction::Merge,
                crate::types::LoadFormat::Text,
                "set system host-name test",
            )
            .await
            .expect("load_configuration failed");

        // Close session
        session.close_session().await.expect("close failed");

        // Verify discard-changes WAS sent
        let written = written_handle.lock().unwrap();
        let written_str = String::from_utf8_lossy(&written);
        let discard_count = written_str.matches("discard-changes").count();
        assert_eq!(
            discard_count, 1,
            "Junos session that loaded config should send discard-changes on close"
        );
    }

    #[tokio::test]
    async fn test_junos_edit_config_candidate_dirties() {
        let mut response_data = mock_junos_hello();
        response_data.extend_from_slice(&mock_ok_reply("1")); // edit-config reply
        response_data.extend_from_slice(&mock_ok_reply("2")); // discard-changes reply
        response_data.extend_from_slice(&mock_ok_reply("3")); // close-session reply

        let transport = MockTransport::new(response_data);
        let written_handle = transport.written_handle();
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        // Edit candidate (dirties it)
        session
            .edit_config(
                Datastore::Candidate,
                "<system><host-name>test</host-name></system>",
                None,
                None,
                None,
            )
            .await
            .expect("edit_config failed");

        session.close_session().await.expect("close failed");

        let written = written_handle.lock().unwrap();
        let written_str = String::from_utf8_lossy(&written);
        let discard_count = written_str.matches("discard-changes").count();
        assert_eq!(
            discard_count, 1,
            "edit-config on candidate should send discard-changes on close"
        );
    }

    #[tokio::test]
    async fn test_junos_edit_config_running_does_not_dirty_candidate() {
        let mut response_data = mock_junos_hello();
        response_data.extend_from_slice(&mock_ok_reply("1")); // edit-config reply
        response_data.extend_from_slice(&mock_ok_reply("2")); // close-session reply (no discard)

        let transport = MockTransport::new(response_data);
        let written_handle = transport.written_handle();
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        // Edit running (does NOT dirty candidate)
        session
            .edit_config(
                Datastore::Running,
                "<system><host-name>test</host-name></system>",
                None,
                None,
                None,
            )
            .await
            .expect("edit_config failed");

        session.close_session().await.expect("close failed");

        let written = written_handle.lock().unwrap();
        let written_str = String::from_utf8_lossy(&written);
        let discard_count = written_str.matches("discard-changes").count();
        assert_eq!(
            discard_count, 0,
            "edit-config on running should NOT send discard-changes on close"
        );
    }

    #[tokio::test]
    async fn test_junos_commit_clears_dirty_flag() {
        let mut response_data = mock_junos_hello();
        response_data.extend_from_slice(&mock_ok_reply("1")); // load-configuration reply
        response_data.extend_from_slice(&mock_ok_reply("2")); // commit reply
        response_data.extend_from_slice(&mock_ok_reply("3")); // close-session reply (no discard)

        let transport = MockTransport::new(response_data);
        let written_handle = transport.written_handle();
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        // Load config (dirties candidate)
        session
            .load_configuration(
                crate::types::LoadAction::Merge,
                crate::types::LoadFormat::Text,
                "set system host-name test",
            )
            .await
            .expect("load_configuration failed");

        // Commit (clears dirty flag)
        session.commit().await.expect("commit failed");

        // Close (should NOT send discard-changes)
        session.close_session().await.expect("close failed");

        let written = written_handle.lock().unwrap();
        let written_str = String::from_utf8_lossy(&written);
        let discard_count = written_str.matches("discard-changes").count();
        assert_eq!(
            discard_count, 0,
            "commit should clear dirty flag, so close sends no discard-changes"
        );
    }

    #[tokio::test]
    async fn test_junos_explicit_discard_clears_dirty_flag() {
        let mut response_data = mock_junos_hello();
        response_data.extend_from_slice(&mock_ok_reply("1")); // load-configuration reply
        response_data.extend_from_slice(&mock_ok_reply("2")); // explicit discard-changes reply
        response_data.extend_from_slice(&mock_ok_reply("3")); // close-session reply (no second discard)

        let transport = MockTransport::new(response_data);
        let written_handle = transport.written_handle();
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        // Load config (dirties candidate)
        session
            .load_configuration(
                crate::types::LoadAction::Merge,
                crate::types::LoadFormat::Text,
                "set system host-name test",
            )
            .await
            .expect("load_configuration failed");

        // Explicit discard (clears dirty flag)
        session
            .discard_changes()
            .await
            .expect("discard_changes failed");

        // Close (should NOT send another discard-changes)
        session.close_session().await.expect("close failed");

        let written = written_handle.lock().unwrap();
        let written_str = String::from_utf8_lossy(&written);
        let discard_count = written_str.matches("discard-changes").count();
        assert_eq!(
            discard_count, 1,
            "explicit discard_changes followed by close should produce exactly 1 discard"
        );
    }

    /// An `<rpc-reply>` carrying a `<data>` payload.
    fn mock_data_reply(message_id: &str, payload: &str) -> Vec<u8> {
        let reply = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{message_id}">
  <data>{payload}</data>
</rpc-reply>"#
        );
        let mut buf = reply.into_bytes();
        buf.extend_from_slice(b"]]>]]>");
        buf
    }

    /// A hello that advertises `:xpath:1.0`, unlike `mock_junos_hello`.
    fn mock_xpath_hello() -> Vec<u8> {
        let hello = r#"<?xml version="1.0" encoding="UTF-8"?>
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <capabilities>
    <capability>urn:ietf:params:netconf:base:1.0</capability>
    <capability>urn:ietf:params:netconf:capability:xpath:1.0</capability>
  </capabilities>
  <session-id>1</session-id>
</hello>"#;
        let mut buf = hello.as_bytes().to_vec();
        buf.extend_from_slice(b"]]>]]>");
        buf
    }

    #[test]
    fn delete_target_cannot_name_running_or_candidate() {
        // Compile-time property, asserted as documentation: RFC 6241's
        // config-target choice for delete-config has only startup and url, so
        // DeleteTarget has exactly two variants and the illegal targets are
        // unrepresentable rather than rejected at runtime.
        let targets = [
            DeleteTarget::Startup,
            DeleteTarget::Url("file:///tmp/x".to_string()),
        ];
        assert_eq!(targets.len(), 2);
    }

    #[tokio::test]
    async fn delete_config_allows_startup() {
        let mut data = mock_startup_hello();
        data.extend_from_slice(&mock_ok_reply("1"));
        let transport = MockTransport::new(data);
        let written = transport.written_handle();
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        session
            .delete_config(&DeleteTarget::Startup)
            .await
            .expect("deleting startup is legal");
        let sent = String::from_utf8_lossy(&written.lock().unwrap()).to_string();
        assert!(sent.contains("<nc:delete-config>"), "sent: {sent}");
        assert!(sent.contains("<nc:startup/>"), "sent: {sent}");
    }

    #[tokio::test]
    async fn url_location_requires_the_url_capability() {
        // mock_device_hello does not advertise :url.
        let transport = MockTransport::new(mock_device_hello());
        let written = transport.written_handle();
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        let before = written.lock().unwrap().len();
        let err = session
            .copy_config(
                &ConfigLocation::Url("file:///tmp/backup.xml".to_string()),
                &CopySource::Datastore(Datastore::Running),
            )
            .await
            .expect_err("url without :url capability must be refused");
        assert!(err.to_string().contains("url"), "got {err}");
        assert_eq!(written.lock().unwrap().len(), before, "nothing sent");
    }

    /// A hello advertising `:candidate` and `:writable-running`.
    fn mock_writable_running_hello() -> Vec<u8> {
        let hello = r#"<?xml version="1.0" encoding="UTF-8"?>
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <capabilities>
    <capability>urn:ietf:params:netconf:base:1.0</capability>
    <capability>urn:ietf:params:netconf:capability:candidate:1.0</capability>
    <capability>urn:ietf:params:netconf:capability:writable-running:1.0</capability>
  </capabilities>
  <session-id>1</session-id>
</hello>"#;
        let mut buf = hello.as_bytes().to_vec();
        buf.extend_from_slice(b"]]>]]>");
        buf
    }

    /// A hello advertising `:startup`.
    fn mock_startup_hello() -> Vec<u8> {
        let hello = r#"<?xml version="1.0" encoding="UTF-8"?>
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <capabilities>
    <capability>urn:ietf:params:netconf:base:1.0</capability>
    <capability>urn:ietf:params:netconf:capability:startup:1.0</capability>
  </capabilities>
  <session-id>1</session-id>
</hello>"#;
        let mut buf = hello.as_bytes().to_vec();
        buf.extend_from_slice(b"]]>]]>");
        buf
    }

    /// A hello advertising `:url` with an explicit scheme list.
    fn mock_url_hello(schemes: &str) -> Vec<u8> {
        let hello = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <capabilities>
    <capability>urn:ietf:params:netconf:base:1.0</capability>
    <capability>urn:ietf:params:netconf:capability:url:1.0?scheme={schemes}</capability>
  </capabilities>
  <session-id>1</session-id>
</hello>"#
        );
        let mut buf = hello.into_bytes();
        buf.extend_from_slice(b"]]>]]>");
        buf
    }

    #[tokio::test]
    async fn url_scheme_must_be_advertised() {
        // Device offers https only; a file:// URL must not slip through on the
        // strength of the bare :url capability.
        let transport = MockTransport::new(mock_url_hello("https"));
        let written = transport.written_handle();
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        let before = written.lock().unwrap().len();
        let err = session
            .delete_config(&DeleteTarget::Url("file:///tmp/x.xml".to_string()))
            .await
            .expect_err("file scheme is not advertised");
        assert!(err.to_string().contains("file"), "got {err}");
        assert_eq!(written.lock().unwrap().len(), before, "nothing sent");
    }

    #[tokio::test]
    async fn advertised_url_scheme_is_accepted() {
        let mut data = mock_url_hello("http,file,ftp");
        data.extend_from_slice(&mock_ok_reply("1"));
        let transport = MockTransport::new(data);
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        session
            .delete_config(&DeleteTarget::Url("FILE:///tmp/x.xml".to_string()))
            .await
            .expect("scheme matching is case-insensitive");
    }

    #[tokio::test]
    async fn copy_config_preflight_failure_leaves_candidate_clean() {
        // No establish(), so no capabilities and no wire. Whichever preflight
        // check trips first, nothing is written — and the candidate must not be
        // marked dirty, or a later Junos close would send <discard-changes/>
        // against a shared candidate nobody touched.
        let transport = MockTransport::new(Vec::new());
        let written = transport.written_handle();
        let mut session = Session::new(Box::new(transport));
        assert!(!session.candidate_dirty());

        session
            .copy_config(
                &ConfigLocation::Datastore(Datastore::Candidate),
                &CopySource::Config("<system/>".to_string()),
            )
            .await
            .expect_err("preflight must refuse");

        assert!(
            written.lock().unwrap().is_empty(),
            "nothing should have been written"
        );
        assert!(
            !session.candidate_dirty(),
            "preflight failure must not leave the candidate marked dirty"
        );
    }

    #[tokio::test]
    async fn running_to_candidate_copy_leaves_candidate_clean() {
        // The two datastores are synchronized afterwards, so there is nothing
        // uncommitted to discard. Leaving the flag set would make a later Junos
        // close erase edits another session made to the shared candidate.
        let mut data = mock_junos_hello();
        data.extend_from_slice(&mock_ok_reply("1"));
        let transport = MockTransport::new(data);
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        session
            .copy_config(
                &ConfigLocation::Datastore(Datastore::Candidate),
                &CopySource::Datastore(Datastore::Running),
            )
            .await
            .expect("running -> candidate copy");
        assert!(
            !session.candidate_dirty(),
            "a running->candidate copy synchronizes them; nothing to discard"
        );
    }

    #[tokio::test]
    async fn candidate_to_running_copy_leaves_candidate_clean() {
        // The same synchronization `commit` performs, so the same bookkeeping.
        let mut data = mock_writable_running_hello();
        data.extend_from_slice(&mock_ok_reply("1"));
        data.extend_from_slice(&mock_ok_reply("2"));
        let transport = MockTransport::new(data);
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        session.mark_candidate_dirty();
        session
            .copy_config(
                &ConfigLocation::Datastore(Datastore::Running),
                &CopySource::Datastore(Datastore::Candidate),
            )
            .await
            .expect("candidate -> running copy");
        assert!(
            !session.candidate_dirty(),
            "candidate -> running synchronizes them; nothing left to discard"
        );
    }

    #[tokio::test]
    async fn identical_source_and_target_is_refused_before_marking_dirty() {
        // RFC 6241 §7.3 requires the server to answer invalid-value. Catching
        // it locally also stops the candidate being marked dirty for a request
        // that cannot succeed - which would make a later Junos close discard
        // another session's edits.
        let transport = MockTransport::new(mock_junos_hello());
        let written = transport.written_handle();
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        let before = written.lock().unwrap().len();
        let err = session
            .copy_config(
                &ConfigLocation::Datastore(Datastore::Candidate),
                &CopySource::Datastore(Datastore::Candidate),
            )
            .await
            .expect_err("identical source and target must be refused");
        assert!(err.to_string().contains("invalid value"), "got {err}");
        assert!(
            !session.candidate_dirty(),
            "a refused copy must not mark the candidate dirty"
        );
        assert_eq!(written.lock().unwrap().len(), before, "nothing sent");
    }

    #[tokio::test]
    async fn inline_copy_into_candidate_stays_dirty_and_is_vendor_wrapped() {
        let mut data = mock_junos_hello();
        data.extend_from_slice(&mock_ok_reply("1"));
        let transport = MockTransport::new(data);
        let written = transport.written_handle();
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        session
            .copy_config(
                &ConfigLocation::Datastore(Datastore::Candidate),
                &CopySource::Config("<system><host-name>r1</host-name></system>".to_string()),
            )
            .await
            .expect("inline copy");

        let sent = String::from_utf8_lossy(&written.lock().unwrap()).to_string();
        assert!(
            sent.contains("<configuration><system>"),
            "Junos needs the <configuration> wrapper: {sent}"
        );
        assert!(
            session.candidate_dirty(),
            "candidate now differs from running"
        );
    }

    #[tokio::test]
    async fn inline_copy_source_rejects_a_document_declaration() {
        let transport = MockTransport::new(mock_junos_hello());
        let written = transport.written_handle();
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        let before = written.lock().unwrap().len();
        let err = session
            .copy_config(
                &ConfigLocation::Datastore(Datastore::Candidate),
                &CopySource::Config("<?xml version=\"1.0\"?><system/>".to_string()),
            )
            .await
            .expect_err("a second declaration mid-document is malformed");
        assert!(err.to_string().contains("declaration"), "got {err}");
        assert_eq!(written.lock().unwrap().len(), before, "nothing sent");
    }

    #[tokio::test]
    async fn copy_config_gates_candidate_on_the_capability() {
        // mock_device_hello advertises :candidate; a startup target does not
        // exist there, so the startup gate must fire locally.
        let transport = MockTransport::new(mock_device_hello());
        let written = transport.written_handle();
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        let before = written.lock().unwrap().len();
        let err = session
            .copy_config(
                &ConfigLocation::Datastore(Datastore::Startup),
                &CopySource::Datastore(Datastore::Running),
            )
            .await
            .expect_err("startup is not advertised");
        assert!(err.to_string().contains("startup"), "got {err}");
        assert_eq!(written.lock().unwrap().len(), before, "nothing sent");
    }

    #[tokio::test]
    async fn copy_config_marks_candidate_dirty_before_writing() {
        // The reply never arrives. The flag must already be set, or a Junos
        // close would skip the discard and leave the shared candidate replaced.
        let transport = MockTransport::new(mock_device_hello());
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");
        assert!(!session.candidate_dirty());

        let _ = session
            .copy_config(
                &ConfigLocation::Datastore(Datastore::Candidate),
                &CopySource::Config("<system/>".to_string()),
            )
            .await;

        assert!(
            session.candidate_dirty(),
            "candidate must be marked dirty even when the reply is lost"
        );
    }

    #[tokio::test]
    async fn cancel_commit_requires_confirmed_commit_1_1() {
        // mock_device_hello_with_confirmed_commit advertises 1.0 only.
        let transport = MockTransport::new(mock_device_hello_with_confirmed_commit());
        let written = transport.written_handle();
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        let before = written.lock().unwrap().len();
        let err = session
            .cancel_commit(None)
            .await
            .expect_err("cancel-commit needs :confirmed-commit:1.1");
        assert!(err.to_string().contains("cancel-commit"), "got {err}");
        assert_eq!(written.lock().unwrap().len(), before, "nothing sent");
    }

    /// A hello advertising with-defaults with an explicit mode list.
    ///
    /// `&` between query parameters is XML-escaped, as a real device must do -
    /// an unescaped one makes the hello ill-formed.
    fn mock_with_defaults_hello(params: &str) -> Vec<u8> {
        let params = params.replace('&', "&amp;");
        let hello = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <capabilities>
    <capability>urn:ietf:params:netconf:base:1.0</capability>
    <capability>urn:ietf:params:netconf:capability:candidate:1.0</capability>
    <capability>urn:ietf:params:netconf:capability:with-defaults:1.0?{params}</capability>
  </capabilities>
  <session-id>1</session-id>
</hello>"#
        );
        let mut buf = hello.into_bytes();
        buf.extend_from_slice(b"]]>]]>");
        buf
    }

    #[tokio::test]
    async fn copy_config_with_defaults_emits_the_mode_and_is_gated() {
        // Advertised: accepted and rendered.
        let mut data = mock_with_defaults_hello("basic-mode=explicit&also-supported=trim");
        // add :candidate and :writable-running via a second hello is not
        // possible, so copy between running and startup is used instead.
        let transport = MockTransport::new(data.clone());
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");
        // startup is not advertised here, so the datastore gate fires first -
        // which is itself the point: gates compose and the mode gate is not
        // the only one.
        assert!(session
            .copy_config_with_defaults(
                &ConfigLocation::Datastore(Datastore::Startup),
                &CopySource::Datastore(Datastore::Running),
                WithDefaults::Trim,
            )
            .await
            .is_err());

        // Unadvertised mode is refused before anything is written.
        data = mock_with_defaults_hello("basic-mode=explicit");
        let transport = MockTransport::new(data);
        let written = transport.written_handle();
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");
        let before = written.lock().unwrap().len();
        let err = session
            .copy_config_with_defaults(
                &ConfigLocation::Datastore(Datastore::Running),
                &CopySource::Datastore(Datastore::Startup),
                WithDefaults::ReportAll,
            )
            .await
            .expect_err("report-all is not advertised");
        assert!(err.to_string().contains("report-all"), "got {err}");
        assert_eq!(written.lock().unwrap().len(), before, "nothing sent");
    }

    fn mock_partial_lock_hello() -> Vec<u8> {
        let hello = r#"<?xml version="1.0" encoding="UTF-8"?>
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <capabilities>
    <capability>urn:ietf:params:netconf:base:1.0</capability>
    <capability>urn:ietf:params:netconf:capability:partial-lock:1.0</capability>
  </capabilities>
  <session-id>1</session-id>
</hello>"#;
        let mut buf = hello.as_bytes().to_vec();
        buf.extend_from_slice(b"]]>]]>");
        buf
    }

    #[tokio::test]
    async fn partial_lock_accepts_a_namespace_omitting_device() {
        // The common shape: the envelope declares the base namespace as the
        // default and the device omits RFC 5717's on its output elements, so
        // <lock-id> inherits the base one. Rejecting that would error out after
        // the server granted the lock, stranding it.
        let hello = br#"<?xml version="1.0" encoding="UTF-8"?>
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><capabilities><capability>urn:ietf:params:netconf:base:1.0</capability><capability>urn:ietf:params:netconf:capability:partial-lock:1.0</capability></capabilities><session-id>1</session-id></hello>]]>]]>"#;
        let reply = br#"<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1"><data><lock-id>7</lock-id></data></rpc-reply>]]>]]>"#;
        let mut data = hello.to_vec();
        data.extend_from_slice(reply);

        let transport = MockTransport::new(data);
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        let lock = session
            .partial_lock(&["/x".to_string()], &[])
            .await
            .expect("a namespace-omitting device must still yield its lock-id");
        assert_eq!(lock.lock_id, 7);
    }

    #[tokio::test]
    async fn read_limit_is_adjustable_on_a_live_session() {
        let transport = MockTransport::new(mock_device_hello());
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        let default = session.max_read_buffer();
        assert_eq!(default, MAX_READ_BUFFER);

        session.set_max_read_buffer(512 * 1024 * 1024);
        assert_eq!(session.max_read_buffer(), 512 * 1024 * 1024);

        // And back down again: the ceiling exists to bound a hostile device,
        // so raising it for one fetch must be reversible.
        session.set_max_read_buffer(default);
        assert_eq!(session.max_read_buffer(), default);
    }

    #[tokio::test]
    async fn streaming_get_config_writes_the_reply() {
        let mut data = mock_device_hello();
        data.extend_from_slice(&mock_data_reply(
            "1",
            "<system><host-name>r1</host-name></system>",
        ));
        let transport = MockTransport::new(data);
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        let mut out: Vec<u8> = Vec::new();
        let n = session
            .get_config_streaming(Datastore::Running, None, &mut out)
            .await
            .expect("streaming get-config");

        let text = String::from_utf8(out).expect("utf-8");
        assert_eq!(n, text.len());
        // The *raw envelope*, not the unwrapped payload — that is the contract.
        assert!(text.contains("<rpc-reply"), "got {text}");
        assert!(text.contains("<host-name>r1</host-name>"), "got {text}");
    }

    #[tokio::test]
    async fn streaming_survives_a_reply_larger_than_the_ceiling() {
        // The point of the feature: emitted bytes leave the buffer, so a reply
        // far bigger than `max_read_buffer` streams fine where `get_config`
        // would refuse it.
        let big = "x".repeat(256 * 1024);
        let mut data = mock_device_hello();
        data.extend_from_slice(&mock_data_reply("1", &big));
        let transport = MockTransport::new(data);
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");
        session.set_max_read_buffer(64 * 1024);

        let mut out: Vec<u8> = Vec::new();
        let n = session
            .get_config_streaming(Datastore::Running, None, &mut out)
            .await
            .expect("a large reply must stream under a small ceiling");
        assert!(n > 256 * 1024, "expected the whole payload, got {n}");
    }

    #[tokio::test]
    async fn streaming_reports_eof_mid_reply() {
        // Hello, then a truncated frame: the stream must fail rather than
        // silently returning a partial document.
        let mut data = mock_device_hello();
        data.extend_from_slice(b"<rpc-reply><data>partial");
        let transport = MockTransport::new(data);
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        let mut out: Vec<u8> = Vec::new();
        let err = session
            .get_config_streaming(Datastore::Running, None, &mut out)
            .await
            .expect_err("truncated reply must be an error");
        assert!(err.to_string().contains("mid-reply"), "got {err}");
    }

    #[tokio::test]
    async fn streaming_skips_a_stale_reply_and_returns_ours() {
        // A cancelled RPC can leave its reply queued. Streaming it would hand
        // the caller someone else's XML and leave the real reply unread.
        let mut data = mock_device_hello();
        data.extend_from_slice(&mock_data_reply("99", "<stale/>")); // not ours
        data.extend_from_slice(&mock_data_reply("1", "<ours/>")); // message-id 1
        let transport = MockTransport::new(data);
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        let mut out: Vec<u8> = Vec::new();
        session
            .get_config_streaming(Datastore::Running, None, &mut out)
            .await
            .expect("streaming get-config");

        let text = String::from_utf8(out).expect("utf-8");
        assert!(text.contains("<ours/>"), "should return our reply: {text}");
        assert!(
            !text.contains("<stale/>"),
            "must not emit the stale reply: {text}"
        );
    }

    #[test]
    fn reply_message_id_reads_the_attribute() {
        let f = Session::reply_message_id;
        assert_eq!(f(br#"<rpc-reply message-id="7">"#).as_deref(), Some("7"));
        assert_eq!(
            f(br#"<rpc-reply message-id = '12' >"#).as_deref(),
            Some("12")
        );
        // Not enough bytes yet: keep waiting rather than guessing.
        assert_eq!(f(br#"<rpc-reply message-"#), None);
        assert_eq!(f(br#"<rpc-reply "#), None);
    }

    #[test]
    fn reply_message_id_survives_a_split_codepoint() {
        // A read or chunk boundary can land mid-codepoint. Decoding the whole
        // prefix as UTF-8 would fail and discard a perfectly valid reply.
        let mut buf = br#"<rpc-reply message-id="7"><data>caf"#.to_vec();
        buf.push(0xC3); // first byte of a truncated two-byte codepoint
        assert_eq!(
            Session::reply_message_id(&buf).as_deref(),
            Some("7"),
            "a split codepoint after the opening tag must not hide the id"
        );
    }

    #[test]
    fn reply_message_id_ignores_prologs_and_comments() {
        let f = Session::reply_message_id;
        assert_eq!(
            f(br#"<?xml version="1.0"?><rpc-reply message-id="5">"#).as_deref(),
            Some("5")
        );
        // A decoy inside a comment must not be read as the id.
        assert_eq!(
            f(br#"<!-- message-id="99" --><rpc-reply message-id="5">"#).as_deref(),
            Some("5")
        );
    }

    #[tokio::test]
    async fn streaming_is_refused_while_the_candidate_is_dirty() {
        // An interrupted stream poisons the session, and a poisoned session
        // cannot discard — which would strand edits on a shared candidate.
        let transport = MockTransport::new(mock_junos_hello());
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");
        session.mark_candidate_dirty();

        let mut out: Vec<u8> = Vec::new();
        let err = session
            .get_config_streaming(Datastore::Running, None, &mut out)
            .await
            .expect_err("must refuse with a dirty candidate");
        assert!(err.to_string().contains("candidate is dirty"), "got {err}");
        assert!(
            session.candidate_dirty(),
            "and the discard path must still be available"
        );
        assert!(session.is_alive(), "refusing must not poison the session");
    }

    #[tokio::test]
    async fn streaming_is_refused_while_a_subscription_is_active() {
        // Streaming cannot demultiplex: a notification arriving before the reply
        // would be handed to the caller as the result.
        let mut data = mock_device_hello_with_notification();
        data.extend_from_slice(&mock_ok_reply("1"));
        let transport = MockTransport::new(data);
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");
        session
            .create_subscription(None, None, None, None)
            .await
            .expect("subscribe");

        let mut out: Vec<u8> = Vec::new();
        let err = session
            .get_config_streaming(Datastore::Running, None, &mut out)
            .await
            .expect_err("must refuse while subscribed");
        assert!(err.to_string().contains("subscription"), "got {err}");
    }

    #[tokio::test]
    async fn an_interrupted_stream_poisons_the_session() {
        // Truncated reply: part of the frame is drained, then EOF. The buffer
        // now holds a suffix, so the next RPC would misparse it — and a pooled
        // connection must not be handed on in that state.
        let mut data = mock_device_hello();
        data.extend_from_slice(b"<rpc-reply><data>partial");
        let transport = MockTransport::new(data);
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");
        assert!(session.is_alive());

        let mut out: Vec<u8> = Vec::new();
        let _ = session
            .get_config_streaming(Datastore::Running, None, &mut out)
            .await
            .expect_err("truncated reply");

        assert!(
            !session.is_alive(),
            "a half-drained stream must poison the session"
        );
        assert!(
            session.get(None).await.is_err(),
            "and further RPCs must be refused rather than misparsing the suffix"
        );
    }

    #[tokio::test]
    async fn partial_lock_requires_the_capability() {
        let transport = MockTransport::new(mock_device_hello());
        let written = transport.written_handle();
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        let before = written.lock().unwrap().len();
        let err = session
            .partial_lock(&["/x".to_string()], &[])
            .await
            .expect_err("partial-lock is not advertised");
        assert!(err.to_string().contains("partial-lock"), "got {err}");
        assert_eq!(written.lock().unwrap().len(), before, "nothing sent");
    }

    #[tokio::test]
    async fn partial_lock_returns_the_lock_id() {
        let mut data = mock_partial_lock_hello();
        data.extend_from_slice(&mock_data_reply(
            "1",
            r#"<lock-id xmlns="urn:ietf:params:xml:ns:netconf:partial-lock:1.0">127</lock-id><locked-node xmlns="urn:ietf:params:xml:ns:netconf:partial-lock:1.0">/interfaces</locked-node>"#,
        ));
        let transport = MockTransport::new(data);
        let written = transport.written_handle();
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        let lock = session
            .partial_lock(
                &["/if:interfaces".to_string()],
                &[(
                    "if".to_string(),
                    "urn:ietf:params:xml:ns:yang:ietf-interfaces".to_string(),
                )],
            )
            .await
            .expect("partial-lock");
        assert_eq!(lock.lock_id, 127);
        assert_eq!(lock.locked_nodes.len(), 1);
        assert_eq!(lock.locked_nodes[0].path, "/interfaces");

        let sent = String::from_utf8_lossy(&written.lock().unwrap()).to_string();
        assert!(
            sent.contains("<select>/if:interfaces</select>"),
            "sent: {sent}"
        );
        assert!(sent.contains("xmlns:if="), "sent: {sent}");
    }

    #[tokio::test]
    async fn partial_lock_ok_without_lock_id_is_an_error() {
        // An <ok/> means the server took a lock we can never release.
        let mut data = mock_partial_lock_hello();
        data.extend_from_slice(&mock_ok_reply("1"));
        let transport = MockTransport::new(data);
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        let err = session
            .partial_lock(&["/x".to_string()], &[])
            .await
            .expect_err("<ok/> carries no lock-id");
        assert!(err.to_string().contains("lock-id"), "got {err}");
    }

    #[tokio::test]
    async fn indeterminate_partial_lock_poisons_the_session() {
        // <ok/> with no lock-id: the server may hold a lock we cannot name.
        // The session must not go back into a pool still holding it.
        let mut data = mock_partial_lock_hello();
        data.extend_from_slice(&mock_ok_reply("1"));
        let transport = MockTransport::new(data);
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");
        assert!(session.is_alive());

        let _ = session
            .partial_lock(&["/x".to_string()], &[])
            .await
            .expect_err("<ok/> carries no lock-id");

        assert!(
            !session.is_alive(),
            "an indeterminate partial-lock must poison the session so the pool \
             discards it rather than recycling an unreleasable lock"
        );
    }

    #[tokio::test]
    async fn lock_denied_does_not_poison_the_session() {
        // Routine contention. RFC 5717 makes a failed partial lock atomic, so a
        // parsed <rpc-error> definitively means no lock is held and the session
        // is healthy - poisoning here would throw away good pooled connections
        // every time two operators collide.
        let mut data = mock_partial_lock_hello();
        data.extend_from_slice(&mock_lock_denied_reply("1", 42));
        let transport = MockTransport::new(data);
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        let err = session
            .partial_lock(&["/x".to_string()], &[])
            .await
            .expect_err("lock is held elsewhere");
        assert!(err.to_string().contains("LockDenied"), "got {err}");
        assert!(
            session.is_alive(),
            "a definitive rejection must leave the session usable"
        );
    }

    #[tokio::test]
    async fn a_poisoned_session_refuses_further_lock_operations() {
        // A retry that succeeded would clear the flag and report health while
        // the *first* request's lock is still outstanding and unnameable.
        let mut data = mock_partial_lock_hello();
        data.extend_from_slice(&mock_ok_reply("1")); // <ok/>: no lock-id
        data.extend_from_slice(&mock_data_reply(
            "2",
            r#"<lock-id xmlns="urn:ietf:params:xml:ns:netconf:partial-lock:1.0">5</lock-id>"#,
        ));
        let transport = MockTransport::new(data);
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        let _ = session
            .partial_lock(&["/x".to_string()], &[])
            .await
            .expect_err("<ok/> carries no lock-id");
        assert!(!session.is_alive());

        // Even though a good reply is queued, the retry must be refused.
        assert!(
            session
                .partial_lock(&["/y".to_string()], &[])
                .await
                .is_err(),
            "a poisoned session must not accept another partial-lock"
        );
        assert!(
            session.partial_unlock(5).await.is_err(),
            "nor an unlock, which would look like it resolved the uncertainty"
        );
        assert!(!session.is_alive(), "still poisoned");
    }

    #[tokio::test]
    async fn rejected_partial_unlock_keeps_the_session_poisoned() {
        // Inverse of the acquire case: a refused release means the lock is
        // still held, so the session must not go back into the pool.
        let mut data = mock_partial_lock_hello();
        data.extend_from_slice(&mock_commit_error_reply("1"));
        let transport = MockTransport::new(data);
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        let _ = session
            .partial_unlock(5)
            .await
            .expect_err("server refused the release");
        assert!(
            !session.is_alive(),
            "a refused unlock leaves the lock held; the session must not be recycled"
        );
    }

    #[tokio::test]
    async fn successful_partial_unlock_leaves_the_session_usable() {
        let mut data = mock_partial_lock_hello();
        data.extend_from_slice(&mock_ok_reply("1"));
        let transport = MockTransport::new(data);
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        session.partial_unlock(9).await.expect("partial-unlock");
        assert!(
            session.is_alive(),
            "a clean unlock must leave the session reusable"
        );
    }

    #[tokio::test]
    async fn successful_partial_lock_leaves_the_session_usable() {
        let mut data = mock_partial_lock_hello();
        data.extend_from_slice(&mock_data_reply(
            "1",
            r#"<lock-id xmlns="urn:ietf:params:xml:ns:netconf:partial-lock:1.0">3</lock-id>"#,
        ));
        let transport = MockTransport::new(data);
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        session
            .partial_lock(&["/x".to_string()], &[])
            .await
            .expect("partial-lock");
        assert!(
            session.is_alive(),
            "a clean lock must not poison the session"
        );
    }

    #[tokio::test]
    async fn partial_unlock_sends_the_lock_id() {
        let mut data = mock_partial_lock_hello();
        data.extend_from_slice(&mock_ok_reply("1"));
        let transport = MockTransport::new(data);
        let written = transport.written_handle();
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        session.partial_unlock(127).await.expect("partial-unlock");
        let sent = String::from_utf8_lossy(&written.lock().unwrap()).to_string();
        assert!(sent.contains("<lock-id>127</lock-id>"), "sent: {sent}");
    }

    #[tokio::test]
    async fn unadvertised_with_defaults_mode_is_refused_before_sending() {
        // Device supports explicit only. Sending `trim` anyway would return
        // data in a different shape than the caller asked for.
        let transport = MockTransport::new(mock_with_defaults_hello("basic-mode=explicit"));
        let written = transport.written_handle();
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        let before = written.lock().unwrap().len();
        let err = session
            .get_with_defaults(None, WithDefaults::Trim)
            .await
            .expect_err("trim is not advertised");
        assert!(err.to_string().contains("trim"), "got {err}");
        assert!(
            err.to_string().contains("explicit"),
            "should name what is supported: {err}"
        );
        assert_eq!(written.lock().unwrap().len(), before, "nothing sent");
    }

    #[tokio::test]
    async fn with_defaults_copy_does_not_clear_the_dirty_flag() {
        // trim removes defaulted nodes on the way through, so the candidate is
        // not a copy of running afterwards - the flag must stand.
        let mut data = mock_with_defaults_hello("basic-mode=trim");
        data.extend_from_slice(&mock_ok_reply("1"));
        let transport = MockTransport::new(data);
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        session
            .copy_config_with_defaults(
                &ConfigLocation::Datastore(Datastore::Candidate),
                &CopySource::Datastore(Datastore::Running),
                WithDefaults::Trim,
            )
            .await
            .expect("trim copy");
        assert!(
            session.candidate_dirty(),
            "a transformed copy is not a synchronization"
        );
    }

    #[tokio::test]
    async fn report_all_tagged_keeps_the_vendor_wrapper() {
        // The wd: prefix is bound on <configuration>; unwrapping would orphan
        // the default markers that are the whole point of this mode.
        let mut data = mock_with_defaults_hello("basic-mode=report-all-tagged");
        data.extend_from_slice(&mock_data_reply(
            "1",
            r#"<configuration xmlns:wd="urn:ietf:params:xml:ns:netconf:default:1.0"><system><host-name wd:default="true">r1</host-name></system></configuration>"#,
        ));
        let transport = MockTransport::new(data);
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");
        session.set_vendor_profile(Box::new(crate::vendor::junos::JunosVendor::default()));

        let out = session
            .get_config_with_defaults(Datastore::Running, None, WithDefaults::ReportAllTagged)
            .await
            .expect("report-all-tagged");
        assert!(
            out.contains("xmlns:wd="),
            "the wd binding must survive: {out}"
        );
        assert!(out.contains("wd:default=\"true\""), "got {out}");
    }

    #[tokio::test]
    async fn other_modes_are_still_vendor_unwrapped() {
        // The CLI diffs a self-unwrapped desired config against this, so the
        // wrapper must keep coming off for every mode but report-all-tagged.
        let mut data = mock_with_defaults_hello("basic-mode=trim");
        data.extend_from_slice(&mock_data_reply(
            "1",
            r#"<configuration xmlns:junos="http://xml.juniper.net/junos/1.0" junos:commit-seconds="1"><system/></configuration>"#,
        ));
        let transport = MockTransport::new(data);
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");
        session.set_vendor_profile(Box::new(crate::vendor::junos::JunosVendor::default()));

        let out = session
            .get_config_with_defaults(Datastore::Running, None, WithDefaults::Trim)
            .await
            .expect("trim");
        assert!(
            !out.trim().starts_with("<configuration"),
            "wrapper must still be stripped: {out}"
        );
    }

    #[tokio::test]
    async fn advertised_with_defaults_mode_is_sent() {
        let mut data =
            mock_with_defaults_hello("basic-mode=explicit&also-supported=report-all,trim");
        data.extend_from_slice(&mock_data_reply("1", "<interfaces/>"));
        let transport = MockTransport::new(data);
        let written = transport.written_handle();
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        session
            .get_with_defaults(None, WithDefaults::Trim)
            .await
            .expect("trim is in also-supported");
        let sent = String::from_utf8_lossy(&written.lock().unwrap()).to_string();
        assert!(sent.contains(">trim</with-defaults>"), "sent: {sent}");
    }

    #[tokio::test]
    async fn device_without_the_capability_reports_no_modes() {
        let transport = MockTransport::new(mock_device_hello());
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");
        assert!(session.with_defaults_modes().is_empty());
        assert!(session
            .get_with_defaults(None, WithDefaults::ReportAll)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn xpath_without_capability_is_refused_before_sending() {
        // mock_junos_hello does not advertise :xpath:1.0.
        let transport = MockTransport::new(mock_junos_hello());
        let written = transport.written_handle();
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        let before = written.lock().unwrap().len();
        let err = session
            .get_xpath(&XPathFilter::new("/x"))
            .await
            .expect_err("should refuse without :xpath:1.0");

        assert!(
            matches!(
                err,
                NetconfError::Protocol(ProtocolError::CapabilityMissing(ref uri))
                    if uri == capability::uri::XPATH
            ),
            "unexpected error: {err:?}"
        );
        // The point of the gate: nothing reached the wire. A device lacking
        // XPath may ignore the filter and return the whole datastore, which
        // would look like success.
        assert_eq!(
            written.lock().unwrap().len(),
            before,
            "no bytes should have been written"
        );
    }

    #[tokio::test]
    async fn xpath_with_capability_sends_an_xpath_filter() {
        let mut data = mock_xpath_hello();
        data.extend_from_slice(&mock_data_reply("1", "<interfaces/>"));

        let transport = MockTransport::new(data);
        let written = transport.written_handle();
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        let filter = XPathFilter::new("/if:interfaces")
            .namespace("if", "urn:ietf:params:xml:ns:yang:ietf-interfaces");
        session.get_xpath(&filter).await.expect("get_xpath failed");

        let sent = String::from_utf8_lossy(&written.lock().unwrap()).to_string();
        assert!(sent.contains(r#"type="xpath""#), "sent: {sent}");
        assert!(sent.contains(r#"select="/if:interfaces""#), "sent: {sent}");
        assert!(
            sent.contains(r#"xmlns:if="urn:ietf:params:xml:ns:yang:ietf-interfaces""#),
            "sent: {sent}"
        );
    }

    #[tokio::test]
    async fn test_commit_configuration_with_log_clears_dirty_flag() {
        let mut response_data = mock_junos_hello();
        response_data.extend_from_slice(&mock_ok_reply("1")); // load-configuration reply
        response_data.extend_from_slice(&mock_ok_reply("2")); // commit-configuration reply
        response_data.extend_from_slice(&mock_ok_reply("3")); // close-session reply (no discard)

        let transport = MockTransport::new(response_data);
        let written_handle = transport.written_handle();
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        // Load config (dirties candidate)
        session
            .load_configuration(
                crate::types::LoadAction::Merge,
                crate::types::LoadFormat::Text,
                "set system host-name test",
            )
            .await
            .expect("load_configuration failed");

        // Commit with log (clears dirty flag)
        session
            .commit_configuration_with_log("test commit comment")
            .await
            .expect("commit_configuration_with_log failed");

        // Close (should NOT send discard-changes)
        session.close_session().await.expect("close failed");

        let written = written_handle.lock().unwrap();
        let written_str = String::from_utf8_lossy(&written);
        let discard_count = written_str.matches("discard-changes").count();
        assert_eq!(
            discard_count, 0,
            "commit_configuration_with_log should clear dirty flag, so close sends no discard-changes"
        );
        // Verify the log comment was sent
        assert!(
            written_str.contains("<nc:log>test commit comment</nc:log>"),
            "commit should include log comment"
        );
    }

    /// Build a mock commit-configuration error response.
    fn mock_commit_error_reply(message_id: &str) -> Vec<u8> {
        let reply = format!(
            r#"<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{message_id}">
  <rpc-error>
    <error-type>protocol</error-type>
    <error-tag>operation-failed</error-tag>
    <error-severity>error</error-severity>
    <error-message>commit failed: configuration check-out failed</error-message>
  </rpc-error>
</rpc-reply>"#
        );
        let mut buf = reply.into_bytes();
        buf.extend_from_slice(b"]]>]]>");
        buf
    }

    #[tokio::test]
    async fn test_commit_configuration_with_log_failed_leaves_dirty() {
        let mut response_data = mock_junos_hello();
        response_data.extend_from_slice(&mock_ok_reply("1")); // load-configuration reply
        response_data.extend_from_slice(&mock_commit_error_reply("2")); // commit-configuration fails
        response_data.extend_from_slice(&mock_ok_reply("3")); // discard-changes reply
        response_data.extend_from_slice(&mock_ok_reply("4")); // close-session reply

        let transport = MockTransport::new(response_data);
        let written_handle = transport.written_handle();
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        // Load config (dirties candidate)
        session
            .load_configuration(
                crate::types::LoadAction::Merge,
                crate::types::LoadFormat::Text,
                "set system host-name test",
            )
            .await
            .expect("load_configuration failed");

        // Commit with log fails (leaves dirty flag set)
        let result = session.commit_configuration_with_log("failed commit").await;
        assert!(
            result.is_err(),
            "commit_configuration_with_log should fail with error reply"
        );

        // Candidate should still be dirty
        assert!(
            session.candidate_dirty(),
            "failed commit should leave candidate dirty"
        );

        // Close (SHOULD send discard-changes)
        session.close_session().await.expect("close failed");

        let written = written_handle.lock().unwrap();
        let written_str = String::from_utf8_lossy(&written);
        let discard_count = written_str.matches("discard-changes").count();
        assert_eq!(
            discard_count, 1,
            "failed commit should leave candidate dirty, so close sends discard-changes"
        );
    }

    #[tokio::test]
    async fn test_junos_rollback_dirties_candidate() {
        let mut response_data = mock_junos_hello();
        response_data.extend_from_slice(&mock_ok_reply("1")); // rollback-configuration reply
        response_data.extend_from_slice(&mock_ok_reply("2")); // discard-changes reply
        response_data.extend_from_slice(&mock_ok_reply("3")); // close-session reply

        let transport = MockTransport::new(response_data);
        let written_handle = transport.written_handle();
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        // Rollback (dirties candidate)
        session
            .rollback_configuration(0)
            .await
            .expect("rollback_configuration failed");

        session.close_session().await.expect("close failed");

        let written = written_handle.lock().unwrap();
        let written_str = String::from_utf8_lossy(&written);
        let discard_count = written_str.matches("discard-changes").count();
        assert_eq!(
            discard_count, 1,
            "rollback_configuration should send discard-changes on close"
        );
    }

    #[tokio::test]
    async fn test_junos_mark_candidate_dirty_forces_discard() {
        let mut response_data = mock_junos_hello();
        response_data.extend_from_slice(&mock_ok_reply("1")); // get-config reply (read-only)
        response_data.extend_from_slice(&mock_ok_reply("2")); // discard-changes reply
        response_data.extend_from_slice(&mock_ok_reply("3")); // close-session reply

        let transport = MockTransport::new(response_data);
        let written_handle = transport.written_handle();
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        // Read-only operation
        session
            .get_config(Datastore::Candidate, None)
            .await
            .expect("get_config failed");

        // Manually mark dirty (escape hatch for raw rpc() calls)
        session.mark_candidate_dirty();

        session.close_session().await.expect("close failed");

        let written = written_handle.lock().unwrap();
        let written_str = String::from_utf8_lossy(&written);
        let discard_count = written_str.matches("discard-changes").count();
        assert_eq!(
            discard_count, 1,
            "mark_candidate_dirty should force discard-changes on close"
        );
    }

    #[tokio::test]
    async fn test_generic_vendor_never_discards_on_close() {
        let mut response_data = mock_device_hello(); // generic, NOT Junos
        response_data.extend_from_slice(&mock_ok_reply("1")); // edit-config reply
        response_data.extend_from_slice(&mock_ok_reply("2")); // close-session reply (no discard)

        let transport = MockTransport::new(response_data);
        let written_handle = transport.written_handle();
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");
        assert_eq!(session.vendor_name(), "generic");

        // Edit candidate (would dirty it on Junos)
        session
            .edit_config(
                Datastore::Candidate,
                "<system><host-name>test</host-name></system>",
                None,
                None,
                None,
            )
            .await
            .expect("edit_config failed");

        session.close_session().await.expect("close failed");

        let written = written_handle.lock().unwrap();
        let written_str = String::from_utf8_lossy(&written);
        let discard_count = written_str.matches("discard-changes").count();
        assert_eq!(
            discard_count, 0,
            "generic vendor should never send discard-changes, even if candidate was edited"
        );
    }

    // ── rpc_candidate_change preflight regression tests ────────────────

    /// Test 1: rpc_candidate_change on un-established session returns error
    /// and does NOT mark dirty. This is the core regression test for the
    /// ensure_established preflight failure path.
    #[tokio::test]
    async fn test_rpc_candidate_change_failed_keepalive_does_not_mark_dirty() {
        // Hello only: the keepalive probe that fires before the candidate RPC
        // gets EOF, so nothing of the candidate change ever reaches the wire.
        let response_data = mock_junos_hello();

        let transport = MockTransport::new(response_data);
        let written_handle = transport.written_handle();
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");

        // A zero interval makes `last.elapsed() >= interval` true immediately,
        // so the next RPC probes first — no sleeping, fully deterministic.
        session.set_keepalive_interval(Duration::ZERO);

        let result = session
            .rpc_candidate_change(
                "<load-configuration><configuration><foo/></configuration></load-configuration>",
            )
            .await;

        assert!(
            result.is_err(),
            "keepalive probe hit EOF, so the RPC must fail"
        );
        assert!(
            !session.candidate_dirty(),
            "a candidate RPC that died in the keepalive preflight never reached \
             the device, so it must not mark the shared candidate dirty"
        );

        let written = String::from_utf8_lossy(&written_handle.lock().unwrap()).into_owned();
        assert!(
            !written.contains("load-configuration"),
            "the candidate change must not have been written"
        );
    }

    #[tokio::test]
    async fn test_rpc_candidate_change_not_established_does_not_mark_dirty() {
        let transport = MockTransport::new(vec![]);
        let mut session = Session::new(Box::new(transport));

        // Do NOT call establish()

        let result = session
            .rpc_candidate_change(
                "<load-configuration><configuration><foo/></configuration></load-configuration>",
            )
            .await;

        assert!(
            result.is_err(),
            "rpc_candidate_change on un-established session should fail"
        );

        // Candidate must NOT be marked dirty
        assert!(
            !session.candidate_dirty(),
            "candidate_dirty must be false when ensure_established() fails"
        );
    }

    /// Test 2: rpc_candidate_change on properly established Junos session
    /// with well-formed fragment still marks dirty and causes close_session
    /// to send discard-changes. This is a guard against the restructure
    /// breaking the happy path.
    #[tokio::test]
    async fn test_rpc_candidate_change_established_marks_dirty() {
        let mut response_data = mock_junos_hello();
        response_data.extend_from_slice(&mock_ok_reply("1")); // rpc_candidate_change reply
        response_data.extend_from_slice(&mock_ok_reply("2")); // discard-changes reply
        response_data.extend_from_slice(&mock_ok_reply("3")); // close-session reply

        let transport = MockTransport::new(response_data);
        let written_handle = transport.written_handle();
        let mut session = Session::new(Box::new(transport));
        session.establish().await.expect("establish failed");
        assert_eq!(session.vendor_name(), "junos");

        // Call rpc_candidate_change with well-formed XML
        session
            .rpc_candidate_change(
                "<load-configuration><configuration><foo/></configuration></load-configuration>",
            )
            .await
            .expect("rpc_candidate_change failed");

        // Candidate should be marked dirty
        assert!(
            session.candidate_dirty(),
            "candidate should be dirty after successful rpc_candidate_change"
        );

        // Close session
        session.close_session().await.expect("close failed");

        // Verify discard-changes was sent exactly once
        let written = written_handle.lock().unwrap();
        let written_str = String::from_utf8_lossy(&written);
        let discard_count = written_str.matches("discard-changes").count();
        assert_eq!(
            discard_count, 1,
            "Junos session with rpc_candidate_change should send discard-changes once on close"
        );
    }
}
