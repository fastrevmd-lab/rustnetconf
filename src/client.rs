//! Thin ergonomic client wrapper over `Session`.
//!
//! `Client` provides builder-pattern connection setup and delegates all
//! protocol operations to the underlying `Session`. It owns no protocol state.

use std::time::Duration;

use crate::capability::Capabilities;
use crate::error::NetconfError;
use crate::facts::Facts;
use crate::session::Session;
use crate::transport::ssh::{HostKeyVerification, SshAuth, SshConfig, SshTransport};
use crate::types::{Datastore, DefaultOperation, ErrorOption, TestOption};
use crate::vendor::VendorProfile;

/// Builder for establishing a NETCONF client connection.
///
/// # Examples
/// ```rust,no_run
/// use rustnetconf::Client;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let client = Client::connect("10.0.0.1:830")
///     .username("admin")
///     .password("secret")
///     .connect()
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct ClientBuilder {
    host: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
    key_file: Option<String>,
    key_passphrase: Option<String>,
    use_agent: bool,
    vendor_profile: Option<Box<dyn VendorProfile>>,
    gather_facts: bool,
    keepalive_interval: Option<Duration>,
    host_key_verification: HostKeyVerification,
}

impl ClientBuilder {
    /// Set the SSH username.
    pub fn username(mut self, username: &str) -> Self {
        self.username = Some(username.to_string());
        self
    }

    /// Set the SSH password for authentication.
    pub fn password(mut self, password: &str) -> Self {
        self.password = Some(password.to_string());
        self
    }

    /// Set the path to an SSH private key file.
    pub fn key_file(mut self, path: &str) -> Self {
        self.key_file = Some(path.to_string());
        self
    }

    /// Set the passphrase for the SSH private key.
    pub fn key_passphrase(mut self, passphrase: &str) -> Self {
        self.key_passphrase = Some(passphrase.to_string());
        self
    }

    /// Use the SSH agent for authentication.
    pub fn ssh_agent(mut self) -> Self {
        self.use_agent = true;
        self
    }

    /// Set an explicit vendor profile, overriding auto-detection.
    ///
    /// Use this when auto-detection doesn't work for your device, or
    /// when using a custom vendor implementation.
    pub fn vendor_profile(mut self, profile: Box<dyn VendorProfile>) -> Self {
        self.vendor_profile = Some(profile);
        self
    }

    /// Control whether device facts are gathered after connecting.
    ///
    /// When `true` (the default), the client sends a vendor-specific RPC
    /// (e.g., `<get-system-information/>` on Junos) to populate
    /// [`Client::facts()`] with the device's hostname, model, version, and
    /// serial number.
    ///
    /// Set to `false` to skip facts gathering — useful for clustered devices
    /// where the facts RPC may fail if a peer node is unreachable. Facts can
    /// be gathered later via [`Client::gather_facts()`].
    pub fn gather_facts(mut self, gather: bool) -> Self {
        self.gather_facts = gather;
        self
    }

    /// Set a keepalive interval for automatic session health checks.
    ///
    /// When set, the client tracks the time since the last successful RPC.
    /// Before each RPC, if more than `interval` has elapsed, a lightweight
    /// probe is sent first. If the probe fails, the session is marked dead
    /// and the caller can [`reconnect()`](Client::reconnect).
    ///
    /// Default: no keepalive (disabled).
    pub fn keepalive_interval(mut self, interval: Duration) -> Self {
        self.keepalive_interval = Some(interval);
        self
    }

    /// Set the SSH host key verification policy.
    ///
    /// Controls how the client validates the device's SSH host key during
    /// connection to protect against man-in-the-middle attacks.
    ///
    /// Default: [`HostKeyVerification::AcceptAll`] (a warning is logged).
    ///
    /// # Examples
    /// ```rust,no_run
    /// use rustnetconf::Client;
    /// use rustnetconf::transport::ssh::HostKeyVerification;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::connect("10.0.0.1:830")
    ///     .username("admin")
    ///     .password("secret")
    ///     .host_key_verification(HostKeyVerification::Fingerprint(
    ///         "SHA256:abc123...".to_string(),
    ///     ))
    ///     .connect()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn host_key_verification(mut self, policy: HostKeyVerification) -> Self {
        self.host_key_verification = policy;
        self
    }

    /// Establish the SSH connection and perform the NETCONF hello exchange.
    pub async fn connect(self) -> Result<Client, NetconfError> {
        let username = self
            .username
            .ok_or_else(|| {
                crate::error::TransportError::Auth("username is required".to_string())
            })?;

        let auth = if self.use_agent {
            SshAuth::Agent
        } else if let Some(key_path) = self.key_file {
            SshAuth::KeyFile {
                path: key_path,
                passphrase: self.key_passphrase,
            }
        } else if let Some(password) = self.password {
            SshAuth::Password(password)
        } else {
            return Err(crate::error::TransportError::Auth(
                "no authentication method specified (password, key_file, or ssh_agent)".to_string(),
            )
            .into());
        };

        let config = SshConfig {
            host: self.host,
            port: self.port,
            username,
            auth,
            host_key_verification: self.host_key_verification,
        };

        let transport = SshTransport::connect(config.clone()).await?;
        let mut session = Session::new(Box::new(transport));

        if let Some(interval) = self.keepalive_interval {
            session.set_keepalive_interval(interval);
        }

        // Set explicit vendor profile if provided (overrides auto-detection)
        if let Some(profile) = self.vendor_profile {
            session.set_vendor_profile(profile);
        }

        session.establish().await?;

        if self.gather_facts {
            session.gather_facts().await?;
        }

        Ok(Client {
            session,
            ssh_config: config,
            gather_facts: self.gather_facts,
            keepalive_interval: self.keepalive_interval,
        })
    }
}

/// An async NETCONF client.
///
/// Created via [`Client::connect()`]. All operations are delegated to the
/// underlying [`Session`] which owns all protocol state.
pub struct Client {
    session: Session,
    /// Stored SSH config for reconnect support.
    ssh_config: SshConfig,
    /// Whether to gather facts on connect/reconnect.
    gather_facts: bool,
    /// Keepalive interval (None = disabled).
    keepalive_interval: Option<Duration>,
}

impl Client {
    /// Create a connection builder targeting the given host.
    ///
    /// The address can be `"host:port"` or just `"host"` (defaults to port 830).
    pub fn connect(address: &str) -> ClientBuilder {
        let (host, port) = parse_address(address);
        ClientBuilder {
            host,
            port,
            username: None,
            password: None,
            key_file: None,
            key_passphrase: None,
            use_agent: false,
            vendor_profile: None,
            gather_facts: true,
            keepalive_interval: None,
            host_key_verification: HostKeyVerification::default(),
        }
    }

    /// Send an arbitrary RPC and return the raw XML response content.
    ///
    /// The `rpc_content` is wrapped in `<rpc>` tags with a message-id,
    /// sent to the device, and the inner content of `<rpc-reply>` is returned.
    ///
    /// Use this for vendor-specific RPCs not covered by the standard
    /// NETCONF operations (get-config, edit-config, etc.).
    pub async fn rpc(&mut self, rpc_content: &str) -> Result<String, NetconfError> {
        self.session.rpc(rpc_content).await
    }

    /// Check if the device supports a specific capability URI.
    pub fn supports(&self, capability_uri: &str) -> bool {
        self.session.supports(capability_uri)
    }

    /// Get the detected or configured vendor name (e.g., "junos", "generic").
    pub fn vendor_name(&self) -> &str {
        self.session.vendor_name()
    }

    /// Get the device's capabilities.
    pub fn capabilities(&self) -> Option<&Capabilities> {
        self.session.capabilities()
    }

    /// Get the device facts (hostname, model, version, serial number).
    ///
    /// Returns an empty [`Facts`] if `gather_facts(false)` was used during
    /// connection and [`gather_facts()`](Self::gather_facts) hasn't been
    /// called yet.
    pub fn facts(&self) -> &Facts {
        self.session.facts()
    }

    /// Gather device facts by sending the vendor-specific facts RPC.
    ///
    /// Use this to manually populate facts after connecting with
    /// `gather_facts(false)`. Can also be called to refresh facts.
    pub async fn gather_facts(&mut self) -> Result<(), NetconfError> {
        self.session.gather_facts().await
    }

    /// Check if the session is alive (established and not closed).
    ///
    /// This is a fast in-memory check — it does not send any RPC to the
    /// device. Use this to detect sessions that have been explicitly closed
    /// or marked dead by a failed keepalive probe.
    ///
    /// For a thorough check that verifies the transport is responsive,
    /// see [`probe_session()`](Self::probe_session).
    pub fn session_alive(&self) -> bool {
        self.session.is_alive()
    }

    /// Probe the session by sending a lightweight RPC to verify the
    /// transport is responsive.
    ///
    /// Returns `true` if the device responded, `false` if the probe failed
    /// (in which case the session is marked dead).
    pub async fn probe_session(&mut self) -> bool {
        self.session.probe().await
    }

    /// Re-establish the NETCONF session using the original connection
    /// parameters.
    ///
    /// Closes the current session (if still open) and creates a fresh SSH
    /// connection, performs the hello exchange, and optionally gathers facts
    /// (matching the original `gather_facts` setting).
    ///
    /// This is idempotent — safe to call even if the session is already dead.
    pub async fn reconnect(&mut self) -> Result<(), NetconfError> {
        // Best-effort close of the old session
        let _ = self.session.close_session().await;

        let transport = SshTransport::connect(self.ssh_config.clone()).await?;
        let mut session = Session::new(Box::new(transport));

        if let Some(interval) = self.keepalive_interval {
            session.set_keepalive_interval(interval);
        }

        session.establish().await?;

        if self.gather_facts {
            session.gather_facts().await?;
        }

        self.session = session;

        tracing::info!("NETCONF session reconnected");
        Ok(())
    }

    /// Fetch configuration from a datastore.
    pub async fn get_config(&mut self, source: Datastore) -> Result<String, NetconfError> {
        self.session.get_config(source, None).await
    }

    /// Fetch configuration with a subtree filter.
    pub async fn get_config_filtered(
        &mut self,
        source: Datastore,
        filter: &str,
    ) -> Result<String, NetconfError> {
        self.session.get_config(source, Some(filter)).await
    }

    /// Fetch operational and configuration data.
    pub async fn get(&mut self, filter: Option<&str>) -> Result<String, NetconfError> {
        self.session.get(filter).await
    }

    /// Start building an edit-config operation.
    pub fn edit_config(&mut self, target: Datastore) -> EditConfigBuilder<'_> {
        EditConfigBuilder {
            session: &mut self.session,
            target,
            config: None,
            default_operation: None,
            test_option: None,
            error_option: None,
        }
    }

    /// Lock a datastore.
    pub async fn lock(&mut self, target: Datastore) -> Result<(), NetconfError> {
        self.session.lock(target).await
    }

    /// Unlock a datastore.
    pub async fn unlock(&mut self, target: Datastore) -> Result<(), NetconfError> {
        self.session.unlock(target).await
    }

    /// Discard uncommitted candidate changes.
    pub async fn discard_changes(&mut self) -> Result<(), NetconfError> {
        self.session.discard_changes().await
    }

    /// Commit the candidate configuration.
    pub async fn commit(&mut self) -> Result<(), NetconfError> {
        self.session.commit().await
    }

    /// Validate a datastore.
    pub async fn validate(&mut self, source: Datastore) -> Result<(), NetconfError> {
        self.session.validate(source).await
    }

    /// Close the NETCONF session gracefully.
    pub async fn close_session(&mut self) -> Result<(), NetconfError> {
        self.session.close_session().await
    }

    /// Kill another NETCONF session by ID.
    pub async fn kill_session(&mut self, session_id: u32) -> Result<(), NetconfError> {
        self.session.kill_session(session_id).await
    }

    /// Confirmed commit with automatic rollback timeout.
    ///
    /// The device applies the candidate configuration but automatically
    /// rolls back if [`confirming_commit`](Self::confirming_commit) is not
    /// called within `confirm_timeout` seconds.
    ///
    /// Requires the `:confirmed-commit` capability.
    pub async fn confirmed_commit(&mut self, confirm_timeout: u32) -> Result<(), NetconfError> {
        self.session.confirmed_commit(confirm_timeout).await
    }

    /// Confirm a previous confirmed-commit, making it permanent.
    pub async fn confirming_commit(&mut self) -> Result<(), NetconfError> {
        self.session.confirming_commit().await
    }

    /// Lock a datastore, killing a stale session if the lock is held.
    ///
    /// If the lock is denied because another (possibly crashed) session holds
    /// it, extracts the blocking session-id from the error and kills that
    /// session, then retries the lock.
    ///
    /// Returns `Ok(Some(killed_session_id))` if a stale session was killed,
    /// or `Ok(None)` if the lock was acquired without contention.
    pub async fn lock_or_kill_stale(
        &mut self,
        target: Datastore,
    ) -> Result<Option<u32>, NetconfError> {
        self.session.lock_or_kill_stale(target).await
    }
}

/// Builder for `edit-config` operations.
pub struct EditConfigBuilder<'a> {
    session: &'a mut Session,
    target: Datastore,
    config: Option<String>,
    default_operation: Option<DefaultOperation>,
    test_option: Option<TestOption>,
    error_option: Option<ErrorOption>,
}

impl<'a> EditConfigBuilder<'a> {
    /// Set the configuration XML payload.
    pub fn config(mut self, config: &str) -> Self {
        self.config = Some(config.to_string());
        self
    }

    /// Set the default-operation (merge, replace, none).
    pub fn default_operation(mut self, op: DefaultOperation) -> Self {
        self.default_operation = Some(op);
        self
    }

    /// Set the test-option (test-then-set, set, test-only).
    pub fn test_option(mut self, opt: TestOption) -> Self {
        self.test_option = Some(opt);
        self
    }

    /// Set the error-option (stop-on-error, continue-on-error, rollback-on-error).
    pub fn error_option(mut self, opt: ErrorOption) -> Self {
        self.error_option = Some(opt);
        self
    }

    /// Send the edit-config RPC.
    pub async fn send(self) -> Result<(), NetconfError> {
        let config = self.config.ok_or_else(|| {
            crate::error::ProtocolError::Xml("edit-config requires a config payload".to_string())
        })?;
        self.session
            .edit_config(
                self.target,
                &config,
                self.default_operation,
                self.test_option,
                self.error_option,
            )
            .await
    }
}

/// Parse an address string into (host, port).
///
/// Accepts `"host:port"` or `"host"` (defaults to NETCONF port 830).
fn parse_address(address: &str) -> (String, u16) {
    if let Some((host, port_str)) = address.rsplit_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            return (host.to_string(), port);
        }
    }
    (address.to_string(), 830)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_address_with_port() {
        let (host, port) = parse_address("10.0.0.1:830");
        assert_eq!(host, "10.0.0.1");
        assert_eq!(port, 830);
    }

    #[test]
    fn test_parse_address_without_port() {
        let (host, port) = parse_address("10.0.0.1");
        assert_eq!(host, "10.0.0.1");
        assert_eq!(port, 830);
    }

    #[test]
    fn test_parse_address_hostname() {
        let (host, port) = parse_address("router.example.com:22830");
        assert_eq!(host, "router.example.com");
        assert_eq!(port, 22830);
    }
}
