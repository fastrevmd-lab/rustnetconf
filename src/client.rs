//! Thin ergonomic client wrapper over `Session`.
//!
//! `Client` provides builder-pattern connection setup and delegates all
//! protocol operations to the underlying `Session`. It owns no protocol state.

use std::time::Duration;

use crate::capability::Capabilities;
use crate::error::NetconfError;
use crate::facts::Facts;
use crate::notification::Notification;
use crate::session::Session;
use crate::transport::Transport;
use crate::transport::ssh::{HostKeyVerification, JumpHostConfig, SshAuth, SshConfig, SshTransport};
use crate::ssh_config::{SshConfigError, SshConfigFile};
use std::path::Path;
#[cfg(feature = "tls")]
use crate::transport::tls::{TlsConfig, TlsTransport};
use crate::rpc::RpcErrorInfo;
use crate::types::{Datastore, DefaultOperation, ErrorOption, LoadAction, LoadFormat, OpenConfigurationMode, TestOption};
use crate::vendor::VendorProfile;

/// Internal enum to store the transport configuration for reconnect support.
#[derive(Clone)]
enum TransportConfig {
    Ssh(SshConfig),
    #[cfg(feature = "tls")]
    Tls(TlsConfig),
}

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
    jump_hosts: Vec<JumpHostConfig>,
    proxy_command: Option<String>,
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

    /// Set the ordered list of SSH jump hosts (`ProxyJump` chain) to tunnel
    /// through before reaching the target.
    ///
    /// Each hop carries its own credentials and host-key-verification policy
    /// because in the real world the bastion frequently has different access
    /// rules than the device behind it (different user, key, fingerprint).
    /// The hops are dialed in order: hop 0 directly, hop 1 through hop 0's
    /// `direct-tcpip`, etc., and the final target through the last hop.
    ///
    /// Equivalent to OpenSSH's `ProxyJump h1,h2,...,target`. When empty (the
    /// default), a direct TCP connection is made to the target.
    pub fn jump_hosts(mut self, hops: Vec<JumpHostConfig>) -> Self {
        self.jump_hosts = hops;
        self
    }

    /// Set an OpenSSH-style `ProxyCommand`.
    ///
    /// The command is interpreted by `sh -c` and its stdin/stdout become
    /// the SSH transport stream to the target. The substrings `%h` and
    /// `%p` are replaced with the target host and port respectively.
    ///
    /// Mutually exclusive with [`Self::jump_hosts`] — setting both causes
    /// the connection to fail.
    ///
    /// **Security:** the command runs in a shell. The `%h` and `%p` values
    /// are shell-escaped before substitution. The command template itself
    /// is not escaped — callers are responsible for its safety.
    ///
    /// # Examples
    /// ```rust,no_run
    /// use rustnetconf::Client;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::connect("device.internal:830")
    ///     .username("admin")
    ///     .ssh_agent()
    ///     .proxy_command("ssh -W %h:%p bastion.example.com")
    ///     .connect()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn proxy_command(mut self, command: &str) -> Self {
        self.proxy_command = Some(command.to_string());
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
            jump_hosts: self.jump_hosts,
            proxy_command: self.proxy_command,
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
            transport_config: TransportConfig::Ssh(config),
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
    /// Stored transport config for reconnect support.
    transport_config: TransportConfig,
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
            jump_hosts: Vec::new(),
            proxy_command: None,
        }
    }

    /// Create a connection builder by resolving `alias` against the user's
    /// default SSH config (`$HOME/.ssh/config`).
    ///
    /// Settings derived from the config:
    ///
    /// - `HostName` → connect target (falls back to `alias` if unset)
    /// - `Port` → port (falls back to NETCONF default 830)
    /// - `User` → [`ClientBuilder::username`]
    /// - `IdentityFile` → [`ClientBuilder::key_file`]
    /// - `ProxyJump` → [`ClientBuilder::jump_hosts`]
    /// - `ProxyCommand` → [`ClientBuilder::proxy_command`]
    ///
    /// The returned builder is fully customisable — additional
    /// `.username()`, `.password()`, `.host_key_verification(...)` calls
    /// override what the config provided.
    ///
    /// # Examples
    /// ```rust,no_run
    /// use rustnetconf::Client;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // ~/.ssh/config has `Host edge-r1` block with HostName/User/ProxyJump.
    /// let client = Client::connect_via_ssh_config("edge-r1")?
    ///     .ssh_agent()
    ///     .connect()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn connect_via_ssh_config(alias: &str) -> Result<ClientBuilder, SshConfigError> {
        let path = default_ssh_config_path().ok_or_else(|| SshConfigError::Io {
            path: std::path::PathBuf::from("~/.ssh/config"),
            source: std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "$HOME is not set; cannot locate default ssh config",
            ),
        })?;
        Self::connect_via_ssh_config_at(&path, alias)
    }

    /// Like [`Self::connect_via_ssh_config`] but reads from the explicit
    /// `path` instead of `$HOME/.ssh/config`.
    pub fn connect_via_ssh_config_at(
        path: &Path,
        alias: &str,
    ) -> Result<ClientBuilder, SshConfigError> {
        let cfg = SshConfigFile::load(path)?;
        let resolved = cfg.resolve(alias);

        let host = resolved.hostname.unwrap_or_else(|| alias.to_string());
        // NETCONF default is 830, not 22.
        let port = resolved.port.unwrap_or(830);

        let mut builder = Self::connect(&format!("{host}:{port}"));
        builder.username = resolved.user;
        builder.key_file = resolved.identity_file;
        builder.jump_hosts = resolved.jump_hosts;
        builder.proxy_command = resolved.proxy_command;
        Ok(builder)
    }

    /// Create a TLS connection builder for NETCONF over TLS (RFC 7589).
    ///
    /// # Examples
    /// ```rust,no_run
    /// use rustnetconf::Client;
    /// use rustnetconf::TlsConfig;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = TlsConfig {
    ///     host: "10.0.0.1".into(),
    ///     ca_cert: Some("ca.pem".into()),
    ///     client_cert: Some("client.pem".into()),
    ///     client_key: Some("client-key.pem".into()),
    ///     ..Default::default()
    /// };
    /// let mut client = Client::connect_tls(config).connect().await?;
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "tls")]
    pub fn connect_tls(config: TlsConfig) -> TlsClientBuilder {
        TlsClientBuilder {
            tls_config: config,
            vendor_profile: None,
            gather_facts: true,
            keepalive_interval: None,
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

        let transport: Box<dyn Transport> = match &self.transport_config {
            TransportConfig::Ssh(config) => {
                Box::new(SshTransport::connect(config.clone()).await?)
            }
            #[cfg(feature = "tls")]
            TransportConfig::Tls(config) => {
                Box::new(TlsTransport::connect(config).await?)
            }
        };
        let mut session = Session::new(transport);

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

    // ── Junos-specific operations ────────────────────────────────────

    /// Send an arbitrary RPC, returning both the response and any warnings.
    ///
    /// Like [`rpc()`](Self::rpc), but returns warnings alongside the data.
    pub async fn rpc_with_warnings(
        &mut self,
        rpc_content: &str,
    ) -> Result<(String, Vec<RpcErrorInfo>), NetconfError> {
        self.session.rpc_with_warnings(rpc_content).await
    }

    /// Open a private or exclusive configuration database (Junos).
    ///
    /// Required on chassis-clustered Junos devices before loading
    /// configuration. On standalone devices this is optional but harmless.
    pub async fn open_configuration(
        &mut self,
        mode: OpenConfigurationMode,
    ) -> Result<(), NetconfError> {
        self.session.open_configuration(mode).await
    }

    /// Close a previously opened configuration database (Junos).
    pub async fn close_configuration(&mut self) -> Result<(), NetconfError> {
        self.session.close_configuration().await
    }

    /// Commit using the Junos-native `<commit-configuration/>` RPC.
    ///
    /// Use this instead of [`commit()`](Self::commit) on Junos devices,
    /// especially when a private/exclusive configuration database is open.
    pub async fn commit_configuration(&mut self) -> Result<(), NetconfError> {
        self.session.commit_configuration().await
    }

    /// Rollback the candidate configuration to a previous commit (Junos).
    ///
    /// `rollback` is the rollback index (0 = most recent commit, up to 49).
    pub async fn rollback_configuration(&mut self, rollback: u32) -> Result<(), NetconfError> {
        self.session.rollback_configuration(rollback).await
    }

    /// Get the diff between candidate and a previous commit (Junos).
    ///
    /// Returns the text-format diff. `rollback` is the rollback index
    /// (0 = most recent commit).
    pub async fn get_configuration_compare(
        &mut self,
        rollback: u32,
    ) -> Result<String, NetconfError> {
        self.session.get_configuration_compare(rollback).await
    }

    /// Load configuration using the Junos `<load-configuration>` RPC.
    ///
    /// On chassis-clustered devices, call
    /// [`open_configuration()`](Self::open_configuration) first.
    pub async fn load_configuration(
        &mut self,
        action: LoadAction,
        format: LoadFormat,
        config: &str,
    ) -> Result<String, NetconfError> {
        self.session.load_configuration(action, format, config).await
    }

    /// Whether this device requires `<open-configuration>` before loading config.
    ///
    /// Returns `true` for Junos chassis-clustered devices.
    pub fn requires_open_configuration(&self) -> bool {
        self.session.requires_open_configuration()
    }

    // ── Notification operations (RFC 5277) ───────────────────────────

    /// Create a notification subscription (RFC 5277).
    ///
    /// Requires the `:notification` capability. After subscription, the device
    /// sends `<notification>` messages asynchronously. Retrieve them with
    /// [`drain_notifications()`](Self::drain_notifications) or
    /// [`recv_notification()`](Self::recv_notification).
    pub async fn create_subscription(
        &mut self,
        stream: Option<&str>,
        filter: Option<&str>,
        start_time: Option<&str>,
        stop_time: Option<&str>,
    ) -> Result<(), NetconfError> {
        self.session
            .create_subscription(stream, filter, start_time, stop_time)
            .await
    }

    /// Drain all buffered notifications, returning them and clearing the buffer.
    ///
    /// Notifications are buffered when they arrive during RPC exchanges.
    pub fn drain_notifications(&mut self) -> Vec<Notification> {
        self.session.drain_notifications()
    }

    /// Wait for the next notification from the device.
    ///
    /// Returns `Ok(None)` if the connection is closed.
    pub async fn recv_notification(&mut self) -> Result<Option<Notification>, NetconfError> {
        self.session.recv_notification().await
    }

    /// Check if any notifications are buffered without blocking.
    pub fn has_notifications(&self) -> bool {
        self.session.has_notifications()
    }

    /// Whether this session has an active notification subscription.
    pub fn has_subscription(&self) -> bool {
        self.session.has_subscription()
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

/// Builder for establishing a NETCONF client connection over TLS (RFC 7589).
///
/// Created via [`Client::connect_tls()`]. Supports both server-only and
/// mutual TLS authentication via certificate configuration in [`TlsConfig`].
#[cfg(feature = "tls")]
pub struct TlsClientBuilder {
    tls_config: TlsConfig,
    vendor_profile: Option<Box<dyn VendorProfile>>,
    gather_facts: bool,
    keepalive_interval: Option<Duration>,
}

#[cfg(feature = "tls")]
impl TlsClientBuilder {
    /// Set an explicit vendor profile, overriding auto-detection.
    pub fn vendor_profile(mut self, profile: Box<dyn VendorProfile>) -> Self {
        self.vendor_profile = Some(profile);
        self
    }

    /// Control whether device facts are gathered after connecting.
    pub fn gather_facts(mut self, gather: bool) -> Self {
        self.gather_facts = gather;
        self
    }

    /// Set a keepalive interval for automatic session health checks.
    pub fn keepalive_interval(mut self, interval: Duration) -> Self {
        self.keepalive_interval = Some(interval);
        self
    }

    /// Establish the TLS connection and perform the NETCONF hello exchange.
    pub async fn connect(self) -> Result<Client, NetconfError> {
        let transport = TlsTransport::connect(&self.tls_config).await?;
        let mut session = Session::new(Box::new(transport));

        if let Some(interval) = self.keepalive_interval {
            session.set_keepalive_interval(interval);
        }

        if let Some(profile) = self.vendor_profile {
            session.set_vendor_profile(profile);
        }

        session.establish().await?;

        if self.gather_facts {
            session.gather_facts().await?;
        }

        Ok(Client {
            session,
            transport_config: TransportConfig::Tls(self.tls_config),
            gather_facts: self.gather_facts,
            keepalive_interval: self.keepalive_interval,
        })
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

/// Locate the user's default SSH config (`$HOME/.ssh/config`). Returns
/// `None` if `$HOME` is unset.
fn default_ssh_config_path() -> Option<std::path::PathBuf> {
    std::env::var("HOME")
        .ok()
        .map(|home| std::path::PathBuf::from(home).join(".ssh").join("config"))
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

    #[test]
    fn ssh_config_alias_populates_builder_fields() {
        // End-to-end: write a config, load it via the public API, verify
        // every config-derived field landed in the builder.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config");
        std::fs::write(
            &path,
            "Host edge-r1\n  \
               HostName 10.42.0.1\n  \
               Port 2830\n  \
               User netops\n  \
               IdentityFile /tmp/keys/lab\n  \
               ProxyJump admin@bastion:2222,h2\n",
        )
        .unwrap();

        let builder = Client::connect_via_ssh_config_at(&path, "edge-r1").unwrap();
        assert_eq!(builder.host, "10.42.0.1");
        assert_eq!(builder.port, 2830);
        assert_eq!(builder.username.as_deref(), Some("netops"));
        assert_eq!(builder.key_file.as_deref(), Some("/tmp/keys/lab"));
        assert_eq!(builder.jump_hosts.len(), 2);
        assert_eq!(builder.jump_hosts[0].host, "bastion");
        assert_eq!(builder.jump_hosts[0].username, "admin");
        assert_eq!(builder.jump_hosts[0].port, 2222);
        assert_eq!(builder.jump_hosts[1].host, "h2");
        assert!(builder.proxy_command.is_none());
    }

    #[test]
    fn ssh_config_alias_falls_back_to_alias_when_hostname_unset() {
        // No HostName directive → fall back to the alias as the connect
        // target. NETCONF default port (830) when no Port directive.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config");
        std::fs::write(&path, "Host bare\n  User someone\n").unwrap();

        let builder = Client::connect_via_ssh_config_at(&path, "bare").unwrap();
        assert_eq!(builder.host, "bare");
        assert_eq!(builder.port, 830);
        assert_eq!(builder.username.as_deref(), Some("someone"));
    }

    #[test]
    fn ssh_config_alias_unmatched_alias_yields_minimal_builder() {
        // Alias not in config → still works, with bare alias as host and
        // no auth settings derived. Caller must populate auth manually.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config");
        std::fs::write(&path, "Host other\n  User x\n").unwrap();

        let builder = Client::connect_via_ssh_config_at(&path, "unknown").unwrap();
        assert_eq!(builder.host, "unknown");
        assert_eq!(builder.port, 830);
        assert!(builder.username.is_none());
        assert!(builder.key_file.is_none());
        assert!(builder.jump_hosts.is_empty());
        assert!(builder.proxy_command.is_none());
    }

    #[test]
    fn ssh_config_alias_proxy_command_passes_through() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config");
        std::fs::write(
            &path,
            "Host r1\n  \
               HostName 10.0.0.1\n  \
               ProxyCommand ssh -W %h:%p bastion.example.com\n",
        )
        .unwrap();

        let builder = Client::connect_via_ssh_config_at(&path, "r1").unwrap();
        assert_eq!(
            builder.proxy_command.as_deref(),
            Some("ssh -W %h:%p bastion.example.com")
        );
    }

    #[test]
    fn ssh_config_alias_missing_file_returns_error() {
        let err = match Client::connect_via_ssh_config_at(Path::new("/nonexistent/xyz"), "any") {
            Err(e) => e,
            Ok(_) => panic!("expected error for missing config file"),
        };
        assert!(matches!(err, SshConfigError::Io { .. }));
    }
}
