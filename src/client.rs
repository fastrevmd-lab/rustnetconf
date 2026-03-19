//! Thin ergonomic client wrapper over `Session`.
//!
//! `Client` provides builder-pattern connection setup and delegates all
//! protocol operations to the underlying `Session`. It owns no protocol state.

use crate::capability::Capabilities;
use crate::error::NetconfError;
use crate::session::Session;
use crate::transport::ssh::{SshAuth, SshConfig, SshTransport};
use crate::types::{Datastore, DefaultOperation, ErrorOption, TestOption};

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
        };

        let transport = SshTransport::connect(config).await?;
        let mut session = Session::new(Box::new(transport));
        session.establish().await?;

        Ok(Client { session })
    }
}

/// An async NETCONF client.
///
/// Created via [`Client::connect()`]. All operations are delegated to the
/// underlying [`Session`] which owns all protocol state.
pub struct Client {
    session: Session,
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
        }
    }

    /// Check if the device supports a specific capability URI.
    pub fn supports(&self, capability_uri: &str) -> bool {
        self.session.supports(capability_uri)
    }

    /// Get the device's capabilities.
    pub fn capabilities(&self) -> Option<&Capabilities> {
        self.session.capabilities()
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
