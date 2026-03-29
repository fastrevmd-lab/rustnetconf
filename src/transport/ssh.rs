//! SSH transport implementation using `russh`.
//!
//! Connects to a NETCONF device over SSH, requests the `netconf` subsystem,
//! and provides byte-stream read/write access to the SSH channel.

use async_trait::async_trait;
use russh::*;
use russh_keys::*;
use std::borrow::Cow;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::error::TransportError;
use crate::transport::Transport;

/// SSH transport for NETCONF sessions.
pub struct SshTransport {
    channel: Arc<Mutex<ChannelStream>>,
    handle: Arc<Mutex<client::Handle<SshHandler>>>,
}

/// SSH authentication method.
#[derive(Clone)]
pub enum SshAuth {
    /// Password authentication.
    Password(String),
    /// Key file authentication (path to private key, optional passphrase).
    KeyFile {
        path: String,
        passphrase: Option<String>,
    },
    /// SSH agent authentication.
    Agent,
}

/// SSH host key verification policy.
///
/// Controls how the client validates the device's SSH host key during
/// connection. Use this to protect against man-in-the-middle attacks.
#[derive(Clone, Debug, Default)]
pub enum HostKeyVerification {
    /// Accept all host keys without verification (**INSECURE**).
    ///
    /// Suitable for lab environments, testing, or initial device provisioning.
    /// A warning is logged when this mode is used.
    #[default]
    AcceptAll,

    /// Accept only a host key matching a specific SHA-256 fingerprint.
    ///
    /// The fingerprint can be provided with or without the `SHA256:` prefix
    /// (e.g., `"SHA256:abc123..."` or just `"abc123..."`).
    ///
    /// Obtain the fingerprint with: `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`
    Fingerprint(String),

    /// Reject all host keys (useful for testing error paths).
    RejectAll,
}

/// Configuration for establishing an SSH transport.
#[derive(Clone)]
pub struct SshConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth: SshAuth,
    /// Host key verification policy.
    pub host_key_verification: HostKeyVerification,
}

/// Internal SSH client handler for russh callbacks.
struct SshHandler {
    host_key_verification: HostKeyVerification,
}

#[async_trait]
impl client::Handler for SshHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        match &self.host_key_verification {
            HostKeyVerification::AcceptAll => {
                tracing::warn!(
                    "accepting SSH host key without verification — \
                     set host_key_verification() for production use"
                );
                Ok(true)
            }
            HostKeyVerification::Fingerprint(expected) => {
                let fingerprint = server_public_key.fingerprint(ssh_key::HashAlg::Sha256);
                let actual = fingerprint.to_string();
                // Allow comparison with or without "SHA256:" prefix
                let matches = actual == *expected
                    || actual
                        .strip_prefix("SHA256:")
                        .is_some_and(|stripped| stripped == expected);
                if matches {
                    tracing::debug!("SSH host key fingerprint verified");
                    Ok(true)
                } else {
                    tracing::error!(
                        expected = %expected,
                        actual = %actual,
                        "SSH host key fingerprint mismatch — possible MITM attack"
                    );
                    Ok(false)
                }
            }
            HostKeyVerification::RejectAll => {
                tracing::error!("SSH host key rejected (RejectAll policy)");
                Ok(false)
            }
        }
    }
}

/// Channel stream wrapper that provides read/write on the SSH channel.
struct ChannelStream {
    channel: Channel<client::Msg>,
    /// Buffered data from the channel that hasn't been consumed yet.
    read_buffer: Vec<u8>,
}

impl SshTransport {
    /// Connect to a NETCONF device over SSH and open the `netconf` subsystem.
    pub async fn connect(config: SshConfig) -> Result<Self, TransportError> {
        // Build SSH config with broad algorithm support for network devices.
        // Many devices (Juniper, Cisco) only support ECDH NIST or DH group
        // key exchange — not Curve25519 which is russh's default preference.
        let preferred = Preferred {
            kex: Cow::Borrowed(&[
                kex::CURVE25519,
                kex::CURVE25519_PRE_RFC_8731,
                kex::ECDH_SHA2_NISTP256,
                kex::ECDH_SHA2_NISTP384,
                kex::ECDH_SHA2_NISTP521,
                kex::DH_G16_SHA512,
                kex::DH_G14_SHA256,
                kex::EXTENSION_SUPPORT_AS_CLIENT,
                kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
            ]),
            ..Preferred::default()
        };

        let russh_config = client::Config {
            preferred,
            ..Default::default()
        };

        let handler = SshHandler {
            host_key_verification: config.host_key_verification.clone(),
        };
        let mut handle = client::connect(Arc::new(russh_config), (&*config.host, config.port), handler)
            .await
            .map_err(|e| TransportError::Connect(format!("SSH connect to {}:{} failed: {e}", config.host, config.port)))?;

        // Authenticate
        let auth_result = match &config.auth {
            SshAuth::Password(password) => {
                handle
                    .authenticate_password(&config.username, password)
                    .await
                    .map_err(|e| TransportError::Auth(format!("password auth failed: {e}")))?
            }
            SshAuth::KeyFile { path, passphrase } => {
                let key_path = Path::new(path);
                let key_pair = if let Some(pass) = passphrase {
                    decode_secret_key(&std::fs::read_to_string(key_path)
                        .map_err(|e| {
                            tracing::debug!(path, %e, "failed to read key file");
                            TransportError::Auth("failed to read SSH key file".to_string())
                        })?, Some(pass))
                        .map_err(|e| {
                            tracing::debug!(%e, "failed to decode key");
                            TransportError::Auth("failed to decode SSH key".to_string())
                        })?
                } else {
                    decode_secret_key(&std::fs::read_to_string(key_path)
                        .map_err(|e| {
                            tracing::debug!(path, %e, "failed to read key file");
                            TransportError::Auth("failed to read SSH key file".to_string())
                        })?, None)
                        .map_err(|e| {
                            tracing::debug!(%e, "failed to decode key");
                            TransportError::Auth("failed to decode SSH key".to_string())
                        })?
                };
                handle
                    .authenticate_publickey(&config.username, Arc::new(key_pair))
                    .await
                    .map_err(|e| TransportError::Auth(format!("key auth failed: {e}")))?
            }
            SshAuth::Agent => {
                let mut agent = russh_keys::agent::client::AgentClient::connect_env()
                    .await
                    .map_err(|e| TransportError::Auth(format!("SSH agent connect failed: {e}")))?;
                let identities = agent
                    .request_identities()
                    .await
                    .map_err(|e| TransportError::Auth(format!("SSH agent identities failed: {e}")))?;

                let mut authenticated = false;
                for identity in identities {
                    match handle
                        .authenticate_publickey_with(&config.username, identity, &mut agent)
                        .await
                    {
                        Ok(true) => {
                            authenticated = true;
                            break;
                        }
                        _ => continue,
                    }
                }
                authenticated
            }
        };

        if !auth_result {
            return Err(TransportError::Auth(format!(
                "authentication failed for user '{}'",
                config.username
            )));
        }

        // Open a session channel and request the netconf subsystem
        let mut channel = handle
            .channel_open_session()
            .await
            .map_err(|e| TransportError::Channel(format!("failed to open SSH channel: {e}")))?;

        channel
            .request_subsystem(true, "netconf")
            .await
            .map_err(|e| TransportError::Channel(format!("failed to request netconf subsystem: {e}")))?;

        // Wait for the subsystem confirmation from the server.
        // When `want_reply` is true, the server sends Success or Failure.
        // We must consume channel messages (e.g., WindowAdjusted) until
        // we see the confirmation, otherwise these messages interfere
        // with the first data read (the hello exchange).
        loop {
            match channel.wait().await {
                Some(ChannelMsg::Success) => break,
                Some(ChannelMsg::Failure) => {
                    return Err(TransportError::Channel(
                        "server rejected netconf subsystem request".to_string(),
                    ));
                }
                Some(ChannelMsg::WindowAdjusted { .. }) => {
                    // Expected — the server adjusts the window; keep waiting.
                    continue;
                }
                Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => {
                    return Err(TransportError::ChannelClosed(
                        "channel closed before subsystem confirmation".to_string(),
                    ));
                }
                Some(_other) => {
                    // Other messages (e.g., ExtendedData) — skip.
                    continue;
                }
            }
        }

        let channel_stream = ChannelStream {
            channel,
            read_buffer: Vec::new(),
        };

        Ok(Self {
            channel: Arc::new(Mutex::new(channel_stream)),
            handle: Arc::new(Mutex::new(handle)),
        })
    }
}

#[async_trait]
impl Transport for SshTransport {
    async fn write_all(&mut self, data: &[u8]) -> Result<(), TransportError> {
        let channel = self.channel.lock().await;
        channel
            .channel
            .data(data)
            .await
            .map_err(|e| TransportError::Io(std::io::Error::other(e.to_string())))?;
        Ok(())
    }

    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, TransportError> {
        let mut channel = self.channel.lock().await;

        // First, drain any buffered data
        if !channel.read_buffer.is_empty() {
            let to_read = std::cmp::min(buf.len(), channel.read_buffer.len());
            buf[..to_read].copy_from_slice(&channel.read_buffer[..to_read]);
            channel.read_buffer.drain(..to_read);
            return Ok(to_read);
        }

        // Read from the SSH channel, skipping non-data messages.
        // Messages like WindowAdjusted, Success, ExtendedData (stderr)
        // can arrive at any time and must not be treated as EOF.
        loop {
            match channel.channel.wait().await {
                Some(ChannelMsg::Data { data: channel_data }) => {
                    let bytes = &channel_data[..];
                    let to_copy = std::cmp::min(buf.len(), bytes.len());
                    buf[..to_copy].copy_from_slice(&bytes[..to_copy]);
                    if bytes.len() > to_copy {
                        channel.read_buffer.extend_from_slice(&bytes[to_copy..]);
                    }
                    return Ok(to_copy);
                }
                Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => {
                    return Ok(0);
                }
                Some(_other) => {
                    // WindowAdjusted, Success, ExtendedData, etc. — skip and keep waiting.
                    continue;
                }
            }
        }
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        let channel = self.channel.lock().await;
        channel
            .channel
            .eof()
            .await
            .map_err(|e| TransportError::Io(std::io::Error::other(e.to_string())))?;
        let handle = self.handle.lock().await;
        handle
            .disconnect(Disconnect::ByApplication, "closing session", "en")
            .await
            .map_err(|e| TransportError::Io(std::io::Error::other(e.to_string())))?;
        Ok(())
    }
}
