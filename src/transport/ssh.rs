//! SSH transport implementation using `russh`.
//!
//! Connects to a NETCONF device over SSH, requests the `netconf` subsystem,
//! and provides byte-stream read/write access to the SSH channel.

use async_trait::async_trait;
use russh::client::AuthResult;
use russh::keys::{self, PrivateKeyWithHashAlg};
use russh::*;
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
    /// SSH handles for each jump-host hop, kept alive for the lifetime of
    /// the target session. Dropping a jump handle would tear down the
    /// `direct-tcpip` channel that carries the next hop's transport, so
    /// these must outlive `handle`.
    _jump_handles: Vec<client::Handle<SshHandler>>,
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
    /// Optional ordered list of jump-host hops to tunnel through.
    ///
    /// Each hop has its own host, credentials, and host-key-verification
    /// policy (independent of the target). When empty (the default), a
    /// direct TCP connection is made to `host:port`. When set, an SSH
    /// session is established to each hop in turn, and a `direct-tcpip`
    /// channel is used to carry the next leg — equivalent to OpenSSH's
    /// `ProxyJump h1,h2,h3,...,target`.
    pub jump_hosts: Vec<JumpHostConfig>,
}

/// Configuration for one jump-host hop in a `ProxyJump` chain.
///
/// Each hop carries its own credentials and host-key policy because in
/// the real world the bastion frequently has different access rules than
/// the device behind it (different user, key, fingerprint).
#[derive(Clone)]
pub struct JumpHostConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth: SshAuth,
    pub host_key_verification: HostKeyVerification,
}

/// Internal SSH client handler for russh callbacks.
struct SshHandler {
    host_key_verification: HostKeyVerification,
}

impl client::Handler for SshHandler {
    type Error = russh::Error;

    fn check_server_key(
        &mut self,
        server_public_key: &keys::PublicKey,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        let result = match &self.host_key_verification {
            HostKeyVerification::AcceptAll => {
                tracing::warn!(
                    "accepting SSH host key without verification — \
                     set host_key_verification() for production use"
                );
                Ok(true)
            }
            HostKeyVerification::Fingerprint(expected) => {
                let fingerprint = server_public_key.fingerprint(keys::HashAlg::Sha256);
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
        };
        std::future::ready(result)
    }
}

/// Channel stream wrapper that provides read/write on the SSH channel.
struct ChannelStream {
    channel: Channel<client::Msg>,
    /// Buffered data from the channel that hasn't been consumed yet.
    read_buffer: Vec<u8>,
}

/// Build the russh client config used for every hop and the target.
///
/// Network devices (Juniper, Cisco) often only support ECDH NIST or DH
/// group key exchange — not Curve25519 which is russh's default
/// preference, so we extend the preferred list.
fn build_russh_config() -> client::Config {
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
    client::Config {
        preferred,
        ..Default::default()
    }
}

/// Authenticate an open SSH session against the given username/auth method.
///
/// Used uniformly for jump hosts and the final target.
async fn authenticate(
    handle: &mut client::Handle<SshHandler>,
    username: &str,
    auth: &SshAuth,
) -> Result<(), TransportError> {
    let auth_result = match auth {
        SshAuth::Password(password) => handle
            .authenticate_password(username, password)
            .await
            .map_err(|e| TransportError::Auth(format!("password auth failed: {e}")))?,
        SshAuth::KeyFile { path, passphrase } => {
            let key_path = Path::new(path);
            let key_contents = std::fs::read_to_string(key_path).map_err(|e| {
                tracing::debug!(path, %e, "failed to read key file");
                TransportError::Auth("failed to read SSH key file".to_string())
            })?;
            let key_pair = keys::decode_secret_key(&key_contents, passphrase.as_deref())
                .map_err(|e| {
                    tracing::debug!(%e, "failed to decode key");
                    TransportError::Auth("failed to decode SSH key".to_string())
                })?;
            let hash_alg = handle
                .best_supported_rsa_hash()
                .await
                .unwrap_or(None)
                .flatten();
            let key_with_hash = PrivateKeyWithHashAlg::new(Arc::new(key_pair), hash_alg);
            handle
                .authenticate_publickey(username, key_with_hash)
                .await
                .map_err(|e| TransportError::Auth(format!("key auth failed: {e}")))?
        }
        SshAuth::Agent => {
            let mut agent = keys::agent::client::AgentClient::connect_env()
                .await
                .map_err(|e| TransportError::Auth(format!("SSH agent connect failed: {e}")))?;
            let identities = agent.request_identities().await.map_err(|e| {
                TransportError::Auth(format!("SSH agent identities failed: {e}"))
            })?;

            let mut auth_success = false;
            for identity in identities {
                match handle
                    .authenticate_publickey_with(
                        username,
                        identity.public_key().into_owned(),
                        None,
                        &mut agent,
                    )
                    .await
                {
                    Ok(AuthResult::Success) => {
                        auth_success = true;
                        break;
                    }
                    _ => continue,
                }
            }
            if auth_success {
                AuthResult::Success
            } else {
                AuthResult::Failure {
                    remaining_methods: russh::MethodSet::empty(),
                    partial_success: false,
                }
            }
        }
    };

    if !matches!(auth_result, AuthResult::Success) {
        return Err(TransportError::Auth(format!(
            "authentication failed for user '{username}'"
        )));
    }
    Ok(())
}

impl SshTransport {
    /// Connect to a NETCONF device over SSH and open the `netconf` subsystem.
    ///
    /// If `config.jump_hosts` is non-empty, an SSH session is established to
    /// each hop in turn and a `direct-tcpip` channel is used to carry the
    /// next leg, equivalent to OpenSSH's `ProxyJump h1,h2,...,target`.
    pub async fn connect(config: SshConfig) -> Result<Self, TransportError> {
        let russh_config = Arc::new(build_russh_config());

        // Establish each jump-host hop in sequence. After the loop, `prev`
        // holds the Handle of the last hop (or None for direct connection).
        // We must keep all jump handles alive for the lifetime of the
        // target session — dropping them would tear down the tunneled
        // channels that carry the target session's transport.
        let mut jump_handles: Vec<client::Handle<SshHandler>> = Vec::new();
        let mut prev: Option<&client::Handle<SshHandler>> = None;

        for (idx, hop) in config.jump_hosts.iter().enumerate() {
            let label = format!("jump-host {} ({}:{})", idx, hop.host, hop.port);
            let handle = match prev {
                None => {
                    // First hop: direct TCP connection.
                    let handler = SshHandler {
                        host_key_verification: hop.host_key_verification.clone(),
                    };
                    client::connect(russh_config.clone(), (&*hop.host, hop.port), handler)
                        .await
                        .map_err(|e| {
                            TransportError::Connect(format!("SSH connect to {label} failed: {e}"))
                        })?
                }
                Some(parent) => {
                    // Subsequent hop: tunneled via the previous hop's session.
                    let channel = parent
                        .channel_open_direct_tcpip(&*hop.host, hop.port as u32, "0.0.0.0", 0)
                        .await
                        .map_err(|e| {
                            TransportError::Connect(format!(
                                "direct-tcpip to {label} failed: {e}"
                            ))
                        })?;
                    let stream = channel.into_stream();
                    let handler = SshHandler {
                        host_key_verification: hop.host_key_verification.clone(),
                    };
                    client::connect_stream(russh_config.clone(), stream, handler)
                        .await
                        .map_err(|e| {
                            TransportError::Connect(format!(
                                "SSH handshake with {label} failed: {e}"
                            ))
                        })?
                }
            };

            jump_handles.push(handle);
            prev = Some(jump_handles.last().expect("just pushed"));
        }

        // Authenticate to each jump host in order. Done after the loop above
        // so the borrow of `prev` is released.
        for (idx, hop) in config.jump_hosts.iter().enumerate() {
            let handle = &mut jump_handles[idx];
            authenticate(handle, &hop.username, &hop.auth)
                .await
                .map_err(|e| match e {
                    TransportError::Auth(msg) => TransportError::Auth(format!(
                        "jump-host {} ({}:{}): {msg}",
                        idx, hop.host, hop.port
                    )),
                    other => other,
                })?;
        }

        // Open the final hop to the target — either direct or through the
        // last jump host.
        let target_label = format!("{}:{}", config.host, config.port);
        let mut handle = match jump_handles.last() {
            None => {
                let handler = SshHandler {
                    host_key_verification: config.host_key_verification.clone(),
                };
                client::connect(russh_config.clone(), (&*config.host, config.port), handler)
                    .await
                    .map_err(|e| {
                        TransportError::Connect(format!(
                            "SSH connect to {target_label} failed: {e}"
                        ))
                    })?
            }
            Some(parent) => {
                let channel = parent
                    .channel_open_direct_tcpip(
                        &*config.host,
                        config.port as u32,
                        "0.0.0.0",
                        0,
                    )
                    .await
                    .map_err(|e| {
                        TransportError::Connect(format!(
                            "direct-tcpip to target {target_label} failed: {e}"
                        ))
                    })?;
                let stream = channel.into_stream();
                let handler = SshHandler {
                    host_key_verification: config.host_key_verification.clone(),
                };
                client::connect_stream(russh_config.clone(), stream, handler)
                    .await
                    .map_err(|e| {
                        TransportError::Connect(format!(
                            "SSH handshake with target {target_label} failed: {e}"
                        ))
                    })?
            }
        };

        // Authenticate to the target.
        authenticate(&mut handle, &config.username, &config.auth).await?;

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
            _jump_handles: jump_handles,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_config_default_jump_hosts_is_empty() {
        // Direct connection (no jump hosts) is the default; verify the field
        // exists and constructs cleanly.
        let cfg = SshConfig {
            host: "10.0.0.1".to_string(),
            port: 830,
            username: "u".to_string(),
            auth: SshAuth::Password("p".to_string()),
            host_key_verification: HostKeyVerification::AcceptAll,
            jump_hosts: Vec::new(),
        };
        assert!(cfg.jump_hosts.is_empty());
    }

    #[test]
    fn jump_host_config_constructs_with_independent_creds() {
        // Bastion frequently has different access rules than the device.
        // Verify each hop carries its own credentials and host-key policy.
        let hop = JumpHostConfig {
            host: "bastion.example.com".to_string(),
            port: 22,
            username: "jump-user".to_string(),
            auth: SshAuth::KeyFile {
                path: "/home/me/.ssh/jump_key".to_string(),
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::Fingerprint(
                "SHA256:abc123".to_string(),
            ),
        };
        assert_eq!(hop.host, "bastion.example.com");
        assert_eq!(hop.port, 22);
        assert_eq!(hop.username, "jump-user");
        assert!(matches!(hop.auth, SshAuth::KeyFile { .. }));
        assert!(matches!(
            hop.host_key_verification,
            HostKeyVerification::Fingerprint(_)
        ));
    }

    #[test]
    fn jump_host_config_is_clone() {
        // SshConfig derives Clone (used by ClientBuilder for reconnect),
        // so JumpHostConfig must also be Clone.
        let hop = JumpHostConfig {
            host: "h".to_string(),
            port: 22,
            username: "u".to_string(),
            auth: SshAuth::Agent,
            host_key_verification: HostKeyVerification::AcceptAll,
        };
        let _cloned = hop.clone();
    }

    #[test]
    fn ssh_config_with_multi_hop_chain_clones() {
        // Reconnect support requires SshConfig: Clone, including a chain.
        let hops = vec![
            JumpHostConfig {
                host: "h1".to_string(),
                port: 22,
                username: "u1".to_string(),
                auth: SshAuth::Agent,
                host_key_verification: HostKeyVerification::AcceptAll,
            },
            JumpHostConfig {
                host: "h2".to_string(),
                port: 22,
                username: "u2".to_string(),
                auth: SshAuth::Agent,
                host_key_verification: HostKeyVerification::AcceptAll,
            },
        ];
        let cfg = SshConfig {
            host: "target".to_string(),
            port: 830,
            username: "u".to_string(),
            auth: SshAuth::Agent,
            host_key_verification: HostKeyVerification::AcceptAll,
            jump_hosts: hops,
        };
        let cloned = cfg.clone();
        assert_eq!(cloned.jump_hosts.len(), 2);
        assert_eq!(cloned.jump_hosts[0].host, "h1");
        assert_eq!(cloned.jump_hosts[1].host, "h2");
    }
}
