//! SSH transport implementation using `russh`.
//!
//! Connects to a NETCONF device over SSH, requests the `netconf` subsystem,
//! and provides byte-stream read/write access to the SSH channel.

use async_trait::async_trait;
use russh::*;
use russh_keys::*;
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

/// Configuration for establishing an SSH transport.
pub struct SshConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth: SshAuth,
}

/// Internal SSH client handler for russh callbacks.
struct SshHandler;

#[async_trait]
impl client::Handler for SshHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        // Accept all host keys for now.
        // TODO: Add host key verification (known_hosts support).
        Ok(true)
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
        let russh_config = client::Config::default();

        let handler = SshHandler;
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
                        .map_err(|e| TransportError::Auth(format!("failed to read key file {path}: {e}")))?, Some(pass))
                        .map_err(|e| TransportError::Auth(format!("failed to decode key: {e}")))?
                } else {
                    decode_secret_key(&std::fs::read_to_string(key_path)
                        .map_err(|e| TransportError::Auth(format!("failed to read key file {path}: {e}")))?, None)
                        .map_err(|e| TransportError::Auth(format!("failed to decode key: {e}")))?
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
        let channel = handle
            .channel_open_session()
            .await
            .map_err(|e| TransportError::Channel(format!("failed to open SSH channel: {e}")))?;

        channel
            .request_subsystem(true, "netconf")
            .await
            .map_err(|e| TransportError::Channel(format!("failed to request netconf subsystem: {e}")))?;

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
            .data(&data[..])
            .await
            .map_err(|e| TransportError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;
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

        // Read from the SSH channel
        match channel.channel.wait().await {
            Some(ChannelMsg::Data { data: channel_data }) => {
                let bytes = &channel_data[..];
                let to_copy = std::cmp::min(buf.len(), bytes.len());
                buf[..to_copy].copy_from_slice(&bytes[..to_copy]);
                if bytes.len() > to_copy {
                    channel.read_buffer.extend_from_slice(&bytes[to_copy..]);
                }
                Ok(to_copy)
            }
            Some(ChannelMsg::Eof) | None => Ok(0),
            Some(_) => {
                // Other channel messages (e.g., extended data) — skip and retry
                Ok(0)
            }
        }
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        let channel = self.channel.lock().await;
        channel
            .channel
            .eof()
            .await
            .map_err(|e| TransportError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;
        let handle = self.handle.lock().await;
        handle
            .disconnect(Disconnect::ByApplication, "closing session", "en")
            .await
            .map_err(|e| TransportError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;
        Ok(())
    }
}
