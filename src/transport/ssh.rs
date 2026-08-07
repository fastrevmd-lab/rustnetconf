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
use std::pin::Pin;
use std::process::Stdio;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::process::{Child, ChildStdin, ChildStdout};

use zeroize::Zeroizing;

use crate::error::TransportError;
use crate::transport::Transport;

/// SSH transport for NETCONF sessions.
pub struct SshTransport {
    channel: ChannelStream,
    handle: client::Handle<SshHandler>,
    /// SSH handles for each jump-host hop, kept alive for the lifetime of
    /// the target session. Dropping a jump handle would tear down the
    /// `direct-tcpip` channel that carries the next hop's transport, so
    /// these must outlive `handle`.
    _jump_handles: Vec<client::Handle<SshHandler>>,
    /// `ProxyCommand` subprocess (if any), kept alive for the lifetime of
    /// the target session. Dropping the `Child` would close its stdin/stdout
    /// pipes, tearing down the SSH transport stream that runs over them.
    _proxy_process: Option<Child>,
}

/// SSH authentication method.
///
/// Sensitive fields (passwords, passphrases) use [`Zeroizing<String>`] so
/// the memory is overwritten on drop, reducing the window for credential
/// leakage via memory dumps.
#[derive(Clone)]
pub enum SshAuth {
    /// Password authentication.
    Password(Zeroizing<String>),
    /// Key file authentication (path to private key, optional passphrase).
    KeyFile {
        path: String,
        passphrase: Option<Zeroizing<String>>,
    },
    /// SSH agent authentication.
    Agent,
}

/// SSH host key verification policy.
///
/// Controls how the client validates the device's SSH host key during
/// connection. Use this to protect against man-in-the-middle attacks.
///
/// Default for [`crate::ClientBuilder`]: [`HostKeyVerification::RejectAll`]
/// (fail closed). Callers must explicitly choose a policy via
/// [`crate::ClientBuilder::host_key_verification`] for connections to
/// succeed in production.
#[derive(Clone, Debug)]
pub enum HostKeyVerification {
    /// Accept all host keys without verification (**INSECURE**).
    ///
    /// Suitable for lab environments, testing, or initial device provisioning.
    /// A warning is logged when this mode is used. Never use in production.
    AcceptAll,

    /// Accept only a host key matching a specific SHA-256 fingerprint.
    ///
    /// The fingerprint can be provided with or without the `SHA256:` prefix
    /// (e.g., `"SHA256:abc123..."` or just `"abc123..."`).
    ///
    /// Obtain the fingerprint with: `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`
    Fingerprint(String),

    /// Reject every host key — fail closed.
    ///
    /// This is the default for [`crate::ClientBuilder`]. Connections will
    /// fail until the caller explicitly chooses [`Self::Fingerprint`] (for
    /// production) or [`Self::AcceptAll`] (for labs/testing).
    ///
    /// Also useful in tests to exercise error paths.
    RejectAll,

    /// Validate the device's host key against entries in an OpenSSH-format
    /// `known_hosts` file.
    ///
    /// On connect, the host (and port if non-default) is looked up in the
    /// file. A SHA-256 fingerprint match accepts the key; mismatch, missing
    /// entry, or `@revoked` marker fails closed with a structured
    /// [`crate::error::TransportError`] variant
    /// ([`HostKeyMismatch`](crate::error::TransportError::HostKeyMismatch),
    /// [`HostKeyNotInKnownHosts`](crate::error::TransportError::HostKeyNotInKnownHosts),
    /// or [`HostKeyRevoked`](crate::error::TransportError::HostKeyRevoked)).
    ///
    /// Supported file features: plain hostnames, comma-separated host lists,
    /// `[host]:port` form, wildcards (`*`, `?`), CIDR networks, hashed
    /// entries (`|1|salt|hmac`), and `@revoked` markers. Pre-populate with
    /// `ssh-keyscan -t ed25519,rsa,ecdsa <host>` (add `-H` for hashed,
    /// `-p <port>` for non-default ports).
    ///
    /// `@cert-authority` lines are silently skipped (SSH host certs not yet
    /// supported).
    KnownHosts(std::path::PathBuf),
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
    /// Optional shell command to spawn whose stdin/stdout become the
    /// transport stream to the target — equivalent to OpenSSH's
    /// `ProxyCommand`. The substrings `%h` and `%p` are replaced with the
    /// target host and port respectively.
    ///
    /// Mutually exclusive with `jump_hosts`. If both are set,
    /// [`SshTransport::connect`] returns
    /// [`TransportError::Connect`]. Use one or the other to reach a host.
    ///
    /// **Security:** the command is interpreted by `sh -c` to support
    /// pipelines and shell features. The `%h` and `%p` values are
    /// shell-escaped (single-quoted) before substitution to prevent
    /// injection. The command template itself is not escaped — the
    /// caller is responsible for its safety.
    pub proxy_command: Option<String>,
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

/// Slot for surfacing structured host-key errors from inside the russh
/// callback to the outer `connect()` call.
///
/// `check_server_key` can only return `Result<bool, russh::Error>` — there's
/// no way to thread our own error type through. When `KnownHosts` policy
/// rejects, we record the structured error here; after `client::connect`
/// fails with a generic auth/key error, the caller swaps in this error.
#[derive(Clone, Default)]
struct HostKeyErrorSlot(Arc<std::sync::Mutex<Option<TransportError>>>);

impl HostKeyErrorSlot {
    fn set(&self, err: TransportError) {
        if let Ok(mut guard) = self.0.lock() {
            *guard = Some(err);
        }
    }

    fn take(&self) -> Option<TransportError> {
        self.0.lock().ok().and_then(|mut g| g.take())
    }
}

/// Internal SSH client handler for russh callbacks.
struct SshHandler {
    host_key_verification: HostKeyVerification,
    /// Host this handler is verifying — used for known_hosts lookup and
    /// for structured error messages.
    host: String,
    port: u16,
    /// Shared slot to surface structured rejection errors back to the
    /// outer connect call. Cloned `Arc` so it's visible after the handler
    /// is moved into `client::connect`.
    error_slot: HostKeyErrorSlot,
}

impl client::Handler for SshHandler {
    type Error = russh::Error;

    fn check_server_key(
        &mut self,
        server_public_key: &keys::PublicKey,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        let fingerprint = server_public_key
            .fingerprint(keys::HashAlg::Sha256)
            .to_string();
        let allowed = match &self.host_key_verification {
            HostKeyVerification::AcceptAll => {
                tracing::warn!(
                    "accepting SSH host key without verification — \
                     set host_key_verification() for production use"
                );
                true
            }
            HostKeyVerification::Fingerprint(_) => {
                let ok = evaluate_host_key_policy(&self.host_key_verification, &fingerprint);
                if ok {
                    tracing::debug!("SSH host key fingerprint verified");
                } else {
                    tracing::error!(
                        actual = %fingerprint,
                        "SSH host key fingerprint mismatch — possible MITM attack"
                    );
                }
                ok
            }
            HostKeyVerification::RejectAll => {
                tracing::error!(
                    actual = %fingerprint,
                    "SSH host key rejected (RejectAll policy — fail closed). \
                     Pin the device's fingerprint with HostKeyVerification::Fingerprint \
                     or explicitly opt in to HostKeyVerification::AcceptAll for lab use."
                );
                false
            }
            HostKeyVerification::KnownHosts(path) => {
                match crate::transport::known_hosts::lookup(
                    path,
                    &self.host,
                    self.port,
                    &fingerprint,
                ) {
                    Ok(outcome) => {
                        let res = known_hosts_outcome_to_result(
                            outcome,
                            &self.host,
                            self.port,
                            path,
                            &fingerprint,
                        );
                        match res {
                            Ok(()) => {
                                tracing::debug!(
                                    file = %path.display(),
                                    "SSH host key verified via known_hosts"
                                );
                                true
                            }
                            Err(err) => {
                                tracing::error!(
                                    file = %path.display(),
                                    host = %self.host,
                                    error = %err,
                                    "SSH host key rejected by known_hosts policy"
                                );
                                self.error_slot.set(err);
                                false
                            }
                        }
                    }
                    Err(err) => {
                        // I/O or unrecoverable error reading the file.
                        let transport_err = TransportError::Io(std::io::Error::other(format!(
                            "known_hosts file {path}: {err}",
                            path = path.display()
                        )));
                        tracing::error!(
                            file = %path.display(),
                            error = %err,
                            "could not read known_hosts file — failing closed"
                        );
                        self.error_slot.set(transport_err);
                        false
                    }
                }
            }
        };
        std::future::ready(Ok(allowed))
    }
}

/// Convert a `known_hosts::LookupOutcome` into either `Ok(())` (accept) or a
/// structured [`TransportError`] (reject). Pure — no I/O — so the mapping is
/// unit-testable.
fn known_hosts_outcome_to_result(
    outcome: crate::transport::known_hosts::LookupOutcome,
    host: &str,
    port: u16,
    path: &Path,
    actual_fp: &str,
) -> Result<(), TransportError> {
    use crate::transport::known_hosts::LookupOutcome;
    match outcome {
        LookupOutcome::Match => Ok(()),
        LookupOutcome::Mismatch { file_fp } => Err(TransportError::HostKeyMismatch {
            host: host.to_string(),
            expected: file_fp,
            actual: actual_fp.to_string(),
        }),
        LookupOutcome::NotFound => Err(TransportError::HostKeyNotInKnownHosts {
            host: host.to_string(),
            port,
            path: path.display().to_string(),
        }),
        LookupOutcome::Revoked => Err(TransportError::HostKeyRevoked {
            host: host.to_string(),
        }),
    }
}

/// Decide whether an SSH host key with the given SHA-256 fingerprint should
/// be accepted under `policy`.
///
/// Pure function so the decision is unit-testable without constructing a
/// real `russh::keys::PublicKey`. `actual_fingerprint` is expected in the
/// format produced by `russh::keys::PublicKey::fingerprint(HashAlg::Sha256)`
/// (typically `"SHA256:<base64>"`); comparison against
/// [`HostKeyVerification::Fingerprint`] is tolerant of a missing `SHA256:`
/// prefix on the expected side.
fn evaluate_host_key_policy(policy: &HostKeyVerification, actual_fingerprint: &str) -> bool {
    match policy {
        HostKeyVerification::KnownHosts(_) => false,
        HostKeyVerification::AcceptAll => true,
        HostKeyVerification::RejectAll => false,
        HostKeyVerification::Fingerprint(expected) => {
            actual_fingerprint == expected
                || actual_fingerprint
                    .strip_prefix("SHA256:")
                    .is_some_and(|stripped| stripped == expected)
        }
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

/// Shell-escape a string by wrapping it in single quotes and escaping
/// any embedded single quotes (`'` → `'\''`).
///
/// This is the POSIX-standard way to produce a literal string safe for
/// `sh -c` consumption: `'foo'\''bar'` passes `foo'bar` to the program.
fn shell_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// Substitute OpenSSH `ProxyCommand` tokens in `command`.
///
/// Replaces `%h` with the target host and `%p` with the target port,
/// matching `man 5 ssh_config`. Both values are shell-escaped before
/// substitution to prevent shell injection when the result is passed to
/// `sh -c`.
fn expand_proxy_command(command: &str, host: &str, port: u16) -> String {
    command
        .replace("%h", &shell_escape(host))
        .replace("%p", &shell_escape(&port.to_string()))
}

/// Combined `AsyncRead`/`AsyncWrite` over a child process's stdio,
/// used to give russh a duplex stream for `ProxyCommand` mode.
///
/// The `Child` is held alive by the same struct because dropping it
/// would close the stdio pipes and tear down the SSH transport.
struct ProxyCommandStream {
    stdin: ChildStdin,
    stdout: ChildStdout,
}

impl AsyncRead for ProxyCommandStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stdout).poll_read(cx, buf)
    }
}

impl AsyncWrite for ProxyCommandStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stdin).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stdin).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stdin).poll_shutdown(cx)
    }
}

/// Spawn the `ProxyCommand` shell and return a duplex stream over its
/// stdio plus the `Child` handle (which the caller must keep alive).
fn spawn_proxy_command(
    command: &str,
    host: &str,
    port: u16,
) -> Result<(ProxyCommandStream, Child), TransportError> {
    let expanded = expand_proxy_command(command, host, port);
    let mut child = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(&expanded)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| {
            TransportError::Connect(format!("failed to spawn ProxyCommand `{expanded}`: {e}"))
        })?;

    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| TransportError::Connect("ProxyCommand stdin not captured".to_string()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| TransportError::Connect("ProxyCommand stdout not captured".to_string()))?;

    Ok((ProxyCommandStream { stdin, stdout }, child))
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
            .authenticate_password(username, password.as_str())
            .await
            .map_err(|e| TransportError::Auth(format!("password auth failed: {e}")))?,
        SshAuth::KeyFile { path, passphrase } => {
            let key_path = Path::new(path);
            let key_contents = tokio::fs::read_to_string(key_path).await.map_err(|e| {
                tracing::debug!(path, %e, "failed to read key file");
                TransportError::Auth("failed to read SSH key file".to_string())
            })?;
            let passphrase_str = passphrase.as_ref().map(|p| p.as_str());
            let key_pair = keys::decode_secret_key(&key_contents, passphrase_str).map_err(|e| {
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
            let identities = agent
                .request_identities()
                .await
                .map_err(|e| TransportError::Auth(format!("SSH agent identities failed: {e}")))?;

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
    ///
    /// If `config.proxy_command` is set, the given shell command is spawned
    /// and its stdin/stdout become the transport stream to the target,
    /// equivalent to OpenSSH's `ProxyCommand`. `proxy_command` and
    /// `jump_hosts` are mutually exclusive — setting both returns
    /// [`TransportError::Connect`].
    pub async fn connect(config: SshConfig) -> Result<Self, TransportError> {
        if config.proxy_command.is_some() && !config.jump_hosts.is_empty() {
            return Err(TransportError::Connect(
                "proxy_command and jump_hosts are mutually exclusive — \
                 use one or the other to reach the target"
                    .to_string(),
            ));
        }

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
            let slot = HostKeyErrorSlot::default();
            let handle = match prev {
                None => {
                    // First hop: direct TCP connection.
                    let handler = SshHandler {
                        host_key_verification: hop.host_key_verification.clone(),
                        host: hop.host.clone(),
                        port: hop.port,
                        error_slot: slot.clone(),
                    };
                    client::connect(russh_config.clone(), (&*hop.host, hop.port), handler)
                        .await
                        .map_err(|e| {
                            slot.take().unwrap_or_else(|| {
                                TransportError::Connect(format!(
                                    "SSH connect to {label} failed: {e}"
                                ))
                            })
                        })?
                }
                Some(parent) => {
                    // Subsequent hop: tunneled via the previous hop's session.
                    let channel = parent
                        .channel_open_direct_tcpip(&*hop.host, hop.port as u32, "0.0.0.0", 0)
                        .await
                        .map_err(|e| {
                            TransportError::Connect(format!("direct-tcpip to {label} failed: {e}"))
                        })?;
                    let stream = channel.into_stream();
                    let handler = SshHandler {
                        host_key_verification: hop.host_key_verification.clone(),
                        host: hop.host.clone(),
                        port: hop.port,
                        error_slot: slot.clone(),
                    };
                    client::connect_stream(russh_config.clone(), stream, handler)
                        .await
                        .map_err(|e| {
                            slot.take().unwrap_or_else(|| {
                                TransportError::Connect(format!(
                                    "SSH handshake with {label} failed: {e}"
                                ))
                            })
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

        // Open the final hop to the target. Three modes (in priority order):
        //   1. proxy_command set → spawn a subprocess and run SSH over its stdio
        //   2. jump_hosts non-empty → direct-tcpip tunnel through the last hop
        //   3. otherwise → direct TCP connection to the target
        let target_label = format!("{}:{}", config.host, config.port);
        let mut proxy_process: Option<Child> = None;
        let target_slot = HostKeyErrorSlot::default();
        let mut handle = if let Some(cmd) = config.proxy_command.as_deref() {
            let (stream, child) = spawn_proxy_command(cmd, &config.host, config.port)?;
            proxy_process = Some(child);
            let handler = SshHandler {
                host_key_verification: config.host_key_verification.clone(),
                host: config.host.clone(),
                port: config.port,
                error_slot: target_slot.clone(),
            };
            client::connect_stream(russh_config.clone(), stream, handler)
                .await
                .map_err(|e| {
                    target_slot.take().unwrap_or_else(|| {
                        TransportError::Connect(format!(
                            "SSH handshake with target {target_label} (via ProxyCommand) failed: {e}"
                        ))
                    })
                })?
        } else if let Some(parent) = jump_handles.last() {
            let channel = parent
                .channel_open_direct_tcpip(&*config.host, config.port as u32, "0.0.0.0", 0)
                .await
                .map_err(|e| {
                    TransportError::Connect(format!(
                        "direct-tcpip to target {target_label} failed: {e}"
                    ))
                })?;
            let stream = channel.into_stream();
            let handler = SshHandler {
                host_key_verification: config.host_key_verification.clone(),
                host: config.host.clone(),
                port: config.port,
                error_slot: target_slot.clone(),
            };
            client::connect_stream(russh_config.clone(), stream, handler)
                .await
                .map_err(|e| {
                    target_slot.take().unwrap_or_else(|| {
                        TransportError::Connect(format!(
                            "SSH handshake with target {target_label} failed: {e}"
                        ))
                    })
                })?
        } else {
            let handler = SshHandler {
                host_key_verification: config.host_key_verification.clone(),
                host: config.host.clone(),
                port: config.port,
                error_slot: target_slot.clone(),
            };
            client::connect(russh_config.clone(), (&*config.host, config.port), handler)
                .await
                .map_err(|e| {
                    target_slot.take().unwrap_or_else(|| {
                        TransportError::Connect(format!(
                            "SSH connect to {target_label} failed: {e}"
                        ))
                    })
                })?
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
            .map_err(|e| {
                TransportError::Channel(format!("failed to request netconf subsystem: {e}"))
            })?;

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
            channel: channel_stream,
            handle,
            _jump_handles: jump_handles,
            _proxy_process: proxy_process,
        })
    }
}

#[async_trait]
impl Transport for SshTransport {
    async fn write_all(&mut self, data: &[u8]) -> Result<(), TransportError> {
        self.channel
            .channel
            .data(data)
            .await
            .map_err(|e| TransportError::Io(std::io::Error::other(e.to_string())))?;
        Ok(())
    }

    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, TransportError> {
        // First, drain any buffered data
        if !self.channel.read_buffer.is_empty() {
            let to_read = std::cmp::min(buf.len(), self.channel.read_buffer.len());
            buf[..to_read].copy_from_slice(&self.channel.read_buffer[..to_read]);
            self.channel.read_buffer.drain(..to_read);
            return Ok(to_read);
        }

        // Read from the SSH channel, skipping non-data messages.
        // Messages like WindowAdjusted, Success, ExtendedData (stderr)
        // can arrive at any time and must not be treated as EOF.
        loop {
            match self.channel.channel.wait().await {
                Some(ChannelMsg::Data { data: channel_data }) => {
                    let bytes = &channel_data[..];
                    let to_copy = std::cmp::min(buf.len(), bytes.len());
                    buf[..to_copy].copy_from_slice(&bytes[..to_copy]);
                    if bytes.len() > to_copy {
                        self.channel
                            .read_buffer
                            .extend_from_slice(&bytes[to_copy..]);
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
        self.channel
            .channel
            .eof()
            .await
            .map_err(|e| TransportError::Io(std::io::Error::other(e.to_string())))?;
        self.handle
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
            auth: SshAuth::Password(Zeroizing::new("p".to_string())),
            host_key_verification: HostKeyVerification::AcceptAll,
            jump_hosts: Vec::new(),
            proxy_command: None,
        };
        assert!(cfg.jump_hosts.is_empty());
        assert!(cfg.proxy_command.is_none());
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
            host_key_verification: HostKeyVerification::Fingerprint("SHA256:abc123".to_string()),
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
            proxy_command: None,
        };
        let cloned = cfg.clone();
        assert_eq!(cloned.jump_hosts.len(), 2);
        assert_eq!(cloned.jump_hosts[0].host, "h1");
        assert_eq!(cloned.jump_hosts[1].host, "h2");
    }

    #[test]
    fn shell_escape_plain_string() {
        assert_eq!(shell_escape("hello"), "'hello'");
    }

    #[test]
    fn shell_escape_with_single_quote() {
        assert_eq!(shell_escape("it's"), "'it'\\''s'");
    }

    #[test]
    fn shell_escape_with_metacharacters() {
        assert_eq!(shell_escape("a;rm -rf /"), "'a;rm -rf /'");
    }

    #[test]
    fn expand_proxy_command_replaces_h_and_p() {
        let out = expand_proxy_command("ssh -W %h:%p bastion", "10.1.2.3", 830);
        assert_eq!(out, "ssh -W '10.1.2.3':'830' bastion");
    }

    #[test]
    fn expand_proxy_command_replaces_multiple_occurrences() {
        // %h and %p can appear more than once.
        let out = expand_proxy_command("nc %h %p; echo %h:%p", "host", 22);
        assert_eq!(out, "nc 'host' '22'; echo 'host':'22'");
    }

    #[test]
    fn expand_proxy_command_no_tokens_passthrough() {
        // No %h/%p → passthrough unchanged.
        let out = expand_proxy_command("nc bastion 22", "ignored", 0);
        assert_eq!(out, "nc bastion 22");
    }

    #[test]
    fn expand_proxy_command_escapes_shell_metacharacters() {
        // Shell metacharacters in host are escaped via single-quoting,
        // preventing shell injection when the result is passed to `sh -c`.
        let out = expand_proxy_command("nc %h %p", "host;rm -rf /", 22);
        assert_eq!(out, "nc 'host;rm -rf /' '22'");
    }

    #[tokio::test]
    async fn proxy_command_and_jump_hosts_mutually_exclusive() {
        // Both set → connect rejects without spawning anything or
        // attempting any TCP connection.
        let cfg = SshConfig {
            host: "10.0.0.1".to_string(),
            port: 830,
            username: "u".to_string(),
            auth: SshAuth::Password(Zeroizing::new("p".to_string())),
            host_key_verification: HostKeyVerification::AcceptAll,
            jump_hosts: vec![JumpHostConfig {
                host: "bastion".to_string(),
                port: 22,
                username: "u".to_string(),
                auth: SshAuth::Agent,
                host_key_verification: HostKeyVerification::AcceptAll,
            }],
            proxy_command: Some("nc %h %p".to_string()),
        };
        let err = match SshTransport::connect(cfg).await {
            Err(e) => e,
            Ok(_) => panic!("expected connect to fail"),
        };
        match err {
            TransportError::Connect(msg) => {
                assert!(msg.contains("mutually exclusive"), "unexpected msg: {msg}");
            }
            other => panic!("expected Connect, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn proxy_command_spawn_failure_propagates_as_connect_error() {
        // ssh handshake will fail because `cat` echoes our SSH banner back at
        // us instead of speaking SSH — but the spawn itself succeeds and the
        // error path is exercised. We just want to confirm the proxy_command
        // branch is taken and surfaces a Connect error (not a panic).
        let cfg = SshConfig {
            host: "ignored".to_string(),
            port: 0,
            username: "u".to_string(),
            auth: SshAuth::Password(Zeroizing::new("p".to_string())),
            host_key_verification: HostKeyVerification::AcceptAll,
            jump_hosts: Vec::new(),
            // `false` exits 1 immediately, so stdin/stdout EOF and the SSH
            // handshake errors out — proves the proxy branch is wired.
            proxy_command: Some("false".to_string()),
        };
        let err = match SshTransport::connect(cfg).await {
            Err(e) => e,
            Ok(_) => panic!("expected connect to fail"),
        };
        assert!(matches!(err, TransportError::Connect(_)), "got {err:?}");
    }

    // ───────── host key verification policy ─────────
    //
    // The pure `evaluate_host_key_policy` helper isolates the decision from
    // the russh trait impl so we can unit-test every variant without
    // constructing a real `keys::PublicKey`.

    #[test]
    fn host_key_policy_accept_all_accepts_any_fingerprint() {
        let policy = HostKeyVerification::AcceptAll;
        assert!(evaluate_host_key_policy(&policy, "SHA256:anything"));
        assert!(evaluate_host_key_policy(&policy, ""));
    }

    #[test]
    fn host_key_policy_reject_all_rejects_any_fingerprint() {
        // Production safe default: connections fail until the caller pins
        // a fingerprint or explicitly opts in to AcceptAll.
        let policy = HostKeyVerification::RejectAll;
        assert!(!evaluate_host_key_policy(&policy, "SHA256:abc"));
        assert!(!evaluate_host_key_policy(&policy, "anything"));
    }

    #[test]
    fn host_key_policy_fingerprint_match_accepts() {
        // Full SHA256:... form matches exactly.
        let policy = HostKeyVerification::Fingerprint("SHA256:abc123".to_string());
        assert!(evaluate_host_key_policy(&policy, "SHA256:abc123"));
    }

    #[test]
    fn host_key_policy_fingerprint_match_strips_sha256_prefix() {
        // Users often paste just the base64 portion of `ssh-keygen -lf`
        // output. The helper tolerates a missing prefix on the expected
        // side as long as the actual has it.
        let policy = HostKeyVerification::Fingerprint("abc123".to_string());
        assert!(evaluate_host_key_policy(&policy, "SHA256:abc123"));
    }

    #[test]
    fn host_key_policy_fingerprint_mismatch_rejects() {
        let policy = HostKeyVerification::Fingerprint("SHA256:abc123".to_string());
        assert!(!evaluate_host_key_policy(&policy, "SHA256:def456"));
        assert!(!evaluate_host_key_policy(&policy, ""));
    }

    #[test]
    fn host_key_policy_known_hosts_defers_to_file_lookup_returns_false_here() {
        // evaluate_host_key_policy is pure (no I/O) — for KnownHosts the
        // actual decision happens in the handler via known_hosts::lookup().
        // The pure function must NOT accept on its own.
        let policy = HostKeyVerification::KnownHosts(std::path::PathBuf::from("/tmp/x"));
        assert!(!evaluate_host_key_policy(&policy, "SHA256:abc"));
    }

    #[test]
    fn known_hosts_outcome_to_error_match_is_ok() {
        use crate::transport::known_hosts::LookupOutcome;
        let res = known_hosts_outcome_to_result(
            LookupOutcome::Match,
            "device-a.lab",
            22,
            std::path::Path::new("/etc/known_hosts"),
            "SHA256:abc",
        );
        assert!(res.is_ok(), "Match must produce Ok(())");
    }

    #[test]
    fn known_hosts_outcome_to_error_mismatch_yields_host_key_mismatch() {
        use crate::error::TransportError;
        use crate::transport::known_hosts::LookupOutcome;
        let err = known_hosts_outcome_to_result(
            LookupOutcome::Mismatch {
                file_fp: "SHA256:OLD".into(),
            },
            "device-a.lab",
            22,
            std::path::Path::new("/etc/known_hosts"),
            "SHA256:NEW",
        )
        .unwrap_err();
        match err {
            TransportError::HostKeyMismatch {
                host,
                expected,
                actual,
            } => {
                assert_eq!(host, "device-a.lab");
                assert_eq!(expected, "SHA256:OLD");
                assert_eq!(actual, "SHA256:NEW");
            }
            other => panic!("expected HostKeyMismatch, got {other:?}"),
        }
    }

    #[test]
    fn known_hosts_outcome_to_error_not_found_yields_not_in_known_hosts() {
        use crate::error::TransportError;
        use crate::transport::known_hosts::LookupOutcome;
        let err = known_hosts_outcome_to_result(
            LookupOutcome::NotFound,
            "device-a.lab",
            830,
            std::path::Path::new("/etc/known_hosts"),
            "SHA256:any",
        )
        .unwrap_err();
        match err {
            TransportError::HostKeyNotInKnownHosts { host, port, path } => {
                assert_eq!(host, "device-a.lab");
                assert_eq!(port, 830);
                assert_eq!(path, "/etc/known_hosts");
            }
            other => panic!("expected HostKeyNotInKnownHosts, got {other:?}"),
        }
    }

    #[test]
    fn known_hosts_outcome_to_error_revoked_yields_host_key_revoked() {
        use crate::error::TransportError;
        use crate::transport::known_hosts::LookupOutcome;
        let err = known_hosts_outcome_to_result(
            LookupOutcome::Revoked,
            "device-a.lab",
            22,
            std::path::Path::new("/etc/known_hosts"),
            "SHA256:bad",
        )
        .unwrap_err();
        assert!(matches!(err, TransportError::HostKeyRevoked { host } if host == "device-a.lab"));
    }
}
