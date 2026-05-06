# rustnetconf

A Rust network automation platform: async NETCONF client library, YANG code generation, vendor profiles, connection pooling, and a Terraform-like CLI for declarative network config management.

Built on [tokio](https://tokio.rs), [russh](https://crates.io/crates/russh), and [rustls](https://crates.io/crates/rustls) — pure Rust, no OpenSSL, no libssh2.

## Workspace

| Crate | Description |
|-------|-------------|
| **rustnetconf** | Async NETCONF 1.0/1.1 client library |
| **rustnetconf-yang** | YANG model code generation (compile-time config validation) |
| **rustnetconf-cli** | Terraform-like CLI tool (`netconf` binary) |

## What's New in v0.10.0

**Breaking changes:**
- `HostKeyVerification` no longer implements `Default` — callers must explicitly choose a host key policy
- `SshAuth::Password` and `SshAuth::KeyFile { passphrase }` now use `Zeroizing<String>` instead of `String`
- User-provided XML content (RPC bodies, filters, configs) is now validated for well-formedness before sending

**Security fixes:**
- Shell injection via ProxyCommand `%h`/`%p` substitution — values are now shell-escaped
- Credentials (passwords, passphrases) zeroized on drop via the `zeroize` crate
- XML fragment validation prevents injection through malformed RPC content
- TLS `danger_accept_invalid_certs` now emits a detailed warning about the full scope of the bypass
- CLI device names validated to prevent path traversal; state files written with `0600` permissions

**New features:**
- Configurable RPC timeout (`.rpc_timeout(Duration)`) — prevents indefinite blocking on unresponsive devices
- Configurable read buffer size (`.max_read_buffer(bytes)`) — defaults to 100 MB
- IPv6 address support — bracket notation (`[::1]:830`) and bare IPv6 addresses
- Capability normalization — legacy Junos capability URIs are mapped to standard URIs during session establishment

**Quality improvements:**
- Connection pool health checks — dead connections are discarded on checkout and drop instead of being recycled
- Blocking `std::fs::read_to_string` in async context replaced with `tokio::fs`
- Unnecessary `Arc<Mutex<>>` removed from `SshTransport`
- `AtomicU64` message counter replaced with plain `u64` (Session is `&mut self` only)
- YANG codegen: full container/list XML serialization, complete Rust keyword list, hard error on module load failure
- CLI: plan summary fixed for non-JSON mode, diff engine compares all list elements
- Removed unused `futures` dependency and `quick-xml` serialize feature
- `ErrorTag` implements `std::str::FromStr`; `Session::validate()` checks `:validate` capability
- Dependency updates: russh 0.60.2, rustls 0.23.40, tokio 1.52.2, rustls-webpki 0.103.13

## RFC Support

| RFC | Feature | Status |
|-----|---------|--------|
| RFC 6241 | Network Configuration Protocol (NETCONF) | ✅ supported |
| RFC 6242 | NETCONF over SSH | ✅ supported |
| RFC 7589 | NETCONF over TLS | ✅ supported (feature flag `tls`) — **needs physical SRX or non-vSRX for TLS test** |
| RFC 5277 | Event Notifications | ✅ supported — tested on Junos 24.4 vSRX (subscription + capability; interleave limited by device) |
| RFC 5717 | Partial Lock RPC | 💡 planned |
| RFC 8071 | NETCONF Call Home | 💡 planned |
| RFC 6243 | With-defaults Capability | 💡 planned |
| RFC 6022 | YANG Module for NETCONF Monitoring | 💡 planned |
| RFC 8526 | NETCONF Extensions for NMDA | 💡 planned |
| RFC 6470 | NETCONF Base Notifications | 💡 planned |
| RFC 8040 | RESTCONF | 💡 planned |

## CLI Tool — `netconf`

Declarative network config management. Write desired state as XML files, the CLI diffs against the device and applies changes with confirmed-commit safety.

```bash
netconf init                    # Create project skeleton
netconf plan spine-01           # Show what would change (colored diff)
netconf apply spine-01          # Apply with confirmed-commit (auto-revert on timeout)
netconf confirm spine-01        # Make changes permanent
netconf rollback spine-01       # Revert to saved state
netconf get spine-01            # Fetch running config
netconf validate spine-01       # Dry-run validation
```

### Project Structure

```
my-network/
├── inventory.toml              # Device connection details
├── desired/
│   └── spine-01/
│       ├── interfaces.xml      # Desired interface config
│       └── system.xml          # Desired system config
└── .netconf/state/             # Rollback snapshots (auto-managed)
```

### inventory.toml

```toml
[defaults]
confirm_timeout = 60

[devices.spine-01]
host = "10.0.0.1:830"
username = "admin"
key_file = "~/.ssh/id_ed25519"
# vendor auto-detected from device hello
```

## Library — Quick Start

```toml
[dependencies]
rustnetconf = { git = "https://github.com/fastrevmd-lab/rustnetconf.git" }
tokio = { version = "1", features = ["full"] }
```

For TLS transport (RFC 7589), enable the `tls` feature:

```toml
[dependencies]
rustnetconf = { git = "https://github.com/fastrevmd-lab/rustnetconf.git", features = ["tls"] }
```

### Fetch running config

```rust
use rustnetconf::{Client, Datastore};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = Client::connect("10.0.0.1:830")
        .username("admin")
        .key_file("~/.ssh/id_ed25519")
        .connect()
        .await?;

    let config = client.get_config(Datastore::Running).await?;
    println!("{config}");

    client.close_session().await?;
    Ok(())
}
```

### Edit config (full round trip)

```rust
use rustnetconf::{Client, Datastore, DefaultOperation};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = Client::connect("10.0.0.1:830")
        .username("admin")
        .password("secret")
        .connect()
        .await?;

    client.lock(Datastore::Candidate).await?;

    client.edit_config(Datastore::Candidate)
        .config("<interface><name>ge-0/0/0</name><description>uplink</description></interface>")
        .default_operation(DefaultOperation::Merge)
        .send()
        .await?;

    client.validate(Datastore::Candidate).await?;
    client.commit().await?;
    client.unlock(Datastore::Candidate).await?;

    client.close_session().await?;
    Ok(())
}
```

### Connect through a jump host (`ProxyJump`)

```rust
use rustnetconf::{Client, Datastore};
use rustnetconf::transport::ssh::{JumpHostConfig, SshAuth, HostKeyVerification};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bastion = JumpHostConfig {
        host: "bastion.example.com".into(),
        port: 22,
        username: "jumpuser".into(),
        auth: SshAuth::Agent,
        host_key_verification: HostKeyVerification::AcceptAll,
    };

    let mut client = Client::connect("10.0.0.1:830")
        .username("admin")
        .ssh_agent()
        .jump_hosts(vec![bastion])
        .connect()
        .await?;

    let config = client.get_config(Datastore::Running).await?;
    println!("{config}");
    client.close_session().await?;
    Ok(())
}
```

### Connect using your `~/.ssh/config`

```rust
use rustnetconf::{Client, Datastore};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Resolves `Host edge-r1` from ~/.ssh/config — picks up HostName, Port,
    // User, IdentityFile, ProxyJump, ProxyCommand. NETCONF default port 830
    // is used when the config doesn't pin Port.
    let mut client = Client::connect_via_ssh_config("edge-r1")?
        .ssh_agent()
        .connect()
        .await?;

    let config = client.get_config(Datastore::Running).await?;
    println!("{config}");
    client.close_session().await?;
    Ok(())
}
```

### Connect over TLS (RFC 7589)

> **Note:** vSRX 24.4 has a known TLS handshake issue where the PKI engine cannot
> present a self-signed certificate chain. TLS testing requires a physical SRX,
> MX, or EX device with a CA-signed certificate. The code compiles and passes
> unit tests but has not been validated against a live TLS-capable device.

```rust
use rustnetconf::{Client, TlsConfig, Datastore};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = TlsConfig {
        host: "10.0.0.1".into(),
        ca_cert: Some("ca.pem".into()),
        client_cert: Some("client.pem".into()),
        client_key: Some("client-key.pem".into()),
        ..Default::default()
    };

    let mut client = Client::connect_tls(config).connect().await?;
    let config = client.get_config(Datastore::Running).await?;
    println!("{config}");

    client.close_session().await?;
    Ok(())
}
```

### Event notifications (RFC 5277)

```rust
use rustnetconf::{Client, Datastore};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = Client::connect("10.0.0.1:830")
        .username("admin")
        .password("secret")
        .connect()
        .await?;

    // Subscribe to NETCONF event stream
    client.create_subscription(Some("NETCONF"), None, None, None).await?;

    // Block waiting for notifications
    while let Some(notif) = client.recv_notification().await? {
        println!("[{}] {}", notif.event_time, notif.event_xml);
    }

    Ok(())
}
```

> **Note:** Some devices (e.g., Junos vSRX 24.4) advertise `:interleave` but do not
> respond to RPCs on a session with an active subscription. On these devices, use a
> dedicated session for notifications and a separate session for RPCs. Notifications
> arriving during RPCs on interleave-capable devices are automatically buffered and
> available via `drain_notifications()`.

### Connection pooling

```rust
use rustnetconf::pool::{DevicePool, DeviceConfig};
use rustnetconf::transport::ssh::SshAuth;
use rustnetconf::Datastore;
use zeroize::Zeroizing;

let pool = DevicePool::builder()
    .max_connections(50)
    .add_device("spine-01", DeviceConfig {
        host: "10.0.0.1:830".into(),
        username: "admin".into(),
        auth: SshAuth::KeyFile { path: "~/.ssh/id_ed25519".into(), passphrase: None },
        vendor: None, // auto-detect
    })
    .build();

let mut conn = pool.checkout("spine-01").await?;
let config = conn.get_config(Datastore::Running).await?;
// connection auto-returned to pool on drop
```

## Features

### NETCONF Client
- **Async-first** — tokio-based, push config to 500 devices concurrently
- **SSH + TLS transports** — SSH (RFC 6242) by default, TLS (RFC 7589) via `tls` feature flag
- **SSH bastion support** — `ProxyJump` (multi-hop), `ProxyCommand` (shell-escaped), and OpenSSH `~/.ssh/config` alias resolution
- **NETCONF 1.0 + 1.1** — EOM and chunked framing with auto-negotiation
- **All core RPCs** — get, get-config, edit-config, lock/unlock, commit, validate, close/kill-session, discard-changes
- **Confirmed commit** — auto-rollback safety net (RFC 6241 §8.4)
- **Event notifications** — `create-subscription`, inline notification demux, buffered drain/recv API (RFC 5277)
- **RPC timeout** — configurable per-session deadline prevents indefinite blocking on unresponsive devices
- **XML fragment validation** — user-provided RPC content is validated before insertion to prevent XML injection
- **CommitUnknown detection** — distinguishes "commit failed" from "maybe committed, connection lost"
- **Stale lock recovery** — `lock_or_kill_stale()` kills crashed sessions holding locks
- **Framing mismatch detection** — catches firmware bugs where devices send wrong framing
- **IPv6 support** — connect to devices using bracket notation (`[::1]:830`) or bare IPv6 addresses

### Vendor Profiles
- **Auto-detection** from device `<hello>` capabilities
- **Junos** — config wrapping, namespace normalization, discard-before-close
- **Generic** — standard RFC 6241 for any compliant device
- Extensible — implement `VendorProfile` trait for custom vendors

### Connection Pool
- Tokio semaphore-based concurrency limiting
- Checkout with timeout (no blocking forever)
- Auto-checkin on drop with health check — dead connections are discarded, not recycled
- Connection reuse from idle pool

### YANG Code Generation
- Build-time generation from `.yang` model files via libyang2
- Typed Rust structs with serde Serialize/Deserialize
- Full XML serialization — leaves, containers, and lists
- Correct type mapping (string, bool, uint32, etc.)
- Complete Rust keyword escaping for YANG node names
- Bundled IETF models: ietf-interfaces, ietf-ip, ietf-yang-types, ietf-inet-types

### Authentication
| Method | Transport | Builder API |
|--------|-----------|-------------|
| Password | SSH | `.password("secret")` |
| Key file | SSH | `.key_file("~/.ssh/id_ed25519")` |
| SSH agent | SSH | `.ssh_agent()` |
| Server-only TLS | TLS | `TlsConfig { ca_cert, .. }` |
| Mutual TLS (mTLS) | TLS | `TlsConfig { client_cert, client_key, .. }` |

### SSH Connection Options
| Option | Builder API | Notes |
|--------|-------------|-------|
| Direct TCP | (default) | No proxy |
| `ProxyJump` (bastion chain) | `.jump_hosts(Vec<JumpHostConfig>)` | Each hop has its own credentials and host-key policy |
| `ProxyCommand` | `.proxy_command("ssh -W %h:%p bastion")` | `%h`/`%p` shell-escaped and substituted; runs under `sh -c` |
| `~/.ssh/config` alias | `Client::connect_via_ssh_config("alias")?` | Resolves `HostName`, `Port`, `User`, `IdentityFile`, `ProxyJump`, `ProxyCommand`, `Include` |

`jump_hosts` and `proxy_command` are mutually exclusive at connect time.

### Error Handling

Layered errors matching the protocol stack:

```rust
match result {
    Err(NetconfError::Transport(e)) => { /* SSH/TLS connection issues */ }
    Err(NetconfError::Framing(e))   => { /* Protocol framing errors */ }
    Err(NetconfError::Rpc(e))       => { /* Device rejected RPC (all 7 RFC fields parsed) */ }
    Err(NetconfError::Protocol(e))  => { /* Capability/session errors */ }
    Ok(response) => { /* Success */ }
}
```

## Supported Operations

| Operation | RFC 6241 | Status |
|-----------|----------|--------|
| `get` | §7.7 | Done |
| `get-config` | §7.1 | Done |
| `edit-config` | §7.2 | Done |
| `lock` / `unlock` | §7.4-7.5 | Done |
| `close-session` | §7.8 | Done |
| `kill-session` | §7.9 | Done |
| `commit` | §8.4 | Done |
| `confirmed-commit` | §8.4 | Done |
| `validate` | §8.6 | Done |
| `discard-changes` | §8.3 | Done |

## Testing

197 tests across the workspace:
- **Unit tests** — framing, RPC serialization, capability parsing, vendor profiles, diff engine, inventory parsing, IPv6 address parsing, XML fragment validation, capability normalization
- **Mock transport tests** — session state machine, CommitUnknown detection, lock recovery
- **Integration tests** — 32 tests against a live Juniper vSRX including full edit-config round trips, vendor auto-detection, connection pooling, and concurrent sessions

```bash
cargo test --workspace                    # Run all tests
cargo test --test integration_vsrx        # Run vSRX integration tests only
SKIP_INTEGRATION=1 cargo test             # Skip tests requiring a device
```

## Security

### Known Issues

- **RSA timing sidechannel (RUSTSEC-2023-0071)** — The `rsa` crate (transitive dependency via `russh → internal-russh-forked-ssh-key → rsa`) has a known timing sidechannel that could theoretically allow RSA key recovery. No upstream fix is available. **Mitigation:** Use Ed25519 or ECDSA keys instead of RSA for SSH authentication.

- **Debug logs may contain file paths** — When SSH key file loading fails, the key file path is included in `tracing::debug!` output. This is not exposed at info/warn/error levels. **Mitigation:** Disable debug-level logging in production, or filter `rustnetconf::transport` logs.

### Security Features

- **Credential zeroization** — Passwords and key passphrases use `Zeroizing<String>` (via the `zeroize` crate) and are securely erased from memory on drop.
- **SSH host key verification** — `HostKeyVerification` must be set explicitly (no `Default` impl). Use `Fingerprint("SHA256:...")` to pin host keys in production. `AcceptAll` is available for lab use but emits a `tracing::warn!`.
- **Shell-escaped ProxyCommand** — `%h` and `%p` substitutions are shell-escaped to prevent command injection via malicious hostnames.
- **XML fragment validation** — All user-provided RPC content is validated for well-formedness before insertion, preventing XML injection.
- **XML attribute escaping** — All message-id values are escaped to prevent XML attribute injection.
- **TLS bypass warnings** — `danger_accept_invalid_certs` emits a detailed warning explaining that ALL certificate validation is bypassed (trust chain, signatures, hostname, and expiry).
- **Read buffer limits** — Session read buffers default to 100 MB (configurable via `.max_read_buffer()`) to prevent memory exhaustion.
- **RPC timeout** — Configurable via `.rpc_timeout()` to prevent indefinite blocking on unresponsive devices.
- **CLI input validation** — Device names are validated to prevent path traversal; state files are written with `0600` permissions on Unix.
- **Typed error hierarchy** — Structured error types (`ChannelClosed`, `SessionExpired`, `MessageIdMismatch`) enable precise error handling without string matching.
- **No unsafe code** — The entire codebase uses safe Rust.

### Security Best Practices

- Use Ed25519 SSH keys (not RSA) for device authentication
- Set `host_key_verification(HostKeyVerification::Fingerprint(...))` in production — `HostKeyVerification` has no default, so you must choose explicitly
- Set `.rpc_timeout(Duration::from_secs(30))` to prevent hanging on unresponsive devices
- Prefer SSH agent auth over inline passwords
- Store credentials in inventory.toml with restricted file permissions (`chmod 600`)
- Run the CLI on trusted management networks with direct device connectivity
- Use `confirmed-commit` (the default for `netconf apply`) so the device auto-reverts if something goes wrong
- Disable debug-level logging in production environments

To report a security vulnerability, please open an issue on GitHub.

## Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `async-trait` | 0.1 | Async trait support |
| `quick-xml` | 0.37 | XML parsing (NETCONF RPC encode/decode) |
| `russh` | 0.60 | SSH transport (pure Rust, no libssh2) |
| `thiserror` | 2 | Error derive macros |
| `tokio` | 1 | Async runtime |
| `tracing` | 0.1 | Structured logging/tracing |
| `zeroize` | 1 | Secure credential erasure on drop |

Optional (behind `tls` feature):

| Crate | Version | Purpose |
|-------|---------|---------|
| `rustls` | 0.23 | TLS transport (pure Rust, no OpenSSL) |
| `tokio-rustls` | 0.26 | Async TLS stream adapter |
| `webpki-roots` | 0.26 | Mozilla CA root certificates |

Dev-only:

| Crate | Version | Purpose |
|-------|---------|---------|
| `tokio-test` | 0.4 | Async test utilities |
| `tracing-subscriber` | 0.3 | Log subscriber for tests |
| `tempfile` | 3 | Temporary directories for tests |

## License

MIT OR Apache-2.0

## Contributing

Contributions welcome! See [ARCHITECTURE.md](ARCHITECTURE.md) for the codebase design and [TODOS.md](TODOS.md) for tracked work items.
