# rustnetconf

A Rust network automation platform: async NETCONF client library, YANG code generation, vendor profiles, connection pooling, and a Terraform-like CLI for declarative network config management.

Built on [tokio](https://tokio.rs), [russh](https://crates.io/crates/russh), and [rustls](https://crates.io/crates/rustls) — pure Rust, no OpenSSL, no libssh2.

## Workspace

| Crate | Description |
|-------|-------------|
| **rustnetconf** | Async NETCONF 1.0/1.1 client library |
| **rustnetconf-yang** | YANG model code generation (compile-time config validation) |
| **rustnetconf-cli** | Terraform-like CLI tool (`netconf` binary) |

## RFC Support

| RFC | Feature | Status |
|-----|---------|--------|
| RFC 6241 | Network Configuration Protocol (NETCONF) | ✅ supported |
| RFC 6242 | NETCONF over SSH | ✅ supported |
| RFC 7589 | NETCONF over TLS | ✅ supported (feature flag `tls`) |
| RFC 5277 | Event Notifications | 💡 planned |
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

### Connect over TLS (RFC 7589)

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

### Connection pooling

```rust
use rustnetconf::pool::{DevicePool, DeviceConfig};
use rustnetconf::transport::ssh::SshAuth;
use rustnetconf::Datastore;

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
- **NETCONF 1.0 + 1.1** — EOM and chunked framing with auto-negotiation
- **All core RPCs** — get, get-config, edit-config, lock/unlock, commit, validate, close/kill-session, discard-changes
- **Confirmed commit** — auto-rollback safety net (RFC 6241 §8.4)
- **CommitUnknown detection** — distinguishes "commit failed" from "maybe committed, connection lost"
- **Stale lock recovery** — `lock_or_kill_stale()` kills crashed sessions holding locks
- **Framing mismatch detection** — catches firmware bugs where devices send wrong framing

### Vendor Profiles
- **Auto-detection** from device `<hello>` capabilities
- **Junos** — config wrapping, namespace normalization, discard-before-close
- **Generic** — standard RFC 6241 for any compliant device
- Extensible — implement `VendorProfile` trait for custom vendors

### Connection Pool
- Tokio semaphore-based concurrency limiting
- Checkout with timeout (no blocking forever)
- Auto-checkin on drop, broken connections discarded
- Connection reuse from idle pool

### YANG Code Generation
- Build-time generation from `.yang` model files via libyang2
- Typed Rust structs with serde Serialize/Deserialize
- Correct type mapping (string, bool, uint32, etc.)
- Bundled IETF models: ietf-interfaces, ietf-ip, ietf-yang-types, ietf-inet-types

### Authentication
| Method | Transport | Builder API |
|--------|-----------|-------------|
| Password | SSH | `.password("secret")` |
| Key file | SSH | `.key_file("~/.ssh/id_ed25519")` |
| SSH agent | SSH | `.ssh_agent()` |
| Server-only TLS | TLS | `TlsConfig { ca_cert, .. }` |
| Mutual TLS (mTLS) | TLS | `TlsConfig { client_cert, client_key, .. }` |

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

140+ tests across the workspace:
- **Unit tests** — framing, RPC serialization, capability parsing, vendor profiles, diff engine, inventory parsing
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

- **Credentials not zeroized in memory** — Passwords and key passphrases are stored as `String`, which is not securely zeroed on drop. Credentials may persist in process memory until overwritten. **Mitigation:** Prefer SSH agent authentication (`ssh_agent()`) over inline passwords/passphrases, and avoid core dumps in production.

- **Debug logs may contain file paths** — When SSH key file loading fails, the key file path is included in `tracing::debug!` output. This is not exposed at info/warn/error levels. **Mitigation:** Disable debug-level logging in production, or filter `rustnetconf::transport` logs.

### Security Features

- **SSH host key verification** — Use `host_key_verification(HostKeyVerification::Fingerprint("SHA256:..."))` to pin a device's host key and prevent MITM attacks. Default is `AcceptAll` (with a logged warning), consistent with most network automation tools.
- **XML attribute escaping** — All message-id values are escaped to prevent XML attribute injection.
- **Read buffer limits** — Session read buffers are capped at 100 MB to prevent memory exhaustion from malformed device responses.
- **Typed error hierarchy** — Structured error types (`ChannelClosed`, `SessionExpired`, `MessageIdMismatch`) enable precise error handling without string matching.
- **No unsafe code** — The entire codebase uses safe Rust.

### Security Best Practices

- Use Ed25519 SSH keys (not RSA) for device authentication
- Set `host_key_verification(HostKeyVerification::Fingerprint(...))` in production
- Prefer SSH agent auth over inline passwords
- Store credentials in inventory.toml with restricted file permissions (`chmod 600`)
- Run the CLI on trusted management networks with direct device connectivity
- Use `confirmed-commit` (the default for `netconf apply`) so the device auto-reverts if something goes wrong
- Disable debug-level logging in production environments

To report a security vulnerability, please open an issue on GitHub.

## License

MIT OR Apache-2.0

## Contributing

Contributions welcome! See [ARCHITECTURE.md](ARCHITECTURE.md) for the codebase design and [TODOS.md](TODOS.md) for tracked work items.
