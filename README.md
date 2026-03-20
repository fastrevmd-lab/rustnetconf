# rustnetconf

A Rust network automation platform: async NETCONF client library, YANG code generation, vendor profiles, connection pooling, and a Terraform-like CLI for declarative network config management.

Built on [tokio](https://tokio.rs) and [russh](https://crates.io/crates/russh) — pure Rust, no OpenSSL, no libssh2.

## Workspace

| Crate | Description |
|-------|-------------|
| **rustnetconf** | Async NETCONF 1.0/1.1 client library |
| **rustnetconf-yang** | YANG model code generation (compile-time config validation) |
| **rustnetconf-cli** | Terraform-like CLI tool (`netconf` binary) |

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
| Method | Builder API |
|--------|-------------|
| Password | `.password("secret")` |
| Key file | `.key_file("~/.ssh/id_ed25519")` |
| SSH agent | `.ssh_agent()` |

### Error Handling

Layered errors matching the protocol stack:

```rust
match result {
    Err(NetconfError::Transport(e)) => { /* SSH connection issues */ }
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

## License

MIT OR Apache-2.0

## Contributing

Contributions welcome! See [ARCHITECTURE.md](ARCHITECTURE.md) for the codebase design and [TODOS.md](TODOS.md) for tracked work items.
