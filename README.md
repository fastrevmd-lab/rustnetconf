# rustnetconf

An async-first NETCONF client library for Rust, built on [tokio](https://tokio.rs) and [russh](https://crates.io/crates/russh).

## Why rustnetconf?

Network engineers managing device fleets programmatically are stuck with Python's `ncclient` — synchronous, untyped, and painfully slow when pushing config to hundreds of devices. Existing Rust NETCONF libraries are minimal or abandoned.

**rustnetconf** is the async NETCONF client that Rust has been missing:

- **Async parallelism** — Push config to 500 devices concurrently with tokio. No threading hacks.
- **Typed RPC operations** — `edit_config()`, `get_config()`, `lock()`, `commit()` — not `send_raw_xml_and_hope()`.
- **Protocol correctness** — NETCONF 1.0 (EOM) and 1.1 (chunked) framing, automatic capability negotiation.
- **Pure Rust** — No OpenSSL, no libssh2, no unsafe FFI. The entire stack is memory-safe via `russh`.
- **Structured errors** — Layered error types with fully parsed `<rpc-error>` responses (all 7 RFC 6241 fields).

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
rustnetconf = "0.1"
tokio = { version = "1", features = ["full"] }
```

### Fetch running config

```rust
use rustnetconf::{Client, Datastore};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::connect("10.0.0.1:830")
        .username("admin")
        .key_file("~/.ssh/id_ed25519")
        .connect()
        .await?;

    let config = client.get_config(Datastore::Running).await?;
    println!("{}", config);

    client.close_session().await?;
    Ok(())
}
```

### Edit config (full round trip)

```rust
use rustnetconf::{Client, Datastore, DefaultOperation};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::connect("10.0.0.1:830")
        .username("admin")
        .password("secret")
        .connect()
        .await?;

    // Lock → Edit → Validate → Commit → Unlock
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

## Authentication

rustnetconf supports three SSH authentication methods via `russh`:

| Method | Builder API |
|--------|-------------|
| Password | `.password("secret")` |
| Key file | `.key_file("~/.ssh/id_ed25519")` |
| SSH agent | `.ssh_agent()` |

## Supported Operations

| Operation | RFC 6241 | Status |
|-----------|----------|--------|
| `get` | §7.7 | v0.1 |
| `get-config` | §7.1 | v0.1 |
| `edit-config` | §7.2 | v0.1 |
| `lock` / `unlock` | §7.4-7.5 | v0.1 |
| `close-session` | §7.8 | v0.1 |
| `kill-session` | §7.9 | v0.1 |
| `commit` | §8.4 | v0.1 |
| `validate` | §8.6 | v0.1 |
| `copy-config` | §7.3 | planned |
| `delete-config` | §7.4 | planned |

## NETCONF Protocol Support

- **NETCONF 1.0** (RFC 4741) — end-of-message `]]>]]>` framing
- **NETCONF 1.1** (RFC 6241) — chunked framing
- Automatic version negotiation during `<hello>` exchange
- Capability-gated operations (e.g., `commit` requires `:candidate`)

## Error Handling

Errors are layered to match the protocol stack:

```rust
match result {
    Err(NetconfError::Transport(e)) => { /* SSH connection issues */ }
    Err(NetconfError::Framing(e)) => { /* Protocol framing errors */ }
    Err(NetconfError::Rpc(e)) => {
        // Fully parsed <rpc-error> with all 7 RFC fields:
        // error_type, error_tag, error_severity, error_app_tag,
        // error_path, error_message, error_info
    }
    Err(NetconfError::Protocol(e)) => { /* Capability/session errors */ }
    Ok(response) => { /* Success */ }
}
```

## Roadmap

### v0.1 (current)
- Async NETCONF 1.0/1.1 client over SSH
- Core RPC operations with typed errors
- Password + key + agent authentication

### Future
- **Multi-vendor profiles** — normalize Cisco vs. Juniper vs. Arista quirks behind a consistent API
- **YANG code generation** — `yang-codegen` crate to generate Rust types from YANG models for compile-time config validation
- **Confirmed commit** — automatic rollback safety net via RFC 6241 §8.4
- **CLI tool** — Terraform-like network config management (diff, rollback, dry-run)

## License

TBD — see [Open Questions](TODOS.md)

## Contributing

Contributions welcome! See [ARCHITECTURE.md](ARCHITECTURE.md) for the codebase design.
