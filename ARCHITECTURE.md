# Architecture — rustnetconf

This document describes the internal architecture of rustnetconf. It serves as the implementation guide and contributor reference.

**Design docs:**
- v0.1: `~/.gstack/projects/rustnetconf/mharman-main-design-20260319-130037.md`
- v0.2: `~/.gstack/projects/rustnetconf/mharman-main-design-20260319-170927.md`

## System Overview

```
┌─────────────────────────────────────────────┐
│              DevicePool                      │  Async connection pool
│  Semaphore(max) + HashMap<name, Vec<Client>>│  checkout() → PoolGuard
└──────────────┬──────────────────────────────┘
               │
┌──────────────▼──────────────────────────────┐
│         Client (thin wrapper)                │  Ergonomic API, builder patterns
│  .connect() .edit_config() .lock()           │  .vendor_profile() for explicit vendor
│  .vendor_name() → "junos" / "generic"        │  NO protocol state
└──────────────┬──────────────────────────────┘
               │
┌──────────────▼──────────────────────────────┐
│      Session (owns ALL state)                │  msg-id counter, capabilities,
│                                              │  framing strategy, vendor profile,
│  ┌─────────┐ ┌───────────┐ ┌──────────────┐ │  RPC dispatch
│  │ msg-id  │ │capabilities│ │vendor_profile│ │
│  │ counter │ │ base:1.0   │ │ JunosVendor  │ │
│  └─────────┘ │ :candidate │ │ GenericVendor│ │
│              └───────────┘ └──────────────┘ │
│  Framing switch + vendor detect after hello │
└──────┬──────────────────────┬───────────────┘
       │                      │
┌──────▼──────┐    ┌──────────▼────────┐
│ RPC Layer   │    │  Framing Layer    │
│ operations  │    │  ┌─────┐ ┌─────┐ │
│ filter      │    │  │ EOM │ │Chunk│ │
│ (serialize/ │    │  └─────┘ └─────┘ │
│  parse XML) │    │  Selected by      │
└─────────────┘    │  Session at hello │
                   └──────────┬────────┘
                              │
                   ┌──────────▼────────┐
                   │ Transport (trait)  │  AsyncRead + AsyncWrite
                   │  SshTransport     │  byte-stream interface
                   │  MockTransport    │  (for tests)
                   └──────────┬────────┘
                              │
                          ┌───▼───┐
                          │Device │
                          └───────┘
```

## Module Structure

```
src/
├── lib.rs              # Public API re-exports
├── client.rs           # Client — thin ergonomic wrapper over Session
├── session.rs          # Session — owns msg-id, capabilities, vendor, framing, RPC dispatch
├── transport/
│   ├── mod.rs          # Transport trait + MockTransport (for tests)
│   └── ssh.rs          # SshTransport — russh-based SSH implementation
├── rpc/
│   ├── mod.rs          # RPC types, response parsing (all 7 rpc-error fields)
│   ├── operations.rs   # XML generation: get, get-config, edit-config, lock, unlock,
│   │                   # commit, confirmed-commit, discard-changes, validate, etc.
│   └── filter.rs       # Subtree and XPath filter builders
├── framing/
│   ├── mod.rs          # Framing trait
│   ├── eom.rs          # NETCONF 1.0 end-of-message framing (]]>]]>)
│   └── chunked.rs      # NETCONF 1.1 chunked framing + mismatch detection
├── vendor/
│   ├── mod.rs          # VendorProfile trait + auto-detection
│   ├── junos.rs        # Juniper Junos — config wrapping, capability normalization
│   └── generic.rs      # Default RFC 6241 behavior (passthrough)
├── pool/
│   └── mod.rs          # DevicePool + PoolGuard — async connection pooling
├── error.rs            # Layered error hierarchy (Transport/Framing/Rpc/Protocol)
├── capability.rs       # Capability URIs, negotiation, well-known constants
└── types.rs            # Datastore, DefaultOperation, TestOption, ErrorSeverity, etc.
```

## Key Design Decisions

### 1. Transport Trait = Byte Stream
The `Transport` trait provides raw byte read/write. Framing sits *above* transport:
- Framing logic written once, shared by all transports (DRY)
- Independently testable without SSH
- Future transports (TLS, RESTCONF) plug in without reimplementing framing

### 2. Thin Client + Fat Session
`Client` is an ergonomic wrapper. `Session` owns all protocol state:
- `message_id: AtomicU32` — incremented per RPC
- `capabilities: Capabilities` — device capabilities from `<hello>`
- `framer: Box<dyn Framer>` — selected during hello exchange
- `vendor_profile: Box<dyn VendorProfile>` — auto-detected or explicit
- `pending_commit: bool` — for CommitUnknown detection

### 3. Session-Managed Framing Switch
```
Hello exchange:
  Client sends <hello> with EOM framing (always)
       │
       ▼
  Device responds with <hello> + capabilities
       │
       ▼
  Session parses capabilities:
    Both advertise :base:1.1? → switch to chunked
    Otherwise                 → stay on EOM
       │
       ▼
  Auto-detect vendor from capabilities:
    Junos capability URI? → JunosVendor
    Otherwise             → GenericVendor
```

### 4. Vendor Profiles
```
trait VendorProfile
├── wrap_config()           — add vendor-specific XML wrapping for edit-config
├── unwrap_config()         — strip vendor wrapper from get-config responses
├── normalize_capability()  — normalize legacy/vendor URIs to standard form
└── close_sequence()        — Standard or DiscardThenClose

Built-in:
├── GenericVendor  — passthrough, standard RFC 6241
├── JunosVendor    — auto-detected via http://xml.juniper.net/netconf/junos/1.0
│   Wraps bare config in <configuration>, strips Junos attributes on read,
│   normalizes legacy urn:ietf:params:xml:ns:netconf: URIs,
│   discards uncommitted changes before session close
└── [IosXeVendor]  — planned, deferred until Cisco test device available
```

### 5. Layered Error Hierarchy
```
NetconfError
├── Transport(TransportError)
│   ├── Connect, Auth, Channel, Io, Ssh
├── Framing(FramingError)
│   ├── Invalid, Incomplete, Mismatch (firmware bug detection)
├── Rpc(RpcError)
│   ├── ServerError(Box<RpcServerError>)  — the 7 RFC 6241 §4.3 fields, boxed
│   ├── Timeout, CommitUnknown, ParseError, MessageIdMismatch
└── Protocol(ProtocolError)
    ├── CapabilityMissing, SessionClosed, HelloFailed, Xml
```

### 6. Connection Pool
```
DevicePool
├── Semaphore(max_connections)  — global concurrency limit
├── devices: HashMap<name, DeviceConfig>
└── connections: HashMap<name, Vec<Client>>  — idle pool

checkout("spine-01") → PoolGuard
  - Acquires semaphore permit (with timeout)
  - Reuses idle connection or creates new one
  - PoolGuard derefs to Client
  - Auto-returns to pool on drop (if healthy)
  - Discard broken connections
```

### 7. SSH Authentication
Three methods via `russh` (pure Rust, no OpenSSL):
- Password, Key file (Ed25519/RSA/ECDSA), SSH agent

## Dependencies

| Crate | Purpose | Why this one |
|-------|---------|-------------|
| `tokio` | Async runtime | Industry standard, required for russh |
| `russh` | SSH client | Pure Rust, no OpenSSL/libssh2 dependency |
| `quick-xml` | XML parsing | Streaming parser, low memory footprint |
| `thiserror` | Error types | Ergonomic derive macros for error enums |
| `tracing` | Logging | Structured, async-aware, composable |
| `futures` | Async utilities | join_all for concurrent pool operations |

## Testing Strategy

Three layers:
1. **Unit tests** — pure logic: framing, RPC serialization, capability parsing, vendor wrapping
2. **Mock Transport** — session and vendor integration with canned NETCONF exchanges
3. **vSRX Integration** — real Juniper vSRX for end-to-end validation including vendor auto-detection and pool operations
