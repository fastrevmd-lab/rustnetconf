# Architecture — rustnetconf

This document describes the internal architecture of rustnetconf. It serves as the implementation guide and contributor reference.

**Design doc:** `~/.gstack/projects/rustnetconf/mharman-main-design-20260319-130037.md`
**Eng review:** Completed 2026-03-19, all decisions locked in.

## System Overview

```
┌─────────────────────────────────────┐
│         Client (thin wrapper)       │  Ergonomic API, builder patterns
│  .connect() .edit_config() .lock()  │  NO protocol state
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│      Session (owns ALL state)       │  msg-id counter, capabilities,
│                                     │  framing strategy, RPC dispatch
│  ┌─────────┐ ┌────────────────────┐ │
│  │ msg-id  │ │ capabilities:      │ │
│  │ counter │ │ base:1.0/1.1       │ │
│  │         │ │ :candidate         │ │
│  │         │ │ :confirmed-commit  │ │
│  └─────────┘ └────────────────────┘ │
│  Framing switch after hello ──────► │
└──────┬──────────────────────┬───────┘
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
├── session.rs          # Session — owns msg-id, capabilities, framing, RPC dispatch
├── transport/
│   ├── mod.rs          # Transport trait (AsyncRead + AsyncWrite)
│   └── ssh.rs          # SshTransport — russh-based SSH implementation
├── rpc/
│   ├── mod.rs          # RPC types and serialization
│   ├── operations.rs   # get, get-config, edit-config, lock, unlock, commit, etc.
│   └── filter.rs       # Subtree and XPath filter builders
├── framing/
│   ├── mod.rs          # Framing trait
│   ├── eom.rs          # NETCONF 1.0 end-of-message framing (]]>]]>)
│   └── chunked.rs      # NETCONF 1.1 chunked framing (RFC 6242)
├── error.rs            # Layered error hierarchy
├── capability.rs       # Capability URIs and negotiation logic
└── types.rs            # Datastore, DefaultOperation, TestOption, ErrorSeverity, etc.
```

## Key Design Decisions

### 1. Transport Trait = Byte Stream
The `Transport` trait provides `AsyncRead + AsyncWrite` — raw bytes, not messages. Framing sits *above* transport. This means:
- Framing logic is written once, shared by all transports (DRY)
- Framing is independently testable without SSH
- Future transports (TLS, RESTCONF) plug in without reimplementing framing

### 2. Thin Client + Fat Session
`Client` is an ergonomic wrapper with builder methods. `Session` owns all protocol state:
- `message_id: AtomicU32` — incremented per RPC
- `capabilities: HashSet<String>` — device capabilities from `<hello>`
- `framer: Box<dyn Framer>` — selected during hello exchange
- No split-brain: all state in one place

### 3. Session-Managed Framing Switch
```
Hello exchange flow:
  Client sends <hello> with EOM framing (always — per RFC)
       │
       ▼
  Device responds with <hello> + capability list
       │
       ▼
  Session parses capabilities:
    Both advertise :base:1.1? → switch to chunked framing
    Otherwise                 → stay on EOM framing
```
The framing switch is a one-time event during session setup. After the switch, all subsequent RPCs use the negotiated framing.

### 4. Layered Error Hierarchy
```
NetconfError
├── Transport(TransportError)
│   ├── Connect       — TCP/SSH connection failed
│   ├── Auth          — authentication rejected
│   ├── Channel       — SSH channel/subsystem error
│   └── Io            — general I/O error
├── Framing(FramingError)
│   ├── Invalid       — malformed frame data
│   ├── Incomplete    — partial frame (connection dropped?)
│   └── Mismatch      — device sent wrong framing type (TODO-003)
├── Rpc(RpcError)
│   ├── ServerError   — parsed <rpc-error> with all 7 RFC 6241 §4.3 fields:
│   │     error_type, error_tag, error_severity, error_app_tag,
│   │     error_path, error_message, error_info
│   ├── Timeout       — RPC response not received within deadline
│   └── CommitUnknown — connection lost after <commit> sent (TODO-001)
└── Protocol(ProtocolError)
    ├── CapabilityMissing — operation requires unsupported capability
    ├── SessionClosed     — operation on closed session
    └── HelloFailed       — capability exchange failed
```

### 5. SSH Authentication
Three methods supported via `russh`, all in v0.1:
- Password authentication
- Key file (Ed25519, RSA, ECDSA)
- SSH agent forwarding

## Data Flow: edit-config Round Trip

```
User code                    Client           Session          Framing     Transport
    │                          │                 │                │            │
    │ edit_config(Candidate)   │                 │                │            │
    │ .config("<xml>")         │                 │                │            │
    │ .send().await            │                 │                │            │
    │─────────────────────────►│                 │                │            │
    │                          │ rpc(EditConfig) │                │            │
    │                          │────────────────►│                │            │
    │                          │                 │ serialize XML  │            │
    │                          │                 │ assign msg-id  │            │
    │                          │                 │ frame(xml)     │            │
    │                          │                 │───────────────►│            │
    │                          │                 │                │ write bytes│
    │                          │                 │                │───────────►│
    │                          │                 │                │            │──► Device
    │                          │                 │                │            │
    │                          │                 │                │ read bytes │
    │                          │                 │                │◄───────────│
    │                          │                 │ deframe(bytes) │            │
    │                          │                 │◄───────────────│            │
    │                          │                 │ parse XML      │            │
    │                          │                 │ check msg-id   │            │
    │                          │ Ok/Err          │ return result  │            │
    │                          │◄────────────────│                │            │
    │ Result<RpcReply>         │                 │                │            │
    │◄─────────────────────────│                 │                │            │
```

## Dependencies

| Crate | Purpose | Why this one |
|-------|---------|-------------|
| `tokio` | Async runtime | Industry standard, required for russh |
| `russh` | SSH client | Pure Rust, no OpenSSL/libssh2 dependency |
| `quick-xml` | XML parsing | Streaming parser, low memory footprint |
| `thiserror` | Error types | Ergonomic derive macros for error enums |
| `tracing` | Logging | Structured, async-aware, composable |

## Testing Strategy

Two layers:
1. **Mock Transport** — in-memory `AsyncRead + AsyncWrite` with canned NETCONF exchanges. Tests framing, session, RPC serialization/parsing without any network. Runs in CI in milliseconds.
2. **vSRX Integration** — real Juniper vSRX devices for end-to-end testing. Catches vendor quirks, validates protocol correctness against production firmware.

See `TODOS.md` for tracked implementation items.
