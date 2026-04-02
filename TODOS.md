# TODOS — rustnetconf

## Backlog

### YAML config file support (CLI v2.0)
**What:** Add YAML as an alternative desired-state format alongside XML for the CLI tool.
**Why:** YAML is more ergonomic than XML. Most DevOps engineers prefer it.
**Depends on:** CLI v1.0 (XML-native), rustnetconf-yang for YAML→XML conversion with namespace/type awareness.
**Added:** 2026-03-19 via /plan-eng-review

### Multi-device orchestration (CLI v2.0)
**What:** `netconf plan --all` and `netconf apply --all` for concurrent fleet operations across all inventory devices.
**Why:** The payoff of async Rust + DevicePool. Single-device is the foundation; multi-device is the product.
**Depends on:** CLI v1.0, DevicePool from v0.2.
**Added:** 2026-03-19 via /plan-eng-review

### RFC 7589 — NETCONF over TLS
**What:** Investigate and implement TLS as a second transport alongside SSH.
**Why:** Many enterprise environments prefer or require TLS for NETCONF (especially RESTCONF-adjacent deployments). The transport trait architecture already supports pluggable transports.
**Investigation:**
- Evaluate `rustls` vs `native-tls` for the TLS backend (prefer `rustls` to stay pure-Rust)
- Determine certificate-based mutual auth requirements (RFC 7589 §3)
- Design `TlsTransport` implementing the existing `Transport` trait
- Assess impact on connection pooling (DevicePool needs transport-agnostic checkout)
- Test against devices that support NETCONF over TLS (port 6513)
**Added:** 2026-04-01

### RFC 5277 — NETCONF Event Notifications
**What:** Investigate and implement `create-subscription` RPC and async notification stream handling.
**Why:** Event notifications enable real-time monitoring of device state changes — critical for network automation platforms.
**Investigation:**
- Implement `create-subscription` RPC with stream, filter, startTime, stopTime parameters
- Design async notification receiver (tokio channel or Stream trait) for incoming `<notification>` messages
- Handle interleaved notifications with RPC replies on the same session
- Determine if notification parsing should be generic XML or typed via YANG models
- Test with devices that advertise `:notification` capability
**Added:** 2026-04-01

### RFC 5717 — Partial Lock RPC
**What:** Investigate and implement `partial-lock` and `partial-unlock` RPCs for XPath-scoped locking.
**Why:** Partial lock enables multiple managers to lock different subtrees concurrently — essential for multi-operator environments.
**Investigation:**
- Implement `partial-lock` RPC with XPath select expressions and `partial-unlock` with lock-id
- Determine XPath expression validation strategy (client-side vs device-side only)
- Track lock-ids returned by the device for unlock operations
- Assess interaction with existing full `lock`/`unlock` and `lock_or_kill_stale`
- Test with devices that advertise `:partial-lock` capability
**Added:** 2026-04-01

### RFC 8071 — NETCONF Call Home
**What:** Investigate and implement reverse-SSH (and optionally reverse-TLS) where the device initiates the connection to the manager.
**Why:** Call Home is required for zero-touch provisioning and environments where the manager cannot reach devices directly (NAT, firewalled management planes).
**Investigation:**
- Design a `CallHomeListener` that binds a local port and accepts incoming device connections
- Handle SSH server-side role reversal (manager acts as SSH server for the incoming connection)
- Determine how to map incoming connections to device identity (SSH host key, TLS cert)
- Integrate accepted connections into the existing `Client` / `DevicePool` workflow
- Assess dependency on RFC 7589 (TLS transport) for the TLS call-home variant
**Added:** 2026-04-01

### RFC 6243 — With-defaults Capability
**What:** Investigate and implement the `with-defaults` parameter for `get`, `get-config`, and `copy-config` operations.
**Why:** Devices omit default values by default — operators need explicit control over whether defaults appear in responses (report-all, trim, explicit, report-all-tagged).
**Investigation:**
- Add `with_defaults` parameter to `get_config()` and `get()` builder APIs
- Parse the device's `:with-defaults` capability URI to discover supported modes
- Implement the four basic modes: report-all, trim, explicit, report-all-tagged
- Determine if `report-all-tagged` requires special XML attribute handling in response parsing
- Test with devices that advertise the with-defaults capability
**Added:** 2026-04-01

### RFC 6022 — YANG Module for NETCONF Monitoring
**What:** Investigate and implement the `get-schema` RPC and `netconf-state` monitoring data model.
**Why:** `get-schema` lets the client pull YANG modules directly from a device — essential for auto-discovery of device capabilities and feeding into rustnetconf-yang code generation. The `netconf-state` data model exposes active sessions, supported schemas, datastores, and statistics.
**Investigation:**
- Implement `get-schema` RPC with identifier, version, and format parameters
- Parse `get-schema` response to extract YANG/YIN module text
- Determine integration path with rustnetconf-yang (fetch schema → generate types at runtime vs build-time)
- Implement `netconf-state` queries (sessions, schemas, datastores, statistics) via standard `get` with subtree filter
- Test with devices that advertise `:monitor` capability (urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring)
**Added:** 2026-04-01

### RFC 8526 — NETCONF Extensions for NMDA
**What:** Investigate and implement `get-data` and `edit-data` RPCs for the Network Management Datastore Architecture.
**Why:** Modern devices are moving to the NMDA model which splits datastores into running/intended/operational. `get-data`/`edit-data` are becoming the standard RPCs, replacing `get-config`/`edit-config` on NMDA-capable devices.
**Investigation:**
- Implement `get-data` RPC with datastore, subtree/xpath filter, config-filter, origin-filter, with-origin parameters
- Implement `edit-data` RPC with datastore and config parameters
- Add NMDA datastore types (operational, intended) alongside existing Running/Candidate/Startup
- Parse `:nmda` capability URIs to detect NMDA-capable devices
- Determine coexistence strategy — fall back to `get-config`/`edit-config` on non-NMDA devices
- Test with devices that advertise `urn:ietf:params:netconf:capability:nmda:1.0`
**Added:** 2026-04-01

### RFC 6470 — NETCONF Base Notifications
**What:** Investigate and implement base notification types for NETCONF session and configuration events.
**Why:** Natural companion to RFC 5277 — defines the standard notification types (session start/end, config change, confirmed-commit, capability-change) that most devices emit. Minimal extra work once RFC 5277 notification infrastructure is in place.
**Investigation:**
- Define typed structs for base notification events: netconf-config-change, netconf-capability-change, netconf-session-start, netconf-session-end, netconf-confirmed-commit
- Parse notification XML into typed events
- Determine if these should be auto-subscribed or opt-in via `create-subscription` stream filter
- Assess integration with the RFC 5277 notification stream design
**Depends on:** RFC 5277 (Event Notifications)
**Added:** 2026-04-01

### RFC 8040 — RESTCONF
**What:** Investigate and implement RESTCONF as an HTTP/REST interface to YANG-modeled data.
**Why:** RESTCONF is the HTTP counterpart to NETCONF — many modern devices support both. The transport trait architecture is designed for pluggable transports, and RESTCONF would significantly broaden the library's reach.
**Investigation:**
- Evaluate HTTP client crate (`reqwest` with `rustls` to stay pure-Rust)
- Design `RestconfTransport` — map NETCONF operations to RESTCONF HTTP methods (GET/POST/PUT/PATCH/DELETE)
- Handle JSON and XML encoding (RESTCONF supports both via Accept/Content-Type headers)
- Implement RESTCONF-specific features: YANG Patch (RFC 8072), event streams (SSE), discovery via `/.well-known/host-meta`
- Determine how much of the existing `Client` API can be reused vs RESTCONF-specific client
- Assess scope — this is a large effort, may warrant a separate `rustnetconf-restconf` crate
**Added:** 2026-04-01

### IOS-XE vendor profile
**What:** Implement `IosXeVendor` profile for Cisco IOS-XE NETCONF devices — config namespace wrapping, capability normalization, session termination quirks.
**Why:** IOS-XE is the second most common NETCONF implementation. Without it, Cisco users must use GenericVendor and handle quirks manually.
**Depends on:** VendorProfile trait (v0.2), access to a Cisco IOS-XE NETCONF device (CSR1000v or Cat8000v) for integration testing. Deferred from v0.2 — ship what we can test.
**Added:** 2026-03-19 via /plan-eng-review

### Publish to crates.io
**What:** Publish rustnetconf to crates.io for `cargo add rustnetconf` installation.
**Why:** Makes the library discoverable and installable by the Rust ecosystem. Not blocking — library works as a git dependency today.
**Depends on:** Finalize license choice (Apache-2.0/MIT dual-license), crates.io account setup
**Added:** 2026-03-19

## v0.1 Implementation

### ~~TODO-001: Handle mid-RPC disconnect during commit (CommitUnknown error)~~ DONE
**Completed:** 2026-03-19. Session tracks `pending_commit` flag, returns `RpcError::CommitUnknown` when connection drops mid-commit. 3 unit tests added.

### ~~TODO-002: Stale commit lock recovery + confirmed-commit support~~ DONE
**Completed:** 2026-03-19. Three features implemented:
1. `confirmed_commit(timeout)` — RFC 6241 §8.4 confirmed-commit with auto-rollback timer
2. `confirming_commit()` — makes a confirmed-commit permanent
3. `lock_or_kill_stale(target)` — tries lock, if denied parses stale session-id from error-info, kills it, retries
Also fixed `<error-info>` parsing to preserve child element XML (e.g., `<session-id>42</session-id>`).
9 unit tests added.

### ~~TODO-003: Framing mismatch detection (device says 1.1, sends EOM)~~ DONE
**Completed:** 2026-03-19. ChunkedFramer detects EOM-framed data (XML start, `<!--` comments, `]]>]]>` delimiter) and returns `FramingError::Mismatch` with actionable message. 5 unit tests added.
