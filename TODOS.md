# TODOS — rustnetconf

## Next priorities (as of 2026-07-17, post-v0.13.0)

Recommended order for upcoming work. Grounded in current state: v0.13.0 shipped;
`DevicePool`, vendor profiles, TLS (RFC 7589), and notifications (RFC 5277) are all
in place and published. Reorder to taste — this is an engineering recommendation, not
a fixed roadmap.

**P1 — Multi-device orchestration (`--all`).** The single biggest product gap. The CLI
is still one-device-per-invocation while the async `DevicePool` foundation sits unused
by it — and v0.13.0 just made per-device vendor overrides work in the pool. This is
"the product" per the backlog entry below. Needs its own design pass (concurrency
limits, partial-failure semantics, aggregated diff/apply output). Start with
`plan --all`, then `apply --all`.

**P2 — RFC 6470 Base Notifications.** Cheap now that the RFC 5277 notification stream
landed — mostly typed structs + parsing over existing infrastructure. High
value-to-effort ratio; good follow-on while the notification code is fresh.

**P3 — RFC 6022 `get-schema` / `netconf-state`.** Enables capability auto-discovery and
feeds `rustnetconf-yang` (fetch a device's YANG modules directly). Strong synergy with
the existing yang crate; testable against devices advertising `:monitor`.

**P4 — RFC 6243 with-defaults.** Improves get-config/diff fidelity (control over default
values in responses). Self-contained, testable, moderate effort.

Deferred / opportunistic (unchanged priority): IOS-XE vendor profile (blocked on a
Cisco test device), YAML config support (depends on yang maturity), RFC 5717
partial-lock (niche multi-operator), RFC 8526 NMDA (forward-looking, larger), RFC 8071
Call Home (complex SSH role-reversal), RFC 8040 RESTCONF (large; likely a separate
crate).

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

### ~~RFC 7589 — NETCONF over TLS~~ DONE
**Completed:** 2026-07-17. Implemented TLS transport (RFC 7589) via `TlsTransport` in src/transport/tls.rs using `rustls` backend. Supports both server-only and mutual TLS authentication. Exposed via `TlsClientBuilder` and `TlsConfig`, behind the `tls` feature flag. Re-exported in src/lib.rs.

### ~~RFC 5277 — NETCONF Event Notifications~~ DONE
**Completed:** 2026-07-17. Implemented `create-subscription` RPC and async notification stream handling (RFC 5277) in src/notification.rs. Session tracks subscription state and buffers interleaved notifications during RPC exchanges. Client methods: `create_subscription()`, `drain_notifications()`, `recv_notification()`.

### ~~Publish to crates.io~~ DONE
**Completed:** 2026-07-17. All three crates published to crates.io — `rustnetconf` 0.13.0, `rustnetconf-cli` 0.3.4, `rustnetconf-yang` 0.1.4. Installable via `cargo add rustnetconf`. Release tagged `v0.13.0` with GitHub release notes.
