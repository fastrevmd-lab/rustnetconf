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
