# TODOS — rustnetconf

## Backlog

### Publish to crates.io
**What:** Publish rustnetconf to crates.io for `cargo add rustnetconf` installation.
**Why:** Makes the library discoverable and installable by the Rust ecosystem. Not blocking — library works as a git dependency today.
**Depends on:** Finalize license choice (Apache-2.0/MIT dual-license), crates.io account setup
**Added:** 2026-03-19

## v0.1 Implementation

### ~~TODO-001: Handle mid-RPC disconnect during commit (CommitUnknown error)~~ DONE
**Completed:** 2026-03-19. Session tracks `pending_commit` flag, returns `RpcError::CommitUnknown` when connection drops mid-commit. 3 unit tests added.

### TODO-002: Stale commit lock recovery + confirmed-commit support
**What:** Research and implement handling for stale datastore locks (from crashed sessions) and RFC 6241 §8.4 `confirmed-commit` with timeout rollback.
**Why:** If a client crashes mid-operation, the candidate datastore lock persists until session timeout (5-10 min vendor-dependent). New clients are blocked. `confirmed-commit` provides automatic rollback if the confirming commit isn't sent within the timeout — a safety net for TODO-001's failure scenario.
**Research needed:**
- Vendor-specific lock timeout behavior (Junos, IOS-XE, Arista)
- `kill-session` RPC to clear stale locks
- `:confirmed-commit:1.1` capability detection and confirm-timeout handling
**Effort:** ~100 lines across session.rs, operations.rs, capability.rs
**Depends on:** Session state machine, kill-session RPC, capability detection
**Added:** 2026-03-19 via /plan-eng-review

### TODO-003: Framing mismatch detection (device says 1.1, sends EOM)
**What:** Detect when a device advertises `:base:1.1` but sends EOM-framed responses. Surface a clear `FramingMismatch` error with actionable message: "Device advertised NETCONF 1.1 but sent EOM-framed response. Try forcing 1.0 mode."
**Why:** Known Junos firmware bug in some versions. Chunked decoder gets garbage input and produces cryptic errors. Dedicated detection saves engineers hours of debugging.
**Effort:** ~30 lines in framing layer
**Depends on:** Framing layer, session-managed framing switch
**Added:** 2026-03-19 via /plan-eng-review
