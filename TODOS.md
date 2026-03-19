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

### ~~TODO-003: Framing mismatch detection (device says 1.1, sends EOM)~~ DONE
**Completed:** 2026-03-19. ChunkedFramer detects EOM-framed data (XML start, `<!--` comments, `]]>]]>` delimiter) and returns `FramingError::Mismatch` with actionable message. 5 unit tests added.
