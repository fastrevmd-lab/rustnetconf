# TODOS — rustnetconf

## v0.1 Implementation

### TODO-001: Handle mid-RPC disconnect during commit (CommitUnknown error)
**What:** Add a `CommitUnknown` error variant for when SSH drops after sending `<commit>` but before receiving the response.
**Why:** The device may have committed the change but the client doesn't know. Without a distinct error type, users can't write recovery logic ("if CommitUnknown, verify device state"). This is the #1 trust issue in network automation libraries — ncclient has this gap and users complain.
**Effort:** ~20 lines in session.rs + error.rs
**Depends on:** Session state machine, layered error hierarchy
**Added:** 2026-03-19 via /plan-eng-review

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
