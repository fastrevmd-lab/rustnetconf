<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/mechub-mark.svg">
    <img src="docs/assets/mechub-mark-light.svg" width="72" alt="mechub mark">
  </picture>
</p>

<h1 align="center">rustnetconf</h1>

<p align="center"><strong>A Rust network automation platform</strong><br>
<em>a mechub project — sovereign network-security automation</em></p>

<p align="center">
  <a href="https://crates.io/crates/rustnetconf"><img alt="crates.io — rustnetconf" src="https://img.shields.io/crates/v/rustnetconf.svg?label=rustnetconf&color=0D9488"></a>
  <a href="https://crates.io/crates/rustnetconf-cli"><img alt="crates.io — rustnetconf-cli" src="https://img.shields.io/crates/v/rustnetconf-cli.svg?label=rustnetconf-cli&color=262B38"></a>
  <a href="https://crates.io/crates/rustnetconf-yang"><img alt="crates.io — rustnetconf-yang" src="https://img.shields.io/crates/v/rustnetconf-yang.svg?label=rustnetconf-yang&color=262B38"></a>
  <a href="https://github.com/fastrevmd-lab/rustnetconf/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/fastrevmd-lab/rustnetconf/actions/workflows/ci.yml/badge.svg"></a>
  <a href="#license"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-262B38.svg"></a>
</p>

> **Unofficial / community project.** This repository is an independent, community-driven project. It is not affiliated with, endorsed by, sponsored by, or supported by Hewlett Packard Enterprise or Juniper Networks. "HPE", "Juniper", "SRX", "JUNOS", "Security Director" and "Juniper Mist" are trademarks of their respective owners and are used here only to describe what this software interoperates with. Please direct support and licensing questions about those products to the respective vendors.

Async NETCONF client library, YANG code generation, vendor profiles, connection pooling, and a Terraform-like CLI for declarative network config management.

Built on [tokio](https://tokio.rs), [russh](https://crates.io/crates/russh), and [rustls](https://crates.io/crates/rustls) — pure Rust, no OpenSSL, no libssh2.

> **Latest release — [v0.15.0](https://github.com/fastrevmd-lab/rustnetconf/releases/tag/v0.15.0)** (smaller error types — one breaking change).
> On crates.io: `rustnetconf` 0.15.0 · `rustnetconf-cli` 0.3.6 · `rustnetconf-yang` 0.1.6.
> See [What's New in v0.15.0](#whats-new-in-v0150) below.

## Workspace

| Crate | Description |
|-------|-------------|
| **rustnetconf** | Async NETCONF 1.0/1.1 client library |
| **rustnetconf-yang** | YANG model code generation (compile-time config validation) |
| **rustnetconf-cli** | Terraform-like CLI tool (`netconf` binary) |

## Scope

This is a **NETCONF library** — RFC 6241 (the protocol) and RFC 6242 (NETCONF over SSH) — plus YANG code generation and a CLI built on it.

SSH is present as a *transport for NETCONF*, not as a general-purpose capability. The crate deliberately does **not** provide:

- File transfer (SFTP, SCP) — it is not a file-transfer library
- A public `russh` handle, or a generic "open any SSH subsystem" escape hatch — the SSH connection is an implementation detail of the NETCONF transport, and keeping it private is what stops this crate's public API from becoming russh's version surface
- Remote shell or command execution

Consumers that need those should use a dedicated SSH crate alongside this one. A native SCP1 client was briefly added and then reverted before it was ever released (#52, reverted by #53) for exactly this reason; issues #47 and #51 were closed as not planned on the same grounds. The round trip is visible in `git log` between v0.13.2 and the next release — it was a deliberate reversal, not an accident.

## What's New in v0.15.0

Breaking change (#66). One variant changes shape; nothing else in the public API moves. `rustnetconf-cli` (0.3.6) and `rustnetconf-yang` (0.1.6) have no source changes and bump only to carry the new `rustnetconf = "0.15"` requirement, exactly as they did at 0.14.0.

- **`RpcError::ServerError` now carries a boxed struct.** Its 7 RFC 6241 §4.3 fields moved into a new public `RpcServerError`, and the variant became `ServerError(Box<RpcServerError>)`. The fields are unchanged, still public, and still all present — only where they live moved.

  ```rust
  // before
  Err(NetconfError::Rpc(RpcError::ServerError { tag, message, .. })) => ...

  // after
  Err(NetconfError::Rpc(RpcError::ServerError(e))) => ... // e.tag, e.message
  ```

  Construction gets `From<RpcServerError>` for both `RpcError` and `NetconfError`, so `rpc_server_error.into()` boxes for you. `Display` output is byte-for-byte what it was — code matching on the error *string* is unaffected.

- **Why: the error types were exactly 128 bytes.** `NetconfError` and `RpcError` both measured 128, which is precisely clippy's `result_large_err` threshold, so every fallible function in the public surface tripped the lint — 71 sites once the suppression was lifted. `ServerError` was the whole of it: `message` plus three `Option<String>` is 96 bytes before `ErrorTag`'s own 24. Boxing that one variant takes `RpcError` 128 → 48 and `NetconfError` 128 → 72, and the ceiling becomes `TransportError::HostKeyMismatch` at 72.

  Every `Result<T, NetconfError>` in the crate was moving 128 bytes on the success path too, since a `Result` is as wide as its larger arm.

- **The suppression is gone, not relocated.** `#![allow(clippy::result_large_err)]` in `src/lib.rs` and two local allows in `src/session.rs` were removed; `cargo clippy --workspace --all-targets --all-features -- -D warnings` passes clean without them. A new test asserts each error enum stays under 128 bytes, so a future inline `String` field fails the suite rather than quietly re-arming the lint.

- **The toolchain is now pinned.** `rust-toolchain.toml` pins 1.98.0, matching every sibling crate. CI installed `stable` unpinned, which is why a clippy release turned the gate red with no change on this side.

## What's New in v0.14.5

Bug-fix release (#67). `rustnetconf-cli` and `rustnetconf-yang` are unchanged. No API changes — a drop-in patch upgrade from 0.14.4.

- **Fixed: a benign Junos warning no longer sinks the whole load.** Deleting a statement that is not present on an SRX345 returns an `<rpc-error>` carrying only severity and message — RFC 6241 makes `error-type` and `error-tag` mandatory, and Junos omits both. `RpcErrorBuilder::finish` rejected the reply with "rpc-error is missing error-type", so a warning failed the load and took `commit_check_config` and `apply_junos_change_set` with it — the same tools 0.14.4 had just unblocked on the same device.

- **The tolerance is keyed on severity.** A missing `error-type`/`error-tag` is accepted only when severity is `warning`: a warning carries no verdict, so an absent classification costs nothing, while an `error`-severity `rpc-error` still has to say what it is rather than be reported under an invented tag. `RpcErrorInfo` already modelled `error_type` as `Option`, so the struct did not change; a missing tag becomes `ErrorTag::Other("unspecified")`.

  Severity is read but not consumed before the type and tag checks, so the strict path still reports error-type, then error-tag, then error-severity in that order — an empty `<rpc-error/>` fails exactly as it always did.

## What's New in v0.14.4

Bug-fix release (#65). `rustnetconf-cli` and `rustnetconf-yang` are unchanged. No API changes — a drop-in patch upgrade from 0.14.3.

- **Fixed: a standalone SRX's commit-check verdict was lost.** A single-RE SRX345 answers a commit-check with a closed `<commit-results>` followed by a sibling `<ok/>`. RFC 6241 does not allow a payload and `<ok/>` together, so the reply failed to parse with "`<ok/>` conflicts with an existing payload" and the verdict was discarded even though the check had passed. This made the governed write path unusable on the lab's physical SRX345 while the ungoverned one worked ([rustjunosmcp#358](https://github.com/fastrevmd-lab/rustjunosmcp/issues/358)).

  The chassis-cluster form of the same reply already parsed, because there Junos leaves `<routing-engine>` unclosed — the payload is still open when `<ok/>` arrives. That existing tolerance was keyed on depth > 0, so it covered only the malformed shape: a device that closed the element correctly fared *worse* than one that did not.

- **The scope is deliberately narrow.** Exactly one `<ok/>` after a closed `<commit-results>` is tolerated. An earlier draft accepted `<ok/>` after any closed direct payload, which turned `<software-information>…</software-information><ok/>` into `RpcReply::Ok` — handing the caller an empty string and silently dropping a body it had asked for. Trading a loud parse error for silent data loss is the wrong trade, so every other direct payload keeps the conflict, as do a duplicate `<ok/>` and any direct sibling following the tolerated one. A hard `<rpc-error>` still wins, so a failed check is never reported as passing. All four boundaries are pinned by tests, against a fixture captured off the wire from the SRX345 on Junos 21.2R3-S6.11.

- **Also: `clippy::result_large_err` suppressed.** Stable 1.98.0 turned it into a red gate on main. Suppression was the right scope for a patch release carrying a production bugfix; the lint is fixed properly in 0.15.0 (#66).

## What's New in v0.14.3

Bug-fix release (#61). `rustnetconf-cli` and `rustnetconf-yang` are unchanged. No API changes — every function touched is private — so a drop-in patch upgrade from 0.14.2.

- **Fixed: a cancelled commit no longer misclassifies the next unrelated failure.** `Session` tracked "a commit is in flight" in a `pending_commit` field, set before the send and cleared after it. Drop that future at its `.await` — a `tokio::time::timeout`, a `select!` — and the reset never ran, so the flag stayed set for the life of the session. The next unrelated transport EOF, during a `get-config` or anything else, was then reported as `RpcError::CommitUnknown`.

  That is the flag's purpose inverted. It exists so a genuinely indeterminate commit is not mistaken for a clean I/O failure; the leak made a clean I/O failure look like an indeterminate commit, which can send a caller hunting for a commit that never happened or stop it retrying something perfectly safe to retry.

- **The fix removes state rather than guarding it.** "This is a commit" describes one call, not the session, so it is now an `is_commit` parameter threaded through the private `send_rpc_raw` → `read_rpc_reply` → `read_message` chain, and the field is gone. Cancellation-safety follows by construction: the fact lives in the call frame and dies with any future that is dropped. Commit paths call a new private `send_rpc_commit()`; the other 20 `send_rpc` call sites are untouched.

  An RAII guard was considered and rejected — holding `&mut self.pending_commit` across `self.send_rpc(&mut self)` does not borrow-check, so it would have forced the flag into `Rc<Cell<bool>>`/`Arc<AtomicBool>`, adding an allocation and indirection to every session to fix an error path.

- **Regression test.** `test_cancelled_commit_does_not_poison_later_eof` cancels a commit mid-await against a transport that parks, then asserts a following non-commit EOF is reported as a transport error. It was verified to **fail** against the 0.14.2 implementation, returning `CommitUnknown`, so it guards the fix rather than passing vacuously. A `StallingMockTransport` was added for it, because the existing mock reads synchronously and can never be interrupted mid-await.

## What's New in v0.14.2

Follow-up to 0.14.1, from wiring the consumer side in [rustez#41](https://github.com/fastrevmd-lab/rustez/issues/41) (#60). `rustnetconf-cli` and `rustnetconf-yang` are unchanged — their `rustnetconf = "0.14"` requirement already matches.

No API removals and no source-breaking changes, so a drop-in patch upgrade. One deliberate behaviour change, on an error path only: a Junos `commit-configuration` that disconnects before its reply now reports `CommitUnknown` instead of a generic transport error — see the second bullet.

- **New `Session::commit_configuration_with_log()` / `Client::commit_configuration_with_log()`** — additive. A Junos commit carrying a log comment, visible in `show system commit`. The log text is XML-escaped for you. Clears the candidate-dirty flag on success, exactly as `commit_configuration()` does.

  `commit_configuration()` takes no arguments and `commit_configuration_xml()` hard-coded a bare `<commit-configuration/>`, so a caller wanting Junos's `<log>` child had to build the fragment and send it through raw `rpc()`. Every method that clears the dirty flag does so as a private side effect, and there is no public way to clear it — so that raw path could not. The session stayed marked dirty across a commit that genuinely cleaned the candidate, and `close_session()` then discarded afterwards. Harmless for that session's own work; on the **shared** Junos candidate it destroys anything another operator staged between the commit and the close. This is the mirror of #58: that was an RPC that could not atomically *set* the flag, this was a commit that could not *clear* it.

- **`commit_configuration()` keeps its signature and its XML.** Both methods now delegate to one private helper; the no-log path emits byte-identical XML, asserted in a test. `rpc::operations::commit_configuration_xml()` also keeps its one-argument form — the log variant is a separate `commit_configuration_with_log_xml()`, because that module is public API and changing the arity would break existing callers at source.

- **Fixed: a Junos commit that disconnects before its reply now reports `RpcError::CommitUnknown`.** `commit()` and `confirmed_commit()` already bracketed their send with the pending-commit state; `commit_configuration()` never did, so a mid-commit disconnect surfaced as a generic transport EOF. The device may have applied the commit, and a caller that reads that as a clean failure can retry a commit that already took effect. Both `commit_configuration()` and the new log variant now signal it correctly. This is a behaviour change on an error path only — the success path is untouched.

## What's New in v0.14.1

Additive follow-up to 0.14.0 for `rustnetconf` (0.14.1), from wiring the consumer side in [rustez#36](https://github.com/fastrevmd-lab/rustez/issues/36) (#58). `rustnetconf-cli` (0.3.5) and `rustnetconf-yang` (0.1.5) are unchanged — their `rustnetconf = "0.14"` requirement already matches. No behaviour changes and no API removals: a drop-in patch upgrade from 0.14.0.

- **New `Session::rpc_candidate_change_with_warnings()` / `Client::rpc_candidate_change_with_warnings()`** — additive. The warnings-returning counterpart of `rpc_candidate_change()`, returning the same `(String, Vec<RpcErrorInfo>)` tuple as `rpc_with_warnings()` with the same preflight-then-mark ordering.

  0.14.0 left the warnings path without an atomic option. A caller who needed the warnings back from a candidate-modifying RPC had only `rpc_with_warnings()` plus a hand call to `mark_candidate_dirty()`, and that is not equivalent: `rpc_with_warnings()` validates the fragment and returns *before sending anything*, so a hand-marked malformed fragment left the candidate marked dirty for an RPC that never reached the device — and the next `close_session()` would then send `<discard-changes/>` against another operator's uncommitted work. That is the #55 bug reached by a different route. Hand-marking also could not replicate the keepalive and session-state preflight, since neither is public.

- **No change needed if you already use `rpc_candidate_change()`.** Its ordering and behaviour are identical; the sequence simply moved into a shared internal helper that both methods now call.

## What's New in v0.14.0

Junos candidate-datastore safety for `rustnetconf` (0.14.0), from a bug reproduced on hardware (#55, PR #56). `rustnetconf-cli` (0.3.5) and `rustnetconf-yang` (0.1.5) carry the new dependency requirement but have no source changes.

**This is a behaviour change on close, which is why it is a minor bump and not a patch.** Read the last bullet before upgrading if you send candidate-modifying RPCs through the raw `rpc()` escape hatch.

- **`close_session()` no longer discards a candidate this session never touched** (#55). Junos returns `CloseSequence::DiscardThenClose`, and the discard fired unconditionally — including for sessions that only read. On a standalone Junos device the candidate datastore is *shared*, so closing such a session destroyed uncommitted work belonging to an operator at the CLI or to another NETCONF client. The session now tracks whether it dirtied the candidate and discards only then.

  The tracking is deliberately asymmetric. `edit_config` (candidate target only), `load_configuration`, and `rollback_configuration` mark *before* sending, so a partial or failed edit still counts; `commit`, `commit_configuration`, `confirmed_commit`, `discard_changes`, and `close_configuration` clear it only on success. Anything that fails after the write begins still marks dirty, because a partially applied change does need cleaning up.

- **New `Session::rpc_candidate_change()` / `Client::rpc_candidate_change()`** — additive. The supported way to send a vendor-specific candidate-modifying RPC (Junos `<load-configuration>` and friends) through the raw path. It validates the fragment, completes the send preflight, marks the candidate dirty, and only then writes, so a locally rejected fragment or a failed keepalive probe cannot leave a false mark that a later close would act on.

- **New `mark_candidate_dirty()` / `candidate_dirty()`** on both `Session` and `Client` — additive, for callers who need manual control. Prefer `rpc_candidate_change()`: marking by hand before an RPC that never reaches the device reintroduces exactly the bug above.

- **Upgrade note.** If you send candidate-modifying RPCs through raw `rpc()`, you were previously relying on the unconditional discard to clean up after them. That cleanup is now conditional and will not fire for those calls. Switch them to `rpc_candidate_change()`. Everything going through the typed operations (`edit_config`, `load_configuration`, `rollback_configuration`) is tracked automatically and needs no change.

## What's New in v0.13.3

Maintenance release for `rustnetconf` (0.13.3). `rustnetconf-cli` (0.3.4) and `rustnetconf-yang` (0.1.4) are unchanged. No public API changes — a drop-in patch upgrade from 0.13.2.

- **RPC reply parsing hardened** (#49). Reply parsing and repair moved into a dedicated `reply` module with tightened handling of malformed and partial replies. `parse_rpc_reply`, `RpcReply`, and `RpcErrorInfo` keep their existing paths and signatures via re-export.
- **russh 0.62.4 → 0.62.5** (#50). Picks up the `Channel::data()` backpressure fix. The GHSA-m65r-rprj-r5rg advisory in that release is server-side only; this crate uses `russh::client` exclusively and was never exposed to it.
- **cmov 0.5.3 → 0.5.4** (#46).
- **License gating in CI.** A `deny.toml` allow-list now exists, and CI runs `cargo deny check bans sources licenses`. Previously licenses were ungated, because with no config cargo-deny rejects every license by default.
- **Scope documented** — see [Scope](#scope). A native SCP1 client was added (#52) and reverted (#53) within this cycle, before any release; issues #47 and #51 were closed on the same grounds. No released version ever contained it.

## What's New in v0.13.0

Vendor-profile plumbing for `rustnetconf` (0.13.0) and `rustnetconf-cli` (0.3.4), from a project review (PRs #37, #38). `rustnetconf-yang` is unchanged at 0.1.4.

- **`DevicePool` honors an explicit vendor profile.** `DeviceConfig.vendor` is now wired into connection setup — previously it was silently ignored. The field changed from `Box<dyn VendorProfile>` to `Arc<dyn VendorProfile>`; new `ClientBuilder::vendor_profile_arc()` and `Session::set_vendor_profile_arc()` support the shared-ownership path. The existing `vendor_profile(Box<…>)` API is unchanged.
- **New `Client::unwrap_config()`** (and `Session::unwrap_config()`) exposes the connected device's vendor `unwrap_config` — additive public API.
- **Vendor-aware CLI diffs.** `netconf plan`/`apply` now normalize the desired config through the connected device's vendor profile instead of a hardcoded `<configuration>` strip. This fixes an asymmetric, potentially wrong diff against generic (non-Junos) devices; Junos behavior is unchanged.
- Internally, `VendorProfile::post_facts_hook` takes `&self` (with `JunosVendor` cluster state moved to interior mutability) so profiles work under `Arc`.

## What's New in v0.12.3

Parser correctness patch for `rustnetconf` (0.12.3) and `rustnetconf-cli` (0.3.3), from a full code review (closes #33 via PR #34). No API changes; `rustnetconf-yang` is unchanged at 0.1.4.

- **Namespace prefixes preserved** when reconstructing `<data>`/`error-info`/Junos inner XML — `<if:interfaces xmlns:if="…">` no longer collapses to `<interfaces>`.
- **CDATA sections captured** in every parser (reply data, error fields, capabilities, eventTime, session-id, CLI diff) instead of being silently dropped.
- **Attribute values fully re-escaped** on reconstruction, so single-quoted source attributes containing `"` can't produce malformed output.
- **Text-format Junos config is XML-escaped** in `load_configuration` — set commands containing `&`/`<`/`>` previously generated malformed RPCs.
- **Top-level empty elements** under `<rpc-reply>` (e.g. `<software-information/>`) now parse as data instead of a bare `<ok/>`.
- Dependency hygiene: `anyhow` 1.0.103 (clears RUSTSEC-2026-0190) and un-yanked `crypto-bigint` 0.7.5 — `cargo audit` is fully clean.

## What's New in v0.12.2

Security patch for all three crates (`rustnetconf` 0.12.2, `rustnetconf-cli` 0.3.2, `rustnetconf-yang` 0.1.4), closing #31. No API changes.

- **quick-xml 0.37 → 0.41:** clears two RUSTSEC advisories in the XML parser that handles device-returned NETCONF data — [RUSTSEC-2026-0194](https://rustsec.org/advisories/RUSTSEC-2026-0194) (quadratic duplicate-attribute check) and [RUSTSEC-2026-0195](https://rustsec.org/advisories/RUSTSEC-2026-0195) (unbounded namespace-declaration allocation, memory-exhaustion DoS).
- **Entity handling adapted to quick-xml 0.38+ semantics:** entity references (`&amp;`, `&#38;`, …) now stream as separate `GeneralRef` events instead of arriving decoded inside text. All reader loops accumulate and resolve them, so element values containing `&`, `<`, `>` (Junos descriptions, URLs, error messages) round-trip whole instead of being silently truncated. Covered by new round-trip regression tests in every parser.
- **Dropped the unused `serialize` (serde) feature** of quick-xml in `rustnetconf-yang` — the crate only uses the manual `Writer` API.

## What's New in v0.12.1

Security and robustness patch for `rustnetconf` (0.12.1) and `rustnetconf-cli` (0.3.1). No API changes.

- **Well-formed reconstructed XML:** the RPC reply parser now re-escapes decoded entities (`&`, `<`, `>`) when reconstructing `<data>`, `error-info`, and Junos inner content. Previously `unescape()`-decoded text was re-emitted raw, which could yield malformed XML for device data containing special characters. Covered by new regression tests.
- **Cleared yanked dependency:** bumped `russh` 0.60 → 0.61 and `aes` to 0.9.1, clearing the `cargo audit` yanked-crate warning (and reducing the dependency count).
- **Non-Unix state-file safety:** on non-Unix platforms (no portable `chmod`), `netconf` now emits a warning that saved state snapshots are not guaranteed owner-only and documents the caveat, since snapshots may contain sensitive device config.

## What's New in rustnetconf-yang v0.1.3

Documentation-only patch release of the `rustnetconf-yang` crate (closes #30). No API or behavior changes.

- Module docs now state that generated types require enabling the `generated` Cargo feature (off by default) — without it the `ietf_*` modules are absent.
- Clarified that codegen reads the crate's own bundled `yang-models/`, not the consumer's project; documented how to vendor the crate to use custom YANG files.
- Corrected the usage example to the real generated API (`Option`-wrapped fields, `type` leaf emitted as `type_`).

## What's New in v0.12.0

OpenSSH `known_hosts`-style host-key pinning for fleet operation. Merged via PR #29 (closes #28).

**New features:**
- `HostKeyVerification::KnownHosts(PathBuf)` — verify the server's SHA-256 fingerprint against an OpenSSH `known_hosts(5)` file on every connect. Supports plain hostnames, `[host]:port`, wildcards (`*`/`?`), CIDR networks, hashed `|1|salt|hmac-sha1` entries, and `@revoked` markers. The file is re-read on every connect — no caching, so external rotation tools are picked up immediately.
- New structured errors on `TransportError`: `HostKeyMismatch { host, expected, actual }`, `HostKeyNotInKnownHosts { host, port, path }`, `HostKeyRevoked { host }`.
- CLI: new optional `known_hosts_path` field on `[devices.*]` and `[defaults]` in `inventory.toml`. Per-device value wins; setting both `host_key_fingerprint` and `known_hosts_path` on the same device is a hard error.
- `examples/known_hosts.rs` demonstrates the `ssh-keyscan` → `KnownHosts(path)` workflow with comments on each failure mode.

**Breaking changes:**
- `DeviceConfig` (the connection-pool config struct) gained a new field `host_key_verification: Option<HostKeyVerification>`. Existing struct-literal callers must add the field. `None` means "use library default" (`RejectAll` since v0.11.0).

**Quality:**
- Live-device integration tests (`integration_vsrx`, `integration_vendor_pool`) are now opt-in via `RUSTNETCONF_TEST_VSRX_HOST` — without it, the suite is a clean no-op for contributors without a Junos lab.

## What's New in v0.11.0

Security remediation pass — addresses the seven findings from the internal
audit (RNC-SEC-001..006 + CI hardening). Merged via PR #27.

**Breaking changes:**
- `ClientBuilder` default `HostKeyVerification` is now `RejectAll` (fail closed). Connections refuse to complete until the caller pins a fingerprint or explicitly opts in to `AcceptAll`. `ProxyJump` hops parsed from `~/.ssh/config` likewise default to `RejectAll`.
- `inventory.toml`: device `password` and `key_passphrase` fields now deserialize into a `SecretString` newtype. `Debug` prints `SecretString(***)` and contents zeroize on drop.
- `ClientBuilder::password` / `.key_passphrase` now accept `Option<Zeroizing<String>>` (was plain `Option<String>`).

**Security fixes:**
- **RNC-SEC-001** — SSH host-key verification fails closed by default in both the library and the CLI. New CLI flag `--insecure-accept-host-key` for lab use; otherwise `host_key_fingerprint` must be set per device in `inventory.toml`.
- **RNC-SEC-002** — RUSTSEC-2023-0071 (rsa Marvin Attack timing side-channel) risk-accepted via `.cargo/audit.toml` with reachability analysis and review date 2026-08-01. russh bumped 0.60.2 → 0.60.3.
- **RNC-SEC-003** — Inventory passwords use the new `SecretString` type with redacted `Debug` and a custom `Deserialize` that zeroizes on drop.
- **RNC-SEC-004** — State files always land at `0o600` via atomic temp-file + `rename(2)`, even when a pre-existing file had looser permissions. `.netconf` and `.netconf/state` are forced to `0o700` on every call. Stale temp files from a prior crash are cleaned up.
- **RNC-SEC-005** — `apply` and `rollback` guarantee candidate-lock cleanup on error. New `Client::release_candidate_lock_best_effort` (discard-changes + unlock, swallowing errors) is invoked from extracted `*_locked_region` helpers.
- **RNC-SEC-006** — Desired XML is validated for well-formedness *before* any device connection or candidate lock. Errors name the offending file.

**CI hardening:**
- New `.github/workflows/ci.yml` runs build, test (workspace, all features), clippy with `-D warnings`, rustfmt, and `cargo audit` on every push and PR to main.

**Quality fixes:**
- YANG codegen: generated `use super::*;` / `use crate::serialize::*;` imports now carry `#[allow(unused_imports)]` so modules without leaf references compile cleanly under `-D warnings`.
- YANG codegen test: corrected `r#type` → `type_` to match the field-sanitization the generator actually emits.

## What's New in v0.10.0

**Breaking changes:**
- `HostKeyVerification` no longer implements `Default` — callers must explicitly choose a host key policy
- `SshAuth::Password` and `SshAuth::KeyFile { passphrase }` now use `Zeroizing<String>` instead of `String`
- User-provided XML content (RPC bodies, filters, configs) is now validated for well-formedness before sending

**Security fixes:**
- Shell injection via ProxyCommand `%h`/`%p` substitution — values are now shell-escaped
- Credentials (passwords, passphrases) zeroized on drop via the `zeroize` crate
- XML fragment validation prevents injection through malformed RPC content
- TLS `danger_accept_invalid_certs` now emits a detailed warning about the full scope of the bypass
- CLI device names validated to prevent path traversal; state files written with `0600` permissions

**New features:**
- Configurable RPC timeout (`.rpc_timeout(Duration)`) — prevents indefinite blocking on unresponsive devices
- Configurable read buffer size (`.max_read_buffer(bytes)`) — defaults to 100 MB
- IPv6 address support — bracket notation (`[::1]:830`) and bare IPv6 addresses
- Capability normalization — legacy Junos capability URIs are mapped to standard URIs during session establishment

**Quality improvements:**
- Connection pool health checks — dead connections are discarded on checkout and drop instead of being recycled
- Blocking `std::fs::read_to_string` in async context replaced with `tokio::fs`
- Unnecessary `Arc<Mutex<>>` removed from `SshTransport`
- `AtomicU64` message counter replaced with plain `u64` (Session is `&mut self` only)
- YANG codegen: full container/list XML serialization, complete Rust keyword list, hard error on module load failure
- CLI: plan summary fixed for non-JSON mode, diff engine compares all list elements
- Removed unused `futures` dependency and `quick-xml` serialize feature
- `ErrorTag` implements `std::str::FromStr`; `Session::validate()` checks `:validate` capability
- Dependency updates: russh 0.60.2, rustls 0.23.40, tokio 1.52.2, rustls-webpki 0.103.13

## RFC Support

| RFC | Feature | Status |
|-----|---------|--------|
| RFC 6241 | Network Configuration Protocol (NETCONF) | ✅ supported |
| RFC 6242 | NETCONF over SSH | ✅ supported |
| RFC 7589 | NETCONF over TLS | ✅ supported (feature flag `tls`) — **needs physical SRX or non-vSRX for TLS test** |
| RFC 5277 | Event Notifications | ✅ supported — tested on Junos 24.4 vSRX (subscription + capability; interleave limited by device) |
| RFC 5717 | Partial Lock RPC | 💡 planned |
| RFC 8071 | NETCONF Call Home | 💡 planned |
| RFC 6243 | With-defaults Capability | 💡 planned |
| RFC 6022 | YANG Module for NETCONF Monitoring | 💡 planned |
| RFC 8526 | NETCONF Extensions for NMDA | 💡 planned |
| RFC 6470 | NETCONF Base Notifications | 💡 planned |
| RFC 8040 | RESTCONF | 💡 planned |

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

**Secrets:** `inventory.toml` may contain plaintext passwords. Prefer
`key_file` or SSH-agent auth where possible. If you must use inline
passwords, protect the file with `chmod 600 inventory.toml` and add it
to `.gitignore`. Passwords are stored in zeroizing memory and redacted
from `Debug` output, but the on-disk file itself is plaintext.

## Library — Quick Start

```toml
[dependencies]
rustnetconf = { git = "https://github.com/fastrevmd-lab/rustnetconf.git" }
tokio = { version = "1", features = ["full"] }
```

For TLS transport (RFC 7589), enable the `tls` feature:

```toml
[dependencies]
rustnetconf = { git = "https://github.com/fastrevmd-lab/rustnetconf.git", features = ["tls"] }
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

### Connect through a jump host (`ProxyJump`)

```rust
use rustnetconf::{Client, Datastore};
use rustnetconf::transport::ssh::{JumpHostConfig, SshAuth, HostKeyVerification};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bastion = JumpHostConfig {
        host: "bastion.example.com".into(),
        port: 22,
        username: "jumpuser".into(),
        auth: SshAuth::Agent,
        host_key_verification: HostKeyVerification::AcceptAll,
    };

    let mut client = Client::connect("10.0.0.1:830")
        .username("admin")
        .ssh_agent()
        .jump_hosts(vec![bastion])
        .connect()
        .await?;

    let config = client.get_config(Datastore::Running).await?;
    println!("{config}");
    client.close_session().await?;
    Ok(())
}
```

### Connect using your `~/.ssh/config`

```rust
use rustnetconf::{Client, Datastore};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Resolves `Host edge-r1` from ~/.ssh/config — picks up HostName, Port,
    // User, IdentityFile, ProxyJump, ProxyCommand. NETCONF default port 830
    // is used when the config doesn't pin Port.
    let mut client = Client::connect_via_ssh_config("edge-r1")?
        .ssh_agent()
        .connect()
        .await?;

    let config = client.get_config(Datastore::Running).await?;
    println!("{config}");
    client.close_session().await?;
    Ok(())
}
```

### Connect over TLS (RFC 7589)

> **Note:** vSRX 24.4 has a known TLS handshake issue where the PKI engine cannot
> present a self-signed certificate chain. TLS testing requires a physical SRX,
> MX, or EX device with a CA-signed certificate. The code compiles and passes
> unit tests but has not been validated against a live TLS-capable device.

```rust
use rustnetconf::{Client, TlsConfig, Datastore};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = TlsConfig {
        host: "10.0.0.1".into(),
        ca_cert: Some("ca.pem".into()),
        client_cert: Some("client.pem".into()),
        client_key: Some("client-key.pem".into()),
        ..Default::default()
    };

    let mut client = Client::connect_tls(config).connect().await?;
    let config = client.get_config(Datastore::Running).await?;
    println!("{config}");

    client.close_session().await?;
    Ok(())
}
```

### Event notifications (RFC 5277)

```rust
use rustnetconf::{Client, Datastore};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = Client::connect("10.0.0.1:830")
        .username("admin")
        .password("secret")
        .connect()
        .await?;

    // Subscribe to NETCONF event stream
    client.create_subscription(Some("NETCONF"), None, None, None).await?;

    // Block waiting for notifications
    while let Some(notif) = client.recv_notification().await? {
        println!("[{}] {}", notif.event_time, notif.event_xml);
    }

    Ok(())
}
```

> **Note:** Some devices (e.g., Junos vSRX 24.4) advertise `:interleave` but do not
> respond to RPCs on a session with an active subscription. On these devices, use a
> dedicated session for notifications and a separate session for RPCs. Notifications
> arriving during RPCs on interleave-capable devices are automatically buffered and
> available via `drain_notifications()`.

### Connection pooling

```rust
use rustnetconf::pool::{DevicePool, DeviceConfig};
use rustnetconf::transport::ssh::SshAuth;
use rustnetconf::Datastore;
use zeroize::Zeroizing;

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
- **SSH + TLS transports** — SSH (RFC 6242) by default, TLS (RFC 7589) via `tls` feature flag
- **SSH bastion support** — `ProxyJump` (multi-hop), `ProxyCommand` (shell-escaped), and OpenSSH `~/.ssh/config` alias resolution
- **NETCONF 1.0 + 1.1** — EOM and chunked framing with auto-negotiation
- **All core RPCs** — get, get-config, edit-config, copy-config, delete-config, lock/unlock, commit, confirmed-commit, cancel-commit, validate, close/kill-session, discard-changes
- **Subtree and XPath filters** — `SubtreeFilter` builds subtree filters; `XPathFilter` builds XPath ones (RFC 6241 §6.4) with namespace binding, gated on the device advertising `:xpath:1.0` so an unsupported filter fails loudly instead of silently returning the whole datastore
- **Confirmed commit** — auto-rollback safety net (RFC 6241 §8.4)
- **Event notifications** — `create-subscription`, inline notification demux, buffered drain/recv API (RFC 5277)
- **RPC timeout** — configurable per-session deadline prevents indefinite blocking on unresponsive devices
- **XML fragment validation** — user-provided RPC content is validated before insertion to prevent XML injection
- **CommitUnknown detection** — distinguishes "commit failed" from "maybe committed, connection lost"
- **Stale lock recovery** — `lock_or_kill_stale()` kills crashed sessions holding locks
- **Framing mismatch detection** — catches firmware bugs where devices send wrong framing
- **IPv6 support** — connect to devices using bracket notation (`[::1]:830`) or bare IPv6 addresses

### Vendor Profiles
- **Auto-detection** from device `<hello>` capabilities
- **Junos** — config wrapping, namespace normalization, discard-before-close
- **Generic** — standard RFC 6241 for any compliant device
- Extensible — implement `VendorProfile` trait for custom vendors

### Connection Pool
- Tokio semaphore-based concurrency limiting
- Checkout with timeout (no blocking forever)
- Auto-checkin on drop with health check — dead connections are discarded, not recycled
- Connection reuse from idle pool

### YANG Code Generation
- Build-time generation from `.yang` model files via libyang2
- Typed Rust structs with serde Serialize/Deserialize
- Full XML serialization — leaves, containers, and lists
- Correct type mapping (string, bool, uint32, etc.)
- Complete Rust keyword escaping for YANG node names
- Bundled IETF models: ietf-interfaces, ietf-ip, ietf-yang-types, ietf-inet-types

### Authentication
| Method | Transport | Builder API |
|--------|-----------|-------------|
| Password | SSH | `.password("secret")` |
| Key file | SSH | `.key_file("~/.ssh/id_ed25519")` |
| SSH agent | SSH | `.ssh_agent()` |
| Server-only TLS | TLS | `TlsConfig { ca_cert, .. }` |
| Mutual TLS (mTLS) | TLS | `TlsConfig { client_cert, client_key, .. }` |

### SSH Connection Options
| Option | Builder API | Notes |
|--------|-------------|-------|
| Direct TCP | (default) | No proxy |
| `ProxyJump` (bastion chain) | `.jump_hosts(Vec<JumpHostConfig>)` | Each hop has its own credentials and host-key policy |
| `ProxyCommand` | `.proxy_command("ssh -W %h:%p bastion")` | `%h`/`%p` shell-escaped and substituted; runs under `sh -c` |
| `~/.ssh/config` alias | `Client::connect_via_ssh_config("alias")?` | Resolves `HostName`, `Port`, `User`, `IdentityFile`, `ProxyJump`, `ProxyCommand`, `Include` |

`jump_hosts` and `proxy_command` are mutually exclusive at connect time.

### Error Handling

Layered errors matching the protocol stack:

```rust
match result {
    Err(NetconfError::Transport(e)) => { /* SSH/TLS connection issues */ }
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
| `copy-config` | §7.3 | Done |
| `delete-config` | §7.4 | Done (startup / url) |
| `lock` / `unlock` | §7.5-7.6 | Done |
| `close-session` | §7.8 | Done |
| `kill-session` | §7.9 | Done |
| `commit` | §8.4 | Done |
| `confirmed-commit` | §8.4 | Done |
| `cancel-commit` | §8.4.4.1 | Done |
| `validate` | §8.6 | Done |
| `discard-changes` | §8.3 | Done |

## Testing

504 tests across the workspace, the count CI runs
(`cargo test --workspace --all-features`) — 489 in unit and integration
harnesses plus 15 doc-tests:
- **Unit tests** — framing, RPC serialization, capability parsing, vendor profiles, diff engine, inventory parsing, IPv6 address parsing, XML fragment validation, capability normalization
- **Mock transport tests** — session state machine, CommitUnknown detection, lock recovery
- **Integration tests** — 32 tests against a live Juniper vSRX including full edit-config round trips, vendor auto-detection, connection pooling, and concurrent sessions

### Prerequisites

The `rustnetconf-yang` subcrate builds `libyang2` from source via `yang2`'s `bundled` feature, which requires `cmake`. Install it before running workspace-wide tests or clippy:

```bash
# Debian/Ubuntu
sudo apt-get install cmake

# macOS
brew install cmake

# Fedora/RHEL
sudo dnf install cmake
```

The core `rustnetconf` and `rustnetconf-cli` crates do not require `cmake`; `cargo test -p rustnetconf` works without it.

`bundled` is a default-on feature of `rustnetconf-yang`, not a hard requirement.
If you already have libyang2 installed system-wide, opt out and link it instead —
this skips the source build entirely (~44 MB of build artifacts) and drops the
`cmake` prerequisite:

```bash
cargo build -p rustnetconf-yang --no-default-features   # links system libyang
```

**This path needs a libyang providing `libyang.so.3`** — SONAME 3, not
SONAME 2. The two are binary-incompatible.

The reason matters: `libyang2-sys` probes for `libyang` with no version
constraint and falls back to a bare `-lyang`, while the bindings it ships are
generated against SONAME 3. An ABI-2 library would therefore link without
complaint and then feed our `build.rs` wrong struct offsets while it walks
libyang's C types — silent undefined behaviour during code generation rather
than a build failure.

**We do not verify this for you, and the build says so.** Checking it properly
means knowing which file `-lyang` actually resolves to, which depends on `-L`
ordering, symlink targets, platform library naming, and — because a build
script is a host binary — on host rather than target settings when
cross-compiling. libyang exposes no runtime soversion accessor through these
bindings to settle it. A check that guessed and reported "OK" would be worse
than none, so `build.rs` emits a warning stating the ABI was not verified and
leaves the responsibility with you.

Check the **soname**, not the package version:

```bash
ls $(pkg-config --variable=libdir libyang)/libyang.so.*   # want libyang.so.3
```

`pkg-config --modversion libyang` is *not* the right check. libyang carries a
project version and a soversion that deliberately disagree — the release
vendored here is `LIBYANG_VERSION 2.2.8` with `LIBYANG_MAJOR_SOVERSION 3`, and
`libyang.pc` publishes the former. Gating on the package version rejects
exactly the library you want.

Without any system libyang on the linker path, the build fails with
`unable to find library -lyang`. That and the explicit ABI error are both
expected outcomes — install a libyang providing SONAME 3, or keep the default.

Note that `yang2` is a **build-dependency**: it runs `build.rs` code generation
and is not linked into anything that depends on `rustnetconf-yang`, so it never
appears in a consumer's runtime dependency graph.

```bash
cargo test --workspace                    # Run all tests (requires cmake)
cargo test --test integration_vsrx        # Run vSRX integration tests only
SKIP_INTEGRATION=1 cargo test             # Skip tests requiring a device
```

## Security

### Known Issues

- **Debug logs may contain file paths** — When SSH key file loading fails, the key file path is included in `tracing::debug!` output. This is not exposed at info/warn/error levels. **Mitigation:** Disable debug-level logging in production, or filter `rustnetconf::transport` logs.

### Security Features

- **Credential zeroization** — Passwords and key passphrases use `Zeroizing<String>` (via the `zeroize` crate) and are securely erased from memory on drop.
- **SSH host key verification** — `HostKeyVerification` must be set explicitly. The `ClientBuilder` default is `RejectAll` (fail closed): the SSH handshake fails until the caller pins a fingerprint via `Fingerprint("SHA256:...")` or explicitly opts in to `AcceptAll` for lab use (logs a `tracing::warn!`). `ProxyJump` hops parsed from `~/.ssh/config` likewise default to `RejectAll` and must be individually configured. In the CLI, set `host_key_fingerprint` per device in `inventory.toml`, or pass `--insecure-accept-host-key` for lab use only.
- **Shell-escaped ProxyCommand** — `%h` and `%p` substitutions are shell-escaped to prevent command injection via malicious hostnames.
- **XML fragment validation** — All user-provided RPC content is validated for well-formedness before insertion, preventing XML injection.
- **XML attribute escaping** — All message-id values are escaped to prevent XML attribute injection.
- **TLS bypass warnings** — `danger_accept_invalid_certs` emits a detailed warning explaining that ALL certificate validation is bypassed (trust chain, signatures, hostname, and expiry).
- **Read buffer limits** — Session read buffers default to 100 MB (configurable via `.max_read_buffer()`) to prevent memory exhaustion.
- **RPC timeout** — Configurable via `.rpc_timeout()` to prevent indefinite blocking on unresponsive devices.
- **CLI input validation** — Device names are validated to prevent path traversal; state files are written with `0600` permissions on Unix.
- **Typed error hierarchy** — Structured error types (`ChannelClosed`, `SessionExpired`, `MessageIdMismatch`) enable precise error handling without string matching.
- **No unsafe code, enforced across every target** — declared as `unsafe_code = "forbid"` in `[workspace.lints.rust]`, which each package opts into. This is deliberate rather than a crate-root `#![forbid(unsafe_code)]`: build scripts, examples and integration tests compile as separate crates, so an inner attribute would not reach them. Verified by injecting an `unsafe` block into `build.rs`, a test target and an example, each of which now fails to compile. The one place that previously needed `unsafe` was two tests setting `HOME` via `std::env::set_var`, which the 2024 edition makes unsafe; the tilde expansion they covered was split into a pure function taking the home directory as an argument.

### Known advisories

None currently suppressed — `.cargo/audit.toml` has an empty `ignore` list,
and `cargo audit` plus `cargo deny` run on every CI build.

**RUSTSEC-2023-0071** (Marvin Attack, `rsa` timing side-channel) was carried
here until russh 0.62. It is now *absent from the graph*, not tolerated within
it: russh gates `rsa` behind a non-default feature and this crate builds with
`default-features = false`, so both of these come up empty:

```bash
grep '^name = "rsa"' Cargo.lock
cargo tree --workspace --all-features -i rsa
```

The suppression was removed rather than left in place, so that a future
dependency bump reintroducing `rsa` fails the audit loudly instead of passing
under an ignore nobody re-reads.

### Security Best Practices

- Use Ed25519 SSH keys (not RSA) for device authentication — smaller, faster,
  constant-time by construction, and not exposed to the RSA timing
  side-channel class of bug in the first place
- Set `host_key_verification(HostKeyVerification::Fingerprint(...))` or `HostKeyVerification::KnownHosts(path)` in production — the default is `RejectAll` (fail closed), so the connection will refuse to complete until you choose a policy. For the CLI, set either `host_key_fingerprint = "SHA256:..."` or `known_hosts_path = "/path/to/known_hosts"` per device in `inventory.toml` (or `known_hosts_path` under `[defaults]` for fleet-wide pinning). See `examples/known_hosts.rs` for the `ssh-keyscan` workflow.
- Set `.rpc_timeout(Duration::from_secs(30))` to prevent hanging on unresponsive devices
- Prefer SSH agent auth over inline passwords
- Store credentials in inventory.toml with restricted file permissions (`chmod 600`)
- Run the CLI on trusted management networks with direct device connectivity
- Use `confirmed-commit` (the default for `netconf apply`) so the device auto-reverts if something goes wrong
- Disable debug-level logging in production environments

To report a security vulnerability, please open an issue on GitHub.

## Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `async-trait` | 0.1 | Async trait support |
| `aws-lc-rs` | 1 | SHA-256 fingerprints and HMAC for `known_hosts` |
| `base64ct` | 1 | Constant-time base64 for key blobs |
| `quick-xml` | 0.41 | XML parsing (NETCONF RPC encode/decode) |
| `russh` | 0.62 | SSH transport (pure Rust, no libssh2) |
| `thiserror` | 2 | Error derive macros |
| `tokio` | 1 | Async runtime |
| `tracing` | 0.1 | Structured logging/tracing |
| `zeroize` | 1 | Secure credential erasure on drop |

Optional (behind `tls` feature):

| Crate | Version | Purpose |
|-------|---------|---------|
| `rustls` | 0.23 | TLS transport (pure Rust, no OpenSSL) |
| `tokio-rustls` | 0.26 | Async TLS stream adapter |
| `webpki-roots` | 0.26 | Mozilla CA root certificates |

Dev-only:

| Crate | Version | Purpose |
|-------|---------|---------|
| `tokio-test` | 0.4 | Async test utilities |
| `tracing-subscriber` | 0.3 | Log subscriber for tests |
| `tempfile` | 3 | Temporary directories for tests |

## License

MIT

## Contributing

Contributions welcome! See [ARCHITECTURE.md](ARCHITECTURE.md) for the codebase design and [TODOS.md](TODOS.md) for tracked work items.

---

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/mechub-mark.svg">
    <img src="docs/assets/mechub-mark-light.svg" width="28" alt="">
  </picture><br>
  <sub><code>a mechub project</code> · deterministic decides · the model explains · a human approves<br>
  <a href="https://github.com/fastrevmd-lab">github.com/fastrevmd-lab</a></sub>
</p>
