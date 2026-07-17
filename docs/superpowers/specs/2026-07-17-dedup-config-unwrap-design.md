# Design: Deduplicate config unwrapping via the vendor profile

**Date:** 2026-07-17
**Branch:** `refactor/dedup-config-unwrap`
**Status:** Approved

## Problem

The CLI's `strip_configuration_wrapper` (`rustnetconf-cli/src/commands/plan.rs:66`) is a
hand-copied clone of the library's `JunosVendor::unwrap_config`
(`src/vendor/junos.rs:76`). Its own doc comment states it "Matches the vendor profile's
unwrap_config behavior." `apply.rs` reaches across command modules to reuse it
(`crate::commands::plan::strip_configuration_wrapper`).

Two problems follow:

1. **Drift.** The duplicated string-slicing logic will diverge from the real vendor
   implementation over time — a maintenance hazard with no compiler backstop.
2. **Latent correctness gap.** The CLI strips `<configuration>` from the *desired*
   config **unconditionally**. Against a generic (non-Junos) device — whose real
   `unwrap_config` is a passthrough — the running config is *not* unwrapped by the
   session, but the desired config *is* stripped by the CLI. The diff is asymmetric
   and can be wrong for non-Junos devices.

## Goal

The CLI must normalize the *desired* config the same way the session already
normalizes the *running* config it fetches — using the **connected device's actual
vendor profile**, not a hardcoded Junos-style strip.

Decision (approved): fix the correctness gap (vendor-aware), and expose the shared
logic as a focused `Client::unwrap_config()` method rather than leaking the trait
object.

## Design

### Library (`rustnetconf`)

- Add `Session::unwrap_config(&self, xml: &str) -> String` delegating to
  `self.vendor_profile.unwrap_config(xml)`. The session already calls this internally
  on get-config responses (`src/session.rs:609`); this exposes the same operation.
- Add `Client::unwrap_config(&self, xml: &str) -> String` delegating to the session.
  Public, `&self`, generally useful to any library consumer doing config diffs. This
  is the sole new public surface — the vendor trait object stays encapsulated.

### CLI (`rustnetconf-cli`)

- Delete `strip_configuration_wrapper` from `plan.rs` (both the function and its
  doc comment).
- In `plan.rs` and `apply.rs`, replace `strip_configuration_wrapper(&config.xml)`
  with `client.unwrap_config(&config.xml)`. Because `client` carries the
  detected/overridden vendor:
  - Junos device → strips `<configuration>` (unchanged behavior).
  - Generic device → passes through, making the diff symmetric with the
    (already vendor-unwrapped) running config.
- This also removes the `apply.rs → plan.rs` cross-command coupling.

## Data flow (after change)

```
desired.xml ──► client.unwrap_config() ─┐
                                         ├─► diff_xml() ──► entries
running (get-config, session already ────┘
        vendor-unwrapped via session.rs:609)
```

Both sides of the diff now pass through the *same* vendor `unwrap_config`, so they are
normalized consistently for every vendor.

## Testing

- **Library unit test (TDD, write first):** a `JunosVendor`-backed client unwraps
  `<configuration>…</configuration>` to its inner content; a `GenericVendor`-backed
  client leaves the XML untouched. Reuse the existing `MockTransport` hello harness /
  `Client::from_session_for_test`. Write the **generic-passthrough** assertion first —
  it is the behavior the old CLI logic got wrong — confirm it is red against the old
  path, then implement and confirm green.
- **CLI:** grep to confirm no remaining references to `strip_configuration_wrapper`;
  run the existing `plan`/`apply` diff tests to confirm the Junos path is unchanged.
- **Full suite + strict clippy** on `rustnetconf` and `rustnetconf-cli` with the `tls`
  feature, as in the prior change.

## Scope guard (YAGNI)

- Do **not** expose `wrap_config` — nothing needs it yet.
- No changes to diff formatting, command surface, or output.
- No behavior change for Junos devices (the common case).

## Risk

- Behavior changes only for **non-Junos** devices, which are currently unusual in this
  project's usage. The change makes those diffs *more* correct, not less.
- `Client::unwrap_config` is additive public API; no existing signatures change.
