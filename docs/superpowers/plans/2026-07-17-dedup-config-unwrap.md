# Deduplicate Config Unwrapping Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the CLI's hand-copied `strip_configuration_wrapper` with the connected device's real vendor `unwrap_config`, exposed through a new `Client::unwrap_config()` method.

**Architecture:** Add a thin delegating `Session::unwrap_config` → `Client::unwrap_config` (mirroring the existing `vendor_name` delegation chain), then point both CLI call sites at it. The library already applies `vendor_profile.unwrap_config()` to get-config responses (`src/session.rs:609`); this exposes the same operation so the CLI can normalize the *desired* config symmetrically for every vendor.

**Tech Stack:** Rust, tokio, `MockTransport` test harness. No new dependencies.

## Global Constraints

- Do NOT touch the `rustnetconf-yang` crate (needs `cmake`, not installed). Build/test only `rustnetconf` and `rustnetconf-cli`.
- Additive public API only — do not change existing signatures.
- Do NOT expose `wrap_config` (YAGNI).
- No changes to diff formatting, command surface, or output.
- Verify commands (run for every task that touches Rust):
  - `cargo test -p rustnetconf -p rustnetconf-cli --features rustnetconf/tls`
  - `cargo clippy -p rustnetconf -p rustnetconf-cli --features rustnetconf/tls -- -D warnings`
- Branch: `refactor/dedup-config-unwrap` (already checked out).
- Commit trailer on every commit:
  ```
  Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
  ```

---

### Task 1: Add `Session::unwrap_config` and `Client::unwrap_config`

**Files:**
- Modify: `src/session.rs` (insert after `vendor_name`, currently ends at line 244)
- Modify: `src/client.rs` (insert after `vendor_name`, currently ends at line 496)
- Test: `src/client.rs` (existing `#[cfg(test)] mod tests` at the bottom, which already uses `MockTransport` and `Client::from_session_for_test`)

**Interfaces:**
- Consumes: existing `Session.vendor_profile: Arc<dyn VendorProfile>` and its `unwrap_config(&self, &str) -> String`; existing test helpers `crate::transport::mock::MockTransport` and `Client::from_session_for_test(session)`.
- Produces: `Client::unwrap_config(&self, xml: &str) -> String` and `Session::unwrap_config(&self, xml: &str) -> String`. The CLI (Task 2) relies on `Client::unwrap_config`.

- [ ] **Step 1: Write the failing test**

Add to the `#[cfg(test)] mod tests` block at the bottom of `src/client.rs`. Uses the same `MockTransport` + `from_session_for_test` pattern as the existing tests there (see the tests around `src/client.rs:1213`). The generic-passthrough assertion is the behavior the old CLI logic got wrong — assert it first.

```rust
    #[test]
    fn test_unwrap_config_generic_passes_through() {
        use crate::transport::mock::MockTransport;
        // Generic vendor is the default when no hello/detection has run.
        let transport = MockTransport::new(Vec::new());
        let session = Session::new(Box::new(transport));
        let client = Client::from_session_for_test(session);

        let input = "<configuration><foo>bar</foo></configuration>";
        // Generic unwrap_config is a passthrough: input is returned unchanged.
        assert_eq!(client.unwrap_config(input), input);
    }

    #[test]
    fn test_unwrap_config_junos_strips_configuration_wrapper() {
        use crate::transport::mock::MockTransport;
        let transport = MockTransport::new(Vec::new());
        let mut session = Session::new(Box::new(transport));
        session.set_vendor_profile(Box::new(crate::vendor::junos::JunosVendor::default()));
        let client = Client::from_session_for_test(session);

        let input = "<configuration junos:commit-seconds=\"1\"><foo>bar</foo></configuration>";
        assert_eq!(client.unwrap_config(input), "<foo>bar</foo>");
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p rustnetconf --features tls unwrap_config 2>&1 | tail -20`
Expected: FAIL — compile error `no method named `unwrap_config` found for ... Client`.

- [ ] **Step 3: Implement `Session::unwrap_config`**

In `src/session.rs`, immediately after the `vendor_name` method (after line 244, before the `/// Get the device facts.` doc comment):

```rust

    /// Normalize a config fragment the way this session's vendor profile does
    /// (e.g. Junos strips the outer `<configuration>` wrapper; generic passes
    /// through). This is the same operation applied to get-config responses,
    /// exposed so callers can normalize a *desired* config symmetrically.
    pub fn unwrap_config(&self, xml: &str) -> String {
        self.vendor_profile.unwrap_config(xml)
    }
```

- [ ] **Step 4: Implement `Client::unwrap_config`**

In `src/client.rs`, immediately after the `vendor_name` method (after line 496, before the `/// Get the device's capabilities.` doc comment):

```rust

    /// Normalize a config fragment using the connected device's vendor profile.
    ///
    /// Junos strips the outer `<configuration>` wrapper; generic vendors pass
    /// the input through unchanged. Useful for diffing a desired config against
    /// a (already vendor-unwrapped) running config.
    pub fn unwrap_config(&self, xml: &str) -> String {
        self.session.unwrap_config(xml)
    }
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p rustnetconf --features tls unwrap_config 2>&1 | tail -20`
Expected: PASS — both `test_unwrap_config_generic_passes_through` and `test_unwrap_config_junos_strips_configuration_wrapper` pass.

- [ ] **Step 6: Full verify**

Run: `cargo test -p rustnetconf -p rustnetconf-cli --features rustnetconf/tls 2>&1 | grep -E "test result|error\[|FAILED"`
Expected: all `test result: ok`, no FAILED.
Run: `cargo clippy -p rustnetconf -p rustnetconf-cli --features rustnetconf/tls -- -D warnings 2>&1 | grep -E "warning|error"; echo done`
Expected: only `done` (no warnings/errors).

- [ ] **Step 7: Commit**

```bash
git add src/session.rs src/client.rs
git commit -m "feat(client): add unwrap_config delegating to vendor profile

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: Point CLI at `Client::unwrap_config`, delete the duplicate

**Files:**
- Modify: `rustnetconf-cli/src/commands/plan.rs` (remove `strip_configuration_wrapper` at lines 64-79; update the call at line 37)
- Modify: `rustnetconf-cli/src/commands/apply.rs` (update the call at line 73)

**Interfaces:**
- Consumes: `Client::unwrap_config(&self, xml: &str) -> String` from Task 1. In both files `client` is already connected before the call, so its vendor profile is set.
- Produces: nothing new; removes the `pub fn strip_configuration_wrapper` and the `apply.rs → plan.rs` cross-module reference.

- [ ] **Step 1: Update the `plan.rs` call site**

In `rustnetconf-cli/src/commands/plan.rs`, line 37, replace:

```rust
        let desired_inner = strip_configuration_wrapper(&config.xml);
```

with:

```rust
        let desired_inner = client.unwrap_config(&config.xml);
```

- [ ] **Step 2: Delete the duplicated helper from `plan.rs`**

In `rustnetconf-cli/src/commands/plan.rs`, delete the entire function and its doc comment (currently lines 64-79):

```rust
/// Strip outer `<configuration ...>...</configuration>` wrapper from XML.
/// Matches the vendor profile's unwrap_config behavior.
pub fn strip_configuration_wrapper(xml: &str) -> String {
    let trimmed = xml.trim();
    if let Some(start) = trimmed.find("<configuration") {
        if let Some(tag_end) = trimmed[start..].find('>') {
            let inner_start = start + tag_end + 1;
            if let Some(close) = trimmed.rfind("</configuration>") {
                if inner_start < close {
                    return trimmed[inner_start..close].trim().to_string();
                }
            }
        }
    }
    trimmed.to_string()
}
```

(Also remove the now-trailing blank line if one remains at end of file.)

- [ ] **Step 3: Update the `apply.rs` call site**

In `rustnetconf-cli/src/commands/apply.rs`, line 73, replace:

```rust
        let desired_inner = crate::commands::plan::strip_configuration_wrapper(&config.xml);
```

with:

```rust
        let desired_inner = client.unwrap_config(&config.xml);
```

- [ ] **Step 4: Verify no references remain**

Run: `grep -rn "strip_configuration_wrapper" rustnetconf-cli/src; echo "exit: $?"`
Expected: no matches (grep prints nothing; `exit: 1`).

- [ ] **Step 5: Build and test**

Run: `cargo build -p rustnetconf-cli 2>&1 | tail -5`
Expected: `Finished` with no errors (in particular, no "unused import"/"unused function" warnings).
Run: `cargo test -p rustnetconf -p rustnetconf-cli --features rustnetconf/tls 2>&1 | grep -E "test result|error\[|FAILED"`
Expected: all `test result: ok`, no FAILED — the existing `plan`/`apply` diff tests confirm the Junos path is unchanged.
Run: `cargo clippy -p rustnetconf -p rustnetconf-cli --features rustnetconf/tls -- -D warnings 2>&1 | grep -E "warning|error"; echo done`
Expected: only `done`.

- [ ] **Step 6: Commit**

```bash
git add rustnetconf-cli/src/commands/plan.rs rustnetconf-cli/src/commands/apply.rs
git commit -m "refactor(cli): use Client::unwrap_config instead of duplicated strip

Routes desired-config normalization through the connected device's vendor
profile, fixing the asymmetric diff against generic (non-Junos) devices and
removing the apply->plan cross-module coupling.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage:**
- Library `Session::unwrap_config` + `Client::unwrap_config` → Task 1. ✓
- CLI deletes `strip_configuration_wrapper`, both call sites use `client.unwrap_config` → Task 2. ✓
- Removes `apply.rs → plan.rs` coupling → Task 2, Step 3. ✓
- Library test: junos strips / generic passes through, generic-first TDD → Task 1, Steps 1-2. ✓
- CLI: grep for stale refs + run diff tests → Task 2, Steps 4-5. ✓
- YAGNI (no `wrap_config`), additive API, no Junos behavior change → Global Constraints + Task boundaries. ✓

**Placeholder scan:** none — all steps carry exact code, paths, and commands.

**Type consistency:** `unwrap_config(&self, xml: &str) -> String` is identical across `Session`, `Client`, both test call sites, and both CLI call sites. Test helper `Client::from_session_for_test` and `MockTransport::new(Vec::new())` match existing usage in `src/client.rs`. `JunosVendor::default()` and `Session::set_vendor_profile(Box::new(...))` match the API confirmed in the prior change.
