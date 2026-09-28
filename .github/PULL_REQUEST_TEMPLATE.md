## Summary

<!-- What does this PR do, and why? -->

## Changes

<!-- Bullet list of what changed -->

## Verification

<!-- Exact commands you ran and their result. "Should work" is not verification. -->

```sh

```

## Checklist

- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings` passes
- [ ] Tests added or updated for this change, and they fail against the old code
- [ ] `cargo audit` and `cargo deny check bans sources licenses` are clean, or any new advisory/license exception is called out below
- [ ] No secrets, credentials, real hostnames, serials, or real device configs in code, tests, fixtures, or this description
- [ ] No new telemetry, analytics, or outbound network call added
- [ ] If this touches a path that can act on a device: deterministic code decides, not a model output

## Anything you're unsure about

<!-- Flag it here rather than hoping review catches it -->
