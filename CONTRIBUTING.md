# Contributing to rustnetconf

Thanks for considering a contribution. rustnetconf is an async-first NETCONF 1.0/1.1 client library for Rust — part of the [mechub](https://github.com/mechubsec) family of open-source, self-hosted network automation tooling. See [README.md](README.md) for what the library does and [ARCHITECTURE.md](ARCHITECTURE.md) for how it's put together.

## Before you start

- Check open issues and PRs first — someone may already be working on it.
- For anything larger than a small fix, open an issue to discuss the approach before writing code. It saves everyone a rewrite.
- This project follows one hard rule across the whole mechub fleet: **deterministic code decides, a model may explain, a human approves.** Nothing you contribute should let an LLM or other model output directly drive a device action (a `commit`, a `set`, a config push). Models may draft, summarize, or explain; deterministic code decides.

## Workspace layout

This is a Cargo workspace with three members:

- `.` (`rustnetconf`) — the core NETCONF client library
- `rustnetconf-yang` — YANG code generation (the generated types are committed; regeneration is a maintainer-only path requiring `cmake`/`libyang2`)
- `rustnetconf-cli` — a Terraform-like CLI for declarative config management

## Build and test

Minimal build (no YANG codegen, no `cmake` needed):

```sh
cargo build --workspace
cargo test --workspace
```

Full build, matching what CI runs (`--all-features` pulls in `rustnetconf-yang`'s `regenerate` feature, which needs `cmake`):

```sh
sudo apt-get install -y cmake   # or your platform's equivalent
cargo build --workspace --all-features --verbose
cargo test --workspace --all-features --verbose
```

Lint and format, both required to pass in CI:

```sh
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

Dependency and license checks, both required to pass in CI (`.github/workflows/security.yml`):

```sh
cargo audit
cargo deny check bans sources licenses
```

### Integration tests

`integration_vsrx` and `integration_vendor_pool` (under `tests/`) talk to a real Junos device and are gated behind `RUSTNETCONF_TEST_VSRX_HOST`. They're no-ops in hosted CI and not required for a normal contribution — skip them unless you have lab access. Never point them at a production device, and never commit real hostnames, credentials, or device output from a run against real hardware; use the existing fixtures.

### If you touch `rustnetconf-yang`'s models

`rustnetconf-yang/src/generated.rs` is committed, not built. If you change anything under `yang-models/`, regenerate it and let CI's `yang-codegen-drift` job catch drift:

```sh
cargo run -p rustnetconf-yang --features regenerate --bin codegen
git diff --exit-code -- rustnetconf-yang/src/generated.rs   # should be empty after a regenerate
```

## Commit and PR conventions

- Match the existing commit style: `type(scope): summary` (`fix(deps):`, `docs(#105):`, `chore(release):`, etc.) — see `git log` for examples.
- Keep PRs focused on one change. A bug fix doesn't need a drive-by refactor riding along.
- Fill out the PR template, including the exact commands you ran to verify the change.
- By opening a pull request, you're agreeing your contribution is licensed under this repository's [MIT license](LICENSE).

## Review process

Every pull request goes through a security review and a code review, then an independent test run, before anything merges. Only a maintainer merges — contributors, including anyone with write access, should not merge their own PR. CI (build, test, clippy, fmt, `cargo audit`, `cargo deny`, secret scanning) must be green first.

## Reporting a vulnerability

Please don't open a public issue for a security vulnerability — see [SECURITY.md](SECURITY.md) for how to report one privately.

## Fixtures and test data

Never commit real device configs, hostnames, serial numbers, or credentials — synthetic or sanitized fixtures only. If you find real data already committed anywhere in this repo, don't add to it — report it privately instead (see [SECURITY.md](SECURITY.md)).
