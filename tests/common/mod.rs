//! Shared helpers for live-device integration tests.
//!
//! These tests are **opt-in**: they only run when the
//! `RUSTNETCONF_TEST_VSRX_HOST` environment variable is set. Without it,
//! each test calls [`skip_unless_vsrx_configured`] which returns `None`
//! and the test early-returns as a no-op.
//!
//! ## A no-op run reports as `ok`, not as skipped
//!
//! libtest has no "skipped" outcome for a test that returns normally, so a
//! suite that never contacted a device is indistinguishable from one that
//! did — both print `test result: ok`. That makes a green line worthless as
//! evidence for anything that depends on the device having been reached.
//!
//! Set `RUSTNETCONF_TEST_VSRX_REQUIRED=1` whenever the run is meant to be
//! device coverage. Every skip then panics instead of returning `None`, so a
//! misspelled variable, an env that did not survive into the cargo process,
//! or an unreadable key file fails the run rather than passing it.
//!
//! ## Configuration
//!
//! | Env var | Required | Default | Notes |
//! |---|---|---|---|
//! | `RUSTNETCONF_TEST_VSRX_HOST` | yes | — | e.g. `192.168.1.227:22` |
//!
//! **Port 22, not 830.** This fleet serves NETCONF as an SSH *subsystem* on 22.
//! Port 830 is open and authenticates, then returns nothing on stdout — which
//! reads as a device or transport fault rather than a wrong port, and is what
//! made an earlier attempt at this suite look credential-blocked. Check with:
//!
//! ```sh
//! ssh -i <key> -o IdentitiesOnly=yes -p 22 -s netconf@<host> netconf
//! ```
//!
//! A working target answers with `<nc:hello ...>` on stdout.
//! | `RUSTNETCONF_TEST_VSRX_USER` | no | `netconf` | Junos username |
//! | `RUSTNETCONF_TEST_VSRX_KEY` | no | `$HOME/.ssh/id_ed25519` | SSH private key path |
//! | `RUSTNETCONF_TEST_VSRX_REQUIRED` | no | unset | `1`/`true`/`yes` — turn every skip into a failure |
//!
//! ## Examples
//!
//! ```sh
//! # Run all integration tests against VM114 (CI-tester-vSRX):
//! RUSTNETCONF_TEST_VSRX_HOST=192.168.1.227:22 cargo test --test integration_vsrx
//!
//! # Use a different SSH key and user:
//! RUSTNETCONF_TEST_VSRX_HOST=10.0.0.1:22 \
//!     RUSTNETCONF_TEST_VSRX_USER=netconf \
//!     RUSTNETCONF_TEST_VSRX_KEY=~/.ssh/netconf_ed25519 \
//!     cargo test --test integration_vendor_pool
//! ```

#![allow(dead_code)] // each integration_*.rs file uses a different subset

/// Resolved coordinates for a live vSRX test target.
pub struct VsrxTarget {
    pub host: String,
    pub username: String,
    pub key_path: String,
}

impl VsrxTarget {
    /// `host:port` string suitable for [`rustnetconf::Client::connect`].
    pub fn endpoint(&self) -> &str {
        &self.host
    }
}

/// True when `RUSTNETCONF_TEST_VSRX_REQUIRED` asks for device coverage.
///
/// The point of the flag is that a skipped live test is reported as a pass.
/// When it is set, every reason to skip becomes a panic instead, so a run
/// that never reached the device fails rather than printing `ok`.
fn device_required() -> bool {
    match std::env::var("RUSTNETCONF_TEST_VSRX_REQUIRED") {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => false,
    }
}

/// Skip, or fail loudly if the run was asked to be device coverage.
fn skip_or_fail(reason: &str) -> Option<VsrxTarget> {
    assert!(
        !device_required(),
        "RUSTNETCONF_TEST_VSRX_REQUIRED is set, but this test cannot reach a \
         device: {reason}. The suite is refusing to report a pass it did not earn."
    );
    None
}

/// Expand a leading `~/` against `$HOME`.
///
/// Rust does no tilde expansion, and neither does every shell in the position
/// `VAR=~/path cmd`. Without this, `RUSTNETCONF_TEST_VSRX_KEY=~/.ssh/k` hands
/// russh a literal `~/.ssh/k`, which fails as an authentication error — the
/// same misleading shape as the `srxoutpost` username bug documented above.
fn expand_tilde(path: &str) -> String {
    let Some(rest) = path.strip_prefix("~/") else {
        return path.to_string();
    };
    match std::env::var("HOME") {
        Ok(home) => format!("{}/{rest}", home.trim_end_matches('/')),
        Err(_) => path.to_string(),
    }
}

/// Returns `Some(VsrxTarget)` when `RUSTNETCONF_TEST_VSRX_HOST` is set and the
/// configured key file is readable, otherwise `None`.
///
/// Tests should early-return on `None` so the suite is a no-op for
/// contributors without a lab device. Under
/// `RUSTNETCONF_TEST_VSRX_REQUIRED=1` there is no `None` — each of those
/// cases panics with the specific reason instead.
pub fn vsrx_target() -> Option<VsrxTarget> {
    let Ok(host) = std::env::var("RUSTNETCONF_TEST_VSRX_HOST") else {
        return skip_or_fail("RUSTNETCONF_TEST_VSRX_HOST is unset");
    };
    if host.trim().is_empty() {
        return skip_or_fail("RUSTNETCONF_TEST_VSRX_HOST is set but empty");
    }
    let username =
        std::env::var("RUSTNETCONF_TEST_VSRX_USER").unwrap_or_else(|_| "netconf".to_string());
    let key_path = expand_tilde(
        &std::env::var("RUSTNETCONF_TEST_VSRX_KEY").unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/home/mharman".to_string());
            format!("{home}/.ssh/id_ed25519")
        }),
    );

    // Checked here rather than at connect time: an unusable key surfaces from
    // russh as `authentication failed`, which reads as a device or account
    // fault. Naming the file is the difference between a five-minute fix and
    // an afternoon on the wrong device.
    //
    // Opened rather than stat'd. `Path::is_file` answers a question about the
    // directory entry, not about access — a key at mode 000 is `is_file() ==
    // true` and unreadable, which is precisely the case this check exists for.
    if let Err(e) = std::fs::File::open(&key_path) {
        return skip_or_fail(&format!("SSH key {key_path} cannot be opened: {e}"));
    }

    Some(VsrxTarget {
        host,
        username,
        key_path,
    })
}

/// Convenience for tests that just need to bail when no device is configured.
///
/// Use at the top of a test:
/// ```ignore
/// let target = match common::skip_unless_vsrx_configured() {
///     Some(t) => t,
///     None => return,
/// };
/// ```
///
/// Returns `None` only when the run is not required to be device coverage —
/// see [`vsrx_target`].
pub fn skip_unless_vsrx_configured() -> Option<VsrxTarget> {
    vsrx_target()
}

/// Split a `host:port` endpoint into its parts. Useful when a test needs to
/// poke a *different* port on the same host (e.g. testing connection-refused
/// against a closed port on the live device).
pub fn split_host_port(endpoint: &str) -> (&str, u16) {
    if let Some((host, port_str)) = endpoint.rsplit_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            return (host, port);
        }
    }
    (endpoint, 830)
}
