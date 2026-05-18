//! Shared helpers for live-device integration tests.
//!
//! These tests are **opt-in**: they only run when the
//! `RUSTNETCONF_TEST_VSRX_HOST` environment variable is set. Without it,
//! each test calls [`skip_unless_vsrx_configured`] which returns `None`
//! and the test early-returns as a no-op.
//!
//! ## Configuration
//!
//! | Env var | Required | Default | Notes |
//! |---|---|---|---|
//! | `RUSTNETCONF_TEST_VSRX_HOST` | yes | — | e.g. `192.168.1.227:830` |
//! | `RUSTNETCONF_TEST_VSRX_USER` | no | `srxoutpost` | Junos username |
//! | `RUSTNETCONF_TEST_VSRX_KEY` | no | `$HOME/.ssh/id_ed25519` | SSH private key path |
//!
//! ## Examples
//!
//! ```sh
//! # Run all integration tests against VM114 (CI-tester-vSRX):
//! RUSTNETCONF_TEST_VSRX_HOST=192.168.1.227:830 cargo test --test integration_vsrx
//!
//! # Use a different SSH key and user:
//! RUSTNETCONF_TEST_VSRX_HOST=10.0.0.1:830 \
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

/// Returns `Some(VsrxTarget)` when `RUSTNETCONF_TEST_VSRX_HOST` is set,
/// otherwise `None`. Tests should early-return on `None` so the suite is a
/// no-op for contributors without a lab device.
pub fn vsrx_target() -> Option<VsrxTarget> {
    let host = std::env::var("RUSTNETCONF_TEST_VSRX_HOST").ok()?;
    let username =
        std::env::var("RUSTNETCONF_TEST_VSRX_USER").unwrap_or_else(|_| "srxoutpost".to_string());
    let key_path = std::env::var("RUSTNETCONF_TEST_VSRX_KEY").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/home/mharman".to_string());
        format!("{home}/.ssh/id_ed25519")
    });
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
