//! Shared device connection helper.

use crate::inventory::ResolvedDevice;
use rustnetconf::transport::ssh::HostKeyVerification;
use rustnetconf::Client;

/// Connect to a device using resolved inventory details.
///
/// `accept_insecure_host_key` is true when the user passed
/// `--insecure-accept-host-key` on the CLI. In that case the SSH host key
/// is accepted without verification. Otherwise the policy is:
///
/// 1. If the inventory entry has `host_key_fingerprint`, pin it.
/// 2. Else, fall back to the library default (`RejectAll`), which fails
///    closed — the user must add a fingerprint to the inventory or pass
///    `--insecure-accept-host-key` to proceed.
pub async fn connect_device(
    device: &ResolvedDevice,
    accept_insecure_host_key: bool,
) -> Result<Client, String> {
    let mut builder = Client::connect(&device.host).username(&device.username);

    if let Some(ref key) = device.key_file {
        builder = builder.key_file(key);
    } else if let Some(ref pass) = device.password {
        builder = builder.password(pass.expose());
    } else {
        return Err(format!(
            "device '{}': no authentication method (key_file or password)",
            device.name
        ));
    }

    let host_key_policy = if accept_insecure_host_key {
        eprintln!(
            "WARNING: --insecure-accept-host-key set — accepting SSH host key for '{}' without verification",
            device.name
        );
        HostKeyVerification::AcceptAll
    } else if let Some(ref fingerprint) = device.host_key_fingerprint {
        HostKeyVerification::Fingerprint(fingerprint.clone())
    } else {
        return Err(format!(
            "device '{}': no host_key_fingerprint in inventory and \
             --insecure-accept-host-key not set. Pin the device's host key in \
             inventory.toml (host_key_fingerprint = \"SHA256:...\") or rerun \
             with --insecure-accept-host-key for lab use.",
            device.name
        ));
    };
    builder = builder.host_key_verification(host_key_policy);

    builder.connect().await.map_err(|e| {
        format!(
            "failed to connect to '{}' ({}): {e}",
            device.name, device.host
        )
    })
}
