//! Shared device connection helper.

use crate::inventory::ResolvedDevice;
use rustnetconf::transport::ssh::HostKeyVerification;
use rustnetconf::Client;
use std::path::PathBuf;

/// Pure policy-selection helper — decides which `HostKeyVerification` to use
/// based on inventory state and the `--insecure-accept-host-key` flag.
///
/// Precedence (most to least secure):
/// 1. `--insecure-accept-host-key` → `AcceptAll` (with a logged warning,
///    handled by the caller).
/// 2. `device.known_hosts_path` set → `KnownHosts(path)`.
/// 3. `device.host_key_fingerprint` set → `Fingerprint(fp)`.
/// 4. Nothing pinned → `Err` (fail closed; user must pin or pass the
///    insecure flag).
///
/// The inventory resolver already errors when both `known_hosts_path` and
/// `host_key_fingerprint` are set on the same device entry, so this function
/// trusts that `device.known_hosts_path` and `device.host_key_fingerprint`
/// will not both be `Some`.
pub(crate) fn select_host_key_policy(
    device: &ResolvedDevice,
    accept_insecure_host_key: bool,
) -> Result<HostKeyVerification, String> {
    if accept_insecure_host_key {
        return Ok(HostKeyVerification::AcceptAll);
    }
    if let Some(ref path) = device.known_hosts_path {
        return Ok(HostKeyVerification::KnownHosts(PathBuf::from(path)));
    }
    if let Some(ref fingerprint) = device.host_key_fingerprint {
        return Ok(HostKeyVerification::Fingerprint(fingerprint.clone()));
    }
    Err(format!(
        "device '{}': no host_key_fingerprint or known_hosts_path in inventory \
         and --insecure-accept-host-key not set. Pin the device's host key in \
         inventory.toml (host_key_fingerprint = \"SHA256:...\" or \
         known_hosts_path = \"/path/to/known_hosts\") or rerun with \
         --insecure-accept-host-key for lab use.",
        device.name
    ))
}

/// Connect to a device using resolved inventory details.
///
/// `accept_insecure_host_key` is true when the user passed
/// `--insecure-accept-host-key` on the CLI. In that case the SSH host key
/// is accepted without verification. Otherwise [`select_host_key_policy`]
/// decides the policy from inventory state.
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

    if accept_insecure_host_key {
        eprintln!(
            "WARNING: --insecure-accept-host-key set — accepting SSH host key for '{}' without verification",
            device.name
        );
    }
    let host_key_policy = select_host_key_policy(device, accept_insecure_host_key)?;
    builder = builder.host_key_verification(host_key_policy);

    builder.connect().await.map_err(|e| {
        format!(
            "failed to connect to '{}' ({}): {e}",
            device.name, device.host
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::ResolvedDevice;

    fn dev() -> ResolvedDevice {
        ResolvedDevice {
            name: "router-01".to_string(),
            host: "10.0.0.1".to_string(),
            username: "admin".to_string(),
            password: None,
            key_file: Some("~/.ssh/id_ed25519".to_string()),
            vendor: None,
            confirm_timeout: 60,
            host_key_fingerprint: None,
            known_hosts_path: None,
        }
    }

    #[test]
    fn insecure_flag_yields_accept_all() {
        let policy = select_host_key_policy(&dev(), true).unwrap();
        assert!(matches!(policy, HostKeyVerification::AcceptAll));
    }

    #[test]
    fn known_hosts_path_yields_known_hosts_policy() {
        let mut d = dev();
        d.known_hosts_path = Some("/etc/jmcp/known_hosts".to_string());
        let policy = select_host_key_policy(&d, false).unwrap();
        match policy {
            HostKeyVerification::KnownHosts(path) => {
                assert_eq!(path, PathBuf::from("/etc/jmcp/known_hosts"));
            }
            other => panic!("expected KnownHosts, got {other:?}"),
        }
    }

    #[test]
    fn fingerprint_yields_fingerprint_policy() {
        let mut d = dev();
        d.host_key_fingerprint = Some("SHA256:aaa".to_string());
        let policy = select_host_key_policy(&d, false).unwrap();
        match policy {
            HostKeyVerification::Fingerprint(fp) => assert_eq!(fp, "SHA256:aaa"),
            other => panic!("expected Fingerprint, got {other:?}"),
        }
    }

    /// known_hosts_path wins over a (hypothetical) fingerprint — but the
    /// inventory resolver already prevents this combination, so this just
    /// documents precedence in case it slips past validation in some future
    /// refactor.
    #[test]
    fn known_hosts_path_wins_over_fingerprint() {
        let mut d = dev();
        d.known_hosts_path = Some("/etc/jmcp/known_hosts".to_string());
        d.host_key_fingerprint = Some("SHA256:aaa".to_string());
        let policy = select_host_key_policy(&d, false).unwrap();
        assert!(matches!(policy, HostKeyVerification::KnownHosts(_)));
    }

    #[test]
    fn insecure_wins_even_when_fingerprint_set() {
        let mut d = dev();
        d.host_key_fingerprint = Some("SHA256:aaa".to_string());
        let policy = select_host_key_policy(&d, true).unwrap();
        assert!(matches!(policy, HostKeyVerification::AcceptAll));
    }

    #[test]
    fn no_pin_and_no_insecure_errors_with_actionable_message() {
        let err = select_host_key_policy(&dev(), false).unwrap_err();
        assert!(err.contains("router-01"), "error names device: {err}");
        assert!(
            err.contains("host_key_fingerprint") || err.contains("known_hosts_path"),
            "error mentions options: {err}"
        );
        assert!(
            err.contains("--insecure-accept-host-key"),
            "error mentions escape hatch: {err}"
        );
    }
}
