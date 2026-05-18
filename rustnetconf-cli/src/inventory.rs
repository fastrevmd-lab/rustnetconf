//! Parse inventory.toml — maps device names to connection details.
//!
//! ## Secrets
//!
//! `inventory.toml` may contain plaintext passwords. Treat the file as
//! sensitive: protect with restrictive filesystem permissions (`chmod 600`),
//! add it to `.gitignore`, and prefer key-file or SSH-agent authentication
//! over inline passwords where possible.

use serde::{Deserialize, Deserializer};
use std::collections::HashMap;
use std::fmt;
use std::path::Path;
use zeroize::Zeroizing;

/// A password or other secret that:
/// 1. Is zeroized on drop (backed by [`zeroize::Zeroizing`]).
/// 2. Redacts itself in `Debug` output to prevent accidental disclosure via
///    panic messages, `tracing`, or `dbg!`.
/// 3. Deserializes from a plain TOML string transparently.
#[derive(Clone)]
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    /// Wrap an existing string. Prefer `Deserialize` for the normal path —
    /// this constructor exists for tests and programmatic construction.
    #[allow(dead_code)]
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    /// Borrow the inner secret as `&str`. Callers should pass this directly
    /// into APIs that need it and avoid storing the result.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretString(***)")
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Ok(SecretString(Zeroizing::new(raw)))
    }
}

#[derive(Debug, Deserialize)]
pub struct Inventory {
    #[serde(default)]
    pub defaults: InventoryDefaults,
    #[serde(default)]
    pub devices: HashMap<String, DeviceEntry>,
}

#[derive(Debug, Default, Deserialize)]
pub struct InventoryDefaults {
    pub confirm_timeout: Option<u32>,
    pub username: Option<String>,
    pub vendor: Option<String>,
    /// Default known_hosts file path applied to every device that doesn't
    /// override it. Tilde (`~`) is expanded to `$HOME`.
    pub known_hosts_path: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DeviceEntry {
    pub host: String,
    pub username: Option<String>,
    /// Plaintext password from `inventory.toml`. Wrapped in
    /// [`SecretString`] so it is zeroized on drop and never shows up in
    /// `Debug` output. Prefer `key_file` where possible.
    pub password: Option<SecretString>,
    pub key_file: Option<String>,
    pub vendor: Option<String>,
    /// SHA-256 host key fingerprint to pin (with or without `SHA256:` prefix).
    ///
    /// Obtain with `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the
    /// device. When set, the SSH host key must match exactly or the
    /// connection is rejected.
    ///
    /// Mutually exclusive with `known_hosts_path` — setting both is a hard
    /// error to avoid ambiguity about which policy is in effect.
    pub host_key_fingerprint: Option<String>,
    /// Path to an OpenSSH-format `known_hosts` file. When set, the device's
    /// host key is verified against entries in this file on every connect.
    /// Tilde (`~`) is expanded to `$HOME`.
    ///
    /// Overrides `defaults.known_hosts_path` for this device only.
    /// Mutually exclusive with `host_key_fingerprint`.
    pub known_hosts_path: Option<String>,
}

impl Inventory {
    /// Load inventory from a TOML file.
    pub fn load(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
        let inventory: Inventory = toml::from_str(&content)
            .map_err(|e| format!("failed to parse {}: {e}", path.display()))?;

        if inventory.devices.is_empty() {
            return Err(format!("{} contains no devices", path.display()));
        }

        Ok(inventory)
    }

    /// Get a device entry by name, with defaults applied.
    pub fn device(&self, name: &str) -> Result<ResolvedDevice, String> {
        let entry = self
            .devices
            .get(name)
            .ok_or_else(|| format!("device '{name}' not found in inventory"))?;

        let username = entry
            .username
            .clone()
            .or_else(|| self.defaults.username.clone())
            .ok_or_else(|| format!("device '{name}': no username specified"))?;

        let key_file = entry.key_file.as_ref().map(|p| resolve_home(p));

        if entry.host_key_fingerprint.is_some() && entry.known_hosts_path.is_some() {
            return Err(format!(
                "device '{name}': host_key_fingerprint and known_hosts_path are mutually exclusive — choose one"
            ));
        }

        // Per-device explicit setting overrides defaults entirely:
        //   - if device sets known_hosts_path → that wins
        //   - else if device sets host_key_fingerprint → no known_hosts inherited
        //     (fingerprint is the policy for this device)
        //   - else → inherit defaults.known_hosts_path
        let known_hosts_path = if let Some(p) = entry.known_hosts_path.as_ref() {
            Some(resolve_home(p))
        } else if entry.host_key_fingerprint.is_some() {
            None
        } else {
            self.defaults
                .known_hosts_path
                .as_ref()
                .map(|p| resolve_home(p))
        };

        Ok(ResolvedDevice {
            name: name.to_string(),
            host: entry.host.clone(),
            username,
            password: entry.password.clone(),
            key_file,
            vendor: entry
                .vendor
                .clone()
                .or_else(|| self.defaults.vendor.clone()),
            confirm_timeout: self.defaults.confirm_timeout.unwrap_or(60),
            host_key_fingerprint: entry.host_key_fingerprint.clone(),
            known_hosts_path,
        })
    }
}

/// A device with all defaults resolved.
#[derive(Debug)]
pub struct ResolvedDevice {
    pub name: String,
    pub host: String,
    pub username: String,
    /// Password from inventory, redacted in `Debug` and zeroized on drop.
    pub password: Option<SecretString>,
    pub key_file: Option<String>,
    #[allow(dead_code)]
    pub vendor: Option<String>,
    pub confirm_timeout: u32,
    /// Optional SHA-256 host key fingerprint to pin for this device.
    pub host_key_fingerprint: Option<String>,
    /// Optional `known_hosts` file (already tilde-expanded). When set, host
    /// key is verified against this file at connect time.
    pub known_hosts_path: Option<String>,
}

/// Resolve ~ to home directory in a path.
fn resolve_home(path: &str) -> String {
    if path.starts_with("~/") {
        if let Ok(home) = std::env::var("HOME") {
            if let Some(rest) = path.strip_prefix("~/") {
                return format!("{home}/{rest}");
            }
        }
    }
    path.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_inventory() {
        let toml = r#"
[defaults]
confirm_timeout = 120

[devices.spine-01]
host = "10.0.0.1:830"
username = "admin"
key_file = "~/.ssh/id_ed25519"

[devices.spine-02]
host = "10.0.0.2:830"
username = "admin"
password = "secret"
"#;
        let inv: Inventory = toml::from_str(toml).unwrap();
        assert_eq!(inv.devices.len(), 2);
        assert_eq!(inv.defaults.confirm_timeout, Some(120));

        let dev = inv.device("spine-01").unwrap();
        assert_eq!(dev.host, "10.0.0.1:830");
        assert_eq!(dev.confirm_timeout, 120);

        // Password deserialized into a SecretString and is recoverable
        // via expose().
        let dev2 = inv.device("spine-02").unwrap();
        assert_eq!(
            dev2.password.as_ref().map(SecretString::expose),
            Some("secret")
        );
    }

    /// Plaintext password from inventory.toml must never appear in Debug
    /// output of `DeviceEntry`, `ResolvedDevice`, or `Inventory`. Regression
    /// guard for RNC-SEC-003.
    #[test]
    fn debug_output_does_not_leak_password() {
        let toml = r#"
[devices.router-01]
host = "10.0.0.1"
username = "admin"
password = "hunter2-do-not-leak"
"#;
        let inv: Inventory = toml::from_str(toml).unwrap();
        let inventory_debug = format!("{inv:?}");
        assert!(
            !inventory_debug.contains("hunter2-do-not-leak"),
            "password leaked through Inventory Debug: {inventory_debug}"
        );

        let dev = inv.device("router-01").unwrap();
        let device_debug = format!("{dev:?}");
        assert!(
            !device_debug.contains("hunter2-do-not-leak"),
            "password leaked through ResolvedDevice Debug: {device_debug}"
        );

        // Sanity: the redacted marker is present so we know Debug actually
        // visited the field.
        assert!(device_debug.contains("SecretString(***)"));
    }

    #[test]
    fn secret_string_debug_redacts_value() {
        let secret = SecretString::new("super-secret".to_string());
        let debug = format!("{secret:?}");
        assert_eq!(debug, "SecretString(***)");
        // Sanity: expose() still returns the plaintext for actual use.
        assert_eq!(secret.expose(), "super-secret");
    }

    #[test]
    fn test_device_not_found() {
        let toml = r#"
[devices.spine-01]
host = "10.0.0.1"
username = "admin"
"#;
        let inv: Inventory = toml::from_str(toml).unwrap();
        assert!(inv.device("nonexistent").is_err());
    }

    #[test]
    fn test_defaults_applied() {
        let toml = r#"
[defaults]
username = "default-user"
confirm_timeout = 90

[devices.router-01]
host = "10.0.0.1"
"#;
        let inv: Inventory = toml::from_str(toml).unwrap();
        let dev = inv.device("router-01").unwrap();
        assert_eq!(dev.username, "default-user");
        assert_eq!(dev.confirm_timeout, 90);
    }

    #[test]
    fn test_resolve_home() {
        let resolved = resolve_home("~/.ssh/id_ed25519");
        assert!(!resolved.starts_with("~"));
        assert!(resolved.contains(".ssh/id_ed25519"));
    }

    #[test]
    fn known_hosts_path_set_on_device_resolves_directly() {
        let toml = r#"
[devices.router-01]
host = "10.0.0.1"
username = "admin"
known_hosts_path = "/etc/jmcp/known_hosts"
"#;
        let inv: Inventory = toml::from_str(toml).unwrap();
        let dev = inv.device("router-01").unwrap();
        assert_eq!(
            dev.known_hosts_path.as_deref(),
            Some("/etc/jmcp/known_hosts")
        );
    }

    #[test]
    fn known_hosts_path_falls_back_to_defaults() {
        let toml = r#"
[defaults]
known_hosts_path = "/etc/jmcp/known_hosts"

[devices.router-01]
host = "10.0.0.1"
username = "admin"
"#;
        let inv: Inventory = toml::from_str(toml).unwrap();
        let dev = inv.device("router-01").unwrap();
        assert_eq!(
            dev.known_hosts_path.as_deref(),
            Some("/etc/jmcp/known_hosts")
        );
    }

    #[test]
    fn device_known_hosts_path_overrides_defaults() {
        let toml = r#"
[defaults]
known_hosts_path = "/etc/jmcp/known_hosts"

[devices.router-01]
host = "10.0.0.1"
username = "admin"
known_hosts_path = "/var/lib/jmcp/router-01_known_hosts"
"#;
        let inv: Inventory = toml::from_str(toml).unwrap();
        let dev = inv.device("router-01").unwrap();
        assert_eq!(
            dev.known_hosts_path.as_deref(),
            Some("/var/lib/jmcp/router-01_known_hosts")
        );
    }

    #[test]
    fn known_hosts_path_expands_tilde() {
        std::env::set_var("HOME", "/home/test-user");
        let toml = r#"
[devices.router-01]
host = "10.0.0.1"
username = "admin"
known_hosts_path = "~/.ssh/known_hosts"
"#;
        let inv: Inventory = toml::from_str(toml).unwrap();
        let dev = inv.device("router-01").unwrap();
        assert_eq!(
            dev.known_hosts_path.as_deref(),
            Some("/home/test-user/.ssh/known_hosts")
        );
    }

    /// Setting both `host_key_fingerprint` and `known_hosts_path` on the same
    /// device is ambiguous — fail loudly at inventory-resolution time rather
    /// than silently preferring one.
    #[test]
    fn fingerprint_and_known_hosts_path_conflict_errors() {
        let toml = r#"
[devices.router-01]
host = "10.0.0.1"
username = "admin"
host_key_fingerprint = "SHA256:aaa"
known_hosts_path = "/etc/jmcp/known_hosts"
"#;
        let inv: Inventory = toml::from_str(toml).unwrap();
        let err = inv.device("router-01").unwrap_err();
        assert!(
            err.contains("mutually exclusive"),
            "expected conflict error, got: {err}"
        );
        assert!(err.contains("router-01"), "error should name device: {err}");
    }

    /// A device-level `host_key_fingerprint` opts the device out of the
    /// defaults-level `known_hosts_path`. The two are NOT both set on the
    /// resolved device — the device's explicit choice wins cleanly so
    /// policy selection in `connect.rs` has no ambiguity to resolve.
    #[test]
    fn device_fingerprint_suppresses_defaults_known_hosts() {
        let toml = r#"
[defaults]
known_hosts_path = "/etc/jmcp/known_hosts"

[devices.router-01]
host = "10.0.0.1"
username = "admin"
host_key_fingerprint = "SHA256:aaa"
"#;
        let inv: Inventory = toml::from_str(toml).unwrap();
        let dev = inv.device("router-01").expect("should resolve");
        assert_eq!(dev.host_key_fingerprint.as_deref(), Some("SHA256:aaa"));
        assert!(
            dev.known_hosts_path.is_none(),
            "defaults known_hosts must not be inherited when device pins fingerprint"
        );
    }
}
