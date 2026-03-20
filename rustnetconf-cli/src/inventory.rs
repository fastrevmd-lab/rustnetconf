//! Parse inventory.toml — maps device names to connection details.

use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

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
}

#[derive(Debug, Deserialize)]
pub struct DeviceEntry {
    pub host: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub key_file: Option<String>,
    pub vendor: Option<String>,
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
        let entry = self.devices.get(name)
            .ok_or_else(|| format!("device '{name}' not found in inventory"))?;

        let username = entry.username.clone()
            .or_else(|| self.defaults.username.clone())
            .ok_or_else(|| format!("device '{name}': no username specified"))?;

        let key_file = entry.key_file.as_ref().map(|p| resolve_home(p));

        Ok(ResolvedDevice {
            name: name.to_string(),
            host: entry.host.clone(),
            username,
            password: entry.password.clone(),
            key_file,
            vendor: entry.vendor.clone().or_else(|| self.defaults.vendor.clone()),
            confirm_timeout: self.defaults.confirm_timeout.unwrap_or(60),
        })
    }
}

/// A device with all defaults resolved.
#[derive(Debug)]
pub struct ResolvedDevice {
    pub name: String,
    pub host: String,
    pub username: String,
    pub password: Option<String>,
    pub key_file: Option<String>,
    pub vendor: Option<String>,
    pub confirm_timeout: u32,
}

/// Resolve ~ to home directory in a path.
fn resolve_home(path: &str) -> String {
    if path.starts_with("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{home}/{}", &path[2..]);
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
}
