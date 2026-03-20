//! Local state management — saves running config snapshots for rollback.

use std::path::{Path, PathBuf};

/// Get the state directory path.
pub fn state_dir(project_dir: &Path) -> PathBuf {
    project_dir.join(".netconf").join("state")
}

/// Save a device's running config to the local state.
pub fn save_state(project_dir: &Path, device_name: &str, config: &str) -> Result<(), String> {
    let dir = state_dir(project_dir);
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("failed to create state dir: {e}"))?;

    let path = dir.join(format!("{device_name}.xml"));
    std::fs::write(&path, config)
        .map_err(|e| format!("failed to save state to {}: {e}", path.display()))?;

    Ok(())
}

/// Load a device's saved running config from local state.
pub fn load_state(project_dir: &Path, device_name: &str) -> Result<String, String> {
    let path = state_dir(project_dir).join(format!("{device_name}.xml"));

    if !path.exists() {
        return Err(format!(
            "no saved state for '{device_name}' — run 'netconf apply' first to save device state"
        ));
    }

    std::fs::read_to_string(&path)
        .map_err(|e| format!("failed to read {}: {e}", path.display()))
}
