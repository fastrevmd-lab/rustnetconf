//! Local state management — saves running config snapshots for rollback.

use std::path::{Path, PathBuf};

/// Get the state directory path.
pub fn state_dir(project_dir: &Path) -> PathBuf {
    project_dir.join(".netconf").join("state")
}

/// Tighten directory permissions to `0o700` (owner-only) on Unix. No-op
/// elsewhere. Failures are propagated because a permissive state dir is
/// the whole concern this fix is intended to address.
#[cfg(unix)]
fn enforce_dir_mode_0o700(dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o700);
    std::fs::set_permissions(dir, perms)
        .map_err(|e| format!("failed to chmod state dir {}: {e}", dir.display()))
}

/// Save a device's running config to the local state.
///
/// Sensitive device configurations are written atomically:
///
/// 1. The `.netconf` and `.netconf/state` directories are forced to mode
///    `0o700` on Unix on every call so an existing world-readable
///    directory cannot leak future writes.
/// 2. The new contents are written to a sibling temp file created with
///    mode `0o600`, then atomically `rename(2)`d over the destination.
///    This guarantees the destination always lands at `0o600`, even when
///    a pre-existing file was looser, and avoids partial-write windows.
///
/// On non-Unix platforms there is no portable equivalent of `chmod`, so the
/// file is written with the platform's default permissions (typically
/// inherited from the parent directory's ACL). Since the snapshot may contain
/// sensitive device configuration, a warning is emitted so the operator can
/// restrict access manually. Unix is the supported and recommended platform.
pub fn save_state(project_dir: &Path, device_name: &str, config: &str) -> Result<(), String> {
    let netconf_dir = project_dir.join(".netconf");
    let dir = netconf_dir.join("state");
    std::fs::create_dir_all(&dir).map_err(|e| format!("failed to create state dir: {e}"))?;

    #[cfg(unix)]
    {
        enforce_dir_mode_0o700(&netconf_dir)?;
        enforce_dir_mode_0o700(&dir)?;
    }

    let path = dir.join(format!("{device_name}.xml"));

    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        // Atomic write: temp file with 0o600 in the same directory,
        // then rename over the destination. Same-filesystem rename(2)
        // is atomic and replaces any pre-existing file, dropping its
        // looser permissions.
        let tmp_path = dir.join(format!(".{device_name}.xml.tmp"));

        // If a stale temp file exists from a prior crash, remove it
        // first so we cannot inherit its permissions.
        let _ = std::fs::remove_file(&tmp_path);

        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)
            .map_err(|e| format!("failed to open temp state file {}: {e}", tmp_path.display()))?;
        file.write_all(config.as_bytes())
            .map_err(|e| format!("failed to write state to {}: {e}", tmp_path.display()))?;
        file.sync_all().ok();
        drop(file);

        std::fs::rename(&tmp_path, &path).map_err(|e| {
            // Best-effort cleanup if the rename failed.
            let _ = std::fs::remove_file(&tmp_path);
            format!(
                "failed to rename {} -> {}: {e}",
                tmp_path.display(),
                path.display()
            )
        })?;
    }

    #[cfg(not(unix))]
    {
        // No portable chmod here — warn so the operator knows the snapshot may
        // contain sensitive config and is not guaranteed to be owner-only.
        eprintln!(
            "WARNING: writing state file {} with default platform permissions — \
             restrict access manually; this snapshot may contain sensitive config",
            path.display()
        );
        std::fs::write(&path, config)
            .map_err(|e| format!("failed to save state to {}: {e}", path.display()))?;
    }

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

    std::fs::read_to_string(&path).map_err(|e| format!("failed to read {}: {e}", path.display()))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// Regression guard for RNC-SEC-004: a pre-existing state file with
    /// loose mode (0o644) must be rewritten with mode 0o600.
    #[test]
    fn save_state_replaces_loose_existing_file_with_0600() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path();
        let dir = state_dir(project);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("dev.xml");

        // Plant a pre-existing world-readable file.
        std::fs::write(&path, "OLD").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(mode_of(&path), 0o644);

        save_state(project, "dev", "NEW").unwrap();

        assert_eq!(mode_of(&path), 0o600, "file should be tightened to 0o600");
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, "NEW", "file content should be replaced");
    }

    /// `.netconf` and `.netconf/state` must end up at 0o700 even if they
    /// pre-existed with loose permissions.
    #[test]
    fn save_state_tightens_state_dir_perms() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path();
        let netconf = project.join(".netconf");
        let state = netconf.join("state");
        std::fs::create_dir_all(&state).unwrap();

        // Plant loose perms on both dirs.
        std::fs::set_permissions(&netconf, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o755)).unwrap();

        save_state(project, "dev", "data").unwrap();

        assert_eq!(mode_of(&netconf), 0o700, ".netconf should be 0o700");
        assert_eq!(mode_of(&state), 0o700, ".netconf/state should be 0o700");
    }

    /// Fresh saves with no pre-existing file should still land at 0o600.
    #[test]
    fn save_state_first_write_is_0600() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path();
        save_state(project, "fresh", "data").unwrap();
        let path = state_dir(project).join("fresh.xml");
        assert_eq!(mode_of(&path), 0o600);
    }

    /// A leftover temp file from a prior crash must not block the next save.
    #[test]
    fn save_state_recovers_from_stale_temp_file() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path();
        let dir = state_dir(project);
        std::fs::create_dir_all(&dir).unwrap();
        let stale = dir.join(".dev.xml.tmp");
        std::fs::write(&stale, "stale").unwrap();

        save_state(project, "dev", "fresh").unwrap();

        let final_path = dir.join("dev.xml");
        assert_eq!(mode_of(&final_path), 0o600);
        assert_eq!(std::fs::read_to_string(&final_path).unwrap(), "fresh");
        assert!(!stale.exists(), "stale temp file should be gone");
    }
}
