//! `netconf init` — create a project skeleton.

use std::path::Path;

pub fn run(project_dir: &Path) -> Result<(), String> {
    // Create directories
    let dirs = ["desired", ".netconf/state"];
    for dir in &dirs {
        let path = project_dir.join(dir);
        std::fs::create_dir_all(&path)
            .map_err(|e| format!("failed to create {}: {e}", path.display()))?;
    }

    // Create inventory.toml if it doesn't exist
    let inventory_path = project_dir.join("inventory.toml");
    if !inventory_path.exists() {
        let template = r#"# rustnetconf inventory
# Define your network devices here.

[defaults]
confirm_timeout = 60
# username = "admin"

# [devices.spine-01]
# host = "10.0.0.1:830"
# username = "admin"
# key_file = "~/.ssh/id_ed25519"
# vendor = "junos"  # optional, auto-detected

# [devices.spine-02]
# host = "10.0.0.2:830"
# username = "admin"
# password = "secret"
"#;
        std::fs::write(&inventory_path, template)
            .map_err(|e| format!("failed to write inventory.toml: {e}"))?;
        eprintln!("Created inventory.toml");
    } else {
        eprintln!("inventory.toml already exists, skipping");
    }

    // Create .gitignore for state dir
    let gitignore_path = project_dir.join(".netconf").join(".gitignore");
    if !gitignore_path.exists() {
        std::fs::write(&gitignore_path, "state/\n")
            .map_err(|e| format!("failed to write .gitignore: {e}"))?;
    }

    eprintln!("Project initialized. Next steps:");
    eprintln!("  1. Edit inventory.toml with your device details");
    eprintln!("  2. Create desired/<device-name>/ directories");
    eprintln!("  3. Add XML config files to desired/<device-name>/");
    eprintln!("  4. Run: netconf plan <device-name>");

    Ok(())
}
