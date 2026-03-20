//! `netconf validate <device>` — validate desired config against device (dry-run).

use std::path::Path;
use rustnetconf::{Datastore, DefaultOperation};
use crate::connect::connect_device;
use crate::desired::read_desired_configs;
use crate::inventory::Inventory;

pub async fn run(project_dir: &Path, device_name: &str) -> Result<(), String> {
    let inventory = Inventory::load(&project_dir.join("inventory.toml"))?;
    let device = inventory.device(device_name)?;
    let desired_configs = read_desired_configs(project_dir, device_name)?;

    eprintln!("Connecting to {} ({})...", device.name, device.host);
    let mut client = connect_device(&device).await?;

    // Lock candidate for validation
    client.lock(Datastore::Candidate).await
        .map_err(|e| format!("lock failed: {e}"))?;

    // Apply each config to candidate (not committing)
    for config in &desired_configs {
        eprintln!("Loading {}...", config.name);
        client.edit_config(Datastore::Candidate)
            .config(&config.xml)
            .default_operation(DefaultOperation::Merge)
            .send()
            .await
            .map_err(|e| format!("edit-config failed for {}: {e}", config.name))?;
    }

    // Validate
    eprintln!("Validating...");
    client.validate(Datastore::Candidate).await
        .map_err(|e| format!("validation failed: {e}"))?;

    // Discard — don't commit
    client.discard_changes().await
        .map_err(|e| format!("discard failed: {e}"))?;

    client.unlock(Datastore::Candidate).await
        .map_err(|e| format!("unlock failed: {e}"))?;

    eprintln!("Validation passed. Configuration is valid.");
    client.close_session().await.ok();
    Ok(())
}
