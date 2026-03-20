//! `netconf rollback <device>` — revert to saved state.

use std::path::Path;
use rustnetconf::{Datastore, DefaultOperation};
use crate::connect::connect_device;
use crate::inventory::Inventory;
use crate::state;

pub async fn run(project_dir: &Path, device_name: &str) -> Result<(), String> {
    let inventory = Inventory::load(&project_dir.join("inventory.toml"))?;
    let device = inventory.device(device_name)?;

    // Load saved state
    let saved_config = state::load_state(project_dir, device_name)?;

    eprintln!("Connecting to {} ({})...", device.name, device.host);
    let mut client = connect_device(&device).await?;

    eprintln!("Rolling back to saved configuration...");

    client.lock(Datastore::Candidate).await
        .map_err(|e| format!("lock failed: {e}"))?;

    // Push the saved config as a full replace
    client.edit_config(Datastore::Candidate)
        .config(&saved_config)
        .default_operation(DefaultOperation::Replace)
        .send()
        .await
        .map_err(|e| format!("rollback edit-config failed: {e}"))?;

    client.validate(Datastore::Candidate).await
        .map_err(|e| format!("rollback validation failed: {e}"))?;

    client.commit().await
        .map_err(|e| format!("rollback commit failed: {e}"))?;

    client.unlock(Datastore::Candidate).await
        .map_err(|e| format!("unlock failed: {e}"))?;

    eprintln!("Rollback complete. Device restored to saved state.");
    client.close_session().await.ok();
    Ok(())
}
