//! `netconf confirm <device>` — confirm a pending confirmed-commit.

use std::path::Path;
use crate::connect::connect_device;
use crate::inventory::Inventory;

pub async fn run(project_dir: &Path, device_name: &str) -> Result<(), String> {
    let inventory = Inventory::load(&project_dir.join("inventory.toml"))?;
    let device = inventory.device(device_name)?;

    eprintln!("Connecting to {} ({})...", device.name, device.host);
    let mut client = connect_device(&device).await?;

    eprintln!("Sending confirming commit...");
    client.confirming_commit().await
        .map_err(|e| format!("confirming commit failed: {e}"))?;

    eprintln!("Configuration confirmed and permanent.");
    client.close_session().await.ok();
    Ok(())
}
