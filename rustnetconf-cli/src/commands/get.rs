//! `netconf get <device>` — fetch and display running config.

use std::path::Path;
use rustnetconf::Datastore;
use crate::connect::connect_device;
use crate::inventory::Inventory;

pub async fn run(project_dir: &Path, device_name: &str) -> Result<(), String> {
    let inventory = Inventory::load(&project_dir.join("inventory.toml"))?;
    let device = inventory.device(device_name)?;

    eprintln!("Connecting to {} ({})...", device.name, device.host);
    let mut client = connect_device(&device).await?;

    let config = client.get_config(Datastore::Running).await
        .map_err(|e| format!("get-config failed: {e}"))?;

    println!("{config}");

    client.close_session().await.ok();
    Ok(())
}
