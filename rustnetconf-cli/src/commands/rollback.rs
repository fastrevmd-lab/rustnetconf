//! `netconf rollback <device>` — revert to saved state.

use crate::connect::connect_device;
use crate::inventory::Inventory;
use crate::state;
use rustnetconf::{Client, Datastore, DefaultOperation};
use std::path::Path;

/// Run the edit/validate/commit sequence inside the candidate lock.
///
/// Extracted so the caller can attach a cleanup guard: any error returned
/// here triggers `release_candidate_lock_best_effort` before the session
/// is closed.
async fn rollback_locked_region(client: &mut Client, saved_config: &str) -> Result<(), String> {
    client
        .edit_config(Datastore::Candidate)
        .config(saved_config)
        .default_operation(DefaultOperation::Replace)
        .send()
        .await
        .map_err(|e| format!("rollback edit-config failed: {e}"))?;

    client
        .validate(Datastore::Candidate)
        .await
        .map_err(|e| format!("rollback validation failed: {e}"))?;

    client
        .commit()
        .await
        .map_err(|e| format!("rollback commit failed: {e}"))?;

    Ok(())
}

pub async fn run(
    project_dir: &Path,
    device_name: &str,
    accept_insecure_host_key: bool,
) -> Result<(), String> {
    let inventory = Inventory::load(&project_dir.join("inventory.toml"))?;
    let device = inventory.device(device_name)?;

    // Load saved state
    let saved_config = state::load_state(project_dir, device_name)?;

    eprintln!("Connecting to {} ({})...", device.name, device.host);
    let mut client = connect_device(&device, accept_insecure_host_key).await?;

    eprintln!("Rolling back to saved configuration...");

    client
        .lock(Datastore::Candidate)
        .await
        .map_err(|e| format!("lock failed: {e}"))?;

    let result = rollback_locked_region(&mut client, &saved_config).await;

    if let Err(e) = result {
        eprintln!("Error during rollback, releasing candidate lock...");
        client.release_candidate_lock_best_effort().await;
        client.close_session().await.ok();
        return Err(e);
    }

    client
        .unlock(Datastore::Candidate)
        .await
        .map_err(|e| format!("unlock failed: {e}"))?;

    eprintln!("Rollback complete. Device restored to saved state.");
    client.close_session().await.ok();
    Ok(())
}
