//! `netconf apply <device>` — apply desired config with confirmed-commit.

use crate::connect::connect_device;
use crate::desired::read_desired_configs;
use crate::desired::DesiredConfig;
use crate::diff::{diff_xml, format_colored};
use crate::inventory::Inventory;
use crate::state;
use rustnetconf::{Client, Datastore, DefaultOperation};
use std::path::Path;

/// Run the edit/validate/commit sequence inside the candidate lock.
///
/// Extracted so the caller can attach a cleanup guard: any error returned
/// here triggers `release_candidate_lock_best_effort` before the session
/// is closed, preventing a stale lock from blocking subsequent runs.
async fn apply_locked_region(
    client: &mut Client,
    configs_to_apply: &[&DesiredConfig],
    confirm_timeout: u32,
) -> Result<(), String> {
    for config in configs_to_apply {
        eprintln!("Applying {}...", config.name);
        client
            .edit_config(Datastore::Candidate)
            .config(&config.xml)
            .default_operation(DefaultOperation::Merge)
            .send()
            .await
            .map_err(|e| format!("edit-config failed for {}: {e}", config.name))?;
    }

    eprintln!("Validating...");
    client
        .validate(Datastore::Candidate)
        .await
        .map_err(|e| format!("validation failed: {e}"))?;

    eprintln!("Committing (confirmed, {}s timeout)...", confirm_timeout);
    client
        .confirmed_commit(confirm_timeout)
        .await
        .map_err(|e| format!("confirmed-commit failed: {e}"))?;

    Ok(())
}

pub async fn run(
    project_dir: &Path,
    device_name: &str,
    auto_confirm: bool,
    accept_insecure_host_key: bool,
) -> Result<(), String> {
    let inventory = Inventory::load(&project_dir.join("inventory.toml"))?;
    let device = inventory.device(device_name)?;
    let desired_configs = read_desired_configs(project_dir, device_name)?;
    let confirm_timeout = device.confirm_timeout;

    eprintln!("Connecting to {} ({})...", device.name, device.host);
    let mut client = connect_device(&device, accept_insecure_host_key).await?;
    eprintln!("Connected (vendor: {})", client.vendor_name());

    // Show plan first
    let mut has_changes = false;
    let mut configs_to_apply = Vec::new();

    for config in &desired_configs {
        let running = client
            .get_config_filtered(Datastore::Running, &config.filter)
            .await
            .map_err(|e| format!("get-config failed for {}: {e}", config.name))?;

        let desired_inner = client.unwrap_config(&config.xml);
        let entries = diff_xml(&desired_inner, &running)?;
        print!("{}", format_colored(&entries, &config.name));

        if !entries.is_empty() {
            has_changes = true;
            configs_to_apply.push(config);
        }
    }

    if !has_changes {
        eprintln!("\nNo changes to apply.");
        client.close_session().await.ok();
        return Ok(());
    }

    eprintln!();

    // Prompt for confirmation
    if !auto_confirm {
        let confirm = dialoguer::Confirm::new()
            .with_prompt("Apply these changes?")
            .default(false)
            .interact()
            .map_err(|e| format!("prompt error: {e}"))?;

        if !confirm {
            eprintln!("Aborted.");
            client.close_session().await.ok();
            return Ok(());
        }
    }

    // Save current running config for rollback
    eprintln!("Saving current config for rollback...");
    let full_running = client
        .get_config(Datastore::Running)
        .await
        .map_err(|e| format!("get-config failed: {e}"))?;
    state::save_state(project_dir, device_name, &full_running)?;

    // Lock candidate
    eprintln!("Locking candidate datastore...");
    client
        .lock(Datastore::Candidate)
        .await
        .map_err(|e| format!("lock failed: {e}"))?;

    // Run the edit/validate/commit region with a cleanup guard so any
    // mid-transaction error releases the lock and discards pending changes.
    let result = apply_locked_region(&mut client, &configs_to_apply, confirm_timeout).await;

    if let Err(e) = result {
        eprintln!("Error during apply, releasing candidate lock...");
        client.release_candidate_lock_best_effort().await;
        client.close_session().await.ok();
        return Err(e);
    }

    // Unlock on success path
    client
        .unlock(Datastore::Candidate)
        .await
        .map_err(|e| format!("unlock failed: {e}"))?;

    eprintln!(
        "\nChanges applied. Run 'netconf confirm {}' within {}s to make permanent.",
        device_name, confirm_timeout
    );
    eprintln!("If you don't confirm, the device will auto-revert.");

    client.close_session().await.ok();
    Ok(())
}
