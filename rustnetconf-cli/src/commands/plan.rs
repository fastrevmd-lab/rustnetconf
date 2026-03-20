//! `netconf plan <device>` — show what would change.

use std::path::Path;
use rustnetconf::Datastore;
use crate::connect::connect_device;
use crate::desired::read_desired_configs;
use crate::diff::{diff_xml, format_colored, format::summary};
use crate::inventory::Inventory;

pub async fn run(
    project_dir: &Path,
    device_name: &str,
    json_output: bool,
) -> Result<bool, String> {
    let inventory = Inventory::load(&project_dir.join("inventory.toml"))?;
    let device = inventory.device(device_name)?;
    let desired_configs = read_desired_configs(project_dir, device_name)?;

    eprintln!("Connecting to {} ({})...", device.name, device.host);
    let mut client = connect_device(&device).await?;
    eprintln!("Connected (vendor: {})", client.vendor_name());

    let mut has_changes = false;
    let mut all_entries = Vec::new();

    for config in &desired_configs {
        // Fetch the matching section from the device using subtree filter
        let running = client
            .get_config_filtered(Datastore::Running, &config.filter)
            .await
            .map_err(|e| format!("get-config failed for {}: {e}", config.name))?;

        // Strip <configuration> wrapper from desired to match the vendor-unwrapped
        // running config. The vendor profile strips this from get-config responses,
        // so the desired XML needs the same treatment for an accurate diff.
        let desired_inner = strip_configuration_wrapper(&config.xml);
        let entries = diff_xml(&desired_inner, &running)?;

        if !entries.is_empty() {
            has_changes = true;
        }

        if json_output {
            all_entries.extend(entries);
        } else {
            print!("{}", format_colored(&entries, &config.name));
        }
    }

    if json_output {
        println!("{}", crate::diff::format_json(&all_entries));
    }

    eprintln!("\n{}", summary(&all_entries.clone()));

    client.close_session().await.map_err(|e| format!("close failed: {e}"))?;

    Ok(has_changes)
}

/// Strip outer `<configuration ...>...</configuration>` wrapper from XML.
/// Matches the vendor profile's unwrap_config behavior.
pub fn strip_configuration_wrapper(xml: &str) -> String {
    let trimmed = xml.trim();
    if let Some(start) = trimmed.find("<configuration") {
        if let Some(tag_end) = trimmed[start..].find('>') {
            let inner_start = start + tag_end + 1;
            if let Some(close) = trimmed.rfind("</configuration>") {
                if inner_start < close {
                    return trimmed[inner_start..close].trim().to_string();
                }
            }
        }
    }
    trimmed.to_string()
}
