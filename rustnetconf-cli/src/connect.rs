//! Shared device connection helper.

use rustnetconf::Client;
use crate::inventory::ResolvedDevice;

/// Connect to a device using resolved inventory details.
pub async fn connect_device(device: &ResolvedDevice) -> Result<Client, String> {
    let mut builder = Client::connect(&device.host).username(&device.username);

    if let Some(ref key) = device.key_file {
        builder = builder.key_file(key);
    } else if let Some(ref pass) = device.password {
        builder = builder.password(pass);
    } else {
        return Err(format!(
            "device '{}': no authentication method (key_file or password)",
            device.name
        ));
    }

    builder.connect().await.map_err(|e| format!(
        "failed to connect to '{}' ({}): {e}",
        device.name, device.host
    ))
}
