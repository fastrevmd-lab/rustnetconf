//! Full edit-config round trip: lock → edit → validate → commit → unlock.
//!
//! Usage:
//!   cargo run --example edit_config -- <host> <username> --key <path> --config <xml>
//!
//! Examples:
//!   cargo run --example edit_config -- 192.168.1.226 admin --key ~/.ssh/id_ed25519 \
//!     --config "<configuration><system><location><building>Lab-A</building></location></system></configuration>"

use rustnetconf::{Client, Datastore, DefaultOperation};
use std::env;
use std::process;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        eprintln!(
            "Usage: {} <host[:port]> <username> [--password <pass>] [--key <path>] --config <xml>",
            args[0]
        );
        process::exit(1);
    }

    let host = &args[1];
    let username = &args[2];

    let mut password: Option<String> = None;
    let mut key_file: Option<String> = None;
    let mut config_xml: Option<String> = None;

    let mut idx = 3;
    while idx < args.len() {
        match args[idx].as_str() {
            "--password" => {
                idx += 1;
                password = Some(args.get(idx).expect("--password requires a value").clone());
            }
            "--key" => {
                idx += 1;
                key_file = Some(args.get(idx).expect("--key requires a value").clone());
            }
            "--config" => {
                idx += 1;
                config_xml = Some(args.get(idx).expect("--config requires a value").clone());
            }
            other => {
                eprintln!("Unknown option: {other}");
                process::exit(1);
            }
        }
        idx += 1;
    }

    let config_xml = match config_xml {
        Some(c) => c,
        None => {
            eprintln!("Error: --config <xml> is required");
            process::exit(1);
        }
    };

    // Build connection
    let mut builder = Client::connect(host).username(username);

    if let Some(ref key) = key_file {
        builder = builder.key_file(key);
    } else if let Some(ref pass) = password {
        builder = builder.password(pass);
    } else {
        eprintln!("Error: specify --password or --key for authentication");
        process::exit(1);
    }

    let mut client = match builder.connect().await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Connection failed: {e}");
            process::exit(1);
        }
    };

    if let Some(caps) = client.capabilities() {
        eprintln!(
            "Connected (session-id: {})",
            caps.session_id().map(|id| id.to_string()).unwrap_or_else(|| "unknown".into()),
        );
    }

    // Check candidate support
    if !client.supports("urn:ietf:params:netconf:capability:candidate:1.0") {
        eprintln!("Error: device does not support :candidate datastore");
        client.close_session().await.ok();
        process::exit(1);
    }

    // Lock
    eprintln!("Locking candidate datastore...");
    if let Err(e) = client.lock(Datastore::Candidate).await {
        eprintln!("Lock failed: {e}");
        client.close_session().await.ok();
        process::exit(1);
    }

    // Edit
    eprintln!("Applying configuration...");
    if let Err(e) = client
        .edit_config(Datastore::Candidate)
        .config(&config_xml)
        .default_operation(DefaultOperation::Merge)
        .send()
        .await
    {
        eprintln!("Edit-config failed: {e}");
        eprintln!("Unlocking...");
        client.unlock(Datastore::Candidate).await.ok();
        client.close_session().await.ok();
        process::exit(1);
    }

    // Validate
    eprintln!("Validating...");
    if let Err(e) = client.validate(Datastore::Candidate).await {
        eprintln!("Validation failed: {e}");
        eprintln!("Unlocking (discarding changes)...");
        client.unlock(Datastore::Candidate).await.ok();
        client.close_session().await.ok();
        process::exit(1);
    }

    // Commit
    eprintln!("Committing...");
    if let Err(e) = client.commit().await {
        eprintln!("Commit failed: {e}");
        eprintln!("Unlocking (discarding changes)...");
        client.unlock(Datastore::Candidate).await.ok();
        client.close_session().await.ok();
        process::exit(1);
    }

    // Unlock
    eprintln!("Unlocking...");
    if let Err(e) = client.unlock(Datastore::Candidate).await {
        eprintln!("Unlock failed: {e}");
    }

    eprintln!("Done — configuration committed successfully.");
    client.close_session().await.ok();
}
