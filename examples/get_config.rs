//! Fetch running configuration from a NETCONF device.
//!
//! Usage:
//!   cargo run --example get_config -- <host> <username> [--password <pass>] [--key <path>] [--filter <xml>]
//!
//! Examples:
//!   cargo run --example get_config -- 192.168.1.226 admin --key ~/.ssh/id_ed25519
//!   cargo run --example get_config -- 10.0.0.1:830 admin --password secret
//!   cargo run --example get_config -- 10.0.0.1 admin --key ~/.ssh/id_ed25519 --filter "<configuration><system><host-name/></system></configuration>"

use rustnetconf::{Client, Datastore};
use std::env;
use std::process;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        eprintln!("Usage: {} <host[:port]> <username> [--password <pass>] [--key <path>] [--filter <xml>]", args[0]);
        process::exit(1);
    }

    let host = &args[1];
    let username = &args[2];

    let mut password: Option<String> = None;
    let mut key_file: Option<String> = None;
    let mut filter: Option<String> = None;

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
            "--filter" => {
                idx += 1;
                filter = Some(args.get(idx).expect("--filter requires a value").clone());
            }
            other => {
                eprintln!("Unknown option: {other}");
                process::exit(1);
            }
        }
        idx += 1;
    }

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

    // Print session info
    if let Some(caps) = client.capabilities() {
        eprintln!(
            "Connected (session-id: {}, capabilities: {})",
            caps.session_id().map(|id| id.to_string()).unwrap_or_else(|| "unknown".into()),
            caps.all_uris().len()
        );
    }

    // Fetch config
    let config = match filter {
        Some(ref f) => client.get_config_filtered(Datastore::Running, f).await,
        None => client.get_config(Datastore::Running).await,
    };

    match config {
        Ok(data) => println!("{data}"),
        Err(e) => {
            eprintln!("get-config failed: {e}");
            client.close_session().await.ok();
            process::exit(1);
        }
    }

    client.close_session().await.ok();
}
