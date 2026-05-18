//! Verify a device's SSH host key against an OpenSSH `known_hosts` file.
//!
//! This is the recommended host-key policy for managing a fleet of network
//! devices — you can ship a single `known_hosts` file (e.g. baked into a
//! container image or a config-management bundle) and the library will fail
//! closed on any host whose key is missing, mismatched, or `@revoked`.
//!
//! ## Workflow
//!
//! 1. Pre-populate a `known_hosts` file using `ssh-keyscan`:
//!
//!    ```sh
//!    # Default port 22
//!    ssh-keyscan -t ed25519,rsa,ecdsa router-01.example.com >> ./known_hosts
//!
//!    # Custom NETCONF port — ssh-keyscan emits the [host]:port form
//!    ssh-keyscan -t ed25519,rsa,ecdsa -p 830 router-01.example.com \
//!        >> ./known_hosts
//!    ```
//!
//!    Always inspect the file before trusting it — `ssh-keyscan` does NOT
//!    verify host identity itself (TOFU). Confirm the fingerprints out of
//!    band (e.g. via console, MOTD, or your provisioning system) before
//!    promoting the file to production.
//!
//! 2. Run this example:
//!
//!    ```sh
//!    cargo run --example known_hosts -- \
//!        router-01.example.com:830 admin ./known_hosts \
//!        --key ~/.ssh/id_ed25519
//!    ```
//!
//! ## Failure modes
//!
//! - `TransportError::HostKeyMismatch` — file has a different fingerprint
//!   for this host. Possible MITM or rotated host key. Investigate before
//!   updating the file.
//! - `TransportError::HostKeyNotInKnownHosts` — host has no entry. Run
//!   `ssh-keyscan` to add one, after verifying the key out of band.
//! - `TransportError::HostKeyRevoked` — the file has an `@revoked` marker
//!   for the key the server presented. Do not connect; the operator has
//!   explicitly blocklisted this key.

use rustnetconf::transport::ssh::HostKeyVerification;
use rustnetconf::{Client, Datastore};
use std::env;
use std::path::PathBuf;
use std::process;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 4 {
        eprintln!(
            "Usage: {} <host[:port]> <username> <known_hosts_path> [--password <pass>] [--key <path>]",
            args[0]
        );
        process::exit(1);
    }

    let host = &args[1];
    let username = &args[2];
    let known_hosts_path = PathBuf::from(&args[3]);

    let mut password: Option<String> = None;
    let mut key_file: Option<String> = None;
    let mut idx = 4;
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
            other => {
                eprintln!("Unknown option: {other}");
                process::exit(1);
            }
        }
        idx += 1;
    }

    let mut builder = Client::connect(host)
        .username(username)
        .host_key_verification(HostKeyVerification::KnownHosts(known_hosts_path.clone()));

    if let Some(ref key) = key_file {
        builder = builder.key_file(key);
    } else if let Some(ref pass) = password {
        builder = builder.password(pass);
    } else {
        eprintln!("Error: specify --password or --key for authentication");
        process::exit(1);
    }

    eprintln!(
        "Connecting to {host} (host key verified against {})",
        known_hosts_path.display()
    );

    let mut client = match builder.connect().await {
        Ok(c) => c,
        Err(e) => {
            // The structured TransportError variants (HostKeyMismatch,
            // HostKeyNotInKnownHosts, HostKeyRevoked) flow through here as
            // part of the rendered error chain.
            eprintln!("Connection failed: {e}");
            process::exit(1);
        }
    };

    eprintln!("Host key verified.");

    // Fetch a small piece of running config to prove the session works.
    match client.get_config(Datastore::Running).await {
        Ok(data) => {
            // Print only the first 500 chars to keep example output short.
            let preview: String = data.chars().take(500).collect();
            println!("{preview}");
            if data.len() > 500 {
                println!("... ({} more chars)", data.len() - 500);
            }
        }
        Err(e) => {
            eprintln!("get-config failed: {e}");
            client.close_session().await.ok();
            process::exit(1);
        }
    }

    client.close_session().await.ok();
}
