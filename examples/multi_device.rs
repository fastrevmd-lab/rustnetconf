//! Fetch config from multiple devices concurrently.
//!
//! Demonstrates rustnetconf's async parallelism — the primary differentiator
//! over Python's ncclient. Connects to N devices simultaneously using tokio.
//!
//! Usage:
//!   cargo run --example multi_device -- --key ~/.ssh/id_ed25519 --user admin \
//!     192.168.1.1 192.168.1.2 192.168.1.3

use rustnetconf::{Client, Datastore};
use std::env;
use std::process;
use std::time::Instant;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!(
            "Usage: {} --key <path> --user <username> [--password <pass>] <host1> <host2> ...",
            args[0]
        );
        process::exit(1);
    }

    let mut key_file: Option<String> = None;
    let mut password: Option<String> = None;
    let mut username: Option<String> = None;
    let mut hosts: Vec<String> = Vec::new();

    let mut idx = 1;
    while idx < args.len() {
        match args[idx].as_str() {
            "--key" => {
                idx += 1;
                key_file = Some(args.get(idx).expect("--key requires a value").clone());
            }
            "--password" => {
                idx += 1;
                password = Some(args.get(idx).expect("--password requires a value").clone());
            }
            "--user" => {
                idx += 1;
                username = Some(args.get(idx).expect("--user requires a value").clone());
            }
            host => {
                hosts.push(host.to_string());
            }
        }
        idx += 1;
    }

    let username = username.unwrap_or_else(|| {
        eprintln!("Error: --user is required");
        process::exit(1);
    });

    if hosts.is_empty() {
        eprintln!("Error: specify at least one host");
        process::exit(1);
    }

    eprintln!("Fetching config from {} devices concurrently...", hosts.len());
    let start = Instant::now();

    // Spawn concurrent tasks for each device
    let mut handles = Vec::new();

    for host in hosts {
        let username = username.clone();
        let key_file = key_file.clone();
        let password = password.clone();

        let handle = tokio::spawn(async move {
            let mut builder = Client::connect(&host).username(&username);

            if let Some(ref key) = key_file {
                builder = builder.key_file(key);
            } else if let Some(ref pass) = password {
                builder = builder.password(pass);
            }

            let device_start = Instant::now();
            let mut client = match builder.connect().await {
                Ok(c) => c,
                Err(e) => return (host, Err(format!("connect failed: {e}"))),
            };

            let result = match client.get_config(Datastore::Running).await {
                Ok(config) => {
                    let elapsed = device_start.elapsed();
                    Ok(format!("{} bytes in {:.1}s", config.len(), elapsed.as_secs_f64()))
                }
                Err(e) => Err(format!("get-config failed: {e}")),
            };

            client.close_session().await.ok();
            (host, result)
        });

        handles.push(handle);
    }

    // Collect results
    let mut success_count = 0;
    let mut fail_count = 0;

    for handle in handles {
        match handle.await {
            Ok((host, Ok(summary))) => {
                println!("[OK]   {host}: {summary}");
                success_count += 1;
            }
            Ok((host, Err(err))) => {
                println!("[FAIL] {host}: {err}");
                fail_count += 1;
            }
            Err(e) => {
                println!("[FAIL] task panicked: {e}");
                fail_count += 1;
            }
        }
    }

    let total_elapsed = start.elapsed();
    eprintln!(
        "\nDone: {success_count} succeeded, {fail_count} failed in {:.1}s total",
        total_elapsed.as_secs_f64()
    );

    if fail_count > 0 {
        process::exit(1);
    }
}
