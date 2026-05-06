//! rustnetconf CLI — Terraform-like declarative network config management.
//!
//! ```text
//! netconf plan <device>       Show what would change
//! netconf apply <device>      Apply changes with confirmed-commit
//! netconf confirm <device>    Make changes permanent
//! netconf rollback <device>   Revert to saved state
//! netconf get <device>        Fetch running config
//! netconf validate <device>   Dry-run validation
//! netconf init                Create project skeleton
//! ```

mod commands;
mod connect;
mod desired;
mod diff;
mod inventory;
mod state;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process;

/// Validate that a device name contains only safe characters.
///
/// Allowed: alphanumeric characters, hyphens (`-`), underscores (`_`), and dots (`.`).
/// Rejects path traversal sequences and shell-special characters.
fn validate_device_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("device name must not be empty".to_string());
    }
    let valid = name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.');
    if !valid {
        return Err(format!(
            "invalid device name '{name}': only alphanumeric characters, hyphens, underscores, and dots are allowed"
        ));
    }
    Ok(())
}

#[derive(Parser)]
#[command(name = "netconf", version, about = "Declarative NETCONF config management")]
struct Cli {
    /// Project directory (defaults to current directory).
    #[arg(short = 'C', long, default_value = ".")]
    project_dir: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show what would change on a device.
    Plan {
        /// Device name from inventory.toml.
        device: String,
        /// Output as JSON instead of colored text.
        #[arg(long)]
        json: bool,
    },
    /// Apply desired config with confirmed-commit safety.
    Apply {
        /// Device name from inventory.toml.
        device: String,
        /// Skip the confirmation prompt.
        #[arg(short = 'y', long)]
        yes: bool,
    },
    /// Confirm a pending confirmed-commit (make permanent).
    Confirm {
        /// Device name from inventory.toml.
        device: String,
    },
    /// Revert to the saved pre-apply configuration.
    Rollback {
        /// Device name from inventory.toml.
        device: String,
    },
    /// Fetch and display the running configuration.
    Get {
        /// Device name from inventory.toml.
        device: String,
    },
    /// Validate desired config against device (dry-run, no changes).
    Validate {
        /// Device name from inventory.toml.
        device: String,
    },
    /// Create a new project skeleton.
    Init,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let project_dir = &cli.project_dir;

    let result = match cli.command {
        Commands::Plan { device, json } => match validate_device_name(&device) {
            Err(e) => Err(e),
            Ok(()) => commands::plan::run(project_dir, &device, json).await.map(|_| ()),
        },
        Commands::Apply { device, yes } => match validate_device_name(&device) {
            Err(e) => Err(e),
            Ok(()) => commands::apply::run(project_dir, &device, yes).await,
        },
        Commands::Confirm { device } => match validate_device_name(&device) {
            Err(e) => Err(e),
            Ok(()) => commands::confirm::run(project_dir, &device).await,
        },
        Commands::Rollback { device } => match validate_device_name(&device) {
            Err(e) => Err(e),
            Ok(()) => commands::rollback::run(project_dir, &device).await,
        },
        Commands::Get { device } => match validate_device_name(&device) {
            Err(e) => Err(e),
            Ok(()) => commands::get::run(project_dir, &device).await,
        },
        Commands::Validate { device } => match validate_device_name(&device) {
            Err(e) => Err(e),
            Ok(()) => commands::validate::run(project_dir, &device).await,
        },
        Commands::Init => {
            commands::init::run(project_dir)
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        process::exit(1);
    }
}
