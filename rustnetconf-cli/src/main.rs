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
        Commands::Plan { device, json } => {
            commands::plan::run(project_dir, &device, json).await.map(|_| ())
        }
        Commands::Apply { device, yes } => {
            commands::apply::run(project_dir, &device, yes).await
        }
        Commands::Confirm { device } => {
            commands::confirm::run(project_dir, &device).await
        }
        Commands::Rollback { device } => {
            commands::rollback::run(project_dir, &device).await
        }
        Commands::Get { device } => {
            commands::get::run(project_dir, &device).await
        }
        Commands::Validate { device } => {
            commands::validate::run(project_dir, &device).await
        }
        Commands::Init => {
            commands::init::run(project_dir)
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        process::exit(1);
    }
}
