//! IONA Admin CLI Tool
//!
//! Provides administrative commands for node operators:
//! - Reset chain data, identity, or full node
//! - Show node status and disk usage
//! - Print peer ID and multiaddress
//! - Backup and restore
//! - Show configuration and version
//!
//! # Usage
//!
//! ```bash
//! iona-admin reset chain --data-dir ./data/node --confirm
//! iona-admin status --data-dir ./data/node
//! iona-admin peer-id --data-dir ./data/node
//! iona-admin backup --data-dir ./data/node --output ./backup
//! ```

use clap::{Parser, Subcommand};
use iona::admin::{
    exec_backup, exec_config, exec_print_multiaddr, exec_print_peer_id, exec_reset_chain,
    exec_reset_full, exec_reset_identity, exec_status, exec_version, result_to_json,
};
use serde_json::Value;
use std::path::PathBuf;

// -----------------------------------------------------------------------------
// Command-line arguments
// -----------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(name = "iona-admin", about = "IONA node administration tool")]
struct Args {
    /// Path to the node's data directory (default: ./data/node)
    #[arg(long, default_value = "./data/node")]
    data_dir: PathBuf,

    /// Output format: "json" or "text" (default: text)
    #[arg(long, default_value = "text")]
    format: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Reset chain data only (preserve identity)
    ResetChain {
        /// Skip confirmation prompt
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Reset identity keys only (preserve chain data)
    ResetIdentity {
        /// Skip confirmation prompt
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Reset everything (full wipe)
    ResetFull {
        /// Skip confirmation prompt
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Show node status (height, peers, disk usage, etc.)
    Status,
    /// Print the node's peer ID (from identity key)
    PeerId,
    /// Print the node's multiaddress (peer ID + listen address)
    Multiaddr {
        /// Listen address (e.g., /ip4/0.0.0.0/tcp/30333)
        #[arg(long, default_value = "/ip4/0.0.0.0/tcp/30333")]
        listen: String,
    },
    /// Create a timestamped backup of the data directory
    Backup {
        /// Output directory for the backup
        #[arg(long, default_value = "./backup")]
        output: PathBuf,
    },
    /// Show current configuration (from config.toml)
    Config {
        /// Path to config file (default: ./config.toml)
        #[arg(long, default_value = "./config.toml")]
        config_path: PathBuf,
    },
    /// Show version information
    Version,
    /// Verify node health (quick check)
    Health,
    /// Run integrity check on block store
    Verify,
}

// -----------------------------------------------------------------------------
// Main entry point
// -----------------------------------------------------------------------------

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let result = match args.command {
        Command::ResetChain { force } => {
            exec_reset_chain(args.data_dir.to_str().unwrap(), !force)?
        }
        Command::ResetIdentity { force } => {
            exec_reset_identity(args.data_dir.to_str().unwrap(), !force)?
        }
        Command::ResetFull { force } => {
            exec_reset_full(args.data_dir.to_str().unwrap(), !force)?
        }
        Command::Status => exec_status(args.data_dir.to_str().unwrap())?,
        Command::PeerId => exec_print_peer_id(args.data_dir.to_str().unwrap())?,
        Command::Multiaddr { listen } => {
            exec_print_multiaddr(args.data_dir.to_str().unwrap(), &listen)?
        }
        Command::Backup { output } => {
            exec_backup(args.data_dir.to_str().unwrap(), output.to_str().unwrap())?
        }
        Command::Config { config_path } => {
            exec_config(config_path.to_str().unwrap())?
        }
        Command::Version => exec_version(),
        Command::Health => {
            // Quick health check: just status with simplified output
            exec_status(args.data_dir.to_str().unwrap())?
        }
        Command::Verify => {
            // Run block store integrity check
            let layout = iona::data_layout::DataLayout::new(args.data_dir.to_str().unwrap());
            let store = iona::storage::block_store::FsBlockStore::open(layout.blocks_dir())?;
            store.verify_integrity()?;
            println!("Integrity check passed.");
            return Ok(());
        }
    };

    if args.format == "json" {
        println!("{}", result_to_json(&result));
    } else {
        print_result(&result);
    }

    Ok(())
}

// -----------------------------------------------------------------------------
// Pretty printing
// -----------------------------------------------------------------------------

fn print_result(result: &iona::admin::AdminResult) {
    match result {
        iona::admin::AdminResult::ResetChain {
            dirs_removed,
            dirs_preserved,
        } => {
            println!("Chain data reset.");
            println!("  Removed: {}", dirs_removed.join(", "));
            println!("  Preserved: {}", dirs_preserved.join(", "));
        }
        iona::admin::AdminResult::ResetIdentity {
            dirs_removed,
            dirs_preserved,
        } => {
            println!("Identity keys reset.");
            println!("  Removed: {}", dirs_removed.join(", "));
            println!("  Preserved: {}", dirs_preserved.join(", "));
        }
        iona::admin::AdminResult::ResetFull { dirs_removed } => {
            println!("Full node reset (all data removed).");
            println!("  Removed: {}", dirs_removed.join(", "));
        }
        iona::admin::AdminResult::Status { info } => {
            println!("Node Status:");
            println!("  Data directory: {}", info.data_dir);
            println!("  Best height: {}", info.blocks_count);
            println!("  Snapshots: {}", info.snapshots_count);
            println!("  Has identity: {}", info.has_identity);
            println!("  Has validator key: {}", info.has_validator_key);
            println!("  Has chain data: {}", info.has_chain_data);
            println!("  Disk usage: {} bytes", info.disk_usage_bytes);
            if let Some(sv) = info.schema_version {
                println!("  Schema version: {}", sv);
            }
        }
        iona::admin::AdminResult::PrintPeerId { peer_id } => {
            println!("Peer ID: {}", peer_id);
        }
        iona::admin::AdminResult::PrintMultiaddr { multiaddr } => {
            println!("Multiaddress: {}", multiaddr);
        }
        iona::admin::AdminResult::Config { config } => {
            println!("Configuration:");
            println!("{}", serde_json::to_string_pretty(config).unwrap());
        }
        iona::admin::AdminResult::Version { version, commit } => {
            println!("IONA node version: {}", version);
            if commit != "unknown" {
                println!("Git commit: {}", commit);
            }
        }
        iona::admin::AdminResult::BackupCreated { backup_path } => {
            println!("Backup created at: {}", backup_path);
        }
    }
}
