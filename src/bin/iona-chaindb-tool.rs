//! IONA ChainDB Maintenance Tool
//!
//! Provides commands to inspect, prune, and compact the chain database.
//! The database is stored as JSONL (JSON Lines) files for blocks, receipts,
//! transactions, and logs.
//!
//! # Usage
//!
//! ```text
//! iona-chaindb-tool --chain-db-dir ./chaindb info
//! iona-chaindb-tool --chain-db-dir ./chaindb prune-compact --keep-blocks 10000
//! iona-chaindb-tool --chain-db-dir ./chaindb compact --keep-blocks 10000
//! ```

use clap::{Parser, Subcommand};
use iona::rpc::eth_rpc::EthRpcState;
use iona::rpc::chain_store::{self, ensure_meta, files, load_jsonl, prune_and_compact};
use std::path::{Path, PathBuf};
use thiserror::Error;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default chain database directory.
const DEFAULT_CHAIN_DB_DIR: &str = "./chaindb";

/// Default number of blocks to keep when pruning.
const DEFAULT_KEEP_BLOCKS: usize = 10_000;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during tool execution.
#[derive(Debug, Error)]
pub enum ToolError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("chain store error: {0}")]
    ChainStore(#[from] chain_store::ChainStoreError),

    #[error("invalid directory: {0}")]
    InvalidDirectory(PathBuf),

    #[error("keep_blocks must be > 0, got {0}")]
    InvalidKeepBlocks(usize),
}

pub type ToolResult<T> = Result<T, ToolError>;

// -----------------------------------------------------------------------------
// CLI Arguments
// -----------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(name = "iona-chaindb-tool")]
#[command(about = "IONA ChainDB maintenance tool", long_about = None)]
struct Args {
    /// Chain database directory (JSONL files).
    #[arg(long, default_value = DEFAULT_CHAIN_DB_DIR)]
    chain_db_dir: PathBuf,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Print metadata and record counts.
    Info,

    /// Prune old blocks and compact files (preserve only last N blocks).
    PruneCompact {
        /// Number of blocks to keep (oldest are removed).
        #[arg(long, default_value_t = DEFAULT_KEEP_BLOCKS)]
        keep_blocks: usize,
    },

    /// Full rebuild: load state, then write fresh compacted files.
    Compact {
        /// Number of blocks to keep.
        #[arg(long, default_value_t = DEFAULT_KEEP_BLOCKS)]
        keep_blocks: usize,
    },
}

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------

fn main() -> ToolResult<()> {
    let args = Args::parse();
    let dir = &args.chain_db_dir;

    // Validate directory existence (if it should exist for certain commands)
    match args.cmd {
        Cmd::Info => {
            if !dir.exists() {
                return Err(ToolError::InvalidDirectory(dir.clone()));
            }
        }
        Cmd::PruneCompact { keep_blocks } | Cmd::Compact { keep_blocks } => {
            if !dir.exists() {
                return Err(ToolError::InvalidDirectory(dir.clone()));
            }
            if keep_blocks == 0 {
                return Err(ToolError::InvalidKeepBlocks(keep_blocks));
            }
        }
    }

    match args.cmd {
        Cmd::Info => cmd_info(dir),
        Cmd::PruneCompact { keep_blocks } => cmd_prune_compact(dir, keep_blocks),
        Cmd::Compact { keep_blocks } => cmd_compact(dir, keep_blocks),
    }
}

// -----------------------------------------------------------------------------
// Command implementations
// -----------------------------------------------------------------------------

/// Display metadata and record counts.
fn cmd_info(dir: &Path) -> ToolResult<()> {
    let meta = ensure_meta(dir)?;
    println!("Metadata:");
    println!("  schema_version:  {}", meta.schema_version);
    println!("  created_at_unix: {}", meta.created_at_unix);

    let file_set = files(dir);
    let blocks: Vec<ionafaston::rpc::eth_rpc::Block> = load_jsonl(&file_set.blocks)
        .map_err(|e| ToolError::ChainStore(e))?;
    let receipts: Vec<ionafast::rpc::eth_rpc::Receipt> = load_jsonl(&file_set.receipts)
        .map_err(|e| ToolError::ChainStore(e))?;
    let txs: Vec<ionafast::rpc::eth_rpc::TxRecord> = load_jsonl(&file_set.txs)
        .map_err(|e| ToolError::ChainStore(e))?;
    let logs: Vec<ionafast::rpc::eth_rpc::Log> = load_jsonl(&file_set.logs)
        .map_err(|e| ToolError::ChainStore(e))?;

    println!("Counts:");
    println!("  blocks:    {}", blocks.len());
    println!("  receipts:  {}", receipts.len());
    println!("  txs:       {}", txs.len());
    println!("  logs:      {}", logs.len());

    Ok(())
}

/// Prune and compact: remove old blocks, compact files, rebuild indices.
fn cmd_prune_compact(dir: &Path, keep_blocks: usize) -> ToolResult<()> {
    let mut state = EthRpcState::default();
    state.chain_db_dir = Some(dir.to_path_buf());
    chain_store::load_into_state(dir, &mut state)?;
    chain_store::prune_and_compact(dir, &state, keep_blocks)?;
    println!("Prune and compact completed successfully.");
    Ok(())
}

/// Full rebuild: load state, then write fresh compacted files.
fn cmd_compact(dir: &Path, keep_blocks: usize) -> ToolResult<()> {
    let mut state = EthRpcState::default();
    state.chain_db_dir = Some(dir.to_path_buf());
    chain_store::load_into_state(dir, &mut state)?;
    chain_store::prune_and_compact(dir, &state, keep_blocks)?;
    println!("Full compact completed successfully.");
    Ok(())
}
