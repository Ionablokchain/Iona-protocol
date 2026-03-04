use clap::{Parser, Subcommand};
use iona::rpc::eth_rpc::EthRpcState;

#[derive(Parser, Debug)]
#[command(name="iona-chaindb-tool")]
struct Args {
    /// Chain DB dir (jsonl)
    #[arg(long, default_value="./chaindb")]
    chain_db_dir: String,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Print meta + counts
    Info,
    /// Prune to keep last N blocks and compact files + rebuild indices.
    PruneCompact { #[arg(long, default_value_t=10_000)] keep_blocks: usize },
    /// Rebuild in-memory state from files and then write fresh compacted files.
    Compact { #[arg(long, default_value_t=10_000)] keep_blocks: usize },
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let dir = args.chain_db_dir;

    match args.cmd {
        Cmd::Info => {
            let meta = iona::rpc::chain_store::ensure_meta(&dir)?;
            println!("meta: schema_version={}, created_at_unix={}", meta.schema_version, meta.created_at_unix);
            let f = iona::rpc::chain_store::files(&dir);
            let blocks: Vec<iona::rpc::eth_rpc::Block> = iona::rpc::chain_store::load_jsonl(&f.blocks).unwrap_or_default();
            let receipts: Vec<iona::rpc::eth_rpc::Receipt> = iona::rpc::chain_store::load_jsonl(&f.receipts).unwrap_or_default();
            let txs: Vec<iona::rpc::eth_rpc::TxRecord> = iona::rpc::chain_store::load_jsonl(&f.txs).unwrap_or_default();
            let logs: Vec<iona::rpc::eth_rpc::Log> = iona::rpc::chain_store::load_jsonl(&f.logs).unwrap_or_default();
            println!("blocks={} receipts={} txs={} logs={}", blocks.len(), receipts.len(), txs.len(), logs.len());
        }
        Cmd::PruneCompact { keep_blocks } | Cmd::Compact { keep_blocks } => {
            let mut st = EthRpcState::default();
            st.chain_db_dir = Some(dir.clone());
            iona::rpc::chain_store::load_into_state(&dir, &mut st)?;
            iona::rpc::chain_store::prune_and_compact(&dir, &st, keep_blocks)?;
            println!("done");
        }
    }
    Ok(())
}
