use clap::Parser;
use iona::rpc::router::build_router;
use iona::rpc::eth_rpc::EthRpcState;
use std::net::SocketAddr;
use tokio::time::{sleep, Duration};
use tokio::net::TcpListener;

#[derive(Parser, Debug)]
#[command(name="iona-evm-rpc")]
struct Args {
    /// Data dir for persistence (state snapshot)
    #[arg(long)]
    data_dir: Option<String>,

    /// Append-only chain DB dir (jsonl). If set, loads blocks/receipts/txs/logs from files and appends new ones.
    #[arg(long)]
    chain_db_dir: Option<String>,

    /// If set, prune+compact chain DB at startup to keep last N blocks.
    #[arg(long)]
    prune_keep_blocks: Option<usize>,

    /// Listen address (e.g. 127.0.0.1:8545)
    #[arg(long, default_value="127.0.0.1:8545")]
    listen: String,

    /// Block time in milliseconds. If >0, produces blocks periodically by calling iona_mine internally.
    #[arg(long, default_value_t=0)]
    block_time_ms: u64,

    /// Max txs per produced block
    #[arg(long, default_value_t=256)]
    max_txs: u64,

    /// Disable automine (do not mine immediately on sendRawTransaction)
    #[arg(long, default_value_t=false)]
    no_automine: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let mut st = EthRpcState::default();

    if let Some(dir) = args.data_dir.clone() {
        // snapshot persistence

        st.persist_dir = Some(dir.clone());
        if let Ok(Some(snap)) = iona::rpc::fs_store::load_snapshot(&dir) {
            iona::rpc::fs_store::apply_snapshot_to_state(&mut st, snap);
        }
    }

    if args.no_automine {
        st.automine = false;
    }

    if let Some(cdir) = args.chain_db_dir.clone() {
        st.chain_db_dir = Some(cdir.clone());
        if let Ok(_) = iona::rpc::chain_store::load_into_state(&cdir, &mut st) {
            // loaded append-only chain db into memory
        }
        if let Some(keep) = args.prune_keep_blocks {
            let _ = iona::rpc::chain_store::prune_and_compact(&cdir, &st, keep);
        }
    }


    let addr: SocketAddr = args.listen.parse()?;
    let app = build_router(st.clone());

    if args.block_time_ms > 0 {
        let st2 = st.clone();
        let bt = args.block_time_ms;
        let max = args.max_txs as usize;
        tokio::spawn(async move {
            loop {
                sleep(Duration::from_millis(bt)).await;
                // mine if there are txs
                let n = st2.txpool.lock().unwrap().len();
                if n > 0 {
                    let _ = iona::rpc::eth_rpc::mine_pending_block_public(&st2, max);
                }
            }
        });
    }

    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
