//! IONA v24.3 — Production Node
//!
//! Changes vs v20:
//! - Static peer dialing (--peers / config.toml [network] peers)
//! - Config TOML support (--config config.toml, CLI overrides)
//! - Dynamic validator set via governance txs
//! - Slashing with jail/unjail/tombstone
//! - Deterministic binary sign bytes (stable across serde versions)
//! - Block store LRU cache + tx-hash index
//! - Gossipsub heartbeat 100ms
//! - Peer reconnect every 30s for static peers
//! - /validator endpoint for status report
//! - /tx_location/<hash> endpoint for tx lookup

use axum::{
    extract::{ConnectInfo, Extension, Path, State},
    middleware,
    routing::{get, post},
    Json, Router,
};
use clap::Parser;

#[derive(clap::ValueEnum, Clone, Debug)]
enum OnOff {
    On,
    Off,
}

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use iona::config::NodeConfig;
use iona::consensus::{
    BlockStore, Config as Cfg, DoubleSignGuard, Engine, Outbox as OutboxTrait, SimpleBlockProducer,
    SimpleProducerCfg, Validator, ValidatorSet,
};
use iona::crypto::ed25519::{Ed25519Keypair, Ed25519Verifier};
use iona::crypto::tx::derive_address;
use iona::crypto::{Signer, Verifier};
use iona::economics::params::EconomicsParams;
use iona::economics::rewards::{distribute_epoch_rewards, is_epoch_boundary};
use iona::economics::staking::StakingState;
use iona::execution::vm_executor::derive_contract_address;
use iona::execution::KvState;
use iona::governance::{parse_gov_payload, GovPayloadAction, GovernanceState};
use iona::mempool::Mempool;
use iona::metrics::{self, Metrics};
use iona::net::p2p::{
    BlockResponse, P2p, P2pConfig, P2pEvent, RangeResponse, Req, Resp, StatusResponse,
};
use iona::rpc::middleware::{
    body_limit_middleware, concurrency_middleware, header_size_middleware, json_depth_middleware,
    read_limit_middleware, request_id_middleware,
};
use iona::rpc_limits::{new_request_id, validate_tx, RpcLimitResult, RpcLimiter};
use iona::slashing::{StakeLedger, UptimeTracker};
use iona::storage::block_store::FsBlockStore;
use iona::storage::evidence_store::EvidenceStore;
use iona::storage::peer_store::PeerStore;
use iona::storage::receipts_store::ReceiptsStore;
use iona::storage::DataDir;
use iona::types::{Hash32, Tx};
use iona::wal::{Wal, WalEvent};
use libp2p::{Multiaddr, PeerId};
use std::option::Option::None;
use std::result::Result::Ok;
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};
use tokio::{sync::Mutex, time::Instant};
use tower_http::cors::CorsLayer;
use tracing::{debug, error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

// ── Startup security gate: key-file and data-directory permissions ─────────

/// Verify that the key file and data directory have safe Unix permissions.
///
/// * Key file (`keys.enc` or `keys.json`) must be `0600` (owner read/write only).
/// * Data directory must be `0700` (owner only).
///
/// On non-Unix systems this is a no-op (returns `Ok(())`).
fn check_key_permissions(data_dir: &str, keystore_mode: &str) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        // Check data directory permissions.
        let dir_path = std::path::Path::new(data_dir);
        if dir_path.exists() {
            let meta = std::fs::metadata(dir_path)
                .map_err(|e| anyhow::anyhow!("cannot stat data_dir '{}': {e}", data_dir))?;
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                anyhow::bail!(
                    "SECURITY: data directory '{}' has permissions {:03o} — too permissive.\n\
                     Expected 0700 (owner-only). Fix with:\n\
                     chmod 0700 {}",
                    data_dir,
                    mode,
                    data_dir
                );
            }
        }

        // Check key file permissions.
        let key_file = match keystore_mode.trim().to_lowercase().as_str() {
            "encrypted" => format!("{data_dir}/keys.enc"),
            _ => format!("{data_dir}/keys.json"),
        };
        let key_path = std::path::Path::new(&key_file);
        if key_path.exists() {
            let meta = std::fs::metadata(key_path)
                .map_err(|e| anyhow::anyhow!("cannot stat key file '{}': {e}", key_file))?;
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o177 != 0 {
                anyhow::bail!(
                    "SECURITY: key file '{}' has permissions {:03o} — too permissive.\n\
                     Expected 0600 (owner read/write only). Fix with:\n\
                     chmod 0600 {}",
                    key_file,
                    mode,
                    key_file
                );
            }
        }
    }
    Ok(())
}

// ── No-op outbox used during WAL replay/bootstrap (no network side effects) ─

// No-op outbox used during WAL replay/bootstrap (no network side effects).
struct NoopOutbox;
impl OutboxTrait for NoopOutbox {
    fn broadcast(&mut self, _msg: iona::consensus::ConsensusMsg) {}
    fn request_block(&mut self, _block_id: iona::types::Hash32) {}
    fn on_commit(
        &mut self,
        _cert: &iona::consensus::CommitCertificate,
        _block: &iona::types::Block,
        _new_state: &iona::execution::KvState,
        _new_base_fee: u64,
        _receipts: &[iona::types::Receipt],
    ) {
    }
}

// ── CLI Args ──────────────────────────────────────────────────────────────

#[derive(Parser, Debug, Clone)]
#[command(
    name = "iona-node",
    version = "28.1.0",
    about = "IONA v28.1 production node"
)]
struct Args {
    /// Path to TOML config file (CLI flags override file values)
    #[arg(long, default_value = "")]
    config: String,

    // Network
    #[arg(long)]
    listen: Option<String>,
    /// Static peer addresses to dial and maintain (repeatable)
    #[arg(long)]
    peers: Vec<String>,

    /// Bootstrap peers (repeatable). May include /p2p/<peerid> for DHT seeding.
    #[arg(long)]
    bootnodes: Vec<String>,

    /// Enable LAN peer discovery via mDNS
    #[arg(long)]
    enable_mdns: Option<bool>,

    /// Enable Kademlia DHT
    #[arg(long)]
    enable_kad: Option<bool>,
    #[arg(long)]
    rpc: Option<String>,

    // Node identity
    #[arg(long)]
    data: Option<String>,
    #[arg(long)]
    seed: Option<u64>,
    #[arg(long)]
    chain_id: Option<u64>,

    // Consensus
    #[arg(long)]
    propose_timeout_ms: Option<u64>,
    #[arg(long)]
    prevote_timeout_ms: Option<u64>,
    #[arg(long)]
    precommit_timeout_ms: Option<u64>,
    #[arg(long)]
    max_txs_per_block: Option<usize>,
    #[arg(long)]
    gas_target: Option<u64>,
    #[arg(long)]
    fast_quorum: Option<bool>,
    #[arg(long)]
    stake_each: Option<u64>,
    #[arg(long)]
    initial_base_fee: Option<u64>,

    /// Enable/disable the Simple PoS block producer (on/off)
    #[arg(long, value_enum)]
    simple_producer: Option<OnOff>,

    // Production options
    #[arg(long)]
    enable_faucet: Option<bool>,
    #[arg(long)]
    mempool_cap: Option<usize>,
    #[arg(long)]
    log_level: Option<String>,

    /// Write an example config.toml and exit
    #[arg(long, default_value_t = false)]
    write_example_config: bool,

    /// Allow RPC to bind on a public address (e.g. 0.0.0.0).
    /// Without this flag, the node refuses to start if rpc.listen is not a
    /// loopback address. Always log a prominent WARNING when active.
    #[arg(long, default_value_t = false)]
    unsafe_rpc_public: bool,

    /// Skip keystore file-permission checks at startup.
    /// Useful on Windows or exotic filesystems. NOT recommended for production.
    #[arg(long, default_value_t = false)]
    unsafe_skip_key_perms: bool,

    /// Check whether the on-disk schema is compatible with this binary and
    /// print a compatibility report, then exit. No modifications are made.
    #[arg(long, default_value_t = false)]
    check_compat: bool,

    /// Simulate schema migrations (dry-run mode): validate all pending
    /// migrations and report what would change, then exit without modifying
    /// anything on disk.
    #[arg(long, default_value_t = false)]
    dry_run_migrations: bool,

    /// Hardening profile to apply at startup.
    ///
    /// - `dev`  : loopback RPC, permissive CORS, relaxed gates (default if not set)
    /// - `prod` : loopback RPC enforced, CORS off, key-perm gates, warn if any deviation
    /// - `hard` : all of prod, plus refuse to start if peers < 3, metrics exposed on loopback only
    ///
    /// The profile adds guards on top of config.toml settings — it does NOT override explicit
    /// config values, but it WILL refuse to start if config violates the profile's minimum bar.
    #[arg(long, default_value = "dev")]
    profile: String,
}

// ── Shared App state ──────────────────────────────────────────────────────

#[derive(Clone)]
struct App {
    mempool: Arc<Mutex<Mempool>>,
    kv_state: Arc<Mutex<KvState>>,
    governance: Arc<Mutex<GovernanceState>>,
    peers: Arc<Mutex<BTreeMap<String, i32>>>,
    base_fee: Arc<Mutex<u64>>,
    best_height: Arc<Mutex<u64>>,
    chain_id: u64,
    store: Arc<FsBlockStore>,
    receipts: Arc<ReceiptsStore>,
    limiter: Arc<RpcLimiter>,
    metrics: Arc<Metrics>,
    enable_faucet: bool,
    // Shared validator state for the /validators endpoint
    validator_info: Arc<Mutex<Vec<ValidatorInfo>>>,
    // Uptime tracker for downtime-based jailing
    uptime_tracker: Arc<Mutex<UptimeTracker>>,
    // PoS staking state (delegations, unbonding)
    staking_state: Arc<Mutex<StakingState>>,
    // Economics parameters (inflation, min_stake, etc.)
    economics_params: EconomicsParams,
}

#[derive(Clone, serde::Serialize)]
struct ValidatorInfo {
    address: String,
    stake: u64,
    slashed_total: u64,
    status: String,
}

// ── Main ──────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    if args.write_example_config {
        NodeConfig::write_example("config.toml")?;
        println!("Wrote example config.toml");
        return Ok(());
    }

    // Load config file, then apply CLI overrides
    let mut cfg_file = if args.config.is_empty() {
        NodeConfig::load("config.toml").unwrap_or_default()
    } else {
        NodeConfig::load(&args.config)?
    };

    // ── Early-exit upgrade / compat flags ──────────────────────────────────
    //
    // These flags perform a read-only check and exit before any node subsystem
    // is started.  They do NOT require full initialisation.

    if args.check_compat {
        let data_dir = std::path::Path::new(&cfg_file.node.data_dir);
        let report = iona::upgrade::check_compat(data_dir)?;
        print!("{report}");
        if !report.is_ok() {
            std::process::exit(1);
        }
        return Ok(());
    }

    if args.dry_run_migrations {
        let data_dir = std::path::Path::new(&cfg_file.node.data_dir);
        let ok = iona::upgrade::dry_run_migrations(data_dir)?;
        if !ok {
            std::process::exit(1);
        }
        return Ok(());
    }

    // ── Profile gates ──────────────────────────────────────────────────────
    //
    // Apply hardening guards based on --profile.  Each profile adds
    // progressively stricter startup checks on top of config.toml settings.
    //
    // Profiles:
    //   dev          — relax all gates (useful for local testing)
    //   prod         — enforce loopback-only RPC
    //   hard         — all of prod + cors_allow_all=false enforced
    //   cosmos-hard  — all of hard + Cosmos validator recommendations:
    //                  ≥3 peers, eclipse_profile=mainnet, admin mTLS required

    let profile = args.profile.to_ascii_lowercase();
    let profile = profile.as_str();

    match profile {
        "prod" | "hard" | "cosmos-hard" => {
            // Check 1 (all hardened profiles): RPC must not be on a public address.
            let rpc_listen = &cfg_file.rpc.listen;
            let is_public = !rpc_listen.starts_with("127.")
                && !rpc_listen.starts_with("[::1]")
                && rpc_listen != "localhost";
            if is_public && !args.unsafe_rpc_public {
                anyhow::bail!(
                    "[profile={}] RPC is configured to listen on a public address ({rpc_listen}). \
                     This is blocked by the --profile guard. Either set rpc.listen to a loopback \
                     address, or add --unsafe-rpc-public to explicitly allow public RPC.",
                    profile
                );
            }

            // Check 2 (hard + cosmos-hard): CORS must not be opened globally.
            if matches!(profile, "hard" | "cosmos-hard") {
                if cfg_file.rpc.cors_allow_all {
                    anyhow::bail!(
                        "[profile={profile}] cors_allow_all=true is not permitted. \
                         Set cors_allow_all = false in config.toml."
                    );
                }
            }

            // Check 3 (cosmos-hard): Cosmos validator specific enforcement.
            if profile == "cosmos-hard" {
                // Require at least 3 peers or bootnodes — single-peer validators
                // are vulnerable to eclipse attacks on Cosmos networks.
                let peer_count = cfg_file.network.peers.len() + cfg_file.network.bootnodes.len();
                if peer_count < 3 {
                    anyhow::bail!(
                        "[profile=cosmos-hard] Fewer than 3 peers/bootnodes configured ({peer_count} found). \
                         Cosmos validators must have ≥3 static peers or bootnodes to resist eclipse attacks. \
                         Add peers to [network].peers or [network].bootnodes in config.toml."
                    );
                }

                // Enforce mainnet eclipse resistance profile.
                if cfg_file.network.eclipse_profile != "mainnet" {
                    anyhow::bail!(
                        "[profile=cosmos-hard] eclipse_profile must be \"mainnet\" \
                         (currently \"{}\"). Set eclipse_profile = \"mainnet\" in config.toml.",
                        cfg_file.network.eclipse_profile
                    );
                }

                // Admin interface must use mTLS — unprotected admin = full compromise.
                if !cfg_file.admin.require_mtls {
                    anyhow::bail!(
                        "[profile=cosmos-hard] admin.require_mtls must be true. \
                         The admin interface controls key operations and must be mTLS-protected."
                    );
                }

                tracing::info!(
                    "cosmos-hard profile enforced: eclipse=mainnet, admin mTLS=required, peers≥3"
                );
                tracing::info!(
                    "Port mapping reference (CometBFT → IONA): P2P 26656→7001, RPC 26657→9001, \
                     gRPC 9090→9090, Admin →9002"
                );
            }

            tracing::info!(profile = %profile, "hardening profile active");
        }
        "dev" => {
            tracing::warn!(
                "Running in dev profile — security gates are RELAXED. Do NOT use in production."
            );
        }
        other => {
            anyhow::bail!(
                "Unknown --profile value: '{other}'. Valid values: dev, prod, hard, cosmos-hard"
            );
        }
    }

    // CLI overrides
    if let Some(v) = &args.listen {
        cfg_file.network.listen = v.clone();
    }
    if !args.peers.is_empty() {
        cfg_file.network.peers = args.peers.clone();
    }
    if !args.bootnodes.is_empty() {
        cfg_file.network.bootnodes = args.bootnodes.clone();
    }
    if let Some(v) = args.enable_mdns {
        cfg_file.network.enable_mdns = v;
    }
    if let Some(v) = args.enable_kad {
        cfg_file.network.enable_kad = v;
    }
    if let Some(v) = &args.rpc {
        cfg_file.rpc.listen = v.clone();
    }
    if let Some(v) = &args.data {
        cfg_file.node.data_dir = v.clone();
    }
    if let Some(v) = args.seed {
        cfg_file.node.seed = v;
    }
    if let Some(v) = args.chain_id {
        cfg_file.node.chain_id = v;
    }
    if let Some(v) = args.propose_timeout_ms {
        cfg_file.consensus.propose_timeout_ms = v;
    }
    if let Some(v) = args.prevote_timeout_ms {
        cfg_file.consensus.prevote_timeout_ms = v;
    }
    if let Some(v) = args.precommit_timeout_ms {
        cfg_file.consensus.precommit_timeout_ms = v;
    }
    if let Some(v) = args.max_txs_per_block {
        cfg_file.consensus.max_txs_per_block = v;
    }
    if let Some(v) = args.gas_target {
        cfg_file.consensus.gas_target = v;
    }
    if let Some(v) = args.fast_quorum {
        cfg_file.consensus.fast_quorum = v;
    }
    if let Some(v) = args.stake_each {
        cfg_file.consensus.stake_each = v;
    }
    if let Some(v) = args.initial_base_fee {
        cfg_file.consensus.initial_base_fee = v;
    }
    if let Some(v) = &args.simple_producer {
        cfg_file.consensus.simple_producer = matches!(v, OnOff::On);
    }
    if let Some(v) = args.enable_faucet {
        cfg_file.rpc.enable_faucet = v;
    }
    if let Some(v) = args.mempool_cap {
        cfg_file.mempool.capacity = v;
    }
    if let Some(v) = &args.log_level {
        cfg_file.node.log_level = v.clone();
    }
    tracing::info!(
        "Simple producer enabled: {}",
        cfg_file.consensus.simple_producer
    );

    let cfg = cfg_file;

    // ── Security gate: RPC bind-address check ────────────────────────────
    // Block public exposure unless the operator explicitly opts in.
    {
        let listen = &cfg.rpc.listen;
        let is_public =
            !listen.starts_with("127.") && !listen.starts_with("[::1]") && listen != "localhost";
        if is_public && !args.unsafe_rpc_public {
            anyhow::bail!(
                "SECURITY: rpc.listen is set to '{}' which exposes the RPC server publicly.\n\
                 This is blocked by default to prevent accidental exposure.\n\
                 To proceed, start the node with --unsafe-rpc-public.\n\
                 You should also ensure firewall rules restrict access appropriately.",
                listen
            );
        }
        if is_public {
            warn!("══════════════════════════════════════════════════════════");
            warn!("WARNING: RPC is exposed publicly on {}.", listen);
            warn!("Ensure firewall rules restrict access appropriately.");
            warn!("══════════════════════════════════════════════════════════");
        }
        if cfg.rpc.cors_allow_all {
            warn!("WARNING: RPC CORS is set to allow-all (cors_allow_all=true). Dev/testnet only.");
        }
        if cfg.rpc.enable_faucet {
            warn!("WARNING: Faucet endpoint is enabled. TESTNET ONLY.");
        }
    }

    let snap_plan = SnapshotPlan::from_cfg(&cfg.storage);
    let attest_pool: Arc<StdMutex<AttestPool>> = Arc::new(StdMutex::new(AttestPool::default()));

    // Logging (+ optional OpenTelemetry if compiled with --features otel)
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cfg.node.log_level));

    let fmt_layer = tracing_subscriber::fmt::layer();

    #[cfg(feature = "otel")]
    let subscriber = {
        if cfg.observability.enable_otel {
            match iona::metrics::build_otel_layer(
                &cfg.observability.service_name,
                &cfg.observability.otel_endpoint,
            ) {
                Ok(otel_layer) => tracing_subscriber::registry()
                    .with(env_filter)
                    .with(fmt_layer)
                    .with(otel_layer),
                Err(e) => {
                    eprintln!("otel init failed: {e}");
                    tracing_subscriber::registry()
                        .with(env_filter)
                        .with(fmt_layer)
                }
            }
        } else {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt_layer)
        }
    };

    #[cfg(not(feature = "otel"))]
    let subscriber = tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer);

    subscriber.init();

    info!(
        version = "24.6.0",
        chain_id = cfg.node.chain_id,
        "IONA node starting"
    );

    let dd = DataDir::new(&cfg.node.data_dir);
    dd.ensure()?;
    dd.ensure_schema_and_migrate()?;

    // Snapshot restore (fast local recovery)
    if cfg.storage.enable_snapshots {
        let state_full_path = format!("{}/state_full.json", cfg.node.data_dir);
        match iona::storage::snapshots::restore_latest_if_missing(
            &cfg.node.data_dir,
            &state_full_path,
        ) {
            Ok(Some(h)) => info!(height = h, "restored state_full.json from latest snapshot"),
            Ok(None) => {}
            Err(e) => warn!("snapshot restore failed: {e}"),
        }
    }

    // P2P state sync (download snapshot from peers) if state_full.json is still missing.
    // This is a "single-shot" bootstrap: it runs only at startup.
    if cfg.network.enable_p2p_state_sync {
        let state_full_path = format!("{}/state_full.json", cfg.node.data_dir);
        if !std::path::Path::new(&state_full_path).exists() {
            let mut addrs = Vec::new();
            for s in cfg.network.peers.iter().chain(cfg.network.bootnodes.iter()) {
                if let Ok(a) = s.parse() {
                    addrs.push(a);
                }
            }
            match iona::net::state_sync::try_p2p_restore_state(
                &cfg.node.data_dir,
                &state_full_path,
                addrs,
                cfg.network.state_sync_timeout_s,
                cfg.network.state_sync_chunk_bytes as usize,
            )
            .await
            {
                Ok(true) => info!("p2p state sync completed"),
                Ok(false) => debug!("p2p state sync skipped/unavailable"),
                Err(e) => warn!("p2p state sync failed: {e}"),
            }
        }
    }

    // ── Security gate: key-file and data-directory permissions ───────────────
    if !args.unsafe_skip_key_perms {
        check_key_permissions(&cfg.node.data_dir, &cfg.node.keystore)?;
    } else {
        warn!("--unsafe-skip-key-perms: key-file permission checks are DISABLED.");
    }

    // Keys
    let signer: Ed25519Keypair = dd.load_or_create_keys_with_fallback(
        cfg.node.seed,
        &cfg.node.keystore,
        &cfg.node.keystore_password_env,
        &cfg.node.keystore_password,
    )?;
    let node_addr = derive_address(&signer.public_key().0);
    info!(addr = %node_addr, "node identity");

    // WAL
    let wal_dir = format!("{}/wal", cfg.node.data_dir);
    let mut wal = Wal::open(&wal_dir)?;

    let _evidence_store = EvidenceStore::open(dd.evidence_path())?;

    // State
    let mut kv = dd.load_state_full()?;
    if kv.balances.is_empty() {
        kv.balances.insert(node_addr.clone(), 1_000_000_000_000u64);
    }

    // Governance state
    let gov_state = GovernanceState::default();

    // Validator set — from config (validator_seeds), matching genesis validators.
    // All nodes MUST use the same validator_seeds for consensus to agree on proposer rotation.
    let validator_seeds = &cfg.consensus.validator_seeds;
    if validator_seeds.is_empty() {
        anyhow::bail!("consensus.validator_seeds must not be empty — need at least 1 validator");
    }
    info!(seeds = ?validator_seeds, "validator set");
    let mut validators = Vec::new();
    for s in validator_seeds {
        let mut seed32 = [0u8; 32];
        seed32[..8].copy_from_slice(&s.to_le_bytes());
        validators.push(Ed25519Keypair::from_seed(seed32).public_key());
    }
    let mut vset = ValidatorSet {
        vals: validators
            .iter()
            .map(|v| Validator {
                pk: v.clone(),
                power: cfg.consensus.stake_each,
            })
            .collect(),
    };

    let mut stakes = dd.load_stakes()?;
    if stakes.validators.is_empty() {
        stakes = StakeLedger::default_demo_with(&validators, cfg.consensus.stake_each);
        dd.save_stakes(&stakes)?;
    }

    let store = Arc::new(FsBlockStore::open(dd.blocks_dir())?);
    let receipts = Arc::new(ReceiptsStore::open(dd.receipts_dir())?);

    // Consensus engine config
    let mut eng_cfg = Cfg::default();
    eng_cfg.initial_base_fee_per_gas = cfg.consensus.initial_base_fee;
    eng_cfg.propose_timeout_ms = cfg.consensus.propose_timeout_ms;
    eng_cfg.prevote_timeout_ms = cfg.consensus.prevote_timeout_ms;
    eng_cfg.precommit_timeout_ms = cfg.consensus.precommit_timeout_ms;
    eng_cfg.max_txs_per_block = cfg.consensus.max_txs_per_block;
    eng_cfg.gas_target = cfg.consensus.gas_target;
    eng_cfg.fast_quorum = cfg.consensus.fast_quorum;

    info!(
        propose_ms = eng_cfg.propose_timeout_ms,
        fast_quorum = eng_cfg.fast_quorum,
        max_txs = eng_cfg.max_txs_per_block,
        gas_target = eng_cfg.gas_target,
        "consensus config"
    );

    // DoubleSignGuard::new returns Result — a tampered or rolled-back guard file
    // must abort startup rather than allowing a potential double-sign.
    let ds_guard = Some(
        DoubleSignGuard::new(&dd.root, &signer.public_key()).map_err(|e| {
            anyhow::anyhow!("double-sign guard integrity check FAILED — refusing to start: {e}")
        })?,
    );
    let ds_guard_clone = ds_guard.clone();
    let mut engine: Engine<Ed25519Verifier> = Engine::new(
        eng_cfg.clone(),
        vset.clone(),
        1,
        Hash32::zero(),
        kv.clone(),
        stakes.clone(),
        ds_guard,
    );

    // Simple PoS producer: round-robin proposer that builds + signs a Proposal and broadcasts it.
    // This producer does not generate votes; those remain in the consensus engine.
    let producer = SimpleBlockProducer::new(SimpleProducerCfg {
        max_txs: eng_cfg.max_txs_per_block,
        include_block_in_proposal: eng_cfg.include_block_in_proposal,
    });

    // WAL replay
    let wal_events = {
        let new = Wal::replay(&wal_dir)?;
        if new.is_empty() {
            Wal::replay_path(&dd.wal_path()).unwrap_or_default()
        } else {
            new
        }
    };
    let mut start_at = 0usize;
    for (i, ev) in wal_events.iter().enumerate() {
        if let WalEvent::Snapshot { bytes } = ev {
            if let Ok(m) = bincode::deserialize::<EngineMirror>(bytes) {
                engine = m.into_engine(ds_guard_clone.clone());
                start_at = i + 1;
            }
        }
    }
    for ev in wal_events.into_iter().skip(start_at) {
        if let WalEvent::Inbound { bytes } = ev {
            if let Ok(msg) = bincode::deserialize::<iona::consensus::ConsensusMsg>(&bytes) {
                let mut ob = NoopOutbox;
                let _ = engine.on_message(&signer, &*store, &mut ob, msg);
            }
        }
    }
    dd.save_state_full(&engine.app_state)?;
    dd.save_stakes(&engine.stakes)?;

    // Metrics
    let prod_metrics = Arc::new(Metrics::new()?);
    prod_metrics
        .consensus_height
        .set(engine.state.height as i64);
    prod_metrics.base_fee.set(engine.base_fee_per_gas as f64);

    // Build initial validator info
    let initial_vi: Vec<ValidatorInfo> = engine
        .stakes
        .status_report()
        .into_iter()
        .map(|(pk, rec)| ValidatorInfo {
            address: hex::encode(&blake3::hash(&pk.0).as_bytes()[..20]),
            stake: rec.stake,
            slashed_total: rec.slashed_total,
            status: format!("{:?}", rec.status),
        })
        .collect();

    // Persistent peer store (stores configured peers + bootnodes)
    let peer_store_path = format!("{}/peers.json", cfg.node.data_dir);
    let mut peer_store = PeerStore::open(peer_store_path)?;

    for p in cfg.network.peers.iter() {
        let _ = peer_store.add(p.clone());
    }
    for b in cfg.network.bootnodes.iter() {
        let _ = peer_store.add(b.clone());
    }

    let stored = peer_store.addrs();

    // P2P networking — with static peers + bootnodes
    let static_peers: Vec<Multiaddr> = stored
        .iter()
        .chain(cfg.network.peers.iter())
        .filter_map(|s| s.parse().ok())
        .collect();

    let bootnodes: Vec<Multiaddr> = stored
        .iter()
        .chain(cfg.network.bootnodes.iter())
        .filter_map(|s| s.parse().ok())
        .collect();

    let p2p_cfg = P2pConfig {
        local_key: libp2p::identity::Keypair::generate_ed25519(),
        listen: cfg.network.listen.parse()?,
        static_peers: static_peers.clone(),
        bootnodes: bootnodes.clone(),
        enable_mdns: cfg.network.enable_mdns,
        enable_kad: cfg.network.enable_kad,
        reconnect_s: cfg.network.reconnect_s,
        max_connections_total: cfg.network.max_connections_total,
        max_connections_per_peer: cfg.network.max_connections_per_peer,

        rr_max_req_per_sec_block: cfg.network.rr_max_req_per_sec_block,
        rr_max_req_per_sec_status: cfg.network.rr_max_req_per_sec_status,
        rr_max_req_per_sec_range: cfg.network.rr_max_req_per_sec_range,
        rr_max_req_per_sec_state: cfg.network.rr_max_req_per_sec_state,

        rr_max_bytes_per_sec_block: cfg.network.rr_max_bytes_per_sec_block,
        rr_max_bytes_per_sec_status: cfg.network.rr_max_bytes_per_sec_status,
        rr_max_bytes_per_sec_range: cfg.network.rr_max_bytes_per_sec_range,
        rr_max_bytes_per_sec_state: cfg.network.rr_max_bytes_per_sec_state,

        rr_global_in_bytes_per_sec: cfg.network.rr_global_in_bytes_per_sec,
        rr_global_out_bytes_per_sec: cfg.network.rr_global_out_bytes_per_sec,

        peer_strike_decay_s: cfg.network.peer_strike_decay_s,
        peer_score_decay_s: cfg.network.peer_score_decay_s,
        peer_quarantine_s: cfg.network.peer_quarantine_s,
        rr_strikes_before_quarantine: cfg.network.rr_strikes_before_quarantine,
        rr_strikes_before_ban: cfg.network.rr_strikes_before_ban,
        rr_quarantines_before_ban: cfg.network.rr_quarantines_before_ban,

        gs_max_publish_msgs_per_sec: cfg.network.gossipsub.max_publish_msgs_per_sec,
        gs_max_publish_bytes_per_sec: cfg.network.gossipsub.max_publish_bytes_per_sec,
        gs_max_in_msgs_per_sec: cfg.network.gossipsub.max_in_msgs_per_sec,
        gs_max_in_bytes_per_sec: cfg.network.gossipsub.max_in_bytes_per_sec,
        gs_allowed_topics: cfg.network.gossipsub.allowed_topics.clone(),
        gs_deny_unknown_topics: cfg.network.gossipsub.deny_unknown_topics,
        gs_topic_limits: cfg
            .network
            .gossipsub
            .topic_limits
            .iter()
            .map(|t| {
                (
                    t.topic.clone(),
                    t.max_in_msgs_per_sec,
                    t.max_in_bytes_per_sec,
                )
            })
            .collect(),

        diversity_bucket_kind: cfg.network.diversity.bucket_kind.clone(),
        max_inbound_per_bucket: cfg.network.diversity.max_inbound_per_bucket,
        max_outbound_per_bucket: cfg.network.diversity.max_outbound_per_bucket,
        eclipse_detection_min_buckets: cfg.network.diversity.eclipse_detection_min_buckets,
        reseed_cooldown_s: cfg.network.diversity.reseed_cooldown_s,

        quarantine_path: PathBuf::from(&cfg.node.data_dir).join("quarantine.json"),
        persist_quarantine: cfg.network.persist_quarantine,
    };
    let mut p2p = P2p::new(p2p_cfg)?;

    // Dial static peers immediately
    p2p.dial_static_peers();
    info!(
        count = static_peers.len(),
        bootnodes = bootnodes.len(),
        "dialing peers"
    );

    // Shared state
    let app = App {
        mempool: Arc::new(Mutex::new(Mempool::new(cfg.mempool.capacity))),
        kv_state: Arc::new(Mutex::new(engine.app_state.clone())),
        governance: Arc::new(Mutex::new(gov_state)),
        peers: Arc::new(Mutex::new(BTreeMap::new())),
        base_fee: Arc::new(Mutex::new(engine.base_fee_per_gas)),
        best_height: Arc::new(Mutex::new(store.best_height())),
        chain_id: cfg.node.chain_id,
        store: store.clone(),
        receipts: receipts.clone(),
        limiter: Arc::new(RpcLimiter::new()),
        metrics: prod_metrics.clone(),
        enable_faucet: cfg.rpc.enable_faucet,
        validator_info: Arc::new(Mutex::new(initial_vi)),
        uptime_tracker: Arc::new(Mutex::new(UptimeTracker::default())),
        staking_state: Arc::new(Mutex::new(StakingState::default())),
        economics_params: EconomicsParams::default(),
    };

    // RPC
    let rpc_addr: SocketAddr = cfg.rpc.listen.parse()?;
    let router = Router::new()
        .route("/health", get(health))
        .route("/metrics", get(prometheus_metrics))
        .route("/state", get(get_state))
        .route("/base_fee", get(get_base_fee))
        .route("/peers", get(get_peers))
        .route("/tx", post(post_tx))
        .route("/block/:height", get(get_block_by_height))
        .route("/receipt/:block_id", get(get_receipts))
        .route("/tx_location/:hash", get(get_tx_location))
        .route("/validators", get(get_validators))
        .route("/mempool/stats", get(mempool_stats))
        .route("/mempool", get(mempool_stats))
        .route("/governance", get(get_governance))
        .route("/staking", get(get_staking))
        .route("/vm/state", get(get_vm_state))
        .route("/vm/call", post(post_vm_call))
        .route("/faucet/:addr/:amount", post(faucet))
        .with_state(app.clone())
        // Middleware stack (innermost → outermost in request-processing order).
        // Layer order: last .layer() call = outermost (first to see the request).
        //
        //  json_depth  ← innermost: validate JSON depth before handler
        //  body_limit  ← check Content-Length header
        //  concurrency ← enforce global slot cap
        //  read_limit  ← per-IP rate limit on GET/HEAD (needs Extension below)
        //  Extension   ← injects Arc<RpcLimiter> for the above three
        //  header_size ← cheap header-block size check (no limiter needed)
        //  request_id  ← inject X-Request-ID for all downstream middleware
        //  CORS        ← outermost: handle preflight and CORS headers
        .layer(middleware::from_fn(json_depth_middleware))
        .layer(middleware::from_fn(body_limit_middleware))
        .layer(middleware::from_fn(concurrency_middleware))
        .layer(middleware::from_fn(read_limit_middleware))
        .layer(Extension(app.limiter.clone()))
        .layer(middleware::from_fn(header_size_middleware))
        .layer(middleware::from_fn(request_id_middleware))
        .layer({
            // CORS policy: permissive in dev (cors_allow_all=true), restrictive in prod.
            if cfg.rpc.cors_allow_all {
                CorsLayer::permissive()
            } else {
                // No cross-origin access by default.
                // Browsers won't send cross-origin requests without Access-Control-Allow-Origin.
                tower_http::cors::CorsLayer::new()
            }
        });

    tokio::spawn(async move {
        info!(%rpc_addr, "RPC listening");
        let listener = match tokio::net::TcpListener::bind(rpc_addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(%rpc_addr, "RPC bind failed: {e}");
                return;
            }
        };
        if let Err(e) = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        {
            tracing::error!("RPC server error: {e}");
        }
    });

    // Main event loop
    let mut last_tick = Instant::now();
    let mut last_status = Instant::now();
    let mut last_snapshot = Instant::now();
    let mut last_reconnect = Instant::now();
    let reconnect_interval = Duration::from_secs(cfg.network.reconnect_s);
    let snapshot_interval = Duration::from_secs(30);

    loop {
        tokio::select! {
                    event = p2p.next_event() => {
                        match event {
                            Ok(P2pEvent::Consensus { from, msg, raw }) => {
                                prod_metrics.msgs_received.inc();
                                let _ = wal.append(&WalEvent::Inbound { bytes: raw });
                                let mut ob = NodeOutbox {
                                    p2p: Some(&mut p2p),
                                    wal: &mut wal,
                                    store: store.clone(),
                                    receipts: receipts.clone(),
                                    dd: &dd,
                                    app: Some(app.clone()),
                                    metrics: Some(prod_metrics.clone()),
                                    snap: snap_plan,
                                    last_snap_height: 0,
                                    attest_pool: Some(attest_pool.clone()),
                                    attest_enabled: cfg.network.enable_snapshot_attestation,
                                    attest_threshold: cfg.network.snapshot_attestation_threshold,
                                    attest_collect_s: cfg.network.snapshot_attestation_collect_s,
                                };
                                if let Err(e) = engine.on_message(&signer, &*store, &mut ob, msg) {
                                    warn!(%from, "consensus: {e:?}");
                                }
                            }
                            Ok(P2pEvent::Request { from, req, channel }) => {
                                match req {
                                    Req::Status(_) => {
                                        let best = store.best_height();
                                        p2p.respond(channel, Resp::Status(StatusResponse {
                                            best_height: best,
                                            best_block_id: store.block_id_by_height(best),
                                        }));
                                    }
                                    Req::Block(br) => {
                                        p2p.respond(channel, Resp::Block(BlockResponse { block: store.get(&br.id) }));
                                    }
                                    Req::Range(rr) => {
                                        let mut blocks = Vec::new();
                                        // Cap to MAX_RANGE_BLOCKS blocks served
                                        let to_capped = rr.to.min(rr.from + iona::net::p2p::MAX_RANGE_BLOCKS - 1);
                                        for h in rr.from..=to_capped {
                                            if let Some(id) = store.block_id_by_height(h) {
                                                if let Some(b) = store.get(&id) { blocks.push(b); }
                                            }
                                        }
                                        prod_metrics.range_syncs.inc();
                                        p2p.respond(channel, Resp::Range(RangeResponse { blocks }));
                                    }
                                    Req::State(sreq) => {
                                        use iona::storage::snapshots;
                                        match sreq {

        iona::net::p2p::StateReq::Index(_) => {
            let hs = snapshots::list_snapshot_heights(&cfg.node.data_dir).unwrap_or_default();
            let edges = snapshots::list_delta_edges(&cfg.node.data_dir).unwrap_or_default();
            p2p.respond(channel, Resp::State(iona::net::p2p::StateResp::Index(
                iona::net::p2p::StateIndexResponse { snapshot_heights: hs, delta_edges: edges }
            )));
        }
        iona::net::p2p::StateReq::Attest(ar) => {
            // Only attest if we have the snapshot and the root matches.
            let ok = match snapshots::latest_snapshot_height(&cfg.node.data_dir) {
                Ok(Some(_)) => true,
                _ => false,
            };
            if ok {
                if let Ok(mani) = snapshots::read_snapshot_manifest(&cfg.node.data_dir, ar.height) {
                    if mani.state_root_hex == ar.state_root_hex {
                        // Sign canonical bytes.
                        let sb_res = if cfg.network.state_sync_security.bind_validator_set || cfg.network.state_sync_security.bind_epoch {
            let vsh = engine.vset.hash_hex();
            let epoch_len = cfg.network.state_sync_security.attestation_epoch_s.max(1);
            let now_s = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
            let epoch_nonce = now_s / epoch_len;
            snapshots::snapshot_attest_sign_bytes_v2(cfg.node.chain_id, ar.height, &ar.state_root_hex, &vsh, epoch_nonce)
        } else {
            snapshots::snapshot_attest_sign_bytes(ar.height, &ar.state_root_hex)
        };

        if let Ok(sb) = sb_res {

                            let sig = signer.sign(&sb).0;
                            let resp = iona::net::p2p::SnapshotAttestResponse {
                                height: ar.height,
                                state_root_hex: ar.state_root_hex.clone(),
                                pubkey_hex: hex::encode(signer.public_key().0.clone()),
                                sig_b64: base64::encode(sig),
                            };
                            p2p.respond(channel, Resp::State(iona::net::p2p::StateResp::Attest(resp)));
                            continue;
                        }
                    }
                }
            }
            // Fallback: respond with empty signature (caller will ignore).
            let resp = iona::net::p2p::SnapshotAttestResponse {
                height: ar.height,
                state_root_hex: ar.state_root_hex,
                pubkey_hex: hex::encode(signer.public_key().0.clone()),
                sig_b64: "".into(),
            };
            p2p.respond(channel, Resp::State(iona::net::p2p::StateResp::Attest(resp)));
        }
                                            iona::net::p2p::StateReq::Manifest(_) => {
                                                let mani = match snapshots::latest_snapshot_height(&cfg.node.data_dir) {
                                                    Ok(Some(h)) => {
                                                        // Build or load a cached statesync manifest with per-chunk hashes.
                                                        // Use the node's configured state-sync chunk size to keep chunk hashes consistent.
                                                        let cs = cfg.network.state_sync_chunk_bytes.max(1024) as u32;
                                                        match snapshots::load_or_build_statesync_manifest(&cfg.node.data_dir, h, cs) {
                                                            Ok(m) => {
                                                                let att = m.attestation.map(|a| iona::net::p2p::SnapshotAttestation {
                                                                    validators_hash_hex: a.validators_hash_hex,
                                                                    threshold: a.threshold,
                                                                    signatures: a.signatures.into_iter().map(|s| iona::net::p2p::AttestationSig { pubkey_hex: s.pubkey_hex, sig_base64: s.sig_base64 }).collect(),
                                                                });
                                                                iona::net::p2p::StateManifestResponse {
                                                                    height: m.height,
                                                                    total_bytes: m.total_bytes,
                                                                    blake3_hex: m.blake3_hex,
                                                                    chunk_size: m.chunk_size,
                                                                    chunk_hashes: m.chunk_hashes,
                                                                    state_root_hex: m.state_root_hex,
                                                                    attestation: att,
                                                                }
                                                            }
                                                            Err(_) => iona::net::p2p::StateManifestResponse { height: 0, total_bytes: 0, blake3_hex: "".into(), chunk_size: cs, chunk_hashes: vec![], state_root_hex: None, attestation: None },
                                                        }
                                                    }
                                                    _ => iona::net::p2p::StateManifestResponse { height: 0, total_bytes: 0, blake3_hex: "".into(), chunk_size: cfg.network.state_sync_chunk_bytes.max(1024) as u32, chunk_hashes: vec![], state_root_hex: None, attestation: None },
                                                };

                                                p2p.respond(channel, Resp::State(iona::net::p2p::StateResp::Manifest(mani)));
                                            }
                                            iona::net::p2p::StateReq::Chunk(c) => {
                                                let path = snapshots::snapshot_path(&cfg.node.data_dir, c.height);
                                                let mut out = iona::net::p2p::StateChunkResponse { offset: c.offset, data: vec![], done: true };
                                                if let Ok(mut f) = std::fs::File::open(&path) {
                                                    use std::io::{Read, Seek, SeekFrom};
                                                    let _ = f.seek(SeekFrom::Start(c.offset));
                                                    let mut buf = vec![0u8; c.len as usize];
                                                    match f.read(&mut buf) {
                                                        Ok(n) => {
                                                            buf.truncate(n);
                                                            out.data = buf;
                                                            out.done = n == 0 || (c.offset + n as u64) >= f.metadata().map(|m| m.len()).unwrap_or(0);
                                                        }
                                                        Err(_) => {}
                                                    }
                                                }
                                                p2p.respond(channel, Resp::State(iona::net::p2p::StateResp::Chunk(out)));
                                            }

                                            iona::net::p2p::StateReq::DeltaManifest(dm) => {
                                                let mut out = iona::net::p2p::DeltaManifestResponse {
                                                    from_height: dm.from_height,
                                                    to_height: dm.to_height,
                                                    total_bytes: 0,
                                                    blake3_hex: "".into(),
                                                    chunk_size: cfg.network.state_sync_chunk_bytes.max(1024) as u32,
                                                    chunk_hashes: vec![],
                                                    to_state_root_hex: "".into(),
                                                };
                                                let mp = snapshots::delta_statesync_manifest_path(&cfg.node.data_dir, dm.from_height, dm.to_height);
                                                if let Ok(s) = std::fs::read_to_string(mp) {
                                                    if let Ok(m) = serde_json::from_str::<snapshots::DeltaSyncManifest>(&s) {
                                                        out.total_bytes = m.total_bytes;
                                                        out.blake3_hex = m.blake3_hex;
                                                        out.chunk_size = m.chunk_size;
                                                        out.chunk_hashes = m.chunk_hashes;
                                                        out.to_state_root_hex = m.to_state_root_hex;
                                                    }
                                                }
                                                p2p.respond(channel, Resp::State(iona::net::p2p::StateResp::DeltaManifest(out)));
                                            }

                                            iona::net::p2p::StateReq::DeltaChunk(dc) => {
                                                let path = snapshots::delta_path(&cfg.node.data_dir, dc.from_height, dc.to_height);
                                                let mut out = iona::net::p2p::DeltaChunkResponse { offset: dc.offset, data: vec![], done: true };
                                                if let Ok(mut f) = std::fs::File::open(&path) {
                                                    use std::io::{Read, Seek, SeekFrom};
                                                    let _ = f.seek(SeekFrom::Start(dc.offset));
                                                    let mut buf = vec![0u8; dc.len as usize];
                                                    match f.read(&mut buf) {
                                                        Ok(n) => {
                                                            buf.truncate(n);
                                                            out.data = buf;
                                                            out.done = n == 0 || (dc.offset + n as u64) >= f.metadata().map(|m| m.len()).unwrap_or(0);
                                                        }
                                                        Err(_) => {}
                                                    }
                                                }
                                                p2p.respond(channel, Resp::State(iona::net::p2p::StateResp::DeltaChunk(out)));
                                            }
                                        }
                                    }
                                }
                            }
                            Ok(P2pEvent::Response { resp, .. }) => {
                                match resp {
                                    Resp::Status(s) => {
                                        let local_best = store.best_height();
                                        if s.best_height > local_best + 1 {
                                            let from_h = local_best + 1;
                                            let to_h   = s.best_height.min(from_h + 200);
                                            if let Some(peer) = p2p.peers().first().cloned() {
                                                p2p.request_range(peer, from_h, to_h);
                                            }
                                        }
                                    }
                                    Resp::Block(br) => {
                                        if let Some(block) = br.block {
                                            store.put(block.clone());
                                            let mut ob = NodeOutbox {
                                                p2p: Some(&mut p2p),
                                                wal: &mut wal,
                                                store: store.clone(),
                                                receipts: receipts.clone(),
                                                dd: &dd,
                                                app: Some(app.clone()),
                                                metrics: Some(prod_metrics.clone()),
                                                snap: snap_plan,
                                                last_snap_height: 0,
                                                attest_pool: Some(attest_pool.clone()),
                                                attest_enabled: cfg.network.enable_snapshot_attestation,
                                                attest_threshold: cfg.network.snapshot_attestation_threshold,
                                                attest_collect_s: cfg.network.snapshot_attestation_collect_s,
                                            };
                                            let _ = engine.on_block_received(&signer, &*store, &mut ob, block);
                                        }
                                    }
                                    Resp::Range(rr) => {
                                        // Validate: cap count, ensure sequential heights, basic sanity
                                        let max = iona::net::p2p::MAX_RANGE_BLOCKS as usize;
                                        let blocks = rr.blocks;
                                        if blocks.len() > max {
                                            warn!("range response too large: {} blocks (max {}), truncating", blocks.len(), max);
                                        }
                                        let mut prev_height: Option<u64> = None;
                                        for block in blocks.into_iter().take(max) {
                                            // Reject blocks out of sequence
                                            if let Some(ph) = prev_height {
                                                if block.header.height != ph + 1 {
                                                    warn!("range: non-sequential block height {} after {}, stopping", block.header.height, ph);
                                                    break;
                                                }
                                            }
                                            // Reject blocks we already have
                                            if store.block_id_by_height(block.header.height).is_some() {
                                                prev_height = Some(block.header.height);
                                                continue;
                                            }
                                            prev_height = Some(block.header.height);
                                            store.put(block);
                                        }
                                    }
                                    Resp::State(sr) => {
                                        // Snapshot attestation responses are aggregated here; other state-sync responses are handled
                                        // by the dedicated startup client.
                                        if let iona::net::p2p::StateResp::Attest(ar) = sr {
                                            if cfg.network.enable_snapshot_attestation {
                                                // Check if we are collecting for this height.
                                                let mut should_write: Option<iona::storage::snapshots::SnapshotAttestation> = None;
                                                {
                                                    let mut g = attest_pool.lock().unwrap();
                                                    if let Some(p) = g.pending.get_mut(&ar.height) {
                                                        // Time window
                                                        if p.created.elapsed().as_secs() <= p.collect_s {
                                                            // Verify root matches
                                                            if p.state_root_hex == ar.state_root_hex {
                                                                // Verify signature and validator membership
                                                                if let (Ok(pk), Ok(sig_bytes)) = (hex::decode(&ar.pubkey_hex), B64.decode(ar.sig_b64.as_bytes())) {
                                                                    let pkb = iona::crypto::PublicKeyBytes(pk);
                                                                    let sig = iona::crypto::SignatureBytes(sig_bytes);
                                                                    if vset.contains(&pkb) {
                                                                        if let Ok(msg) = iona::storage::snapshots::snapshot_attest_sign_bytes(ar.height, &ar.state_root_hex) {
                                                                            if iona::crypto::ed25519::Ed25519Verifier::verify(&pkb, &msg, &sig).is_ok() {
                                                                                p.sigs.entry(ar.pubkey_hex.clone()).or_insert(ar.sig_b64.clone());
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }

                                                        if (p.sigs.len() as u32) >= p.threshold {
                                                            // Build attestation for persistence.
                                                            let mut pubkeys_hex: Vec<String> = vset.vals.iter().map(|v| hex::encode(&v.pk.0)).collect();
                                                            pubkeys_hex.sort();
                                                            let vh = iona::storage::snapshots::validators_hash_hex(&pubkeys_hex);
                                                            let sigs = p.sigs.iter().map(|(k, v)| iona::storage::snapshots::AttestationSig { pubkey_hex: k.clone(), sig_base64: v.clone() }).collect();
                                                            should_write = Some(iona::storage::snapshots::SnapshotAttestation { validators_hash_hex: vh, threshold: p.threshold, signatures: sigs });
                                                        }
                                                    }
                                                }
                                                if let Some(a) = should_write {
                                                    // Persist and stop collecting.
                                                    let _ = iona::storage::snapshots::write_attestation(&cfg.node.data_dir, ar.height, &a);
                                                    let mut g = attest_pool.lock().unwrap();
                                                    g.pending.remove(&ar.height);
                                                    info!(height = ar.height, sigs = a.signatures.len(), "snapshot attestation aggregated");
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            Err(e) => { error!("p2p error: {e}"); }
                        }

                        self_sync(&app, &engine, &p2p, &prod_metrics).await;

                        if engine.state.decided.is_some() {
                            after_commit(&app, &mut engine, &signer, &mut p2p, &mut wal,
                                         &store, &receipts, &dd, &prod_metrics).await;
                        }
                    }

                    _ = tokio::time::sleep(Duration::from_millis(10)) => {
                        let now   = Instant::now();
                        let dt    = now.duration_since(last_tick);
                        last_tick = now;

                        // Periodic status poll
                        if now.duration_since(last_status) > Duration::from_secs(5) {
                            last_status = now;
                            let peers = p2p.peers();
                            if !peers.is_empty() { p2p.request_status(peers); }
                        }

                        // Periodic reconnect to static peers
                        if now.duration_since(last_reconnect) > reconnect_interval {
                            last_reconnect = now;
                            p2p.dial_static_peers();
                        }

                        // Periodic WAL snapshot
                        if now.duration_since(last_snapshot) > snapshot_interval {
                            last_snapshot = now;
                            let mirror = EngineMirror::from_engine(&engine);
                            if let Ok(bytes) = bincode::serialize(&mirror) {
                                let _ = wal.append(&WalEvent::Snapshot { bytes });
                            }
                        }

                        let mempool = app.mempool.clone();
                        let drain = move |n: usize| {
                            tokio::task::block_in_place(|| {
                                futures::executor::block_on(mempool.lock()).drain_best(n)
                            })
                        };
                        let mut ob = NodeOutbox {
                            p2p: Some(&mut p2p),
                            wal: &mut wal,
                            store: store.clone(),
                            receipts: receipts.clone(),
                            dd: &dd,
                            app: Some(app.clone()),
                            metrics: Some(prod_metrics.clone()),
                            snap: snap_plan,
                            last_snap_height: 0,
                            attest_pool: Some(attest_pool.clone()),
                            attest_enabled: cfg.network.enable_snapshot_attestation,
                            attest_threshold: cfg.network.snapshot_attestation_threshold,
                            attest_collect_s: cfg.network.snapshot_attestation_collect_s,
                        };

                        // ── Simple proposer hook (no votes here) ─────────────────────────────
                        // If it's our turn (round-robin) and we're in the Propose step, build + sign
                        // a Proposal and broadcast it. The consensus engine will still handle votes.
                        // ── Proposal + tick logic ──────────────────────────────────
                        // If simple_producer is enabled and it's our turn, the external
                        // producer builds the proposal BEFORE the engine tick.  The engine
                        // tick then sees proposal.is_some() and skips maybe_propose.
                        //
                        // If simple_producer is disabled (follower / rpc), we just let the
                        // engine tick handle everything — including maybe_propose which
                        // will build the block internally when it's our turn.
                        if cfg.consensus.simple_producer {
                            let can_propose = engine.state.step == iona::consensus::Step::Propose
                                && engine.state.proposal.is_none()
                                && engine.is_proposer(&signer.public_key());
                            if can_propose {
                                let txs = drain(engine.cfg.max_txs_per_block);
                                let _ = producer.try_produce(&mut engine, &signer, &*store, &mut ob, txs);
                                // Tick with empty drain — proposal already built.
                                engine.tick(&signer, &*store, &mut ob, dt.as_millis() as u64, |_| vec![]);
                            } else {
                                engine.tick(&signer, &*store, &mut ob, dt.as_millis() as u64, drain);
                            }
                        } else {
                            // Follower / RPC: let the engine handle everything.
                            // The engine's maybe_propose will use the drain if it's our turn.
                            engine.tick(&signer, &*store, &mut ob, dt.as_millis() as u64, drain);
                        }

                        self_sync(&app, &engine, &p2p, &prod_metrics).await;

                        if engine.state.decided.is_some() {
                            after_commit(&app, &mut engine, &signer, &mut p2p, &mut wal,
                                         &store, &receipts, &dd, &prod_metrics).await;
                        }
                    }

                    _ = tokio::signal::ctrl_c() => {
                        info!("shutdown");
                        dd.save_state_full(&engine.app_state)?;
                        dd.save_stakes(&engine.stakes)?;
                        if let Ok(bytes) = bincode::serialize(&EngineMirror::from_engine(&engine)) {
                            let _ = wal.append(&WalEvent::Snapshot { bytes });
                        }
                        break;
                    }
                }
    }
    Ok(())
}

// ── After-commit hook ─────────────────────────────────────────────────────

async fn after_commit(
    app: &App,
    engine: &mut Engine<Ed25519Verifier>,
    signer: &Ed25519Keypair,
    p2p: &mut P2p,
    wal: &mut Wal,
    store: &Arc<FsBlockStore>,
    receipts: &Arc<ReceiptsStore>,
    dd: &DataDir,
    metrics: &Arc<Metrics>,
) {
    let committed_height = engine.state.height;
    app.mempool.lock().await.advance_height(committed_height);

    // Update validator info for /validators endpoint
    let vi: Vec<ValidatorInfo> = engine
        .stakes
        .status_report()
        .into_iter()
        .map(|(pk, rec)| ValidatorInfo {
            address: hex::encode(&blake3::hash(&pk.0).as_bytes()[..20]),
            stake: rec.stake,
            slashed_total: rec.slashed_total,
            status: format!("{:?}", rec.status),
        })
        .collect();
    *app.validator_info.lock().await = vi;

    // ── Downtime tracking: record which validators signed this block ──────
    {
        // The precommits in the last committed cert tell us who signed
        let signers: Vec<iona::crypto::PublicKeyBytes> = if let Some(cert) = &engine.state.decided {
            cert.precommits.iter().map(|v| v.voter.clone()).collect()
        } else {
            vec![]
        };
        let all_validators: Vec<iona::crypto::PublicKeyBytes> =
            engine.vset.vals.iter().map(|v| v.pk.clone()).collect();

        let mut tracker = app.uptime_tracker.lock().await;
        tracker.record_block(committed_height, &signers, &all_validators);

        // Check for downtime violations and jail offenders
        let offenders = tracker.check_downtime(committed_height, &engine.stakes);
        for pk in offenders {
            engine.stakes.slash_downtime(&pk, committed_height);
            tracing::warn!(
                validator = %hex::encode(&pk.0),
                height = committed_height,
                "validator jailed for downtime"
            );
        }
    }

    // ── Epoch boundary: distribute PoS rewards ────────────────────────────
    if is_epoch_boundary(committed_height) {
        let mut staking = app.staking_state.lock().await;
        let reward = distribute_epoch_rewards(
            committed_height,
            &mut engine.app_state,
            &mut staking,
            &app.economics_params,
        );
        tracing::info!(
            epoch = reward.epoch,
            height = committed_height,
            minted = reward.inflation_minted,
            treasury = reward.treasury_share,
            "epoch reward distributed"
        );
    }

    engine.next_height(signer, &**store, &mut NoopOutbox);

    dd.save_state_full(&engine.app_state).ok();
    dd.save_stakes(&engine.stakes).ok();
}

// Sync shared state from engine
async fn self_sync(app: &App, engine: &Engine<Ed25519Verifier>, p2p: &P2p, metrics: &Arc<Metrics>) {
    *app.kv_state.lock().await = engine.app_state.clone();
    *app.base_fee.lock().await = engine.base_fee_per_gas;
    *app.best_height.lock().await = engine.state.height.saturating_sub(1);
    metrics.base_fee.set(engine.base_fee_per_gas as f64);
    metrics.consensus_height.set(engine.state.height as i64);
    metrics.p2p_peers.set(p2p.peer_count() as i64);
}

// ── RPC Handlers ──────────────────────────────────────────────────────────

async fn health(State(app): State<App>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "height": *app.best_height.lock().await,
        "mempool": app.mempool.lock().await.len(),
        "peers": app.peers.lock().await.len(),
        "chain_id": app.chain_id,
        "version": "24.1.0",
    }))
}

async fn prometheus_metrics() -> String {
    metrics::render()
}

async fn get_state(State(app): State<App>) -> Json<KvState> {
    Json(app.kv_state.lock().await.clone())
}

async fn get_base_fee(State(app): State<App>) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "base_fee_per_gas": *app.base_fee.lock().await }))
}

async fn get_peers(State(app): State<App>) -> Json<serde_json::Value> {
    Json(serde_json::json!(app.peers.lock().await.clone()))
}

async fn get_validators(State(app): State<App>) -> Json<serde_json::Value> {
    Json(serde_json::json!(app.validator_info.lock().await.clone()))
}

async fn mempool_stats(State(app): State<App>) -> Json<serde_json::Value> {
    let mp = app.mempool.lock().await;
    let m = &mp.metrics;
    Json(serde_json::json!({
        "size": mp.len(), "senders": mp.sender_count(),
        "admitted": m.admitted, "rejected_dup": m.rejected_dup,
        "rejected_full": m.rejected_full, "rejected_sender_limit": m.rejected_sender_limit,
        "evicted": m.evicted, "expired": m.expired, "rbf_replaced": m.rbf_replaced,
    }))
}

async fn get_governance(State(app): State<App>) -> Json<serde_json::Value> {
    let gov = app.governance.lock().await;
    let proposals: Vec<serde_json::Value> = gov.pending.values().map(|p| {
        serde_json::json!({
            "id": gov.pending.iter().find(|(_, v)| std::ptr::eq(*v, p)).map(|(k, _)| *k).unwrap_or(0),
            "action": format!("{:?}", p.action),
            "proposer": p.proposer,
            "height": p.height,
            "votes": p.votes,
        })
    }).collect();
    let params: serde_json::Value = serde_json::to_value(&gov.params).unwrap_or_default();
    Json(serde_json::json!({
        "pending_proposals": proposals,
        "next_id": gov.next_id,
        "params": params,
    }))
}

async fn get_staking(State(app): State<App>) -> Json<serde_json::Value> {
    let staking = app.staking_state.lock().await;
    let params = &app.economics_params;

    let validators: Vec<serde_json::Value> = staking
        .validators
        .iter()
        .map(|(addr, v)| {
            serde_json::json!({
                "address": addr,
                "stake": v.stake,
                "jailed": v.jailed,
                "commission_bps": v.commission_bps,
                "commission_pct": v.commission_bps as f64 / 100.0,
            })
        })
        .collect();

    let delegations: Vec<serde_json::Value> = staking
        .delegations
        .iter()
        .map(|((delegator, validator), &amount)| {
            serde_json::json!({
                "delegator": delegator,
                "validator": validator,
                "amount": amount,
            })
        })
        .collect();

    let unbonding: Vec<serde_json::Value> = staking
        .unbonding
        .iter()
        .map(|((delegator, validator), &(amount, unlock_epoch))| {
            serde_json::json!({
                "delegator": delegator,
                "validator": validator,
                "amount": amount,
                "unlock_epoch": unlock_epoch,
            })
        })
        .collect();

    let total_staked: u128 = staking
        .validators
        .values()
        .filter(|v| !v.jailed)
        .map(|v| v.stake)
        .sum();

    Json(serde_json::json!({
        "validators": validators,
        "delegations": delegations,
        "unbonding": unbonding,
        "total_staked": total_staked,
        "params": {
            "base_inflation_bps": params.base_inflation_bps,
            "min_stake": params.min_stake,
            "unbonding_epochs": params.unbonding_epochs,
            "treasury_bps": params.treasury_bps,
            "slash_double_sign_bps": params.slash_double_sign_bps,
            "slash_downtime_bps": params.slash_downtime_bps,
        }
    }))
}

async fn get_block_by_height(
    State(app): State<App>,
    Path(height): Path<u64>,
) -> Json<serde_json::Value> {
    if let Some(id) = app.store.block_id_by_height(height) {
        if let Some(b) = app.store.get(&id) {
            return Json(
                serde_json::json!({ "height": height, "id": hex::encode(id.0), "block": b }),
            );
        }
    }
    Json(serde_json::json!({ "error": "not found" }))
}

async fn get_receipts(
    State(app): State<App>,
    Path(block_id_hex): Path<String>,
) -> Json<serde_json::Value> {
    let bytes = match hex::decode(&block_id_hex) {
        Ok(b) if b.len() == 32 => b,
        _ => return Json(serde_json::json!({ "error": "bad block id" })),
    };
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let id = Hash32(arr);
    match app.receipts.get(&id) {
        Ok(Some(r)) => Json(serde_json::json!({ "block_id": hex::encode(id.0), "receipts": r })),
        Ok(None) => Json(serde_json::json!({ "error": "not found" })),
        Err(e) => Json(serde_json::json!({ "error": e.to_string() })),
    }
}

/// NEW: Look up which block contains a transaction by its hash.
async fn get_tx_location(
    State(app): State<App>,
    Path(hash_hex): Path<String>,
) -> Json<serde_json::Value> {
    let bytes = match hex::decode(&hash_hex) {
        Ok(b) if b.len() == 32 => b,
        _ => return Json(serde_json::json!({ "error": "bad tx hash" })),
    };
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let hash = Hash32(arr);
    match app.store.tx_location(&hash) {
        Some(loc) => Json(serde_json::json!({
            "tx_hash":      hash_hex,
            "block_height": loc.block_height,
            "block_id":     loc.block_id,
            "tx_index":     loc.tx_index,
        })),
        None => Json(serde_json::json!({ "error": "tx not found" })),
    }
}

#[derive(serde::Deserialize)]
struct TxReq {
    pubkey_hex: String,
    nonce: u64,
    max_fee_per_gas: u64,
    max_priority_fee_per_gas: u64,
    gas_limit: u64,
    payload: String,
    signature_b64: String,
    chain_id: u64,
}

async fn post_tx(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(app): State<App>,
    Json(req): Json<TxReq>,
) -> Json<serde_json::Value> {
    app.metrics.rpc_requests.inc();

    let req_id = new_request_id();
    match app.limiter.check_submit(addr.ip(), &req_id) {
        RpcLimitResult::Allowed => {}
        _ => {
            app.metrics.rpc_errors.inc();
            return Json(serde_json::json!({ "ok": false, "error": "rate limit exceeded" }));
        }
    }

    let pubkey = match hex::decode(&req.pubkey_hex) {
        Ok(x) => x,
        Err(_) => return Json(serde_json::json!({ "ok": false, "error": "bad pubkey_hex" })),
    };
    let signature = match base64::decode(&req.signature_b64) {
        Ok(x) => x,
        Err(_) => return Json(serde_json::json!({ "ok": false, "error": "bad signature_b64" })),
    };
    let from = derive_address(&pubkey);

    let tx = Tx {
        pubkey,
        from: from.clone(),
        nonce: req.nonce,
        max_fee_per_gas: req.max_fee_per_gas,
        max_priority_fee_per_gas: req.max_priority_fee_per_gas,
        gas_limit: req.gas_limit,
        payload: req.payload.clone(),
        signature,
        chain_id: req.chain_id,
    };

    let sender_nonce = *app.kv_state.lock().await.nonces.get(&from).unwrap_or(&0);
    if let Err(e) = validate_tx(&tx, app.chain_id, sender_nonce) {
        app.metrics.rpc_errors.inc();
        return Json(serde_json::json!({ "ok": false, "error": e.to_string() }));
    }

    // Route governance payloads
    if let Some(gov_action) = parse_gov_payload(&req.payload, &from, 0) {
        let mut gov = app.governance.lock().await;
        match gov_action {
            GovPayloadAction::Submit(action) => {
                let id = gov.submit(action, from, 0);
                return Json(serde_json::json!({ "ok": true, "gov_proposal_id": id }));
            }
            GovPayloadAction::Vote { id, voter, yes } => {
                let ok = gov.vote(id, voter, yes);
                return Json(serde_json::json!({ "ok": ok, "gov_proposal_id": id }));
            }
        }
    }

    let current_base_fee = *app.base_fee.lock().await;
    let mut mp = app.mempool.lock().await;
    match mp.push_with_base_fee(tx, current_base_fee) {
        Ok(_) => {
            app.metrics.rpc_tx_submitted.inc();
            Json(serde_json::json!({ "ok": true, "mempool_len": mp.len() }))
        }
        Err(e) => {
            app.metrics.rpc_errors.inc();
            Json(serde_json::json!({ "ok": false, "error": e }))
        }
    }
}

async fn faucet(
    State(app): State<App>,
    Path((addr, amount)): Path<(String, u64)>,
) -> Json<serde_json::Value> {
    if !app.enable_faucet {
        return Json(
            serde_json::json!({ "ok": false, "error": "faucet disabled; use --enable-faucet for testnets" }),
        );
    }
    let mut st = app.kv_state.lock().await;
    let cur = *st.balances.get(&addr).unwrap_or(&0);
    st.balances.insert(addr.clone(), cur.saturating_add(amount));
    Json(serde_json::json!({ "ok": true, "addr": addr, "balance": st.balances[&addr] }))
}

// ── VM endpoints ──────────────────────────────────────────────────────────

/// GET /vm/state — returns all deployed contracts and their storage slot counts.
async fn get_vm_state(State(app): State<App>) -> Json<serde_json::Value> {
    let st = app.kv_state.lock().await;
    let contracts: Vec<serde_json::Value> = st
        .vm
        .code
        .iter()
        .map(|(addr, code)| {
            let slot_count = st
                .vm
                .storage
                .range((*addr, [0u8; 32])..=(*addr, [0xFFu8; 32]))
                .count();
            serde_json::json!({
                "address":    hex::encode(addr),
                "code_bytes": code.len(),
                "storage_slots": slot_count,
            })
        })
        .collect();

    Json(serde_json::json!({
        "contracts": contracts,
        "total": contracts.len(),
    }))
}

/// POST /vm/call — execute a read-only (view) call against a deployed contract.
/// Does NOT commit state changes. Useful for querying contract state.
///
/// Body: { "caller": "hex32", "contract": "hex32", "calldata": "hex", "gas_limit": 100000 }
async fn post_vm_call(
    State(app): State<App>,
    axum::extract::Json(body): axum::extract::Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    use iona::execution::vm_executor::vm_call;

    let parse_hex32 = |s: &str| -> Option<[u8; 32]> {
        let raw = hex::decode(s.trim_start_matches("0x")).ok()?;
        if raw.len() > 32 {
            return None;
        }
        let mut b = [0u8; 32];
        b[32 - raw.len()..].copy_from_slice(&raw);
        Some(b)
    };

    let caller_str = body
        .get("caller")
        .and_then(|v| v.as_str())
        .unwrap_or("0000000000000000000000000000000000000000000000000000000000000000");
    let contract_str = match body.get("contract").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => {
            return Json(serde_json::json!({ "ok": false, "error": "missing 'contract' field" }))
        }
    };
    let calldata_str = body.get("calldata").and_then(|v| v.as_str()).unwrap_or("");
    let gas_limit = body
        .get("gas_limit")
        .and_then(|v| v.as_u64())
        .unwrap_or(100_000);

    // Basic anti-DoS limits
    const MAX_CALLDATA_BYTES: usize = 64 * 1024;
    const VM_CALL_TIMEOUT_MS: u64 = 200;

    let caller = match parse_hex32(caller_str) {
        Some(b) => b,
        None => return Json(serde_json::json!({ "ok": false, "error": "invalid caller hex" })),
    };
    let contract = match parse_hex32(contract_str) {
        Some(b) => b,
        None => return Json(serde_json::json!({ "ok": false, "error": "invalid contract hex" })),
    };
    let calldata = hex::decode(calldata_str.trim_start_matches("0x")).unwrap_or_default();
    if calldata.len() > MAX_CALLDATA_BYTES {
        return Json(serde_json::json!({ "ok": false, "error": "calldata too large" }));
    }

    // Clone state for read-only simulation (don't commit)
    let mut st = app.kv_state.lock().await.clone();
    let result = match tokio::time::timeout(
        std::time::Duration::from_millis(VM_CALL_TIMEOUT_MS),
        async { vm_call(&mut st, &caller, &contract, &calldata, gas_limit) },
    )
    .await
    {
        Ok(r) => r,
        Err(_) => {
            return Json(serde_json::json!({ "ok": false, "error": "vm call timeout" }));
        }
    };

    Json(serde_json::json!({
        "ok":          result.success,
        "reverted":    result.reverted,
        "gas_used":    result.gas_used,
        "return_data": hex::encode(&result.return_data),
        "logs":        result.logs.len(),
        "error":       result.error,
    }))
}

// ── Engine mirror ─────────────────────────────────────────────────────────

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct EngineMirror {
    cfg: iona::consensus::Config,
    vset: ValidatorSet,
    state: iona::consensus::ConsensusState,
    prev_block_id: Hash32,
    app_state: KvState,
    stakes: StakeLedger,
    base_fee_per_gas: u64,
}

impl EngineMirror {
    fn from_engine(e: &Engine<Ed25519Verifier>) -> Self {
        Self {
            cfg: e.cfg.clone(),
            vset: e.vset.clone(),
            state: e.state.clone(),
            prev_block_id: e.prev_block_id.clone(),
            app_state: e.app_state.clone(),
            stakes: e.stakes.clone(),
            base_fee_per_gas: e.base_fee_per_gas,
        }
    }
    fn into_engine(self, ds_guard: Option<DoubleSignGuard>) -> Engine<Ed25519Verifier> {
        let mut e = Engine::new(
            self.cfg.clone(),
            self.vset.clone(),
            self.state.height,
            self.prev_block_id.clone(),
            self.app_state.clone(),
            self.stakes.clone(),
            ds_guard,
        );
        e.state = self.state;
        e.base_fee_per_gas = self.base_fee_per_gas;
        e
    }
}

// ── Outbox ────────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
struct SnapshotPlan {
    enabled: bool,
    every_n_blocks: u64,
    keep: usize,
    zstd_level: i32,
}

impl SnapshotPlan {
    fn from_cfg(cfg: &iona::config::StorageSection) -> Self {
        Self {
            enabled: cfg.enable_snapshots,
            every_n_blocks: cfg.snapshot_every_n_blocks,
            keep: cfg.snapshot_keep,
            zstd_level: cfg.snapshot_zstd_level,
        }
    }
}

// ── Snapshot attestation aggregation (threshold) ─────────────────────────

#[derive(Default)]
struct AttestPool {
    pending: std::collections::HashMap<u64, PendingAttest>,
}

struct PendingAttest {
    state_root_hex: String,
    threshold: u32,
    // pubkey_hex -> sig_b64
    sigs: std::collections::HashMap<String, String>,
    created: std::time::Instant,
    collect_s: u64,
}

struct NodeOutbox<'a> {
    p2p: Option<&'a mut P2p>,
    wal: &'a mut Wal,
    store: Arc<FsBlockStore>,
    receipts: Arc<ReceiptsStore>,
    dd: &'a DataDir,
    app: Option<App>,
    metrics: Option<Arc<Metrics>>,
    snap: SnapshotPlan,
    last_snap_height: u64,
    attest_pool: Option<Arc<StdMutex<AttestPool>>>,
    attest_enabled: bool,
    attest_threshold: u32,
    attest_collect_s: u64,
}

impl<'a> NodeOutbox<'a> {
    fn new(
        p2p: Option<&'a mut P2p>,
        wal: &'a mut Wal,
        store: Arc<FsBlockStore>,
        receipts: Arc<ReceiptsStore>,
        dd: &'a DataDir,
        app: Option<App>,
        metrics: Option<Arc<Metrics>>,
        snap: SnapshotPlan,
        attest_pool: Option<Arc<StdMutex<AttestPool>>>,
        attest_enabled: bool,
        attest_threshold: u32,
        attest_collect_s: u64,
    ) -> Self {
        Self {
            p2p,
            wal,
            store,
            receipts,
            dd,
            app,
            metrics,
            snap,
            last_snap_height: 0,
            attest_pool,
            attest_enabled,
            attest_threshold,
            attest_collect_s,
        }
    }
}

impl<'a> OutboxTrait for NodeOutbox<'a> {
    fn broadcast(&mut self, msg: iona::consensus::ConsensusMsg) {
        if let Ok(bytes) = bincode::serialize(&msg) {
            match self.wal.append(&WalEvent::Outbound { bytes }) {
                Ok(_) => {
                    if let Some(m) = &self.metrics {
                        m.wal_writes.inc();
                        m.msgs_broadcast.inc();
                    }
                }
                Err(_) => {
                    if let Some(m) = &self.metrics {
                        m.wal_write_errors.inc();
                    }
                }
            }
        }
        if let Some(p) = self.p2p.as_mut() {
            p.publish(&msg);
        }
    }

    fn request_block(&mut self, block_id: Hash32) {
        if let Some(m) = &self.metrics {
            m.block_requests.inc();
        }
        if let Some(p) = self.p2p.as_mut() {
            p.request_block(p.peers(), block_id);
        }
    }

    fn on_commit(
        &mut self,
        cert: &iona::consensus::CommitCertificate,
        block: &iona::types::Block,
        new_state: &KvState,
        new_base_fee: u64,
        receipts: &[iona::types::Receipt],
    ) {
        if let Err(e) = self.dd.save_state_full(new_state) {
            error!("state save: {e}");
        }
        // Periodic compressed snapshots for fast recovery / fast sync.
        if self.snap.enabled && self.snap.every_n_blocks > 0 {
            if cert.height % self.snap.every_n_blocks == 0 && cert.height != self.last_snap_height {
                let prev_h = iona::storage::snapshots::latest_snapshot_height(&self.dd.root)
                    .ok()
                    .flatten();
                match iona::storage::snapshots::write_snapshot(
                    &self.dd.root,
                    cert.height,
                    new_state,
                    self.snap.zstd_level,
                ) {
                    Ok(_) => {
                        let _ = iona::storage::snapshots::prune_snapshots(
                            &self.dd.root,
                            self.snap.keep,
                        );

                        // Delta snapshots: if we have a previous snapshot, write a delta from prev->current.
                        if let Some(ph) = prev_h {
                            if ph < cert.height {
                                match iona::storage::snapshots::read_snapshot_state(
                                    &self.dd.root,
                                    ph,
                                ) {
                                    Ok(old) => {
                                        let _ = iona::storage::snapshots::write_delta(
                                            &self.dd.root,
                                            ph,
                                            cert.height,
                                            &old,
                                            new_state,
                                            self.snap.zstd_level,
                                            1_048_576,
                                        );
                                    }
                                    Err(e) => warn!("delta base snapshot read failed: {e}"),
                                }
                            }
                        }

                        self.last_snap_height = cert.height;
                        info!(height = cert.height, "snapshot written");

                        // Start attestation collection for this snapshot (threshold). We request signatures from peers
                        // and aggregate responses in the main event loop.
                        if self.attest_enabled {
                            if let Some(pool) = &self.attest_pool {
                                let mut g = pool.lock().unwrap();
                                g.pending.insert(
                                    cert.height,
                                    PendingAttest {
                                        state_root_hex: hex::encode(new_state.root().0),
                                        threshold: self.attest_threshold.max(1),
                                        sigs: std::collections::HashMap::new(),
                                        created: std::time::Instant::now(),
                                        collect_s: self.attest_collect_s.max(3),
                                    },
                                );
                            }
                            if let Some(p) = self.p2p.as_mut() {
                                let root_hex = hex::encode(new_state.root().0);
                                for peer in p.peers() {
                                    p.request_snapshot_attest(peer, cert.height, root_hex.clone());
                                }
                            }
                        }
                    }
                    Err(e) => warn!("snapshot write failed: {e}"),
                }
            }
        }

        self.store.put(block.clone());
        if let Err(e) = self.receipts.put(&cert.block_id, receipts) {
            error!("receipts save: {e}");
        }
        let _ = self.wal.append(&WalEvent::Note {
            msg: format!(
                "commit height={} block={}",
                cert.height,
                hex::encode(cert.block_id.0)
            ),
        });
        if let Some(app) = self.app.clone() {
            let bf = app.base_fee.clone();
            tokio::spawn(async move {
                *bf.lock().await = new_base_fee;
            });
        }
        if let Some(m) = &self.metrics {
            m.blocks_committed.inc();
            m.state_saves.inc();
            m.txs_per_block.observe(block.txs.len() as f64);
            m.gas_per_block.observe(block.header.gas_used as f64);
            m.base_fee.set(new_base_fee as f64);
        }
        info!(
            height = cert.height,
            txs = block.txs.len(),
            gas = block.header.gas_used,
            base_fee = new_base_fee,
            "committed"
        );
    }
}