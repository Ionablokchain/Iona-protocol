//! TOML configuration file support for IONA v24.
//!
//! Config file is loaded from --config path (default: ./config.toml).
//! CLI flags override config file values.
//! Environment variables (IONA_*) override both.

pub mod validation;

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NodeConfig {
    #[serde(default)]
    pub node: NodeSection,
    #[serde(default)]
    pub consensus: ConsensusSection,
    #[serde(default)]
    pub network: NetworkSection,
    #[serde(default)]
    pub mempool: MempoolSection,
    #[serde(default)]
    pub rpc: RpcSection,
    #[serde(default)]
    pub admin: AdminSection,
    #[serde(default)]
    pub signing: SigningSection,
    #[serde(default)]
    pub storage: StorageSection,
    #[serde(default)]
    pub observability: ObservabilitySection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeSection {
    pub data_dir: String,
    pub seed: u64,
    pub chain_id: u64,
    pub log_level: String,
    /// Key storage mode: "plain" (keys.json) or "encrypted" (keys.enc)
    pub keystore: String,
    /// Keystore password (plaintext in config). Used as fallback when env var is not set.
    #[serde(default)]
    pub keystore_password: String,
    /// Environment variable name holding the keystore password when keystore=encrypted.
    /// If the env var is set, it takes precedence over `keystore_password`.
    pub keystore_password_env: String,
}

impl Default for NodeSection {
    fn default() -> Self {
        Self {
            data_dir: "./data/node".into(),
            seed: 1,
            chain_id: 1,
            log_level: "info".into(),
            keystore: "plain".into(),
            keystore_password: String::new(),
            keystore_password_env: "IONA_KEYSTORE_PASSWORD".into(),
        }
    }
}

fn default_validator_seeds() -> Vec<u64> {
    vec![2, 3, 4]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusSection {
    pub propose_timeout_ms: u64,
    pub prevote_timeout_ms: u64,
    pub precommit_timeout_ms: u64,
    pub max_txs_per_block: usize,
    pub gas_target: u64,
    pub fast_quorum: bool,
    pub initial_base_fee: u64,
    pub stake_each: u64,
    /// Enable the Simple PoS block producer (round-robin propose + sign + broadcast)
    pub simple_producer: bool,
    /// Seeds of the validators that participate in consensus.
    /// Must match across all nodes for consensus to work.
    /// Default: [2, 3, 4] (the three producers in the standard topology).
    #[serde(default = "default_validator_seeds")]
    pub validator_seeds: Vec<u64>,
    /// Protocol upgrade activation schedule.
    /// Each entry specifies a protocol version and the height at which it activates.
    /// Used for coordinated hard-fork upgrades.
    #[serde(default = "default_activations")]
    pub protocol_activations: Vec<crate::protocol::version::ProtocolActivation>,
}

fn default_activations() -> Vec<crate::protocol::version::ProtocolActivation> {
    crate::protocol::version::default_activations()
}

fn default_eclipse_profile() -> String {
    "testnet".into()
}

impl Default for ConsensusSection {
    fn default() -> Self {
        Self {
            propose_timeout_ms: 300,
            prevote_timeout_ms: 200,
            precommit_timeout_ms: 200,
            max_txs_per_block: 4096,
            gas_target: 43_000_000,
            fast_quorum: true,
            initial_base_fee: 1,
            stake_each: 1000,
            simple_producer: true,
            validator_seeds: default_validator_seeds(),
            protocol_activations: default_activations(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkSection {
    pub listen: String,
    /// Static peer multiaddresses (e.g. ["/ip4/1.2.3.4/tcp/7001"])
    pub peers: Vec<String>,
    /// Optional bootstrap peers (may include /p2p/<peerid> for Kademlia)
    pub bootnodes: Vec<String>,
    /// Enable LAN peer discovery via mDNS
    pub enable_mdns: bool,
    /// Enable Kademlia DHT (optional)
    pub enable_kad: bool,
    pub reconnect_s: u64,

    /// Connection limits (anti-DoS)
    pub max_connections_total: usize,
    pub max_connections_per_peer: usize,

    /// Request-response rate limits (global and per-protocol)
    pub rr_max_req_per_sec: u32,
    pub rr_strikes_before_ban: u32,

    /// Per-protocol request rate limits (requests/sec)
    pub rr_max_req_per_sec_block: u32,
    pub rr_max_req_per_sec_status: u32,
    pub rr_max_req_per_sec_range: u32,
    pub rr_max_req_per_sec_state: u32,

    /// Per-protocol inbound bandwidth caps (bytes/sec) for request-response messages
    pub rr_max_bytes_per_sec_block: u32,
    pub rr_max_bytes_per_sec_status: u32,
    pub rr_max_bytes_per_sec_range: u32,
    pub rr_max_bytes_per_sec_state: u32,

    /// Global inbound/outbound bandwidth caps (bytes/sec) for request-response
    pub rr_global_in_bytes_per_sec: u32,
    pub rr_global_out_bytes_per_sec: u32,

    /// Strike/score decay + quarantine thresholds
    pub peer_strike_decay_s: u64,
    /// Peer score decay interval (seconds). Moves score toward 0 over time.
    pub peer_score_decay_s: u64,
    pub peer_quarantine_s: u64,
    pub rr_strikes_before_quarantine: u32,
    pub rr_quarantines_before_ban: u32,

    /// Persist quarantine list to disk so it survives restarts
    pub persist_quarantine: bool,

    /// Gossipsub limits + ACL
    pub gossipsub: GossipsubSection,

    /// Peer diversity / eclipse resistance
    pub diversity: DiversitySection,

    /// Eclipse protection profile: "prod" (strict) or "testnet" (relaxed).
    /// Overrides diversity defaults when set.
    #[serde(default = "default_eclipse_profile")]
    pub eclipse_profile: String,

    /// State sync knobs
    pub enable_p2p_state_sync: bool,
    /// Chunk size for P2P state sync transfers (bytes)
    pub state_sync_chunk_bytes: u32,
    /// Timeout for a single state-sync request (seconds)
    pub state_sync_timeout_s: u64,

    /// Snapshot attestation collection/serving.
    pub enable_snapshot_attestation: bool,
    /// Required signatures for an aggregated attestation (threshold).
    pub snapshot_attestation_threshold: u32,
    /// How long (seconds) to collect attestations after creating a snapshot.
    pub snapshot_attestation_collect_s: u64,

    /// State-sync security bindings (validator-set/epoch/nonce)
    pub state_sync_security: StateSyncSecuritySection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DiversitySection {
    pub bucket_kind: String, // ip16 | ip24 | asn (asn is scaffold only)
    pub max_inbound_per_bucket: usize,
    pub max_outbound_per_bucket: usize,
    pub eclipse_detection_min_buckets: usize,
    pub reseed_cooldown_s: u64,
}

impl Default for DiversitySection {
    fn default() -> Self {
        Self {
            bucket_kind: "ip16".into(),
            max_inbound_per_bucket: 4,
            max_outbound_per_bucket: 4,
            eclipse_detection_min_buckets: 3,
            reseed_cooldown_s: 60,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct TopicLimit {
    pub topic: String,
    pub max_in_msgs_per_sec: u32,
    pub max_in_bytes_per_sec: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GossipsubSection {
    pub allowed_topics: Vec<String>,
    pub deny_unknown_topics: bool,

    /// local publish caps
    pub max_publish_msgs_per_sec: u32,
    pub max_publish_bytes_per_sec: u32,

    /// inbound per-peer caps
    pub max_in_msgs_per_sec: u32,
    pub max_in_bytes_per_sec: u32,

    /// optional per-topic overrides
    pub topic_limits: Vec<TopicLimit>,
}

impl Default for GossipsubSection {
    fn default() -> Self {
        Self {
            allowed_topics: vec![
                "iona/tx".into(),
                "iona/blocks".into(),
                "iona/evidence".into(),
            ],
            deny_unknown_topics: true,
            max_publish_msgs_per_sec: 30,
            max_publish_bytes_per_sec: 2_000_000,
            max_in_msgs_per_sec: 60,
            max_in_bytes_per_sec: 4_000_000,
            topic_limits: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StateSyncSecuritySection {
    pub bind_validator_set: bool,
    pub bind_epoch: bool,
    pub attestation_epoch_s: u64,
    pub require_attestation: bool,
    pub use_aggregated_signatures: bool,
}

impl Default for StateSyncSecuritySection {
    fn default() -> Self {
        Self {
            bind_validator_set: true,
            bind_epoch: true,
            attestation_epoch_s: 60,
            require_attestation: false,
            use_aggregated_signatures: false,
        }
    }
}

impl Default for NetworkSection {
    fn default() -> Self {
        Self {
            listen: "/ip4/0.0.0.0/tcp/7001".into(),
            peers: vec![],
            bootnodes: vec![],
            enable_mdns: false,
            enable_kad: true,
            reconnect_s: 30,

            max_connections_total: 200,
            max_connections_per_peer: 8,

            rr_max_req_per_sec: 25,
            rr_strikes_before_ban: 3,

            rr_max_req_per_sec_block: 15,
            rr_max_req_per_sec_status: 30,
            rr_max_req_per_sec_range: 5,
            rr_max_req_per_sec_state: 10,

            rr_max_bytes_per_sec_block: 2_000_000,
            rr_max_bytes_per_sec_status: 200_000,
            rr_max_bytes_per_sec_range: 4_000_000,
            rr_max_bytes_per_sec_state: 8_000_000,

            rr_global_in_bytes_per_sec: 10_000_000,
            rr_global_out_bytes_per_sec: 10_000_000,

            peer_strike_decay_s: 30,
            peer_score_decay_s: 60,
            peer_quarantine_s: 60,
            rr_strikes_before_quarantine: 2,
            rr_quarantines_before_ban: 2,

            persist_quarantine: true,

            gossipsub: GossipsubSection::default(),
            diversity: DiversitySection::default(),

            eclipse_profile: default_eclipse_profile(),

            enable_p2p_state_sync: true,
            state_sync_chunk_bytes: 1_048_576, // 1 MiB
            state_sync_timeout_s: 10,

            enable_snapshot_attestation: true,
            snapshot_attestation_threshold: 2,
            snapshot_attestation_collect_s: 8,

            state_sync_security: StateSyncSecuritySection::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolSection {
    pub capacity: usize,
}

impl Default for MempoolSection {
    fn default() -> Self {
        Self { capacity: 200_000 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RpcSection {
    /// Socket address the RPC server binds to.
    /// Default: 127.0.0.1:9001 (loopback-only, secure).
    /// To expose publicly you MUST also pass --unsafe-rpc-public at startup.
    pub listen: String,
    /// Enable the /faucet endpoint. TESTNET ONLY.
    pub enable_faucet: bool,
    /// Allow cross-origin requests (CORS permissive mode).
    /// false = restrictive (default, production-safe).
    /// true  = allow-all (dev/testnet UI only).
    pub cors_allow_all: bool,
}

impl Default for RpcSection {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:9001".into(),
            enable_faucet: false,
            cors_allow_all: false,
        }
    }
}

/// Admin server configuration — mTLS + RBAC.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AdminSection {
    /// Admin server bind address. Loopback-only by default.
    /// Use a Unix socket or localhost:port; never bind to 0.0.0.0 in production.
    pub listen: String,
    /// Path to the RBAC policy file (rbac.toml).
    pub rbac_path: String,
    /// If true, require mTLS client certificates for all admin requests.
    /// Set to false ONLY for dev/test environments.
    pub require_mtls: bool,
    /// TLS server cert PEM for the admin socket (mTLS server side).
    pub tls_cert_pem: String,
    /// TLS server key PEM for the admin socket.
    pub tls_key_pem: String,
    /// CA cert PEM used to verify client certificates.
    pub tls_ca_cert_pem: String,
    /// Path for the append-only tamper-evident audit log.
    pub audit_log_path: String,
}

impl Default for AdminSection {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:9002".into(),
            rbac_path: "./rbac.toml".into(),
            require_mtls: true,
            tls_cert_pem: "./deploy/tls/admin-server.crt.pem".into(),
            tls_key_pem: "./deploy/tls/admin-server.key.pem".into(),
            tls_ca_cert_pem: "./deploy/tls/ca.crt.pem".into(),
            audit_log_path: "./data/audit.log".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SigningSection {
    /// Signing mode used by helper tools / RPC features that need to sign locally.
    /// - "local"  : use node keystore
    /// - "remote" : use remote signer HTTP service
    pub mode: String,
    /// Remote signer base URL, e.g. http://127.0.0.1:9100
    pub remote_url: String,
    /// Remote signer request timeout (seconds)
    pub remote_timeout_s: u64,
    /// Remote signer mTLS: client certificate PEM path (optional)
    pub remote_tls_client_cert_pem: String,
    /// Remote signer mTLS: client private key PEM path (optional)
    pub remote_tls_client_key_pem: String,
    /// Remote signer mTLS: CA certificate PEM path (optional)
    pub remote_tls_ca_cert_pem: String,
    /// Remote signer mTLS: expected server name for TLS (SNI), optional
    pub remote_tls_server_name: String,
}

impl Default for SigningSection {
    fn default() -> Self {
        Self {
            mode: "local".into(),
            remote_url: "http://127.0.0.1:9100".into(),
            remote_timeout_s: 10,
            remote_tls_client_cert_pem: "".into(),
            remote_tls_client_key_pem: "".into(),
            remote_tls_ca_cert_pem: "".into(),
            remote_tls_server_name: "".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StorageSection {
    /// Enable periodic local snapshots of state to data_dir/snapshots/
    pub enable_snapshots: bool,
    /// Snapshot every N blocks (0 disables interval)
    pub snapshot_every_n_blocks: u64,
    /// How many snapshots to keep (oldest pruned)
    pub snapshot_keep: usize,
    /// zstd compression level (1-22)
    pub snapshot_zstd_level: i32,
    /// Max concurrent background tasks (0 = auto)
    pub max_concurrent_tasks: usize,
}

impl Default for StorageSection {
    fn default() -> Self {
        Self {
            enable_snapshots: true,
            snapshot_every_n_blocks: 500,
            snapshot_keep: 10,
            snapshot_zstd_level: 3,
            max_concurrent_tasks: 256,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ObservabilitySection {
    /// Enable OpenTelemetry export (requires --features otel)
    pub enable_otel: bool,
    /// OTLP endpoint (e.g. http://localhost:4317)
    pub otel_endpoint: String,
    pub service_name: String,
}

impl Default for ObservabilitySection {
    fn default() -> Self {
        Self {
            enable_otel: false,
            otel_endpoint: "http://127.0.0.1:4317".into(),
            service_name: "iona-node".into(),
        }
    }
}

impl NodeConfig {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        if !Path::new(path).exists() {
            return Ok(Self::default());
        }
        let s = std::fs::read_to_string(path)?;
        let cfg: NodeConfig = toml::from_str(&s)?;
        Ok(cfg)
    }

    pub fn example_toml() -> &'static str {
        r#"# IONA v24+ node configuration
# All values shown are defaults.

[node]
data_dir  = "./data/node1"
seed      = 1             # deterministic key seed (change per node)
chain_id  = 6126151
log_level = "info"        # trace | debug | info | warn | error
keystore  = "plain"       # plain | encrypted
keystore_password     = ""  # password for encrypted keystore (fallback if env not set)
keystore_password_env = "IONA_KEYSTORE_PASSWORD"

[consensus]
propose_timeout_ms   = 300   # ms to wait for proposal before nil-voting
prevote_timeout_ms   = 200   # ms timeout for prevote phase (fallback)
precommit_timeout_ms = 200   # ms timeout for precommit phase (fallback)
max_txs_per_block    = 4096  # max transactions per block
gas_target           = 43000000  # EIP-1559 target gas per block
fast_quorum          = true  # advance immediately when 2/3+ votes received
initial_base_fee     = 1
stake_each           = 1000  # stake assigned to each demo validator

[network]
listen = "/ip4/0.0.0.0/tcp/7001"
peers  = [
  # "/ip4/1.2.3.4/tcp/7001",  # static peer 1
  # "/ip4/1.2.3.5/tcp/7002",  # static peer 2
]
bootnodes = [
  # "/dns4/node.example/tcp/7001/p2p/12D3KooW...",
]
enable_mdns = false
enable_kad  = true
reconnect_s = 30  # seconds between reconnect attempts to static peers

# P2P state sync (download latest snapshot from peers when state_full.json is missing)
enable_p2p_state_sync = true
state_sync_chunk_bytes = 1048576
state_sync_timeout_s = 15

[mempool]
capacity = 200000

[rpc]
listen        = "0.0.0.0:9001"
enable_faucet = false  # set true ONLY for testnets

[signing]
mode = "local"              # local | remote
remote_url = "http://127.0.0.1:9100"
remote_timeout_s = 10

[storage]
enable_snapshots = true
snapshot_every_n_blocks = 500
snapshot_keep = 10
snapshot_zstd_level = 3
max_concurrent_tasks = 256

[observability]
enable_otel = false
otel_endpoint = "http://127.0.0.1:4317"
service_name = "iona-node"
"#
    }

    pub fn write_example(path: &str) -> std::io::Result<()> {
        std::fs::write(path, Self::example_toml())
    }
}
