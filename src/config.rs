//! Quantum configuration system for IONA v28.
//!
//! # Quantum Configuration Architecture
//!
//! The configuration is treated as a quantum observable Ô_config whose
//! eigenvalues correspond to valid configuration states. Each section
//! exists in a superposition of possible values until measured (loaded
//! from file, CLI, or environment).
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                        Configuration Module                            │
//! ├─────────────┬──────────────┬───────────────┬──────────────────────────┤
//! │   Config    │    Error     │    Metrics    │         Types            │
//! │ (ConfigMgr) │ (ConfigErr)  │ (ConfigMetr)  │ (NodeConfig, Sections)   │
//! ├─────────────┼──────────────┼───────────────┼──────────────────────────┤
//! │   Helpers   │   Manager    │    Legacy     │                          │
//! │ (merge,     │ (ConfigMgr)  │ (global fns)  │                          │
//! │  validation)│              │               │                          │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::config::{ConfigManager, NodeConfig};
//!
//! let mut mgr = ConfigManager::new("config.toml");
//! let cfg = mgr.load()?;
//! ```
//!
//! # Measurement Order (Priority)
//!
//! 1. Default values (ground state)
//! 2. Config file (first projective measurement)
//! 3. Environment variables IONA_* (second projective measurement)
//! 4. CLI flags (final projective measurement)
//!
//! The last measurement collapses the wavefunction to the final configuration.

#![allow(dead_code)]

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;
use tracing::{debug, info, warn};

// -----------------------------------------------------------------------------
// Submodules (embedded)
// -----------------------------------------------------------------------------

pub mod config {
    //! Configuration sections and validation.
    use serde::{Deserialize, Serialize};
    use std::collections::HashSet;
    use super::error::ConfigError;
    use super::types::ConfigResult;

    /// The complete node configuration — a quantum observable.
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

    impl NodeConfig {
        /// Validate the entire configuration.
        pub fn validate(&self) -> ConfigResult<()> {
            self.node.validate()?;
            self.consensus.validate()?;
            self.network.validate()?;
            self.mempool.validate()?;
            self.rpc.validate()?;
            self.admin.validate()?;
            self.signing.validate()?;
            self.storage.validate()?;
            self.observability.validate()?;
            Ok(())
        }
    }

    // -------------------------------------------------------------------------
    // Node Section
    // -------------------------------------------------------------------------

    /// Node identity and key management.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct NodeSection {
        pub data_dir: String,
        pub seed: u64,
        pub chain_id: u64,
        pub log_level: String,
        pub keystore: String,
        #[serde(default)]
        pub keystore_password: String,
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

    impl NodeSection {
        fn validate(&self) -> ConfigResult<()> {
            if !["plain", "encrypted"].contains(&self.keystore.as_str()) {
                return Err(ConfigError::Validation(
                    "node.keystore must be 'plain' or 'encrypted'".into(),
                ));
            }
            if self.keystore == "encrypted"
                && self.keystore_password.is_empty()
                && self.keystore_password_env.is_empty()
            {
                return Err(ConfigError::Validation(
                    "encrypted keystore requires keystore_password or keystore_password_env".into(),
                ));
            }
            if !["trace", "debug", "info", "warn", "error"].contains(&self.log_level.as_str()) {
                return Err(ConfigError::Validation(
                    "node.log_level must be one of: trace, debug, info, warn, error".into(),
                ));
            }
            Ok(())
        }
    }

    // -------------------------------------------------------------------------
    // Consensus Section
    // -------------------------------------------------------------------------

    /// Consensus protocol configuration.
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
        pub simple_producer: bool,
        #[serde(default = "default_validator_seeds")]
        pub validator_seeds: Vec<u64>,
        #[serde(default = "default_activations")]
        pub protocol_activations: Vec<crate::protocol::version::ProtocolActivation>,
    }

    fn default_validator_seeds() -> Vec<u64> {
        vec![2, 3, 4]
    }

    fn default_activations() -> Vec<crate::protocol::version::ProtocolActivation> {
        crate::protocol::version::default_activations()
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

    impl ConsensusSection {
        fn validate(&self) -> ConfigResult<()> {
            let validators = [
                ("propose_timeout_ms", self.propose_timeout_ms),
                ("prevote_timeout_ms", self.prevote_timeout_ms),
                ("precommit_timeout_ms", self.precommit_timeout_ms),
            ];
            for (name, value) in &validators {
                if *value == 0 {
                    return Err(ConfigError::Validation(format!(
                        "consensus.{name} must be > 0"
                    )));
                }
            }
            if self.max_txs_per_block == 0 {
                return Err(ConfigError::Validation(
                    "consensus.max_txs_per_block must be > 0".into(),
                ));
            }
            if self.validator_seeds.is_empty() {
                return Err(ConfigError::Validation(
                    "consensus.validator_seeds cannot be empty".into(),
                ));
            }
            let unique: HashSet<_> = self.validator_seeds.iter().collect();
            if unique.len() != self.validator_seeds.len() {
                return Err(ConfigError::Validation(
                    "consensus.validator_seeds must contain unique seeds".into(),
                ));
            }
            Ok(())
        }
    }

    // -------------------------------------------------------------------------
    // Network Section
    // -------------------------------------------------------------------------

    /// Network and P2P configuration.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(default)]
    pub struct NetworkSection {
        pub listen: String,
        pub peers: Vec<String>,
        pub bootnodes: Vec<String>,
        pub enable_mdns: bool,
        pub enable_kad: bool,
        pub reconnect_s: u64,
        pub max_connections_total: usize,
        pub max_connections_per_peer: usize,
        pub rr_max_req_per_sec: u32,
        pub rr_strikes_before_ban: u32,
        pub rr_max_req_per_sec_block: u32,
        pub rr_max_req_per_sec_status: u32,
        pub rr_max_req_per_sec_range: u32,
        pub rr_max_req_per_sec_state: u32,
        pub rr_max_bytes_per_sec_block: u32,
        pub rr_max_bytes_per_sec_status: u32,
        pub rr_max_bytes_per_sec_range: u32,
        pub rr_max_bytes_per_sec_state: u32,
        pub rr_global_in_bytes_per_sec: u32,
        pub rr_global_out_bytes_per_sec: u32,
        pub peer_strike_decay_s: u64,
        pub peer_score_decay_s: u64,
        pub peer_quarantine_s: u64,
        pub rr_strikes_before_quarantine: u32,
        pub rr_quarantines_before_ban: u32,
        pub persist_quarantine: bool,
        #[serde(default)]
        pub gossipsub: GossipsubSection,
        #[serde(default)]
        pub diversity: DiversitySection,
        pub eclipse_profile: String,
        pub enable_p2p_state_sync: bool,
        pub state_sync_chunk_bytes: u32,
        pub state_sync_timeout_s: u64,
        pub enable_snapshot_attestation: bool,
        pub snapshot_attestation_threshold: u32,
        pub snapshot_attestation_collect_s: u64,
        #[serde(default)]
        pub state_sync_security: StateSyncSecuritySection,
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
                eclipse_profile: "testnet".into(),
                enable_p2p_state_sync: true,
                state_sync_chunk_bytes: 1_048_576,
                state_sync_timeout_s: 10,
                enable_snapshot_attestation: true,
                snapshot_attestation_threshold: 2,
                snapshot_attestation_collect_s: 8,
                state_sync_security: StateSyncSecuritySection::default(),
            }
        }
    }

    impl NetworkSection {
        fn validate(&self) -> ConfigResult<()> {
            if !self.listen.contains("/tcp/") && !self.listen.contains("/ws/") {
                return Err(ConfigError::Validation(
                    "network.listen must be a valid multiaddress with /tcp/ or /ws/".into(),
                ));
            }
            if self.max_connections_total == 0 {
                return Err(ConfigError::Validation(
                    "network.max_connections_total must be > 0".into(),
                ));
            }
            if self.rr_max_req_per_sec == 0 {
                return Err(ConfigError::Validation(
                    "network.rr_max_req_per_sec must be > 0".into(),
                ));
            }
            if self.rr_strikes_before_ban == 0 {
                return Err(ConfigError::Validation(
                    "network.rr_strikes_before_ban must be > 0".into(),
                ));
            }
            if self.rr_strikes_before_quarantine == 0 {
                return Err(ConfigError::Validation(
                    "network.rr_strikes_before_quarantine must be > 0".into(),
                ));
            }
            if self.rr_quarantines_before_ban == 0 {
                return Err(ConfigError::Validation(
                    "network.rr_quarantines_before_ban must be > 0".into(),
                ));
            }
            Ok(())
        }
    }

    // Sub-sections of Network
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
        pub max_publish_msgs_per_sec: u32,
        pub max_publish_bytes_per_sec: u32,
        pub max_in_msgs_per_sec: u32,
        pub max_in_bytes_per_sec: u32,
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
    pub struct DiversitySection {
        pub bucket_kind: String,
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

    // -------------------------------------------------------------------------
    // Mempool Section
    // -------------------------------------------------------------------------

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct MempoolSection {
        pub capacity: usize,
    }

    impl Default for MempoolSection {
        fn default() -> Self { Self { capacity: 200_000 } }
    }

    impl MempoolSection {
        fn validate(&self) -> ConfigResult<()> {
            if self.capacity == 0 {
                return Err(ConfigError::Validation(
                    "mempool.capacity must be > 0".into(),
                ));
            }
            Ok(())
        }
    }

    // -------------------------------------------------------------------------
    // RPC Section
    // -------------------------------------------------------------------------

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(default)]
    pub struct RpcSection {
        pub listen: String,
        pub enable_faucet: bool,
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

    impl RpcSection {
        fn validate(&self) -> ConfigResult<()> {
            if !self.listen.contains(':') {
                return Err(ConfigError::Validation(
                    "rpc.listen must be in format 'host:port'".into(),
                ));
            }
            let parts: Vec<&str> = self.listen.split(':').collect();
            if parts.len() != 2 || parts[1].parse::<u16>().is_err() {
                return Err(ConfigError::Validation(
                    format!("rpc.listen '{}' must be 'host:port' with a valid port", self.listen)
                ));
            }
            Ok(())
        }
    }

    // -------------------------------------------------------------------------
    // Admin Section
    // -------------------------------------------------------------------------

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(default)]
    pub struct AdminSection {
        pub listen: String,
        pub rbac_path: String,
        pub require_mtls: bool,
        pub tls_cert_pem: String,
        pub tls_key_pem: String,
        pub tls_ca_cert_pem: String,
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

    impl AdminSection {
        fn validate(&self) -> ConfigResult<()> {
            if self.require_mtls
                && (self.tls_cert_pem.is_empty()
                    || self.tls_key_pem.is_empty()
                    || self.tls_ca_cert_pem.is_empty())
            {
                return Err(ConfigError::Validation(
                    "admin.require_mtls=true requires tls_cert_pem, tls_key_pem, and tls_ca_cert_pem"
                        .into(),
                ));
            }
            Ok(())
        }
    }

    // -------------------------------------------------------------------------
    // Signing Section
    // -------------------------------------------------------------------------

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(default)]
    pub struct SigningSection {
        pub mode: String,
        pub remote_url: String,
        pub remote_timeout_s: u64,
        pub remote_tls_client_cert_pem: String,
        pub remote_tls_client_key_pem: String,
        pub remote_tls_ca_cert_pem: String,
        pub remote_tls_server_name: String,
    }

    impl Default for SigningSection {
        fn default() -> Self {
            Self {
                mode: "local".into(),
                remote_url: "http://127.0.0.1:9100".into(),
                remote_timeout_s: 10,
                remote_tls_client_cert_pem: String::new(),
                remote_tls_client_key_pem: String::new(),
                remote_tls_ca_cert_pem: String::new(),
                remote_tls_server_name: String::new(),
            }
        }
    }

    impl SigningSection {
        fn validate(&self) -> ConfigResult<()> {
            if !["local", "remote"].contains(&self.mode.as_str()) {
                return Err(ConfigError::Validation(
                    "signing.mode must be 'local' or 'remote'".into(),
                ));
            }
            if self.mode == "remote" && self.remote_url.is_empty() {
                return Err(ConfigError::Validation(
                    "signing.remote_url must be set when mode=remote".into(),
                ));
            }
            Ok(())
        }
    }

    // -------------------------------------------------------------------------
    // Storage Section
    // -------------------------------------------------------------------------

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(default)]
    pub struct StorageSection {
        pub enable_snapshots: bool,
        pub snapshot_every_n_blocks: u64,
        pub snapshot_keep: usize,
        pub snapshot_zstd_level: i32,
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

    impl StorageSection {
        fn validate(&self) -> ConfigResult<()> {
            if self.snapshot_zstd_level < 1 || self.snapshot_zstd_level > 22 {
                return Err(ConfigError::Validation(
                    "storage.snapshot_zstd_level must be between 1 and 22".into(),
                ));
            }
            if self.snapshot_keep == 0 {
                return Err(ConfigError::Validation(
                    "storage.snapshot_keep must be > 0".into(),
                ));
            }
            Ok(())
        }
    }

    // -------------------------------------------------------------------------
    // Observability Section
    // -------------------------------------------------------------------------

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(default)]
    pub struct ObservabilitySection {
        pub enable_otel: bool,
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

    impl ObservabilitySection {
        fn validate(&self) -> ConfigResult<()> {
            if self.enable_otel && self.otel_endpoint.is_empty() {
                return Err(ConfigError::Validation(
                    "observability.otel_endpoint must be set when enable_otel=true".into(),
                ));
            }
            Ok(())
        }
    }
}

pub mod error {
    //! Error types for the configuration system.
    use std::path::PathBuf;
    use thiserror::Error;

    #[derive(Debug, Error)]
    pub enum ConfigError {
        #[error("I/O decoherence reading config file {path}: {source}")]
        Io {
            path: PathBuf,
            #[source]
            source: std::io::Error,
        },

        #[error("TOML wavefunction collapse error in {path}: {source}")]
        Toml {
            path: PathBuf,
            #[source]
            source: toml::de::Error,
        },

        #[error("TOML serialization error: {source}")]
        TomlSerialize {
            #[source]
            source: toml::ser::Error,
        },

        #[error("Configuration validation failed: {0}")]
        Validation(String),

        #[error("Quantum coherence lost: conflicting configuration eigenvalues")]
        CoherenceLost,

        #[error("Environment variable parse error: {key} = {value}")]
        EnvParse { key: String, value: String },

        #[error("Lock acquisition failed: {0}")]
        LockFailed(String),

        #[error("Config file does not exist: {path}")]
        NotFound { path: PathBuf },
    }

    pub type ConfigResult<T> = Result<T, ConfigError>;
}

pub mod helpers {
    //! Helper functions for configuration.
    use super::error::ConfigError;
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    use std::env;
    use std::fs::{self, File, OpenOptions};
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use fs2::FileExt;
    use toml::Value;

    /// Merge two TOML values recursively, with `overrides` taking precedence.
    pub fn merge_toml_values(base: &mut Value, overrides: Value) {
        match (base, overrides) {
            (Value::Table(base_table), Value::Table(override_table)) => {
                for (key, value) in override_table {
                    if let Some(existing) = base_table.get_mut(&key) {
                        merge_toml_values(existing, value);
                    } else {
                        base_table.insert(key, value);
                    }
                }
            }
            (base, override_val) => {
                *base = override_val;
            }
        }
    }

    /// Parse environment variables of the form IONA_* into a TOML string.
    pub fn env_to_toml() -> String {
        let mut toml_string = String::new();
        for (key, value) in env::vars() {
            if key.starts_with("IONA_") && !value.is_empty() {
                let parts: Vec<&str> = key.splitn(3, '_').collect();
                if parts.len() == 3 {
                    let section = parts[1].to_lowercase();
                    let field = parts[2].to_lowercase();
                    let toml_value = if value.parse::<i64>().is_ok()
                        || value.parse::<f64>().is_ok()
                        || value.parse::<bool>().is_ok()
                    {
                        value.clone()
                    } else {
                        format!("\"{}\"", value.replace('\"', "\\\""))
                    };
                    toml_string.push_str(&format!("{}.{} = {}\n", section, field, toml_value));
                }
            }
        }
        toml_string
    }

    /// Write a TOML value to a file atomically (with locking).
    pub fn write_toml_atomically(
        path: &Path,
        contents: &str,
    ) -> Result<(), ConfigError> {
        // Ensure parent directory exists.
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| ConfigError::Io {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }

        // Acquire exclusive lock.
        let lock_path = path.with_extension("lock");
        let lock_file = OpenOptions::new()
            .create(true)
            .write(true)
            .open(&lock_path)
            .map_err(|e| ConfigError::Io { path: lock_path.clone(), source: e })?;
        lock_file.lock_exclusive().map_err(|e| ConfigError::LockFailed(e.to_string()))?;

        // Write to temp file.
        let temp_path = path.with_extension("tmp");
        fs::write(&temp_path, contents).map_err(|e| ConfigError::Io {
            path: temp_path.clone(),
            source: e,
        })?;

        // Atomic rename.
        fs::rename(&temp_path, path).map_err(|e| ConfigError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;

        Ok(())
    }

    /// Read a TOML file with shared lock.
    pub fn read_toml(path: &Path) -> Result<String, ConfigError> {
        let file = File::open(path).map_err(|e| ConfigError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        file.lock_shared().map_err(|e| ConfigError::LockFailed(e.to_string()))?;
        let contents = std::fs::read_to_string(path).map_err(|e| ConfigError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        Ok(contents)
    }
}

pub mod metrics {
    //! Metrics for configuration operations.
    use core::sync::atomic::{AtomicU64, Ordering};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Default)]
    pub struct ConfigMetrics {
        pub loads: AtomicU64,
        pub saves: AtomicU64,
        pub validations: AtomicU64,
        pub load_failures: AtomicU64,
        pub save_failures: AtomicU64,
        pub validation_failures: AtomicU64,
        pub env_overrides: AtomicU64,
        pub cli_overrides: AtomicU64,
        pub lock_acquire_failures: AtomicU64,
    }

    impl ConfigMetrics {
        pub fn inc_load(&self) { self.loads.fetch_add(1, Ordering::Relaxed); }
        pub fn inc_save(&self) { self.saves.fetch_add(1, Ordering::Relaxed); }
        pub fn inc_validation(&self) { self.validations.fetch_add(1, Ordering::Relaxed); }
        pub fn inc_load_failure(&self) { self.load_failures.fetch_add(1, Ordering::Relaxed); }
        pub fn inc_save_failure(&self) { self.save_failures.fetch_add(1, Ordering::Relaxed); }
        pub fn inc_validation_failure(&self) { self.validation_failures.fetch_add(1, Ordering::Relaxed); }
        pub fn inc_env_override(&self) { self.env_overrides.fetch_add(1, Ordering::Relaxed); }
        pub fn inc_cli_override(&self) { self.cli_overrides.fetch_add(1, Ordering::Relaxed); }
        pub fn inc_lock_failure(&self) { self.lock_acquire_failures.fetch_add(1, Ordering::Relaxed); }

        pub fn snapshot(&self) -> ConfigMetricsSnapshot {
            ConfigMetricsSnapshot {
                loads: self.loads.load(Ordering::Relaxed),
                saves: self.saves.load(Ordering::Relaxed),
                validations: self.validations.load(Ordering::Relaxed),
                load_failures: self.load_failures.load(Ordering::Relaxed),
                save_failures: self.save_failures.load(Ordering::Relaxed),
                validation_failures: self.validation_failures.load(Ordering::Relaxed),
                env_overrides: self.env_overrides.load(Ordering::Relaxed),
                cli_overrides: self.cli_overrides.load(Ordering::Relaxed),
                lock_acquire_failures: self.lock_acquire_failures.load(Ordering::Relaxed),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ConfigMetricsSnapshot {
        pub loads: u64,
        pub saves: u64,
        pub validations: u64,
        pub load_failures: u64,
        pub save_failures: u64,
        pub validation_failures: u64,
        pub env_overrides: u64,
        pub cli_overrides: u64,
        pub lock_acquire_failures: u64,
    }

    /// Global metrics instance.
    pub(crate) static GLOBAL_METRICS: spin::Once<ConfigMetrics> = spin::Once::new();

    pub fn global_metrics() -> &'static ConfigMetrics {
        GLOBAL_METRICS.get_or_init(ConfigMetrics::default)
    }
}

pub mod manager {
    //! Centralised manager for configuration.
    use super::{
        config::NodeConfig,
        error::{ConfigError, ConfigResult},
        helpers::{merge_toml_values, env_to_toml, write_toml_atomically, read_toml},
        metrics::global_metrics,
    };
    use std::path::{Path, PathBuf};
    use toml::Value;
    use tracing::{debug, info, warn};

    /// Manager for configuration operations.
    pub struct ConfigManager {
        path: PathBuf,
        config: NodeConfig,
        initialised: bool,
    }

    impl ConfigManager {
        /// Create a new configuration manager with a file path.
        pub fn new(path: impl AsRef<Path>) -> Self {
            Self {
                path: path.as_ref().to_path_buf(),
                config: NodeConfig::default(),
                initialised: false,
            }
        }

        /// Load configuration from file, applying environment overrides.
        pub fn load(&mut self) -> ConfigResult<&NodeConfig> {
            global_metrics().inc_load();
            let path = &self.path;

            let mut cfg = if path.exists() {
                let contents = read_toml(path)?;
                let cfg: NodeConfig = toml::from_str(&contents)
                    .map_err(|e| ConfigError::Toml { path: path.to_path_buf(), source: e })?;
                cfg
            } else {
                // No file, start with defaults.
                NodeConfig::default()
            };

            // Apply environment variables.
            let env_toml = env_to_toml();
            if !env_toml.is_empty() {
                if let Ok(overrides) = toml::from_str::<Value>(&env_toml) {
                    let mut self_value = toml::Value::try_from(cfg.clone())
                        .map_err(|e| ConfigError::TomlSerialize { source: e })?;
                    merge_toml_values(&mut self_value, overrides);
                    cfg = NodeConfig::deserialize(self_value)
                        .map_err(|e| ConfigError::Toml { path: path.to_path_buf(), source: e })?;
                    global_metrics().inc_env_override();
                } else {
                    // Ignore malformed env overrides.
                }
            }

            // Validate.
            cfg.validate()?;

            self.config = cfg;
            self.initialised = true;
            info!("Configuration loaded from {}", path.display());
            Ok(&self.config)
        }

        /// Apply CLI overrides (highest priority).
        pub fn apply_cli_overrides(&mut self, overrides: &[String]) -> ConfigResult<()> {
            if overrides.is_empty() {
                return Ok(());
            }
            global_metrics().inc_cli_override();

            let mut toml_string = String::new();
            for override_str in overrides {
                let parts: Vec<&str> = override_str.splitn(2, '=').collect();
                if parts.len() != 2 {
                    return Err(ConfigError::Validation(
                        format!("Invalid CLI override format: '{}', expected 'section.field=value'", override_str)
                    ));
                }
                let key = parts[0].trim();
                let value = parts[1].trim();
                let toml_value = if value.parse::<i64>().is_ok()
                    || value.parse::<f64>().is_ok()
                    || value.parse::<bool>().is_ok()
                {
                    value.to_string()
                } else {
                    format!("\"{}\"", value.replace('\"', "\\\""))
                };
                toml_string.push_str(&format!("{} = {}\n", key, toml_value));
            }

            if !toml_string.is_empty() {
                let overrides: Value = toml::from_str(&toml_string)
                    .map_err(|e| ConfigError::Toml { path: self.path.clone(), source: e })?;
                let mut self_value = toml::Value::try_from(self.config.clone())
                    .map_err(|e| ConfigError::TomlSerialize { source: e })?;
                merge_toml_values(&mut self_value, overrides);
                self.config = NodeConfig::deserialize(self_value)
                    .map_err(|e| ConfigError::Toml { path: self.path.clone(), source: e })?;
                // Re-validate after CLI overrides.
                self.config.validate()?;
            }

            Ok(())
        }

        /// Save the current configuration to file.
        pub fn save(&self) -> ConfigResult<()> {
            global_metrics().inc_save();
            let toml_string = toml::to_string_pretty(&self.config)
                .map_err(|e| ConfigError::TomlSerialize { source: e })?;
            write_toml_atomically(&self.path, &toml_string)?;
            info!("Configuration saved to {}", self.path.display());
            Ok(())
        }

        /// Reload configuration from file (overwrites current).
        pub fn reload(&mut self) -> ConfigResult<&NodeConfig> {
            self.load()
        }

        /// Get a reference to the current configuration.
        pub fn config(&self) -> &NodeConfig {
            &self.config
        }

        /// Get a mutable reference to the configuration (use with care).
        pub fn config_mut(&mut self) -> &mut NodeConfig {
            &mut self.config
        }

        /// Validate the current configuration.
        pub fn validate(&self) -> ConfigResult<()> {
            global_metrics().inc_validation();
            self.config.validate()
        }

        /// Write an example configuration to the file.
        pub fn write_example(&self) -> ConfigResult<()> {
            let example = include_str!("config_example.toml");
            write_toml_atomically(&self.path, example)?;
            Ok(())
        }
    }
}

// -----------------------------------------------------------------------------
// Public exports
// -----------------------------------------------------------------------------

pub use config::{
    NodeConfig, NodeSection, ConsensusSection, NetworkSection,
    MempoolSection, RpcSection, AdminSection, SigningSection,
    StorageSection, ObservabilitySection,
    GossipsubSection, DiversitySection, StateSyncSecuritySection, TopicLimit,
};
pub use error::{ConfigError, ConfigResult};
pub use metrics::{ConfigMetrics, ConfigMetricsSnapshot};
pub use manager::ConfigManager;

// -----------------------------------------------------------------------------
// Legacy global API (backward compatibility)
// -----------------------------------------------------------------------------

use spin::Once;

static GLOBAL_MANAGER: Once<ConfigManager> = Once::new();

/// Get the global manager (initialises with defaults if not yet set).
fn global_manager(path: &Path) -> &'static ConfigManager {
    GLOBAL_MANAGER.get_or_init(|| ConfigManager::new(path))
}

/// Load configuration from a file using global manager (legacy).
pub fn load_config(path: &Path) -> ConfigResult<NodeConfig> {
    let mgr = global_manager(path);
    // We need mutable access, but we can't get it from Once.
    // We'll use a static mutex for the manager.
    static MUTEX: spin::Mutex<Option<ConfigManager>> = spin::Mutex::new(None);
    let mut guard = MUTEX.lock();
    if guard.is_none() {
        *guard = Some(ConfigManager::new(path));
    }
    let mgr = guard.as_mut().unwrap();
    mgr.load()?;
    Ok(mgr.config().clone())
}

/// Legacy convenience: load with default path.
pub fn load_default_config() -> ConfigResult<NodeConfig> {
    load_config(Path::new("config.toml"))
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_default_config_is_valid() {
        let cfg = NodeConfig::default();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_consensus_validation() {
        let mut cfg = NodeConfig::default();
        cfg.consensus.propose_timeout_ms = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_network_validation() {
        let mut cfg = NodeConfig::default();
        cfg.network.listen = "invalid".into();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_mempool_validation() {
        let mut cfg = NodeConfig::default();
        cfg.mempool.capacity = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_rpc_validation() {
        let mut cfg = NodeConfig::default();
        cfg.rpc.listen = "invalid".into();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_admin_mtls_validation() {
        let mut cfg = NodeConfig::default();
        cfg.admin.require_mtls = true;
        cfg.admin.tls_cert_pem = String::new();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_signing_validation() {
        let mut cfg = NodeConfig::default();
        cfg.signing.mode = "invalid".into();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_storage_validation() {
        let mut cfg = NodeConfig::default();
        cfg.storage.snapshot_zstd_level = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_load_with_env() {
        // Set env vars.
        env::set_var("IONA_NODE_DATA_DIR", "/custom/data");
        env::set_var("IONA_CONSENSUS_PROPOSE_TIMEOUT_MS", "500");
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        // Create empty file.
        std::fs::write(&path, "").unwrap();
        let cfg = load_config(&path).unwrap();
        assert_eq!(cfg.node.data_dir, "/custom/data");
        assert_eq!(cfg.consensus.propose_timeout_ms, 500);
        // Clean up.
        env::remove_var("IONA_NODE_DATA_DIR");
        env::remove_var("IONA_CONSENSUS_PROPOSE_TIMEOUT_MS");
    }

    #[test]
    fn test_manager_load_and_save() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut mgr = ConfigManager::new(&path);
        mgr.config_mut().node.data_dir = "/test/data".into();
        mgr.save().unwrap();

        let mut mgr2 = ConfigManager::new(&path);
        mgr2.load().unwrap();
        assert_eq!(mgr2.config().node.data_dir, "/test/data");
    }

    #[test]
    fn test_cli_overrides() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut mgr = ConfigManager::new(&path);
        mgr.load().unwrap();
        let overrides = vec![
            "node.data_dir=/cli/data".into(),
            "consensus.propose_timeout_ms=100".into(),
        ];
        mgr.apply_cli_overrides(&overrides).unwrap();
        assert_eq!(mgr.config().node.data_dir, "/cli/data");
        assert_eq!(mgr.config().consensus.propose_timeout_ms, 100);
    }
}
