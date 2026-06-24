//! Quantum configuration system for IONA v28.
//!
//! # Quantum Configuration Architecture
//!
//! The configuration is treated as a quantum observable Ô_config whose
//! eigenvalues correspond to valid configuration states. Each section
//! exists in a superposition of possible values until measured (loaded
//! from file, CLI, or environment).
//!
//! # Hamiltonian for Configuration
//!
//! ```text
//! Ĥ_config = Ĥ_node + Ĥ_consensus + Ĥ_network + Ĥ_mempool + Ĥ_rpc + Ĥ_admin + Ĥ_signing + Ĥ_storage + Ĥ_observability
//!
//! Each section Hamiltonian:
//! Ĥ_section = Σ_i E_i |valid_i⟩⟨valid_i| + Σ_j ∞ |invalid_j⟩⟨invalid_j|
//! ```
//!
//! Invalid configurations have infinite energy, making them unobservable
//! (the system cannot exist in those states).
//!
//! # Measurement Order (Priority)
//!
//! 1. Default values (ground state)
//! 2. Config file (first projective measurement)
//! 3. Environment variables IONA_* (second projective measurement)
//! 4. CLI flags (final projective measurement)
//!
//! The last measurement collapses the wavefunction to the final configuration.

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
// Quantum Configuration Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during quantum configuration measurement.
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

// -----------------------------------------------------------------------------
// Main Configuration Observable
// -----------------------------------------------------------------------------

/// The complete node configuration — a quantum observable.
///
/// When measured (loaded), it collapses to a single valid eigenstate.
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
    /// Measure configuration from a TOML file, applying environment overrides.
    ///
    /// If the file does not exist, returns the ground state (defaults) with env overrides.
    pub fn load(path: impl AsRef<Path>) -> ConfigResult<Self> {
        let path = path.as_ref();
        let mut cfg = if path.exists() {
            // Acquire shared lock for reading.
            let file = File::open(path).map_err(|e| ConfigError::Io {
                path: path.to_path_buf(),
                source: e,
            })?;
            file.lock_shared().map_err(|e| ConfigError::LockFailed(e.to_string()))?;

            let contents = std::fs::read_to_string(path).map_err(|e| ConfigError::Io {
                path: path.to_path_buf(),
                source: e,
            })?;
            let cfg: Self = toml::from_str(&contents).map_err(|e| ConfigError::Toml {
                path: path.to_path_buf(),
                source: e,
            })?;
            // Release lock (file will be dropped).
            cfg
        } else {
            // No file, start with defaults.
            Self::default()
        };

        // Apply environment variables.
        cfg.apply_env()?;

        // Validate.
        cfg.validate()?;

        Ok(cfg)
    }

    /// Apply environment variables of the form IONA_* to override config fields.
    /// The mapping uses the pattern: IONA_SECTION_FIELD = value.
    /// For example: IONA_NODE_DATA_DIR = "/data".
    fn apply_env(&mut self) -> ConfigResult<()> {
        let mut env_vars: HashMap<String, String> = HashMap::new();
        for (key, value) in env::vars() {
            if key.starts_with("IONA_") && !value.is_empty() {
                env_vars.insert(key, value);
            }
        }

        // Helper to parse TOML from env vars.
        // We'll construct a TOML string from env vars and merge.
        let mut toml_string = String::new();
        for (key, value) in &env_vars {
            // key format: IONA_SECTION_FIELD -> section.field
            let parts: Vec<&str> = key.splitn(3, '_').collect();
            if parts.len() == 3 {
                let section = parts[1].to_lowercase();
                let field = parts[2].to_lowercase();
                // Convert value to TOML literal (string, number, bool).
                let toml_value = if value.parse::<i64>().is_ok()
                    || value.parse::<f64>().is_ok()
                    || value.parse::<bool>().is_ok()
                {
                    value.clone()
                } else {
                    // String needs quoting.
                    format!("\"{}\"", value.replace('\"', "\\\""))
                };
                toml_string.push_str(&format!("{}.{} = {}\n", section, field, toml_value));
            }
        }

        if !toml_string.is_empty() {
            // Parse the TOML overrides and merge into self.
            // We'll use a temporary TOML value and deserialize into a partial struct.
            // But easier: we can merge by deserializing into a Value and applying.
            let overrides: toml::Value = toml::from_str(&toml_string)
                .map_err(|e| ConfigError::EnvParse {
                    key: "unknown".to_string(),
                    value: e.to_string(),
                })?;
            // Convert self to toml::Value, merge, and deserialize back.
            let mut self_value = toml::Value::try_from(self.clone())
                .map_err(|e| ConfigError::TomlSerialize { source: e })?;
            merge_toml_values(&mut self_value, overrides);
            *self = Self::deserialize(self_value)
                .map_err(|e| ConfigError::Toml { path: PathBuf::from("env"), source: e })?;
        }

        Ok(())
    }

    /// Apply CLI overrides: a list of "section.field=value" strings.
    /// This is the final measurement, so it has highest priority.
    pub fn apply_cli_overrides(&mut self, overrides: &[String]) -> ConfigResult<()> {
        if overrides.is_empty() {
            return Ok(());
        }

        let mut toml_string = String::new();
        for override_str in overrides {
            // Split by '=' to get key and value.
            let parts: Vec<&str> = override_str.splitn(2, '=').collect();
            if parts.len() != 2 {
                return Err(ConfigError::Validation(
                    format!("Invalid CLI override format: '{}', expected 'section.field=value'", override_str)
                ));
            }
            let key = parts[0].trim();
            let value = parts[1].trim();

            // Convert value to TOML literal.
            let toml_value = if value.parse::<i64>().is_ok()
                || value.parse::<f64>().is_ok()
                || value.parse::<bool>().is_ok()
            {
                value.to_string()
            } else {
                // String needs quoting.
                format!("\"{}\"", value.replace('\"', "\\\""))
            };
            toml_string.push_str(&format!("{} = {}\n", key, toml_value));
        }

        if !toml_string.is_empty() {
            let overrides: toml::Value = toml::from_str(&toml_string)
                .map_err(|e| ConfigError::Toml { path: PathBuf::from("cli"), source: e })?;
            let mut self_value = toml::Value::try_from(self.clone())
                .map_err(|e| ConfigError::TomlSerialize { source: e })?;
            merge_toml_values(&mut self_value, overrides);
            *self = Self::deserialize(self_value)
                .map_err(|e| ConfigError::Toml { path: PathBuf::from("cli"), source: e })?;
        }

        Ok(())
    }

    /// Validate the entire configuration — measure all observables.
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

    /// Write the configuration to a file atomically (write to temp, then rename).
    /// Acquires an exclusive lock during writing.
    pub fn write(&self, path: impl AsRef<Path>) -> ConfigResult<()> {
        let path = path.as_ref();
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
        let toml_string = toml::to_string_pretty(self)
            .map_err(|e| ConfigError::TomlSerialize { source: e })?;
        fs::write(&temp_path, toml_string).map_err(|e| ConfigError::Io {
            path: temp_path.clone(),
            source: e,
        })?;

        // Atomic rename.
        fs::rename(&temp_path, path).map_err(|e| ConfigError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;

        // Release lock (drop file).
        Ok(())
    }

    /// Example configuration string (classical representation).
    pub fn example_toml() -> &'static str {
        include_str!("config_example.toml")
    }

    /// Write example configuration to a file.
    pub fn write_example(path: impl AsRef<Path>) -> ConfigResult<()> {
        let path = path.as_ref();
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

        fs::write(path, Self::example_toml()).map_err(|e| ConfigError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;

        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Helper: Merge TOML values recursively
// -----------------------------------------------------------------------------

/// Merge two TOML values recursively, with `overrides` taking precedence.
fn merge_toml_values(base: &mut toml::Value, overrides: toml::Value) {
    match (base, overrides) {
        (toml::Value::Table(base_table), toml::Value::Table(override_table)) => {
            for (key, value) in override_table {
                if let Some(existing) = base_table.get_mut(&key) {
                    merge_toml_values(existing, value);
                } else {
                    base_table.insert(key, value);
                }
            }
        }
        (base, override_val) => {
            // Override completely.
            *base = override_val;
        }
    }
}

// -----------------------------------------------------------------------------
// Node Section
// -----------------------------------------------------------------------------

/// Node identity and key management configuration.
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
        // Check log_level validity.
        if !["trace", "debug", "info", "warn", "error"].contains(&self.log_level.as_str()) {
            return Err(ConfigError::Validation(
                "node.log_level must be one of: trace, debug, info, warn, error".into(),
            ));
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Consensus Section
// -----------------------------------------------------------------------------

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

        // Check uniqueness of validator seeds.
        let unique: std::collections::HashSet<_> = self.validator_seeds.iter().collect();
        if unique.len() != self.validator_seeds.len() {
            return Err(ConfigError::Validation(
                "consensus.validator_seeds must contain unique seeds".into(),
            ));
        }

        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Network Section
// -----------------------------------------------------------------------------

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

// -----------------------------------------------------------------------------
// Sub-sections
// -----------------------------------------------------------------------------

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

// -----------------------------------------------------------------------------
// Remaining sections
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolSection {
    pub capacity: usize,
}

impl Default for MempoolSection {
    fn default() -> Self {
        Self { capacity: 200_000 }
    }
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
        // Ensure port is numeric.
        let parts: Vec<&str> = self.listen.split(':').collect();
        if parts.len() != 2 || parts[1].parse::<u16>().is_err() {
            return Err(ConfigError::Validation(
                format!("rpc.listen '{}' must be 'host:port' with a valid port", self.listen)
            ));
        }
        Ok(())
    }
}

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
        let cfg = NodeConfig::load("non_existent_file.toml").unwrap();
        assert_eq!(cfg.node.data_dir, "/custom/data");
        assert_eq!(cfg.consensus.propose_timeout_ms, 500);
        // Clean up.
        env::remove_var("IONA_NODE_DATA_DIR");
        env::remove_var("IONA_CONSENSUS_PROPOSE_TIMEOUT_MS");
    }

    #[test]
    fn test_cli_overrides() {
        let mut cfg = NodeConfig::default();
        let overrides = vec![
            "node.data_dir=/cli/data".into(),
            "consensus.propose_timeout_ms=100".into(),
        ];
        cfg.apply_cli_overrides(&overrides).unwrap();
        assert_eq!(cfg.node.data_dir, "/cli/data");
        assert_eq!(cfg.consensus.propose_timeout_ms, 100);
    }

    #[test]
    fn test_write_and_load() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut cfg = NodeConfig::default();
        cfg.node.data_dir = "/test/data".into();
        cfg.write(&path).unwrap();

        let loaded = NodeConfig::load(&path).unwrap();
        assert_eq!(loaded.node.data_dir, "/test/data");
    }
}
