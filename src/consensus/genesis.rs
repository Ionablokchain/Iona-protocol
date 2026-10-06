//! Genesis configuration — IONA v30.
//!
//! Provides:
//! - [`GenesisConfig`] — on-disk format (`genesis.json`)
//! - [`GenesisConfig::generate_testnet`] — one-call testnet genesis
//! - [`GenesisConfig::genesis_hash`] — deterministic hash all nodes verify
//! - [`GenesisConfig::load_or_generate`] — idempotent load-or-create
//! - [`GenesisConfig::validator_set`] — validated `ValidatorSet` construction
//!
//! # Determinism contract
//!
//! `genesis_hash` is the network's identity. Every node **must** compute the
//! same hash from the same genesis.json. Two rules enforce this:
//!
//! 1. The canonical encoding is derived from a `BTreeMap` (sorted keys) and a
//!    fixed prefix `b"IONA_GENESIS_V1:"`, so key ordering in the source file
//!    does not affect the hash.
//! 2. `genesis_time` and any other field that defaults to "now" is **not**
//!    defaulted to wall-clock time on load. Missing values become `0`, which
//!    is deterministic. Only the generator writes the current timestamp, and
//!    once written it is immutable.
//!
//! Breaking any of these silently forks the network. The regression tests at
//! the bottom of this file guard against it.
//!
//! ## Usage
//! ```bash
//! # Generate genesis for a 4-node testnet
//! iona-cli genesis generate --validators 4 --chain-id 6126151 --out ./testnet/genesis.json
//! # Each node verifies on startup:
//! iona-node --config node1/config.toml --genesis testnet/genesis.json
//! ```

use crate::consensus::validator_set::{Validator, ValidatorSet, VotingPower};
use crate::crypto::{ed25519::Ed25519Keypair, PublicKeyBytes, Signer};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::{
    collections::BTreeMap,
    fs, io,
    path::Path,
};
use tracing::{info, warn};

// ── Constants ─────────────────────────────────────────────────────────────

/// Bumped only when the on-disk format or hashing rule changes.
/// Included in the hash prefix, so any change automatically re-hashes.
pub const GENESIS_SCHEMA_VERSION: &str = "V1";

/// Maximum number of validators we will generate in one call.
/// Guards against runaway memory use and runaway testnet configs.
pub const MAX_TESTNET_VALIDATORS: usize = 1000;

/// Faucet address: 20-byte hex, mnemonic-friendly (`facade` is hex).
///
/// The previous implementation used `0xFAuCET…`, which is not valid hex
/// (`u` is not a hex digit). The string is stored verbatim as the map key,
/// so any downstream tool that validated it would reject the genesis.
pub const FAUCET_ADDRESS: &str = "0xfacade0000000000000000000000000000000000";

/// Faucet balance: 1,000,000 ETH expressed in wei (10^24).
pub const FAUCET_BALANCE_WEI: &str = "1000000000000000000000000";

/// Default per-validator stake in the slashing ledger.
pub const DEFAULT_STAKE_EACH: u64 = 1_000_000;

/// Default initial base fee (1 Gwei in wei).
pub const DEFAULT_INITIAL_BASE_FEE: u64 = 1_000_000_000;

// ── On-disk format ────────────────────────────────────────────────────────

/// Genesis configuration, matching the on-disk `genesis.json` format.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GenesisConfig {
    /// Unique numeric chain ID (used in EIP-155 tx signing).
    pub chain_id: u64,
    /// Human-readable chain name (e.g. `"iona-testnet-1"`).
    #[serde(default)]
    pub chain_name: String,
    /// Validators with their seeds and voting power.
    pub validators: Vec<GenesisValidator>,
    /// Initial protocol version.
    #[serde(default = "default_protocol_version")]
    pub protocol_version: u32,
    /// Initial base fee per gas (wei).
    #[serde(default = "default_base_fee")]
    pub initial_base_fee: u64,
    /// Stake per validator (for the slashing ledger).
    #[serde(default = "default_stake")]
    pub stake_each: u64,
    /// Unix timestamp of the genesis block.
    ///
    /// **Do not** default this to wall-clock time — that would make the
    /// genesis hash non-deterministic across nodes that load the same file.
    /// A missing value becomes `0`.
    #[serde(default)]
    pub genesis_time: u64,
    /// Pre-funded accounts: 0x-prefixed 20-byte hex → balance in wei.
    ///
    /// Uses `BTreeMap` (sorted) rather than `HashMap` so the canonical
    /// serialization — and therefore `genesis_hash` — is deterministic.
    #[serde(default)]
    pub alloc: BTreeMap<String, GenesisAlloc>,
}

/// Pre-funded account entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GenesisAlloc {
    /// Balance in wei as a decimal string (e.g. `"1000000000000000000"`).
    pub balance: String,
    /// Account nonce at genesis.
    #[serde(default)]
    pub nonce: u64,
}

/// Validator entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GenesisValidator {
    /// Deterministic seed for key derivation.
    ///
    /// **Demo only** — production genesis files must set `pubkey_hex`.
    /// When `pubkey_hex` is `Some`, the seed is ignored.
    #[serde(default)]
    pub seed: u64,
    /// Voting power (stake weight in consensus).
    #[serde(default = "default_power")]
    pub power: VotingPower,
    /// Human-readable label.
    #[serde(default)]
    pub name: String,
    /// Explicit hex-encoded Ed25519 public key (32 bytes, optional `0x` prefix).
    /// Overrides the seed-derived key when present.
    #[serde(default)]
    pub pubkey_hex: Option<String>,
    /// P2P address (e.g. `"/ip4/127.0.0.1/tcp/7001"`).
    #[serde(default)]
    pub p2p_addr: Option<String>,
    /// RPC endpoint (e.g. `"http://127.0.0.1:8545"`).
    #[serde(default)]
    pub rpc_addr: Option<String>,
}

fn default_protocol_version() -> u32 {
    1
}
fn default_base_fee() -> u64 {
    DEFAULT_INITIAL_BASE_FEE
}
fn default_stake() -> u64 {
    DEFAULT_STAKE_EACH
}
fn default_power() -> VotingPower {
    1
}

// ── Core methods ─────────────────────────────────────────────────────────

impl GenesisConfig {
    /// Load genesis from a JSON file **and validate it**.
    ///
    /// Rejects structurally valid JSON that is semantically broken (no
    /// validators, invalid hex, duplicate keys, etc.). If you need the raw
    /// parsed value without validation, use [`serde_json::from_str`] directly.
    pub fn load(path: impl AsRef<Path>) -> io::Result<Self> {
        let s = fs::read_to_string(path.as_ref())?;
        let cfg: Self = serde_json::from_str(&s).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("genesis.json parse: {e}"),
            )
        })?;
        cfg.validate().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("genesis.json validation: {e}"),
            )
        })?;
        Ok(cfg)
    }

    /// Save genesis to a JSON file (pretty-printed).
    ///
    /// Creates parent directories if needed. Does **not** validate first —
    /// call [`validate`](Self::validate) explicitly if you need to.
    pub fn save(&self, path: impl AsRef<Path>) -> io::Result<()> {
        let out = serde_json::to_string_pretty(self).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("genesis.json encode: {e}"),
            )
        })?;
        if let Some(parent) = path.as_ref().parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        fs::write(path, out)?;
        Ok(())
    }

    /// Compute the deterministic 32-byte genesis hash.
    ///
    /// All nodes MUST produce the same hash from the same genesis.json.
    /// Nodes refuse to connect to peers with a different genesis hash.
    ///
    /// # Panics
    ///
    /// Never panics: serialization is over a `#[derive(Serialize)]` struct
    /// with no fallible `Serialize` impls in its field types, so `to_vec`
    /// cannot fail in practice. If it somehow does, we panic explicitly
    /// rather than silently hashing an empty buffer.
    pub fn genesis_hash(&self) -> [u8; 32] {
        let canonical = serde_json::to_vec(self)
            .expect("GenesisConfig serialization is infallible by construction");
        let mut h = Keccak256::new();
        h.update(format!("IONA_GENESIS_{GENESIS_SCHEMA_VERSION}:").as_bytes());
        h.update(&canonical);
        h.finalize().into()
    }

    /// Genesis hash as a `0x`-prefixed hex string.
    pub fn genesis_hash_hex(&self) -> String {
        format!("0x{}", hex::encode(self.genesis_hash()))
    }

    /// Resolve a validator's Ed25519 public key.
    fn resolve_pubkey(gv: &GenesisValidator) -> Result<PublicKeyBytes, String> {
        if let Some(pk_hex) = &gv.pubkey_hex {
            let trimmed = pk_hex.trim_start_matches("0x");
            let bytes = hex::decode(trimmed)
                .map_err(|e| format!("validator {:?}: pubkey_hex not hex: {e}", gv.name))?;
            if bytes.len() != 32 {
                return Err(format!(
                    "validator {:?}: pubkey_hex must decode to 32 bytes, got {}",
                    gv.name,
                    bytes.len()
                ));
            }
            Ok(PublicKeyBytes(bytes))
        } else {
            let mut seed = [0u8; 32];
            seed[..8].copy_from_slice(&gv.seed.to_le_bytes());
            let kp = Ed25519Keypair::from_seed(seed);
            Ok(kp.public_key())
        }
    }

    /// Build the initial `ValidatorSet` from this genesis config.
    ///
    /// Returns an error if the config is invalid; prefer this over relying on
    /// [`validate`](Self::validate) being called separately.
    pub fn validator_set(&self) -> Result<ValidatorSet, String> {
        self.validate()?;
        let mut vals = Vec::with_capacity(self.validators.len());
        for gv in &self.validators {
            vals.push(Validator {
                pk: Self::resolve_pubkey(gv)?,
                power: gv.power,
            });
        }
        Ok(ValidatorSet { vals })
    }

    /// Load if the file exists, otherwise generate and save a testnet genesis.
    ///
    /// Idempotent: calling this twice with the same arguments does not
    /// regenerate an existing file.
    pub fn load_or_generate(
        path: impl AsRef<Path>,
        n_validators: usize,
        chain_id: u64,
    ) -> io::Result<Self> {
        let p = path.as_ref();
        if p.exists() {
            Self::load(p)
        } else {
            let cfg = Self::generate_testnet(n_validators, chain_id)?;
            cfg.save(p)?;
            info!(
                path = %p.display(),
                hash = cfg.genesis_hash_hex(),
                "Generated new testnet genesis"
            );
            Ok(cfg)
        }
    }

    /// Generate a standard N-validator testnet genesis with sane defaults.
    ///
    /// - `chain_id`: unique per testnet (prevents replay across testnets).
    /// - Validators: seeds `1..=N`, equal power `1`.
    /// - Pre-funded faucet: 1,000,000 ETH to [`FAUCET_ADDRESS`].
    /// - Base fee: 1 Gwei.
    ///
    /// # Errors
    ///
    /// Returns an error if `n_validators` is `0` or exceeds
    /// [`MAX_TESTNET_VALIDATORS`].
    pub fn generate_testnet(n_validators: usize, chain_id: u64) -> io::Result<Self> {
        if n_validators == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "n_validators must be > 0",
            ));
        }
        if n_validators > MAX_TESTNET_VALIDATORS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "n_validators must be <= {} (got {})",
                    MAX_TESTNET_VALIDATORS, n_validators
                ),
            ));
        }
        if chain_id == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "chain_id must be > 0",
            ));
        }

        let validators = (1..=n_validators as u64)
            .map(|i| GenesisValidator {
                seed: i,
                power: 1,
                name: format!("val{i}"),
                pubkey_hex: None,
                p2p_addr: Some(format!("/ip4/127.0.0.1/tcp/{}", 7000 + i * 10)),
                rpc_addr: Some(format!("http://127.0.0.1:{}", 8540 + i)),
            })
            .collect();

        let mut alloc = BTreeMap::new();
        alloc.insert(
            FAUCET_ADDRESS.to_string(),
            GenesisAlloc {
                balance: FAUCET_BALANCE_WEI.to_string(),
                nonce: 0,
            },
        );

        Ok(Self {
            chain_id,
            chain_name: format!("iona-testnet-{chain_id}"),
            validators,
            protocol_version: 1,
            initial_base_fee: DEFAULT_INITIAL_BASE_FEE,
            stake_each: DEFAULT_STAKE_EACH,
            genesis_time: current_unix_secs(),
            alloc,
        })
    }

    /// Thorough validation of a genesis config.
    ///
    /// Called automatically by [`load`](Self::load) and
    /// [`validator_set`](Self::validator_set). Call it explicitly after
    /// programmatic construction.
    pub fn validate(&self) -> Result<(), String> {
        if self.chain_id == 0 {
            return Err("genesis: chain_id must be > 0".into());
        }
        if self.validators.is_empty() {
            return Err("genesis: no validators".into());
        }
        if self.validators.len() > MAX_TESTNET_VALIDATORS {
            return Err(format!(
                "genesis: too many validators ({} > {})",
                self.validators.len(),
                MAX_TESTNET_VALIDATORS
            ));
        }
        if self.protocol_version == 0 {
            return Err("genesis: protocol_version must be > 0".into());
        }

        // Voting power.
        let total_power: VotingPower = self
            .validators
            .iter()
            .try_fold(0u64, |acc, v| acc.checked_add(v.power))
            .ok_or_else(|| "genesis: total voting power overflow".to_string())?;
        if total_power == 0 {
            return Err("genesis: total voting power is 0".into());
        }
        for (i, v) in self.validators.iter().enumerate() {
            if v.power == 0 {
                return Err(format!("genesis: validator #{i} has zero power"));
            }
        }

        // Duplicate seed detection (only meaningful when pubkey_hex is absent).
        let mut seeds = std::collections::HashSet::new();
        for v in &self.validators {
            if v.pubkey_hex.is_none() && !seeds.insert(v.seed) {
                return Err(format!("genesis: duplicate validator seed {}", v.seed));
            }
        }

        // Pubkey resolution + duplicate pubkey detection.
        let mut pubkeys = std::collections::HashSet::new();
        for v in &self.validators {
            let pk = Self::resolve_pubkey(v)?;
            let key = hex::encode(&pk.0);
            if !pubkeys.insert(key) {
                return Err(format!(
                    "genesis: duplicate validator public key (name={:?})",
                    v.name
                ));
            }
        }

        // Alloc entries.
        for (addr, entry) in &self.alloc {
            validate_hex_address(addr)
                .map_err(|e| format!("genesis: alloc address {addr:?}: {e}"))?;
            parse_decimal_u128(&entry.balance)
                .map_err(|e| format!("genesis: alloc {addr:?} balance: {e}"))?;
        }

        Ok(())
    }

    /// Total voting power across all validators.
    ///
    /// Returns `0` if the sum would overflow (defensive; `validate` rejects
    /// such configs).
    #[must_use]
    pub fn total_power(&self) -> VotingPower {
        self.validators
            .iter()
            .try_fold(0u64, |acc, v| acc.checked_add(v.power))
            .unwrap_or(0)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────

fn current_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Validate a `0x`-prefixed 20-byte hex address (ETH-style).
fn validate_hex_address(addr: &str) -> Result<(), String> {
    let trimmed = addr
        .strip_prefix("0x")
        .or_else(|| addr.strip_prefix("0X"))
        .ok_or_else(|| "must start with 0x".to_string())?;
    if trimmed.len() != 40 {
        return Err(format!(
            "must be 40 hex chars after 0x (got {})",
            trimmed.len()
        ));
    }
    if !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("contains non-hex characters".into());
    }
    Ok(())
}

/// Parse a decimal string as `u128`.
fn parse_decimal_u128(s: &str) -> Result<u128, String> {
    if s.is_empty() {
        return Err("empty string".into());
    }
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("not a decimal integer: {s:?}"));
    }
    s.parse::<u128>()
        .map_err(|e| format!("does not fit in u128: {e}"))
}

// ── Testnet config file generator ────────────────────────────────────────

/// Generate per-node `config.toml` files for a local testnet.
///
/// Creates:
/// - `{out_dir}/genesis.json`
/// - `{out_dir}/node{i}/config.toml` and `{out_dir}/node{i}/data/`
/// - `{out_dir}/run_testnet.sh` (mode 0755 on Unix)
pub fn generate_testnet_configs(
    out_dir: impl AsRef<Path>,
    n_validators: usize,
    chain_id: u64,
) -> io::Result<()> {
    if n_validators == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "n_validators must be > 0",
        ));
    }
    if n_validators > MAX_TESTNET_VALIDATORS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("n_validators must be <= {MAX_TESTNET_VALIDATORS}"),
        ));
    }

    let dir = out_dir.as_ref();
    fs::create_dir_all(dir)?;

    let genesis = GenesisConfig::generate_testnet(n_validators, chain_id)?;
    genesis.save(dir.join("genesis.json"))?;

    let genesis_hash = genesis.genesis_hash_hex();
    let peers: Vec<String> = (1..=n_validators as u64)
        .map(|i| format!("/ip4/127.0.0.1/tcp/{}", 7000 + i * 10))
        .collect();

    for i in 1..=n_validators {
        let node_dir = dir.join(format!("node{i}"));
        fs::create_dir_all(&node_dir)?;
        fs::create_dir_all(node_dir.join("data"))?;

        let p2p_port = 7000 + i as u64 * 10;
        let rpc_port = 8540 + i as u64;
        let admin_port = 9000 + i as u64;
        let metrics_port = 9090 + i as u64;

        // All peers except self.
        let peer_list: Vec<&String> = peers
            .iter()
            .enumerate()
            .filter(|(idx, _)| *idx + 1 != i)
            .map(|(_, p)| p)
            .collect();
        let peers_str = peer_list
            .iter()
            .map(|p| format!("\"{p}\""))
            .collect::<Vec<_>>()
            .join(", ");

        let config = format!(
            r#"# IONA v30 — Node {i} config (auto-generated)
# Genesis hash: {genesis_hash}

[node]
data_dir          = "{}"
seed              = {i}
chain_id          = {chain_id}
log_level         = "info"
genesis_file      = "{}"
keystore          = "plain"
keystore_password = ""

[network]
listen               = "/ip4/0.0.0.0/tcp/{p2p_port}"
peers                = [{peers_str}]
enable_mdns          = false
max_peers            = 50
reconnect_interval_s = 30

[rpc]
# SECURITY: loopback only by default.
listen          = "127.0.0.1:{rpc_port}"
enable_faucet   = true
cors_allow_all  = false

[admin]
listen = "127.0.0.1:{admin_port}"

[consensus]
stake_each           = 1000000
propose_timeout_ms   = 300
prevote_timeout_ms   = 200
precommit_timeout_ms = 200
max_txs_per_block    = 4096
fast_quorum          = true

[storage]
persist_interval_secs = 5

[metrics]
enabled = true
listen  = "127.0.0.1:{metrics_port}"
"#,
            node_dir.join("data").display(),
            dir.join("genesis.json").display(),
        );

        fs::write(node_dir.join("config.toml"), config)?;
    }

    // Run script.
    let run_script = format!(
        r#"#!/usr/bin/env bash
# Start all {n_validators} testnet nodes locally.
# Genesis hash: {genesis_hash}
set -euo pipefail

PIDS=()
cleanup() {{ kill "${{PIDS[@]}}" 2>/dev/null || true; }}
trap cleanup EXIT INT TERM

for i in $(seq 1 {n_validators}); do
    iona-node --config "node$i/config.toml" &
    PIDS+=("$!")
    echo "Started node$i (PID=${{PIDS[-1]}})"
    sleep 0.5
done

echo "Testnet running. Press Ctrl+C to stop."
wait
"#
    );
    let run_path = dir.join("run_testnet.sh");
    fs::write(&run_path, run_script)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&run_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&run_path, perms)?;
    }

    info!(
        dir = %dir.display(),
        genesis_hash = %genesis_hash,
        "testnet configs generated"
    );
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    // ── Determinism ─────────────────────────────────────────────────────

    #[test]
    fn genesis_hash_is_clone_stable() {
        let g1 = GenesisConfig::generate_testnet(4, 6126151).unwrap();
        let g2 = g1.clone();
        assert_eq!(g1.genesis_hash_hex(), g2.genesis_hash_hex());
    }

    #[test]
    fn genesis_hash_survives_json_roundtrip() {
        // Regression: with `HashMap<String, _>` for `alloc`, two processes
        // could iterate the map in different orders, producing different
        // hashes. `BTreeMap` fixes this.
        let g1 = GenesisConfig::generate_testnet(4, 9999).unwrap();
        let json = serde_json::to_string(&g1).unwrap();
        let g2: GenesisConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(g1, g2);
        assert_eq!(g1.genesis_hash_hex(), g2.genesis_hash_hex());
    }

    #[test]
    fn genesis_hash_ignores_map_insertion_order() {
        // Two configs with the same alloc entries inserted in different
        // orders must hash identically (BTreeMap sorts on serialize).
        let mut a = GenesisConfig::generate_testnet(1, 42).unwrap();
        let mut b = a.clone();

        a.alloc.insert(
            "0x000000000000000000000000000000000000000a".into(),
            GenesisAlloc { balance: "1".into(), nonce: 0 },
        );
        a.alloc.insert(
            "0x000000000000000000000000000000000000000b".into(),
            GenesisAlloc { balance: "2".into(), nonce: 0 },
        );

        // Reverse insertion order on b.
        b.alloc.insert(
            "0x000000000000000000000000000000000000000b".into(),
            GenesisAlloc { balance: "2".into(), nonce: 0 },
        );
        b.alloc.insert(
            "0x000000000000000000000000000000000000000a".into(),
            GenesisAlloc { balance: "1".into(), nonce: 0 },
        );

        assert_eq!(a.genesis_hash_hex(), b.genesis_hash_hex());
    }

    #[test]
    fn genesis_hash_missing_time_defaults_to_zero() {
        // Regression: `genesis_time` used to default to `SystemTime::now()`
        // on every load, which broke determinism across processes.
        let json = r#"{
            "chain_id": 1,
            "validators": [{"seed": 1, "power": 1, "name": "v1"}]
        }"#;
        let a: GenesisConfig = serde_json::from_str(json).unwrap();
        let b: GenesisConfig = serde_json::from_str(json).unwrap();
        assert_eq!(a.genesis_time, 0);
        assert_eq!(a.genesis_hash_hex(), b.genesis_hash_hex());
    }

    #[test]
    fn genesis_hash_changes_with_content() {
        let a = GenesisConfig::generate_testnet(4, 9999).unwrap();
        let mut b = a.clone();
        b.chain_id = 10000;
        assert_ne!(a.genesis_hash_hex(), b.genesis_hash_hex());
    }

    // ── Validation ──────────────────────────────────────────────────────

    #[test]
    fn genesis_validate_ok() {
        let g = GenesisConfig::generate_testnet(4, 9999).unwrap();
        assert!(g.validate().is_ok());
    }

    #[test]
    fn genesis_validate_no_validators() {
        let mut g = GenesisConfig::generate_testnet(4, 9999).unwrap();
        g.validators.clear();
        assert!(g.validate().is_err());
    }

    #[test]
    fn genesis_validate_zero_chain_id() {
        let mut g = GenesisConfig::generate_testnet(4, 9999).unwrap();
        g.chain_id = 0;
        assert!(g.validate().is_err());
    }

    #[test]
    fn genesis_validate_zero_power() {
        let mut g = GenesisConfig::generate_testnet(2, 9999).unwrap();
        g.validators[0].power = 0;
        assert!(g.validate().is_err());
    }

    #[test]
    fn genesis_validate_duplicate_seed() {
        let mut g = GenesisConfig::generate_testnet(2, 9999).unwrap();
        g.validators[1].seed = g.validators[0].seed;
        assert!(g.validate().is_err());
    }

    #[test]
    fn genesis_validate_duplicate_pubkey() {
        let mut g = GenesisConfig::generate_testnet(2, 9999).unwrap();
        let pk = format!("0x{}", hex::encode([0xAAu8; 32]));
        g.validators[0].pubkey_hex = Some(pk.clone());
        g.validators[1].pubkey_hex = Some(pk);
        assert!(g.validate().is_err());
    }

    #[test]
    fn genesis_validate_bad_pubkey_hex() {
        let mut g = GenesisConfig::generate_testnet(1, 9999).unwrap();
        // Regression: bad hex used to silently become `[0u8; 32]`.
        g.validators[0].pubkey_hex = Some("0xzzzz".into());
        let err = g.validate().unwrap_err();
        assert!(err.contains("not hex"), "got: {err}");
    }

    #[test]
    fn genesis_validate_pubkey_wrong_length() {
        let mut g = GenesisConfig::generate_testnet(1, 9999).unwrap();
        g.validators[0].pubkey_hex = Some("0xaabb".into());
        let err = g.validate().unwrap_err();
        assert!(err.contains("32 bytes"), "got: {err}");
    }

    #[test]
    fn genesis_validate_bad_alloc_address() {
        let mut g = GenesisConfig::generate_testnet(1, 9999).unwrap();
        g.alloc
            .insert("not-an-address".into(), GenesisAlloc { balance: "1".into(), nonce: 0 });
        assert!(g.validate().is_err());
    }

    #[test]
    fn genesis_validate_bad_alloc_balance() {
        let mut g = GenesisConfig::generate_testnet(1, 9999).unwrap();
        g.alloc.insert(
            "0x0000000000000000000000000000000000000001".into(),
            GenesisAlloc { balance: "not-a-number".into(), nonce: 0 },
        );
        assert!(g.validate().is_err());
    }

    #[test]
    fn genesis_validate_faucet_address_is_valid_hex() {
        // Regression: `0xFAuCET…` was not hex.
        validate_hex_address(FAUCET_ADDRESS).expect("faucet must be valid hex");
    }

    #[test]
    fn genesis_validate_rejects_too_many_validators() {
        // Construct in memory without generating (generation has its own guard).
        let mut g = GenesisConfig::generate_testnet(1, 1).unwrap();
        g.validators = (0..(MAX_TESTNET_VALIDATORS as u64 + 1))
            .map(|i| GenesisValidator {
                seed: i,
                power: 1,
                name: format!("v{i}"),
                pubkey_hex: None,
                p2p_addr: None,
                rpc_addr: None,
            })
            .collect();
        assert!(g.validate().is_err());
    }

    // ── Generator ───────────────────────────────────────────────────────

    #[test]
    fn generate_rejects_zero_validators() {
        assert!(GenesisConfig::generate_testnet(0, 1).is_err());
    }

    #[test]
    fn generate_rejects_too_many_validators() {
        assert!(GenesisConfig::generate_testnet(MAX_TESTNET_VALIDATORS + 1, 1).is_err());
    }

    #[test]
    fn generate_rejects_zero_chain_id() {
        assert!(GenesisConfig::generate_testnet(1, 0).is_err());
    }

    #[test]
    fn generate_is_deterministic_for_fixed_time() {
        // Two generations share the same wall-clock second in practice; even
        // if they don't, we can override `genesis_time` to make it explicit.
        let mut a = GenesisConfig::generate_testnet(3, 42).unwrap();
        let mut b = GenesisConfig::generate_testnet(3, 42).unwrap();
        a.genesis_time = 0;
        b.genesis_time = 0;
        assert_eq!(a.genesis_hash_hex(), b.genesis_hash_hex());
    }

    #[test]
    fn generate_testnet_configs_rejects_zero() {
        let dir = tempdir().unwrap();
        assert!(generate_testnet_configs(dir.path(), 0, 1).is_err());
    }

    // ── Validator set ───────────────────────────────────────────────────

    #[test]
    fn validator_set_from_genesis() {
        let g = GenesisConfig::generate_testnet(4, 9999).unwrap();
        let vs = g.validator_set().unwrap();
        assert_eq!(vs.vals.len(), 4);
    }

    #[test]
    fn validator_set_rejects_invalid_genesis() {
        let mut g = GenesisConfig::generate_testnet(2, 9999).unwrap();
        g.validators[0].pubkey_hex = Some("0xnothex".into());
        assert!(g.validator_set().is_err());
    }

    #[test]
    fn validator_set_pubkey_hex_overrides_seed() {
        let mut g = GenesisConfig::generate_testnet(1, 9999).unwrap();
        let explicit = hex::encode([0xCDu8; 32]);
        g.validators[0].pubkey_hex = Some(format!("0x{explicit}"));
        let vs = g.validator_set().unwrap();
        assert_eq!(vs.vals[0].pk.0, vec![0xCDu8; 32]);
    }

    // ── Disk ────────────────────────────────────────────────────────────

    #[test]
    fn load_or_generate_is_idempotent() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("genesis.json");
        let a = GenesisConfig::load_or_generate(&path, 3, 42).unwrap();
        let b = GenesisConfig::load_or_generate(&path, 3, 42).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.genesis_hash_hex(), b.genesis_hash_hex());
    }

    #[test]
    fn load_validates() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("bad_genesis.json");
        fs::write(
            &path,
            r#"{"chain_id":0,"validators":[]}"#,
        )
        .unwrap();
        assert!(GenesisConfig::load(&path).is_err());
    }

    #[test]
    fn save_creates_parent_directories() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a").join("b").join("genesis.json");
        let g = GenesisConfig::generate_testnet(1, 1).unwrap();
        g.save(&path).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn save_load_roundtrip_preserves_hash() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("genesis.json");
        let a = GenesisConfig::generate_testnet(5, 12345).unwrap();
        a.save(&path).unwrap();
        let b = GenesisConfig::load(&path).unwrap();
        assert_eq!(a.genesis_hash_hex(), b.genesis_hash_hex());
    }

    // ── Config generation ───────────────────────────────────────────────

    #[test]
    fn generate_testnet_configs_succeeds() {
        let dir = tempdir().unwrap();
        generate_testnet_configs(dir.path(), 3, 42).unwrap();
        for i in 1..=3 {
            let node_dir = dir.path().join(format!("node{i}"));
            assert!(node_dir.join("config.toml").exists());
            assert!(node_dir.join("data").exists());
        }
        assert!(dir.path().join("genesis.json").exists());
        assert!(dir.path().join("run_testnet.sh").exists());
    }

    #[cfg(unix)]
    #[test]
    fn run_script_is_executable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        generate_testnet_configs(dir.path(), 2, 42).unwrap();
        let meta = fs::metadata(dir.path().join("run_testnet.sh")).unwrap();
        assert_ne!(meta.permissions().mode() & 0o111, 0);
    }
}
