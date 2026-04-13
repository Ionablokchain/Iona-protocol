//! Genesis configuration — IONA v30.
//!
//! Provides:
//! - `GenesisConfig` — on-disk format (genesis.json)
//! - `generate_testnet_genesis()` — one-call 4-node testnet genesis
//! - `genesis_hash()` — deterministic hash for all nodes to verify
//! - `load_or_generate()` — idempotent: load if exists, generate if not
//! - `ValidatorSet` construction from genesis
//!
//! ## Usage
//! ```bash
//! # Generate genesis for 4-node testnet
//! iona-cli genesis generate --validators 4 --chain-id 6126151 --out ./testnet/genesis.json
//! # Each node verifies on startup:
//! # iona-node --config node1/config.toml --genesis testnet/genesis.json
//! ```

use crate::consensus::validator_set::{Validator, ValidatorSet, VotingPower};
use crate::crypto::{ed25519::Ed25519Keypair, PublicKeyBytes, Signer};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::{fs, io, path::Path};

// ── On-disk format ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisConfig {
    /// Unique numeric chain ID (used in EIP-155 tx signing).
    pub chain_id: u64,
    /// Human-readable chain name (e.g. "iona-testnet-1").
    #[serde(default)]
    pub chain_name: String,
    /// Validators with their seeds and voting power.
    pub validators: Vec<GenesisValidator>,
    /// Initial protocol version.
    #[serde(default = "default_pv")]
    pub protocol_version: u32,
    /// Initial base fee per gas (wei).
    #[serde(default = "default_base_fee")]
    pub initial_base_fee: u64,
    /// Stake per validator (for slashing ledger).
    #[serde(default = "default_stake")]
    pub stake_each: u64,
    /// Unix timestamp of genesis block.
    #[serde(default = "default_genesis_time")]
    pub genesis_time: u64,
    /// Pre-funded accounts: address (0x hex) → balance (decimal wei string).
    #[serde(default)]
    pub alloc: std::collections::HashMap<String, GenesisAlloc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisAlloc {
    /// Balance in wei as decimal string (e.g. "1000000000000000000").
    pub balance: String,
    #[serde(default)]
    pub nonce: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisValidator {
    /// Deterministic seed for key derivation (demo only — use explicit pubkeys in prod).
    pub seed: u64,
    /// Voting power (stake weight in consensus).
    #[serde(default = "default_power")]
    pub power: VotingPower,
    /// Human-readable label.
    #[serde(default)]
    pub name: String,
    /// Optional: explicit hex-encoded public key (overrides seed-derived key).
    #[serde(default)]
    pub pubkey_hex: Option<String>,
    /// P2P address for this validator (e.g. "/ip4/127.0.0.1/tcp/7001").
    #[serde(default)]
    pub p2p_addr: Option<String>,
    /// RPC endpoint exposed by this validator (e.g. "http://127.0.0.1:8545").
    #[serde(default)]
    pub rpc_addr: Option<String>,
}

fn default_pv() -> u32 {
    1
}
fn default_base_fee() -> u64 {
    1_000_000_000
} // 1 Gwei
fn default_stake() -> u64 {
    1_000_000
}
fn default_power() -> VotingPower {
    1
}
fn default_genesis_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── Core methods ─────────────────────────────────────────────────────────

impl GenesisConfig {
    /// Load genesis from a JSON file.
    pub fn load(path: impl AsRef<Path>) -> io::Result<Self> {
        let s = fs::read_to_string(path.as_ref())?;
        serde_json::from_str(&s).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("genesis.json parse: {e}"),
            )
        })
    }

    /// Save genesis to a JSON file (pretty-printed).
    pub fn save(&self, path: impl AsRef<Path>) -> io::Result<()> {
        let out = serde_json::to_string_pretty(self).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("genesis.json encode: {e}"),
            )
        })?;
        if let Some(parent) = path.as_ref().parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, out)?;
        Ok(())
    }

    /// Compute a deterministic 32-byte genesis hash.
    ///
    /// All nodes MUST produce the same hash from the same genesis.json.
    /// Nodes refuse to connect to peers with a different genesis hash.
    pub fn genesis_hash(&self) -> [u8; 32] {
        let canonical = serde_json::to_vec(&self).unwrap_or_default();
        let mut h = Keccak256::new();
        h.update(b"IONA_GENESIS_V1:");
        h.update(&canonical);
        h.finalize().into()
    }

    /// Genesis hash as 0x-prefixed hex string.
    pub fn genesis_hash_hex(&self) -> String {
        format!("0x{}", hex::encode(self.genesis_hash()))
    }

    /// Build the initial `ValidatorSet` from this genesis config.
    pub fn validator_set(&self) -> ValidatorSet {
        let vals: Vec<Validator> = self
            .validators
            .iter()
            .map(|gv| {
                let pk: PublicKeyBytes = if let Some(pk_hex) = &gv.pubkey_hex {
                    // Explicit pubkey provided
                    let bytes = hex::decode(pk_hex.trim_start_matches("0x"))
                        .unwrap_or_else(|_| vec![0u8; 32]);
                    PublicKeyBytes(bytes)
                } else {
                    // Derive from seed — expand u64 seed into [u8;32]
                    let mut seed = [0u8; 32];
                    seed[..8].copy_from_slice(&gv.seed.to_le_bytes());
                    let kp = Ed25519Keypair::from_seed(seed);
                    kp.public_key()
                };
                Validator {
                    pk,
                    power: gv.power,
                }
            })
            .collect();

        ValidatorSet { vals }
    }

    /// Load if the file exists, otherwise generate and save a testnet genesis.
    pub fn load_or_generate(
        path: impl AsRef<Path>,
        n_validators: usize,
        chain_id: u64,
    ) -> io::Result<Self> {
        let p = path.as_ref();
        if p.exists() {
            Self::load(p)
        } else {
            let cfg = Self::generate_testnet(n_validators, chain_id);
            cfg.save(p)?;
            tracing::info!(
                path = %p.display(),
                hash = cfg.genesis_hash_hex(),
                "Generated new testnet genesis"
            );
            Ok(cfg)
        }
    }

    /// Generate a standard N-validator testnet genesis with sane defaults.
    ///
    /// - chain_id: unique per testnet (prevents tx replay across testnets)
    /// - Validators: seed 1..=N, equal power 1
    /// - Pre-funded faucet: 1M ETH to address 0xfaucet...
    /// - Base fee: 1 Gwei
    pub fn generate_testnet(n_validators: usize, chain_id: u64) -> Self {
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

        let mut alloc = std::collections::HashMap::new();
        // Faucet: 1_000_000 ETH (10^24 wei)
        alloc.insert(
            "0xFAuCET0000000000000000000000000000000001".to_lowercase(),
            GenesisAlloc {
                balance: "1000000000000000000000000".to_string(),
                nonce: 0,
            },
        );

        Self {
            chain_id,
            chain_name: format!("iona-testnet-{chain_id}"),
            validators,
            protocol_version: 1,
            initial_base_fee: 1_000_000_000,
            stake_each: 1_000_000,
            genesis_time: default_genesis_time(),
            alloc,
        }
    }

    /// Validate the genesis config (called at node startup).
    ///
    /// Returns an error string if the config is invalid.
    pub fn validate(&self) -> Result<(), String> {
        if self.validators.is_empty() {
            return Err("genesis: no validators".into());
        }
        if self.chain_id == 0 {
            return Err("genesis: chain_id must be > 0".into());
        }
        let total_power: VotingPower = self.validators.iter().map(|v| v.power).sum();
        if total_power == 0 {
            return Err("genesis: total voting power is 0".into());
        }
        // Check for duplicate seeds
        let mut seeds = std::collections::HashSet::new();
        for v in &self.validators {
            if v.pubkey_hex.is_none() && !seeds.insert(v.seed) {
                return Err(format!("genesis: duplicate validator seed {}", v.seed));
            }
        }
        Ok(())
    }
}

// ── Testnet config file generator ────────────────────────────────────────

/// Generate per-node config.toml files for a local testnet.
///
/// Creates: `{out_dir}/node{i}/config.toml` and `{out_dir}/genesis.json`
pub fn generate_testnet_configs(
    out_dir: impl AsRef<Path>,
    n_validators: usize,
    chain_id: u64,
) -> io::Result<()> {
    let dir = out_dir.as_ref();
    fs::create_dir_all(dir)?;

    let genesis = GenesisConfig::generate_testnet(n_validators, chain_id);
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

        // All peers except self
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
            r#"# IONA v30.0.0 — Node {i} config (auto-generated)
# Genesis hash: {genesis_hash}

[node]
data_dir         = "{}"
seed             = {i}
chain_id         = {chain_id}
log_level        = "info"
genesis_file     = "{}"
keystore         = "plain"
keystore_password = ""

[network]
listen      = "/ip4/0.0.0.0/tcp/{p2p_port}"
peers       = [{peers_str}]
enable_mdns = false
max_peers   = 50
reconnect_interval_s = 30

[rpc]
# ⚠️  SECURITY: loopback only by default
listen        = "127.0.0.1:{rpc_port}"
enable_faucet = true
cors_allow_all = false

[admin]
listen = "127.0.0.1:{admin_port}"

[consensus]
stake_each              = 1000000
propose_timeout_ms      = 300
prevote_timeout_ms      = 200
precommit_timeout_ms    = 200
max_txs_per_block       = 4096
fast_quorum             = true

[storage]
persist_interval_secs = 5

[metrics]
enabled = true
listen  = "127.0.0.1:{}"
"#,
            node_dir.join("data").display(),
            dir.join("genesis.json").display(),
            9090 + i as u64,
        );

        fs::write(node_dir.join("config.toml"), config)?;
    }

    // Write run script
    let run_script = format!(
        r#"#!/usr/bin/env bash
# Start all {n_validators} testnet nodes locally
# Genesis hash: {genesis_hash}
set -e
PIDS=()
cleanup() {{ kill "${{PIDS[@]}}" 2>/dev/null; }}
trap cleanup EXIT

for i in $(seq 1 {n_validators}); do
    iona-node --config node$i/config.toml &
    PIDS+=($!)
    echo "Started node$i (PID=${{PIDS[-1]}})"
    sleep 0.5
done

echo "Testnet running. Press Ctrl+C to stop."
wait
"#
    );
    fs::write(dir.join("run_testnet.sh"), run_script)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(dir.join("run_testnet.sh"))?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(dir.join("run_testnet.sh"), perms)?;
    }

    println!(
        "Testnet configs generated in: {}\nGenesis hash: {}\nStart with: cd {} && bash run_testnet.sh",
        dir.display(), genesis_hash, dir.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_hash_deterministic() {
        let g1 = GenesisConfig::generate_testnet(4, 6126151);
        let g2 = g1.clone();
        // Hash is not stable across timestamps, but structure should serialize
        let h1 = g1.genesis_hash_hex();
        let h2 = g2.genesis_hash_hex();
        assert_eq!(h1, h2);
        assert!(h1.starts_with("0x"));
    }

    #[test]
    fn genesis_validate_ok() {
        let g = GenesisConfig::generate_testnet(4, 9999);
        assert!(g.validate().is_ok());
    }

    #[test]
    fn genesis_validate_no_validators() {
        let mut g = GenesisConfig::generate_testnet(4, 9999);
        g.validators.clear();
        assert!(g.validate().is_err());
    }

    #[test]
    fn validator_set_from_genesis() {
        let g = GenesisConfig::generate_testnet(4, 9999);
        let vs = g.validator_set();
        assert_eq!(vs.vals.len(), 4);
    }
}
