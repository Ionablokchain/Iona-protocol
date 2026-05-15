//! STEP 3 — Strict config + genesis validation at boot.
//!
//! Node MUST NOT start if any of these fail:
//! - Bootnodes invalid (malformed multiaddr)
//! - Chain ID mismatch (config vs genesis)
//! - Stake config invalid (zero or negative)
//! - simple_producer conflict (follower/RPC running as producer)
//! - Genesis mismatch (hash differs from expected)
//! - Genesis hash check at boot
//!
//! All failures are **fatal** — not warnings.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use thiserror::Error;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Minimum parts expected in a multiaddress (including empty first part).
const MIN_MULTIADDR_PARTS: usize = 5;

/// Supported protocol names for multiaddress.
const PROTOCOL_IP4: &str = "ip4";
const PROTOCOL_IP6: &str = "ip6";
const PROTOCOL_DNS4: &str = "dns4";
const PROTOCOL_DNS6: &str = "dns6";

/// Protocol name for TCP.
const PROTOCOL_TCP: &str = "tcp";

/// Protocol name for P2P peer ID.
const PROTOCOL_P2P: &str = "p2p";

/// Default listen port for RPC (used in self‑bootstrap detection).
const DEFAULT_RPC_PORT: u16 = 9001;

// -----------------------------------------------------------------------------
// Error types
// -----------------------------------------------------------------------------

/// Fatal validation error that prevents node startup.
#[derive(Debug, Error)]
pub enum BootstrapError {
    #[error("invalid bootnode at index {index}: {reason}")]
    InvalidBootnode { index: usize, reason: String },

    #[error("duplicate bootnode entries")]
    DuplicateBootnodes,

    #[error("self‑bootstrap detected: node appears to bootstrap from its own address")]
    SelfBootstrap,

    #[error("chain ID mismatch: config={config}, genesis={genesis}")]
    ChainIdMismatch { config: u64, genesis: u64 },

    #[error("invalid stake_each: must be > 0, got {stake}")]
    ZeroStake { stake: u64 },

    #[error("simple_producer conflict: node seed {seed} is not in validator set {validators:?}")]
    SimpleProducerConflict { seed: u64, validators: Vec<u64> },

    #[error("empty RPC listen address")]
    EmptyListenAddress,

    #[error("genesis file error: {reason}")]
    GenesisFile { reason: String },

    #[error("genesis hash mismatch: expected {expected}, got {actual}")]
    GenesisHashMismatch { expected: String, actual: String },
}

pub type BootstrapResult<T> = Result<T, BootstrapError>;

// -----------------------------------------------------------------------------
// Validation functions
// -----------------------------------------------------------------------------

/// Validate a bootnode multiaddr string.
/// Valid formats: `/ip4/X.X.X.X/tcp/PORT` or `/ip4/X.X.X.X/tcp/PORT/p2p/PEERID`
/// or `/dns4/HOST/tcp/PORT/p2p/PEERID`
fn validate_bootnode(addr: &str, index: usize) -> BootstrapResult<()> {
    if addr.is_empty() {
        return Err(BootstrapError::InvalidBootnode {
            index,
            reason: "empty bootnode address".into(),
        });
    }

    let parts: Vec<&str> = addr.split('/').collect();
    if parts.len() < MIN_MULTIADDR_PARTS {
        return Err(BootstrapError::InvalidBootnode {
            index,
            reason: format!("malformed multiaddr (too few parts): {addr}"),
        });
    }

    // First part should be empty (leading /).
    if !parts[0].is_empty() {
        return Err(BootstrapError::InvalidBootnode {
            index,
            reason: format!("multiaddr must start with /: {addr}"),
        });
    }

    // Check protocol prefix.
    match parts[1] {
        PROTOCOL_IP4 => {
            let ip = parts[2];
            let octets: Vec<&str> = ip.split('.').collect();
            if octets.len() != 4 {
                return Err(BootstrapError::InvalidBootnode {
                    index,
                    reason: format!("invalid IPv4 address: {ip}"),
                });
            }
            for octet in &octets {
                if octet.parse::<u8>().is_err() {
                    return Err(BootstrapError::InvalidBootnode {
                        index,
                        reason: format!("invalid IPv4 octet: {octet}"),
                    });
                }
            }
        }
        PROTOCOL_DNS4 | PROTOCOL_DNS6 => {
            if parts[2].is_empty() {
                return Err(BootstrapError::InvalidBootnode {
                    index,
                    reason: "empty DNS hostname".into(),
                });
            }
        }
        PROTOCOL_IP6 => {
            // IPv6 is accepted without detailed validation
        }
        other => {
            return Err(BootstrapError::InvalidBootnode {
                index,
                reason: format!("unsupported multiaddr protocol: {other}"),
            });
        }
    }

    // Check for /tcp/PORT.
    if parts.len() >= MIN_MULTIADDR_PARTS && parts[3] == PROTOCOL_TCP {
        let port = parts[4];
        if port.parse::<u16>().is_err() {
            return Err(BootstrapError::InvalidBootnode {
                index,
                reason: format!("invalid TCP port: {port}"),
            });
        }
    }

    Ok(())
}

/// Validate the full node configuration. Returns `Ok(())` on success.
pub fn validate_config(
    chain_id_config: u64,
    chain_id_genesis: Option<u64>,
    bootnodes: &[String],
    stake_each: u64,
    simple_producer: bool,
    node_seed: u64,
    genesis_validator_seeds: &[u64],
    listen_addr: &str,
) -> BootstrapResult<()> {
    // 1. Validate bootnodes.
    for (i, bn) in bootnodes.iter().enumerate() {
        validate_bootnode(bn, i)?;
    }

    // 2. Check for duplicate bootnodes.
    let unique: BTreeSet<&str> = bootnodes.iter().map(|s| s.as_str()).collect();
    if unique.len() < bootnodes.len() {
        return Err(BootstrapError::DuplicateBootnodes);
    }

    // 3. Check for self‑bootstrap (node's own address in bootnodes).
    let listen_port = listen_addr
        .rsplit(':')
        .next()
        .unwrap_or("")
        .chars()
        .filter(|c| c.is_ascii_digit())
        .collect::<String>();
    let listen_port_u16 = listen_port.parse::<u16>().unwrap_or(DEFAULT_RPC_PORT);
    for bn in bootnodes {
        if bn.contains("127.0.0.1") && bn.contains(&listen_port_u16.to_string()) {
            return Err(BootstrapError::SelfBootstrap);
        }
    }

    // 4. Chain ID mismatch.
    if let Some(genesis_chain_id) = chain_id_genesis {
        if chain_id_config != genesis_chain_id {
            return Err(BootstrapError::ChainIdMismatch {
                config: chain_id_config,
                genesis: genesis_chain_id,
            });
        }
    }

    // 5. Stake config invalid.
    if stake_each == 0 {
        return Err(BootstrapError::ZeroStake { stake: stake_each });
    }

    // 6. simple_producer conflict.
    if simple_producer && !genesis_validator_seeds.is_empty() {
        let is_validator = genesis_validator_seeds.contains(&node_seed);
        if !is_validator {
            return Err(BootstrapError::SimpleProducerConflict {
                seed: node_seed,
                validators: genesis_validator_seeds.to_vec(),
            });
        }
    }

    // 7. Listen address validation.
    if listen_addr.is_empty() {
        return Err(BootstrapError::EmptyListenAddress);
    }

    Ok(())
}

// -----------------------------------------------------------------------------
// Genesis validation
// -----------------------------------------------------------------------------

/// Compute a genesis hash using SHA‑256 of the canonical JSON representation.
pub fn genesis_hash(genesis_json: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(genesis_json.as_bytes());
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Verify genesis file integrity.
/// Compares the hash of the genesis file against an expected hash.
pub fn verify_genesis_integrity(
    genesis_path: impl AsRef<Path>,
    expected_hash: Option<&[u8; 32]>,
) -> BootstrapResult<[u8; 32]> {
    let content = std::fs::read_to_string(genesis_path.as_ref())
        .map_err(|e| BootstrapError::GenesisFile {
            reason: format!("cannot read genesis: {e}"),
        })?;

    let hash = genesis_hash(&content);

    if let Some(expected) = expected_hash {
        if hash != *expected {
            return Err(BootstrapError::GenesisHashMismatch {
                expected: hex::encode(expected),
                actual: hex::encode(hash),
            });
        }
    }

    Ok(hash)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_validate_bootnode_valid() {
        assert!(validate_bootnode("/ip4/1.2.3.4/tcp/7001", 0).is_ok());
        assert!(validate_bootnode("/ip4/192.168.1.1/tcp/30333/p2p/12D3KooW", 0).is_ok());
        assert!(validate_bootnode("/dns4/node.example.com/tcp/7001", 0).is_ok());
    }

    #[test]
    fn test_validate_bootnode_invalid() {
        assert!(validate_bootnode("", 0).is_err());
        assert!(validate_bootnode("not-a-multiaddr", 0).is_err());
        assert!(validate_bootnode("/ip4/999.999.999.999/tcp/7001", 0).is_err());
        assert!(validate_bootnode("/ip4/1.2.3.4/tcp/99999", 0).is_err());
        assert!(validate_bootnode("/ip4/1.2.3.4", 0).is_err());
    }

    #[test]
    fn test_config_valid() {
        let result = validate_config(
            6126151,
            Some(6126151),
            &["/ip4/1.2.3.4/tcp/7001".into()],
            1000,
            true,
            2,
            &[2, 3, 4],
            "0.0.0.0:9001",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_chain_id_mismatch() {
        let result = validate_config(
            6126151,
            Some(9999),
            &[],
            1000,
            false,
            1,
            &[],
            "0.0.0.0:9001",
        );
        assert!(matches!(
            result.unwrap_err(),
            BootstrapError::ChainIdMismatch { config: 6126151, genesis: 9999 }
        ));
    }

    #[test]
    fn test_invalid_bootnode() {
        let result = validate_config(
            6126151,
            None,
            &["not-valid".into()],
            1000,
            false,
            1,
            &[],
            "0.0.0.0:9001",
        );
        assert!(matches!(
            result.unwrap_err(),
            BootstrapError::InvalidBootnode { index: 0, .. }
        ));
    }

    #[test]
    fn test_zero_stake() {
        let result = validate_config(
            6126151,
            None,
            &[],
            0,
            false,
            1,
            &[],
            "0.0.0.0:9001",
        );
        assert!(matches!(result.unwrap_err(), BootstrapError::ZeroStake { stake: 0 }));
    }

    #[test]
    fn test_simple_producer_conflict() {
        let result = validate_config(
            6126151,
            None,
            &[],
            1000,
            true,
            1,
            &[2, 3, 4],
            "0.0.0.0:9001",
        );
        assert!(matches!(
            result.unwrap_err(),
            BootstrapError::SimpleProducerConflict { seed: 1, .. }
        ));
    }

    #[test]
    fn test_duplicate_bootnodes() {
        let result = validate_config(
            6126151,
            None,
            &[
                "/ip4/1.2.3.4/tcp/7001".into(),
                "/ip4/1.2.3.4/tcp/7001".into(),
            ],
            1000,
            false,
            1,
            &[],
            "0.0.0.0:9001",
        );
        assert!(matches!(result.unwrap_err(), BootstrapError::DuplicateBootnodes));
    }

    #[test]
    fn test_empty_listen_addr() {
        let result = validate_config(
            6126151,
            None,
            &[],
            1000,
            false,
            1,
            &[],
            "",
        );
        assert!(matches!(result.unwrap_err(), BootstrapError::EmptyListenAddress));
    }

    #[test]
    fn test_genesis_hash_deterministic() {
        let json = r#"{"chain_id":6126151,"validators":[{"seed":2}]}"#;
        let h1 = genesis_hash(json);
        let h2 = genesis_hash(json);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_genesis_hash_different() {
        let json1 = r#"{"chain_id":6126151}"#;
        let json2 = r#"{"chain_id":9999}"#;
        assert_ne!(genesis_hash(json1), genesis_hash(json2));
    }

    #[test]
    fn test_verify_genesis_integrity() -> BootstrapResult<()> {
        let file = NamedTempFile::new().unwrap();
        let path = file.path();
        let content = r#"{"chain_id":6126151,"validators":[]}"#;
        std::fs::write(path, content).unwrap();

        let hash = verify_genesis_integrity(path, None)?;
        assert_ne!(hash, [0u8; 32]);

        // Correct hash
        assert!(verify_genesis_integrity(path, Some(&hash)).is_ok());

        // Wrong hash
        let bad = [0xFFu8; 32];
        let err = verify_genesis_integrity(path, Some(&bad)).unwrap_err();
        assert!(matches!(err, BootstrapError::GenesisHashMismatch { .. }));
        Ok(())
    }
}
