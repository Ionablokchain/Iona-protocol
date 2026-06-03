//! STEP 3 — Strict config + genesis validation at boot.
//!
//! Node MUST NOT start if any of these fail:
//! - Bootnodes invalid (malformed multiaddr)
//! - Chain ID mismatch (config vs genesis)
//! - Stake config invalid (zero or negative)
//! - simple_producer conflict (follower/RPC running as producer)
//! - Genesis mismatch (hash differs from expected)
//! - Genesis hash check at boot
//! - Listen address malformed or empty
//! - Duplicate bootnode entries
//! - Self‑bootstrap (node connecting to itself)
//!
//! All failures are **fatal** — not warnings.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use thiserror::Error;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Minimum parts expected in a multiaddress (including empty first part).
/// Format: `/<proto>/<addr>/<proto>/<port>[/<proto>/<peerid>]`
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

/// Default RPC port (used in self‑bootstrap detection as fallback).
const DEFAULT_RPC_PORT: u16 = 9001;

/// Default P2P port (used in self‑bootstrap detection as fallback).
const DEFAULT_P2P_PORT: u16 = 7001;

/// Maximum valid TCP/UDP port number.
const MAX_PORT: u16 = 65535;

/// Minimum valid TCP/UDP port number (privileged ports are allowed but warned).
const MIN_PORT: u16 = 1;

/// Localhost IPs that indicate self‑bootstrap risk.
const LOCALHOST_IPV4: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
const LOCALHOST_IPV6: Ipv6Addr = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);

// -----------------------------------------------------------------------------
// Error types
// -----------------------------------------------------------------------------

/// Fatal validation error that prevents node startup.
#[derive(Debug, Error)]
pub enum BootstrapError {
    #[error("invalid bootnode at index {index}: {reason}")]
    InvalidBootnode { index: usize, reason: String },

    #[error("duplicate bootnode entries: {duplicates:?}")]
    DuplicateBootnodes { duplicates: Vec<String> },

    #[error("self‑bootstrap detected: node appears to bootstrap from its own address ({addr})")]
    SelfBootstrap { addr: String },

    #[error("chain ID mismatch: config={config}, genesis={genesis}")]
    ChainIdMismatch { config: u64, genesis: u64 },

    #[error("invalid stake_each: must be > 0, got {stake}")]
    ZeroStake { stake: u64 },

    #[error(
        "simple_producer conflict: node seed {seed} is not in validator set {validators:?}"
    )]
    SimpleProducerConflict { seed: u64, validators: Vec<u64> },

    #[error("empty or malformed listen address: '{addr}'")]
    InvalidListenAddress { addr: String },

    #[error("genesis file error: {reason}")]
    GenesisFile { reason: String },

    #[error("genesis hash mismatch: expected {expected}, got {actual}")]
    GenesisHashMismatch { expected: String, actual: String },

    #[error("genesis file is empty")]
    EmptyGenesis,

    #[error("invalid port number: {port} (must be {min}..{max})")]
    InvalidPort { port: u16, min: u16, max: u16 },
}

pub type BootstrapResult<T> = Result<T, BootstrapError>;

// -----------------------------------------------------------------------------
// Multiaddr parsing helpers
// -----------------------------------------------------------------------------

/// Parsed multiaddress components.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedMultiaddr {
    protocol: String,
    host: String,
    port: u16,
    peer_id: Option<String>,
}

/// Parse a multiaddr string into its components.
fn parse_multiaddr(addr: &str) -> BootstrapResult<ParsedMultiaddr> {
    if addr.is_empty() {
        return Err(BootstrapError::InvalidBootnode {
            index: 0,
            reason: "empty bootnode address".into(),
        });
    }

    if !addr.starts_with('/') {
        return Err(BootstrapError::InvalidBootnode {
            index: 0,
            reason: format!("multiaddr must start with '/': {addr}"),
        });
    }

    let parts: Vec<&str> = addr.split('/').skip(1).collect(); // skip empty first part

    if parts.len() < 4 {
        return Err(BootstrapError::InvalidBootnode {
            index: 0,
            reason: format!(
                "multiaddr too short: need at least /proto/host/proto/port, got {addr}"
            ),
        });
    }

    // Parse protocol
    let protocol = parts[0].to_lowercase();
    if !matches!(
        protocol.as_str(),
        PROTOCOL_IP4 | PROTOCOL_IP6 | PROTOCOL_DNS4 | PROTOCOL_DNS6
    ) {
        return Err(BootstrapError::InvalidBootnode {
            index: 0,
            reason: format!("unsupported protocol: {protocol}"),
        });
    }

    // Parse host
    let host = parts[1].to_string();
    if host.is_empty() {
        return Err(BootstrapError::InvalidBootnode {
            index: 0,
            reason: "empty host in multiaddr".into(),
        });
    }

    // Validate host based on protocol
    match protocol.as_str() {
        PROTOCOL_IP4 => {
            let octets: Vec<&str> = host.split('.').collect();
            if octets.len() != 4 {
                return Err(BootstrapError::InvalidBootnode {
                    index: 0,
                    reason: format!("invalid IPv4 address: {host}"),
                });
            }
            for octet in &octets {
                if octet.parse::<u8>().is_err() {
                    return Err(BootstrapError::InvalidBootnode {
                        index: 0,
                        reason: format!("invalid IPv4 octet: {octet}"),
                    });
                }
            }
        }
        PROTOCOL_IP6 => {
            if host.parse::<Ipv6Addr>().is_err() {
                return Err(BootstrapError::InvalidBootnode {
                    index: 0,
                    reason: format!("invalid IPv6 address: {host}"),
                });
            }
        }
        _ => {
            // DNS — accept any non‑empty string
        }
    }

    // Parse transport protocol (must be tcp for now)
    if parts.len() < 3 || parts[2].to_lowercase() != PROTOCOL_TCP {
        return Err(BootstrapError::InvalidBootnode {
            index: 0,
            reason: format!("expected /tcp/ after host, got: {addr}"),
        });
    }

    // Parse port
    let port_str = parts[3];
    let port: u16 = port_str.parse().map_err(|_| BootstrapError::InvalidBootnode {
        index: 0,
        reason: format!("invalid port number: {port_str}"),
    })?;

    if port < MIN_PORT || port > MAX_PORT {
        return Err(BootstrapError::InvalidPort {
            port,
            min: MIN_PORT,
            max: MAX_PORT,
        });
    }

    // Optional P2P peer ID
    let peer_id = if parts.len() >= 5 && parts[4] == PROTOCOL_P2P {
        if parts.len() >= 6 {
            Some(parts[5].to_string())
        } else {
            None
        }
    } else {
        None
    };

    Ok(ParsedMultiaddr {
        protocol,
        host,
        port,
        peer_id,
    })
}

/// Extract the port from a listen address (e.g., "0.0.0.0:7001" → 7001).
fn extract_port(listen_addr: &str) -> u16 {
    listen_addr
        .rsplit(':')
        .next()
        .unwrap_or("")
        .parse()
        .unwrap_or(DEFAULT_P2P_PORT)
}

// -----------------------------------------------------------------------------
// Core validation
// -----------------------------------------------------------------------------

/// Validate the full node configuration. Returns `Ok(())` on success.
///
/// # Arguments
/// * `chain_id_config` — chain ID from the node config file.
/// * `chain_id_genesis` — chain ID from the genesis file (if loaded).
/// * `bootnodes` — list of bootnode multiaddresses.
/// * `stake_each` — stake amount per validator.
/// * `simple_producer` — whether simple producer mode is enabled.
/// * `node_seed` — the node's seed identifier.
/// * `genesis_validator_seeds` — seeds of validators in genesis.
/// * `listen_addr` — the node's P2P listen address.
///
/// # Errors
/// Returns a fatal `BootstrapError` if any validation fails.
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
    // ── 1. Validate listen address ──────────────────────────────────────
    validate_listen_addr(listen_addr)?;

    // ── 2. Validate each bootnode ───────────────────────────────────────
    let parsed_bootnodes: Vec<ParsedMultiaddr> = bootnodes
        .iter()
        .enumerate()
        .map(|(i, bn)| {
            parse_multiaddr(bn).map_err(|_| BootstrapError::InvalidBootnode {
                index: i,
                reason: format!("malformed multiaddr: {bn}"),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    // ── 3. Check for duplicate bootnodes ────────────────────────────────
    let unique: BTreeSet<&str> = bootnodes.iter().map(|s| s.as_str()).collect();
    if unique.len() < bootnodes.len() {
        let mut seen = BTreeSet::new();
        let mut duplicates = Vec::new();
        for bn in bootnodes {
            if !seen.insert(bn.as_str()) {
                duplicates.push(bn.clone());
            }
        }
        return Err(BootstrapError::DuplicateBootnodes { duplicates });
    }

    // ── 4. Check for self‑bootstrap ─────────────────────────────────────
    let listen_port = extract_port(listen_addr);
    for parsed in &parsed_bootnodes {
        let is_localhost = match parsed.protocol.as_str() {
            PROTOCOL_IP4 => {
                parsed.host.parse::<Ipv4Addr>().ok() == Some(LOCALHOST_IPV4)
            }
            PROTOCOL_IP6 => {
                parsed.host.parse::<Ipv6Addr>().ok() == Some(LOCALHOST_IPV6)
            }
            _ => parsed.host == "localhost",
        };

        if is_localhost && parsed.port == listen_port {
            return Err(BootstrapError::SelfBootstrap {
                addr: format!("{}:{}", parsed.host, parsed.port),
            });
        }
    }

    // ── 5. Chain ID mismatch ────────────────────────────────────────────
    if let Some(genesis_chain_id) = chain_id_genesis {
        if chain_id_config != genesis_chain_id {
            return Err(BootstrapError::ChainIdMismatch {
                config: chain_id_config,
                genesis: genesis_chain_id,
            });
        }
    }

    // ── 6. Stake config invalid ─────────────────────────────────────────
    if stake_each == 0 {
        return Err(BootstrapError::ZeroStake { stake: stake_each });
    }

    // ── 7. simple_producer conflict ─────────────────────────────────────
    if simple_producer && !genesis_validator_seeds.is_empty() {
        let is_validator = genesis_validator_seeds.contains(&node_seed);
        if !is_validator {
            return Err(BootstrapError::SimpleProducerConflict {
                seed: node_seed,
                validators: genesis_validator_seeds.to_vec(),
            });
        }
    }

    Ok(())
}

/// Validate the listen address format.
fn validate_listen_addr(addr: &str) -> BootstrapResult<()> {
    if addr.is_empty() {
        return Err(BootstrapError::InvalidListenAddress {
            addr: "empty string".into(),
        });
    }

    // Format: <host>:<port>
    let parts: Vec<&str> = addr.rsplitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(BootstrapError::InvalidListenAddress {
            addr: addr.to_string(),
        });
    }

    let port_str = parts[0];
    let port: u16 = port_str
        .parse()
        .map_err(|_| BootstrapError::InvalidListenAddress {
            addr: addr.to_string(),
        })?;

    if port < MIN_PORT || port > MAX_PORT {
        return Err(BootstrapError::InvalidPort {
            port,
            min: MIN_PORT,
            max: MAX_PORT,
        });
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
///
/// Compares the hash of the genesis file against an expected hash.
/// If `expected_hash` is `None`, any valid genesis file is accepted.
///
/// Returns the computed hash on success.
pub fn verify_genesis_integrity(
    genesis_path: impl AsRef<Path>,
    expected_hash: Option<&[u8; 32]>,
) -> BootstrapResult<[u8; 32]> {
    let path = genesis_path.as_ref();

    if !path.exists() {
        return Err(BootstrapError::GenesisFile {
            reason: format!("file not found: {}", path.display()),
        });
    }

    let content = std::fs::read_to_string(path).map_err(|e| BootstrapError::GenesisFile {
        reason: format!("cannot read genesis: {e}"),
    })?;

    if content.trim().is_empty() {
        return Err(BootstrapError::EmptyGenesis);
    }

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

/// Verify genesis content is valid JSON with required fields.
pub fn verify_genesis_content(genesis_json: &str) -> BootstrapResult<()> {
    let parsed: serde_json::Value = serde_json::from_str(genesis_json).map_err(|e| {
        BootstrapError::GenesisFile {
            reason: format!("invalid JSON: {e}"),
        }
    })?;

    // Check required top‑level fields
    if parsed.get("chain_id").is_none() {
        return Err(BootstrapError::GenesisFile {
            reason: "missing required field: 'chain_id'".into(),
        });
    }

    Ok(())
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    // ── Multiaddr parsing tests ────────────────────────────────────────
    #[test]
    fn test_parse_multiaddr_valid() {
        let addr = "/ip4/1.2.3.4/tcp/7001";
        let parsed = parse_multiaddr(addr).unwrap();
        assert_eq!(parsed.protocol, "ip4");
        assert_eq!(parsed.host, "1.2.3.4");
        assert_eq!(parsed.port, 7001);
        assert!(parsed.peer_id.is_none());
    }

    #[test]
    fn test_parse_multiaddr_with_peer_id() {
        let addr = "/ip4/192.168.1.1/tcp/30333/p2p/12D3KooW";
        let parsed = parse_multiaddr(addr).unwrap();
        assert_eq!(parsed.peer_id, Some("12D3KooW".into()));
    }

    #[test]
    fn test_parse_multiaddr_dns() {
        let addr = "/dns4/node.example.com/tcp/7001";
        let parsed = parse_multiaddr(addr).unwrap();
        assert_eq!(parsed.protocol, "dns4");
        assert_eq!(parsed.host, "node.example.com");
    }

    #[test]
    fn test_parse_multiaddr_ipv6() {
        let addr = "/ip6/::1/tcp/7001";
        let parsed = parse_multiaddr(addr).unwrap();
        assert_eq!(parsed.protocol, "ip6");
        assert_eq!(parsed.host, "::1");
    }

    #[test]
    fn test_parse_multiaddr_invalid() {
        assert!(parse_multiaddr("").is_err());
        assert!(parse_multiaddr("not-a-multiaddr").is_err());
        assert!(parse_multiaddr("/ip4/999.999.999.999/tcp/7001").is_err());
        assert!(parse_multiaddr("/ip4/1.2.3.4/tcp/99999").is_err());
        assert!(parse_multiaddr("/ip4/1.2.3.4").is_err());
        assert!(parse_multiaddr("/ip4/1.2.3.4/udp/7001").is_err());
    }

    // ── Config validation tests ────────────────────────────────────────
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
            "0.0.0.0:7001",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_config_valid_no_genesis_chain_id() {
        let result = validate_config(
            6126151,
            None,
            &["/dns4/node.com/tcp/7001".into()],
            1000,
            false,
            1,
            &[],
            "0.0.0.0:7001",
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
            "0.0.0.0:7001",
        );
        assert!(matches!(
            result.unwrap_err(),
            BootstrapError::ChainIdMismatch {
                config: 6126151,
                genesis: 9999
            }
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
            "0.0.0.0:7001",
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
            "0.0.0.0:7001",
        );
        assert!(matches!(
            result.unwrap_err(),
            BootstrapError::ZeroStake { stake: 0 }
        ));
    }

    #[test]
    fn test_simple_producer_conflict() {
        let result = validate_config(
            6126151,
            None,
            &[],
            1000,
            true,
            1, // seed 1 not in [2, 3, 4]
            &[2, 3, 4],
            "0.0.0.0:7001",
        );
        assert!(matches!(
            result.unwrap_err(),
            BootstrapError::SimpleProducerConflict { seed: 1, .. }
        ));
    }

    #[test]
    fn test_simple_producer_no_conflict() {
        // seed 2 IS in the validator set
        let result = validate_config(
            6126151,
            None,
            &[],
            1000,
            true,
            2,
            &[2, 3, 4],
            "0.0.0.0:7001",
        );
        assert!(result.is_ok());
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
            "0.0.0.0:7001",
        );
        assert!(matches!(
            result.unwrap_err(),
            BootstrapError::DuplicateBootnodes { .. }
        ));
    }

    #[test]
    fn test_self_bootstrap_detection() {
        let result = validate_config(
            6126151,
            None,
            &["/ip4/127.0.0.1/tcp/7001".into()],
            1000,
            false,
            1,
            &[],
            "0.0.0.0:7001",
        );
        assert!(matches!(
            result.unwrap_err(),
            BootstrapError::SelfBootstrap { .. }
        ));
    }

    #[test]
    fn test_self_bootstrap_ipv6() {
        let result = validate_config(
            6126151,
            None,
            &["/ip6/::1/tcp/7001".into()],
            1000,
            false,
            1,
            &[],
            "[::]:7001",
        );
        assert!(matches!(
            result.unwrap_err(),
            BootstrapError::SelfBootstrap { .. }
        ));
    }

    #[test]
    fn test_empty_listen_addr() {
        let result = validate_config(6126151, None, &[], 1000, false, 1, &[], "");
        assert!(matches!(
            result.unwrap_err(),
            BootstrapError::InvalidListenAddress { .. }
        ));
    }

    #[test]
    fn test_malformed_listen_addr() {
        let result = validate_config(
            6126151,
            None,
            &[],
            1000,
            false,
            1,
            &[],
            "not-a-valid-address",
        );
        assert!(matches!(
            result.unwrap_err(),
            BootstrapError::InvalidListenAddress { .. }
        ));
    }

    #[test]
    fn test_invalid_port_in_listen_addr() {
        let result = validate_config(
            6126151,
            None,
            &[],
            1000,
            false,
            1,
            &[],
            "0.0.0.0:99999",
        );
        assert!(matches!(
            result.unwrap_err(),
            BootstrapError::InvalidPort { .. }
        ));
    }

    // ── Genesis validation tests ───────────────────────────────────────
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
    fn test_verify_genesis_integrity_ok() -> BootstrapResult<()> {
        let file = NamedTempFile::new().unwrap();
        let path = file.path();
        let content = r#"{"chain_id":6126151,"validators":[]}"#;
        std::fs::write(path, content).unwrap();

        let hash = verify_genesis_integrity(path, None)?;
        assert_ne!(hash, [0u8; 32]);

        // Correct hash passes
        assert!(verify_genesis_integrity(path, Some(&hash)).is_ok());

        Ok(())
    }

    #[test]
    fn test_verify_genesis_integrity_mismatch() -> BootstrapResult<()> {
        let file = NamedTempFile::new().unwrap();
        let path = file.path();
        std::fs::write(path, r#"{"chain_id":6126151}"#).unwrap();

        let bad = [0xFFu8; 32];
        let err = verify_genesis_integrity(path, Some(&bad)).unwrap_err();
        assert!(matches!(
            err,
            BootstrapError::GenesisHashMismatch { .. }
        ));
        Ok(())
    }

    #[test]
    fn test_verify_genesis_integrity_empty_file() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path();
        std::fs::write(path, "").unwrap();
        let err = verify_genesis_integrity(path, None).unwrap_err();
        assert!(matches!(err, BootstrapError::EmptyGenesis));
    }

    #[test]
    fn test_verify_genesis_integrity_missing_file() {
        let err = verify_genesis_integrity("/nonexistent/file.json", None).unwrap_err();
        assert!(matches!(err, BootstrapError::GenesisFile { .. }));
    }

    #[test]
    fn test_verify_genesis_content_valid() {
        let json = r#"{"chain_id":6126151,"validators":[]}"#;
        assert!(verify_genesis_content(json).is_ok());
    }

    #[test]
    fn test_verify_genesis_content_missing_chain_id() {
        let json = r#"{"validators":[]}"#;
        let err = verify_genesis_content(json).unwrap_err();
        assert!(matches!(err, BootstrapError::GenesisFile { .. }));
    }

    #[test]
    fn test_verify_genesis_content_invalid_json() {
        let err = verify_genesis_content("not json").unwrap_err();
        assert!(matches!(err, BootstrapError::GenesisFile { .. }));
    }
}
