//! STEP 3 — Strict config + genesis validation at boot.
//!
//! Node MUST NOT start if any of these fail:
//! - Bootnodes invalid (malformed multiaddr, missing peer ID)
//! - Chain ID mismatch (config vs genesis)
//! - Stake config invalid (zero, negative, or exceeding maximum)
//! - simple_producer conflict (follower/RPC running as producer)
//! - Genesis mismatch (hash differs from expected)
//! - Genesis hash check at boot
//! - Duplicate validator seeds in genesis
//! - Empty validator set
//! - Invalid listen address/port
//! - Protocol activation schedule invalid
//! - Keystore mode consistency
//! - Data directory permissions
//! - Resource limits sanity

use std::collections::BTreeSet;
use std::path::Path;

/// Maximum allowed stake per validator (1 billion units).
const MAX_STAKE: u64 = 1_000_000_000;

/// A fatal validation error that prevents node startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    pub field: String,
    pub message: String,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FATAL config error [{}]: {}", self.field, self.message)
    }
}

/// Result of config validation.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub errors: Vec<ValidationError>,
}

impl ValidationResult {
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }

    pub fn into_result(self) -> Result<(), Vec<ValidationError>> {
        if self.errors.is_empty() {
            Ok(())
        } else {
            Err(self.errors)
        }
    }
}

impl std::fmt::Display for ValidationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_ok() {
            write!(f, "Config validation: PASS")
        } else {
            writeln!(f, "Config validation: FAIL ({} errors)", self.errors.len())?;
            for e in &self.errors {
                writeln!(f, "  {e}")?;
            }
            Ok(())
        }
    }
}

// -----------------------------------------------------------------------------
// Bootnode validation
// -----------------------------------------------------------------------------

/// Validate a bootnode multiaddr string.
/// Valid formats: /ip4/X.X.X.X/tcp/PORT/p2p/PEERID or /dns4/HOST/tcp/PORT/p2p/PEERID
/// The peer ID is mandatory for bootnodes.
fn validate_bootnode(addr: &str) -> Result<(), String> {
    if addr.is_empty() {
        return Err("empty bootnode address".into());
    }

    let parts: Vec<&str> = addr.split('/').collect();
    if parts.len() < 7 {
        return Err(format!("malformed multiaddr (too few parts, missing peer ID?): {addr}"));
    }

    if !parts[0].is_empty() {
        return Err(format!("multiaddr must start with /: {addr}"));
    }

    match parts[1] {
        "ip4" => {
            let ip = parts[2];
            let octets: Vec<&str> = ip.split('.').collect();
            if octets.len() != 4 {
                return Err(format!("invalid IPv4 address: {ip}"));
            }
            for octet in &octets {
                if octet.parse::<u8>().is_err() {
                    return Err(format!("invalid IPv4 octet: {octet}"));
                }
            }
        }
        "dns4" | "dns6" => {
            if parts[2].is_empty() {
                return Err("empty DNS hostname".into());
            }
        }
        "ip6" => { /* Accept IPv6, we don't validate further */ }
        other => return Err(format!("unsupported multiaddr protocol: {other}")),
    }

    if parts.len() >= 5 && parts[3] == "tcp" {
        if parts[4].parse::<u16>().is_err() {
            return Err(format!("invalid TCP port: {}", parts[4]));
        }
    } else {
        return Err(format!("missing /tcp/ portion: {addr}"));
    }

    if parts.len() >= 7 && parts[5] == "p2p" {
        if parts[6].is_empty() {
            return Err("empty peer ID".into());
        }
    } else {
        return Err(format!("bootnode missing /p2p/ peer ID: {addr}"));
    }

    Ok(())
}

// -----------------------------------------------------------------------------
// Genesis hash helpers
// -----------------------------------------------------------------------------

/// Compute a genesis hash for integrity checking.
/// Uses SHA-256 of the canonical JSON representation (normalized to avoid formatting differences).
pub fn genesis_hash(genesis_json: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let parsed: serde_json::Value = serde_json::from_str(genesis_json)
        .expect("genesis JSON must be valid");
    let canonical = serde_json::to_string(&parsed)
        .expect("canonical serialization failed");

    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Verify genesis file integrity and basic structure.
pub fn verify_genesis_integrity(
    genesis_path: impl AsRef<Path>,
    expected_hash: Option<&[u8; 32]>,
) -> Result<[u8; 32], String> {
    let content = std::fs::read_to_string(genesis_path.as_ref())
        .map_err(|e| format!("cannot read genesis: {e}"))?;

    // Validate JSON structure
    let parsed: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| format!("invalid JSON in genesis: {e}"))?;

    // Basic required fields
    if parsed.get("chain_id").is_none() {
        return Err("genesis missing 'chain_id'".into());
    }
    if parsed.get("validators").is_none() {
        return Err("genesis missing 'validators'".into());
    }

    let hash = genesis_hash(&content);

    if let Some(expected) = expected_hash {
        if hash != *expected {
            return Err(format!(
                "genesis hash mismatch: expected 0x{}, got 0x{}",
                hex::encode(expected),
                hex::encode(hash),
            ));
        }
    }

    Ok(hash)
}

// -----------------------------------------------------------------------------
// Configuration validation (core)
// -----------------------------------------------------------------------------

/// Validate the full node configuration. Returns fatal errors.
///
/// This is called at boot: `config.validate() -> fatal if errors`.
#[allow(clippy::too_many_arguments)]
pub fn validate_config(
    chain_id_config: u64,
    chain_id_genesis: Option<u64>,
    bootnodes: &[String],
    stake_each: u64,
    simple_producer: bool,
    rpc_enabled: bool,
    node_seed: u64,
    genesis_validator_seeds: &[u64],
    config_validator_seeds: &[u64],   // added
    protocol_activations: &[crate::protocol::version::ProtocolActivation],
    listen_addr: &str,
    p2p_listen_addr: &str,
    data_dir: &str,
    keystore_mode: &str,
    keystore_password_configured: bool,
    mempool_capacity: usize,
    max_connections_total: u32,
    max_connections_per_peer: u32,
) -> ValidationResult {
    let mut errors = Vec::new();

    // 1. Validate bootnodes.
    for (i, bn) in bootnodes.iter().enumerate() {
        if let Err(e) = validate_bootnode(bn) {
            errors.push(ValidationError {
                field: format!("network.bootnodes[{i}]"),
                message: e,
            });
        }
    }

    // 2. Check for self-bootstrap (node's own address in bootnodes).
    let listen_port = listen_addr.rsplit(':').next().unwrap_or("")
        .chars().filter(|c| c.is_ascii_digit()).collect::<String>();
    let self_indicators = ["127.0.0.1", "0.0.0.0", "localhost"];
    for bn in bootnodes {
        if !listen_port.is_empty() {
            for indicator in &self_indicators {
                if bn.contains(indicator) && bn.contains(&listen_port) {
                    errors.push(ValidationError {
                        field: "network.bootnodes".into(),
                        message: format!("node appears to bootstrap from itself: {bn} (contains local address {indicator} and port {listen_port})"),
                    });
                    break;
                }
            }
        }
    }

    // 3. Chain ID checks.
    if chain_id_config == 0 {
        errors.push(ValidationError {
            field: "node.chain_id".into(),
            message: "chain_id must be non‑zero".into(),
        });
    }
    if let Some(genesis_chain_id) = chain_id_genesis {
        if chain_id_config != genesis_chain_id {
            errors.push(ValidationError {
                field: "node.chain_id".into(),
                message: format!(
                    "config chain_id={chain_id_config} does not match genesis chain_id={genesis_chain_id}"
                ),
            });
        }
    }

    // 4. Stake config.
    if stake_each == 0 {
        errors.push(ValidationError {
            field: "consensus.stake_each".into(),
            message: "stake_each must be > 0".into(),
        });
    }
    if stake_each > MAX_STAKE {
        errors.push(ValidationError {
            field: "consensus.stake_each".into(),
            message: format!("stake_each={stake_each} exceeds maximum allowed ({MAX_STAKE})"),
        });
    }

    // 5. Genesis validator set must not be empty.
    if genesis_validator_seeds.is_empty() {
        errors.push(ValidationError {
            field: "genesis.validators".into(),
            message: "genesis must have at least one validator".into(),
        });
    }

    // 6. Duplicate validator seeds in genesis.
    let unique_seeds: BTreeSet<&u64> = genesis_validator_seeds.iter().collect();
    if unique_seeds.len() < genesis_validator_seeds.len() {
        errors.push(ValidationError {
            field: "genesis.validators".into(),
            message: "duplicate validator seeds detected".into(),
        });
    }

    // 7. Config validator seeds must match genesis seeds (all nodes must agree).
    if config_validator_seeds.len() != genesis_validator_seeds.len()
        || config_validator_seeds.iter().collect::<BTreeSet<_>>() != unique_seeds
    {
        errors.push(ValidationError {
            field: "consensus.validator_seeds".into(),
            message: "config validator seeds must exactly match genesis validator seeds".into(),
        });
    }

    // 8. simple_producer conflict.
    if simple_producer {
        if !genesis_validator_seeds.contains(&node_seed) {
            errors.push(ValidationError {
                field: "consensus.simple_producer".into(),
                message: format!(
                    "simple_producer=true but node seed={node_seed} is not in validator set {:?}",
                    genesis_validator_seeds
                ),
            });
        }
        if rpc_enabled {
            errors.push(ValidationError {
                field: "consensus.simple_producer".into(),
                message: "simple_producer=true and rpc_enabled=true are mutually exclusive".into(),
            });
        }
    }

    // 9. Duplicate bootnode check.
    let unique_bootnodes: BTreeSet<&str> = bootnodes.iter().map(|s| s.as_str()).collect();
    if unique_bootnodes.len() < bootnodes.len() {
        errors.push(ValidationError {
            field: "network.bootnodes".into(),
            message: "duplicate bootnode entries detected".into(),
        });
    }

    // 10. Listen address validation (RPC).
    if listen_addr.is_empty() {
        errors.push(ValidationError {
            field: "rpc.listen".into(),
            message: "RPC listen address cannot be empty".into(),
        });
    } else if let Some(port_str) = listen_addr.split(':').last() {
        if port_str.parse::<u16>().is_err() {
            errors.push(ValidationError {
                field: "rpc.listen".into(),
                message: format!("invalid port number in RPC listen address: {port_str}"),
            });
        }
    } else {
        errors.push(ValidationError {
            field: "rpc.listen".into(),
            message: format!("RPC listen address missing port: {listen_addr}"),
        });
    }

    // 11. P2P listen address validation.
    if p2p_listen_addr.is_empty() {
        errors.push(ValidationError {
            field: "network.listen".into(),
            message: "P2P listen address cannot be empty".into(),
        });
    } else if let Some(port_str) = p2p_listen_addr.split(':').last() {
        if port_str.parse::<u16>().is_err() {
            errors.push(ValidationError {
                field: "network.listen".into(),
                message: format!("invalid port number in P2P listen address: {port_str}"),
            });
        }
    } else {
        errors.push(ValidationError {
            field: "network.listen".into(),
            message: format!("P2P listen address missing port: {p2p_listen_addr}"),
        });
    }

    // 12. Protocol activations schedule.
    if protocol_activations.is_empty() {
        errors.push(ValidationError {
            field: "consensus.protocol_activations".into(),
            message: "protocol activation schedule cannot be empty".into(),
        });
    } else {
        let has_v1_at_zero = protocol_activations.iter().any(|a| {
            a.protocol_version == 1 && a.activation_height == Some(0)
        });
        if !has_v1_at_zero {
            errors.push(ValidationError {
                field: "consensus.protocol_activations".into(),
                message: "must include activation for protocol_version=1 at height 0".into(),
            });
        }
        // Check monotonicity of heights.
        let mut prev_height: Option<u64> = None;
        for act in protocol_activations {
            if let Some(h) = act.activation_height {
                if let Some(prev) = prev_height {
                    if h <= prev {
                        errors.push(ValidationError {
                            field: "consensus.protocol_activations".into(),
                            message: format!("activation heights must be strictly increasing ({} <= {})", prev, h),
                        });
                        break;
                    }
                }
                prev_height = Some(h);
            }
        }
    }

    // 13. Data directory.
    if data_dir.is_empty() {
        errors.push(ValidationError {
            field: "node.data_dir".into(),
            message: "data_dir cannot be empty".into(),
        });
    } else {
        // Try to create directory (or check write permissions).
        if let Err(e) = std::fs::create_dir_all(data_dir) {
            errors.push(ValidationError {
                field: "node.data_dir".into(),
                message: format!("cannot create or access data directory: {e}"),
            });
        }
    }

    // 14. Keystore mode and password.
    match keystore_mode {
        "plain" => { /* ok */ }
        "encrypted" => {
            if !keystore_password_configured {
                errors.push(ValidationError {
                    field: "node.keystore".into(),
                    message: "keystore=encrypted but no password provided (set keystore_password or IONA_KEYSTORE_PASSWORD)".into(),
                });
            }
        }
        other => {
            errors.push(ValidationError {
                field: "node.keystore".into(),
                message: format!("invalid keystore mode: {other} (must be 'plain' or 'encrypted')"),
            });
        }
    }

    // 15. Mempool capacity.
    if mempool_capacity < 1_000 {
        errors.push(ValidationError {
            field: "mempool.capacity".into(),
            message: format!("mempool.capacity too low: {mempool_capacity} (minimum 1000)"),
        });
    }
    if mempool_capacity > 1_000_000 {
        errors.push(ValidationError {
            field: "mempool.capacity".into(),
            message: format!("mempool.capacity too high: {mempool_capacity} (maximum 1,000,000)"),
        });
    }

    // 16. Connection limits.
    if max_connections_total < 1 || max_connections_total > 10_000 {
        errors.push(ValidationError {
            field: "network.max_connections_total".into(),
            message: format!("max_connections_total must be between 1 and 10000 (got {max_connections_total})"),
        });
    }
    if max_connections_per_peer < 1 || max_connections_per_peer > 100 {
        errors.push(ValidationError {
            field: "network.max_connections_per_peer".into(),
            message: format!("max_connections_per_peer must be between 1 and 100 (got {max_connections_per_peer})"),
        });
    }
    if max_connections_per_peer > max_connections_total {
        errors.push(ValidationError {
            field: "network.max_connections_per_peer".into(),
            message: "max_connections_per_peer cannot exceed max_connections_total".into(),
        });
    }

    ValidationResult { errors }
}

// -----------------------------------------------------------------------------
// Convenience: validate a full NodeConfig (future extension)
// -----------------------------------------------------------------------------

// For completeness, you could add a method to NodeConfig that calls this.
// But we keep the existing function for now.

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::version::ProtocolActivation;

    fn dummy_activation() -> Vec<ProtocolActivation> {
        vec![
            ProtocolActivation { protocol_version: 1, activation_height: Some(0), grace_blocks: 0 },
            ProtocolActivation { protocol_version: 2, activation_height: Some(100), grace_blocks: 10 },
        ]
    }

    #[test]
    fn test_validate_bootnode_valid() {
        assert!(validate_bootnode("/ip4/1.2.3.4/tcp/7001/p2p/12D3KooW").is_ok());
        assert!(validate_bootnode("/ip4/192.168.1.1/tcp/30333/p2p/12D3KooW").is_ok());
        assert!(validate_bootnode("/dns4/node.example.com/tcp/7001/p2p/12D3KooW").is_ok());
    }

    #[test]
    fn test_validate_bootnode_invalid() {
        assert!(validate_bootnode("").is_err());
        assert!(validate_bootnode("not-a-multiaddr").is_err());
        assert!(validate_bootnode("/ip4/999.999.999.999/tcp/7001/p2p/id").is_err());
        assert!(validate_bootnode("/ip4/1.2.3.4/tcp/99999/p2p/id").is_err());
        assert!(validate_bootnode("/ip4/1.2.3.4/tcp/7001").is_err()); // missing /p2p/
        assert!(validate_bootnode("/ip4/1.2.3.4/tcp/7001/p2p/").is_err()); // empty peer ID
        assert!(validate_bootnode("/dns4//tcp/7001/p2p/id").is_err()); // empty hostname
    }

    #[test]
    fn test_config_valid() {
        let result = validate_config(
            6126151,
            Some(6126151),
            &["/ip4/1.2.3.4/tcp/7001/p2p/12D3KooW".into()],
            1000,
            true,
            false,   // rpc_enabled
            2,       // node seed in validator set
            &[2, 3, 4],
            &[2, 3, 4],
            &dummy_activation(),
            "0.0.0.0:9001",
            "/ip4/0.0.0.0/tcp/7001",
            "/tmp/iona",
            "plain",
            false,   // no password needed for plain
            200_000,
            200,
            8,
        );
        assert!(result.is_ok(), "{result}");
    }

    #[test]
    fn test_chain_id_mismatch() {
        let result = validate_config(
            6126151,
            Some(9999),
            &[],
            1000,
            false,
            false,
            1,
            &[1, 2, 3],
            &[1, 2, 3],
            &dummy_activation(),
            "0.0.0.0:9001",
            "/ip4/0.0.0.0/tcp/7001",
            "/tmp/iona",
            "plain",
            false,
            200_000,
            200,
            8,
        );
        assert!(!result.is_ok());
        assert!(result.errors.iter().any(|e| e.field == "node.chain_id"));
    }

    #[test]
    fn test_invalid_bootnode() {
        let result = validate_config(
            6126151,
            None,
            &["not-valid".into()],
            1000,
            false,
            false,
            1,
            &[1, 2, 3],
            &[1, 2, 3],
            &dummy_activation(),
            "0.0.0.0:9001",
            "/ip4/0.0.0.0/tcp/7001",
            "/tmp/iona",
            "plain",
            false,
            200_000,
            200,
            8,
        );
        assert!(!result.is_ok());
        assert!(result.errors.iter().any(|e| e.field.contains("bootnodes")));
    }

    #[test]
    fn test_zero_stake() {
        let result = validate_config(
            6126151,
            None,
            &[],
            0,
            false,
            false,
            1,
            &[1, 2, 3],
            &[1, 2, 3],
            &dummy_activation(),
            "0.0.0.0:9001",
            "/ip4/0.0.0.0/tcp/7001",
            "/tmp/iona",
            "plain",
            false,
            200_000,
            200,
            8,
        );
        assert!(!result.is_ok());
        assert!(result.errors.iter().any(|e| e.field.contains("stake_each")));
    }

    #[test]
    fn test_stake_exceeds_max() {
        let result = validate_config(
            6126151,
            None,
            &[],
            MAX_STAKE + 1,
            false,
            false,
            1,
            &[1, 2, 3],
            &[1, 2, 3],
            &dummy_activation(),
            "0.0.0.0:9001",
            "/ip4/0.0.0.0/tcp/7001",
            "/tmp/iona",
            "plain",
            false,
            200_000,
            200,
            8,
        );
        assert!(!result.is_ok());
        assert!(result.errors.iter().any(|e| e.message.contains("exceeds maximum")));
    }

    #[test]
    fn test_simple_producer_conflict_not_validator() {
        let result = validate_config(
            6126151,
            None,
            &[],
            1000,
            true,
            false,
            1,
            &[2, 3, 4],
            &[2, 3, 4],
            &dummy_activation(),
            "0.0.0.0:9001",
            "/ip4/0.0.0.0/tcp/7001",
            "/tmp/iona",
            "plain",
            false,
            200_000,
            200,
            8,
        );
        assert!(!result.is_ok());
        assert!(result.errors.iter().any(|e| e.field.contains("simple_producer")));
    }

    #[test]
    fn test_simple_producer_conflict_rpc_enabled() {
        let result = validate_config(
            6126151,
            None,
            &[],
            1000,
            true,
            true,
            2,
            &[2, 3, 4],
            &[2, 3, 4],
            &dummy_activation(),
            "0.0.0.0:9001",
            "/ip4/0.0.0.0/tcp/7001",
            "/tmp/iona",
            "plain",
            false,
            200_000,
            200,
            8,
        );
        assert!(!result.is_ok());
        assert!(result.errors.iter().any(|e| e.message.contains("mutually exclusive")));
    }

    #[test]
    fn test_duplicate_bootnodes() {
        let result = validate_config(
            6126151,
            None,
            &[
                "/ip4/1.2.3.4/tcp/7001/p2p/id".into(),
                "/ip4/1.2.3.4/tcp/7001/p2p/id".into(),
            ],
            1000,
            false,
            false,
            1,
            &[1, 2, 3],
            &[1, 2, 3],
            &dummy_activation(),
            "0.0.0.0:9001",
            "/ip4/0.0.0.0/tcp/7001",
            "/tmp/iona",
            "plain",
            false,
            200_000,
            200,
            8,
        );
        assert!(!result.is_ok());
        assert!(result.errors.iter().any(|e| e.message.contains("duplicate")));
    }

    #[test]
    fn test_empty_listen_addr() {
        let result = validate_config(
            6126151,
            None,
            &[],
            1000,
            false,
            false,
            1,
            &[1, 2, 3],
            &[1, 2, 3],
            &dummy_activation(),
            "",
            "/ip4/0.0.0.0/tcp/7001",
            "/tmp/iona",
            "plain",
            false,
            200_000,
            200,
            8,
        );
        assert!(!result.is_ok());
        assert!(result.errors.iter().any(|e| e.field.contains("listen")));
    }

    #[test]
    fn test_invalid_listen_port() {
        let result = validate_config(
            6126151,
            None,
            &[],
            1000,
            false,
            false,
            1,
            &[1, 2, 3],
            &[1, 2, 3],
            &dummy_activation(),
            "0.0.0.0:99999",
            "/ip4/0.0.0.0/tcp/7001",
            "/tmp/iona",
            "plain",
            false,
            200_000,
            200,
            8,
        );
        assert!(!result.is_ok());
        assert!(result.errors.iter().any(|e| e.message.contains("invalid port")));
    }

    #[test]
    fn test_empty_validator_set() {
        let result = validate_config(
            6126151,
            None,
            &[],
            1000,
            false,
            false,
            1,
            &[],
            &[],
            &dummy_activation(),
            "0.0.0.0:9001",
            "/ip4/0.0.0.0/tcp/7001",
            "/tmp/iona",
            "plain",
            false,
            200_000,
            200,
            8,
        );
        assert!(!result.is_ok());
        assert!(result.errors.iter().any(|e| e.message.contains("at least one validator")));
    }

    #[test]
    fn test_duplicate_validator_seeds() {
        let result = validate_config(
            6126151,
            None,
            &[],
            1000,
            false,
            false,
            1,
            &[1, 2, 2, 3],
            &[1, 2, 2, 3],
            &dummy_activation(),
            "0.0.0.0:9001",
            "/ip4/0.0.0.0/tcp/7001",
            "/tmp/iona",
            "plain",
            false,
            200_000,
            200,
            8,
        );
        assert!(!result.is_ok());
        assert!(result.errors.iter().any(|e| e.message.contains("duplicate validator seeds")));
    }

    #[test]
    fn test_validator_seeds_mismatch() {
        let result = validate_config(
            6126151,
            None,
            &[],
            1000,
            false,
            false,
            1,
            &[1, 2, 3],
            &[1, 2, 4],
            &dummy_activation(),
            "0.0.0.0:9001",
            "/ip4/0.0.0.0/tcp/7001",
            "/tmp/iona",
            "plain",
            false,
            200_000,
            200,
            8,
        );
        assert!(!result.is_ok());
        assert!(result.errors.iter().any(|e| e.message.contains("must exactly match")));
    }

    #[test]
    fn test_genesis_hash_deterministic() {
        let json1 = r#"{"chain_id":6126151,"validators":[{"seed":2}]}"#;
        let json2 = r#"
        {
            "chain_id": 6126151,
            "validators": [{"seed": 2}]
        }
        "#;
        let h1 = genesis_hash(json1);
        let h2 = genesis_hash(json2);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_genesis_hash_different() {
        let json1 = r#"{"chain_id":6126151}"#;
        let json2 = r#"{"chain_id":9999}"#;
        assert_ne!(genesis_hash(json1), genesis_hash(json2));
    }

    #[test]
    fn test_verify_genesis_integrity() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("genesis.json");
        let content = r#"{"chain_id":6126151,"validators":[]}"#;
        std::fs::write(&path, content).unwrap();

        let hash = verify_genesis_integrity(&path, None).unwrap();
        assert_ne!(hash, [0u8; 32]);

        assert!(verify_genesis_integrity(&path, Some(&hash)).is_ok());

        let bad = [0xFFu8; 32];
        assert!(verify_genesis_integrity(&path, Some(&bad)).is_err());
    }

    #[test]
    fn test_invalid_genesis_json() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("genesis.json");
        std::fs::write(&path, "not valid json").unwrap();
        let res = verify_genesis_integrity(&path, None);
        assert!(res.is_err());
    }

    #[test]
    fn test_missing_genesis_fields() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("genesis.json");
        std::fs::write(&path, r#"{"chain_id":123}"#).unwrap();
        let res = verify_genesis_integrity(&path, None);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("validators"));
    }

    #[test]
    fn test_protocol_activations_invalid() {
        let result = validate_config(
            6126151,
            None,
            &[],
            1000,
            false,
            false,
            1,
            &[1, 2, 3],
            &[1, 2, 3],
            &[], // empty activations
            "0.0.0.0:9001",
            "/ip4/0.0.0.0/tcp/7001",
            "/tmp/iona",
            "plain",
            false,
            200_000,
            200,
            8,
        );
        assert!(!result.is_ok());
        assert!(result.errors.iter().any(|e| e.message.contains("cannot be empty")));
    }

    #[test]
    fn test_protocol_activations_no_v1() {
        let activations = vec![
            ProtocolActivation { protocol_version: 2, activation_height: Some(100), grace_blocks: 10 },
        ];
        let result = validate_config(
            6126151,
            None,
            &[],
            1000,
            false,
            false,
            1,
            &[1, 2, 3],
            &[1, 2, 3],
            &activations,
            "0.0.0.0:9001",
            "/ip4/0.0.0.0/tcp/7001",
            "/tmp/iona",
            "plain",
            false,
            200_000,
            200,
            8,
        );
        assert!(!result.is_ok());
        assert!(result.errors.iter().any(|e| e.message.contains("must include activation for protocol_version=1 at height 0")));
    }

    #[test]
    fn test_data_dir_inaccessible() {
        // We'll create a path that cannot be created (e.g., root protected, but we can simulate with a non‑existing parent).
        // Since we cannot guarantee permission failure in tests, we just check that empty dir is caught.
        let result = validate_config(
            6126151,
            None,
            &[],
            1000,
            false,
            false,
            1,
            &[1, 2, 3],
            &[1, 2, 3],
            &dummy_activation(),
            "0.0.0.0:9001",
            "/ip4/0.0.0.0/tcp/7001",
            "", // empty data dir
            "plain",
            false,
            200_000,
            200,
            8,
        );
        assert!(!result.is_ok());
        assert!(result.errors.iter().any(|e| e.field == "node.data_dir"));
    }

    #[test]
    fn test_keystore_encrypted_no_password() {
        let result = validate_config(
            6126151,
            None,
            &[],
            1000,
            false,
            false,
            1,
            &[1, 2, 3],
            &[1, 2, 3],
            &dummy_activation(),
            "0.0.0.0:9001",
            "/ip4/0.0.0.0/tcp/7001",
            "/tmp/iona",
            "encrypted",
            false, // password not configured
            200_000,
            200,
            8,
        );
        assert!(!result.is_ok());
        assert!(result.errors.iter().any(|e| e.message.contains("no password provided")));
    }

    #[test]
    fn test_mempool_capacity_out_of_bounds() {
        let result = validate_config(
            6126151,
            None,
            &[],
            1000,
            false,
            false,
            1,
            &[1, 2, 3],
            &[1, 2, 3],
            &dummy_activation(),
            "0.0.0.0:9001",
            "/ip4/0.0.0.0/tcp/7001",
            "/tmp/iona",
            "plain",
            false,
            500, // too low
            200,
            8,
        );
        assert!(!result.is_ok());
        assert!(result.errors.iter().any(|e| e.message.contains("too low")));
    }

    #[test]
    fn test_connection_limits() {
        let result = validate_config(
            6126151,
            None,
            &[],
            1000,
            false,
            false,
            1,
            &[1, 2, 3],
            &[1, 2, 3],
            &dummy_activation(),
            "0.0.0.0:9001",
            "/ip4/0.0.0.0/tcp/7001",
            "/tmp/iona",
            "plain",
            false,
            200_000,
            0, // invalid total
            8,
        );
        assert!(!result.is_ok());
        assert!(result.errors.iter().any(|e| e.message.contains("max_connections_total")));

        let result = validate_config(
            6126151,
            None,
            &[],
            1000,
            false,
            false,
            1,
            &[1, 2, 3],
            &[1, 2, 3],
            &dummy_activation(),
            "0.0.0.0:9001",
            "/ip4/0.0.0.0/tcp/7001",
            "/tmp/iona",
            "plain",
            false,
            200_000,
            200,
            300, // per peer > total
        );
        assert!(!result.is_ok());
        assert!(result.errors.iter().any(|e| e.message.contains("cannot exceed")));
    }
}
