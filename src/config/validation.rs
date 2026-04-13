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
use std::path::Path;

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

/// Validate a bootnode multiaddr string.
/// Valid formats: /ip4/X.X.X.X/tcp/PORT or /ip4/X.X.X.X/tcp/PORT/p2p/PEERID
/// or /dns4/HOST/tcp/PORT/p2p/PEERID
fn validate_bootnode(addr: &str) -> Result<(), String> {
    if addr.is_empty() {
        return Err("empty bootnode address".into());
    }

    let parts: Vec<&str> = addr.split('/').collect();
    if parts.len() < 5 {
        return Err(format!("malformed multiaddr (too few parts): {addr}"));
    }

    // First part should be empty (leading /).
    if !parts[0].is_empty() {
        return Err(format!("multiaddr must start with /: {addr}"));
    }

    // Check protocol prefix.
    match parts[1] {
        "ip4" => {
            // Validate IP.
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
            // DNS hostname — just check it's not empty.
            if parts[2].is_empty() {
                return Err("empty DNS hostname".into());
            }
        }
        "ip6" => { /* Accept IPv6 */ }
        other => {
            return Err(format!("unsupported multiaddr protocol: {other}"));
        }
    }

    // Check for /tcp/PORT.
    if parts.len() >= 5 && parts[3] == "tcp" {
        if parts[4].parse::<u16>().is_err() {
            return Err(format!("invalid TCP port: {}", parts[4]));
        }
    }

    Ok(())
}

/// Validate the full node configuration. Returns fatal errors.
///
/// This is called at boot: `config.validate() -> fatal if errors`.
pub fn validate_config(
    chain_id_config: u64,
    chain_id_genesis: Option<u64>,
    bootnodes: &[String],
    stake_each: u64,
    simple_producer: bool,
    node_seed: u64,
    genesis_validator_seeds: &[u64],
    listen_addr: &str,
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
    // We can detect this if the bootnode points to the same listen address.
    // (Simple heuristic: check if any bootnode contains the listen port)
    let listen_port = listen_addr
        .rsplit(':')
        .next()
        .unwrap_or("")
        .chars()
        .filter(|c| c.is_ascii_digit())
        .collect::<String>();
    for bn in bootnodes {
        if !listen_port.is_empty() && bn.contains("127.0.0.1") && bn.contains(&listen_port) {
            errors.push(ValidationError {
                field: "network.bootnodes".into(),
                message: format!("node appears to bootstrap from itself: {bn}"),
            });
        }
    }

    // 3. Chain ID mismatch.
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

    // 4. Stake config invalid.
    if stake_each == 0 {
        errors.push(ValidationError {
            field: "consensus.stake_each".into(),
            message: "stake_each must be > 0".into(),
        });
    }

    // 5. simple_producer conflict: if node is not a validator, it shouldn't produce.
    if simple_producer && !genesis_validator_seeds.is_empty() {
        let is_validator = genesis_validator_seeds.contains(&node_seed);
        if !is_validator {
            errors.push(ValidationError {
                field: "consensus.simple_producer".into(),
                message: format!(
                    "simple_producer=true but node seed={node_seed} is not in validator set {:?}",
                    genesis_validator_seeds
                ),
            });
        }
    }

    // 6. Duplicate bootnode check.
    let unique: BTreeSet<&str> = bootnodes.iter().map(|s| s.as_str()).collect();
    if unique.len() < bootnodes.len() {
        errors.push(ValidationError {
            field: "network.bootnodes".into(),
            message: "duplicate bootnode entries detected".into(),
        });
    }

    // 7. Listen address validation.
    if listen_addr.is_empty() {
        errors.push(ValidationError {
            field: "rpc.listen".into(),
            message: "listen address cannot be empty".into(),
        });
    }

    ValidationResult { errors }
}

/// Compute a genesis hash for integrity checking.
/// Uses SHA-256 of the canonical JSON representation.
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
) -> Result<[u8; 32], String> {
    let content = std::fs::read_to_string(genesis_path.as_ref())
        .map_err(|e| format!("cannot read genesis: {e}"))?;

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

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_bootnode_valid() {
        assert!(validate_bootnode("/ip4/1.2.3.4/tcp/7001").is_ok());
        assert!(validate_bootnode("/ip4/192.168.1.1/tcp/30333/p2p/12D3KooW").is_ok());
        assert!(validate_bootnode("/dns4/node.example.com/tcp/7001").is_ok());
    }

    #[test]
    fn test_validate_bootnode_invalid() {
        assert!(validate_bootnode("").is_err());
        assert!(validate_bootnode("not-a-multiaddr").is_err());
        assert!(validate_bootnode("/ip4/999.999.999.999/tcp/7001").is_err());
        assert!(validate_bootnode("/ip4/1.2.3.4/tcp/99999").is_err());
    }

    #[test]
    fn test_config_valid() {
        let result = validate_config(
            6126151,
            Some(6126151),
            &["/ip4/1.2.3.4/tcp/7001".into()],
            1000,
            true,
            2, // Seed 2 is in validator set.
            &[2, 3, 4],
            "0.0.0.0:9001",
        );
        assert!(result.is_ok(), "{result}");
    }

    #[test]
    fn test_chain_id_mismatch() {
        let result = validate_config(
            6126151,
            Some(9999), // Different!
            &[],
            1000,
            false,
            1,
            &[],
            "0.0.0.0:9001",
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
            1,
            &[],
            "0.0.0.0:9001",
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
            0, // Invalid!
            false,
            1,
            &[],
            "0.0.0.0:9001",
        );
        assert!(!result.is_ok());
        assert!(result.errors.iter().any(|e| e.field.contains("stake_each")));
    }

    #[test]
    fn test_simple_producer_conflict() {
        let result = validate_config(
            6126151,
            None,
            &[],
            1000,
            true, // Producer enabled...
            1,    // ...but seed 1 is NOT a validator.
            &[2, 3, 4],
            "0.0.0.0:9001",
        );
        assert!(!result.is_ok());
        assert!(result
            .errors
            .iter()
            .any(|e| e.field.contains("simple_producer")));
    }

    #[test]
    fn test_duplicate_bootnodes() {
        let result = validate_config(
            6126151,
            None,
            &[
                "/ip4/1.2.3.4/tcp/7001".into(),
                "/ip4/1.2.3.4/tcp/7001".into(), // Duplicate!
            ],
            1000,
            false,
            1,
            &[],
            "0.0.0.0:9001",
        );
        assert!(!result.is_ok());
        assert!(result
            .errors
            .iter()
            .any(|e| e.message.contains("duplicate")));
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
            "", // Empty!
        );
        assert!(!result.is_ok());
        assert!(result.errors.iter().any(|e| e.field.contains("listen")));
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
    fn test_verify_genesis_integrity() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("genesis.json");
        let content = r#"{"chain_id":6126151,"validators":[]}"#;
        std::fs::write(&path, content).unwrap();

        // Without expected hash — just compute.
        let hash = verify_genesis_integrity(&path, None).unwrap();
        assert_ne!(hash, [0u8; 32]);

        // With correct expected hash.
        let result = verify_genesis_integrity(&path, Some(&hash));
        assert!(result.is_ok());

        // With wrong expected hash.
        let bad = [0xFFu8; 32];
        let result = verify_genesis_integrity(&path, Some(&bad));
        assert!(result.is_err());
    }

    #[test]
    fn test_validation_result_display() {
        let result = ValidationResult {
            errors: vec![ValidationError {
                field: "test".into(),
                message: "bad".into(),
            }],
        };
        let s = format!("{result}");
        assert!(s.contains("FAIL"));
        assert!(s.contains("1 errors"));
    }

    #[test]
    fn test_validation_result_ok_display() {
        let result = ValidationResult { errors: vec![] };
        let s = format!("{result}");
        assert!(s.contains("PASS"));
    }

    #[test]
    fn test_validation_into_result() {
        let ok = ValidationResult { errors: vec![] };
        assert!(ok.into_result().is_ok());

        let fail = ValidationResult {
            errors: vec![ValidationError {
                field: "x".into(),
                message: "y".into(),
            }],
        };
        assert!(fail.into_result().is_err());
    }
}
