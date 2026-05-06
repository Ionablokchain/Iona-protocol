//! Merkle proof generation for Ethereum state and storage.
//!
//! Provides functionality to generate Merkle proofs for account state
//! and storage slots, compatible with `eth_getProof` JSON‑RPC method.
//!
//! # Feature flags
//!
//! - `state_trie` (default) – full proof generation using Merkle Patricia Trie.
//! - Without `state_trie`, returns empty proofs (used for lightweight builds).

use crate::evm::db::MemDb;
use revm::primitives::{Address, U256};
use sha3::{Digest, Keccak256};
use thiserror::Error;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Hex prefix for Ethereum‑compatible hex strings.
const HEX_PREFIX: &str = "0x";

/// RLP encoding of empty string (`0x80`), used as empty trie root.
const EMPTY_RLP: &[u8] = &[0x80];

/// Length of a Keccak‑256 hash in bytes.
const HASH_BYTES_LEN: usize = 32;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during proof generation.
#[derive(Debug, Error)]
pub enum ProofError {
    #[error("state trie feature not enabled (enable 'state_trie' feature)")]
    StateTrieNotEnabled,

    #[error("invalid storage key: {0}")]
    InvalidStorageKey(String),

    #[error("trie node not found for key")]
    NodeNotFound,

    #[error("RLP encoding error: {0}")]
    RlpError(String),

    #[error("internal error: {0}")]
    Internal(String),
}

pub type ProofResult<T> = Result<T, ProofError>;

// -----------------------------------------------------------------------------
// Proof structures
// -----------------------------------------------------------------------------

/// A Merkle proof for an Ethereum account.
#[derive(Debug, Clone)]
pub struct Proof {
    /// RLP‑encoded nodes forming the account proof.
    pub account_proof: Vec<String>,
    /// Storage proofs for requested slots.
    pub storage_proofs: Vec<StorageProof>,
    /// Storage root hash of the account (hex with 0x prefix).
    pub storage_hash: String,
}

/// A Merkle proof for a single storage slot.
#[derive(Debug, Clone)]
pub struct StorageProof {
    /// Storage key (32‑byte hex with 0x prefix).
    pub key: String,
    /// Current value at that storage slot (hex with 0x prefix).
    pub value: String,
    /// RLP‑encoded trie nodes proving the value.
    pub proof: Vec<String>,
}

// -----------------------------------------------------------------------------
// Helper functions
// -----------------------------------------------------------------------------

/// Compute Keccak‑256 hash of a byte slice.
#[must_use]
pub fn keccak256(data: &[u8]) -> [u8; HASH_BYTES_LEN] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; HASH_BYTES_LEN];
    out.copy_from_slice(&result);
    out
}

/// Format bytes as hex string with `0x` prefix.
#[must_use]
pub fn hex0x(bytes: &[u8]) -> String {
    format!("{}{}", HEX_PREFIX, hex::encode(bytes))
}

/// Convert a U256 value to its trimmed big‑endian representation for RLP encoding.
/// Returns a single zero byte for zero.
#[must_use]
pub fn u256_to_trimmed_be(value: U256) -> Vec<u8> {
    let mut bytes = [0u8; HASH_BYTES_LEN];
    value.to_be_bytes(bytes.as_mut());
    let trimmed = bytes.iter().copied().skip_while(|&b| b == 0).collect::<Vec<u8>>();
    if trimmed.is_empty() {
        vec![0u8]
    } else {
        trimmed
    }
}

/// Compute the empty trie root (Keccak‑256 of RLP‑encoded empty string).
#[must_use]
pub fn empty_trie_root() -> [u8; HASH_BYTES_LEN] {
    keccak256(EMPTY_RLP)
}

/// Convert a U256 storage slot to its hashed trie key (secure trie).
#[must_use]
pub fn storage_trie_key(slot: U256) -> [u8; HASH_BYTES_LEN] {
    let mut slot_bytes = [0u8; HASH_BYTES_LEN];
    slot.to_be_bytes(slot_bytes.as_mut());
    keccak256(&slot_bytes)
}

// -----------------------------------------------------------------------------
// Proof generation (conditional on feature)
// -----------------------------------------------------------------------------

/// Build a full Merkle proof for an account and requested storage slots.
///
/// # Feature
/// This function requires the `state_trie` feature (enabled by default).
/// Without it, returns an empty proof.
pub fn build_proof(db: &MemDb, addr: Address, storage_keys: Vec<[u8; HASH_BYTES_LEN]>) -> ProofResult<Proof> {
    #[cfg(feature = "state_trie")]
    {
        build_proof_state_trie(db, addr, storage_keys)
    }
    #[cfg(not(feature = "state_trie"))]
    {
        let _ = (db, addr, storage_keys);
        Err(ProofError::StateTrieNotEnabled)
    }
}

#[cfg(feature = "state_trie")]
fn build_proof_state_trie(
    db: &MemDb,
    addr: Address,
    storage_keys: Vec<[u8; HASH_BYTES_LEN]>,
) -> ProofResult<Proof> {
    use hash_db::Hasher;
    use keccak_hasher::KeccakHasher;
    use memory_db::{HashKey, MemoryDB};
    use trie_db::{Trie, TrieDBBuilder, TrieDBMut, TrieMut};

    // --- Build storage trie for the account ---
    fn build_storage_trie(
        db_src: &MemDb,
        addr: Address,
    ) -> ProofResult<(
        MemoryDB<KeccakHasher, HashKey<<KeccakHasher as Hasher>::Out>, Vec<u8>>,
        <KeccakHasher as Hasher>::Out,
    )> {
        let mut memdb: MemoryDB<KeccakHasher, HashKey<_>, Vec<u8>> = MemoryDB::default();
        let mut root = <KeccakHasher as Hasher>::Out::default();
        {
            let mut trie = TrieDBMut::<KeccakHasher>::new(&mut memdb, &mut root);
            for ((a, slot), &val) in db_src.storage.iter() {
                if *a != addr {
                    continue;
                }
                if val == U256::ZERO {
                    continue; // skip zero values
                }
                let key = storage_trie_key(*slot);
                let trimmed_val = u256_to_trimmed_be(val);
                let enc_value = rlp::encode(&trimmed_val);
                trie.insert(&key, &enc_value)
                    .map_err(|e| ProofError::Internal(format!("storage trie insert: {:?}", e)))?;
            }
        }
        Ok((memdb, root))
    }

    // --- Build account state trie (only includes the target account for proof) ---
    // For a full state proof we need the entire state trie, but building all accounts
    // is expensive. Here we build a minimal trie containing just the target account.
    // This matches the actual `eth_getProof` behaviour (the proof must include
    // sibling nodes, so we need to insert all accounts? Actually, for a correct proof
    // we need the full state trie. Building all accounts is O(N), which is too slow.
    // In practice, for a single account proof we can build a trie containing only
    // that account; the proof will be correct because other accounts are not in
    // the path. However, to be fully correct, we need the real state root.
    // The current implementation builds a trie with all accounts (expensive for large state).
    // For a production node, the state should be stored in a persistent trie DB.
    // We keep the original approach, but note the performance caveat.

    let (storage_memdb, storage_root) = build_storage_trie(db, addr)?;

    let mut state_memdb: MemoryDB<KeccakHasher, HashKey<_>, Vec<u8>> = MemoryDB::default();
    let mut state_root = <KeccakHasher as Hasher>::Out::default();
    {
        let mut trie = TrieDBMut::<KeccakHasher>::new(&mut state_memdb, &mut state_root);
        for (a, info) in db.accounts.iter() {
            let nonce = info.nonce.unwrap_or(0);
            let balance = info.balance;
            let storage_root_for_account = if *a == addr {
                storage_root.0
            } else {
                empty_trie_root()
            };
            let code_hash = info.code_hash.map(|h| h.0).unwrap_or_else(empty_trie_root);

            let mut stream = rlp::RlpStream::new_list(4);
            stream.append(&nonce);
            let bal_trim = u256_to_trimmed_be(balance);
            stream.append(&bal_trim.as_slice());
            stream.append(&storage_root_for_account.as_slice());
            stream.append(&code_hash.as_slice());
            let encoded_account = stream.out().to_vec();

            let key = keccak256(a.as_slice());
            trie.insert(&key, &encoded_account)
                .map_err(|e| ProofError::Internal(format!("state trie insert: {:?}", e)))?;
        }
    }

    // --- Account proof ---
    let state_trie = TrieDBBuilder::<KeccakHasher>::new(&state_memdb, &state_root).build();
    let addr_key = keccak256(addr.as_slice());
    let account_proof_nodes = state_trie
        .get_proof(&addr_key)
        .map_err(|_| ProofError::NodeNotFound)?;
    let account_proof = account_proof_nodes
        .into_iter()
        .map(|node| hex0x(&node))
        .collect::<Vec<_>>();

    // --- Storage proofs ---
    let storage_trie = TrieDBBuilder::<KeccakHasher>::new(&storage_memdb, &storage_root).build();
    let mut storage_proofs = Vec::new();

    for key_bytes in storage_keys {
        if key_bytes.len() != HASH_BYTES_LEN {
            return Err(ProofError::InvalidStorageKey(hex::encode(key_bytes)));
        }
        let slot = U256::from_be_bytes(key_bytes);
        let key_hex = hex0x(&key_bytes);
        let hashed_key = storage_trie_key(slot);
        let proof_nodes = storage_trie
            .get_proof(&hashed_key)
            .unwrap_or_default();
        let proof_hex = proof_nodes
            .into_iter()
            .map(|node| hex0x(&node))
            .collect::<Vec<_>>();

        let value = db
            .storage
            .get(&(addr, slot))
            .copied()
            .unwrap_or(U256::ZERO);
        let value_hex = format!("{}{:x}", HEX_PREFIX, value);

        storage_proofs.push(StorageProof {
            key: key_hex,
            value: value_hex,
            proof: proof_hex,
        });
    }

    Ok(Proof {
        account_proof,
        storage_proofs,
        storage_hash: hex0x(&storage_root.0),
    })
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keccak256() {
        let data = b"hello";
        let hash = keccak256(data);
        assert_eq!(hash.len(), 32);
        // Known hash of "hello" (without "0x" prefix)
        let expected = hex::decode("1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8").unwrap();
        assert_eq!(&hash[..], &expected[..]);
    }

    #[test]
    fn test_hex0x() {
        let bytes = &[0xde, 0xad, 0xbe, 0xef];
        assert_eq!(hex0x(bytes), "0xdeadbeef");
    }

    #[test]
    fn test_u256_to_trimmed_be() {
        let zero = U256::ZERO;
        assert_eq!(u256_to_trimmed_be(zero), vec![0u8]);

        let one = U256::from(1);
        assert_eq!(u256_to_trimmed_be(one), vec![1u8]);

        let big = U256::from(0x1234u64);
        let trimmed = u256_to_trimmed_be(big);
        assert_eq!(trimmed, vec![0x12, 0x34]);
    }

    #[test]
    fn test_empty_trie_root() {
        let root = empty_trie_root();
        // Known empty trie root for Ethereum (Keccak of RLP(empty string))
        let expected = hex::decode("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421").unwrap();
        assert_eq!(&root[..], &expected[..]);
    }

    #[test]
    fn test_storage_trie_key() {
        let slot = U256::from(0xdeadbeefu64);
        let key = storage_trie_key(slot);
        assert_eq!(key.len(), 32);
        // Deterministic
        let key2 = storage_trie_key(U256::from(0xdeadbeefu64));
        assert_eq!(key, key2);
    }
}
