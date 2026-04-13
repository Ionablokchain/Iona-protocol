//! State trie computation — revm primitives compatible (v9).
//!
//! revm v9 AccountInfo uses:
//!   - `nonce: u64`           (not Option<u64>)
//!   - `code_hash: B256`      (not Option<B256>)
//!   - `balance: U256`
//!   - `code: Option<Bytecode>`
//!
//! U256::to_be_bytes::<32>() was removed in newer ruint.
//! Use `U256::to_be_bytes_vec()` or manual conversion via `to_be_bytes_trimmed_vec`.

use crate::evm::db::MemDb;
use revm::primitives::{Address, B256, U256};
use sha3::{Digest, Keccak256};

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(data);
    h.finalize().into()
}

pub fn keccak_hex(data: &[u8]) -> String {
    format!("0x{}", hex::encode(keccak256(data)))
}

/// RLP-encode an Ethereum account: [nonce, balance, storageRoot, codeHash]
fn rlp_account(nonce: u64, balance: U256, storage_root: [u8; 32], code_hash: [u8; 32]) -> Vec<u8> {
    let mut s = rlp::RlpStream::new_list(4);
    s.append(&nonce);
    // U256 → minimal big-endian bytes (no leading zeros)
    let bal_bytes = u256_to_be_trimmed(balance);
    if bal_bytes.is_empty() {
        s.append(&0u8);
    } else {
        s.append(&bal_bytes.as_slice());
    }
    s.append(&storage_root.as_slice());
    s.append(&code_hash.as_slice());
    s.out().to_vec()
}

/// Convert U256 to minimal big-endian bytes (trim leading zeros).
/// Compatible with ruint U256 used in revm v9.
pub fn u256_to_be_trimmed(v: U256) -> Vec<u8> {
    if v == U256::ZERO {
        return vec![];
    }
    // U256 in ruint has to_be_bytes::<32>() returning [u8;32]
    let bytes: [u8; 32] = v.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(31);
    bytes[start..].to_vec()
}

/// Compute storage root for a single account from MemDb.
pub fn compute_storage_root(addr: &Address, db: &MemDb) -> [u8; 32] {
    let mut entries: Vec<([u8; 32], [u8; 32])> = db
        .storage
        .iter()
        .filter(|((a, _), _)| a == addr)
        .filter_map(|((_, key), val)| {
            if *val == U256::ZERO {
                return None;
            }
            let k: [u8; 32] = key.to_be_bytes();
            let v_bytes = u256_to_be_trimmed(*val);
            // RLP encode value as a single-item list for storage trie leaves
            let mut s = rlp::RlpStream::new();
            s.append(&v_bytes.as_slice());
            let v_rlp = s.out().to_vec();
            Some((k, v_rlp.try_into().unwrap_or([0u8; 32])))
        })
        .collect();

    if entries.is_empty() {
        return empty_trie_root();
    }

    entries.sort_by_key(|(k, _)| *k);

    // Simple deterministic hash of sorted (key, value) pairs
    // In production this would be a real secure MPT; here it's a stable placeholder.
    let mut h = Keccak256::new();
    for (k, v) in &entries {
        h.update(keccak256(k)); // secure MPT: key = keccak(slot)
        h.update(v);
    }
    h.finalize().into()
}

/// Empty trie root = keccak256(RLP(0x80)) — matches Ethereum spec.
pub fn empty_trie_root() -> [u8; 32] {
    keccak256(&[0x80])
}

/// Compute stateRoot hex from MemDb.
///
/// Without the `state_trie` feature: returns a deterministic keccak of all
/// account RLP encodings (correct structure, not a real MPT).
///
/// With the `state_trie` feature: uses a real secure MPT backed by memory-db.
pub fn compute_state_root_hex(db: &MemDb) -> String {
    #[cfg(feature = "state_trie")]
    {
        return compute_state_root_hex_mpt(db);
    }
    #[cfg(not(feature = "state_trie"))]
    {
        let mut items: Vec<Vec<u8>> = db
            .accounts
            .iter()
            .map(|(addr, info)| {
                // revm v9: nonce is u64 (not Option)
                let nonce = info.nonce;
                let balance = info.balance;
                let stor_root = compute_storage_root(addr, db);
                // revm v9: code_hash is B256 (not Option)
                let code_hash: [u8; 32] = info.code_hash.0;
                rlp_account(nonce, balance, stor_root, code_hash)
            })
            .collect();

        items.sort();
        let mut h = Keccak256::new();
        for it in &items {
            h.update(it);
        }
        return format!("0x{}", hex::encode(h.finalize()));
    }
}

#[cfg(feature = "state_trie")]
fn compute_state_root_hex_mpt(db: &MemDb) -> String {
    use hash_db::Hasher;
    use keccak_hasher::KeccakHasher;
    use memory_db::{HashKey, MemoryDB};
    use trie_db::{TrieDBMut, TrieMut};

    let mut memdb: MemoryDB<KeccakHasher, HashKey<_>, Vec<u8>> = MemoryDB::default();
    let mut root = <KeccakHasher as Hasher>::Out::default();

    {
        let mut trie = TrieDBMut::new(&mut memdb, &mut root);
        for (addr, info) in &db.accounts {
            let nonce = info.nonce;
            let balance = info.balance;
            let stor_root = compute_storage_root(addr, db);
            let code_hash: [u8; 32] = info.code_hash.0;
            let account_rlp = rlp_account(nonce, balance, stor_root, code_hash);
            // Secure trie: key = keccak256(address)
            let key = keccak256(addr.as_slice());
            let _ = trie.insert(&key, &account_rlp);
        }
    }

    format!("0x{}", hex::encode(root))
}

/// Compute receipts root from a list of RLP-encoded receipts.
pub fn compute_receipts_root_hex(receipt_rlps: &[Vec<u8>]) -> String {
    crate::rpc::mpt::eth_ordered_trie_root_hex(receipt_rlps)
}

/// Compute transactions root from a list of RLP-encoded transactions.
pub fn compute_txs_root_hex(tx_rlps: &[Vec<u8>]) -> String {
    crate::rpc::mpt::eth_ordered_trie_root_hex(tx_rlps)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_trie_root_stable() {
        // Must match Ethereum's empty trie root
        let r = empty_trie_root();
        // keccak256(0x80) = 56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421
        assert_eq!(
            hex::encode(r),
            "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
        );
    }

    #[test]
    fn u256_trimmed_zero() {
        assert!(u256_to_be_trimmed(U256::ZERO).is_empty());
    }

    #[test]
    fn u256_trimmed_one() {
        let b = u256_to_be_trimmed(U256::from(1u64));
        assert_eq!(b, vec![1u8]);
    }

    #[test]
    fn state_root_empty_db() {
        let db = MemDb::default();
        let r = compute_state_root_hex(&db);
        assert!(r.starts_with("0x"));
    }
}
