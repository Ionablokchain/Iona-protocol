use crate::evm::db::MemDb;
use revm::primitives::{Address, B256, U256};
use std::collections::BTreeMap;
use sha3::{Digest, Keccak256};

/// Ethereum empty trie root (computed as keccak256(rlp(empty))).
/// We compute it at runtime in helper to avoid hardcoding.
fn keccak256(data: &[u8]) -> [u8;32] {
    let mut h = Keccak256::new();
    h.update(data);
    let r = h.finalize();
    let mut out=[0u8;32];
    out.copy_from_slice(&r);
    out
}

fn keccak_hex(data: &[u8]) -> String {
    format!("0x{}", hex::encode(keccak256(data)))
}

/// RLP encode an Ethereum account: [nonce, balance, storageRoot, codeHash]
fn rlp_account(nonce: u64, balance: U256, storage_root: [u8;32], code_hash: [u8;32]) -> Vec<u8> {
    let mut s = rlp::RlpStream::new_list(4);
    s.append(&nonce);
    // U256 as big-endian bytes without leading zeros (rlp handles bytes)
    let mut bal = [0u8;32];
    balance.to_be_bytes::<32>(&mut bal);
    let bal_trim = bal.iter().skip_while(|b| **b == 0).cloned().collect::<Vec<u8>>();
    if bal_trim.is_empty() { s.append(&0u8); } else { s.append(&bal_trim.as_slice()); }
    s.append(&storage_root.as_slice());
    s.append(&code_hash.as_slice());
    s.out().to_vec()
}

/// Compute stateRoot hex.
/// - With feature `state_trie`: uses a real secure MPT (address->account RLP).
/// - Without the feature: returns a stable placeholder keccak of concatenated account encodings.
pub fn compute_state_root_hex(db: &MemDb) -> String {
    #[cfg(feature = "state_trie")]
    {
        return compute_state_root_hex_mpt(db);
    }
    #[cfg(not(feature = "state_trie"))]
    {
        // Placeholder: deterministic but NOT MPT
        let mut items: Vec<Vec<u8>> = vec![];
        for (addr, info) in db.accounts.iter() {
            let nonce = info.nonce.unwrap_or(0);
            let balance = info.balance;
            let storage_root = compute_storage_root(addr, db);
            let code_hash = match info.code_hash {
                Some(h) => h.0,
                None => keccak256(&[]),
            };
            items.push(rlp_account(nonce, balance, storage_root, code_hash));
        }
        items.sort();
        let mut h = Keccak256::new();
        for it in items { h.update(&it); }
        return format!("0x{}", hex::encode(h.finalize()));
    }
}

fn empty_trie_root() -> [u8;32] {
    // keccak256(rlp::NULL) is the empty trie root in Ethereum. Here: RLP empty string is 0x80.
    keccak256(&[0x80])
}

#[cfg(feature = "state_trie")]
fn compute_state_root_hex_mpt(db: &MemDb) -> String {
    use hash_db::Hasher;
    use keccak_hasher::KeccakHasher;
    use memory_db::{MemoryDB, HashKey};
    use trie_db::{TrieDBMut, TrieMut};

    // Build a secure trie: key = keccak(address), value = RLP(account)
    let mut memdb: MemoryDB<KeccakHasher, HashKey<_>, Vec<u8>> = MemoryDB::default();
    let mut root = <KeccakHasher as Hasher>::Out::default();

    {
        let mut trie = TrieDBMut::<KeccakHasher>::new(&mut memdb, &mut root);

        // Insert accounts
        for (addr, info) in db.accounts.iter() {
            let nonce = info.nonce.unwrap_or(0);
            let balance = info.balance;

            // Storage root TODO: compute from db.storage for that address (another secure trie).
            let storage_root = compute_storage_root(addr, db);

            // Code hash
            let code_hash = match info.code_hash {
                Some(h) => h.0,
                None => keccak256(&[]),
            };

            let val = rlp_account(nonce, balance, storage_root, code_hash);

            let key = keccak256(addr.as_slice()); // secure trie uses hashed keys
            trie.insert(&key, &val).map_err(|e| format!("{e:?}")).unwrap();
        }
    }

    format!("0x{}", hex::encode(root))
}


/// Compute storageRoot for a single account from MemDb storage map.
///
/// Storage trie is a secure MPT:
/// - key = keccak256(padded_32(slot))
/// - value = RLP(value_bytes_trimmed)
#[cfg(feature = "state_trie")]
fn compute_storage_root(addr: &Address, db: &MemDb) -> [u8;32] {
    use hash_db::Hasher;
    use keccak_hasher::KeccakHasher;
    use memory_db::{MemoryDB, HashKey};
    use trie_db::{TrieDBMut, TrieMut};

    let mut memdb: MemoryDB<KeccakHasher, HashKey<_>, Vec<u8>> = MemoryDB::default();
    let mut root = <KeccakHasher as Hasher>::Out::default();

    // collect slots sorted for determinism (not required but stable)
    let mut slots: BTreeMap<[u8;32], [u8;32]> = BTreeMap::new();
    for ((a, slot), val) in db.storage.iter() {
        if a == addr {
            let mut k = [0u8;32];
            slot.to_be_bytes::<32>(&mut k);
            let mut v = [0u8;32];
            val.to_be_bytes::<32>(&mut v);
            slots.insert(k, v);
        }
    }

    {
        let mut trie = TrieDBMut::<KeccakHasher>::new(&mut memdb, &mut root);
        for (slot_be, val_be) in slots.into_iter() {
            let key = keccak256(&slot_be); // secure trie key
            // trim leading zeros
            let val_trim = val_be.iter().skip_while(|b| **b == 0).cloned().collect::<Vec<u8>>();
            let mut s = rlp::RlpStream::new();
            if val_trim.is_empty() {
                s.append(&0u8);
            } else {
                s.append(&val_trim.as_slice());
            }
            let enc = s.out().to_vec();
            trie.insert(&key, &enc).map_err(|e| format!("{e:?}")).unwrap();
        }
    }

    root
}

/// Public wrapper: compute storage root for an address as a hex string.
/// Works with or without the `state_trie` feature flag.
pub fn compute_storage_root_hex(addr: &Address, db: &MemDb) -> String {
    use sha3::{Digest, Keccak256};

    #[cfg(feature = "state_trie")]
    {
        let root = compute_storage_root(addr, db);
        return format!("0x{}", hex::encode(root));
    }

    #[cfg(not(feature = "state_trie"))]
    {
        // Deterministic but non-MPT fallback: hash all (slot, value) pairs for this account
        let mut pairs: Vec<([u8; 32], [u8; 32])> = db.storage.iter()
            .filter(|((a, _), _)| a == addr)
            .map(|((_, slot), val)| {
                let mut k = [0u8; 32];
                let mut v = [0u8; 32];
                slot.to_be_bytes::<32>(&mut k);
                val.to_be_bytes::<32>(&mut v);
                (k, v)
            })
            .collect();

        if pairs.is_empty() {
            // Empty trie root: keccak256(0x80)
            let mut h = Keccak256::new();
            h.update(&[0x80u8]);
            return format!("0x{}", hex::encode(h.finalize()));
        }

        pairs.sort_by_key(|(k, _)| *k);
        let mut h = Keccak256::new();
        for (k, v) in pairs {
            h.update(k);
            h.update(v);
        }
        format!("0x{}", hex::encode(h.finalize()))
    }
}
