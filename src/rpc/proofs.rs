use crate::evm::db::MemDb;
use revm::primitives::Address;
use sha3::{Digest, Keccak256};

fn keccak256(data: &[u8]) -> [u8;32] {
    let mut h = Keccak256::new();
    h.update(data);
    let r = h.finalize();
    let mut out=[0u8;32];
    out.copy_from_slice(&r);
    out
}

fn hex0x(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

#[derive(Debug, Clone)]
pub struct Proof {
    pub account_proof: Vec<String>,
    pub storage_proofs: Vec<(String, String, Vec<String>)>,
    pub storage_hash: String,
}

pub fn build_proof(db: &MemDb, addr: Address, storage_keys: Vec<[u8;32]>) -> Proof {
    #[cfg(feature="state_trie")]
    {
        return build_proof_state_trie(db, addr, storage_keys);
    }
    #[cfg(not(feature="state_trie"))]
    {
        let _ = (db, addr, storage_keys);
        Proof { account_proof: vec![], storage_proofs: vec![], storage_hash: "0x".to_string() }
    }
}


#[cfg(feature="state_trie")]
fn build_proof_state_trie(db: &MemDb, addr: Address, storage_keys: Vec<[u8;32]>) -> Proof {
    use hash_db::Hasher;
    use keccak_hasher::KeccakHasher;
    use memory_db::{MemoryDB, HashKey};
    use trie_db::{TrieDBMut, TrieMut, TrieDBBuilder, Trie};

    // --- helpers ---
    fn empty_trie_root() -> [u8;32] { keccak256(&[0x80]) } // RLP empty string
    fn u256_to_trimmed_be(v: revm::primitives::U256) -> Vec<u8> {
        let mut b = [0u8;32];
        v.to_be_bytes::<32>(&mut b);
        let t = b.iter().skip_while(|x| **x==0).cloned().collect::<Vec<u8>>();
        if t.is_empty() { vec![0u8] } else { t }
    }

    // Build storage trie for addr and return (root, db, trie)
    fn build_storage_trie(dbsrc: &MemDb, addr: Address) -> (MemoryDB<KeccakHasher, HashKey<<KeccakHasher as Hasher>::Out>, Vec<u8>>, <KeccakHasher as Hasher>::Out) {
        let mut memdb: MemoryDB<KeccakHasher, HashKey<_>, Vec<u8>> = MemoryDB::default();
        let mut root = <KeccakHasher as Hasher>::Out::default();
        {
            let mut trie = TrieDBMut::<KeccakHasher>::new(&mut memdb, &mut root);
            for ((a, slot), val) in dbsrc.storage.iter() {
                if *a != addr { continue; }
                let mut slot_be=[0u8;32];
                slot.to_be_bytes::<32>(&mut slot_be);
                let key = keccak256(&slot_be); // secure trie key
                // value is RLP(trimmed value bytes)
                let enc_bytes = u256_to_trimmed_be(*val);
                let mut s = rlp::RlpStream::new();
                s.append(&enc_bytes.as_slice());
                let enc = s.out().to_vec();
                let _ = trie.insert(&key, &enc);
            }
        }
        (memdb, root)
    }

    // Build state trie and include storageRoot derived from storage trie
    let (stor_memdb, stor_root) = build_storage_trie(db, addr);

    let mut memdb: MemoryDB<KeccakHasher, HashKey<_>, Vec<u8>> = MemoryDB::default();
    let mut root_state = <KeccakHasher as Hasher>::Out::default();
    {
        let mut trie = TrieDBMut::<KeccakHasher>::new(&mut memdb, &mut root_state);
        for (a, info) in db.accounts.iter() {
            let nonce = info.nonce.unwrap_or(0);
            let balance = info.balance;

            // compute storage root for this account (empty unless a==addr to avoid rebuilding all)
            let storage_root = if *a == addr { stor_root.0 } else { empty_trie_root() };

            let code_hash = match info.code_hash {
                Some(h) => h.0,
                None => keccak256(&[]),
            };

            let mut s = rlp::RlpStream::new_list(4);
            s.append(&nonce);
            let bal_trim = u256_to_trimmed_be(balance);
            s.append(&bal_trim.as_slice());
            s.append(&storage_root.as_slice());
            s.append(&code_hash.as_slice());
            let val = s.out().to_vec();

            let key = keccak256(a.as_slice());
            let _ = trie.insert(&key, &val);
        }
    }

    // Account proof
    let trie_state = TrieDBBuilder::<KeccakHasher>::new(&memdb, &root_state).build();
    let addr_key = keccak256(addr.as_slice());
    let nodes = trie_state.get_proof(&addr_key).unwrap_or_default();
    let account_proof = nodes.into_iter().map(|n| hex0x(&n)).collect::<Vec<_>>();

    // Storage proof nodes
    let trie_storage = TrieDBBuilder::<KeccakHasher>::new(&stor_memdb, &stor_root).build();
    let mut storage_proofs = vec![];
    for k in storage_keys {
        let key_hex = hex0x(&k);
        // compute secure trie key = keccak(slot_be_32)
        let key_hashed = keccak256(&k);
        let nodes = trie_storage.get_proof(&key_hashed).unwrap_or_default();
        let proof_nodes = nodes.into_iter().map(|n| hex0x(&n)).collect::<Vec<_>>();

        // value from DB if present
        let val_u = db.storage.get(&(addr, revm::primitives::U256::from_be_bytes(k))).copied().unwrap_or(revm::primitives::U256::ZERO);
        let val_hex = format!("0x{:x}", val_u);

        storage_proofs.push((key_hex, val_hex, proof_nodes));
    }

    Proof {
        account_proof,
        storage_proofs,
        storage_hash: format!("0x{}", hex::encode(stor_root)),
    }
}
