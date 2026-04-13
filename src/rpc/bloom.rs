use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

/// Ethereum logs bloom filter — 256 bytes (2048 bits).
///
/// Implements the Ethereum bloom filter algorithm (EIP-234):
/// for each inserted item, 3 bit positions are set using consecutive
/// 2-byte windows of the keccak256 hash.
///
/// `Default` is manually derived (not auto-derivable for [u8; 256]).
#[derive(Clone, Debug)]
pub struct Bloom(pub [u8; 256]);

impl Default for Bloom {
    fn default() -> Self {
        Bloom([0u8; 256])
    }
}

impl Bloom {
    /// Create an empty bloom filter.
    pub fn zero() -> Self {
        Self::default()
    }

    /// Insert an item into the bloom filter.
    pub fn insert(&mut self, data: &[u8]) {
        let hash = keccak256(data);
        for i in 0..3 {
            let bitpos = ((hash[2 * i] as u16) << 8 | hash[2 * i + 1] as u16) & 2047;
            let byte_index = (bitpos / 8) as usize;
            let bit_in_byte = (bitpos % 8) as u8;
            self.0[byte_index] |= 1u8 << bit_in_byte;
        }
    }

    /// Test whether an item *might* be in the set (false positive possible).
    pub fn contains(&self, data: &[u8]) -> bool {
        let hash = keccak256(data);
        for i in 0..3 {
            let bitpos = ((hash[2 * i] as u16) << 8 | hash[2 * i + 1] as u16) & 2047;
            let byte_index = (bitpos / 8) as usize;
            let bit_in_byte = (bitpos % 8) as u8;
            if self.0[byte_index] & (1u8 << bit_in_byte) == 0 {
                return false;
            }
        }
        true
    }

    /// Encode to 0x-prefixed hex string (512 hex chars).
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }

    /// Decode from 0x-prefixed or raw hex string.
    pub fn from_hex(s: &str) -> Option<Self> {
        let hexs = s.trim_start_matches("0x");
        let bytes = hex::decode(hexs).ok()?;
        if bytes.len() != 256 {
            return None;
        }
        let mut b = [0u8; 256];
        b.copy_from_slice(&bytes);
        Some(Bloom(b))
    }

    /// Bitwise OR two blooms (aggregate).
    pub fn accrue(&mut self, other: &Bloom) {
        for (a, b) in self.0.iter_mut().zip(other.0.iter()) {
            *a |= b;
        }
    }
}

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(data);
    let r = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&r);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bloom_insert_contains() {
        let mut b = Bloom::default();
        b.insert(b"hello");
        assert!(b.contains(b"hello"));
        assert!(!b.contains(b"world"));
    }

    #[test]
    fn bloom_hex_roundtrip() {
        let mut b = Bloom::default();
        b.insert(b"test");
        let hex = b.to_hex();
        let b2 = Bloom::from_hex(&hex).unwrap();
        assert_eq!(b.0, b2.0);
    }

    #[test]
    fn bloom_default_is_zero() {
        let b = Bloom::default();
        assert!(b.0.iter().all(|&x| x == 0));
    }
}
