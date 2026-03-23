//! Ethereum‑style bloom filter implementation (2048 bits, 256 bytes).
//!
//! Used for log filtering in Ethereum‑compatible RPC responses.

use sha3::{Digest, Keccak256};
use std::str::FromStr;

/// Number of bytes in a bloom filter (256 bytes = 2048 bits).
pub const BLOOM_BYTES: usize = 256;
/// Number of bits in a bloom filter.
pub const BLOOM_BITS: usize = BLOOM_BYTES * 8;

/// Ethereum logs bloom filter (2048 bits).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Bloom(pub [u8; BLOOM_BYTES]);

impl Bloom {
    /// Creates a new zeroed bloom filter.
    pub fn new() -> Self {
        Self([0u8; BLOOM_BYTES])
    }

    /// Inserts a piece of data into the bloom filter.
    ///
    /// Sets three bits based on the Keccak-256 hash of `data`.
    /// The bits are determined by the first 6 bytes of the hash,
    /// each 16‑bit value masked with `BLOOM_BITS - 1`.
    pub fn insert(&mut self, data: &[u8]) {
        let hash = keccak256(data);
        for i in 0..3 {
            let bitpos = ((hash[2 * i] as u16) << 8 | (hash[2 * i + 1] as u16)) & (BLOOM_BITS - 1) as u16;
            let byte_index = (bitpos / 8) as usize;
            let bit_in_byte = (bitpos % 8) as u8;
            self.0[byte_index] |= 1u8 << bit_in_byte;
        }
    }

    /// Checks whether the bloom filter contains the given data.
    ///
    /// Returns `true` if all three bits that would be set by `insert(data)`
    /// are already set in this bloom filter. This is used for fast log filtering.
    pub fn contains(&self, data: &[u8]) -> bool {
        let hash = keccak256(data);
        for i in 0..3 {
            let bitpos = ((hash[2 * i] as u16) << 8 | (hash[2 * i + 1] as u16)) & (BLOOM_BITS - 1) as u16;
            let byte_index = (bitpos / 8) as usize;
            let bit_in_byte = (bitpos % 8) as u8;
            if (self.0[byte_index] & (1u8 << bit_in_byte)) == 0 {
                return false;
            }
        }
        true
    }

    /// Returns `true` if the bloom filter is all zeros.
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }

    /// Merges another bloom filter into this one (bitwise OR).
    pub fn or_assign(&mut self, other: &Bloom) {
        for i in 0..BLOOM_BYTES {
            self.0[i] |= other.0[i];
        }
    }

    /// Returns a new bloom filter that is the bitwise OR of `self` and `other`.
    pub fn or(&self, other: &Bloom) -> Bloom {
        let mut res = self.clone();
        res.or_assign(other);
        res
    }

    /// Creates a bloom filter from an iterator of byte slices.
    pub fn from_iter<'a, I>(iter: I) -> Self
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        let mut bloom = Bloom::new();
        for data in iter {
            bloom.insert(data);
        }
        bloom
    }

    /// Returns the hex string representation with a `0x` prefix.
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }

    /// Parses a bloom filter from a hex string (with or without `0x` prefix).
    /// Returns `None` if the string is invalid or the length is not 512 hex characters (256 bytes).
    pub fn from_hex(s: &str) -> Option<Self> {
        let hex_str = s.trim_start_matches("0x");
        if hex_str.len() != BLOOM_BYTES * 2 {
            return None;
        }
        let bytes = hex::decode(hex_str).ok()?;
        let mut arr = [0u8; BLOOM_BYTES];
        arr.copy_from_slice(&bytes);
        Some(Bloom(arr))
    }
}

impl FromStr for Bloom {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s).ok_or("invalid bloom hex string")
    }
}

/// Computes the Keccak-256 hash of the input data and returns it as a 32‑byte array.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bloom_insert_contains() {
        let mut bloom = Bloom::new();
        let data = b"test data";
        bloom.insert(data);
        assert!(bloom.contains(data));
        assert!(!bloom.contains(b"other"));
    }

    #[test]
    fn test_bloom_merge() {
        let mut b1 = Bloom::new();
        let mut b2 = Bloom::new();
        b1.insert(b"a");
        b2.insert(b"b");

        let merged = b1.or(&b2);
        assert!(merged.contains(b"a"));
        assert!(merged.contains(b"b"));
        assert!(!merged.contains(b"c"));
    }

    #[test]
    fn test_bloom_is_zero() {
        let bloom = Bloom::new();
        assert!(bloom.is_zero());

        let mut non_zero = Bloom::new();
        non_zero.insert(b"something");
        assert!(!non_zero.is_zero());
    }

    #[test]
    fn test_bloom_from_iter() {
        let items = vec![b"a", b"b"];
        let bloom = Bloom::from_iter(items);
        assert!(bloom.contains(b"a"));
        assert!(bloom.contains(b"b"));
    }

    #[test]
    fn test_bloom_hex_roundtrip() {
        let mut bloom = Bloom::new();
        bloom.insert(b"test");
        let hex = bloom.to_hex();
        let parsed = Bloom::from_hex(&hex).unwrap();
        assert_eq!(bloom, parsed);
    }

    #[test]
    fn test_bloom_from_str() {
        let hex = "0x0000000000000000000000000000000000000000000000000000000000000000";
        let bloom: Bloom = hex.parse().unwrap();
        assert!(bloom.is_zero());
    }

    #[test]
    fn test_keccak256_length() {
        let hash = keccak256(b"");
        assert_eq!(hash.len(), 32);
        // known empty hash
        assert_eq!(
            hex::encode(hash),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }
}
