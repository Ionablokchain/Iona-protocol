use sha3::{Digest, Keccak256};

/// Ethereum logs bloom is 256 bytes (2048 bits).
#[derive(Clone, Debug, Default)]
pub struct Bloom(pub [u8; 256]);

impl Bloom {
    pub fn insert(&mut self, data: &[u8]) {
        let hash = keccak256(data);
        for i in 0..3 {
            let bitpos = ((hash[2*i] as u16) << 8 | (hash[2*i+1] as u16)) & 2047;
            let byte_index = (bitpos / 8) as usize;
            let bit_in_byte = (bitpos % 8) as u8;
            self.0[byte_index] |= 1u8 << bit_in_byte;
        }
    }

    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }
}

pub fn keccak256(data: &[u8]) -> [u8;32] {
    let mut h = Keccak256::new();
    h.update(data);
    let r = h.finalize();
    let mut out=[0u8;32];
    out.copy_from_slice(&r);
    out
}


impl Bloom {
    pub fn from_hex(s: &str) -> Option<Self> {
        let hexs = s.trim_start_matches("0x");
        let bytes = hex::decode(hexs).ok()?;
        if bytes.len() != 256 { return None; }
        let mut b = [0u8;256];
        b.copy_from_slice(&bytes);
        Some(Bloom(b))
    }
}
