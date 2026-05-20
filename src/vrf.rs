//! IONA v33 — On-chain Verifiable Random Function (VRF).
//!
//! Implements **ECVRF-EDWARDS25519-SHA512-TAI** (try-and-increment hash-to-curve)
//! per RFC 9381 Section 5.4.1. This is the same VRF construction used by
//! Algorand, Cardano, and the Ethereum VRF oracle.
//!
//! # How it works
//!
//! 1. Block proposer computes `(output, proof) = VRF_prove(sk, input)`
//!    where `input = prev_block_hash || height`
//! 2. VRF output is included in block header as `random_seed`
//! 3. Validators verify: `VRF_verify(pk, input, proof)` → `output`
//! 4. Contracts read `block.prevrandao` (EVM opcode) → `random_seed`
//!
//! # Security properties
//! - **Uniqueness**: Only one valid output per (sk, input) (binding)
//! - **Pseudorandomness**: Output indistinguishable from random (under DLEQ assumption)
//! - **Verifiability**: Anyone with pk can verify the proof
//!
//! # Protocol (RFC 9381 §5)
//! Given secret scalar `x` and public key `Y = x·B`:
//! 1. `H = ECVRF_hash_to_try_and_increment(pk, input)` — hash input to Ed25519 point
//! 2. `Γ = x·H` — evaluate VRF ("hash to curve + scalar multiply")
//! 3. `k = nonce_generation(sk, input)` — deterministic nonce
//! 4. `c = ECVRF_hash_points(H, Γ, k·B, k·H)` — Fiat-Shamir challenge (16 bytes)
//! 5. `s = k - c·x (mod q)` — response scalar
//! 6. Proof π = (Γ, c, s)
//! 7. Output β = SHA-512(suite || 0x03 || Γ_encoded)[..32]
//!
//! Verification:
//!   U = s·B + c·Y,  V = s·H + c·Γ
//!   c' = ECVRF_hash_points(H, Γ, U, V)
//!   Accept iff c' == c

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as B;
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha512};
use serde::{Deserialize, Serialize};
use crate::types::{Hash32, Height};

/// ECVRF suite string for ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381 §5.5).
const SUITE: u8 = 0x03;
/// ECVRF cofactor for Ed25519 (8).
const COFACTOR: u8 = 8;

// ── VRF Output ────────────────────────────────────────────────────────────

/// VRF output: the random value + cryptographic proof of correctness.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VrfOutput {
    /// The 32-byte VRF output (pseudorandom, used as block randomness).
    pub output: [u8; 32],
    /// RFC 9381 proof π = (Γ, c, s).
    pub proof: VrfProof,
}

/// VRF proof π = (Γ_encoded, c, s) per RFC 9381 §5.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VrfProof {
    /// Proposer's Ed25519 public key (32 bytes).
    pub public_key:  Vec<u8>,
    /// Γ encoded as compressed Edwards point (32 bytes).
    pub gamma:       [u8; 32],
    /// Challenge scalar c (16 bytes, lower half of 32-byte scalar).
    pub c:           [u8; 16],
    /// Response scalar s (32 bytes).
    pub s:           [u8; 32],
}

impl VrfOutput {
    /// Generate a VRF output+proof from an Ed25519 signing key.
    ///
    /// Implements RFC 9381 §5.1 ECVRF_prove.
    ///
    /// `sk` — 32-byte Ed25519 secret key seed
    /// `pk` — corresponding 32-byte public key
    /// `input` — message to evaluate the VRF on
    pub fn generate(sk: &[u8], pk: &[u8], input: &[u8]) -> Self {
        // Expand the Ed25519 secret key → scalar x and nonce prefix
        let mut sk_bytes = [0u8; 32];
        let len = sk.len().min(32);
        sk_bytes[..len].copy_from_slice(&sk[..len]);
        let signing_key = SigningKey::from_bytes(&sk_bytes);

        // Derive scalar x from expanded key (RFC 8032 §5.1.5)
        // expanded = SHA-512(seed); x = clamp(expanded[..32]); nonce_prefix = expanded[32..]
        let expanded = Sha512::digest(&sk_bytes);
        let mut scalar_bytes = [0u8; 32];
        scalar_bytes.copy_from_slice(&expanded[..32]);
        // Clamp per Ed25519 spec
        scalar_bytes[0]  &= 248;
        scalar_bytes[31] &= 127;
        scalar_bytes[31] |= 64;
        let x = Scalar::from_bytes_mod_order(scalar_bytes);

        // Public key Y = x·B
        let y_point = &x * B;

        // Step 1: H = hash_to_try_and_increment(pk, input)
        let h = ecvrf_hash_to_try_and_increment(pk, input);

        // Step 2: Γ = x·H
        let gamma = &x * h;

        // Step 3: Deterministic nonce k (RFC 9381 §5.4.2.2 using nonce_prefix)
        let nonce_prefix = &expanded[32..];
        let k = ecvrf_nonce_generation(nonce_prefix, &h);

        // k·B and k·H for the proof
        let k_b = &k * B;
        let k_h = &k * h;

        // Step 4: Challenge c = hash_points(H, Γ, k·B, k·H) — 16 bytes
        let c_full = ecvrf_hash_points(&[h, gamma, k_b, k_h]);
        let mut c_bytes = [0u8; 16];
        c_bytes.copy_from_slice(&c_full[..16]);

        // Lift c to scalar (RFC 9381 §2.6)
        let mut c_scalar_bytes = [0u8; 32];
        c_scalar_bytes[..16].copy_from_slice(&c_bytes);
        let c_scalar = Scalar::from_bytes_mod_order(c_scalar_bytes);

        // Step 5: s = k - c·x (mod q)
        let s = k - c_scalar * x;

        // Step 6: Output β = SHA-512(suite || 0x03 || Γ_cofactor)[..32]
        let gamma_cofactor = gamma * Scalar::from(COFACTOR as u64);
        let gamma_enc = gamma_cofactor.compress().to_bytes();
        let mut hasher = Sha512::new();
        hasher.update([SUITE, 0x03]);
        hasher.update(gamma_enc);
        let beta = hasher.finalize();
        let mut output = [0u8; 32];
        output.copy_from_slice(&beta[..32]);

        Self {
            output,
            proof: VrfProof {
                public_key:  pk.to_vec(),
                gamma:       gamma.compress().to_bytes(),
                c:           c_bytes,
                s:           s.to_bytes(),
            },
        }
    }

    /// Verify a VRF proof against the public key and input.
    ///
    /// Implements RFC 9381 §5.3 ECVRF_verify.
    /// Returns `true` iff the proof is valid and output is correct.
    pub fn verify(&self, pk: &[u8], input: &[u8]) -> bool {
        if self.proof.public_key != pk { return false; }
        if self.proof.gamma.iter().all(|&b| b == 0) { return false; }

        // Decode Y (public key)
        let mut pk_bytes = [0u8; 32];
        let len = pk.len().min(32);
        pk_bytes[..len].copy_from_slice(&pk[..len]);
        let pk_compressed = CompressedEdwardsY(pk_bytes);
        let y_point = match pk_compressed.decompress() {
            Some(p) => p, None => return false,
        };

        // Decode Γ
        let gamma_compressed = CompressedEdwardsY(self.proof.gamma);
        let gamma = match gamma_compressed.decompress() {
            Some(p) => p, None => return false,
        };

        // Decode s (response scalar)
        let s = Scalar::from_bytes_mod_order(self.proof.s);

        // Lift c (challenge) to scalar
        let mut c_scalar_bytes = [0u8; 32];
        c_scalar_bytes[..16].copy_from_slice(&self.proof.c);
        let c_scalar = Scalar::from_bytes_mod_order(c_scalar_bytes);

        // Step 1: Recompute H
        let h = ecvrf_hash_to_try_and_increment(pk, input);

        // Step 2: U = s·B + c·Y
        let u = EdwardsPoint::vartime_double_scalar_mul_basepoint(&c_scalar, &y_point, &s);

        // Step 3: V = s·H + c·Γ
        let v = s * h + c_scalar * gamma;

        // Step 4: c' = hash_points(H, Γ, U, V)
        let c_prime_full = ecvrf_hash_points(&[h, gamma, u, v]);
        let c_prime = &c_prime_full[..16];

        // Step 5: Accept iff c' == c
        if c_prime != &self.proof.c {
            return false;
        }

        // Step 6: Verify output = SHA-512(suite || 0x03 || Γ_cofactor)[..32]
        let gamma_cofactor = gamma * Scalar::from(COFACTOR as u64);
        let gamma_enc = gamma_cofactor.compress().to_bytes();
        let mut hasher = Sha512::new();
        hasher.update([SUITE, 0x03]);
        hasher.update(gamma_enc);
        let expected_output = hasher.finalize();
        self.output == expected_output[..32]
    }

    /// Compute the per-block VRF input from previous block hash and height.
    pub fn block_input(prev_hash: &Hash32, height: Height) -> Vec<u8> {
        let mut input = Vec::with_capacity(40);
        input.extend_from_slice(&prev_hash.0);
        input.extend_from_slice(&height.to_le_bytes());
        input
    }
}

// ── ECVRF internal functions (RFC 9381) ───────────────────────────────────

/// ECVRF_hash_to_try_and_increment (RFC 9381 §5.4.1.1).
///
/// Hashes (pk, input) to an Ed25519 curve point using try-and-increment.
fn ecvrf_hash_to_try_and_increment(pk: &[u8], input: &[u8]) -> EdwardsPoint {
    let mut ctr: u8 = 0;
    loop {
        let mut hasher = Sha512::new();
        hasher.update([SUITE, 0x01]); // domain separation
        hasher.update(pk);
        hasher.update(input);
        hasher.update([ctr, 0x00]);
        let hash = hasher.finalize();

        let mut candidate = [0u8; 32];
        candidate.copy_from_slice(&hash[..32]);

        if let Some(point) = CompressedEdwardsY(candidate).decompress() {
            // Multiply by cofactor to get a point in the prime-order subgroup
            return point * Scalar::from(COFACTOR as u64);
        }
        ctr = ctr.wrapping_add(1);
        if ctr == 0 { panic!("hash_to_try_and_increment exhausted — cryptographic failure"); }
    }
}

/// ECVRF_nonce_generation (RFC 9381 §5.4.2.2 — deterministic from key and H).
fn ecvrf_nonce_generation(nonce_prefix: &[u8], h: &EdwardsPoint) -> Scalar {
    let h_string = h.compress().to_bytes();
    let mut hasher = Sha512::new();
    hasher.update(nonce_prefix);
    hasher.update(h_string);
    let hash = hasher.finalize();
    Scalar::from_bytes_mod_order_wide(&hash.into())
}

/// ECVRF_hash_points (RFC 9381 §5.4.3) — Fiat-Shamir challenge.
fn ecvrf_hash_points(points: &[EdwardsPoint]) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update([SUITE, 0x02]); // domain separation for challenge
    for p in points {
        hasher.update(p.compress().to_bytes());
    }
    let hash = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash[..32]);
    out
}

// ── BlockRandomness ───────────────────────────────────────────────────────

/// Per-block randomness record stored in block headers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlockRandomness {
    /// The VRF random output (= block.prevrandao for EVM compatibility).
    pub seed: [u8; 32],
    /// VRF proof for verification by validators.
    pub proof: VrfProof,
    /// Combined seed from last N blocks (rolling RANDAO-style).
    pub accumulated_seed: [u8; 32],
}

impl BlockRandomness {
    pub fn generate(
        proposer_sk: &[u8], proposer_pk: &[u8],
        prev_hash: &Hash32, height: Height,
        prev_accumulated: &[u8; 32],
    ) -> Self {
        let input = VrfOutput::block_input(prev_hash, height);
        let vrf = VrfOutput::generate(proposer_sk, proposer_pk, &input);
        let mut accumulated_seed = *prev_accumulated;
        for (i, b) in vrf.output.iter().enumerate() {
            accumulated_seed[i] ^= b;
        }
        let height_bytes = height.to_le_bytes();
        for (i, b) in height_bytes.iter().enumerate() {
            accumulated_seed[i % 32] ^= b;
        }
        Self { seed: vrf.output, proof: vrf.proof, accumulated_seed }
    }

    pub fn verify(&self, proposer_pk: &[u8], prev_hash: &Hash32, height: Height) -> bool {
        let input = VrfOutput::block_input(prev_hash, height);
        let vrf = VrfOutput { output: self.seed, proof: self.proof.clone() };
        vrf.verify(proposer_pk, &input)
    }

    pub fn prevrandao(&self) -> revm::primitives::U256 {
        revm::primitives::U256::from_be_bytes(self.accumulated_seed)
    }
}

// ── VRF Registry ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VrfRegistry {
    pub history: std::collections::BTreeMap<Height, [u8; 32]>,
}

const KEEP_HISTORY: usize = 256;

impl VrfRegistry {
    pub fn record(&mut self, height: Height, seed: [u8; 32]) {
        self.history.insert(height, seed);
        while self.history.len() > KEEP_HISTORY {
            if let Some(&oldest) = self.history.keys().next() {
                self.history.remove(&oldest);
            }
        }
    }
    pub fn get(&self, height: Height) -> Option<[u8; 32]> { self.history.get(&height).copied() }
    pub fn latest_seed(&self) -> [u8; 32] {
        self.history.values().next_back().copied().unwrap_or([0u8; 32])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Hash32;

    /// Real Ed25519 key pair for testing.
    fn test_keypair() -> ([u8; 32], [u8; 32]) {
        // Deterministic test seed
        let sk = [0x42u8; 32];
        let sk_expanded = sha2::Sha512::digest(&sk);
        let mut scalar_bytes = [0u8; 32];
        scalar_bytes.copy_from_slice(&sk_expanded[..32]);
        scalar_bytes[0]  &= 248;
        scalar_bytes[31] &= 127;
        scalar_bytes[31] |= 64;
        let x = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(scalar_bytes);
        let y = &x * curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
        let pk = y.compress().to_bytes();
        (sk, pk)
    }

    #[test]
    fn ecvrf_generate_and_verify() {
        let (sk, pk) = test_keypair();
        let input = b"IONA block 42 prevhash";

        let vrf = VrfOutput::generate(&sk, &pk, input);
        assert_eq!(vrf.output.len(), 32, "output must be 32 bytes");
        assert!(vrf.verify(&pk, input), "valid proof must verify");
    }

    #[test]
    fn ecvrf_deterministic() {
        let (sk, pk) = test_keypair();
        let input = b"same input";
        let v1 = VrfOutput::generate(&sk, &pk, input);
        let v2 = VrfOutput::generate(&sk, &pk, input);
        assert_eq!(v1.output, v2.output, "VRF must be deterministic");
        assert_eq!(v1.proof.gamma, v2.proof.gamma, "gamma must be deterministic");
    }

    #[test]
    fn ecvrf_wrong_pk_fails() {
        let (sk, pk) = test_keypair();
        let vrf = VrfOutput::generate(&sk, &pk, b"input");
        assert!(!vrf.verify(&[0x99u8; 32], b"input"), "wrong pk must fail");
    }

    #[test]
    fn ecvrf_wrong_input_fails() {
        let (sk, pk) = test_keypair();
        let vrf = VrfOutput::generate(&sk, &pk, b"original input");
        assert!(!vrf.verify(&pk, b"tampered input"), "wrong input must fail");
    }

    #[test]
    fn ecvrf_tampered_output_fails() {
        let (sk, pk) = test_keypair();
        let mut vrf = VrfOutput::generate(&sk, &pk, b"input");
        vrf.output[0] ^= 0xFF;
        assert!(!vrf.verify(&pk, b"input"), "tampered output must fail");
    }

    #[test]
    fn ecvrf_tampered_proof_gamma_fails() {
        let (sk, pk) = test_keypair();
        let mut vrf = VrfOutput::generate(&sk, &pk, b"input");
        vrf.proof.gamma[0] ^= 0xFF;
        assert!(!vrf.verify(&pk, b"input"), "tampered gamma must fail");
    }

    #[test]
    fn ecvrf_different_inputs_different_outputs() {
        let (sk, pk) = test_keypair();
        let v1 = VrfOutput::generate(&sk, &pk, b"block-1");
        let v2 = VrfOutput::generate(&sk, &pk, b"block-2");
        assert_ne!(v1.output, v2.output, "different inputs must give different outputs");
    }

    #[test]
    fn block_randomness_full_lifecycle() {
        let (sk, pk) = test_keypair();
        let prev = Hash32([0u8; 32]);
        let prev_acc = [0u8; 32];
        let r = BlockRandomness::generate(&sk, &pk, &prev, 1, &prev_acc);
        assert!(r.verify(&pk, &prev, 1), "block randomness must verify");
        assert!(r.seed.iter().any(|&b| b != 0), "seed must be non-zero");
    }

    #[test]
    fn vrf_registry_caps_history() {
        let mut reg = VrfRegistry::default();
        for i in 0..300u64 { reg.record(i, [i as u8; 32]); }
        assert!(reg.history.len() <= KEEP_HISTORY);
        assert!(reg.get(0).is_none());
        assert!(reg.get(299).is_some());
    }
}
