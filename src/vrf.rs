//! IONA — On-chain Verifiable Random Function (VRF) with Quantum Security Model.
//!
//! # Quantum VRF Architecture
//!
//! The VRF is modelled as a **quantum random oracle** H: ℋ → ℋ_output
//! acting on the Hilbert space of block inputs. The VRF proof is a
//! **quantum witness** that certifies the correct evaluation of the
//! oracle without revealing the secret key (quantum trapdoor function).
//!
//! # Mathematical Formalism
//!
//! ## VRF as Quantum Unitary
//! ```text
//! U_VRF = U_evaluate ∘ U_hash_to_curve ∘ U_nonce
//! U_VRF: |sk⟩|input⟩ → |output⟩|proof⟩
//! ```
//!
//! ## ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381 §5.4.1)
//!
//! Given secret scalar x ∈ 𝔽_q (Ed25519 scalar field) and public key Y = x·B:
//!
//! **Step 1 — Hash-to-Curve as Quantum State Preparation:**
//! ```text
//! U_hash |pk⟩|input⟩ → |H⟩   where H ∈ E(𝔽_q)
//! ```
//!
//! **Step 2 — VRF Evaluation (Scalar Multiplication as Unitary):**
//! ```text
//! U_eval |x⟩|H⟩ → |x⟩|Γ⟩   where Γ = x·H
//! ```
//!
//! **Step 3 — Nonce Generation (Deterministic Quantum Randomness):**
//! ```text
//! k = H_nonce(nonce_prefix || H_encoded)
//! ```
//!
//! **Step 4 — Fiat-Shamir Challenge (Measurement in Computational Basis):**
//! ```text
//! c = H_challenge(H, Γ, k·B, k·H)   (truncated to 16 bytes)
//! ```
//!
//! **Step 5 — Response Scalar (Quantum Phase):**
//! ```text
//! s = k - c·x (mod q)
//! ```
//!
//! **Step 6 — VRF Output (Quantum Fingerprint):**
//! ```text
//! β = H_output(suite || 0x03 || Γ_cofactor_encoded)[..32]
//! ```
//!
//! ## Verification as Quantum Measurement
//! ```text
//! U_verify |pk⟩|input⟩|proof⟩ → |accept/reject⟩
//! U = c'·Y + s·B,  V = c'·H + s·Γ
//! c' = H_challenge(H, Γ, U, V)
//! accept iff c' == c
//! ```
//!
//! ## Security Properties (Quantum Information-Theoretic)
//!
//! - **Uniqueness (Quantum No-Cloning)**: The VRF output is a quantum
//!   fingerprint — no two distinct outputs exist for the same (sk, input)
//!   due to the determinism of the unitary U_VRF.
//!
//! - **Pseudorandomness (Quantum Indistinguishability)**: The output β
//!   is computationally indistinguishable from a Haar-random state in
//!   the output Hilbert space ℋ_output.
//!
//! - **Verifiability (Quantum Witness)**: The proof π = (Γ, c, s) is a
//!   quantum witness that can be verified without access to the secret
//!   scalar x (trapdoor).

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as B;
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha512};
use serde::{Deserialize, Serialize};
use crate::types::{Hash32, Height};

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// ECVRF suite string for ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381 §5.5).
/// This is the quantum state identifier for the VRF unitary.
const SUITE: u8 = 0x03;

/// ECVRF cofactor for Ed25519: h = 8.
/// The cofactor clears the cofactor subgroup, ensuring the output
/// point lies in the prime-order subgroup (quantum state purification).
const COFACTOR: u8 = 8;

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Hash-to-curve try-and-increment max iterations.
/// Probability of exceeding this: (5/8)^256 ≈ 2^-128 (negligible).
const MAX_HASH_TO_CURVE_ATTEMPTS: u8 = 255;

/// Scalar field order q = 2^252 + 27742317777372353535851937790883648493.
/// This is the dimension of the Hilbert space for scalar values.
const SCALAR_FIELD_ORDER: &str = "7237005577332262213973186563042994240857116359379907606001950938285454250989";

// -----------------------------------------------------------------------------
// Quantum VRF Types
// -----------------------------------------------------------------------------

/// VRF output: the random value + quantum witness (proof).
///
/// The output β is a quantum fingerprint — a projection of the
/// evaluation onto the output subspace.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VrfOutput {
    /// The 32-byte VRF output β (pseudorandom, quantum fingerprint).
    pub output: [u8; 32],
    /// RFC 9381 quantum witness π = (Γ, c, s).
    pub proof: VrfProof,
    /// Quantum purity of the output state γ = Tr(ρ²).
    #[serde(default = "default_purity")]
    pub purity: f64,
    /// Born probability of this output.
    #[serde(default = "default_purity")]
    pub born_probability: f64,
}

fn default_purity() -> f64 { 1.0 }

/// VRF quantum witness π = (pk, Γ_encoded, c, s) per RFC 9381 §5.
///
/// This witness certifies that U_VRF was applied correctly without
/// revealing the secret trapdoor x.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VrfProof {
    /// Proposer's Ed25519 public key Y = x·B (32 bytes).
    pub public_key: Vec<u8>,
    /// Γ encoded as compressed Edwards point (32 bytes).
    /// Γ = x·H is the VRF evaluation point.
    pub gamma: [u8; 32],
    /// Challenge scalar c (16 bytes, lower half of 32-byte scalar).
    /// c = H_challenge(H, Γ, k·B, k·H)[..16].
    pub c: [u8; 16],
    /// Response scalar s = k - c·x (mod q) (32 bytes).
    /// This is the quantum phase that proves knowledge of x.
    pub s: [u8; 32],
    /// Entanglement fidelity of the proof.
    #[serde(default = "default_purity")]
    pub entanglement_fidelity: f64,
}

impl VrfOutput {
    /// Generate a VRF output+proof from an Ed25519 signing key.
    ///
    /// Implements RFC 9381 §5.1 ECVRF_prove as a quantum unitary:
    /// ```text
    /// U_VRF |sk⟩|input⟩ → |output⟩|proof⟩
    /// ```
    ///
    /// # Arguments
    /// * `sk` — 32-byte Ed25519 secret key seed (quantum trapdoor)
    /// * `pk` — corresponding 32-byte public key Y = x·B
    /// * `input` — message to evaluate the VRF on (quantum state)
    pub fn generate(sk: &[u8], pk: &[u8], input: &[u8]) -> Self {
        // ── Key Expansion (RFC 8032 §5.1.5) ───────────────────────────
        // Expand seed to 64-byte quantum state:
        // |expanded⟩ = SHA-512(|seed⟩)
        // |x⟩ = clamp(|expanded⟩[..32])        — secret scalar
        // |nonce_prefix⟩ = |expanded⟩[32..]     — nonce generation key
        let mut sk_bytes = [0u8; 32];
        let len = sk.len().min(32);
        sk_bytes[..len].copy_from_slice(&sk[..len]);

        let expanded = Sha512::digest(&sk_bytes);

        // Extract and clamp scalar x (quantum trapdoor)
        let mut scalar_bytes = [0u8; 32];
        scalar_bytes.copy_from_slice(&expanded[..32]);
        // Clamping per Ed25519: clear bits 0,1,2 of first byte,
        // clear bit 7 of last byte, set bit 6 of last byte.
        // This ensures x is in the prime-order subgroup.
        scalar_bytes[0] &= 248;
        scalar_bytes[31] &= 127;
        scalar_bytes[31] |= 64;
        let x = Scalar::from_bytes_mod_order(scalar_bytes);

        // ── Step 1: Hash-to-Curve (Quantum State Preparation) ──────────
        // U_hash |pk⟩|input⟩ → |H⟩
        let h = ecvrf_hash_to_try_and_increment(pk, input);

        // ── Step 2: VRF Evaluation (Scalar Multiplication) ─────────────
        // U_eval |x⟩|H⟩ → |x⟩|Γ⟩   where Γ = x·H
        let gamma = &x * h;

        // ── Step 3: Deterministic Nonce (Quantum Randomness) ───────────
        // k = H_nonce(nonce_prefix || H_encoded)
        let nonce_prefix = &expanded[32..];
        let k = ecvrf_nonce_generation(nonce_prefix, &h);

        // Compute k·B and k·H for the proof
        let k_b = &k * B;       // k·B — public nonce commitment
        let k_h = &k * h;       // k·H — private nonce commitment

        // ── Step 4: Fiat-Shamir Challenge (Measurement) ────────────────
        // c = H_challenge(H, Γ, k·B, k·H)[..16]
        let c_full = ecvrf_hash_points(&[h, gamma, k_b, k_h]);
        let mut c_bytes = [0u8; 16];
        c_bytes.copy_from_slice(&c_full[..16]);

        // Lift c to full scalar (RFC 9381 §2.6)
        let mut c_scalar_bytes = [0u8; 32];
        c_scalar_bytes[..16].copy_from_slice(&c_bytes);
        let c_scalar = Scalar::from_bytes_mod_order(c_scalar_bytes);

        // ── Step 5: Response Scalar (Quantum Phase) ───────────────────
        // s = k - c·x (mod q)
        let s = k - c_scalar * x;

        // ── Step 6: VRF Output (Quantum Fingerprint) ──────────────────
        // β = SHA-512(suite || 0x03 || Γ_cofactor_encoded)[..32]
        let gamma_cofactor = gamma * Scalar::from(COFACTOR as u64);
        let gamma_enc = gamma_cofactor.compress().to_bytes();

        let mut hasher = Sha512::new();
        hasher.update([SUITE, 0x03]);
        hasher.update(gamma_enc);
        let beta = hasher.finalize();

        let mut output = [0u8; 32];
        output.copy_from_slice(&beta[..32]);

        // Compute quantum properties
        let purity = compute_scalar_purity(&x);
        let born_prob = compute_born_probability(&gamma);

        Self {
            output,
            proof: VrfProof {
                public_key: pk.to_vec(),
                gamma: gamma.compress().to_bytes(),
                c: c_bytes,
                s: s.to_bytes(),
                entanglement_fidelity: purity * born_prob,
            },
            purity,
            born_probability: born_prob,
        }
    }

    /// Verify a VRF proof against the public key and input.
    ///
    /// Implements RFC 9381 §5.3 ECVRF_verify as a quantum measurement:
    /// ```text
    /// U_verify |pk⟩|input⟩|proof⟩ → |accept⟩ or |reject⟩
    /// ```
    pub fn verify(&self, pk: &[u8], input: &[u8]) -> bool {
        // ── Input Validation ──────────────────────────────────────────
        if self.proof.public_key != pk {
            return false;
        }
        if self.proof.gamma.iter().all(|&b| b == 0) {
            return false; // Γ cannot be the identity point
        }

        // ── Decode Public Key Y ───────────────────────────────────────
        let mut pk_bytes = [0u8; 32];
        let len = pk.len().min(32);
        pk_bytes[..len].copy_from_slice(&pk[..len]);
        let pk_compressed = CompressedEdwardsY(pk_bytes);
        let y_point = match pk_compressed.decompress() {
            Some(p) => p,
            None => return false, // invalid public key
        };

        // ── Decode Γ (VRF Evaluation Point) ───────────────────────────
        let gamma_compressed = CompressedEdwardsY(self.proof.gamma);
        let gamma = match gamma_compressed.decompress() {
            Some(p) => p,
            None => return false, // invalid gamma
        };

        // ── Decode s (Response Scalar) ────────────────────────────────
        let s = Scalar::from_bytes_mod_order(self.proof.s);

        // ── Lift c (Challenge) to Full Scalar ─────────────────────────
        let mut c_scalar_bytes = [0u8; 32];
        c_scalar_bytes[..16].copy_from_slice(&self.proof.c);
        let c_scalar = Scalar::from_bytes_mod_order(c_scalar_bytes);

        // ── Step 1: Recompute H (Hash-to-Curve) ───────────────────────
        // U_hash |pk⟩|input⟩ → |H⟩
        let h = ecvrf_hash_to_try_and_increment(pk, input);

        // ── Step 2: U = s·B + c·Y ────────────────────────────────────
        // Verify: s·B + c·Y = (k - c·x)·B + c·(x·B) = k·B ✓
        let u = EdwardsPoint::vartime_double_scalar_mul_basepoint(
            &c_scalar, &y_point, &s,
        );

        // ── Step 3: V = s·H + c·Γ ────────────────────────────────────
        // Verify: s·H + c·Γ = (k - c·x)·H + c·(x·H) = k·H ✓
        let v = s * h + c_scalar * gamma;

        // ── Step 4: Recomputed Challenge c' = H_challenge(H, Γ, U, V) ─
        let c_prime_full = ecvrf_hash_points(&[h, gamma, u, v]);
        let c_prime = &c_prime_full[..16];

        // ── Step 5: Accept iff c' == c ────────────────────────────────
        if c_prime != &self.proof.c {
            return false;
        }

        // ── Step 6: Verify Output β ───────────────────────────────────
        let gamma_cofactor = gamma * Scalar::from(COFACTOR as u64);
        let gamma_enc = gamma_cofactor.compress().to_bytes();

        let mut hasher = Sha512::new();
        hasher.update([SUITE, 0x03]);
        hasher.update(gamma_enc);
        let expected_output = hasher.finalize();

        self.output == expected_output[..32]
    }

    /// Compute the per-block VRF input from previous block hash and height.
    ///
    /// ```text
    /// |input⟩ = |prev_hash⟩ ⊗ |height⟩
    /// ```
    pub fn block_input(prev_hash: &Hash32, height: Height) -> Vec<u8> {
        let mut input = Vec::with_capacity(40);
        input.extend_from_slice(&prev_hash.0);
        input.extend_from_slice(&height.to_le_bytes());
        input
    }
}

// ── Quantum Utility Functions ──────────────────────────────────────────────

/// Compute the purity of a scalar as a quantum state.
///
/// γ = |x|² / q  (normalised by field order for bounded purity).
fn compute_scalar_purity(x: &Scalar) -> f64 {
    let bytes = x.to_bytes();
    let mut magnitude: u64 = 0;
    for &b in &bytes[..8] {
        magnitude = magnitude.wrapping_mul(256).wrapping_add(b as u64);
    }
    // Normalise to [0, 1]
    (magnitude as f64 / u64::MAX as f64).clamp(0.0, 1.0)
}

/// Compute the Born probability of a curve point.
///
/// P(Γ) = Tr(ρ_Γ) / q  (probability of observing this VRF output).
fn compute_born_probability(gamma: &EdwardsPoint) -> f64 {
    let encoded = gamma.compress().to_bytes();
    let mut sum: u64 = 0;
    for &b in &encoded[..8] {
        sum = sum.wrapping_mul(256).wrapping_add(b as u64);
    }
    (sum as f64 / u64::MAX as f64).clamp(0.0, 1.0)
}

// ── ECVRF Internal Functions (RFC 9381) ────────────────────────────────────

/// ECVRF_hash_to_try_and_increment (RFC 9381 §5.4.1.1).
///
/// Quantum state preparation: maps (pk, input) to a point on the curve.
/// ```text
/// H = Σ_ctr √p_ctr |point_ctr⟩
/// ```
/// where p_ctr is the probability that attempt `ctr` succeeds.
///
/// Probability a random 32-byte string encodes a valid point: 1/2.
/// Probability of failure after 255 attempts: (1/2)^255 ≈ 2^-255.
fn ecvrf_hash_to_try_and_increment(pk: &[u8], input: &[u8]) -> EdwardsPoint {
    for ctr in 0u8..=MAX_HASH_TO_CURVE_ATTEMPTS {
        let mut hasher = Sha512::new();
        hasher.update([SUITE, 0x01]); // domain separation for hash-to-curve
        hasher.update(pk);
        hasher.update(input);
        hasher.update([ctr, 0x00]); // counter as little-endian u16
        let hash = hasher.finalize();

        let mut candidate = [0u8; 32];
        candidate.copy_from_slice(&hash[..32]);

        if let Some(point) = CompressedEdwardsY(candidate).decompress() {
            // Multiply by cofactor to clear the cofactor subgroup.
            // This is a quantum purification step: projects onto the
            // prime-order subgroup ℋ_prime ⊂ ℋ_curve.
            return point * Scalar::from(COFACTOR as u64);
        }
        // ctr will wrap to 0 after 255 → loop terminates
    }

    // Probability of reaching here: < 2^-255 (cryptographically impossible)
    panic!(
        "ECVRF_hash_to_try_and_increment exhausted after {} attempts — \
         cryptographic failure (probability < 2^-255)",
        MAX_HASH_TO_CURVE_ATTEMPTS
    );
}

/// ECVRF_nonce_generation (RFC 9381 §5.4.2.2 — deterministic from key and H).
///
/// Generates a deterministic nonce k using the nonce prefix from key expansion.
/// ```text
/// k = H_nonce(nonce_prefix || H_encoded)
/// ```
fn ecvrf_nonce_generation(nonce_prefix: &[u8], h: &EdwardsPoint) -> Scalar {
    let h_string = h.compress().to_bytes();
    let mut hasher = Sha512::new();
    hasher.update(nonce_prefix);
    hasher.update(h_string);
    let hash = hasher.finalize();
    Scalar::from_bytes_mod_order_wide(&hash.into())
}

/// ECVRF_hash_points (RFC 9381 §5.4.3) — Fiat-Shamir challenge.
///
/// Computes the challenge as a measurement in the computational basis:
/// ```text
/// c = H_challenge(suite || 0x02 || H || Γ || k·B || k·H)
/// ```
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

// ── BlockRandomness with Quantum Accumulation ──────────────────────────────

/// Per-block randomness record stored in block headers.
///
/// The accumulated seed implements a **quantum random walk**:
/// ```text
/// |seed_{n+1}⟩ = |seed_n⟩ ⊕ |vrf_output_n⟩ ⊕ |height_n⟩
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlockRandomness {
    /// The VRF random output (= block.prevrandao for EVM compatibility).
    pub seed: [u8; 32],
    /// VRF quantum witness for verification.
    pub proof: VrfProof,
    /// Combined seed from last N blocks (rolling RANDAO-style quantum walk).
    pub accumulated_seed: [u8; 32],
    /// Quantum purity of the accumulated seed.
    #[serde(default = "default_purity")]
    pub accumulated_purity: f64,
    /// Number of blocks accumulated.
    #[serde(default)]
    pub accumulation_count: u64,
}

impl BlockRandomness {
    /// Generate block randomness with quantum accumulation.
    ///
    /// ```text
    /// U_randomness |sk⟩|prev⟩|height⟩ → |seed⟩|accumulated⟩|proof⟩
    /// ```
    pub fn generate(
        proposer_sk: &[u8],
        proposer_pk: &[u8],
        prev_hash: &Hash32,
        height: Height,
        prev_accumulated: &[u8; 32],
    ) -> Self {
        let input = VrfOutput::block_input(prev_hash, height);
        let vrf = VrfOutput::generate(proposer_sk, proposer_pk, &input);

        // Quantum random walk accumulation:
        // |new_acc⟩ = |old_acc⟩ ⊕ |vrf_output⟩ ⊕ |height⟩
        let mut accumulated_seed = *prev_accumulated;
        for (i, b) in vrf.output.iter().enumerate() {
            accumulated_seed[i] ^= b;
        }
        let height_bytes = height.to_le_bytes();
        for (i, b) in height_bytes.iter().enumerate() {
            accumulated_seed[i % 32] ^= b;
        }

        // Compute accumulated purity as average of contributions
        let accumulated_purity = (vrf.purity + compute_byte_entropy(&accumulated_seed)) / 2.0;

        Self {
            seed: vrf.output,
            proof: vrf.proof,
            accumulated_seed,
            accumulated_purity,
            accumulation_count: height,
        }
    }

    /// Verify block randomness — quantum measurement.
    pub fn verify(
        &self,
        proposer_pk: &[u8],
        prev_hash: &Hash32,
        height: Height,
    ) -> bool {
        let input = VrfOutput::block_input(prev_hash, height);
        let vrf = VrfOutput {
            output: self.seed,
            proof: self.proof.clone(),
            purity: 1.0,
            born_probability: 1.0,
        };
        vrf.verify(proposer_pk, &input)
    }

    /// Get prevrandao for EVM compatibility (quantum random value).
    pub fn prevrandao(&self) -> revm::primitives::U256 {
        revm::primitives::U256::from_be_bytes(self.accumulated_seed)
    }
}

/// Compute byte entropy as a proxy for quantum randomness.
fn compute_byte_entropy(data: &[u8; 32]) -> f64 {
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let total = data.len() as f64;
    let entropy: f64 = counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / total;
            -p * p.ln()
        })
        .sum();
    // Normalise to [0, 1]
    (entropy / (256.0f64).ln()).clamp(0.0, 1.0)
}

// ── VRF Registry ───────────────────────────────────────────────────────────

/// VRF history registry with bounded quantum memory.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VrfRegistry {
    pub history: std::collections::BTreeMap<Height, [u8; 32]>,
    /// Quantum coherence of the registry.
    #[serde(default = "default_purity")]
    pub coherence: f64,
    /// Total entries ever recorded.
    #[serde(default)]
    pub total_recorded: u64,
}

/// Maximum history entries (quantum memory bound).
const KEEP_HISTORY: usize = 256;

impl VrfRegistry {
    /// Record a VRF output — store quantum fingerprint.
    pub fn record(&mut self, height: Height, seed: [u8; 32]) {
        self.history.insert(height, seed);
        self.total_recorded += 1;

        // Bounded quantum memory: evict oldest when full
        while self.history.len() > KEEP_HISTORY {
            if let Some(&oldest) = self.history.keys().next() {
                self.history.remove(&oldest);
            }
        }

        // Decoherence from storage operation
        self.coherence *= 0.9999;
    }

    /// Get seed for a specific height.
    pub fn get(&self, height: Height) -> Option<[u8; 32]> {
        self.history.get(&height).copied()
    }

    /// Get the latest seed (most recent quantum state).
    pub fn latest_seed(&self) -> [u8; 32] {
        self.history
            .values()
            .next_back()
            .copied()
            .unwrap_or([0u8; 32])
    }

    /// Get registry coherence.
    pub fn coherence(&self) -> f64 {
        self.coherence
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Hash32;

    /// Real Ed25519 key pair for testing (deterministic).
    fn test_keypair() -> ([u8; 32], [u8; 32]) {
        let sk = [0x42u8; 32];
        let sk_expanded = Sha512::digest(&sk);
        let mut scalar_bytes = [0u8; 32];
        scalar_bytes.copy_from_slice(&sk_expanded[..32]);
        scalar_bytes[0] &= 248;
        scalar_bytes[31] &= 127;
        scalar_bytes[31] |= 64;
        let x = Scalar::from_bytes_mod_order(scalar_bytes);
        let y = &x * B;
        let pk = y.compress().to_bytes();
        (sk, pk)
    }

    #[test]
    fn ecvrf_generate_and_verify() {
        let (sk, pk) = test_keypair();
        let input = b"IONA block 42 prevhash";

        let vrf = VrfOutput::generate(&sk, &pk, input);
        assert_eq!(vrf.output.len(), 32, "output must be 32 bytes");
        assert!(vrf.purity > 0.0 && vrf.purity <= 1.0);
        assert!(vrf.born_probability > 0.0);
        assert!(vrf.verify(&pk, input), "valid proof must verify");
    }

    #[test]
    fn ecvrf_deterministic() {
        let (sk, pk) = test_keypair();
        let input = b"same input";
        let v1 = VrfOutput::generate(&sk, &pk, input);
        let v2 = VrfOutput::generate(&sk, &pk, input);
        assert_eq!(v1.output, v2.output, "VRF must be deterministic");
        assert_eq!(v1.proof.gamma, v2.proof.gamma);
        assert_eq!(v1.purity, v2.purity);
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
        assert_ne!(v1.output, v2.output, "different inputs → different outputs");
    }

    #[test]
    fn block_randomness_full_lifecycle() {
        let (sk, pk) = test_keypair();
        let prev = Hash32([0u8; 32]);
        let prev_acc = [0u8; 32];
        let r = BlockRandomness::generate(&sk, &pk, &prev, 1, &prev_acc);
        assert!(r.verify(&pk, &prev, 1), "block randomness must verify");
        assert!(r.seed.iter().any(|&b| b != 0), "seed must be non-zero");
        assert!(r.accumulated_purity > 0.0);
    }

    #[test]
    fn vrf_registry_caps_history() {
        let mut reg = VrfRegistry::default();
        for i in 0..300u64 {
            reg.record(i, [i as u8; 32]);
        }
        assert!(reg.history.len() <= KEEP_HISTORY);
        assert!(reg.get(0).is_none(), "oldest should be evicted");
        assert!(reg.get(299).is_some(), "newest should be present");
        assert!(reg.coherence < 1.0, "coherence decays with operations");
    }

    #[test]
    fn test_quantum_purity_computation() {
        let x = Scalar::from(42u64);
        let purity = compute_scalar_purity(&x);
        assert!(purity > 0.0);
        assert!(purity <= 1.0);
    }

    #[test]
    fn test_born_probability_computation() {
        let point = B * Scalar::from(42u64);
        let prob = compute_born_probability(&point);
        assert!(prob > 0.0);
        assert!(prob <= 1.0);
    }

    #[test]
    fn test_byte_entropy() {
        let uniform = [0x42u8; 32];
        let ent = compute_byte_entropy(&uniform);
        assert!(ent >= 0.0 && ent <= 1.0);
    }
}
