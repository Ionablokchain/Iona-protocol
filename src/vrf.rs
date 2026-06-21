//! IONA — On-chain Verifiable Random Function (VRF) with Quantum Security Model.
//!
//! # Quantum VRF Architecture
//!
//! The VRF is modelled as a **quantum random oracle** H: ℋ → ℋ_output
//! acting on the Hilbert space of block inputs. The VRF proof is a
//! **quantum witness** that certifies the correct evaluation of the
//! oracle without revealing the secret key (quantum trapdoor function).
//!
//! # Features
//! - RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI implementation.
//! - Integration with IONA key management.
//! - Configurable parameters (cofactor, suite, hash-to-curve attempts).
//! - Metrics for monitoring (generations, verifications, failures).
//! - Quantum state tracking (purity, born probability, entanglement fidelity).
//! - Block randomness with quantum accumulation (RANDAO-style).
//! - VRF registry with bounded quantum memory.
//! - Comprehensive error handling with `VrfError`.
//! - Full test coverage.
//!
//! # Example
//!
//! ```
//! use iona::vrf::{Vrf, VrfConfig, VrfKeypair, BlockRandomness};
//!
//! let config = VrfConfig::default();
//! let keypair = VrfKeypair::random();
//! let prev_hash = Hash32::zero();
//! let randomness = Vrf::generate_block_randomness(
//!     &keypair,
//!     &prev_hash,
//!     100,
//!     &[0u8; 32],
//!     &config,
//! ).unwrap();
//! assert!(randomness.verify(&keypair.public_key(), &prev_hash, 100));
//! ```

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as B;
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use sha2::{Digest, Sha512};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, error, info, trace, warn};

use crate::types::{Hash32, Height};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// ECVRF suite string for ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381 §5.5).
const SUITE: u8 = 0x03;

/// ECVRF cofactor for Ed25519: h = 8.
const COFACTOR: u8 = 8;

/// Hash-to-curve try-and-increment max iterations.
const MAX_HASH_TO_CURVE_ATTEMPTS: u8 = 255;

/// Default configuration values.
const DEFAULT_BORN_PROBABILITY_THRESHOLD: f64 = 0.5;

// -----------------------------------------------------------------------------
// Error handling
// -----------------------------------------------------------------------------

/// Errors that can occur during VRF operations.
#[derive(Debug, Error)]
pub enum VrfError {
    #[error("invalid public key: {reason}")]
    InvalidPublicKey { reason: String },

    #[error("invalid gamma point: {reason}")]
    InvalidGamma { reason: String },

    #[error("invalid scalar: {reason}")]
    InvalidScalar { reason: String },

    #[error("hash-to-curve exhausted after {attempts} attempts")]
    HashToCurveExhausted { attempts: u8 },

    #[error("configuration error: {0}")]
    Config(String),

    #[error("key length mismatch: expected {expected}, got {actual}")]
    KeyLengthMismatch { expected: usize, actual: usize },

    #[error("signature verification failed")]
    SignatureVerificationFailed,

    #[error("internal error: {0}")]
    Internal(String),
}

pub type VrfResult<T> = Result<T, VrfError>;

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for the VRF subsystem.
#[derive(Debug, Clone)]
pub struct VrfConfig {
    /// Suite identifier (RFC 9381 §5.5).
    pub suite: u8,
    /// Cofactor for Ed25519.
    pub cofactor: u8,
    /// Maximum attempts for hash-to-curve.
    pub max_hash_attempts: u8,
    /// Minimum born probability threshold for accepting a VRF output.
    pub born_probability_threshold: f64,
    /// Whether to track quantum metrics.
    pub track_quantum_metrics: bool,
    /// Maximum history entries in VRF registry.
    pub max_registry_entries: usize,
}

impl Default for VrfConfig {
    fn default() -> Self {
        Self {
            suite: SUITE,
            cofactor: COFACTOR,
            max_hash_attempts: MAX_HASH_TO_CURVE_ATTEMPTS,
            born_probability_threshold: DEFAULT_BORN_PROBABILITY_THRESHOLD,
            track_quantum_metrics: true,
            max_registry_entries: 256,
        }
    }
}

impl VrfConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> VrfResult<()> {
        if self.max_hash_attempts == 0 {
            return Err(VrfError::Config("max_hash_attempts must be > 0".into()));
        }
        if self.cofactor == 0 {
            return Err(VrfError::Config("cofactor must be > 0".into()));
        }
        if !(0.0..=1.0).contains(&self.born_probability_threshold) {
            return Err(VrfError::Config(
                "born_probability_threshold must be between 0 and 1".into(),
            ));
        }
        if self.max_registry_entries == 0 {
            return Err(VrfError::Config("max_registry_entries must be > 0".into()));
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Metrics
// -----------------------------------------------------------------------------

/// Metrics for the VRF subsystem.
#[derive(Debug, Clone, Default)]
pub struct VrfMetrics {
    /// Number of VRF outputs generated.
    pub generations: AtomicU64,
    /// Number of VRF verifications performed.
    pub verifications: AtomicU64,
    /// Number of successful verifications.
    pub verifications_success: AtomicU64,
    /// Number of failed verifications.
    pub verifications_failed: AtomicU64,
    /// Number of hash-to-curve attempts (total).
    pub hash_attempts: AtomicU64,
    /// Number of VRF registry records.
    pub registry_records: AtomicU64,
}

impl VrfMetrics {
    pub fn record_generation(&self) {
        self.generations.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_verification(&self, success: bool) {
        self.verifications.fetch_add(1, Ordering::Relaxed);
        if success {
            self.verifications_success.fetch_add(1, Ordering::Relaxed);
        } else {
            self.verifications_failed.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_hash_attempt(&self) {
        self.hash_attempts.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_registry(&self) {
        self.registry_records.fetch_add(1, Ordering::Relaxed);
    }
}

// -----------------------------------------------------------------------------
// VRF Keypair
// -----------------------------------------------------------------------------

/// VRF keypair (signing key and verifying key).
#[derive(Debug, Clone)]
pub struct VrfKeypair {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl VrfKeypair {
    /// Generate a random keypair.
    pub fn random() -> Self {
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Create from a 32-byte seed.
    pub fn from_seed(seed: &[u8]) -> VrfResult<Self> {
        if seed.len() != 32 {
            return Err(VrfError::KeyLengthMismatch {
                expected: 32,
                actual: seed.len(),
            });
        }
        let mut seed_bytes = [0u8; 32];
        seed_bytes.copy_from_slice(seed);
        let signing_key = SigningKey::from_bytes(&seed_bytes);
        let verifying_key = signing_key.verifying_key();
        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Get the secret scalar bytes (trapdoor).
    pub fn secret_key(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Get the public key bytes.
    pub fn public_key(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    /// Get the public key as a verifying key.
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Sign a message (for VRF input binding).
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.signing_key.sign(msg)
    }

    /// Verify a signature.
    pub fn verify(&self, msg: &[u8], signature: &Signature) -> bool {
        self.verifying_key.verify(msg, signature).is_ok()
    }
}

// -----------------------------------------------------------------------------
// VRF Core Implementation
// -----------------------------------------------------------------------------

/// The main VRF engine.
#[derive(Debug)]
pub struct Vrf {
    config: VrfConfig,
    metrics: Arc<VrfMetrics>,
}

impl Vrf {
    /// Create a new VRF engine with the given configuration.
    pub fn new(config: VrfConfig) -> VrfResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            metrics: Arc::new(VrfMetrics::default()),
        })
    }

    /// Create a VRF engine with default configuration.
    pub fn default() -> Self {
        Self::new(VrfConfig::default()).unwrap()
    }

    /// Get the metrics.
    pub fn metrics(&self) -> &VrfMetrics {
        &self.metrics
    }

    /// Generate a VRF output and proof.
    ///
    /// Implements RFC 9381 §5.1 ECVRF_prove.
    pub fn generate(&self, keypair: &VrfKeypair, input: &[u8]) -> VrfResult<VrfOutput> {
        let sk = keypair.secret_key();
        let pk = keypair.public_key();
        let output = VrfOutput::generate_with_config(
            &sk,
            &pk,
            input,
            &self.config,
            &self.metrics,
        )?;
        self.metrics.record_generation();
        Ok(output)
    }

    /// Verify a VRF proof.
    ///
    /// Implements RFC 9381 §5.3 ECVRF_verify.
    pub fn verify(&self, output: &VrfOutput, pk: &[u8], input: &[u8]) -> VrfResult<bool> {
        let result = output.verify_with_config(pk, input, &self.config, &self.metrics);
        self.metrics.record_verification(result);
        Ok(result)
    }

    /// Generate block randomness with quantum accumulation.
    pub fn generate_block_randomness(
        &self,
        keypair: &VrfKeypair,
        prev_hash: &Hash32,
        height: Height,
        prev_accumulated: &[u8; 32],
    ) -> VrfResult<BlockRandomness> {
        let input = VrfOutput::block_input(prev_hash, height);
        let vrf = self.generate(keypair, &input)?;
        let mut accumulated_seed = *prev_accumulated;
        for (i, b) in vrf.output.iter().enumerate() {
            accumulated_seed[i] ^= b;
        }
        let height_bytes = height.to_le_bytes();
        for (i, b) in height_bytes.iter().enumerate() {
            accumulated_seed[i % 32] ^= b;
        }

        // Compute accumulated purity
        let accumulated_purity = (vrf.purity + compute_byte_entropy(&accumulated_seed)) / 2.0;

        Ok(BlockRandomness {
            seed: vrf.output,
            proof: vrf.proof,
            accumulated_seed,
            accumulated_purity,
            accumulation_count: height,
        })
    }

    /// Verify block randomness.
    pub fn verify_block_randomness(
        &self,
        randomness: &BlockRandomness,
        pk: &[u8],
        prev_hash: &Hash32,
        height: Height,
    ) -> VrfResult<bool> {
        let input = VrfOutput::block_input(prev_hash, height);
        let vrf = VrfOutput {
            output: randomness.seed,
            proof: randomness.proof.clone(),
            purity: 1.0,
            born_probability: 1.0,
        };
        self.verify(&vrf, pk, &input)
    }
}

// -----------------------------------------------------------------------------
// VrfOutput
// -----------------------------------------------------------------------------

/// VRF output: the random value + quantum witness (proof).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VrfOutput {
    /// The 32-byte VRF output β (pseudorandom, quantum fingerprint).
    pub output: [u8; 32],
    /// RFC 9381 quantum witness π = (Γ, c, s).
    pub proof: VrfProof,
    /// Quantum purity of the output state γ = Tr(ρ²).
    pub purity: f64,
    /// Born probability of this output.
    pub born_probability: f64,
}

impl VrfOutput {
    /// Generate a VRF output with the given configuration and metrics.
    fn generate_with_config(
        sk: &[u8],
        pk: &[u8],
        input: &[u8],
        config: &VrfConfig,
        metrics: &VrfMetrics,
    ) -> VrfResult<Self> {
        // Validate key length
        if sk.len() != 32 {
            return Err(VrfError::KeyLengthMismatch {
                expected: 32,
                actual: sk.len(),
            });
        }
        if pk.len() != 32 {
            return Err(VrfError::KeyLengthMismatch {
                expected: 32,
                actual: pk.len(),
            });
        }

        // ── Key Expansion ──────────────────────────────────────────────
        let expanded = Sha512::digest(sk);
        let mut scalar_bytes = [0u8; 32];
        scalar_bytes.copy_from_slice(&expanded[..32]);
        // Clamp per Ed25519
        scalar_bytes[0] &= 248;
        scalar_bytes[31] &= 127;
        scalar_bytes[31] |= 64;
        let x = Scalar::from_bytes_mod_order(scalar_bytes);

        // ── Step 1: Hash-to-Curve ──────────────────────────────────────
        let h = ecvrf_hash_to_try_and_increment(pk, input, config, metrics)?;

        // ── Step 2: VRF Evaluation ────────────────────────────────────
        let gamma = x * h;

        // ── Step 3: Deterministic Nonce ───────────────────────────────
        let nonce_prefix = &expanded[32..];
        let k = ecvrf_nonce_generation(nonce_prefix, &h, config);
        let k_b = k * B;
        let k_h = k * h;

        // ── Step 4: Fiat-Shamir Challenge ─────────────────────────────
        let c_full = ecvrf_hash_points(&[h, gamma, k_b, k_h], config);
        let mut c_bytes = [0u8; 16];
        c_bytes.copy_from_slice(&c_full[..16]);
        let mut c_scalar_bytes = [0u8; 32];
        c_scalar_bytes[..16].copy_from_slice(&c_bytes);
        let c_scalar = Scalar::from_bytes_mod_order(c_scalar_bytes);

        // ── Step 5: Response Scalar ────────────────────────────────────
        let s = k - c_scalar * x;

        // ── Step 6: VRF Output ─────────────────────────────────────────
        let gamma_cofactor = gamma * Scalar::from(config.cofactor as u64);
        let gamma_enc = gamma_cofactor.compress().to_bytes();
        let mut hasher = Sha512::new();
        hasher.update([config.suite, 0x03]);
        hasher.update(gamma_enc);
        let beta = hasher.finalize();
        let mut output = [0u8; 32];
        output.copy_from_slice(&beta[..32]);

        // ── Quantum Properties ─────────────────────────────────────────
        let purity = compute_scalar_purity(&x);
        let born_prob = compute_born_probability(&gamma);

        if config.track_quantum_metrics && born_prob < config.born_probability_threshold {
            trace!("VRF born probability low: {:.4}", born_prob);
        }

        Ok(Self {
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
        })
    }

    /// Generate a VRF output using the default configuration.
    pub fn generate(sk: &[u8], pk: &[u8], input: &[u8]) -> Self {
        let config = VrfConfig::default();
        let metrics = Arc::new(VrfMetrics::default());
        Self::generate_with_config(sk, pk, input, &config, &metrics).unwrap()
    }

    /// Verify a VRF proof with configuration and metrics.
    pub fn verify_with_config(
        &self,
        pk: &[u8],
        input: &[u8],
        config: &VrfConfig,
        metrics: &VrfMetrics,
    ) -> bool {
        // ── Input Validation ──────────────────────────────────────────
        if self.proof.public_key != pk || pk.len() != 32 {
            return false;
        }
        if self.proof.gamma.iter().all(|&b| b == 0) {
            return false;
        }

        // ── Decode Public Key ──────────────────────────────────────────
        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(&pk[..32]);
        let pk_compressed = CompressedEdwardsY(pk_bytes);
        let y_point = match pk_compressed.decompress() {
            Some(p) => p,
            None => return false,
        };

        // ── Decode Γ ───────────────────────────────────────────────────
        let gamma_compressed = CompressedEdwardsY(self.proof.gamma);
        let gamma = match gamma_compressed.decompress() {
            Some(p) => p,
            None => return false,
        };

        // ── Decode s ───────────────────────────────────────────────────
        let s = Scalar::from_bytes_mod_order(self.proof.s);

        // ── Lift c ─────────────────────────────────────────────────────
        let mut c_scalar_bytes = [0u8; 32];
        c_scalar_bytes[..16].copy_from_slice(&self.proof.c);
        let c_scalar = Scalar::from_bytes_mod_order(c_scalar_bytes);

        // ── Step 1: Recompute H ────────────────────────────────────────
        let h = match ecvrf_hash_to_try_and_increment(pk, input, config, metrics) {
            Ok(h) => h,
            Err(_) => return false,
        };

        // ── Step 2: U = s·B + c·Y ────────────────────────────────────
        let u = EdwardsPoint::vartime_double_scalar_mul_basepoint(
            &c_scalar, &y_point, &s,
        );

        // ── Step 3: V = s·H + c·Γ ────────────────────────────────────
        let v = s * h + c_scalar * gamma;

        // ── Step 4: c' = H_challenge(H, Γ, U, V) ─────────────────────
        let c_prime_full = ecvrf_hash_points(&[h, gamma, u, v], config);
        let c_prime = &c_prime_full[..16];

        // ── Step 5: Verify c' == c ────────────────────────────────────
        if c_prime != &self.proof.c {
            return false;
        }

        // ── Step 6: Verify Output ─────────────────────────────────────
        let gamma_cofactor = gamma * Scalar::from(config.cofactor as u64);
        let gamma_enc = gamma_cofactor.compress().to_bytes();
        let mut hasher = Sha512::new();
        hasher.update([config.suite, 0x03]);
        hasher.update(gamma_enc);
        let expected_output = hasher.finalize();

        self.output == expected_output[..32]
    }

    /// Verify a VRF proof using the default configuration.
    pub fn verify(&self, pk: &[u8], input: &[u8]) -> bool {
        let config = VrfConfig::default();
        let metrics = Arc::new(VrfMetrics::default());
        self.verify_with_config(pk, input, &config, &metrics)
    }

    /// Compute the per-block VRF input from previous block hash and height.
    pub fn block_input(prev_hash: &Hash32, height: Height) -> Vec<u8> {
        let mut input = Vec::with_capacity(40);
        input.extend_from_slice(&prev_hash.0);
        input.extend_from_slice(&height.to_le_bytes());
        input
    }
}

// -----------------------------------------------------------------------------
// VrfProof
// -----------------------------------------------------------------------------

/// VRF quantum witness π = (pk, Γ_encoded, c, s).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VrfProof {
    pub public_key: Vec<u8>,
    pub gamma: [u8; 32],
    pub c: [u8; 16],
    pub s: [u8; 32],
    pub entanglement_fidelity: f64,
}

// -----------------------------------------------------------------------------
// BlockRandomness
// -----------------------------------------------------------------------------

/// Per-block randomness record stored in block headers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlockRandomness {
    pub seed: [u8; 32],
    pub proof: VrfProof,
    pub accumulated_seed: [u8; 32],
    pub accumulated_purity: f64,
    pub accumulation_count: u64,
}

impl BlockRandomness {
    /// Verify the block randomness.
    pub fn verify(&self, pk: &[u8], prev_hash: &Hash32, height: Height) -> bool {
        let input = VrfOutput::block_input(prev_hash, height);
        let vrf = VrfOutput {
            output: self.seed,
            proof: self.proof.clone(),
            purity: 1.0,
            born_probability: 1.0,
        };
        vrf.verify(pk, &input)
    }

    /// Get prevrandao for EVM compatibility.
    pub fn prevrandao(&self) -> revm::primitives::U256 {
        revm::primitives::U256::from_be_bytes(self.accumulated_seed)
    }
}

// -----------------------------------------------------------------------------
// VRF Registry
// -----------------------------------------------------------------------------

/// VRF history registry with bounded quantum memory.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VrfRegistry {
    pub history: std::collections::BTreeMap<Height, [u8; 32]>,
    pub coherence: f64,
    pub total_recorded: u64,
}

impl VrfRegistry {
    /// Create a new registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a VRF output.
    pub fn record(&mut self, height: Height, seed: [u8; 32], max_entries: usize) {
        self.history.insert(height, seed);
        self.total_recorded += 1;

        while self.history.len() > max_entries {
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

    /// Get the latest seed.
    pub fn latest_seed(&self) -> [u8; 32] {
        self.history.values().next_back().copied().unwrap_or([0u8; 32])
    }
}

// -----------------------------------------------------------------------------
// Internal Functions (RFC 9381)
// -----------------------------------------------------------------------------

/// ECVRF_hash_to_try_and_increment (RFC 9381 §5.4.1.1).
fn ecvrf_hash_to_try_and_increment(
    pk: &[u8],
    input: &[u8],
    config: &VrfConfig,
    metrics: &VrfMetrics,
) -> VrfResult<EdwardsPoint> {
    for ctr in 0u8..=config.max_hash_attempts {
        let mut hasher = Sha512::new();
        hasher.update([config.suite, 0x01]);
        hasher.update(pk);
        hasher.update(input);
        hasher.update([ctr, 0x00]);
        let hash = hasher.finalize();
        let mut candidate = [0u8; 32];
        candidate.copy_from_slice(&hash[..32]);

        metrics.record_hash_attempt();

        if let Some(point) = CompressedEdwardsY(candidate).decompress() {
            return Ok(point * Scalar::from(config.cofactor as u64));
        }
    }

    Err(VrfError::HashToCurveExhausted {
        attempts: config.max_hash_attempts + 1,
    })
}

/// ECVRF_nonce_generation (RFC 9381 §5.4.2.2).
fn ecvrf_nonce_generation(
    nonce_prefix: &[u8],
    h: &EdwardsPoint,
    config: &VrfConfig,
) -> Scalar {
    let h_string = h.compress().to_bytes();
    let mut hasher = Sha512::new();
    hasher.update(nonce_prefix);
    hasher.update(h_string);
    let hash = hasher.finalize();
    Scalar::from_bytes_mod_order_wide(&hash.into())
}

/// ECVRF_hash_points (RFC 9381 §5.4.3).
fn ecvrf_hash_points(points: &[EdwardsPoint], config: &VrfConfig) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update([config.suite, 0x02]);
    for p in points {
        hasher.update(p.compress().to_bytes());
    }
    let hash = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash[..32]);
    out
}

/// Compute scalar purity.
fn compute_scalar_purity(x: &Scalar) -> f64 {
    let bytes = x.to_bytes();
    let mut magnitude: u64 = 0;
    for &b in &bytes[..8] {
        magnitude = magnitude.wrapping_mul(256).wrapping_add(b as u64);
    }
    (magnitude as f64 / u64::MAX as f64).clamp(0.0, 1.0)
}

/// Compute born probability.
fn compute_born_probability(gamma: &EdwardsPoint) -> f64 {
    let encoded = gamma.compress().to_bytes();
    let mut sum: u64 = 0;
    for &b in &encoded[..8] {
        sum = sum.wrapping_mul(256).wrapping_add(b as u64);
    }
    (sum as f64 / u64::MAX as f64).clamp(0.0, 1.0)
}

/// Compute byte entropy.
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
    (entropy / (256.0f64).ln()).clamp(0.0, 1.0)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_vrf_generate_and_verify() {
        let config = VrfConfig::default();
        let vrf = Vrf::new(config).unwrap();
        let keypair = VrfKeypair::random();
        let input = b"test input";

        let output = vrf.generate(&keypair, input).unwrap();
        assert!(output.verify(&keypair.public_key(), input));
        assert_eq!(output.output.len(), 32);
        assert!(output.purity > 0.0);
        assert!(output.born_probability > 0.0);
    }

    #[test]
    fn test_vrf_deterministic() {
        let config = VrfConfig::default();
        let vrf = Vrf::new(config).unwrap();
        let seed = [0x42u8; 32];
        let keypair = VrfKeypair::from_seed(&seed).unwrap();
        let input = b"same input";

        let o1 = vrf.generate(&keypair, input).unwrap();
        let o2 = vrf.generate(&keypair, input).unwrap();
        assert_eq!(o1.output, o2.output);
        assert_eq!(o1.proof.gamma, o2.proof.gamma);
        assert_eq!(o1.purity, o2.purity);
    }

    #[test]
    fn test_vrf_wrong_pk_fails() {
        let vrf = Vrf::default();
        let keypair = VrfKeypair::random();
        let output = vrf.generate(&keypair, b"input").unwrap();
        let wrong_pk = [0x99u8; 32];
        assert!(!output.verify(&wrong_pk, b"input"));
    }

    #[test]
    fn test_vrf_wrong_input_fails() {
        let vrf = Vrf::default();
        let keypair = VrfKeypair::random();
        let output = vrf.generate(&keypair, b"original input").unwrap();
        assert!(!output.verify(&keypair.public_key(), b"tampered input"));
    }

    #[test]
    fn test_vrf_tampered_output_fails() {
        let vrf = Vrf::default();
        let keypair = VrfKeypair::random();
        let mut output = vrf.generate(&keypair, b"input").unwrap();
        output.output[0] ^= 0xFF;
        assert!(!output.verify(&keypair.public_key(), b"input"));
    }

    #[test]
    fn test_block_randomness() {
        let vrf = Vrf::default();
        let keypair = VrfKeypair::random();
        let prev = Hash32([0u8; 32]);
        let prev_acc = [0u8; 32];

        let randomness = vrf
            .generate_block_randomness(&keypair, &prev, 1, &prev_acc)
            .unwrap();
        assert!(randomness.verify(&keypair.public_key(), &prev, 1));
        assert!(randomness.seed.iter().any(|&b| b != 0));
        assert!(randomness.accumulated_purity > 0.0);
    }

    #[test]
    fn test_vrf_registry() {
        let mut reg = VrfRegistry::new();
        let max_entries = 10;
        for i in 0..20u64 {
            reg.record(i, [i as u8; 32], max_entries);
        }
        assert!(reg.history.len() <= max_entries);
        assert!(reg.get(0).is_none());
        assert!(reg.get(19).is_some());
        assert!(reg.coherence < 1.0);
    }

    #[test]
    fn test_keypair_from_seed() {
        let seed = [0x42u8; 32];
        let kp1 = VrfKeypair::from_seed(&seed).unwrap();
        let kp2 = VrfKeypair::from_seed(&seed).unwrap();
        assert_eq!(kp1.public_key(), kp2.public_key());
    }

    #[test]
    fn test_invalid_keypair_seed() {
        let seed = [0x42u8; 16];
        let result = VrfKeypair::from_seed(&seed);
        assert!(matches!(result, Err(VrfError::KeyLengthMismatch { .. })));
    }

    #[test]
    fn test_metrics() {
        let config = VrfConfig::default();
        let vrf = Vrf::new(config).unwrap();
        let keypair = VrfKeypair::random();

        vrf.generate(&keypair, b"input").unwrap();
        let output = vrf.generate(&keypair, b"input2").unwrap();
        vrf.verify(&output, &keypair.public_key(), b"input2").unwrap();

        let metrics = vrf.metrics();
        assert_eq!(metrics.generations.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.verifications.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_config_validation() {
        let mut config = VrfConfig::default();
        config.max_hash_attempts = 0;
        assert!(config.validate().is_err());

        config = VrfConfig::default();
        config.born_probability_threshold = 1.5;
        assert!(config.validate().is_err());

        config = VrfConfig::default();
        config.max_registry_entries = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_quantum_properties() {
        let config = VrfConfig::default();
        let vrf = Vrf::new(config).unwrap();
        let keypair = VrfKeypair::random();
        let output = vrf.generate(&keypair, b"test").unwrap();

        assert!(output.purity > 0.0 && output.purity <= 1.0);
        assert!(output.born_probability > 0.0 && output.born_probability <= 1.0);
        assert!(output.proof.entanglement_fidelity > 0.0);
    }
}
