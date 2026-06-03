//! Eclipse protection profiles for IONA v28 — Quantum Security Model.
//!
//! # Quantum Eclipse Protection
//!
//! Eclipse attacks are modelled as **quantum decoherence** of the node's
//! peer diversity state. Each connection bucket represents a **quantum
//! subspace**, and the node's security is a **superposition** of diverse
//! connections that resists collapse to a single attacker-controlled
//! subspace.
//!
//! # Mathematical Formalism
//!
//! ## Diversity State
//! ```text
//! |Ψ_diversity⟩ = (1/√N) Σ_i √w_i |bucket_i⟩
//! ```
//! where w_i is the fraction of connections in bucket i.
//!
//! ## Eclipse Detection as Entanglement Witness
//! ```text
//! W_eclipse = |dominated⟩⟨dominated|
//! if Tr(ρ W_eclipse) > threshold → ECLIPSE DETECTED
//! ```
//!
//! ## Security Hamiltonian
//! ```text
//! Ĥ_eclipse = Ĥ_diversity + Ĥ_bucket + Ĥ_cooldown
//!
//! Ĥ_diversity = -J Σ_{i≠j} |i⟩⟨j|                      (diversity coupling)
//! Ĥ_bucket    = Σ_k E_k n̂_k                               (bucket occupation)
//! Ĥ_cooldown  = ω_c a†_c a_c                              (reseed oscillator)
//! ```
//!
//! # Profiles as Quantum States
//! - `|prod⟩` = strict diversity (min 3 buckets, low caps) — **pure state**
//! - `|testnet⟩` = relaxed diversity (min 1 bucket, higher caps) — **mixed state**

use serde::{Deserialize, Serialize};

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Default quantum coherence for eclipse protection.
const DEFAULT_COHERENCE: f64 = 1.0;

/// Decoherence rate per connection to same bucket.
const CONNECTION_DECOHERENCE_RATE: f64 = 0.01;

/// Decoherence rate when eclipse is detected.
const ECLIPSE_DECOHERENCE_RATE: f64 = 0.5;

/// Entanglement strength between diverse buckets.
const DIVERSITY_ENTANGLEMENT: f64 = 0.99;

/// Minimum purity threshold for safe state.
const MIN_SAFE_PURITY: f64 = 0.9;

/// Maximum purity for testnet (allows some decoherence).
const MAX_TESTNET_PURITY: f64 = 0.95;

// -----------------------------------------------------------------------------
// Eclipse Profile Enum
// -----------------------------------------------------------------------------

/// Eclipse protection profile — quantum state of the node's security.
///
/// ```text
/// |prod⟩    = strict diversity (min 3 distinct buckets, low caps)
/// |testnet⟩ = relaxed diversity (min 1 distinct bucket, higher caps)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EclipseProfile {
    Prod,
    Testnet,
}

impl Default for EclipseProfile {
    fn default() -> Self {
        Self::Testnet
    }
}

impl EclipseProfile {
    /// Parse from a loose string, accepting multiple variants.
    ///
    /// ```text
    /// "prod" | "production" | "mainnet" → |prod⟩
    /// _ → |testnet⟩
    /// ```
    pub fn from_str_loose(s: &str) -> Self {
        match s.trim().to_lowercase().as_str() {
            "prod" | "production" | "mainnet" => Self::Prod,
            _ => Self::Testnet,
        }
    }

    /// Get the quantum purity expected for this profile.
    pub fn expected_purity(&self) -> f64 {
        match self {
            EclipseProfile::Prod => 1.0,       // pure state
            EclipseProfile::Testnet => 0.95,   // slightly mixed — relaxed
        }
    }

    /// Get the minimum safe purity for this profile.
    pub fn min_safe_purity(&self) -> f64 {
        match self {
            EclipseProfile::Prod => MIN_SAFE_PURITY,
            EclipseProfile::Testnet => 0.8,
        }
    }
}

// -----------------------------------------------------------------------------
// Eclipse Parameters
// -----------------------------------------------------------------------------

/// Eclipse protection parameters derived from the profile.
///
/// These are the **eigenvalues** of the security Hamiltonian Ĥ_eclipse.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EclipseParams {
    pub profile: EclipseProfile,
    /// Bucket classification: "ip16" (first 2 octets) or "ip24" (first 3).
    pub bucket_kind: String,
    /// Max inbound connections per bucket (occupation number limit).
    pub max_inbound_per_bucket: usize,
    /// Max outbound connections per bucket.
    pub max_outbound_per_bucket: usize,
    /// Minimum distinct buckets required (eclipse detection threshold).
    pub eclipse_detection_min_buckets: usize,
    /// Cooldown before re-seeding peers after eclipse detection (seconds).
    pub reseed_cooldown_s: u64,
    /// Max total connections (Hilbert space dimension bound).
    pub max_connections_total: usize,
    /// Max connections per peer (entanglement limit).
    pub max_connections_per_peer: usize,
    /// Expected quantum purity for this profile.
    #[serde(default = "default_purity")]
    pub expected_purity: f64,
    /// Minimum safe purity threshold.
    #[serde(default = "default_min_safe_purity")]
    pub min_safe_purity: f64,
}

fn default_purity() -> f64 {
    1.0
}

fn default_min_safe_purity() -> f64 {
    MIN_SAFE_PURITY
}

impl EclipseParams {
    /// Create parameters from a profile — quantum state preparation.
    ///
    /// ```text
    /// U_prepare |∅⟩ → |profile_params⟩
    /// ```
    pub fn from_profile(profile: EclipseProfile) -> Self {
        match profile {
            EclipseProfile::Prod => Self {
                profile,
                bucket_kind: "ip16".into(),
                max_inbound_per_bucket: 2,
                max_outbound_per_bucket: 2,
                eclipse_detection_min_buckets: 3,
                reseed_cooldown_s: 60,
                max_connections_total: 100,
                max_connections_per_peer: 4,
                expected_purity: profile.expected_purity(),
                min_safe_purity: profile.min_safe_purity(),
            },
            EclipseProfile::Testnet => Self {
                profile,
                bucket_kind: "ip16".into(),
                max_inbound_per_bucket: 8,
                max_outbound_per_bucket: 8,
                eclipse_detection_min_buckets: 1,
                reseed_cooldown_s: 120,
                max_connections_total: 200,
                max_connections_per_peer: 8,
                expected_purity: profile.expected_purity(),
                min_safe_purity: profile.min_safe_purity(),
            },
        }
    }

    /// Validate the parameter configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_inbound_per_bucket == 0 {
            return Err("max_inbound_per_bucket must be > 0".into());
        }
        if self.max_outbound_per_bucket == 0 {
            return Err("max_outbound_per_bucket must be > 0".into());
        }
        if self.eclipse_detection_min_buckets == 0 {
            return Err("eclipse_detection_min_buckets must be > 0".into());
        }
        if self.max_connections_total == 0 {
            return Err("max_connections_total must be > 0".into());
        }
        if self.max_connections_per_peer == 0 {
            return Err("max_connections_per_peer must be > 0".into());
        }
        Ok(())
    }

    /// Quantum measurement: check if bucket distribution is safe.
    ///
    /// ```text
    /// P̂_safe = Σ_{d ≥ d_min} |d⟩⟨d|
    /// is_safe = Tr(ρ P̂_safe) > 0
    /// ```
    pub fn is_safe(&self, distinct_buckets: usize) -> bool {
        distinct_buckets >= self.eclipse_detection_min_buckets
    }

    /// Compute the quantum purity of the current bucket distribution.
    ///
    /// ```text
    /// γ = 1 - exp(-diversity / d_min)
    /// ```
    /// where diversity is the number of distinct buckets.
    pub fn compute_purity(&self, distinct_buckets: usize) -> f64 {
        if distinct_buckets == 0 {
            return 0.0;
        }
        let ratio = distinct_buckets as f64 / self.eclipse_detection_min_buckets as f64;
        (1.0 - (-ratio).exp()).clamp(0.0, 1.0)
    }

    /// Check if the current purity meets the profile's minimum.
    pub fn is_purity_safe(&self, distinct_buckets: usize) -> bool {
        let purity = self.compute_purity(distinct_buckets);
        purity >= self.min_safe_purity
    }

    /// Compute the entanglement fidelity with the ideal profile state.
    ///
    /// ```text
    /// F = |⟨profile_ideal|profile_actual⟩|²
    /// ```
    pub fn entanglement_fidelity(&self, distinct_buckets: usize) -> f64 {
        let purity = self.compute_purity(distinct_buckets);
        let expected = self.expected_purity;
        (purity * expected).sqrt().clamp(0.0, 1.0)
    }

    /// Human-readable description of the profile.
    pub fn description(&self) -> &str {
        match self.profile {
            EclipseProfile::Prod => {
                "Production: strict diversity (min 3 distinct buckets, low per-bucket caps)"
            }
            EclipseProfile::Testnet => {
                "Testnet: relaxed diversity (min 1 distinct bucket, higher caps)"
            }
        }
    }

    /// Get the quantum security level as a percentage.
    pub fn security_level_pct(&self, distinct_buckets: usize) -> f64 {
        let purity = self.compute_purity(distinct_buckets);
        let fidelity = self.entanglement_fidelity(distinct_buckets);
        (purity * fidelity * 100.0).clamp(0.0, 100.0)
    }
}

// -----------------------------------------------------------------------------
// Quantum Eclipse Security State
// -----------------------------------------------------------------------------

/// Quantum state of the eclipse protection system.
///
/// Tracks the density matrix properties of the node's peer diversity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EclipseSecurityState {
    /// Current purity γ = Tr(ρ²).
    pub purity: f64,
    /// Entanglement fidelity with ideal profile.
    pub fidelity: f64,
    /// Number of distinct connection buckets.
    pub distinct_buckets: usize,
    /// Whether the node is in a safe state.
    pub is_safe: bool,
    /// Whether eclipse has been detected.
    pub eclipse_detected: bool,
    /// Number of eclipse detections (cumulative).
    pub eclipse_detections: u64,
    /// Number of reseed operations performed.
    pub reseed_count: u64,
    /// Cooldown remaining in seconds.
    pub cooldown_remaining_s: u64,
}

impl Default for EclipseSecurityState {
    fn default() -> Self {
        Self {
            purity: DEFAULT_COHERENCE,
            fidelity: DEFAULT_COHERENCE,
            distinct_buckets: 0,
            is_safe: true,
            eclipse_detected: false,
            eclipse_detections: 0,
            reseed_count: 0,
            cooldown_remaining_s: 0,
        }
    }
}

impl EclipseSecurityState {
    /// Create a new quantum security state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Update the state based on current bucket distribution.
    pub fn update(&mut self, params: &EclipseParams, distinct_buckets: usize) {
        self.distinct_buckets = distinct_buckets;
        self.purity = params.compute_purity(distinct_buckets);
        self.fidelity = params.entanglement_fidelity(distinct_buckets);
        self.is_safe = params.is_safe(distinct_buckets);
        self.eclipse_detected = !self.is_safe;
    }

    /// Record an eclipse detection event.
    pub fn record_eclipse(&mut self) {
        if !self.eclipse_detected {
            self.eclipse_detected = true;
            self.eclipse_detections = self.eclipse_detections.wrapping_add(1);
            self.purity = (self.purity * (-ECLIPSE_DECOHERENCE_RATE).exp()).clamp(0.0, 1.0);
            self.is_safe = false;
        }
    }

    /// Record a reseed operation.
    pub fn record_reseed(&mut self, cooldown_s: u64) {
        self.reseed_count = self.reseed_count.wrapping_add(1);
        self.cooldown_remaining_s = cooldown_s;
        // Reseed restores some coherence
        self.purity = (self.purity * 1.1).min(1.0);
        self.fidelity = (self.fidelity * 1.05).min(1.0);
        self.eclipse_detected = false;
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── Profile Tests ──────────────────────────────────────────────────
    #[test]
    fn test_prod_profile_params() {
        let p = EclipseParams::from_profile(EclipseProfile::Prod);
        assert_eq!(p.eclipse_detection_min_buckets, 3);
        assert_eq!(p.max_inbound_per_bucket, 2);
        assert_eq!(p.max_connections_total, 100);
        assert!(!p.is_safe(2));
        assert!(p.is_safe(3));
        assert!(p.is_safe(5));
    }

    #[test]
    fn test_testnet_profile_params() {
        let p = EclipseParams::from_profile(EclipseProfile::Testnet);
        assert_eq!(p.eclipse_detection_min_buckets, 1);
        assert_eq!(p.max_inbound_per_bucket, 8);
        assert_eq!(p.max_connections_total, 200);
        assert!(p.is_safe(1));
        assert!(p.is_safe(5));
    }

    #[test]
    fn test_from_str_loose() {
        assert_eq!(EclipseProfile::from_str_loose("prod"), EclipseProfile::Prod);
        assert_eq!(
            EclipseProfile::from_str_loose("production"),
            EclipseProfile::Prod
        );
        assert_eq!(
            EclipseProfile::from_str_loose("mainnet"),
            EclipseProfile::Prod
        );
        assert_eq!(
            EclipseProfile::from_str_loose("testnet"),
            EclipseProfile::Testnet
        );
        assert_eq!(
            EclipseProfile::from_str_loose("dev"),
            EclipseProfile::Testnet
        );
        assert_eq!(
            EclipseProfile::from_str_loose("anything"),
            EclipseProfile::Testnet
        );
    }

    #[test]
    fn test_profile_descriptions() {
        let prod = EclipseParams::from_profile(EclipseProfile::Prod);
        assert!(prod.description().contains("strict"));
        let testnet = EclipseParams::from_profile(EclipseProfile::Testnet);
        assert!(testnet.description().contains("relaxed"));
    }

    // ── Quantum Purity Tests ───────────────────────────────────────────
    #[test]
    fn test_compute_purity_prod() {
        let params = EclipseParams::from_profile(EclipseProfile::Prod);
        let purity_0 = params.compute_purity(0);
        assert!((purity_0 - 0.0).abs() < 1e-10);

        let purity_3 = params.compute_purity(3);
        assert!(purity_3 > 0.6);

        let purity_10 = params.compute_purity(10);
        assert!(purity_10 > purity_3);
        assert!(purity_10 <= 1.0);
    }

    #[test]
    fn test_compute_purity_testnet() {
        let params = EclipseParams::from_profile(EclipseProfile::Testnet);
        let purity_1 = params.compute_purity(1);
        assert!(purity_1 > 0.6);
        assert!(purity_1 <= 1.0);
    }

    #[test]
    fn test_is_purity_safe() {
        let params = EclipseParams::from_profile(EclipseProfile::Prod);
        assert!(!params.is_purity_safe(0));
        assert!(!params.is_purity_safe(1));
        assert!(params.is_purity_safe(3));
        assert!(params.is_purity_safe(10));
    }

    #[test]
    fn test_entanglement_fidelity() {
        let params = EclipseParams::from_profile(EclipseProfile::Prod);
        let fidelity_3 = params.entanglement_fidelity(3);
        assert!(fidelity_3 > 0.7);
        assert!(fidelity_3 <= 1.0);

        let fidelity_1 = params.entanglement_fidelity(1);
        assert!(fidelity_1 < fidelity_3);
    }

    #[test]
    fn test_security_level_pct() {
        let params = EclipseParams::from_profile(EclipseProfile::Prod);
        let level_3 = params.security_level_pct(3);
        assert!(level_3 > 70.0);
        assert!(level_3 <= 100.0);

        let level_0 = params.security_level_pct(0);
        assert!((level_0 - 0.0).abs() < 1e-10);
    }

    // ── Parameter Validation Tests ─────────────────────────────────────
    #[test]
    fn test_validate_valid_params() {
        let params = EclipseParams::from_profile(EclipseProfile::Prod);
        assert!(params.validate().is_ok());
    }

    #[test]
    fn test_validate_invalid_params() {
        let mut params = EclipseParams::from_profile(EclipseProfile::Prod);
        params.max_inbound_per_bucket = 0;
        assert!(params.validate().is_err());

        let mut params = EclipseParams::from_profile(EclipseProfile::Prod);
        params.eclipse_detection_min_buckets = 0;
        assert!(params.validate().is_err());
    }

    // ── Quantum Security State Tests ───────────────────────────────────
    #[test]
    fn test_security_state_initialization() {
        let state = EclipseSecurityState::new();
        assert!((state.purity - 1.0).abs() < 1e-10);
        assert!((state.fidelity - 1.0).abs() < 1e-10);
        assert!(state.is_safe);
        assert!(!state.eclipse_detected);
    }

    #[test]
    fn test_security_state_update() {
        let mut state = EclipseSecurityState::new();
        let params = EclipseParams::from_profile(EclipseProfile::Prod);

        state.update(&params, 3);
        assert!(state.is_safe);
        assert_eq!(state.distinct_buckets, 3);

        state.update(&params, 1);
        assert!(!state.is_safe);
        assert!(state.eclipse_detected);
    }

    #[test]
    fn test_record_eclipse() {
        let mut state = EclipseSecurityState::new();
        let initial_purity = state.purity;

        state.record_eclipse();
        assert!(state.eclipse_detected);
        assert_eq!(state.eclipse_detections, 1);
        assert!(state.purity < initial_purity);
        assert!(!state.is_safe);
    }

    #[test]
    fn test_record_reseed() {
        let mut state = EclipseSecurityState::new();
        let params = EclipseParams::from_profile(EclipseProfile::Prod);

        state.update(&params, 1);
        state.record_eclipse();
        let purity_after_eclipse = state.purity;

        state.record_reseed(60);
        assert!(!state.eclipse_detected);
        assert_eq!(state.reseed_count, 1);
        assert_eq!(state.cooldown_remaining_s, 60);
        assert!(state.purity > purity_after_eclipse);
    }

    #[test]
    fn test_profile_expected_purity() {
        assert!((EclipseProfile::Prod.expected_purity() - 1.0).abs() < 1e-10);
        assert!((EclipseProfile::Testnet.expected_purity() - 0.95).abs() < 1e-10);
    }

    #[test]
    fn test_profile_min_safe_purity() {
        assert!((EclipseProfile::Prod.min_safe_purity() - 0.9).abs() < 1e-10);
        assert!((EclipseProfile::Testnet.min_safe_purity() - 0.8).abs() < 1e-10);
    }
}
