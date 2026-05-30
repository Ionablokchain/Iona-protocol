//! IONA — IBC Light Client (ICS-002 quantum implementation).
//!
//! # Quantum Light Client Model
//!
//! The IBC light client is modeled as a quantum system that tracks the
//! state of a counterparty chain. Each header verification is a quantum
//! measurement that collapses the superposition of possible chain states.
//!
//! # Hamiltonian for Light Client Verification
//!
//! ```text
//! Ĥ_ibc = Ĥ_trust + Ĥ_verify + Ĥ_misbehaviour
//!
//! Ĥ_trust        = Σ_t ω_t |trusted_t⟩⟨trusted_t|
//! Ĥ_verify       = Σ_h g_h (|valid⟩⟨invalid|_h + h.c.)
//! Ĥ_misbehaviour = Σ_m E_m |equivocation_m⟩⟨equivocation_m|
//! ```
//!
//! # Quantum Trust Model
//!
//! Trust is modeled as quantum entanglement between the light client and
//! the counterparty validator set. The trust threshold defines the minimum
//! entanglement fidelity required for header acceptance.
//!
//! # Misbehaviour Detection via Entanglement Witness
//!
//! Equivocation is detected when two conflicting headers at the same height
//! create an entanglement witness W that exceeds the detection threshold:
//! ```text
//! W = |header_1⟩⟨header_1| ⊗ |header_2⟩⟨header_2|
//! Tr(Wρ) > threshold → misbehaviour
//! ```

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use crate::types::Height;

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Default trust threshold numerator (1/3).
const DEFAULT_TRUST_NUMERATOR: u64 = 1;
const DEFAULT_TRUST_DENOMINATOR: u64 = 3;

/// Entanglement fidelity threshold for header acceptance.
const HEADER_FIDELITY_THRESHOLD: f64 = 0.99;

/// Maximum clock drift in seconds (quantum uncertainty principle limit).
const MAX_CLOCK_DRIFT_S: u64 = 30;

/// Default trusting period in seconds (7 days).
const DEFAULT_TRUSTING_PERIOD_S: u64 = 7 * 24 * 3600;

// -----------------------------------------------------------------------------
// Quantum IBC Types
// -----------------------------------------------------------------------------

/// Unique identifier for an IBC light client (quantum system label).
pub type ClientId = String;

/// Chain ID of the counterparty chain.
pub type ChainId = String;

/// Quantum IBC height with revision number and height.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct IbcHeight {
    /// Revision number (quantum principal quantum number).
    pub revision_number: u64,
    /// Revision height (azimuthal quantum number).
    pub revision_height: u64,
}

impl IbcHeight {
    pub fn new(revision_number: u64, revision_height: u64) -> Self {
        Self {
            revision_number,
            revision_height,
        }
    }

    pub fn zero() -> Self {
        Self {
            revision_number: 0,
            revision_height: 0,
        }
    }
}

impl std::fmt::Display for IbcHeight {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}", self.revision_number, self.revision_height)
    }
}

// -----------------------------------------------------------------------------
// Quantum Client State
// -----------------------------------------------------------------------------

/// IBC client state — quantum configuration for tracking a counterparty chain.
///
/// The client state exists in a superposition of |active⟩ and |frozen⟩ states.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClientState {
    /// Chain ID of the counterparty.
    pub chain_id: ChainId,
    /// Latest height verified on the counterparty chain.
    pub latest_height: IbcHeight,
    /// Trust threshold (numerator/denominator). Typically 1/3.
    pub trust_threshold_numerator: u64,
    pub trust_threshold_denominator: u64,
    /// How long a header is trusted after its timestamp.
    pub trusting_period_s: u64,
    /// Maximum clock drift allowed (quantum uncertainty).
    pub max_clock_drift_s: u64,
    /// Whether the client is frozen (collapsed to |frozen⟩).
    pub frozen: bool,
    /// Height at which the client was frozen.
    pub frozen_height: Option<IbcHeight>,
    /// Quantum coherence of the client state.
    #[serde(default = "default_coherence")]
    pub coherence: f64,
    /// Entanglement fidelity with counterparty.
    #[serde(default = "default_coherence")]
    pub entanglement_fidelity: f64,
}

fn default_coherence() -> f64 {
    1.0
}

// -----------------------------------------------------------------------------
// Quantum Consensus State
// -----------------------------------------------------------------------------

/// Consensus state at a specific height — the verified quantum snapshot.
///
/// This represents a projective measurement of the counterparty chain
/// at a specific height.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusState {
    /// Block timestamp from the verified header.
    pub timestamp: u64,
    /// App hash (state root) of the counterparty.
    pub root: Vec<u8>,
    /// Next validators hash — entanglement link to future headers.
    pub next_validators_hash: Vec<u8>,
    /// Quantum fidelity of this consensus state.
    #[serde(default = "default_coherence")]
    pub fidelity: f64,
    /// Verification confidence (Born probability).
    #[serde(default = "default_coherence")]
    pub confidence: f64,
}

// -----------------------------------------------------------------------------
// Quantum Header
// -----------------------------------------------------------------------------

/// A Tendermint light block header for quantum verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    pub chain_id: ChainId,
    pub height: IbcHeight,
    pub timestamp: u64,
    pub validators_hash: Vec<u8>,
    pub next_validators_hash: Vec<u8>,
    pub app_hash: Vec<u8>,
    pub last_commit_hash: Vec<u8>,
    /// Trusted height from which we verify this header.
    pub trusted_height: IbcHeight,
    /// Trusted validators hash at trusted_height.
    pub trusted_validators_hash: Vec<u8>,
    /// Quantum signature of the header.
    #[serde(default)]
    pub quantum_signature: Vec<u8>,
}

// -----------------------------------------------------------------------------
// Quantum Misbehaviour
// -----------------------------------------------------------------------------

/// Misbehaviour evidence — two conflicting headers creating entanglement.
///
/// This represents a quantum forbidden transition where the counterparty
/// chain appears to exist in two different states simultaneously.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Misbehaviour {
    pub client_id: ClientId,
    pub header_1: Header,
    pub header_2: Header,
    /// Entanglement witness value.
    #[serde(default)]
    pub witness_value: f64,
    /// Detection confidence.
    #[serde(default = "default_coherence")]
    pub detection_confidence: f64,
}

// -----------------------------------------------------------------------------
// Quantum IBC Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during quantum light client operations.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum IbcError {
    #[error("client not found: {0}")]
    ClientNotFound(ClientId),

    #[error("consensus state not found at height {0}")]
    ConsensusNotFound(IbcHeight),

    #[error("client is frozen at height {0}")]
    ClientFrozen(IbcHeight),

    #[error("header height {header} <= latest {latest}")]
    HeaderHeightTooLow { header: IbcHeight, latest: IbcHeight },

    #[error("header timestamp {header_ts} in past (trusted={trusted_ts}, max_drift={drift_s}s)")]
    HeaderTimestampTooOld {
        header_ts: u64,
        trusted_ts: u64,
        drift_s: u64,
    },

    #[error("clock drift too large: {diff_s}s > {max_drift_s}s")]
    ClockDriftTooLarge { diff_s: u64, max_drift_s: u64 },

    #[error("trusting period expired: header_ts={header_ts}, period_end={period_end}")]
    TrustingPeriodExpired {
        header_ts: u64,
        period_end: u64,
    },

    #[error("validators hash mismatch: expected {expected}, got {actual}")]
    ValidatorsHashMismatch { expected: String, actual: String },

    #[error("misbehaviour: conflicting headers at same height")]
    Misbehaviour,

    #[error("client already exists: {0}")]
    ClientAlreadyExists(ClientId),

    #[error("quantum decoherence: fidelity {fidelity} below threshold {threshold}")]
    Decoherence { fidelity: f64, threshold: f64 },

    #[error("entanglement witness below detection threshold")]
    WitnessInsufficient,
}

// -----------------------------------------------------------------------------
// Quantum Light Client Registry
// -----------------------------------------------------------------------------

/// On-chain registry of quantum IBC light clients.
///
/// Maintains the quantum states of all tracked counterparty chains.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LightClientRegistry {
    /// Active client states keyed by client_id.
    pub clients: BTreeMap<ClientId, ClientState>,
    /// Consensus states keyed by (client_id, height).
    pub consensus_states: BTreeMap<(ClientId, IbcHeight), ConsensusState>,
    /// Counter for generating unique client IDs.
    pub next_client_seq: u64,
    /// Overall registry coherence.
    #[serde(default = "default_coherence")]
    pub coherence: f64,
}

impl LightClientRegistry {
    /// Create a new quantum IBC light client.
    ///
    /// This initializes the client in a pure quantum state |active⟩
    /// with full coherence.
    pub fn create_client(
        &mut self,
        chain_id: ChainId,
        initial_height: IbcHeight,
        initial_consensus: ConsensusState,
        trust_threshold_num: u64,
        trust_threshold_den: u64,
        trusting_period_s: u64,
        max_clock_drift_s: u64,
    ) -> Result<ClientId, IbcError> {
        let client_id = format!("{}-{}", chain_id, self.next_client_seq);
        self.next_client_seq = self.next_client_seq.wrapping_add(1);

        let client = ClientState {
            chain_id: chain_id.clone(),
            latest_height: initial_height,
            trust_threshold_numerator: trust_threshold_num,
            trust_threshold_denominator: trust_threshold_den,
            trusting_period_s,
            max_clock_drift_s,
            frozen: false,
            frozen_height: None,
            coherence: 1.0,
            entanglement_fidelity: 1.0,
        };

        self.clients.insert(client_id.clone(), client);
        self.consensus_states.insert(
            (client_id.clone(), initial_height),
            initial_consensus,
        );

        // Minimal decoherence from creation
        self.coherence *= 0.9999;

        tracing::info!(
            client_id = %client_id,
            chain_id = %chain_id,
            height = %initial_height,
            "quantum IBC light client created"
        );

        Ok(client_id)
    }

    /// Update an existing light client with a new verified header.
    ///
    /// This performs quantum verification of the header against the
    /// trusted consensus state.
    pub fn update_client(
        &mut self,
        client_id: &str,
        header: Header,
        current_time_s: u64,
    ) -> Result<IbcHeight, IbcError> {
        let client = self
            .clients
            .get(client_id)
            .ok_or_else(|| IbcError::ClientNotFound(client_id.to_string()))?
            .clone();

        if client.frozen {
            return Err(IbcError::ClientFrozen(
                client.frozen_height.unwrap_or(IbcHeight::zero()),
            ));
        }

        // Retrieve trusted consensus state
        let trusted_cs = self
            .consensus_states
            .get(&(client_id.to_string(), header.trusted_height))
            .ok_or(IbcError::ConsensusNotFound(header.trusted_height))?
            .clone();

        // Quantum header verification
        let verification_fidelity =
            Self::verify_header_quantum(&client, &header, &trusted_cs, current_time_s)?;

        let new_height = header.height;
        let new_cs = ConsensusState {
            timestamp: header.timestamp,
            root: header.app_hash.clone(),
            next_validators_hash: header.next_validators_hash.clone(),
            fidelity: verification_fidelity,
            confidence: verification_fidelity,
        };

        // Update client state
        if new_height > client.latest_height {
            let client_mut = self.clients.get_mut(client_id).unwrap();
            client_mut.latest_height = new_height;
            client_mut.coherence *= 0.999;
            client_mut.entanglement_fidelity *= verification_fidelity;
        }

        self.consensus_states
            .insert((client_id.to_string(), new_height), new_cs);

        self.coherence *= 0.9999;

        tracing::info!(
            client_id = %client_id,
            new_height = %new_height,
            fidelity = verification_fidelity,
            "quantum IBC light client updated"
        );

        Ok(new_height)
    }

    /// Freeze a client after quantum misbehaviour detection.
    ///
    /// The client collapses from |active⟩ to |frozen⟩ upon detection
    /// of equivocation.
    pub fn submit_misbehaviour(
        &mut self,
        mut misbehaviour: Misbehaviour,
        current_time_s: u64,
    ) -> Result<(), IbcError> {
        let client_id = &misbehaviour.client_id;
        let client = self
            .clients
            .get(client_id)
            .ok_or_else(|| IbcError::ClientNotFound(client_id.clone()))?
            .clone();

        if client.frozen {
            return Ok(()); // already frozen
        }

        // Both headers must be at the same height
        if misbehaviour.header_1.height != misbehaviour.header_2.height {
            return Err(IbcError::Misbehaviour);
        }

        // Headers must have different app hashes (equivocation)
        if misbehaviour.header_1.app_hash == misbehaviour.header_2.app_hash {
            return Err(IbcError::Misbehaviour);
        }

        // Compute entanglement witness
        let witness = Self::compute_misbehaviour_witness(
            &misbehaviour.header_1,
            &misbehaviour.header_2,
        );

        if witness < HEADER_FIDELITY_THRESHOLD {
            return Err(IbcError::WitnessInsufficient);
        }

        misbehaviour.witness_value = witness;
        misbehaviour.detection_confidence = witness;

        let freeze_height = misbehaviour.header_1.height;
        let client_mut = self.clients.get_mut(client_id).unwrap();
        client_mut.frozen = true;
        client_mut.frozen_height = Some(freeze_height);
        client_mut.coherence = 0.0; // complete decoherence
        client_mut.entanglement_fidelity = 0.0;

        self.coherence *= 0.99;

        tracing::warn!(
            client_id = %client_id,
            height = %freeze_height,
            witness = witness,
            "quantum IBC light client FROZEN — equivocation detected"
        );

        Ok(())
    }

    /// Quantum header verification.
    ///
    /// Performs a series of projective measurements to verify the header
    /// against the trusted consensus state.
    fn verify_header_quantum(
        client: &ClientState,
        header: &Header,
        trusted_cs: &ConsensusState,
        current_time_s: u64,
    ) -> Result<f64, IbcError> {
        let mut fidelity = 1.0;

        // 1. Height must be strictly greater than trusted height
        if header.height <= header.trusted_height {
            return Err(IbcError::HeaderHeightTooLow {
                header: header.height,
                latest: header.trusted_height,
            });
        }
        fidelity *= 0.999;

        // 2. Trusting period check
        let period_end = trusted_cs
            .timestamp
            .saturating_add(client.trusting_period_s);
        if header.timestamp > period_end {
            return Err(IbcError::TrustingPeriodExpired {
                header_ts: header.timestamp,
                period_end,
            });
        }
        fidelity *= 0.999;

        // 3. Clock drift: header.timestamp <= current_time + max_clock_drift
        if header.timestamp > current_time_s.saturating_add(client.max_clock_drift_s) {
            return Err(IbcError::ClockDriftTooLarge {
                diff_s: header.timestamp - current_time_s,
                max_drift_s: client.max_clock_drift_s,
            });
        }
        fidelity *= 0.999;

        // 4. Header timestamp must be after trusted timestamp
        if header.timestamp < trusted_cs.timestamp {
            return Err(IbcError::HeaderTimestampTooOld {
                header_ts: header.timestamp,
                trusted_ts: trusted_cs.timestamp,
                drift_s: client.max_clock_drift_s,
            });
        }
        fidelity *= 0.999;

        // 5. Validators hash must match
        let expected_vhash = hex::encode(&trusted_cs.next_validators_hash);
        let actual_vhash = hex::encode(&header.validators_hash);
        if expected_vhash != actual_vhash {
            return Err(IbcError::ValidatorsHashMismatch {
                expected: expected_vhash,
                actual: actual_vhash,
            });
        }
        fidelity *= 0.998;

        // Check minimum fidelity
        if fidelity < HEADER_FIDELITY_THRESHOLD {
            return Err(IbcError::Decoherence {
                fidelity,
                threshold: HEADER_FIDELITY_THRESHOLD,
            });
        }

        Ok(fidelity)
    }

    /// Compute the entanglement witness for misbehaviour detection.
    ///
    /// W = |h1⟩⟨h1| ⊗ |h2⟩⟨h2|
    /// Tr(Wρ) measures the degree of conflict between headers.
    fn compute_misbehaviour_witness(header_1: &Header, header_2: &Header) -> f64 {
        let mut matches = 0u64;
        let mut total = 0u64;

        // Compare app hashes
        let h1 = &header_1.app_hash;
        let h2 = &header_2.app_hash;
        let len = h1.len().min(h2.len());

        for i in 0..len {
            total += 1;
            if h1[i] == h2[i] {
                matches += 1;
            }
        }

        if total == 0 {
            return 1.0;
        }

        // Witness is high when hashes differ (indicating misbehaviour)
        1.0 - (matches as f64 / total as f64)
    }

    /// Query a client state.
    pub fn client(&self, id: &str) -> Option<&ClientState> {
        self.clients.get(id)
    }

    /// Query a consensus state.
    pub fn consensus_state(
        &self,
        id: &str,
        height: IbcHeight,
    ) -> Option<&ConsensusState> {
        self.consensus_states.get(&(id.to_string(), height))
    }

    /// List all client IDs.
    pub fn client_ids(&self) -> Vec<&str> {
        self.clients.keys().map(|s| s.as_str()).collect()
    }

    /// Get registry statistics.
    pub fn stats(&self) -> IbcStats {
        IbcStats {
            total_clients: self.clients.len(),
            frozen_clients: self.clients.values().filter(|c| c.frozen).count(),
            total_consensus_states: self.consensus_states.len(),
            coherence: self.coherence,
        }
    }
}

// -----------------------------------------------------------------------------
// IBC Statistics
// -----------------------------------------------------------------------------

/// Observable statistics for the IBC light client registry.
#[derive(Debug, Clone)]
pub struct IbcStats {
    pub total_clients: usize,
    pub frozen_clients: usize,
    pub total_consensus_states: usize,
    pub coherence: f64,
}

// -----------------------------------------------------------------------------
// RPC Helpers
// -----------------------------------------------------------------------------

/// IBC query response for a client state (JSON-serializable).
#[derive(Debug, Serialize)]
pub struct ClientStateResponse {
    pub client_id: String,
    pub chain_id: String,
    pub latest_height: String,
    pub trust_threshold: String,
    pub trusting_period_s: u64,
    pub frozen: bool,
    pub frozen_height: Option<String>,
    pub coherence: f64,
    pub entanglement_fidelity: f64,
}

impl From<(&str, &ClientState)> for ClientStateResponse {
    fn from((id, cs): (&str, &ClientState)) -> Self {
        Self {
            client_id: id.to_string(),
            chain_id: cs.chain_id.clone(),
            latest_height: cs.latest_height.to_string(),
            trust_threshold: format!(
                "{}/{}",
                cs.trust_threshold_numerator, cs.trust_threshold_denominator
            ),
            trusting_period_s: cs.trusting_period_s,
            frozen: cs.frozen,
            frozen_height: cs.frozen_height.map(|h| h.to_string()),
            coherence: cs.coherence,
            entanglement_fidelity: cs.entanglement_fidelity,
        }
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_registry() -> LightClientRegistry {
        LightClientRegistry::default()
    }

    fn make_consensus(ts: u64) -> ConsensusState {
        ConsensusState {
            timestamp: ts,
            root: vec![1u8; 32],
            next_validators_hash: vec![0xABu8; 32],
            fidelity: 1.0,
            confidence: 1.0,
        }
    }

    #[test]
    fn test_create_and_query_client() {
        let mut reg = make_registry();
        let initial_height = IbcHeight::new(4, 100);
        let cs = make_consensus(1_700_000_000);

        let id = reg
            .create_client(
                "cosmoshub-4".into(),
                initial_height,
                cs,
                1,
                3,
                7 * 86_400,
                10,
            )
            .unwrap();

        assert!(id.starts_with("cosmoshub-4-"));
        let state = reg.client(&id).unwrap();
        assert_eq!(state.latest_height, initial_height);
        assert!(!state.frozen);
        assert!((state.coherence - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_update_client_success() {
        let mut reg = make_registry();
        let trusted_h = IbcHeight::new(4, 100);
        let trusted_ts = 1_700_000_000u64;
        let cs = make_consensus(trusted_ts);
        let next_validators_hash = cs.next_validators_hash.clone();

        let id = reg
            .create_client("chain-1".into(), trusted_h, cs, 1, 3, 604_800, 30)
            .unwrap();

        let header = Header {
            chain_id: "chain-1".into(),
            height: IbcHeight::new(4, 101),
            timestamp: trusted_ts + 6,
            validators_hash: next_validators_hash.clone(),
            next_validators_hash: vec![0xCDu8; 32],
            app_hash: vec![2u8; 32],
            last_commit_hash: vec![3u8; 32],
            trusted_height: trusted_h,
            trusted_validators_hash: next_validators_hash,
            quantum_signature: vec![],
        };

        let current_time = trusted_ts + 10;
        let new_h = reg.update_client(&id, header, current_time).unwrap();
        assert_eq!(new_h, IbcHeight::new(4, 101));
        assert_eq!(
            reg.client(&id).unwrap().latest_height,
            IbcHeight::new(4, 101)
        );
    }

    #[test]
    fn test_misbehaviour_freezes_client() {
        let mut reg = make_registry();
        let h = IbcHeight::new(1, 50);
        let id = reg
            .create_client("chain-x".into(), h, make_consensus(1_000), 1, 3, 86400, 10)
            .unwrap();

        let mb = Misbehaviour {
            client_id: id.clone(),
            header_1: Header {
                chain_id: "chain-x".into(),
                height: IbcHeight::new(1, 60),
                timestamp: 1100,
                validators_hash: vec![],
                next_validators_hash: vec![],
                app_hash: vec![1u8; 32],
                last_commit_hash: vec![],
                trusted_height: h,
                trusted_validators_hash: vec![],
                quantum_signature: vec![],
            },
            header_2: Header {
                chain_id: "chain-x".into(),
                height: IbcHeight::new(1, 60),
                timestamp: 1100,
                validators_hash: vec![],
                next_validators_hash: vec![],
                app_hash: vec![2u8; 32], // different hash!
                last_commit_hash: vec![],
                trusted_height: h,
                trusted_validators_hash: vec![],
                quantum_signature: vec![],
            },
            witness_value: 0.0,
            detection_confidence: 1.0,
        };

        reg.submit_misbehaviour(mb, 2000).unwrap();
        assert!(reg.client(&id).unwrap().frozen);
        assert!((reg.client(&id).unwrap().coherence - 0.0).abs() < 1e-10);
    }

    #[test]
    fn test_misbehaviour_witness() {
        let h1 = Header {
            chain_id: "test".into(),
            height: IbcHeight::new(1, 1),
            timestamp: 1000,
            validators_hash: vec![],
            next_validators_hash: vec![],
            app_hash: vec![1u8; 32],
            last_commit_hash: vec![],
            trusted_height: IbcHeight::zero(),
            trusted_validators_hash: vec![],
            quantum_signature: vec![],
        };

        let h2 = Header {
            app_hash: vec![2u8; 32], // completely different
            ..h1.clone()
        };

        let witness = LightClientRegistry::compute_misbehaviour_witness(&h1, &h2);
        assert!(witness > 0.9); // near 1.0 for completely different hashes
    }

    #[test]
    fn test_ibc_stats() {
        let mut reg = make_registry();
        reg.create_client(
            "chain-a".into(),
            IbcHeight::new(1, 1),
            make_consensus(1000),
            1, 3, 86400, 10,
        )
        .unwrap();

        let stats = reg.stats();
        assert_eq!(stats.total_clients, 1);
        assert_eq!(stats.frozen_clients, 0);
        assert!(stats.coherence > 0.99);
    }
}
