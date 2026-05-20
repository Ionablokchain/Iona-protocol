//! IONA v33 — IBC Light Client (ICS-002 minimal implementation).
//!
//! Implements the core IBC light client state machine that allows IONA to
//! verify headers from other Tendermint/CometBFT chains.
//!
//! # What this enables
//! - Verify block headers from external chains (Cosmos Hub, Osmosis, etc.)
//! - Store verified ConsensusState on-chain
//! - Foundation for ICS-020 token transfers (v34)
//! - Foundation for ICS-027 interchain accounts (v35)
//!
//! # ICS-002 components implemented
//! - ClientState: configuration for a specific counterparty chain
//! - ConsensusState: verified header snapshot at a given height
//! - Header verification: validate new headers against trusted state
//! - Misbehaviour detection: detect equivocation / light client attacks

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use crate::types::Height;

// ── Client types ──────────────────────────────────────────────────────────

/// Unique identifier for an IBC light client.
pub type ClientId = String;

/// Chain ID of the counterparty chain (e.g. "cosmoshub-4").
pub type ChainId = String;

/// IBC client state — configuration for tracking a counterparty chain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClientState {
    /// Chain ID of the counterparty.
    pub chain_id: ChainId,
    /// Latest height verified on the counterparty chain.
    pub latest_height: IbcHeight,
    /// Trust threshold (numerator/denominator). Typically 1/3.
    pub trust_threshold_numerator:   u64,
    pub trust_threshold_denominator: u64,
    /// How long a header is trusted after its timestamp.
    pub trusting_period_s: u64,
    /// Maximum clock drift allowed between our time and header time (seconds).
    pub max_clock_drift_s: u64,
    /// Whether the client is frozen (after misbehaviour detection).
    pub frozen: bool,
    /// Height at which the client was frozen, if frozen.
    pub frozen_height: Option<IbcHeight>,
}

/// Height in IBC format (revision_number, revision_height).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct IbcHeight {
    pub revision_number: u64,
    pub revision_height: u64,
}

impl IbcHeight {
    pub fn new(revision_number: u64, revision_height: u64) -> Self {
        Self { revision_number, revision_height }
    }

    pub fn zero() -> Self {
        Self { revision_number: 0, revision_height: 0 }
    }
}

impl std::fmt::Display for IbcHeight {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}", self.revision_number, self.revision_height)
    }
}

/// Consensus state at a specific height — the verified snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusState {
    /// Block timestamp from the verified header (Unix seconds).
    pub timestamp: u64,
    /// App hash (state root) of the counterparty at this height.
    pub root: Vec<u8>,
    /// Next validators hash — used to verify subsequent headers.
    pub next_validators_hash: Vec<u8>,
}

/// A Tendermint light block header for verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    pub chain_id:           ChainId,
    pub height:             IbcHeight,
    pub timestamp:          u64,
    pub validators_hash:    Vec<u8>,
    pub next_validators_hash: Vec<u8>,
    pub app_hash:           Vec<u8>,
    pub last_commit_hash:   Vec<u8>,
    /// Trusted height from which we verify this header.
    pub trusted_height:     IbcHeight,
    /// Trusted validators hash at trusted_height.
    pub trusted_validators_hash: Vec<u8>,
}

/// Misbehaviour evidence: two conflicting headers at the same height.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Misbehaviour {
    pub client_id: ClientId,
    pub header_1:  Header,
    pub header_2:  Header,
}

// ── Error types ───────────────────────────────────────────────────────────

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
    #[error("header timestamp {header_ts} is in the past (trusted={trusted_ts}, max_drift={drift_s}s)")]
    HeaderTimestampTooOld { header_ts: u64, trusted_ts: u64, drift_s: u64 },
    #[error("header clock drift too large: {diff_s}s > {max_drift_s}s")]
    ClockDriftTooLarge { diff_s: u64, max_drift_s: u64 },
    #[error("trusted period expired: header_ts={header_ts}, trusted_period_end={period_end}")]
    TrustingPeriodExpired { header_ts: u64, period_end: u64 },
    #[error("validators hash mismatch: expected {expected}, got {actual}")]
    ValidatorsHashMismatch { expected: String, actual: String },
    #[error("misbehaviour: headers at same height have different hashes")]
    Misbehaviour,
    #[error("client already exists: {0}")]
    ClientAlreadyExists(ClientId),
}

// ── Light client registry ─────────────────────────────────────────────────

/// On-chain registry of IBC light clients.
///
/// Stored in the chain state; updated by governance proposals or
/// authorized relayers.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LightClientRegistry {
    /// Active client states keyed by client_id.
    pub clients: BTreeMap<ClientId, ClientState>,
    /// Consensus states keyed by (client_id, height).
    pub consensus_states: BTreeMap<(ClientId, IbcHeight), ConsensusState>,
    /// Counter for generating unique client IDs.
    pub next_client_seq: u64,
}

impl LightClientRegistry {
    /// Create a new IBC light client. Returns the assigned client_id.
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
        self.next_client_seq += 1;

        let client = ClientState {
            chain_id: chain_id.clone(),
            latest_height: initial_height,
            trust_threshold_numerator:   trust_threshold_num,
            trust_threshold_denominator: trust_threshold_den,
            trusting_period_s,
            max_clock_drift_s,
            frozen: false,
            frozen_height: None,
        };

        self.clients.insert(client_id.clone(), client);
        self.consensus_states.insert(
            (client_id.clone(), initial_height),
            initial_consensus,
        );

        tracing::info!(
            client_id = %client_id,
            chain_id  = %chain_id,
            height    = %initial_height,
            "IBC light client created"
        );
        Ok(client_id)
    }

    /// Update an existing light client with a new verified header.
    pub fn update_client(
        &mut self,
        client_id: &str,
        header: Header,
        current_time_s: u64,
    ) -> Result<IbcHeight, IbcError> {
        let client = self.clients.get(client_id)
            .ok_or_else(|| IbcError::ClientNotFound(client_id.to_string()))?
            .clone();

        if client.frozen {
            return Err(IbcError::ClientFrozen(
                client.frozen_height.unwrap_or(IbcHeight::zero())
            ));
        }

        // Retrieve trusted consensus state
        let trusted_cs = self.consensus_states
            .get(&(client_id.to_string(), header.trusted_height))
            .ok_or(IbcError::ConsensusNotFound(header.trusted_height))?
            .clone();

        // Validate header
        Self::verify_header(&client, &header, &trusted_cs, current_time_s)?;

        let new_height = header.height;
        let new_cs = ConsensusState {
            timestamp:            header.timestamp,
            root:                 header.app_hash.clone(),
            next_validators_hash: header.next_validators_hash.clone(),
        };

        // Update client state if new height is greater
        if new_height > client.latest_height {
            self.clients.get_mut(client_id).unwrap().latest_height = new_height;
        }

        self.consensus_states.insert((client_id.to_string(), new_height), new_cs);

        tracing::info!(
            client_id = %client_id,
            new_height = %new_height,
            "IBC light client updated"
        );
        Ok(new_height)
    }

    /// Freeze a client after misbehaviour is detected.
    pub fn submit_misbehaviour(
        &mut self,
        misbehaviour: Misbehaviour,
        current_time_s: u64,
    ) -> Result<(), IbcError> {
        let client_id = &misbehaviour.client_id;
        let client = self.clients.get(client_id)
            .ok_or_else(|| IbcError::ClientNotFound(client_id.clone()))?
            .clone();

        if client.frozen { return Ok(()); } // already frozen

        // Both headers must be at the same height and have different hashes
        if misbehaviour.header_1.height != misbehaviour.header_2.height {
            return Err(IbcError::Misbehaviour);
        }
        if misbehaviour.header_1.app_hash == misbehaviour.header_2.app_hash {
            return Err(IbcError::Misbehaviour);
        }

        let freeze_height = misbehaviour.header_1.height;
        let client = self.clients.get_mut(client_id).unwrap();
        client.frozen = true;
        client.frozen_height = Some(freeze_height);

        tracing::warn!(
            client_id = %client_id,
            height    = %freeze_height,
            "IBC light client FROZEN due to misbehaviour"
        );
        Ok(())
    }

    /// Core header verification logic (ICS-002).
    fn verify_header(
        client: &ClientState,
        header: &Header,
        trusted_cs: &ConsensusState,
        current_time_s: u64,
    ) -> Result<(), IbcError> {
        // 1. Height must be greater than trusted height
        if header.height <= header.trusted_height {
            return Err(IbcError::HeaderHeightTooLow {
                header: header.height,
                latest: header.trusted_height,
            });
        }

        // 2. Trusting period: trusted_cs.timestamp + trusting_period > header.timestamp
        let period_end = trusted_cs.timestamp.saturating_add(client.trusting_period_s);
        if header.timestamp > period_end {
            return Err(IbcError::TrustingPeriodExpired {
                header_ts: header.timestamp,
                period_end,
            });
        }

        // 3. Clock drift: header.timestamp <= current_time + max_clock_drift
        if header.timestamp > current_time_s.saturating_add(client.max_clock_drift_s) {
            return Err(IbcError::ClockDriftTooLarge {
                diff_s:       header.timestamp - current_time_s,
                max_drift_s:  client.max_clock_drift_s,
            });
        }

        // 4. Header timestamp must be after trusted timestamp
        if header.timestamp < trusted_cs.timestamp {
            return Err(IbcError::HeaderTimestampTooOld {
                header_ts:  header.timestamp,
                trusted_ts: trusted_cs.timestamp,
                drift_s:    client.max_clock_drift_s,
            });
        }

        // 5. Validators hash must match (or trust threshold must hold for adjacent headers)
        // For adjacent headers: validators_hash must match trusted next_validators_hash
        // For non-adjacent: trust threshold applies (simplified: require validators match)
        let expected_vhash = hex::encode(&trusted_cs.next_validators_hash);
        let actual_vhash   = hex::encode(&header.validators_hash);
        if expected_vhash != actual_vhash {
            return Err(IbcError::ValidatorsHashMismatch {
                expected: expected_vhash,
                actual:   actual_vhash,
            });
        }

        Ok(())
    }

    /// Query a client state.
    pub fn client(&self, id: &str) -> Option<&ClientState> {
        self.clients.get(id)
    }

    /// Query a consensus state.
    pub fn consensus_state(&self, id: &str, height: IbcHeight) -> Option<&ConsensusState> {
        self.consensus_states.get(&(id.to_string(), height))
    }

    /// List all client IDs.
    pub fn client_ids(&self) -> Vec<&str> {
        self.clients.keys().map(|s| s.as_str()).collect()
    }
}

// ── RPC helpers ───────────────────────────────────────────────────────────

/// IBC query response for a client state (JSON-serializable).
#[derive(Debug, Serialize)]
pub struct ClientStateResponse {
    pub client_id:                   String,
    pub chain_id:                    String,
    pub latest_height:               String,
    pub trust_threshold:             String,
    pub trusting_period_s:           u64,
    pub frozen:                      bool,
    pub frozen_height:               Option<String>,
}

impl From<(&str, &ClientState)> for ClientStateResponse {
    fn from((id, cs): (&str, &ClientState)) -> Self {
        Self {
            client_id:         id.to_string(),
            chain_id:          cs.chain_id.clone(),
            latest_height:     cs.latest_height.to_string(),
            trust_threshold:   format!("{}/{}", cs.trust_threshold_numerator, cs.trust_threshold_denominator),
            trusting_period_s: cs.trusting_period_s,
            frozen:            cs.frozen,
            frozen_height:     cs.frozen_height.map(|h| h.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_registry() -> LightClientRegistry {
        LightClientRegistry::default()
    }

    fn make_consensus(ts: u64) -> ConsensusState {
        ConsensusState {
            timestamp:            ts,
            root:                 vec![1u8; 32],
            next_validators_hash: vec![0xABu8; 32],
        }
    }

    #[test]
    fn create_and_query_client() {
        let mut reg = make_registry();
        let initial_height = IbcHeight::new(4, 100);
        let cs = make_consensus(1_700_000_000);

        let id = reg.create_client(
            "cosmoshub-4".into(),
            initial_height, cs,
            1, 3,          // trust threshold 1/3
            7 * 86_400,    // 7 days
            10,            // 10s clock drift
        ).unwrap();

        assert!(id.starts_with("cosmoshub-4-"));
        let state = reg.client(&id).unwrap();
        assert_eq!(state.latest_height, initial_height);
        assert!(!state.frozen);
    }

    #[test]
    fn update_client_success() {
        let mut reg = make_registry();
        let trusted_h = IbcHeight::new(4, 100);
        let trusted_ts = 1_700_000_000u64;
        let cs = make_consensus(trusted_ts);
        let next_validators_hash = cs.next_validators_hash.clone();

        let id = reg.create_client("chain-1".into(), trusted_h, cs, 1, 3, 604_800, 30).unwrap();

        let header = Header {
            chain_id:             "chain-1".into(),
            height:               IbcHeight::new(4, 101),
            timestamp:            trusted_ts + 6,
            validators_hash:      next_validators_hash.clone(),
            next_validators_hash: vec![0xCDu8; 32],
            app_hash:             vec![2u8; 32],
            last_commit_hash:     vec![3u8; 32],
            trusted_height:       trusted_h,
            trusted_validators_hash: next_validators_hash,
        };

        let current_time = trusted_ts + 10;
        let new_h = reg.update_client(&id, header, current_time).unwrap();
        assert_eq!(new_h, IbcHeight::new(4, 101));
        assert_eq!(reg.client(&id).unwrap().latest_height, IbcHeight::new(4, 101));
    }

    #[test]
    fn misbehaviour_freezes_client() {
        let mut reg = make_registry();
        let h = IbcHeight::new(1, 50);
        let id = reg.create_client("chain-x".into(), h, make_consensus(1_000), 1, 3, 86400, 10).unwrap();

        let mb = Misbehaviour {
            client_id: id.clone(),
            header_1: Header {
                chain_id: "chain-x".into(), height: IbcHeight::new(1, 60),
                timestamp: 1100, validators_hash: vec![], next_validators_hash: vec![],
                app_hash: vec![1u8; 32], last_commit_hash: vec![],
                trusted_height: h, trusted_validators_hash: vec![],
            },
            header_2: Header {
                chain_id: "chain-x".into(), height: IbcHeight::new(1, 60),
                timestamp: 1100, validators_hash: vec![], next_validators_hash: vec![],
                app_hash: vec![2u8; 32], last_commit_hash: vec![],  // different hash!
                trusted_height: h, trusted_validators_hash: vec![],
            },
        };

        reg.submit_misbehaviour(mb, 2000).unwrap();
        assert!(reg.client(&id).unwrap().frozen);
    }
}
