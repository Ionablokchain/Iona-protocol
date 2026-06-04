//! Transaction decoding and sender recovery — Quantum k256 compatibility.
//!
//! # Quantum Signature Recovery Model
//!
//! Sender recovery from ECDSA signatures is modelled as a **quantum
//! measurement** on the elliptic curve group. The recovery process
//! collapses the superposition of possible public keys to a single
//! eigenstate corresponding to the signer's address.
//!
//! # Mathematical Formalism
//!
//! ## Recovery as Quantum Measurement
//! ```text
//! |signature⟩ ⊗ |message⟩ → |public_key⟩ ⊗ |address⟩
//! U_recover = U_verify ⊗ U_hash
//! ```
//!
//! ## Hamiltonian for Decode Operations
//! ```text
//! Ĥ_decode = Ĥ_rlp + Ĥ_recover + Ĥ_validate
//!
//! Ĥ_rlp      = Σ_i E_i |field_i⟩⟨field_i|              (RLP decoding)
//! Ĥ_recover  = Σ_j g_j (|sig⟩⟨pk|_j + h.c.)            (signature recovery)
//! Ĥ_validate = Σ_k λ_k |valid_k⟩⟨valid_k|              (validation observable)
//! ```
//!
//! ## Decoherence from Decoding
//! ```text
//! dρ/dt = -i[Ĥ, ρ] + Σ_l γ_l (L_l ρ L_l† - ½{L_l† L_l, ρ})
//! ```
//! where L_l are Lindblad operators for RLP parsing errors and invalid signatures.

use crate::types::tx_evm::EvmTx;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use rlp::Rlp;
use sha3::{Digest, Keccak256};
use thiserror::Error;

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Default quantum coherence for decode operations.
const DEFAULT_DECODE_COHERENCE: f64 = 1.0;

/// Decoherence rate per RLP field decoded.
const RLP_DECODE_DECOHERENCE_RATE: f64 = 0.00005;

/// Decoherence rate per hash operation.
const HASH_DECOHERENCE_RATE: f64 = 0.0001;

/// Decoherence rate per signature recovery attempt.
const RECOVERY_DECOHERENCE_RATE: f64 = 0.0002;

/// Decoherence rate per failed recovery (stronger).
const FAILED_RECOVERY_DECOHERENCE_RATE: f64 = 0.001;

/// Minimum coherence threshold for valid decode.
const MIN_DECODE_COHERENCE: f64 = 0.99;

/// Kraus rank for decode quantum channels.
const DECODE_KRAUS_RANK: usize = 4;

/// Transaction type for legacy transactions (no type byte).
pub const TX_TYPE_LEGACY: u8 = 0x00;

/// Transaction type for EIP‑2930.
pub const TX_TYPE_EIP2930: u8 = 0x01;

/// Transaction type for EIP‑1559.
pub const TX_TYPE_EIP1559: u8 = 0x02;

/// Length of a 20‑byte Ethereum address.
const ADDR_LEN: usize = 20;

/// Length of a 32‑byte hash.
const HASH_LEN: usize = 32;

/// Length of a 64‑byte signature (r + s).
const SIG_LEN: usize = 64;

// -----------------------------------------------------------------------------
// Quantum Decode State
// -----------------------------------------------------------------------------

/// Quantum state of the transaction decoding system.
///
/// Tracks the density matrix properties during RLP parsing, signature
/// recovery, and address derivation.
#[derive(Debug, Clone)]
pub struct QuantumDecodeState {
    /// Purity γ = Tr(ρ²) of the decode state.
    pub purity: f64,
    /// Von Neumann entropy S = -Tr(ρ ln ρ).
    pub entropy: f64,
    /// Coherence of the RLP decoding.
    pub rlp_coherence: f64,
    /// Coherence of the signature recovery.
    pub recovery_coherence: f64,
    /// Number of RLP fields decoded.
    pub fields_decoded: u64,
    /// Number of hash operations performed.
    pub total_hashes: u64,
    /// Number of signature recoveries attempted.
    pub recoveries_attempted: u64,
    /// Number of failed recoveries.
    pub recoveries_failed: u64,
    /// Whether the decode state is valid.
    pub is_valid: bool,
}

impl Default for QuantumDecodeState {
    fn default() -> Self {
        Self {
            purity: DEFAULT_DECODE_COHERENCE,
            entropy: 0.0,
            rlp_coherence: DEFAULT_DECODE_COHERENCE,
            recovery_coherence: DEFAULT_DECODE_COHERENCE,
            fields_decoded: 0,
            total_hashes: 0,
            recoveries_attempted: 0,
            recoveries_failed: 0,
            is_valid: true,
        }
    }
}

impl QuantumDecodeState {
    /// Create a new quantum decode state in the ground state |∅⟩.
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply decoherence from decoding an RLP field.
    pub fn apply_rlp_field_decoherence(&mut self, field_count: u64) {
        self.fields_decoded = self.fields_decoded.wrapping_add(field_count);
        let decay = (-RLP_DECODE_DECOHERENCE_RATE * field_count as f64).exp();
        self.rlp_coherence = (self.rlp_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Apply decoherence from a hash operation.
    pub fn apply_hash_decoherence(&mut self) {
        self.total_hashes = self.total_hashes.wrapping_add(1);
        let decay = (-HASH_DECOHERENCE_RATE).exp();
        self.rlp_coherence = (self.rlp_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Apply decoherence from a successful signature recovery.
    pub fn apply_recovery_decoherence(&mut self, success: bool) {
        self.recoveries_attempted = self.recoveries_attempted.wrapping_add(1);
        let rate = if success {
            RECOVERY_DECOHERENCE_RATE
        } else {
            self.recoveries_failed = self.recoveries_failed.wrapping_add(1);
            FAILED_RECOVERY_DECOHERENCE_RATE
        };
        let decay = (-rate).exp();
        self.recovery_coherence = (self.recovery_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Apply the Kraus channel for decode operations.
    pub fn apply_decode_channel(&mut self) {
        let kraus_factor = (1.0 / DECODE_KRAUS_RANK as f64).sqrt();
        self.rlp_coherence = (self.rlp_coherence * kraus_factor).clamp(0.0, 1.0);
        self.recovery_coherence = (self.recovery_coherence * kraus_factor).clamp(0.0, 1.0);
        self.recompute();
    }

    fn recompute(&mut self) {
        self.purity = (self.rlp_coherence * self.recovery_coherence).clamp(0.0, 1.0);
        self.entropy = if self.purity >= 1.0 {
            0.0
        } else {
            -self.purity * self.purity.ln().max(0.0)
        };
        self.is_valid = self.purity >= MIN_DECODE_COHERENCE;
    }
}

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during transaction decoding and sender recovery.
#[derive(Debug, Error)]
pub enum TxDecodeError {
    #[error("RLP decoding error: {0}")]
    Rlp(String),

    #[error("invalid transaction type byte: 0x{type_byte:02X}")]
    InvalidTxType { type_byte: u8 },

    #[error("empty transaction data")]
    EmptyData,

    #[error("invalid signature component length: expected 32 bytes, got {len}")]
    InvalidSignatureLength { len: usize },

    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    #[error("invalid recovery id: {0}")]
    InvalidRecoveryId(u8),

    #[error("sender recovery failed: {0}")]
    RecoveryFailed(String),

    #[error("invalid address length: expected 20 bytes, got {len}")]
    InvalidAddressLength { len: usize },

    #[error("invalid storage key length: expected <= 32 bytes, got {len}")]
    InvalidStorageKeyLength { len: usize },

    #[error("unexpected v value in legacy transaction: {v}")]
    UnexpectedV { v: u64 },

    #[error("missing field in RLP list: {field}")]
    MissingField { field: &'static str },

    #[error("quantum decoherence: decode coherence {coherence} below threshold {threshold}")]
    Decoherence {
        coherence: f64,
        threshold: f64,
    },
}

pub type TxDecodeResult<T> = Result<T, TxDecodeError>;

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Compute Keccak‑256 hash of data.
#[must_use]
pub fn keccak256(data: &[u8]) -> [u8; HASH_LEN] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute Keccak‑256 hash with quantum state tracking.
#[must_use]
pub fn keccak256_quantum(data: &[u8]) -> ([u8; HASH_LEN], QuantumDecodeState) {
    let hash = keccak256(data);
    let mut state = QuantumDecodeState::new();
    state.apply_hash_decoherence();
    (hash, state)
}

/// Append a `u128` value to an RLP stream as minimal big‑endian bytes.
fn rlp_append_u128(s: &mut rlp::RlpStream, value: u128) {
    if value == 0 {
        s.append(&0u8);
    } else {
        let bytes = value.to_be_bytes();
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(0);
        s.append(&bytes[start..]);
    }
}

/// Decode an address from RLP bytes (empty means `None`).
fn decode_address(bytes: &[u8]) -> TxDecodeResult<Option<[u8; ADDR_LEN]>> {
    if bytes.is_empty() {
        return Ok(None);
    }
    if bytes.len() != ADDR_LEN {
        return Err(TxDecodeError::InvalidAddressLength { len: bytes.len() });
    }
    let mut addr = [0u8; ADDR_LEN];
    addr.copy_from_slice(bytes);
    Ok(Some(addr))
}

/// Encode an optional address to RLP.
fn rlp_encode_address(s: &mut rlp::RlpStream, addr: &Option<[u8; ADDR_LEN]>) {
    match addr {
        Some(a) => s.append(&a.as_slice()),
        None => s.append_empty_data(),
    }
}

/// Decode `r` and `s` signature components from RLP indices.
fn decode_rlp_rs(
    rlp: &Rlp,
    r_idx: usize,
    s_idx: usize,
) -> TxDecodeResult<([u8; HASH_LEN], [u8; HASH_LEN])> {
    let r_vec: Vec<u8> = rlp.val_at(r_idx).map_err(|e| TxDecodeError::Rlp(e.to_string()))?;
    let s_vec: Vec<u8> = rlp.val_at(s_idx).map_err(|e| TxDecodeError::Rlp(e.to_string()))?;
    if r_vec.len() > HASH_LEN || s_vec.len() > HASH_LEN {
        return Err(TxDecodeError::InvalidSignatureLength {
            len: r_vec.len().max(s_vec.len()),
        });
    }
    let mut r = [0u8; HASH_LEN];
    let mut s = [0u8; HASH_LEN];
    r[HASH_LEN - r_vec.len()..].copy_from_slice(&r_vec);
    s[HASH_LEN - s_vec.len()..].copy_from_slice(&s_vec);
    Ok((r, s))
}

/// Decode an EIP‑2930/EIP‑1559 access list.
fn decode_access_list(
    al_rlp: &Rlp,
) -> TxDecodeResult<Vec<([u8; ADDR_LEN], Vec<[u8; HASH_LEN]>)>> {
    if !al_rlp.is_list() {
        return Ok(vec![]);
    }
    let item_count = al_rlp.item_count().map_err(|e| TxDecodeError::Rlp(e.to_string()))?;
    let mut out = Vec::with_capacity(item_count);
    for i in 0..item_count {
        let item = al_rlp
            .at(i)
            .map_err(|_| TxDecodeError::MissingField { field: "access_list_item" })?;
        let addr_bytes: Vec<u8> = item
            .val_at(0)
            .map_err(|_| TxDecodeError::MissingField { field: "address" })?;
        if addr_bytes.len() != ADDR_LEN {
            return Err(TxDecodeError::InvalidAddressLength { len: addr_bytes.len() });
        }
        let mut addr = [0u8; ADDR_LEN];
        addr.copy_from_slice(&addr_bytes);
        let keys_rlp = item
            .at(1)
            .map_err(|_| TxDecodeError::MissingField { field: "storage_keys" })?;
        let keys_count = keys_rlp.item_count().map_err(|e| TxDecodeError::Rlp(e.to_string()))?;
        let mut keys = Vec::with_capacity(keys_count);
        for j in 0..keys_count {
            let k: Vec<u8> = keys_rlp
                .val_at(j)
                .map_err(|_| TxDecodeError::MissingField { field: "storage_key" })?;
            if k.len() > HASH_LEN {
                return Err(TxDecodeError::InvalidStorageKeyLength { len: k.len() });
            }
            let mut key = [0u8; HASH_LEN];
            key[HASH_LEN - k.len()..].copy_from_slice(&k);
            keys.push(key);
        }
        out.push((addr, keys));
    }
    Ok(out)
}

/// Encode an access list to RLP.
fn rlp_encode_access_list(
    s: &mut rlp::RlpStream,
    al: &[([u8; ADDR_LEN], Vec<[u8; HASH_LEN]>)],
) {
    s.begin_list(al.len());
    for (addr, keys) in al {
        s.begin_list(2);
        s.append(&addr.as_slice());
        s.begin_list(keys.len());
        for key in keys {
            s.append(&key.as_slice());
        }
    }
}

// -----------------------------------------------------------------------------
// Legacy transaction
// -----------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct LegacySignedTx {
    pub nonce: u64,
    pub gas_price: u128,
    pub gas_limit: u64,
    pub to: Option<[u8; ADDR_LEN]>,
    pub value: u128,
    pub data: Vec<u8>,
    pub v: u64,
    pub r: [u8; HASH_LEN],
    pub s: [u8; HASH_LEN],
    pub from: [u8; ADDR_LEN],
    pub chain_id: Option<u64>,
}

impl LegacySignedTx {
    /// Convert to `EvmTx`.
    #[must_use]
    pub fn to_evm_tx(&self) -> EvmTx {
        EvmTx::Legacy {
            from: self.from,
            to: self.to,
            nonce: self.nonce,
            gas_limit: self.gas_limit,
            gas_price: self.gas_price,
            value: self.value,
            data: self.data.clone(),
            chain_id: self.chain_id.unwrap_or(1),
        }
    }
}

/// Decode a raw legacy transaction (no type prefix).
pub fn decode_legacy_signed_tx(raw: &[u8]) -> TxDecodeResult<LegacySignedTx> {
    decode_legacy_signed_tx_quantum(raw).map(|(tx, _)| tx)
}

/// Decode a legacy transaction with quantum state tracking.
pub fn decode_legacy_signed_tx_quantum(
    raw: &[u8],
) -> TxDecodeResult<(LegacySignedTx, QuantumDecodeState)> {
    let mut state = QuantumDecodeState::new();
    let rlp = Rlp::new(raw);

    if !rlp.is_list() {
        return Err(TxDecodeError::Rlp("expected RLP list".into()));
    }
    let item_count = rlp.item_count().map_err(|e| TxDecodeError::Rlp(e.to_string()))?;
    if item_count < 9 {
        return Err(TxDecodeError::MissingField {
            field: "one of required fields (need at least 9 items)",
        });
    }

    state.apply_rlp_field_decoherence(9);

    let nonce: u64 = rlp.val_at(0).map_err(|e| TxDecodeError::Rlp(e.to_string()))?;
    let gas_price: u128 = rlp.val_at(1).map_err(|e| TxDecodeError::Rlp(e.to_string()))?;
    let gas_limit: u64 = rlp.val_at(2).map_err(|e| TxDecodeError::Rlp(e.to_string()))?;
    let to_bytes: Vec<u8> = rlp.val_at(3).map_err(|e| TxDecodeError::Rlp(e.to_string()))?;

    let to = decode_address(&to_bytes)?;
    let value: u128 = rlp.val_at(4).map_err(|e| TxDecodeError::Rlp(e.to_string()))?;
    let data: Vec<u8> = rlp.val_at(5).map_err(|e| TxDecodeError::Rlp(e.to_string()))?;
    let v: u64 = rlp.val_at(6).map_err(|e| TxDecodeError::Rlp(e.to_string()))?;
    let (r, s) = decode_rlp_rs(&rlp, 7, 8)?;

    let (chain_id, sighash) = if v >= 35 {
        let cid = (v - 35) / 2;
        let hash =
            legacy_signing_hash(nonce, gas_price, gas_limit, &to, value, &data, Some(cid));
        (Some(cid), hash)
    } else if v == 27 || v == 28 {
        let hash = legacy_signing_hash(nonce, gas_price, gas_limit, &to, value, &data, None);
        (None, hash)
    } else {
        return Err(TxDecodeError::UnexpectedV { v });
    };

    state.apply_hash_decoherence();
    let from = recover_sender_quantum(&sighash, v, r, s, chain_id, &mut state)?;

    Ok((
        LegacySignedTx {
            nonce,
            gas_price,
            gas_limit,
            to,
            value,
            data,
            v,
            r,
            s,
            from,
            chain_id,
        },
        state,
    ))
}

/// Build the signing pre‑image for a legacy transaction.
fn legacy_signing_hash(
    nonce: u64,
    gas_price: u128,
    gas_limit: u64,
    to: &Option<[u8; ADDR_LEN]>,
    value: u128,
    data: &[u8],
    chain_id: Option<u64>,
) -> [u8; HASH_LEN] {
    let list_len = if chain_id.is_some() { 9 } else { 6 };
    let mut s = rlp::RlpStream::new_list(list_len);
    s.append(&nonce);
    rlp_append_u128(&mut s, gas_price);
    s.append(&gas_limit);
    rlp_encode_address(&mut s, to);
    rlp_append_u128(&mut s, value);
    s.append(&data);
    if let Some(cid) = chain_id {
        s.append(&cid);
        s.append(&0u8);
        s.append(&0u8);
    }
    keccak256(&s.out())
}

// -----------------------------------------------------------------------------
// EIP‑2930 transaction (type 0x01)
// -----------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Eip2930SignedTx {
    pub chain_id: u64,
    pub nonce: u64,
    pub gas_price: u128,
    pub gas_limit: u64,
    pub to: Option<[u8; ADDR_LEN]>,
    pub value: u128,
    pub data: Vec<u8>,
    pub access_list: Vec<([u8; ADDR_LEN], Vec<[u8; HASH_LEN]>)>,
    pub y_parity: u8,
    pub r: [u8; HASH_LEN],
    pub s: [u8; HASH_LEN],
    pub from: [u8; ADDR_LEN],
}

impl Eip2930SignedTx {
    /// Convert to `EvmTx`.
    #[must_use]
    pub fn to_evm_tx(&self) -> EvmTx {
        EvmTx::Eip2930 {
            from: self.from,
            to: self.to,
            nonce: self.nonce,
            gas_limit: self.gas_limit,
            gas_price: self.gas_price,
            value: self.value,
            data: self.data.clone(),
            access_list: self
                .access_list
                .iter()
                .map(|(a, keys)| crate::types::tx_evm::AccessListItem {
                    address: *a,
                    storage_keys: keys.iter().copied().collect(),
                })
                .collect(),
            chain_id: self.chain_id,
        }
    }
}

/// Decode an EIP‑2930 transaction. Caller must strip the `0x01` type byte.
pub fn decode_eip2930_signed_tx(payload: &[u8]) -> TxDecodeResult<Eip2930SignedTx> {
    decode_eip2930_signed_tx_quantum(payload).map(|(tx, _)| tx)
}

/// Decode EIP‑2930 with quantum state tracking.
pub fn decode_eip2930_signed_tx_quantum(
    payload: &[u8],
) -> TxDecodeResult<(Eip2930SignedTx, QuantumDecodeState)> {
    let mut state = QuantumDecodeState::new();
    let rlp = Rlp::new(payload);

    if !rlp.is_list() {
        return Err(TxDecodeError::Rlp("EIP-2930: expected RLP list".into()));
    }

    state.apply_rlp_field_decoherence(11);

    let chain_id: u64 = rlp.val_at(0).map_err(|e| TxDecodeError::Rlp(e.to_string()))?;
    let nonce: u64 = rlp.val_at(1).map_err(|e| TxDecodeError::Rlp(e.to_string()))?;
    let gas_price: u128 = rlp.val_at(2).map_err(|e| TxDecodeError::Rlp(e.to_string()))?;
    let gas_limit: u64 = rlp.val_at(3).map_err(|e| TxDecodeError::Rlp(e.to_string()))?;
    let to_bytes: Vec<u8> = rlp.val_at(4).map_err(|e| TxDecodeError::Rlp(e.to_string()))?;
    let to = decode_address(&to_bytes)?;
    let value: u128 = rlp.val_at(5).map_err(|e| TxDecodeError::Rlp(e.to_string()))?;
    let data: Vec<u8> = rlp.val_at(6).map_err(|e| TxDecodeError::Rlp(e.to_string()))?;
    let access_list_rlp = rlp
        .at(7)
        .map_err(|_| TxDecodeError::MissingField { field: "access_list" })?;
    let access_list = decode_access_list(&access_list_rlp)?;
    let y_parity: u8 = rlp.val_at(8).map_err(|e| TxDecodeError::Rlp(e.to_string()))?;
    let (r, s) = decode_rlp_rs(&rlp, 9, 10)?;

    let sighash = eip2930_signing_hash(
        chain_id, nonce, gas_price, gas_limit, &to, value, &data, &access_list,
    );
    state.apply_hash_decoherence();
    let from = recover_sender_typed_quantum(&sighash, y_parity, r, s, &mut state)?;

    Ok((
        Eip2930SignedTx {
            chain_id,
            nonce,
            gas_price,
            gas_limit,
            to,
            value,
            data,
            access_list,
            y_parity,
            r,
            s,
            from,
        },
        state,
    ))
}

fn eip2930_signing_hash(
    chain_id: u64,
    nonce: u64,
    gas_price: u128,
    gas_limit: u64,
    to: &Option<[u8; ADDR_LEN]>,
    value: u128,
    data: &[u8],
    access_list: &[([u8; ADDR_LEN], Vec<[u8; HASH_LEN]>)],
) -> [u8; HASH_LEN] {
    let mut s = rlp::RlpStream::new_list(8);
    s.append(&chain_id);
    s.append(&nonce);
    rlp_append_u128(&mut s, gas_price);
    s.append(&gas_limit);
    rlp_encode_address(&mut s, to);
    rlp_append_u128(&mut s, value);
    s.append(&data);
    rlp_encode_access_list(&mut s, access_list);
    let inner = s.out();
    let mut preimage = vec![TX_TYPE_EIP2930];
    preimage.extend_from_slice(&inner);
    keccak256(&preimage)
}

// -----------------------------------------------------------------------------
// EIP‑1559 transaction (type 0x02)
// -----------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Eip1559SignedTx {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub gas_limit: u64,
    pub to: Option<[u8; ADDR_LEN]>,
    pub value: u128,
    pub data: Vec<u8>,
    pub access_list: Vec<([u8; ADDR_LEN], Vec<[u8; HASH_LEN]>)>,
    pub y_parity: u8,
    pub r: [u8; HASH_LEN],
    pub s: [u8; HASH_LEN],
    pub from: [u8; ADDR_LEN],
}

impl Eip1559SignedTx {
    /// Convert to `EvmTx`.
    #[must_use]
    pub fn to_evm_tx(&self) -> EvmTx {
        EvmTx::Eip1559 {
            from: self.from,
            to: self.to,
            nonce: self.nonce,
            gas_limit: self.gas_limit,
            max_fee_per_gas: self.max_fee_per_gas,
            max_priority_fee_per_gas: self.max_priority_fee_per_gas,
            value: self.value,
            data: self.data.clone(),
            access_list: self
                .access_list
                .iter()
                .map(|(a, keys)| crate::types::tx_evm::AccessListItem {
                    address: *a,
                    storage_keys: keys.iter().copied().collect(),
                })
                .collect(),
            chain_id: self.chain_id,
        }
    }
}

/// Decode an EIP‑1559 transaction. Caller must strip the `0x02` type byte.
pub fn decode_eip1559_signed_tx(payload: &[u8]) -> TxDecodeResult<Eip1559SignedTx> {
    decode_eip1559_signed_tx_quantum(payload).map(|(tx, _)| tx)
}

/// Decode EIP‑1559 with quantum state tracking.
pub fn decode_eip1559_signed_tx_quantum(
    payload: &[u8],
) -> TxDecodeResult<(Eip1559SignedTx, QuantumDecodeState)> {
    let mut state = QuantumDecodeState::new();
    let rlp = Rlp::new(payload);

    if !rlp.is_list() {
        return Err(TxDecodeError::Rlp("EIP-1559: expected RLP list".into()));
    }

    state.apply_rlp_field_decoherence(12);

    let chain_id: u64 = rlp.val_at(0).map_err(|e| TxDecodeError::Rlp(e.to_string()))?;
    let nonce: u64 = rlp.val_at(1).map_err(|e| TxDecodeError::Rlp(e.to_string()))?;
    let max_priority_fee_per_gas: u128 =
        rlp.val_at(2).map_err(|e| TxDecodeError::Rlp(e.to_string()))?;
    let max_fee_per_gas: u128 =
        rlp.val_at(3).map_err(|e| TxDecodeError::Rlp(e.to_string()))?;
    let gas_limit: u64 = rlp.val_at(4).map_err(|e| TxDecodeError::Rlp(e.to_string()))?;
    let to_bytes: Vec<u8> = rlp.val_at(5).map_err(|e| TxDecodeError::Rlp(e.to_string()))?;
    let to = decode_address(&to_bytes)?;
    let value: u128 = rlp.val_at(6).map_err(|e| TxDecodeError::Rlp(e.to_string()))?;
    let data: Vec<u8> = rlp.val_at(7).map_err(|e| TxDecodeError::Rlp(e.to_string()))?;
    let access_list_rlp = rlp
        .at(8)
        .map_err(|_| TxDecodeError::MissingField { field: "access_list" })?;
    let access_list = decode_access_list(&access_list_rlp)?;
    let y_parity: u8 = rlp.val_at(9).map_err(|e| TxDecodeError::Rlp(e.to_string()))?;
    let (r, s) = decode_rlp_rs(&rlp, 10, 11)?;

    let sighash = eip1559_signing_hash(
        chain_id,
        nonce,
        max_priority_fee_per_gas,
        max_fee_per_gas,
        gas_limit,
        &to,
        value,
        &data,
        &access_list,
    );
    state.apply_hash_decoherence();
    let from = recover_sender_typed_quantum(&sighash, y_parity, r, s, &mut state)?;

    Ok((
        Eip1559SignedTx {
            chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to,
            value,
            data,
            access_list,
            y_parity,
            r,
            s,
            from,
        },
        state,
    ))
}

fn eip1559_signing_hash(
    chain_id: u64,
    nonce: u64,
    max_priority: u128,
    max_fee: u128,
    gas_limit: u64,
    to: &Option<[u8; ADDR_LEN]>,
    value: u128,
    data: &[u8],
    access_list: &[([u8; ADDR_LEN], Vec<[u8; HASH_LEN]>)],
) -> [u8; HASH_LEN] {
    let mut s = rlp::RlpStream::new_list(9);
    s.append(&chain_id);
    s.append(&nonce);
    rlp_append_u128(&mut s, max_priority);
    rlp_append_u128(&mut s, max_fee);
    s.append(&gas_limit);
    rlp_encode_address(&mut s, to);
    rlp_append_u128(&mut s, value);
    s.append(&data);
    rlp_encode_access_list(&mut s, access_list);
    let inner = s.out();
    let mut preimage = vec![TX_TYPE_EIP1559];
    preimage.extend_from_slice(&inner);
    keccak256(&preimage)
}

// -----------------------------------------------------------------------------
// Sender recovery (low‑level, public)
// -----------------------------------------------------------------------------

/// Recover address from legacy signature (with optional chain_id for EIP‑155).
pub fn recover_sender(
    sighash: &[u8; HASH_LEN],
    v: u64,
    r: [u8; HASH_LEN],
    s: [u8; HASH_LEN],
    chain_id: Option<u64>,
) -> TxDecodeResult<[u8; ADDR_LEN]> {
    let mut state = QuantumDecodeState::new();
    recover_sender_quantum(sighash, v, r, s, chain_id, &mut state)
}

/// Recover sender with quantum state tracking.
pub fn recover_sender_quantum(
    sighash: &[u8; HASH_LEN],
    v: u64,
    r: [u8; HASH_LEN],
    s: [u8; HASH_LEN],
    chain_id: Option<u64>,
    state: &mut QuantumDecodeState,
) -> TxDecodeResult<[u8; ADDR_LEN]> {
    let recovery_id_byte: u8 = if let Some(cid) = chain_id {
        let base = cid * 2 + 35;
        if v < base {
            return Err(TxDecodeError::UnexpectedV { v });
        }
        ((v - base) & 1) as u8
    } else {
        if v < 27 {
            return Err(TxDecodeError::UnexpectedV { v });
        }
        ((v - 27) & 1) as u8
    };
    recover_from_components_quantum(sighash, recovery_id_byte, r, s, state)
}

/// Recover address from typed transaction (y_parity directly 0 or 1).
pub fn recover_sender_typed(
    sighash: &[u8; HASH_LEN],
    y_parity: u8,
    r: [u8; HASH_LEN],
    s: [u8; HASH_LEN],
) -> TxDecodeResult<[u8; ADDR_LEN]> {
    let mut state = QuantumDecodeState::new();
    recover_sender_typed_quantum(sighash, y_parity, r, s, &mut state)
}

/// Recover sender from typed tx with quantum state tracking.
pub fn recover_sender_typed_quantum(
    sighash: &[u8; HASH_LEN],
    y_parity: u8,
    r: [u8; HASH_LEN],
    s: [u8; HASH_LEN],
    state: &mut QuantumDecodeState,
) -> TxDecodeResult<[u8; ADDR_LEN]> {
    recover_from_components_quantum(sighash, y_parity & 1, r, s, state)
}

fn recover_from_components(
    sighash: &[u8; HASH_LEN],
    recovery_id_byte: u8,
    r: [u8; HASH_LEN],
    s: [u8; HASH_LEN],
) -> TxDecodeResult<[u8; ADDR_LEN]> {
    let mut state = QuantumDecodeState::new();
    recover_from_components_quantum(sighash, recovery_id_byte, r, s, &mut state)
}

fn recover_from_components_quantum(
    sighash: &[u8; HASH_LEN],
    recovery_id_byte: u8,
    r: [u8; HASH_LEN],
    s: [u8; HASH_LEN],
    state: &mut QuantumDecodeState,
) -> TxDecodeResult<[u8; ADDR_LEN]> {
    let mut sig_bytes = [0u8; SIG_LEN];
    sig_bytes[..HASH_LEN].copy_from_slice(&r);
    sig_bytes[HASH_LEN..].copy_from_slice(&s);
    let sig = Signature::from_bytes(&sig_bytes.into())
        .map_err(|e| TxDecodeError::InvalidSignature(e.to_string()))?;
    let rec_id = RecoveryId::try_from(recovery_id_byte)
        .map_err(|_| TxDecodeError::InvalidRecoveryId(recovery_id_byte))?;
    let vk = VerifyingKey::recover_from_prehash(sighash, &sig, rec_id)
        .map_err(|e| {
            state.apply_recovery_decoherence(false);
            TxDecodeError::RecoveryFailed(e.to_string())
        })?;

    state.apply_recovery_decoherence(true);
    state.apply_hash_decoherence();

    let point = vk.to_encoded_point(false);
    let pk_bytes = point.as_bytes();
    if pk_bytes.len() != 65 {
        return Err(TxDecodeError::RecoveryFailed(format!(
            "unexpected pubkey length {}",
            pk_bytes.len()
        )));
    }
    let hash = keccak256(&pk_bytes[1..]); // skip 0x04 prefix
    let mut addr = [0u8; ADDR_LEN];
    addr.copy_from_slice(&hash[12..]);
    Ok(addr)
}

// -----------------------------------------------------------------------------
// Public dispatcher
// -----------------------------------------------------------------------------

/// Decode any supported raw transaction type and return `(EvmTx, sender_address)`.
pub fn decode_raw_tx(raw: &[u8]) -> TxDecodeResult<(EvmTx, [u8; ADDR_LEN])> {
    decode_raw_tx_quantum(raw).map(|(tx, addr, _)| (tx, addr))
}

/// Decode raw transaction with quantum state tracking.
pub fn decode_raw_tx_quantum(
    raw: &[u8],
) -> TxDecodeResult<(EvmTx, [u8; ADDR_LEN], QuantumDecodeState)> {
    if raw.is_empty() {
        return Err(TxDecodeError::EmptyData);
    }
    match raw[0] {
        TX_TYPE_EIP2930 => {
            let (tx, state) = decode_eip2930_signed_tx_quantum(&raw[1..])?;
            let from = tx.from;
            Ok((tx.to_evm_tx(), from, state))
        }
        TX_TYPE_EIP1559 => {
            let (tx, state) = decode_eip1559_signed_tx_quantum(&raw[1..])?;
            let from = tx.from;
            Ok((tx.to_evm_tx(), from, state))
        }
        _ => {
            let (tx, state) = decode_legacy_signed_tx_quantum(raw)?;
            let from = tx.from;
            Ok((tx.to_evm_tx(), from, state))
        }
    }
}

/// Compute the quantum fidelity between two addresses.
///
/// ```text
/// F = |⟨addr_a|addr_b⟩|²
/// ```
pub fn address_fidelity(a: &[u8; ADDR_LEN], b: &[u8; ADDR_LEN]) -> f64 {
    if a == b {
        1.0
    } else {
        0.0
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── Classical Tests ──────────────────────────────────────────────
    #[test]
    fn keccak_known() {
        let h = keccak256(b"");
        let expected =
            hex::decode("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
                .unwrap();
        assert_eq!(&h[..], &expected[..]);
    }

    #[test]
    fn decode_raw_empty_fails() {
        assert!(decode_raw_tx(&[]).is_err());
    }

    // ── Quantum Tests ────────────────────────────────────────────────
    #[test]
    fn test_quantum_state_initialization() {
        let state = QuantumDecodeState::new();
        assert!((state.purity - 1.0).abs() < 1e-10);
        assert!((state.entropy - 0.0).abs() < 1e-10);
        assert!(state.is_valid);
    }

    #[test]
    fn test_rlp_field_decoherence() {
        let mut state = QuantumDecodeState::new();
        let initial_purity = state.purity;

        state.apply_rlp_field_decoherence(5);
        assert!(state.purity < initial_purity);
        assert_eq!(state.fields_decoded, 5);
    }

    #[test]
    fn test_hash_decoherence() {
        let mut state = QuantumDecodeState::new();
        let initial_purity = state.purity;

        state.apply_hash_decoherence();
        assert!(state.purity < initial_purity);
        assert_eq!(state.total_hashes, 1);
    }

    #[test]
    fn test_recovery_decoherence_success() {
        let mut state = QuantumDecodeState::new();
        let initial_purity = state.purity;

        state.apply_recovery_decoherence(true);
        assert!(state.purity < initial_purity);
        assert_eq!(state.recoveries_attempted, 1);
        assert_eq!(state.recoveries_failed, 0);
    }

    #[test]
    fn test_recovery_decoherence_failure() {
        let mut state1 = QuantumDecodeState::new();
        let mut state2 = QuantumDecodeState::new();

        state1.apply_recovery_decoherence(true);
        state2.apply_recovery_decoherence(false);

        assert!(state2.purity < state1.purity);
        assert_eq!(state2.recoveries_failed, 1);
    }

    #[test]
    fn test_decode_channel() {
        let mut state = QuantumDecodeState::new();
        let initial_rlp_coh = state.rlp_coherence;

        state.apply_decode_channel();
        assert!(state.rlp_coherence < initial_rlp_coh);
        assert!(state.recovery_coherence < 1.0);
    }

    #[test]
    fn test_keccak256_quantum() {
        let (hash, state) = keccak256_quantum(b"test");

        assert_eq!(hash.len(), HASH_LEN);
        assert!(state.purity < 1.0);
        assert_eq!(state.total_hashes, 1);
    }

    #[test]
    fn test_address_fidelity_identical() {
        let addr1 = [0xAA; ADDR_LEN];
        let addr2 = [0xAA; ADDR_LEN];
        assert!((address_fidelity(&addr1, &addr2) - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_address_fidelity_different() {
        let addr1 = [0xAA; ADDR_LEN];
        let addr2 = [0xBB; ADDR_LEN];
        assert!((address_fidelity(&addr1, &addr2) - 0.0).abs() < 1e-10);
    }

    #[test]
    fn test_coherence_validity() {
        let mut state = QuantumDecodeState::new();
        assert!(state.is_valid);

        for _ in 0..5000 {
            state.apply_recovery_decoherence(false);
        }
        assert!(!state.is_valid);
    }

    #[test]
    fn test_purity_never_negative() {
        let mut state = QuantumDecodeState::new();
        for _ in 0..100000 {
            state.apply_hash_decoherence();
        }
        assert!(state.purity >= 0.0);
    }

    #[test]
    fn test_entropy_increases() {
        let mut state = QuantumDecodeState::new();
        let initial_entropy = state.entropy;

        state.apply_rlp_field_decoherence(100);
        assert!(state.entropy > initial_entropy);
    }
}
