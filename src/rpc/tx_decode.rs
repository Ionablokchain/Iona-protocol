//! Transaction decoding and sender recovery — k256 0.13 compatible.
//!
//! k256 0.13 removed the `recoverable` module. Recovery now uses
//! `ecdsa::RecoveryId` + `VerifyingKey::recover_from_prehash`.
//!
//! Supports:
//!   - Legacy (EIP-155 + pre-EIP-155)
//!   - EIP-2930 (type 0x01)
//!   - EIP-1559 (type 0x02)

use crate::types::tx_evm::EvmTx;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use rlp::Rlp;
use sha3::{Digest, Keccak256};

// ── Helpers ───────────────────────────────────────────────────────────────

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(data);
    h.finalize().into()
}

/// Recover 20-byte address from a prehash + (v, r, s) as used in Legacy txs.
///
/// For EIP-155: recovery_id = (v - chain_id * 2 - 35) & 1
/// For pre-EIP-155: recovery_id = v - 27
pub fn recover_sender(
    sighash: &[u8; 32],
    v: u64,
    r: [u8; 32],
    s: [u8; 32],
    chain_id: Option<u64>,
) -> Result<[u8; 20], String> {
    let recovery_id_byte: u8 = if let Some(cid) = chain_id {
        // EIP-155
        let base = cid * 2 + 35;
        if v < base {
            return Err(format!("v={v} < base={base} for chain_id={cid}"));
        }
        ((v - base) & 1) as u8
    } else {
        // pre-EIP-155
        if v < 27 {
            return Err(format!("v={v} < 27"));
        }
        ((v - 27) & 1) as u8
    };

    recover_from_components(sighash, recovery_id_byte, r, s)
}

/// Recover sender from typed tx (y_parity is 0 or 1 directly).
pub fn recover_sender_typed(
    sighash: &[u8; 32],
    y_parity: u8,
    r: [u8; 32],
    s: [u8; 32],
) -> Result<[u8; 20], String> {
    recover_from_components(sighash, y_parity & 1, r, s)
}

fn recover_from_components(
    sighash: &[u8; 32],
    recovery_id_byte: u8,
    r: [u8; 32],
    s: [u8; 32],
) -> Result<[u8; 20], String> {
    // Build 64-byte compact signature [r || s]
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&r);
    sig_bytes[32..].copy_from_slice(&s);

    let sig = Signature::from_bytes((&sig_bytes).into())
        .map_err(|e| format!("invalid signature: {e}"))?;

    let rec_id = RecoveryId::try_from(recovery_id_byte)
        .map_err(|e| format!("invalid recovery id {recovery_id_byte}: {e}"))?;

    let vk = VerifyingKey::recover_from_prehash(sighash, &sig, rec_id)
        .map_err(|e| format!("recovery failed: {e}"))?;

    // Uncompressed public key → keccak256 of last 64 bytes → take last 20 bytes
    let point = vk.to_encoded_point(false);
    let pk_bytes = point.as_bytes();
    if pk_bytes.len() != 65 {
        return Err(format!("unexpected pubkey len {}", pk_bytes.len()));
    }
    let hash = keccak256(&pk_bytes[1..]); // skip 0x04 prefix
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    Ok(addr)
}

// ── Legacy transaction ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LegacySignedTx {
    pub nonce: u64,
    pub gas_price: u128,
    pub gas_limit: u64,
    pub to: Option<[u8; 20]>,
    pub value: u128,
    pub data: Vec<u8>,
    pub v: u64,
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub from: [u8; 20],
    /// Extracted chain_id (None for pre-EIP-155 txs).
    pub chain_id: Option<u64>,
}

impl LegacySignedTx {
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
///
/// Handles both EIP-155 (v = chain_id*2 + 35/36) and
/// pre-EIP-155 (v = 27/28) encoding.
pub fn decode_legacy_signed_tx(raw: &[u8]) -> Result<LegacySignedTx, String> {
    let rlp = Rlp::new(raw);
    if !rlp.is_list() || rlp.item_count().unwrap_or(0) < 9 {
        return Err("not a legacy tx (need RLP list of 9)".into());
    }

    let nonce: u64 = rlp.val_at(0).map_err(|_| "nonce")?;
    let gas_price: u128 = rlp.val_at(1).map_err(|_| "gas_price")?;
    let gas_limit: u64 = rlp.val_at(2).map_err(|_| "gas_limit")?;
    let to_bytes: Vec<u8> = rlp.val_at(3).map_err(|_| "to")?;
    let to = if to_bytes.is_empty() {
        None
    } else {
        if to_bytes.len() != 20 {
            return Err("to: expected 20 bytes".into());
        }
        let mut a = [0u8; 20];
        a.copy_from_slice(&to_bytes);
        Some(a)
    };
    let value: u128 = rlp.val_at(4).map_err(|_| "value")?;
    let data: Vec<u8> = rlp.val_at(5).map_err(|_| "data")?;
    let v: u64 = rlp.val_at(6).map_err(|_| "v")?;
    let r_vec: Vec<u8> = rlp.val_at(7).map_err(|_| "r")?;
    let s_vec: Vec<u8> = rlp.val_at(8).map_err(|_| "s")?;

    let (mut r, mut s) = ([0u8; 32], [0u8; 32]);
    if r_vec.len() > 32 || s_vec.len() > 32 {
        return Err("sig component > 32 bytes".into());
    }
    r[32 - r_vec.len()..].copy_from_slice(&r_vec);
    s[32 - s_vec.len()..].copy_from_slice(&s_vec);

    // Extract chain_id and build signing hash
    let (chain_id, sighash) = if v >= 35 {
        // EIP-155: chain_id = (v - 35) / 2
        let cid = (v - 35) / 2;
        let hash = legacy_signing_hash(nonce, gas_price, gas_limit, &to, value, &data, Some(cid));
        (Some(cid), hash)
    } else if v == 27 || v == 28 {
        // pre-EIP-155
        let hash = legacy_signing_hash(nonce, gas_price, gas_limit, &to, value, &data, None);
        (None, hash)
    } else {
        return Err(format!("unexpected v={v}"));
    };

    let from = recover_sender(&sighash, v, r, s, chain_id)?;

    Ok(LegacySignedTx {
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
    })
}

/// Build the signing pre-image for a legacy tx.
fn legacy_signing_hash(
    nonce: u64,
    gas_price: u128,
    gas_limit: u64,
    to: &Option<[u8; 20]>,
    value: u128,
    data: &[u8],
    chain_id: Option<u64>,
) -> [u8; 32] {
    let mut s = rlp::RlpStream::new_list(if chain_id.is_some() { 9 } else { 6 });
    s.append(&nonce);
    append_u128(&mut s, gas_price);
    s.append(&gas_limit);
    match to {
        Some(a) => s.append(&a.as_slice()),
        None => s.append_empty_data(),
    };
    append_u128(&mut s, value);
    s.append(&data);
    if let Some(cid) = chain_id {
        // EIP-155 replay protection fields
        s.append(&cid);
        s.append(&0u8);
        s.append(&0u8);
    }
    keccak256(&s.out())
}

// ── EIP-2930 transaction (type 0x01) ─────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Eip2930SignedTx {
    pub chain_id: u64,
    pub nonce: u64,
    pub gas_price: u128,
    pub gas_limit: u64,
    pub to: Option<[u8; 20]>,
    pub value: u128,
    pub data: Vec<u8>,
    pub access_list: Vec<([u8; 20], Vec<[u8; 32]>)>,
    pub y_parity: u8,
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub from: [u8; 20],
}

impl Eip2930SignedTx {
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

/// Decode an EIP-2930 transaction.
/// Caller must strip the `0x01` type byte before passing `payload`.
pub fn decode_eip2930_signed_tx(payload: &[u8]) -> Result<Eip2930SignedTx, String> {
    let rlp = Rlp::new(payload);
    if !rlp.is_list() {
        return Err("EIP-2930: expected RLP list".into());
    }

    let chain_id: u64 = rlp.val_at(0).map_err(|_| "chain_id")?;
    let nonce: u64 = rlp.val_at(1).map_err(|_| "nonce")?;
    let gas_price: u128 = rlp.val_at(2).map_err(|_| "gas_price")?;
    let gas_limit: u64 = rlp.val_at(3).map_err(|_| "gas")?;
    let to_bytes: Vec<u8> = rlp.val_at(4).map_err(|_| "to")?;
    let to = decode_to(&to_bytes)?;
    let value: u128 = rlp.val_at(5).map_err(|_| "value")?;
    let data: Vec<u8> = rlp.val_at(6).map_err(|_| "data")?;
    let access_list = decode_access_list(&rlp.at(7).map_err(|_| "access_list")?)?;
    let y_parity: u8 = rlp.val_at(8).map_err(|_| "y_parity")?;
    let (r, s) = decode_rs(&rlp, 9, 10)?;

    // Signing hash: keccak256(0x01 || rlp([chainId,nonce,gasPrice,gas,to,value,data,accessList]))
    let sighash = eip2930_signing_hash(
        chain_id,
        nonce,
        gas_price,
        gas_limit,
        &to,
        value,
        &data,
        &access_list,
    );
    let from = recover_sender_typed(&sighash, y_parity, r, s)?;

    Ok(Eip2930SignedTx {
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
    })
}

fn eip2930_signing_hash(
    chain_id: u64,
    nonce: u64,
    gas_price: u128,
    gas_limit: u64,
    to: &Option<[u8; 20]>,
    value: u128,
    data: &[u8],
    access_list: &[([u8; 20], Vec<[u8; 32]>)],
) -> [u8; 32] {
    let inner = encode_eip2930_body(
        chain_id,
        nonce,
        gas_price,
        gas_limit,
        to,
        value,
        data,
        access_list,
    );
    let mut preimage = vec![0x01u8];
    preimage.extend_from_slice(&inner);
    keccak256(&preimage)
}

fn encode_eip2930_body(
    chain_id: u64,
    nonce: u64,
    gas_price: u128,
    gas_limit: u64,
    to: &Option<[u8; 20]>,
    value: u128,
    data: &[u8],
    access_list: &[([u8; 20], Vec<[u8; 32]>)],
) -> Vec<u8> {
    let mut s = rlp::RlpStream::new_list(8);
    s.append(&chain_id);
    s.append(&nonce);
    append_u128(&mut s, gas_price);
    s.append(&gas_limit);
    encode_to(&mut s, to);
    append_u128(&mut s, value);
    s.append(&data);
    encode_access_list(&mut s, access_list);
    s.out().to_vec()
}

// ── EIP-1559 transaction (type 0x02) ─────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Eip1559SignedTx {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub gas_limit: u64,
    pub to: Option<[u8; 20]>,
    pub value: u128,
    pub data: Vec<u8>,
    pub access_list: Vec<([u8; 20], Vec<[u8; 32]>)>,
    pub y_parity: u8,
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub from: [u8; 20],
}

impl Eip1559SignedTx {
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

/// Decode an EIP-1559 transaction.
/// Caller must strip the `0x02` type byte before passing `payload`.
pub fn decode_eip1559_signed_tx(payload: &[u8]) -> Result<Eip1559SignedTx, String> {
    let rlp = Rlp::new(payload);
    if !rlp.is_list() {
        return Err("EIP-1559: expected RLP list".into());
    }

    let chain_id: u64 = rlp.val_at(0).map_err(|_| "chain_id")?;
    let nonce: u64 = rlp.val_at(1).map_err(|_| "nonce")?;
    let max_priority_fee_per_gas: u128 = rlp.val_at(2).map_err(|_| "max_priority_fee")?;
    let max_fee_per_gas: u128 = rlp.val_at(3).map_err(|_| "max_fee")?;
    let gas_limit: u64 = rlp.val_at(4).map_err(|_| "gas")?;
    let to_bytes: Vec<u8> = rlp.val_at(5).map_err(|_| "to")?;
    let to = decode_to(&to_bytes)?;
    let value: u128 = rlp.val_at(6).map_err(|_| "value")?;
    let data: Vec<u8> = rlp.val_at(7).map_err(|_| "data")?;
    let access_list = decode_access_list(&rlp.at(8).map_err(|_| "access_list")?)?;
    let y_parity: u8 = rlp.val_at(9).map_err(|_| "y_parity")?;
    let (r, s) = decode_rs(&rlp, 10, 11)?;

    // Signing hash: keccak256(0x02 || rlp([chainId,...]))
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
    let from = recover_sender_typed(&sighash, y_parity, r, s)?;

    Ok(Eip1559SignedTx {
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
    })
}

fn eip1559_signing_hash(
    chain_id: u64,
    nonce: u64,
    max_priority: u128,
    max_fee: u128,
    gas_limit: u64,
    to: &Option<[u8; 20]>,
    value: u128,
    data: &[u8],
    access_list: &[([u8; 20], Vec<[u8; 32]>)],
) -> [u8; 32] {
    let mut s = rlp::RlpStream::new_list(9);
    s.append(&chain_id);
    s.append(&nonce);
    append_u128(&mut s, max_priority);
    append_u128(&mut s, max_fee);
    s.append(&gas_limit);
    encode_to(&mut s, to);
    append_u128(&mut s, value);
    s.append(&data);
    encode_access_list(&mut s, access_list);
    let inner = s.out().to_vec();
    let mut preimage = vec![0x02u8];
    preimage.extend_from_slice(&inner);
    keccak256(&preimage)
}

// ── Public dispatcher ─────────────────────────────────────────────────────

/// Decode any supported raw transaction type and return the typed tx + sender.
pub fn decode_raw_tx(raw: &[u8]) -> Result<(EvmTx, [u8; 20]), String> {
    if raw.is_empty() {
        return Err("empty tx".into());
    }
    match raw[0] {
        0x01 => {
            let tx = decode_eip2930_signed_tx(&raw[1..])?;
            let from = tx.from;
            Ok((tx.to_evm_tx(), from))
        }
        0x02 => {
            let tx = decode_eip1559_signed_tx(&raw[1..])?;
            let from = tx.from;
            Ok((tx.to_evm_tx(), from))
        }
        _ => {
            // Legacy: no type prefix
            let tx = decode_legacy_signed_tx(raw)?;
            let from = tx.from;
            Ok((tx.to_evm_tx(), from))
        }
    }
}

// ── Shared RLP helpers ────────────────────────────────────────────────────

fn decode_to(bytes: &[u8]) -> Result<Option<[u8; 20]>, String> {
    if bytes.is_empty() {
        return Ok(None);
    }
    if bytes.len() != 20 {
        return Err(format!("to: expected 20 bytes, got {}", bytes.len()));
    }
    let mut a = [0u8; 20];
    a.copy_from_slice(bytes);
    Ok(Some(a))
}

fn decode_rs(rlp: &Rlp, r_idx: usize, s_idx: usize) -> Result<([u8; 32], [u8; 32]), String> {
    let r_vec: Vec<u8> = rlp.val_at(r_idx).map_err(|_| "r")?;
    let s_vec: Vec<u8> = rlp.val_at(s_idx).map_err(|_| "s")?;
    if r_vec.len() > 32 || s_vec.len() > 32 {
        return Err("sig component > 32 bytes".into());
    }
    let (mut r, mut s) = ([0u8; 32], [0u8; 32]);
    r[32 - r_vec.len()..].copy_from_slice(&r_vec);
    s[32 - s_vec.len()..].copy_from_slice(&s_vec);
    Ok((r, s))
}

fn decode_access_list(al: &Rlp) -> Result<Vec<([u8; 20], Vec<[u8; 32]>)>, String> {
    let mut out = vec![];
    if !al.is_list() {
        return Ok(out);
    }
    for i in 0..al.item_count().unwrap_or(0) {
        let item = al.at(i).map_err(|_| "al item")?;
        let addr_bytes: Vec<u8> = item.val_at(0).map_err(|_| "al addr")?;
        if addr_bytes.len() != 20 {
            return Err("al addr: expected 20 bytes".into());
        }
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&addr_bytes);
        let keys_rlp = item.at(1).map_err(|_| "al keys")?;
        let mut keys = vec![];
        for j in 0..keys_rlp.item_count().unwrap_or(0) {
            let k: Vec<u8> = keys_rlp.val_at(j).map_err(|_| "key")?;
            if k.len() > 32 {
                return Err("storage key > 32 bytes".into());
            }
            let mut hh = [0u8; 32];
            hh[32 - k.len()..].copy_from_slice(&k);
            keys.push(hh);
        }
        out.push((addr, keys));
    }
    Ok(out)
}

fn encode_to(s: &mut rlp::RlpStream, to: &Option<[u8; 20]>) {
    match to {
        Some(a) => s.append(&a.as_slice()),
        None => s.append_empty_data(),
    };
}

fn encode_access_list(s: &mut rlp::RlpStream, al: &[([u8; 20], Vec<[u8; 32]>)]) {
    s.begin_list(al.len());
    for (addr, keys) in al {
        s.begin_list(2);
        s.append(&addr.as_slice());
        s.begin_list(keys.len());
        for k in keys {
            s.append(&k.as_slice());
        }
    }
}

/// Append u128 as minimal big-endian bytes (RLP integer encoding).
fn append_u128(s: &mut rlp::RlpStream, v: u128) {
    if v == 0 {
        s.append(&0u8);
    } else {
        let bytes = v.to_be_bytes();
        let trimmed: &[u8] = bytes.as_ref();
        let start = trimmed.iter().position(|&b| b != 0).unwrap_or(15);
        let tail: &[u8] = &trimmed[start..];
        s.append(&tail);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
