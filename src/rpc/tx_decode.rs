use crate::types::tx_evm::EvmTx;
use k256::ecdsa::{recoverable, signature::Signature as _, Signature, VerifyingKey};
use rlp::Rlp;
use sha3::{Digest, Keccak256};

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
}

impl LegacySignedTx {
    pub fn to_evm_tx(&self, chain_id: u64) -> EvmTx {
        EvmTx::Legacy {
            from: self.from,
            to: self.to,
            nonce: self.nonce,
            gas_limit: self.gas_limit,
            gas_price: self.gas_price,
            value: self.value,
            data: self.data.clone(),
            chain_id,
        }
    }
}

pub fn decode_legacy_signed_tx(raw: &[u8]) -> Result<LegacySignedTx, String> {
    let rlp = Rlp::new(raw);
    if !rlp.is_list() || rlp.item_count().unwrap_or(0) < 9 {
        return Err("not legacy tx".into());
    }

    let nonce: u64 = rlp.val_at(0).map_err(|_| "nonce")?;
    let gas_price: u128 = rlp.val_at(1).map_err(|_| "gas_price")?;
    let gas_limit: u64 = rlp.val_at(2).map_err(|_| "gas_limit")?;
    let to_bytes: Vec<u8> = rlp.val_at(3).map_err(|_| "to")?;
    let to = if to_bytes.is_empty() {
        None
    } else {
        if to_bytes.len() != 20 { return Err("to len".into()); }
        let mut a=[0u8;20]; a.copy_from_slice(&to_bytes); Some(a)
    };
    let value: u128 = rlp.val_at(4).map_err(|_| "value")?;
    let data: Vec<u8> = rlp.val_at(5).map_err(|_| "data")?;

    let v: u64 = rlp.val_at(6).map_err(|_| "v")?;
    let r_vec: Vec<u8> = rlp.val_at(7).map_err(|_| "r")?;
    let s_vec: Vec<u8> = rlp.val_at(8).map_err(|_| "s")?;

    let mut r = [0u8;32]; let mut s = [0u8;32];
    if r_vec.len() > 32 || s_vec.len() > 32 { return Err("sig len".into()); }
    r[32-r_vec.len()..].copy_from_slice(&r_vec);
    s[32-s_vec.len()..].copy_from_slice(&s_vec);

    // Recover sender
    let sighash = keccak256(&raw_for_sig(nonce, gas_price, gas_limit, &to, value, &data, v));
    let from = recover_sender(&sighash, v, r, s)?;

    Ok(LegacySignedTx { nonce, gas_price, gas_limit, to, value, data, v, r, s, from })
}

fn raw_for_sig(
    nonce: u64,
    gas_price: u128,
    gas_limit: u64,
    to: &Option<[u8;20]>,
    value: u128,
    data: &[u8],
    v: u64,
) -> Vec<u8> {
    // EIP-155 handling (very simplified): if v >= 35, chain_id = (v-35)/2
    // For a real chain: use explicit chain_id from config and validate.
    let chain_id_opt = if v >= 35 { Some((v - 35) / 2) } else { None };

    let mut stream = rlp::RlpStream::new_list(if chain_id_opt.is_some() { 9 } else { 6 });
    stream.append(&nonce);
    stream.append(&gas_price);
    stream.append(&gas_limit);
    match to {
        Some(a) => stream.append(&a.as_slice()),
        None => stream.append(&""),
    }
    stream.append(&value);
    stream.append(&data);

    if let Some(cid) = chain_id_opt {
        stream.append(&cid);
        stream.append(&0u8);
        stream.append(&0u8);
    }

    stream.out().to_vec()
}

fn recover_sender(msg_hash: &[u8;32], v: u64, r: [u8;32], s: [u8;32]) -> Result<[u8;20], String> {
    // recovery id
    let recid = if v == 27 || v == 28 {
        (v - 27) as u8
    } else if v >= 35 {
        ((v - 35) % 2) as u8
    } else {
        return Err("bad v".into());
    };

    let sig = Signature::from_scalars(r, s).map_err(|_| "sig")?;
    let rec_id = recoverable::Id::new(recid).map_err(|_| "recid")?;
    let rec_sig = recoverable::Signature::new(&sig, rec_id).map_err(|_| "recsig")?;

    let vk = rec_sig.recover_verifying_key_from_digest_bytes((*msg_hash).into()).map_err(|_| "recover")?;
    let pubkey = vk.to_encoded_point(false);
    let pub_bytes = pubkey.as_bytes();
    // pub_bytes[0] == 0x04, then 64 bytes X||Y
    let hash = keccak256(&pub_bytes[1..]);
    let mut out = [0u8;20];
    out.copy_from_slice(&hash[12..]);
    Ok(out)
}

pub fn keccak256_hex(data: &[u8]) -> String {
    format!("0x{}", hex::encode(keccak256(data)))
}

fn keccak256(data: &[u8]) -> [u8;32] {
    let mut h = Keccak256::new();
    h.update(data);
    let r = h.finalize();
    let mut out=[0u8;32];
    out.copy_from_slice(&r);
    out
}


// -------- EIP-1559 typed tx (0x02) decoding (scaffold) --------

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
    pub access_list: Vec<( [u8;20], Vec<[u8;32]> )>,
    pub y_parity: u8,
    pub r: [u8;32],
    pub s: [u8;32],
    pub from: [u8;20],
}

impl Eip1559SignedTx {
    pub fn to_evm_tx(&self) -> crate::types::tx_evm::EvmTx {
        crate::types::tx_evm::EvmTx::Eip1559 {
            from: self.from,
            to: self.to,
            nonce: self.nonce,
            gas_limit: self.gas_limit,
            max_fee_per_gas: self.max_fee_per_gas,
            max_priority_fee_per_gas: self.max_priority_fee_per_gas,
            value: self.value,
            data: self.data.clone(),
            access_list: self.access_list.iter().map(|(a, keys)| crate::types::tx_evm::AccessListItem{
                address: *a,
                storage_keys: keys.iter().map(|h| *h).collect(),
            }).collect(),
            chain_id: self.chain_id,
        }
    }
}

pub fn decode_typed_tx(raw: &[u8]) -> Result<EvmTx, String> {
    if raw.is_empty() { return Err("empty".into()); }
    match raw[0] {
        0x01 => {
            let t = decode_eip2930_signed_tx(&raw[1..])?;
            Ok(t.to_evm_tx())
        }
        0x02 => {
            let t = decode_eip1559_signed_tx(&raw[1..])?;
            Ok(t.to_evm_tx())
        }
        _ => {
            let t = decode_legacy_signed_tx(raw)?;
            // chain_id supplied by caller in v6; keep as-is here
            Ok(t.to_evm_tx(extract_chain_id_from_v(t.v).unwrap_or(1)))
        }
    }
}

pub fn decode_eip1559_signed_tx(payload: &[u8]) -> Result<Eip1559SignedTx, String> {
    let rlp = Rlp::new(payload);
    if !rlp.is_list() { return Err("not list".into()); }

    let chain_id: u64 = rlp.val_at(0).map_err(|_| "chain_id")?;
    let nonce: u64 = rlp.val_at(1).map_err(|_| "nonce")?;
    let max_priority_fee_per_gas: u128 = rlp.val_at(2).map_err(|_| "tip")?;
    let max_fee_per_gas: u128 = rlp.val_at(3).map_err(|_| "max_fee")?;
    let gas_limit: u64 = rlp.val_at(4).map_err(|_| "gas")?;
    let to_bytes: Vec<u8> = rlp.val_at(5).map_err(|_| "to")?;
    let to = if to_bytes.is_empty() { None } else {
        if to_bytes.len()!=20 { return Err("to len".into()); }
        let mut a=[0u8;20]; a.copy_from_slice(&to_bytes); Some(a)
    };
    let value: u128 = rlp.val_at(6).map_err(|_| "value")?;
    let data: Vec<u8> = rlp.val_at(7).map_err(|_| "data")?;

    // access list
    let mut access_list: Vec<([u8;20], Vec<[u8;32]>)> = vec![];
    let al = rlp.at(8).map_err(|_| "access_list")?;
    if al.is_list() {
        for i in 0..al.item_count().unwrap_or(0) {
            let item = al.at(i).map_err(|_| "al item")?;
            let addr: Vec<u8> = item.val_at(0).map_err(|_| "al addr")?;
            if addr.len()!=20 { return Err("al addr len".into()); }
            let mut a=[0u8;20]; a.copy_from_slice(&addr);
            let keys_rlp = item.at(1).map_err(|_| "al keys")?;
            let mut keys: Vec<[u8;32]> = vec![];
            for j in 0..keys_rlp.item_count().unwrap_or(0) {
                let k: Vec<u8> = keys_rlp.val_at(j).map_err(|_| "key")?;
                if k.len()>32 { return Err("key len".into()); }
                let mut hh=[0u8;32];
                hh[32-k.len()..].copy_from_slice(&k);
                keys.push(hh);
            }
            access_list.push((a, keys));
        }
    }

    let y_parity: u8 = rlp.val_at(9).map_err(|_| "y")?;
    let r_vec: Vec<u8> = rlp.val_at(10).map_err(|_| "r")?;
    let s_vec: Vec<u8> = rlp.val_at(11).map_err(|_| "s")?;
    let mut r=[0u8;32]; let mut s=[0u8;32];
    if r_vec.len()>32 || s_vec.len()>32 { return Err("sig len".into()); }
    r[32-r_vec.len()..].copy_from_slice(&r_vec);
    s[32-s_vec.len()..].copy_from_slice(&s_vec);

    // signing hash: keccak256(0x02 || rlp([chainId,nonce,tip,maxFee,gas,to,value,data,accessList]))
    let mut stream = rlp::RlpStream::new_list(9);
    stream.append(&chain_id);
    stream.append(&nonce);
    stream.append(&max_priority_fee_per_gas);
    stream.append(&max_fee_per_gas);
    stream.append(&gas_limit);
    match &to {
        Some(a) => stream.append(&a.as_slice()),
        None => stream.append(&""),
    }
    stream.append(&value);
    stream.append(&data);
    // access list encode minimal
    stream.begin_list(access_list.len());
    for (a, keys) in access_list.iter() {
        stream.begin_list(2);
        stream.append(&a.as_slice());
        stream.begin_list(keys.len());
        for k in keys.iter() { stream.append(&k.as_slice()); }
    }
    let inner = stream.out().to_vec();
    let mut preimage = vec![0x02];
    preimage.extend_from_slice(&inner);
    let sighash = keccak256(&preimage);

    let from = recover_sender_typed(&sighash, y_parity, r, s)?;

    Ok(Eip1559SignedTx {
        chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit,
        to, value, data, access_list, y_parity, r, s, from
    })
}

fn recover_sender_typed(msg_hash: &[u8;32], y_parity: u8, r: [u8;32], s: [u8;32]) -> Result<[u8;20], String> {
    let recid = (y_parity & 1) as u8;
    let sig = Signature::from_scalars(r, s).map_err(|_| "sig")?;
    let rec_id = recoverable::Id::new(recid).map_err(|_| "recid")?;
    let rec_sig = recoverable::Signature::new(&sig, rec_id).map_err(|_| "recsig")?;
    let vk = rec_sig.recover_verifying_key_from_digest_bytes((*msg_hash).into()).map_err(|_| "recover")?;
    let pubkey = vk.to_encoded_point(false);
    let pub_bytes = pubkey.as_bytes();
    let hash = keccak256(&pub_bytes[1..]);
    let mut out=[0u8;20];
    out.copy_from_slice(&hash[12..]);
    Ok(out)
}


// -------- EIP-2930 typed tx (0x01) decoding (scaffold) --------

#[derive(Debug, Clone)]
pub struct Eip2930SignedTx {
    pub chain_id: u64,
    pub nonce: u64,
    pub gas_price: u128,
    pub gas_limit: u64,
    pub to: Option<[u8; 20]>,
    pub value: u128,
    pub data: Vec<u8>,
    pub access_list: Vec<( [u8;20], Vec<[u8;32]> )>,
    pub y_parity: u8,
    pub r: [u8;32],
    pub s: [u8;32],
    pub from: [u8;20],
}

impl Eip2930SignedTx {
    pub fn to_evm_tx(&self) -> crate::types::tx_evm::EvmTx {
        crate::types::tx_evm::EvmTx::Eip2930 {
            from: self.from,
            to: self.to,
            nonce: self.nonce,
            gas_limit: self.gas_limit,
            gas_price: self.gas_price,
            value: self.value,
            data: self.data.clone(),
            access_list: self.access_list.iter().map(|(a, keys)| crate::types::tx_evm::AccessListItem{
                address: *a,
                storage_keys: keys.iter().copied().collect(),
            }).collect(),
            chain_id: self.chain_id,
        }
    }
}

pub fn decode_eip2930_signed_tx(payload: &[u8]) -> Result<Eip2930SignedTx, String> {
    let rlp = Rlp::new(payload);
    if !rlp.is_list() { return Err("not list".into()); }

    let chain_id: u64 = rlp.val_at(0).map_err(|_| "chain_id")?;
    let nonce: u64 = rlp.val_at(1).map_err(|_| "nonce")?;
    let gas_price: u128 = rlp.val_at(2).map_err(|_| "gas_price")?;
    let gas_limit: u64 = rlp.val_at(3).map_err(|_| "gas")?;
    let to_bytes: Vec<u8> = rlp.val_at(4).map_err(|_| "to")?;
    let to = if to_bytes.is_empty() { None } else {
        if to_bytes.len()!=20 { return Err("to len".into()); }
        let mut a=[0u8;20]; a.copy_from_slice(&to_bytes); Some(a)
    };
    let value: u128 = rlp.val_at(5).map_err(|_| "value")?;
    let data: Vec<u8> = rlp.val_at(6).map_err(|_| "data")?;

    // access list
    let mut access_list: Vec<([u8;20], Vec<[u8;32]>)> = vec![];
    let al = rlp.at(7).map_err(|_| "access_list")?;
    if al.is_list() {
        for i in 0..al.item_count().unwrap_or(0) {
            let item = al.at(i).map_err(|_| "al item")?;
            let addr: Vec<u8> = item.val_at(0).map_err(|_| "al addr")?;
            if addr.len()!=20 { return Err("al addr len".into()); }
            let mut a=[0u8;20]; a.copy_from_slice(&addr);
            let keys_rlp = item.at(1).map_err(|_| "al keys")?;
            let mut keys: Vec<[u8;32]> = vec![];
            for j in 0..keys_rlp.item_count().unwrap_or(0) {
                let k: Vec<u8> = keys_rlp.val_at(j).map_err(|_| "key")?;
                if k.len()>32 { return Err("key len".into()); }
                let mut hh=[0u8;32];
                hh[32-k.len()..].copy_from_slice(&k);
                keys.push(hh);
            }
            access_list.push((a, keys));
        }
    }

    let y_parity: u8 = rlp.val_at(8).map_err(|_| "y")?;
    let r_vec: Vec<u8> = rlp.val_at(9).map_err(|_| "r")?;
    let s_vec: Vec<u8> = rlp.val_at(10).map_err(|_| "s")?;
    let mut r=[0u8;32]; let mut s=[0u8;32];
    if r_vec.len()>32 || s_vec.len()>32 { return Err("sig len".into()); }
    r[32-r_vec.len()..].copy_from_slice(&r_vec);
    s[32-s_vec.len()..].copy_from_slice(&s_vec);

    // signing hash: keccak256(0x01 || rlp([chainId,nonce,gasPrice,gas,to,value,data,accessList]))
    let mut stream = rlp::RlpStream::new_list(8);
    stream.append(&chain_id);
    stream.append(&nonce);
    stream.append(&gas_price);
    stream.append(&gas_limit);
    match &to {
        Some(a) => stream.append(&a.as_slice()),
        None => stream.append(&""),
    }
    stream.append(&value);
    stream.append(&data);
    stream.begin_list(access_list.len());
    for (a, keys) in access_list.iter() {
        stream.begin_list(2);
        stream.append(&a.as_slice());
        stream.begin_list(keys.len());
        for k in keys.iter() { stream.append(&k.as_slice()); }
    }
    let inner = stream.out().to_vec();
    let mut preimage = vec![0x01];
    preimage.extend_from_slice(&inner);
    let sighash = keccak256(&preimage);

    let from = recover_sender_typed(&sighash, y_parity, r, s)?;

    Ok(Eip2930SignedTx{ chain_id, nonce, gas_price, gas_limit, to, value, data, access_list, y_parity, r, s, from })
}
