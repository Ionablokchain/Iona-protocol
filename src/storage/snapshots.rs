use crate::execution::KvState;
use crate::crypto::Verifier;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use std::{fs, io, path::Path};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotManifest {
    pub height: u64,
    pub created_unix_s: u64,
    pub state_root_hex: String,
    pub format: String,
    pub zstd_level: i32,
}

pub fn snapshots_dir(data_dir: &str) -> String {
    format!("{}/snapshots", data_dir)
}

pub fn snapshot_path(data_dir: &str, height: u64) -> String {
    format!("{}/snapshots/state_{:020}.json.zst", data_dir, height)
}

pub fn manifest_path(data_dir: &str, height: u64) -> String {
    format!("{}/snapshots/state_{:020}.manifest.json", data_dir, height)
}

pub fn read_snapshot_manifest(data_dir: &str, height: u64) -> io::Result<SnapshotManifest> {
    let bytes = fs::read(manifest_path(data_dir, height))?;
    let m: SnapshotManifest = serde_json::from_slice(&bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("manifest json: {e}")))?;
    Ok(m)
}


pub fn write_snapshot(data_dir: &str, height: u64, state: &KvState, zstd_level: i32) -> io::Result<()> {
    fs::create_dir_all(snapshots_dir(data_dir))?;

    let json = serde_json::to_vec(state)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("snapshot encode: {e}")))?;

    let compressed = zstd::encode_all(&json[..], zstd_level)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("snapshot zstd: {e}")))?;

    fs::write(snapshot_path(data_dir, height), compressed)?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mani = SnapshotManifest {
        height,
        created_unix_s: now,
        state_root_hex: hex::encode(state.root().0),
        format: "KvState-json-zstd".into(),
        zstd_level,
    };

    let s = serde_json::to_string_pretty(&mani)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("manifest encode: {e}")))?;
    fs::write(manifest_path(data_dir, height), s)?;
    Ok(())
}

pub fn list_snapshot_heights(data_dir: &str) -> io::Result<Vec<u64>> {
    let dir = snapshots_dir(data_dir);
    if !Path::new(&dir).exists() {
        return Ok(vec![]);
    }
    let mut out = vec![];
    for ent in fs::read_dir(dir)? {
        let ent = ent?;
        let name = ent.file_name();
        let name = name.to_string_lossy();
        if let Some(h) = name.strip_prefix("state_").and_then(|s| s.split('.').next()) {
            if let Ok(v) = h.parse::<u64>() {
                out.push(v);
            }
        }
    }
    out.sort_unstable();
    Ok(out)
}

pub fn latest_snapshot_height(data_dir: &str) -> io::Result<Option<u64>> {
    Ok(list_snapshot_heights(data_dir)?.pop())
}


pub fn list_delta_edges(data_dir: &str) -> io::Result<Vec<(u64, u64)>> {
    let dir = snapshots_dir(data_dir);
    if !Path::new(&dir).exists() {
        return Ok(vec![]);
    }
    let mut out = vec![];
    for ent in fs::read_dir(dir)? {
        let ent = ent?;
        let name = ent.file_name();
        let name = name.to_string_lossy();
        if let Some(rest) = name.strip_prefix("delta_") {
            // delta_<from>_<to>.statesync.json OR .json.zst
            let parts: Vec<&str> = rest.split('_').collect();
            if parts.len() >= 2 {
                let from_s = parts[0];
                let to_s = parts[1].split('.').next().unwrap_or("");
                if let (Ok(fh), Ok(th)) = (from_s.parse::<u64>(), to_s.parse::<u64>()) {
                    out.push((fh, th));
                }
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}


pub fn prune_snapshots(data_dir: &str, keep: usize) -> io::Result<()> {
    let hs = list_snapshot_heights(data_dir)?;
    if hs.len() <= keep {
        return Ok(());
    }
    let to_remove = &hs[..hs.len().saturating_sub(keep)];
    for h in to_remove {
        let _ = fs::remove_file(snapshot_path(data_dir, *h));
        let _ = fs::remove_file(manifest_path(data_dir, *h));
    }
    Ok(())
}

pub fn restore_latest_if_missing(data_dir: &str, state_full_path: &str) -> io::Result<Option<u64>> {
    if Path::new(state_full_path).exists() {
        return Ok(None);
    }
    let Some(h) = latest_snapshot_height(data_dir)? else { return Ok(None); };

    let bytes = fs::read(snapshot_path(data_dir, h))?;
    let json = zstd::decode_all(&bytes[..])
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("snapshot decode: {e}")))?;

    // Validate JSON can parse; then persist as the canonical state_full.json
    let _state: KvState = serde_json::from_slice(&json)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("snapshot json: {e}")))?;

    fs::write(state_full_path, json)?;
    Ok(Some(h))
}

// --- Mega-step: state-sync manifest with per-chunk hashes (for incremental verification/resume) ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSyncManifest {
    pub height: u64,
    pub total_bytes: u64,
    pub blake3_hex: String,
    pub chunk_size: u32,
    pub chunk_hashes: Vec<String>,
    #[serde(default)]
    pub state_root_hex: Option<String>,
    #[serde(default)]
    pub attestation: Option<SnapshotAttestation>,
}

/// Snapshot attestation: threshold signatures from validators over canonical bytes.
///
/// Sign bytes: `b"iona:snapshot_attest:v1" || height(le) || state_root(32)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotAttestation {
    /// Hash of validator pubkeys used for verification (stable, sorted).
    pub validators_hash_hex: String,
    /// Minimum signature count required.
    pub threshold: u32,
    /// Validator signatures.
    pub signatures: Vec<AttestationSig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationSig {
    pub pubkey_hex: String,
    pub sig_base64: String,
}

/// Best-effort: attach an attestation if `attestation.json` exists next to the snapshot.
fn load_attestation_if_any(data_dir: &str, height: u64) -> Option<SnapshotAttestation> {
    let p = format!("{}/snapshots/state_{:020}.attestation.json", data_dir, height);
    std::fs::read_to_string(p)
        .ok()
        .and_then(|s| serde_json::from_str::<SnapshotAttestation>(&s).ok())
}

/// Verify a snapshot attestation against a provided validator allowlist.
/// If `attestation` is None, returns Ok(false).
pub fn verify_attestation(
    manifest: &StateSyncManifest,
    validator_pubkeys_hex: &[String],
) -> io::Result<bool> {
    let Some(att) = &manifest.attestation else { return Ok(false); };

    let Some(root_hex) = manifest.state_root_hex.clone() else { return Ok(false); };
    let msg = snapshot_attest_sign_bytes(manifest.height, &root_hex)?;

    let allow: std::collections::HashSet<String> = validator_pubkeys_hex.iter().map(|s| s.to_lowercase()).collect();

    let mut ok = 0u32;
    for s in &att.signatures {
        if !allow.contains(&s.pubkey_hex.to_lowercase()) {
            continue;
        }
        let pk_bytes = match hex::decode(&s.pubkey_hex) {
            Ok(v) => crate::crypto::PublicKeyBytes(v),
            Err(_) => continue,
        };
        let sig = match B64.decode(s.sig_base64.as_bytes()) {
            Ok(v) => crate::crypto::SignatureBytes(v),
            Err(_) => continue,
        };
        if crate::crypto::ed25519::Ed25519Verifier::verify(&pk_bytes, &msg, &sig).is_ok() {
            ok += 1;
        }
    }

    Ok(ok >= att.threshold)
}

pub fn statesync_manifest_path(data_dir: &str, height: u64) -> String {
    format!("{}/snapshots/state_{:020}.statesync.json", data_dir, height)
}

/// Load a cached state-sync manifest if present and consistent; otherwise build it.
///
/// Building reads the compressed snapshot file once and computes:
/// - blake3 over the whole file
/// - blake3 per chunk (chunk_size)
pub fn load_or_build_statesync_manifest(
    data_dir: &str,
    height: u64,
    chunk_size: u32,
) -> io::Result<StateSyncManifest> {
    let snap_path = snapshot_path(data_dir, height);
    let mani_path = statesync_manifest_path(data_dir, height);

    if Path::new(&mani_path).exists() {
        if let Ok(s) = fs::read_to_string(&mani_path) {
            if let Ok(m) = serde_json::from_str::<StateSyncManifest>(&s) {
                if m.height == height && m.chunk_size == chunk_size {
                    if let Ok(meta) = fs::metadata(&snap_path) {
                        if meta.len() == m.total_bytes {
                            // Cheap consistency check: if file hash matches, we trust chunk hashes.
                            if let Ok(bytes) = fs::read(&snap_path) {
                                let got = blake3::hash(&bytes);
                                let got_hex = hex::encode(got.as_bytes());
                                if got_hex == m.blake3_hex {
                                    return Ok(m);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Build manifest
    let bytes = fs::read(&snap_path)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(&bytes);
    let blake3_hex = hex::encode(hasher.finalize().as_bytes());

    let mut chunk_hashes = Vec::new();
    let cs = chunk_size as usize;
    let mut i = 0usize;
    while i < bytes.len() {
        let end = (i + cs).min(bytes.len());
        let ch = blake3::hash(&bytes[i..end]);
        chunk_hashes.push(hex::encode(ch.as_bytes()));
        i = end;
    }

    // Try to enrich with state root from the human-readable snapshot manifest.
    let state_root_hex = fs::read_to_string(manifest_path(data_dir, height))
        .ok()
        .and_then(|s| serde_json::from_str::<SnapshotManifest>(&s).ok())
        .map(|m| m.state_root_hex);

    let attestation = load_attestation_if_any(data_dir, height);

    let m = StateSyncManifest {
        height,
        total_bytes: bytes.len() as u64,
        blake3_hex,
        chunk_size,
        chunk_hashes,
        state_root_hex,
        attestation,
    };

    // Best effort cache write
    if let Ok(s) = serde_json::to_string_pretty(&m) {
        let _ = fs::write(&mani_path, s);
    }

    Ok(m)
}

// --- Delta snapshots (snapshot-to-snapshot diffs) ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateDelta {
    pub from_height: u64,
    pub to_height: u64,
    pub kv_put: Vec<(String, String)>,
    pub kv_del: Vec<String>,
    pub balances_put: Vec<(String, u64)>,
    pub balances_del: Vec<String>,
    pub nonces_put: Vec<(String, u64)>,
    pub nonces_del: Vec<String>,
    pub burned: u64,
    pub to_state_root_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaSyncManifest {
    pub from_height: u64,
    pub to_height: u64,
    pub total_bytes: u64,
    pub blake3_hex: String,
    pub chunk_size: u32,
    pub chunk_hashes: Vec<String>,
    pub to_state_root_hex: String,
}

pub fn delta_path(data_dir: &str, from_h: u64, to_h: u64) -> String {
    format!("{}/snapshots/delta_{:020}_{:020}.json.zst", data_dir, from_h, to_h)
}

pub fn delta_statesync_manifest_path(data_dir: &str, from_h: u64, to_h: u64) -> String {
    format!("{}/snapshots/delta_{:020}_{:020}.statesync.json", data_dir, from_h, to_h)
}

pub fn read_snapshot_state(data_dir: &str, height: u64) -> io::Result<KvState> {
    let bytes = fs::read(snapshot_path(data_dir, height))?;
    let json = zstd::decode_all(&bytes[..])
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("snapshot decode: {e}")))?;
    let st: KvState = serde_json::from_slice(&json)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("snapshot json: {e}")))?;
    Ok(st)
}

pub fn compute_delta(from_h: u64, to_h: u64, from: &KvState, to: &KvState) -> StateDelta {
    let mut kv_put = vec![];
    let mut kv_del = vec![];
    for (k, v) in &to.kv {
        if from.kv.get(k) != Some(v) {
            kv_put.push((k.clone(), v.clone()));
        }
    }
    for k in from.kv.keys() {
        if !to.kv.contains_key(k) {
            kv_del.push(k.clone());
        }
    }

    let mut balances_put = vec![];
    let mut balances_del = vec![];
    for (k, v) in &to.balances {
        if from.balances.get(k) != Some(v) {
            balances_put.push((k.clone(), *v));
        }
    }
    for k in from.balances.keys() {
        if !to.balances.contains_key(k) {
            balances_del.push(k.clone());
        }
    }

    let mut nonces_put = vec![];
    let mut nonces_del = vec![];
    for (k, v) in &to.nonces {
        if from.nonces.get(k) != Some(v) {
            nonces_put.push((k.clone(), *v));
        }
    }
    for k in from.nonces.keys() {
        if !to.nonces.contains_key(k) {
            nonces_del.push(k.clone());
        }
    }

    StateDelta {
        from_height: from_h,
        to_height: to_h,
        kv_put,
        kv_del,
        balances_put,
        balances_del,
        nonces_put,
        nonces_del,
        burned: to.burned,
        to_state_root_hex: hex::encode(to.root().0),
    }
}

pub fn apply_delta(base: &KvState, d: &StateDelta) -> KvState {
    let mut out = base.clone();
    for k in &d.kv_del {
        out.kv.remove(k);
    }
    for (k, v) in &d.kv_put {
        out.kv.insert(k.clone(), v.clone());
    }
    for k in &d.balances_del {
        out.balances.remove(k);
    }
    for (k, v) in &d.balances_put {
        out.balances.insert(k.clone(), *v);
    }
    for k in &d.nonces_del {
        out.nonces.remove(k);
    }
    for (k, v) in &d.nonces_put {
        out.nonces.insert(k.clone(), *v);
    }
    out.burned = d.burned;
    out
}

/// Write a delta file and a statesync manifest for it.
pub fn write_delta(data_dir: &str, from_h: u64, to_h: u64, from: &KvState, to: &KvState, zstd_level: i32, chunk_size: u32) -> io::Result<()> {
    fs::create_dir_all(snapshots_dir(data_dir))?;
    let d = compute_delta(from_h, to_h, from, to);
    let json = serde_json::to_vec(&d)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("delta encode: {e}")))?;
    let compressed = zstd::encode_all(&json[..], zstd_level)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("delta zstd: {e}")))?;
    let p = delta_path(data_dir, from_h, to_h);
    fs::write(&p, &compressed)?;

    // Build a statesync-like manifest for delta file.
    let mut h = blake3::Hasher::new();
    h.update(&compressed);
    let blake3_hex = hex::encode(h.finalize().as_bytes());
    let mut chunk_hashes = Vec::new();
    let cs = chunk_size as usize;
    let mut i = 0usize;
    while i < compressed.len() {
        let end = (i + cs).min(compressed.len());
        let ch = blake3::hash(&compressed[i..end]);
        chunk_hashes.push(hex::encode(ch.as_bytes()));
        i = end;
    }

    let m = DeltaSyncManifest {
        from_height: from_h,
        to_height: to_h,
        total_bytes: compressed.len() as u64,
        blake3_hex,
        chunk_size,
        chunk_hashes,
        to_state_root_hex: d.to_state_root_hex,
    };

    if let Ok(s) = serde_json::to_string_pretty(&m) {
        let _ = fs::write(delta_statesync_manifest_path(data_dir, from_h, to_h), s);
    }

    Ok(())
}


// --- Snapshot attestation persistence helpers ---

pub fn attestation_path(data_dir: &str, height: u64) -> String {
    format!("{}/snapshots/state_{:020}.attestation.json", data_dir, height)
}

pub fn write_attestation(data_dir: &str, height: u64, a: &SnapshotAttestation) -> io::Result<()> {
    fs::create_dir_all(snapshots_dir(data_dir))?;
    let s = serde_json::to_string_pretty(a)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("attestation encode: {e}")))?;
    fs::write(attestation_path(data_dir, height), s)?;
    Ok(())
}

pub fn read_attestation(data_dir: &str, height: u64) -> io::Result<Option<SnapshotAttestation>> {
    let p = attestation_path(data_dir, height);
    if !Path::new(&p).exists() {
        return Ok(None);
    }
    let bytes = fs::read(p)?;
    let a: SnapshotAttestation = serde_json::from_slice(&bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("attestation json: {e}")))?;
    Ok(Some(a))
}

/// Stable hash (hex) over sorted validator pubkeys (hex strings). Used to bind attestations to a validator set.
pub fn validators_hash_hex(pubkeys_hex: &[String]) -> String {
    let mut pks: Vec<String> = pubkeys_hex.iter().map(|s| s.to_lowercase()).collect();
    pks.sort();
    let bytes = bincode::serialize(&pks).unwrap_or_default();
    hex::encode(blake3::hash(&bytes).as_bytes())
}

/// Canonical bytes for snapshot attestation signing.
pub fn snapshot_attest_sign_bytes(height: u64, state_root_hex: &str) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(8 + 32 + 32);
    out.extend_from_slice(b"iona:snapshot_attest:v1");
    out.extend_from_slice(&height.to_le_bytes());
    let root = hex::decode(state_root_hex)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("state_root hex: {e}")))?;
    out.extend_from_slice(&root);
    Ok(out)
}



/// v2 attestation sign-bytes bind the attestation to:
/// - chain_id (prevents cross-chain replay)
/// - validator_set_hash (prevents cross-epoch replay)
/// - epoch_nonce (time/epoch binding; prevents old attestation reuse)
pub fn snapshot_attest_sign_bytes_v2(
    chain_id: u64,
    height: u64,
    state_root_hex: &str,
    validator_set_hash_hex: &str,
    epoch_nonce: u64,
) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(8 + 32 + 32 + 32);
    out.extend_from_slice(b"iona:snapshot_attest:v2");
    out.extend_from_slice(&chain_id.to_le_bytes());
    out.extend_from_slice(&height.to_le_bytes());
    let root = hex::decode(state_root_hex)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("state_root hex: {e}")))?;
    out.extend_from_slice(&root);
    let vsh = hex::decode(validator_set_hash_hex)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("vset_hash hex: {e}")))?;
    out.extend_from_slice(&vsh);
    out.extend_from_slice(&epoch_nonce.to_le_bytes());
    Ok(out)
}
