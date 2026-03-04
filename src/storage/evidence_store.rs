use crate::evidence::Evidence;
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::fs::OpenOptions;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub struct EvidenceStore {
    path: String,
    seen: BTreeSet<String>, // stable id
    // rate limiting: peer -> timestamps (sec)
    rl: HashMap<String, VecDeque<u64>>,
    // per-height cap
    per_height: HashMap<u64, u32>,
}

impl EvidenceStore {
    pub fn open(path: String) -> std::io::Result<Self> {
        if !std::path::Path::new(&path).exists() {
            let _ = OpenOptions::new().create(true).append(true).open(&path)?;
        }
        Ok(Self {
            path,
            seen: BTreeSet::new(),
            rl: HashMap::new(),
            per_height: HashMap::new(),
        })
    }

    pub fn allow(&mut self, peer: &str, height: u64) -> bool {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let q = self.rl.entry(peer.to_string()).or_default();
        while let Some(front) = q.front().cloned() {
            if now.saturating_sub(front) > 60 { q.pop_front(); } else { break; }
        }
        if q.len() >= 30 { // 30 evidence/min/peer
            return false;
        }
        let c = self.per_height.entry(height).or_insert(0);
        if *c >= 200 { // cap global evidence per height
            return false;
        }
        q.push_back(now);
        *c += 1;
        true
    }

    pub fn id(ev: &Evidence) -> String {
        // stable id via hash of json
        let bytes = serde_json::to_vec(ev).unwrap_or_default();
        blake3::hash(&bytes).to_hex().to_string()
    }

    pub fn insert(&mut self, ev: &Evidence) -> std::io::Result<bool> {
        let id = Self::id(ev);
        if self.seen.contains(&id) {
            return Ok(false);
        }
        self.seen.insert(id);
        let mut f = OpenOptions::new().create(true).append(true).open(&self.path)?;
        let line = serde_json::to_vec(ev).unwrap_or_default();
        f.write_all(&line)?;
        f.write_all(b"\n")?;
        f.flush()?;
        Ok(true)
    }
}
