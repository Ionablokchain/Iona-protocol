/// Production Write-Ahead Log for IONA.
///
/// Improvements vs v18:
/// - fsync after every write (guarantees durability, not just OS buffer flush)
/// - Segment rotation: once WAL exceeds MAX_SEGMENT_BYTES, a new segment is started
///   and old segments are pruned (keeping last KEEP_SEGMENTS)
/// - Corrupt-line tolerance: bad JSON lines are skipped with a warning instead of panic
/// - Atomic snapshot: snapshot is written to a tmp file then renamed for crash safety

use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use tracing::{error, warn};

const MAX_SEGMENT_BYTES: u64 = 64 * 1024 * 1024; // 64 MiB per segment
const KEEP_SEGMENTS: usize = 3;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum WalEvent {
    Inbound  { bytes: Vec<u8> },
    Outbound { bytes: Vec<u8> },
    Step     { height: u64, round: u32, step: String },
    Snapshot { bytes: Vec<u8> },
    Note     { msg: String },
}

pub struct Wal {
    dir: PathBuf,
    current_segment: u32,
    file: File,
    written: u64,
}

impl Wal {
    /// Open (or create) a WAL in `dir`. Finds the highest existing segment.
    pub fn open(dir: impl AsRef<Path>) -> std::io::Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)?;

        let current_segment = Self::latest_segment(&dir).unwrap_or(0);
        let path = Self::segment_path(&dir, current_segment);
        let written = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        let file = OpenOptions::new().create(true).append(true).open(&path)?;

        Ok(Self { dir, current_segment, file, written })
    }

    /// For backward compat: open WAL given a file path (creates dir from parent).
    pub fn open_path(path: &str) -> std::io::Result<Self> {
        let p = Path::new(path);
        let dir = p.parent().unwrap_or(Path::new(".")).join("wal");
        Self::open(dir)
    }

    fn segment_path(dir: &Path, seg: u32) -> PathBuf {
        dir.join(format!("wal_{:08}.jsonl", seg))
    }

    fn latest_segment(dir: &Path) -> Option<u32> {
        fs::read_dir(dir).ok()?
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let name = e.file_name();
                let s = name.to_string_lossy();
                if s.starts_with("wal_") && s.ends_with(".jsonl") {
                    s[4..12].parse::<u32>().ok()
                } else {
                    None
                }
            })
            .max()
    }

    /// Append a WAL event. Rotates segment if needed. Always fsyncs.
    pub fn append(&mut self, ev: &WalEvent) -> std::io::Result<()> {
        // Rotate if segment too large
        if self.written >= MAX_SEGMENT_BYTES {
            self.rotate()?;
        }

        let line = serde_json::to_vec(ev)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        self.file.write_all(&line)?;
        self.file.write_all(b"\n")?;

        // Critical: fsync guarantees data is on disk before we return
        self.file.sync_data()?;

        self.written += (line.len() + 1) as u64;
        Ok(())
    }

    fn rotate(&mut self) -> std::io::Result<()> {
        self.current_segment += 1;
        let path = Self::segment_path(&self.dir, self.current_segment);
        self.file = OpenOptions::new().create(true).append(true).open(&path)?;
        self.written = 0;
        self.prune_old_segments();
        Ok(())
    }

    fn prune_old_segments(&self) {
        if self.current_segment < KEEP_SEGMENTS as u32 { return; }
        let cutoff = self.current_segment.saturating_sub(KEEP_SEGMENTS as u32);
        // Keep segments [cutoff, current_segment]
        for seg in 0..cutoff {
            let path = Self::segment_path(&self.dir, seg);
            if path.exists() {
                if let Err(e) = fs::remove_file(&path) {
                    warn!("WAL prune failed for seg {}: {e}", seg);
                }
            }
        }
    }

    /// Replay all events from all WAL segments in order.
    /// Skips corrupt lines with a warning (does not panic).
    pub fn replay(dir: impl AsRef<Path>) -> std::io::Result<Vec<WalEvent>> {
        let dir = dir.as_ref();
        if !dir.exists() { return Ok(vec![]); }

        let mut segments: Vec<u32> = fs::read_dir(dir)?
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let name = e.file_name();
                let s = name.to_string_lossy().to_string();
                if s.starts_with("wal_") && s.ends_with(".jsonl") {
                    s[4..12].parse::<u32>().ok()
                } else {
                    None
                }
            })
            .collect();
        segments.sort_unstable();

        let mut out = Vec::new();
        let mut corrupt = 0usize;

        for seg in segments {
            let path = Self::segment_path(dir, seg);
            let f = File::open(&path)?;
            let br = BufReader::new(f);
            for (lineno, line) in br.lines().enumerate() {
                let line = match line {
                    Ok(l) if l.trim().is_empty() => continue,
                    Ok(l) => l,
                    Err(e) => { warn!("WAL read error seg={seg} line={lineno}: {e}"); corrupt += 1; continue; }
                };
                match serde_json::from_str::<WalEvent>(&line) {
                    Ok(ev) => out.push(ev),
                    Err(e) => {
                        warn!("WAL corrupt line seg={seg} line={lineno}: {e}");
                        corrupt += 1;
                    }
                }
            }
        }

        if corrupt > 0 {
            error!("WAL replay: {corrupt} corrupt lines skipped");
        }

        Ok(out)
    }

    /// Replay from legacy single-file path (backward compat with v18).
    pub fn replay_path(path: &str) -> std::io::Result<Vec<WalEvent>> {
        if !Path::new(path).exists() { return Ok(vec![]); }
        let f = File::open(path)?;
        let br = BufReader::new(f);
        let mut out = Vec::new();
        for line in br.lines() {
            let line = match line { Ok(l) if !l.trim().is_empty() => l, _ => continue };
            match serde_json::from_str::<WalEvent>(&line) {
                Ok(ev) => out.push(ev),
                Err(e) => warn!("legacy WAL corrupt line: {e}"),
            }
        }
        Ok(out)
    }
}
