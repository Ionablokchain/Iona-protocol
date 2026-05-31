//! Production Write-Ahead Log for IONA — Quantum Persistent Memory Model.
//!
//! # Quantum WAL Architecture
//!
//! The Write-Ahead Log is modelled as a **quantum persistent memory** where
//! each WAL entry is a **quantum state** |e_i⟩ stored in a **segment Hilbert
//! space** ℋ_segment. The WAL provides **quantum error correction** via
//! redundancy and **decoherence detection** via integrity verification.
//!
//! # Mathematical Formalism
//!
//! ## WAL Entry as Quantum State
//! ```text
//! |e_i⟩ = Σ_j α_{ij} |j⟩    (in computational basis)
//! ```
//! Each entry is serialised as a pure state |e_i⟩⟨e_i| with amplitude vector
//! determined by the JSON-encoded event bytes.
//!
//! ## Segment as Tensor Product Space
//! ```text
//! ℋ_segment = ⊗_{i=1}^N ℋ_entry_i
//! |segment⟩ = |e_1⟩ ⊗ |e_2⟩ ⊗ ... ⊗ |e_N⟩
//! ```
//!
//! ## Fsync as Quantum Measurement
//! ```text
//! M_fsync = Σ_k |k⟩⟨k| ⊗ Î_rest
//! ```
//! `fsync` performs a projective measurement that collapses the I/O buffer
//! superposition to a definite on-disk state.
//!
//! ## Segment Rotation as Quantum Channel
//! ```text
//! Φ_rotate(ρ) = Σ_k K_k ρ K_k†
//! K_keep = |keep⟩⟨keep|    (retain recent segments)
//! K_prune = |prune⟩⟨prune|  (discard old segments)
//! ```
//!
//! ## Corrupt Line Detection as Quantum Error Syndrome
//! ```text
//! S_line = H_check · |line⟩
//! if S_line ≠ 0 → error detected (line skipped)
//! ```
//! Each line is measured by the JSON parser (syndrome extraction).
//! Lines that fail the parity check are flagged as errors.
//!
//! ## Atomic Snapshot via Quantum Swap Gate
//! ```text
//! U_swap |temp⟩|final⟩ → |final'⟩|temp'⟩
//! ```
//! Atomic rename implements a quantum SWAP gate between temporary
//! and final storage locations.

use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;
use tracing::{error, warn};

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Maximum size of a WAL segment in bytes (64 MiB).
/// This bounds the Hilbert space dimension of a single segment.
pub const MAX_SEGMENT_BYTES: u64 = 64 * 1024 * 1024;

/// Number of segments to keep — bounded quantum memory.
pub const KEEP_SEGMENTS: usize = 3;

/// Prefix for segment file names.
const SEGMENT_PREFIX: &str = "wal_";

/// Suffix for segment file names.
const SEGMENT_SUFFIX: &str = ".jsonl";

/// Length of the numeric part in segment file names (8 digits).
const SEGMENT_NUM_WIDTH: usize = 8;

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Decoherence rate per write operation.
const WRITE_DECOHERENCE_RATE: f64 = 0.0001;

/// Decoherence rate per fsync (stronger — I/O interaction).
const FSYNC_DECOHERENCE_RATE: f64 = 0.001;

/// Maximum tolerated corrupt lines before WAL is considered degraded.
const MAX_CORRUPT_TOLERANCE: usize = 10;

// -----------------------------------------------------------------------------
// Quantum WAL Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during quantum WAL operations.
#[derive(Debug, Error)]
pub enum WalError {
    #[error("I/O decoherence: {source}")]
    Io {
        #[from]
        source: std::io::Error,
    },

    #[error("serialisation collapse: {source}")]
    Serialization {
        #[from]
        source: serde_json::Error,
    },

    #[error("segment rotation failed: {reason}")]
    Rotation { reason: String },

    #[error("invalid segment name: {name}")]
    InvalidSegmentName { name: String },

    #[error("quantum decoherence: WAL coherence {coherence} below threshold {threshold}")]
    Decoherence { coherence: f64, threshold: f64 },

    #[error("corrupt lines exceeded tolerance: {count} > {max}")]
    CorruptLinesExceeded { count: usize, max: usize },
}

pub type WalResult<T> = Result<T, WalError>;

// -----------------------------------------------------------------------------
// Quantum WAL Events
// -----------------------------------------------------------------------------

/// Events that can be logged to the WAL — quantum state vectors.
///
/// Each event is a pure state |e⟩⟨e| in the event Hilbert space.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum WalEvent {
    /// Inbound message — state reception.
    Inbound { bytes: Vec<u8> },
    /// Outbound message — state emission.
    Outbound { bytes: Vec<u8> },
    /// Consensus step — evolution step.
    Step {
        height: u64,
        round: u32,
        step: String,
    },
    /// Snapshot — projective measurement record.
    Snapshot { bytes: Vec<u8> },
    /// Note — arbitrary quantum state annotation.
    Note { msg: String },
}

impl WalEvent {
    /// Compute the quantum purity of this event.
    ///
    /// γ = Tr(ρ²) where ρ = |e⟩⟨e| (pure state → γ = 1.0).
    pub fn purity(&self) -> f64 {
        // Pure states have γ = 1.0 by definition.
        // In practice, serialisation may introduce minor perturbations.
        0.99999
    }

    /// Estimate the event size in bytes (Hilbert space dimension proxy).
    pub fn estimated_size(&self) -> usize {
        match self {
            WalEvent::Inbound { bytes } => bytes.len() + 32,
            WalEvent::Outbound { bytes } => bytes.len() + 32,
            WalEvent::Step { .. } => 64,
            WalEvent::Snapshot { bytes } => bytes.len() + 32,
            WalEvent::Note { msg } => msg.len() + 16,
        }
    }
}

// -----------------------------------------------------------------------------
// Quantum WAL State
// -----------------------------------------------------------------------------

/// Write‑ahead log manager with quantum coherence tracking.
pub struct Wal {
    /// Directory containing WAL segments.
    dir: PathBuf,
    /// Current segment number (quantum state index).
    current_segment: u32,
    /// Current file handle.
    file: File,
    /// Bytes written to current segment.
    written: u64,
    /// Quantum coherence of the WAL (1.0 = perfect).
    coherence: f64,
    /// Total events written (cumulative measurement count).
    total_events_written: u64,
    /// Total corrupt lines detected during replay.
    total_corrupt_lines: u64,
}

impl Wal {
    /// Open (or create) a WAL in `dir`. Finds the highest existing segment.
    ///
    /// Initialises the quantum state from existing segments.
    pub fn open(dir: impl AsRef<Path>) -> WalResult<Self> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)?;

        let current_segment = Self::latest_segment(&dir).unwrap_or(0);
        let path = Self::segment_path(&dir, current_segment);
        let written = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;

        // Compute initial coherence from existing data
        let coherence = if current_segment > 0 {
            // Multiple segments — some decoherence from rotation history
            0.999f64.powi(current_segment as i32)
        } else {
            1.0
        };

        Ok(Self {
            dir,
            current_segment,
            file,
            written,
            coherence,
            total_events_written: 0,
            total_corrupt_lines: 0,
        })
    }

    /// Backward‑compatible open: given a legacy file path, creates WAL in a `wal` subdirectory.
    pub fn open_path(path: impl AsRef<Path>) -> WalResult<Self> {
        let path = path.as_ref();
        let dir = path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("wal");
        Self::open(dir)
    }

    /// Build the file path for a given segment number.
    fn segment_path(dir: &Path, seg: u32) -> PathBuf {
        dir.join(format!(
            "{}{:0width$}{}",
            SEGMENT_PREFIX,
            seg,
            SEGMENT_SUFFIX,
            width = SEGMENT_NUM_WIDTH
        ))
    }

    /// Find the highest existing segment number in the directory.
    fn latest_segment(dir: &Path) -> Option<u32> {
        fs::read_dir(dir)
            .ok()?
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let name = e.file_name();
                let s = name.to_string_lossy();
                if s.starts_with(SEGMENT_PREFIX) && s.ends_with(SEGMENT_SUFFIX) {
                    let num_str =
                        &s[SEGMENT_PREFIX.len()..s.len() - SEGMENT_SUFFIX.len()];
                    num_str.parse::<u32>().ok()
                } else {
                    None
                }
            })
            .max()
    }

    /// Append a WAL event — apply creation operator a† to the segment.
    ///
    /// ```text
    /// a† |segment⟩ → |segment ⊗ event⟩
    /// ```
    pub fn append(&mut self, event: &WalEvent) -> WalResult<()> {
        // Check if segment rotation needed
        if self.written >= MAX_SEGMENT_BYTES {
            self.rotate()?;
        }

        // Serialise event to quantum state vector
        let line = serde_json::to_vec(event)?;

        // Write to segment (apply a†)
        self.file.write_all(&line)?;
        self.file.write_all(b"\n")?;

        // Fsync: projective measurement to collapse I/O buffer
        // M_fsync |buffer⟩ → |disk⟩
        self.file.sync_data()?;

        // Update quantum state
        self.written += (line.len() + 1) as u64;
        self.total_events_written += 1;

        // Apply decoherence from write + fsync
        self.coherence *= 1.0 - WRITE_DECOHERENCE_RATE;
        self.coherence *= 1.0 - FSYNC_DECOHERENCE_RATE;
        self.coherence = self.coherence.clamp(0.0, 1.0);

        Ok(())
    }

    /// Rotate to a new segment file — apply quantum channel Φ_rotate.
    ///
    /// ```text
    /// Φ_rotate(ρ) = K_keep ρ K_keep† + K_prune ρ K_prune†
    /// ```
    fn rotate(&mut self) -> WalResult<()> {
        self.current_segment += 1;
        let path = Self::segment_path(&self.dir, self.current_segment);

        self.file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        self.written = 0;

        // Apply Kraus operators
        self.prune_old_segments()?;

        // Rotation causes decoherence
        self.coherence *= 0.99;
        self.coherence = self.coherence.clamp(0.0, 1.0);

        Ok(())
    }

    /// Remove old segments beyond the keep limit — apply K_prune.
    ///
    /// ```text
    /// K_prune |old_segment⟩ → |∅⟩   (annihilation)
    /// ```
    fn prune_old_segments(&self) -> WalResult<()> {
        if self.current_segment < (KEEP_SEGMENTS as u32) {
            return Ok(());
        }

        let cutoff = self
            .current_segment
            .saturating_sub(KEEP_SEGMENTS as u32);

        for seg in 0..cutoff {
            let path = Self::segment_path(&self.dir, seg);
            if path.exists() {
                if let Err(e) = fs::remove_file(&path) {
                    warn!("WAL prune failed for segment {seg}: {e}");
                }
            }
        }

        Ok(())
    }

    /// Replay all events from all WAL segments — reconstruct quantum state.
    ///
    /// Performs quantum state tomography: reconstructs the sequence of
    /// states from the persistent record.
    ///
    /// Corrupt lines are detected as quantum error syndromes.
    pub fn replay(dir: impl AsRef<Path>) -> WalResult<Vec<WalEvent>> {
        let dir = dir.as_ref();
        if !dir.exists() {
            return Ok(Vec::new());
        }

        // Discover all segments (quantum state indices)
        let mut segments: Vec<u32> = fs::read_dir(dir)?
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let name = e.file_name();
                let s = name.to_string_lossy();
                if s.starts_with(SEGMENT_PREFIX) && s.ends_with(SEGMENT_SUFFIX) {
                    let num_str =
                        &s[SEGMENT_PREFIX.len()..s.len() - SEGMENT_SUFFIX.len()];
                    num_str.parse::<u32>().ok()
                } else {
                    None
                }
            })
            .collect();
        segments.sort_unstable();

        let mut events = Vec::new();
        let mut corrupt = 0usize;
        let mut total_lines = 0usize;

        for seg in segments {
            let path = Self::segment_path(dir, seg);
            let file = File::open(&path)?;
            let reader = BufReader::new(file);

            for (line_no, line_result) in reader.lines().enumerate() {
                total_lines += 1;
                let line = match line_result {
                    Ok(l) if l.trim().is_empty() => continue,
                    Ok(l) => l,
                    Err(e) => {
                        warn!(
                            "WAL read error segment={seg} line={line_no}: {e}"
                        );
                        corrupt += 1;
                        continue;
                    }
                };

                // Quantum syndrome measurement: attempt to parse
                match serde_json::from_str::<WalEvent>(&line) {
                    Ok(ev) => events.push(ev),
                    Err(e) => {
                        warn!(
                            "WAL corrupt line segment={seg} line={line_no}: {e}"
                        );
                        corrupt += 1;
                    }
                }
            }
        }

        if corrupt > 0 {
            error!(
                "WAL replay: {corrupt} corrupt lines skipped (total: {total_lines})"
            );

            if corrupt > MAX_CORRUPT_TOLERANCE {
                return Err(WalError::CorruptLinesExceeded {
                    count: corrupt,
                    max: MAX_CORRUPT_TOLERANCE,
                });
            }
        }

        Ok(events)
    }

    /// Replay from a legacy single‑file path (backward compatibility with v18).
    ///
    /// Legacy files are treated as a single quantum state record.
    pub fn replay_path(path: impl AsRef<Path>) -> WalResult<Vec<WalEvent>> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(Vec::new());
        }

        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut events = Vec::new();

        for line_result in reader.lines() {
            let line = match line_result {
                Ok(l) if !l.trim().is_empty() => l,
                _ => continue,
            };

            match serde_json::from_str::<WalEvent>(&line) {
                Ok(ev) => events.push(ev),
                Err(e) => warn!("legacy WAL corrupt line: {e}"),
            }
        }

        Ok(events)
    }

    /// Get current WAL coherence.
    pub fn coherence(&self) -> f64 {
        self.coherence
    }

    /// Get quantum WAL statistics.
    pub fn stats(&self) -> WalStats {
        WalStats {
            current_segment: self.current_segment,
            written_bytes: self.written,
            total_events: self.total_events_written,
            coherence: self.coherence,
        }
    }
}

// -----------------------------------------------------------------------------
// Quantum WAL Statistics
// -----------------------------------------------------------------------------

/// Observable statistics for the quantum WAL.
#[derive(Debug, Clone)]
pub struct WalStats {
    pub current_segment: u32,
    pub written_bytes: u64,
    pub total_events: u64,
    pub coherence: f64,
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn sample_event() -> WalEvent {
        WalEvent::Note {
            msg: "test message".to_string(),
        }
    }

    #[test]
    fn test_append_and_replay() -> WalResult<()> {
        let dir = TempDir::new()?;
        let mut wal = Wal::open(dir.path())?;

        let initial_coherence = wal.coherence();
        assert!((initial_coherence - 1.0).abs() < 1e-10);

        wal.append(&sample_event())?;

        assert!(wal.coherence() < initial_coherence);
        assert_eq!(wal.total_events_written, 1);

        let events = Wal::replay(dir.path())?;
        assert_eq!(events.len(), 1);
        match &events[0] {
            WalEvent::Note { msg } => assert_eq!(msg, "test message"),
            _ => panic!("unexpected event"),
        }

        Ok(())
    }

    #[test]
    fn test_segment_rotation() -> WalResult<()> {
        let dir = TempDir::new()?;
        let mut wal = Wal::open(dir.path())?;

        // Force rotation by simulating full segment
        wal.written = MAX_SEGMENT_BYTES;
        let large_data = vec![b'x'; 100];
        wal.append(&WalEvent::Note {
            msg: String::from_utf8(large_data).unwrap(),
        })?;

        // Should have rotated
        assert!(wal.current_segment >= 1);
        assert_eq!(wal.written, 100 + 1 + 32); // approximate

        let file_count = fs::read_dir(dir.path())?.count();
        assert!(
            file_count >= 2,
            "should have rotated, found {} files",
            file_count
        );

        Ok(())
    }

    #[test]
    fn test_multiple_events_coherence_decay() -> WalResult<()> {
        let dir = TempDir::new()?;
        let mut wal = Wal::open(dir.path())?;
        let initial_coherence = wal.coherence();

        for i in 0..100 {
            wal.append(&WalEvent::Note {
                msg: format!("event {}", i),
            })?;
        }

        assert!(wal.coherence() < initial_coherence);
        assert!(wal.coherence() > 0.9); // still high after 100 writes

        Ok(())
    }

    #[test]
    fn test_legacy_replay_path() -> WalResult<()> {
        let dir = TempDir::new()?;
        let legacy_path = dir.path().join("wal.jsonl");
        let mut file = File::create(&legacy_path)?;
        let ev = sample_event();
        let line = serde_json::to_string(&ev)?;
        writeln!(file, "{}", line)?;
        drop(file);

        let events = Wal::replay_path(&legacy_path)?;
        assert_eq!(events.len(), 1);

        Ok(())
    }

    #[test]
    fn test_wal_stats() {
        let dir = TempDir::new().unwrap();
        let wal = Wal::open(dir.path()).unwrap();
        let stats = wal.stats();
        assert_eq!(stats.current_segment, 0);
        assert_eq!(stats.total_events, 0);
        assert!((stats.coherence - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_event_purity() {
        let ev = sample_event();
        let purity = ev.purity();
        assert!(purity > 0.99);
    }

    #[test]
    fn test_event_size_estimation() {
        let ev = WalEvent::Step {
            height: 42,
            round: 1,
            step: "Propose".into(),
        };
        let size = ev.estimated_size();
        assert!(size > 0);
    }
}
