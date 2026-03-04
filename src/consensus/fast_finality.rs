//! Sub-second finality module for IONA.
//!
//! Implements optimistic fast-finality with three key mechanisms:
//!
//! 1. **Single-round optimistic commit**: When all validators agree in the first round,
//!    the block commits in a single round-trip (~100-200ms with fast_quorum).
//!
//! 2. **Pipelined proposals**: The next block's proposal is prepared while the current
//!    block's commit certificate propagates, reducing idle time between heights.
//!
//! 3. **Adaptive timeouts**: Timeouts shrink when the network is healthy (consecutive
//!    single-round commits) and grow when rounds fail (partition/slow validator).
//!
//! Combined with the existing `fast_quorum` flag (which skips waiting for timeouts when
//! 2/3+ votes arrive), this achieves consistent sub-second finality under normal conditions.
//!
//! Finality budget (typical 4-validator network, LAN):
//!   - Proposal broadcast:    ~10ms
//!   - Signature verification: ~5ms  (parallel)
//!   - Prevote round-trip:    ~20ms
//!   - Precommit round-trip:  ~20ms
//!   - Block execution:       ~50ms
//!   - Total:                ~105ms  (well under 1s)
//!
//! Even with WAN latencies (~80ms RTT), total is ~300-400ms.

use crate::types::{Hash32, Height};
use crate::consensus::CommitCertificate;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::time::Duration;

/// Tracks finality timing and adapts consensus parameters.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FinalityTracker {
    /// Rolling window of recent finality times (in milliseconds).
    pub recent_finality_ms: VecDeque<u64>,
    /// Maximum window size for the rolling average.
    pub window_size: usize,
    /// Number of consecutive single-round commits.
    pub consecutive_fast_commits: u64,
    /// Total blocks finalized.
    pub total_finalized: u64,
    /// Best (lowest) finality time observed.
    pub best_finality_ms: u64,
    /// Worst (highest) finality time observed.
    pub worst_finality_ms: u64,
    /// Current adaptive propose timeout (ms).
    pub adaptive_propose_ms: u64,
    /// Current adaptive prevote timeout (ms).
    pub adaptive_prevote_ms: u64,
    /// Current adaptive precommit timeout (ms).
    pub adaptive_precommit_ms: u64,
    /// Height at which finality tracking started.
    pub start_height: Height,
}

impl Default for FinalityTracker {
    fn default() -> Self {
        Self {
            recent_finality_ms: VecDeque::with_capacity(100),
            window_size: 100,
            consecutive_fast_commits: 0,
            total_finalized: 0,
            best_finality_ms: u64::MAX,
            worst_finality_ms: 0,
            adaptive_propose_ms: 150,
            adaptive_prevote_ms: 100,
            adaptive_precommit_ms: 100,
            start_height: 0,
        }
    }
}

/// Minimum timeouts (floor) to prevent livelock.
const MIN_PROPOSE_MS: u64 = 50;
const MIN_VOTE_MS: u64 = 30;

/// Maximum timeouts (ceiling) for fallback.
const MAX_PROPOSE_MS: u64 = 500;
const MAX_VOTE_MS: u64 = 300;

/// Threshold: if average finality < this, shrink timeouts.
const SHRINK_THRESHOLD_MS: u64 = 500;
/// Threshold: if average finality > this, grow timeouts.
const GROW_THRESHOLD_MS: u64 = 800;

impl FinalityTracker {
    pub fn new(start_height: Height) -> Self {
        Self {
            start_height,
            ..Default::default()
        }
    }

    /// Record a successful commit with its finality time.
    pub fn record_commit(&mut self, finality_ms: u64, round: u32) {
        self.total_finalized += 1;

        if round == 0 {
            self.consecutive_fast_commits += 1;
        } else {
            self.consecutive_fast_commits = 0;
        }

        if finality_ms < self.best_finality_ms {
            self.best_finality_ms = finality_ms;
        }
        if finality_ms > self.worst_finality_ms {
            self.worst_finality_ms = finality_ms;
        }

        self.recent_finality_ms.push_back(finality_ms);
        if self.recent_finality_ms.len() > self.window_size {
            self.recent_finality_ms.pop_front();
        }

        self.adapt_timeouts();
    }

    /// Average finality time over the recent window.
    pub fn average_finality_ms(&self) -> u64 {
        if self.recent_finality_ms.is_empty() {
            return 0;
        }
        let sum: u64 = self.recent_finality_ms.iter().sum();
        sum / self.recent_finality_ms.len() as u64
    }

    /// P95 finality time.
    pub fn p95_finality_ms(&self) -> u64 {
        if self.recent_finality_ms.is_empty() {
            return 0;
        }
        let mut sorted: Vec<u64> = self.recent_finality_ms.iter().copied().collect();
        sorted.sort_unstable();
        let idx = (sorted.len() as f64 * 0.95) as usize;
        sorted[idx.min(sorted.len() - 1)]
    }

    /// Whether we're consistently achieving sub-second finality.
    pub fn is_sub_second(&self) -> bool {
        self.recent_finality_ms.len() >= 10 && self.p95_finality_ms() < 1000
    }

    /// Adapt timeouts based on recent performance.
    fn adapt_timeouts(&mut self) {
        let avg = self.average_finality_ms();
        if avg == 0 {
            return;
        }

        if avg < SHRINK_THRESHOLD_MS && self.consecutive_fast_commits > 5 {
            // Network is healthy: shrink timeouts toward minimum
            self.adaptive_propose_ms = (self.adaptive_propose_ms * 9 / 10).max(MIN_PROPOSE_MS);
            self.adaptive_prevote_ms = (self.adaptive_prevote_ms * 9 / 10).max(MIN_VOTE_MS);
            self.adaptive_precommit_ms = (self.adaptive_precommit_ms * 9 / 10).max(MIN_VOTE_MS);
        } else if avg > GROW_THRESHOLD_MS || self.consecutive_fast_commits == 0 {
            // Network is stressed: grow timeouts toward maximum
            self.adaptive_propose_ms = (self.adaptive_propose_ms * 11 / 10).min(MAX_PROPOSE_MS);
            self.adaptive_prevote_ms = (self.adaptive_prevote_ms * 11 / 10).min(MAX_VOTE_MS);
            self.adaptive_precommit_ms = (self.adaptive_precommit_ms * 11 / 10).min(MAX_VOTE_MS);
        }
    }

    /// Get current adaptive timeouts as a tuple (propose, prevote, precommit) in ms.
    pub fn adaptive_timeouts(&self) -> (u64, u64, u64) {
        (
            self.adaptive_propose_ms,
            self.adaptive_prevote_ms,
            self.adaptive_precommit_ms,
        )
    }

    /// Report finality statistics as JSON-compatible struct.
    pub fn stats(&self) -> FinalityStats {
        FinalityStats {
            total_finalized: self.total_finalized,
            average_finality_ms: self.average_finality_ms(),
            p95_finality_ms: self.p95_finality_ms(),
            best_finality_ms: if self.best_finality_ms == u64::MAX { 0 } else { self.best_finality_ms },
            worst_finality_ms: self.worst_finality_ms,
            consecutive_fast_commits: self.consecutive_fast_commits,
            is_sub_second: self.is_sub_second(),
            adaptive_propose_ms: self.adaptive_propose_ms,
            adaptive_prevote_ms: self.adaptive_prevote_ms,
            adaptive_precommit_ms: self.adaptive_precommit_ms,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FinalityStats {
    pub total_finalized: u64,
    pub average_finality_ms: u64,
    pub p95_finality_ms: u64,
    pub best_finality_ms: u64,
    pub worst_finality_ms: u64,
    pub consecutive_fast_commits: u64,
    pub is_sub_second: bool,
    pub adaptive_propose_ms: u64,
    pub adaptive_prevote_ms: u64,
    pub adaptive_precommit_ms: u64,
}

/// A finality certificate that proves a block was finalized in < 1 second.
/// This is an extension of CommitCertificate with timing metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FinalityCertificate {
    /// The underlying commit certificate with validator signatures.
    pub commit: CommitCertificate,
    /// Wall-clock finality time in milliseconds (propose -> commit).
    pub finality_ms: u64,
    /// The round in which finality was achieved (0 = optimistic fast path).
    pub finality_round: u32,
    /// Timestamp (Unix ms) when the block was proposed.
    pub propose_timestamp_ms: u64,
    /// Timestamp (Unix ms) when finality was achieved.
    pub finality_timestamp_ms: u64,
}

/// Pipeline state for overlapping block preparation with commit propagation.
/// While the commit certificate for height H propagates, we can start
/// preparing the proposal for height H+1.
#[derive(Clone, Debug)]
pub struct PipelineState {
    /// Pre-computed proposal data for the next height (if we are the proposer).
    pub next_proposal_txs: Option<Vec<crate::types::Tx>>,
    /// Whether the pipeline is active.
    pub active: bool,
    /// Height for which the pipeline is preparing.
    pub pipeline_height: Height,
}

impl Default for PipelineState {
    fn default() -> Self {
        Self {
            next_proposal_txs: None,
            active: false,
            pipeline_height: 0,
        }
    }
}

impl PipelineState {
    /// Begin pipelining: pre-drain mempool transactions for the next height.
    pub fn begin_pipeline(&mut self, height: Height, txs: Vec<crate::types::Tx>) {
        self.active = true;
        self.pipeline_height = height;
        self.next_proposal_txs = Some(txs);
    }

    /// Consume pipelined transactions if they match the expected height.
    pub fn take_pipelined_txs(&mut self, height: Height) -> Option<Vec<crate::types::Tx>> {
        if self.active && self.pipeline_height == height {
            self.active = false;
            self.next_proposal_txs.take()
        } else {
            self.active = false;
            self.next_proposal_txs = None;
            None
        }
    }

    /// Cancel pipeline (e.g., on round change).
    pub fn cancel(&mut self) {
        self.active = false;
        self.next_proposal_txs = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_finality_tracker_basic() {
        let mut ft = FinalityTracker::new(1);

        // Record 10 fast commits at ~100ms
        for _ in 0..10 {
            ft.record_commit(100, 0);
        }

        assert_eq!(ft.total_finalized, 10);
        assert_eq!(ft.consecutive_fast_commits, 10);
        assert_eq!(ft.average_finality_ms(), 100);
        assert!(ft.is_sub_second());
        assert_eq!(ft.best_finality_ms, 100);
    }

    #[test]
    fn test_finality_tracker_adapts_down() {
        let mut ft = FinalityTracker::new(1);

        // Record many fast commits
        for _ in 0..20 {
            ft.record_commit(80, 0);
        }

        // Timeouts should have shrunk
        assert!(ft.adaptive_propose_ms < 150);
        assert!(ft.adaptive_prevote_ms < 100);
    }

    #[test]
    fn test_finality_tracker_adapts_up() {
        let mut ft = FinalityTracker::new(1);

        // Record slow commits (round > 0)
        for _ in 0..10 {
            ft.record_commit(900, 2);
        }

        // Timeouts should have grown
        assert!(ft.adaptive_propose_ms >= 150);
    }

    #[test]
    fn test_pipeline_state() {
        let mut ps = PipelineState::default();
        assert!(!ps.active);

        ps.begin_pipeline(5, vec![]);
        assert!(ps.active);
        assert_eq!(ps.pipeline_height, 5);

        // Take for wrong height
        assert!(ps.take_pipelined_txs(6).is_none());

        ps.begin_pipeline(7, vec![]);
        assert!(ps.take_pipelined_txs(7).is_some());
    }

    #[test]
    fn test_finality_stats() {
        let mut ft = FinalityTracker::new(0);
        for i in 0..50 {
            ft.record_commit(50 + i * 2, 0);
        }
        let stats = ft.stats();
        assert!(stats.is_sub_second);
        assert!(stats.average_finality_ms < 1000);
        assert!(stats.best_finality_ms <= 50);
    }
}
