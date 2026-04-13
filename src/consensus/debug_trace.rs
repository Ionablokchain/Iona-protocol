//! STEP 4 — Consensus debug tracing.
//!
//! Structured logging for every consensus phase:
//! - height
//! - round
//! - proposal (who proposed, hash, tx count)
//! - prevote (validator, vote)
//! - precommit (validator, vote)
//! - commit (height, block hash, state root)
//!
//! This makes consensus debugging possible without guessing.

use crate::types::{Hash32, Height};
use std::collections::BTreeMap;

/// A single consensus trace event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsensusEvent {
    /// New height started.
    NewHeight { height: Height },
    /// New round started.
    NewRound { height: Height, round: u32 },
    /// Proposal received/created.
    Proposal {
        height: Height,
        round: u32,
        proposer: String,
        block_hash: Hash32,
        tx_count: usize,
    },
    /// Prevote cast.
    Prevote {
        height: Height,
        round: u32,
        validator: String,
        block_hash: Option<Hash32>, // None = nil vote
    },
    /// Precommit cast.
    Precommit {
        height: Height,
        round: u32,
        validator: String,
        block_hash: Option<Hash32>,
    },
    /// Block committed.
    Commit {
        height: Height,
        round: u32,
        block_hash: Hash32,
        state_root: Hash32,
        tx_count: usize,
        gas_used: u64,
    },
    /// Timeout occurred.
    Timeout {
        height: Height,
        round: u32,
        phase: String, // "propose" | "prevote" | "precommit"
    },
    /// Round skip (jumped to higher round).
    RoundSkip {
        height: Height,
        from_round: u32,
        to_round: u32,
        reason: String,
    },
}

impl std::fmt::Display for ConsensusEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NewHeight { height } =>
                write!(f, "[CONSENSUS] NEW_HEIGHT height={height}"),
            Self::NewRound { height, round } =>
                write!(f, "[CONSENSUS] NEW_ROUND height={height} round={round}"),
            Self::Proposal { height, round, proposer, block_hash, tx_count } =>
                write!(f, "[CONSENSUS] PROPOSAL height={height} round={round} proposer={proposer} hash=0x{} txs={tx_count}",
                    hex::encode(&block_hash.0[..8])),
            Self::Prevote { height, round, validator, block_hash } => {
                let vote = block_hash.as_ref()
                    .map(|h| format!("0x{}", hex::encode(&h.0[..8])))
                    .unwrap_or_else(|| "NIL".into());
                write!(f, "[CONSENSUS] PREVOTE height={height} round={round} validator={validator} vote={vote}")
            }
            Self::Precommit { height, round, validator, block_hash } => {
                let vote = block_hash.as_ref()
                    .map(|h| format!("0x{}", hex::encode(&h.0[..8])))
                    .unwrap_or_else(|| "NIL".into());
                write!(f, "[CONSENSUS] PRECOMMIT height={height} round={round} validator={validator} vote={vote}")
            }
            Self::Commit { height, round, block_hash, state_root, tx_count, gas_used } =>
                write!(f, "[CONSENSUS] COMMIT height={height} round={round} hash=0x{} root=0x{} txs={tx_count} gas={gas_used}",
                    hex::encode(&block_hash.0[..8]),
                    hex::encode(&state_root.0[..8])),
            Self::Timeout { height, round, phase } =>
                write!(f, "[CONSENSUS] TIMEOUT height={height} round={round} phase={phase}"),
            Self::RoundSkip { height, from_round, to_round, reason } =>
                write!(f, "[CONSENSUS] ROUND_SKIP height={height} from={from_round} to={to_round} reason={reason}"),
        }
    }
}

/// Consensus debug tracer that collects structured events.
///
/// Use this to understand exactly what happened during consensus:
/// ```text
/// [CONSENSUS] NEW_HEIGHT height=100
/// [CONSENSUS] NEW_ROUND height=100 round=0
/// [CONSENSUS] PROPOSAL height=100 round=0 proposer=val2 hash=0xabcd... txs=5
/// [CONSENSUS] PREVOTE height=100 round=0 validator=val2 vote=0xabcd...
/// [CONSENSUS] PREVOTE height=100 round=0 validator=val3 vote=0xabcd...
/// [CONSENSUS] PRECOMMIT height=100 round=0 validator=val2 vote=0xabcd...
/// [CONSENSUS] PRECOMMIT height=100 round=0 validator=val3 vote=0xabcd...
/// [CONSENSUS] COMMIT height=100 round=0 hash=0xabcd... root=0x1234... txs=5 gas=21000
/// ```
#[derive(Debug)]
pub struct ConsensusTracer {
    events: Vec<ConsensusEvent>,
    max_events: usize,
    enabled: bool,
}

impl ConsensusTracer {
    /// Create a new tracer.
    pub fn new(enabled: bool, max_events: usize) -> Self {
        Self {
            events: Vec::new(),
            max_events,
            enabled,
        }
    }

    /// Record a consensus event.
    pub fn record(&mut self, event: ConsensusEvent) {
        if !self.enabled {
            return;
        }
        // Ring buffer: drop oldest if at capacity.
        if self.events.len() >= self.max_events {
            self.events.remove(0);
        }
        self.events.push(event);
    }

    /// Record a new height event.
    pub fn trace_new_height(&mut self, height: Height) {
        self.record(ConsensusEvent::NewHeight { height });
    }

    /// Record a new round event.
    pub fn trace_new_round(&mut self, height: Height, round: u32) {
        self.record(ConsensusEvent::NewRound { height, round });
    }

    /// Record a proposal event.
    pub fn trace_proposal(
        &mut self,
        height: Height,
        round: u32,
        proposer: &str,
        block_hash: Hash32,
        tx_count: usize,
    ) {
        self.record(ConsensusEvent::Proposal {
            height,
            round,
            proposer: proposer.to_string(),
            block_hash,
            tx_count,
        });
    }

    /// Record a prevote event.
    pub fn trace_prevote(
        &mut self,
        height: Height,
        round: u32,
        validator: &str,
        block_hash: Option<Hash32>,
    ) {
        self.record(ConsensusEvent::Prevote {
            height,
            round,
            validator: validator.to_string(),
            block_hash,
        });
    }

    /// Record a precommit event.
    pub fn trace_precommit(
        &mut self,
        height: Height,
        round: u32,
        validator: &str,
        block_hash: Option<Hash32>,
    ) {
        self.record(ConsensusEvent::Precommit {
            height,
            round,
            validator: validator.to_string(),
            block_hash,
        });
    }

    /// Record a commit event.
    pub fn trace_commit(
        &mut self,
        height: Height,
        round: u32,
        block_hash: Hash32,
        state_root: Hash32,
        tx_count: usize,
        gas_used: u64,
    ) {
        self.record(ConsensusEvent::Commit {
            height,
            round,
            block_hash,
            state_root,
            tx_count,
            gas_used,
        });
    }

    /// Record a timeout event.
    pub fn trace_timeout(&mut self, height: Height, round: u32, phase: &str) {
        self.record(ConsensusEvent::Timeout {
            height,
            round,
            phase: phase.to_string(),
        });
    }

    /// Record a round skip.
    pub fn trace_round_skip(&mut self, height: Height, from: u32, to: u32, reason: &str) {
        self.record(ConsensusEvent::RoundSkip {
            height,
            from_round: from,
            to_round: to,
            reason: reason.to_string(),
        });
    }

    /// Get all recorded events.
    pub fn events(&self) -> &[ConsensusEvent] {
        &self.events
    }

    /// Get events for a specific height.
    pub fn events_at_height(&self, height: Height) -> Vec<&ConsensusEvent> {
        self.events
            .iter()
            .filter(|e| event_height(e) == Some(height))
            .collect()
    }

    /// Get the latest commit event.
    pub fn latest_commit(&self) -> Option<&ConsensusEvent> {
        self.events
            .iter()
            .rev()
            .find(|e| matches!(e, ConsensusEvent::Commit { .. }))
    }

    /// Get stats for a height range.
    pub fn stats(&self, from: Height, to: Height) -> ConsensusStats {
        let relevant: Vec<&ConsensusEvent> = self
            .events
            .iter()
            .filter(|e| {
                event_height(e)
                    .map(|h| h >= from && h <= to)
                    .unwrap_or(false)
            })
            .collect();

        let proposals = relevant
            .iter()
            .filter(|e| matches!(e, ConsensusEvent::Proposal { .. }))
            .count();
        let prevotes = relevant
            .iter()
            .filter(|e| matches!(e, ConsensusEvent::Prevote { .. }))
            .count();
        let precommits = relevant
            .iter()
            .filter(|e| matches!(e, ConsensusEvent::Precommit { .. }))
            .count();
        let commits = relevant
            .iter()
            .filter(|e| matches!(e, ConsensusEvent::Commit { .. }))
            .count();
        let timeouts = relevant
            .iter()
            .filter(|e| matches!(e, ConsensusEvent::Timeout { .. }))
            .count();
        let round_skips = relevant
            .iter()
            .filter(|e| matches!(e, ConsensusEvent::RoundSkip { .. }))
            .count();

        ConsensusStats {
            from,
            to,
            proposals,
            prevotes,
            precommits,
            commits,
            timeouts,
            round_skips,
        }
    }

    /// Clear all events.
    pub fn clear(&mut self) {
        self.events.clear();
    }

    /// Check if tracing is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

/// Extract height from a consensus event.
fn event_height(event: &ConsensusEvent) -> Option<Height> {
    match event {
        ConsensusEvent::NewHeight { height } => Some(*height),
        ConsensusEvent::NewRound { height, .. } => Some(*height),
        ConsensusEvent::Proposal { height, .. } => Some(*height),
        ConsensusEvent::Prevote { height, .. } => Some(*height),
        ConsensusEvent::Precommit { height, .. } => Some(*height),
        ConsensusEvent::Commit { height, .. } => Some(*height),
        ConsensusEvent::Timeout { height, .. } => Some(*height),
        ConsensusEvent::RoundSkip { height, .. } => Some(*height),
    }
}

/// Aggregated consensus statistics.
#[derive(Debug, Clone)]
pub struct ConsensusStats {
    pub from: Height,
    pub to: Height,
    pub proposals: usize,
    pub prevotes: usize,
    pub precommits: usize,
    pub commits: usize,
    pub timeouts: usize,
    pub round_skips: usize,
}

impl std::fmt::Display for ConsensusStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Consensus Stats [{}..{}]: proposals={} prevotes={} precommits={} commits={} timeouts={} round_skips={}",
            self.from, self.to, self.proposals, self.prevotes, self.precommits,
            self.commits, self.timeouts, self.round_skips,
        )
    }
}

/// STEP 5 extension: State root log entry.
/// Per-block state root logging: `height=100 root=0xabc...`
#[derive(Debug, Clone)]
pub struct StateRootLogEntry {
    pub height: Height,
    pub state_root: Hash32,
    pub timestamp: u64,
}

impl std::fmt::Display for StateRootLogEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "height={} root=0x{}",
            self.height,
            hex::encode(self.state_root.0)
        )
    }
}

/// State root logger: maintains a log of (height, state_root) for every committed block.
#[derive(Debug)]
pub struct StateRootLog {
    entries: BTreeMap<Height, StateRootLogEntry>,
    enabled: bool,
}

impl StateRootLog {
    pub fn new(enabled: bool) -> Self {
        Self {
            entries: BTreeMap::new(),
            enabled,
        }
    }

    /// Log a state root for a committed block.
    pub fn log(&mut self, height: Height, state_root: Hash32, timestamp: u64) {
        if !self.enabled {
            return;
        }
        self.entries.insert(
            height,
            StateRootLogEntry {
                height,
                state_root,
                timestamp,
            },
        );
    }

    /// Get the state root at a specific height.
    pub fn get(&self, height: Height) -> Option<&StateRootLogEntry> {
        self.entries.get(&height)
    }

    /// Get all entries as a BTreeMap of height -> Hash32 (for cross-node comparison).
    pub fn roots(&self) -> BTreeMap<Height, Hash32> {
        self.entries
            .iter()
            .map(|(&h, e)| (h, e.state_root.clone()))
            .collect()
    }

    /// Get the latest logged height.
    pub fn latest_height(&self) -> Option<Height> {
        self.entries.keys().next_back().copied()
    }

    /// Get total entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Export log as text (for `iona compare` tool).
    pub fn export_text(&self) -> String {
        let mut out = String::new();
        for entry in self.entries.values() {
            out.push_str(&format!("{entry}\n"));
        }
        out
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tracer_basic_flow() {
        let mut tracer = ConsensusTracer::new(true, 1000);

        tracer.trace_new_height(100);
        tracer.trace_new_round(100, 0);
        tracer.trace_proposal(100, 0, "val2", Hash32([0xAB; 32]), 5);
        tracer.trace_prevote(100, 0, "val2", Some(Hash32([0xAB; 32])));
        tracer.trace_prevote(100, 0, "val3", Some(Hash32([0xAB; 32])));
        tracer.trace_precommit(100, 0, "val2", Some(Hash32([0xAB; 32])));
        tracer.trace_precommit(100, 0, "val3", Some(Hash32([0xAB; 32])));
        tracer.trace_commit(100, 0, Hash32([0xAB; 32]), Hash32([0xCD; 32]), 5, 21000);

        assert_eq!(tracer.events().len(), 8);
    }

    #[test]
    fn test_tracer_disabled() {
        let mut tracer = ConsensusTracer::new(false, 100);
        tracer.trace_new_height(1);
        assert!(tracer.events().is_empty());
    }

    #[test]
    fn test_tracer_ring_buffer() {
        let mut tracer = ConsensusTracer::new(true, 3);
        tracer.trace_new_height(1);
        tracer.trace_new_height(2);
        tracer.trace_new_height(3);
        tracer.trace_new_height(4); // Should evict height=1.

        assert_eq!(tracer.events().len(), 3);
        assert_eq!(tracer.events()[0], ConsensusEvent::NewHeight { height: 2 });
    }

    #[test]
    fn test_events_at_height() {
        let mut tracer = ConsensusTracer::new(true, 100);
        tracer.trace_new_height(100);
        tracer.trace_proposal(100, 0, "val2", Hash32([0; 32]), 0);
        tracer.trace_new_height(101);

        let at_100 = tracer.events_at_height(100);
        assert_eq!(at_100.len(), 2);

        let at_101 = tracer.events_at_height(101);
        assert_eq!(at_101.len(), 1);
    }

    #[test]
    fn test_latest_commit() {
        let mut tracer = ConsensusTracer::new(true, 100);
        tracer.trace_commit(1, 0, Hash32([1; 32]), Hash32([2; 32]), 0, 0);
        tracer.trace_commit(2, 0, Hash32([3; 32]), Hash32([4; 32]), 1, 100);
        tracer.trace_new_height(3);

        let commit = tracer.latest_commit().unwrap();
        match commit {
            ConsensusEvent::Commit { height, .. } => assert_eq!(*height, 2),
            _ => panic!("expected Commit"),
        }
    }

    #[test]
    fn test_consensus_stats() {
        let mut tracer = ConsensusTracer::new(true, 100);
        tracer.trace_new_height(1);
        tracer.trace_proposal(1, 0, "v", Hash32([0; 32]), 0);
        tracer.trace_prevote(1, 0, "v1", None);
        tracer.trace_prevote(1, 0, "v2", Some(Hash32([0; 32])));
        tracer.trace_precommit(1, 0, "v1", Some(Hash32([0; 32])));
        tracer.trace_commit(1, 0, Hash32([0; 32]), Hash32([0; 32]), 0, 0);
        tracer.trace_timeout(1, 0, "propose");

        let stats = tracer.stats(1, 1);
        assert_eq!(stats.proposals, 1);
        assert_eq!(stats.prevotes, 2);
        assert_eq!(stats.precommits, 1);
        assert_eq!(stats.commits, 1);
        assert_eq!(stats.timeouts, 1);
    }

    #[test]
    fn test_consensus_stats_display() {
        let stats = ConsensusStats {
            from: 1,
            to: 100,
            proposals: 100,
            prevotes: 300,
            precommits: 300,
            commits: 100,
            timeouts: 2,
            round_skips: 1,
        };
        let s = format!("{stats}");
        assert!(s.contains("proposals=100"));
        assert!(s.contains("commits=100"));
    }

    #[test]
    fn test_event_display() {
        let events = vec![
            ConsensusEvent::NewHeight { height: 42 },
            ConsensusEvent::NewRound {
                height: 42,
                round: 1,
            },
            ConsensusEvent::Proposal {
                height: 42,
                round: 0,
                proposer: "val2".into(),
                block_hash: Hash32([0xAB; 32]),
                tx_count: 5,
            },
            ConsensusEvent::Prevote {
                height: 42,
                round: 0,
                validator: "val2".into(),
                block_hash: Some(Hash32([0xAB; 32])),
            },
            ConsensusEvent::Prevote {
                height: 42,
                round: 0,
                validator: "val3".into(),
                block_hash: None, // NIL vote
            },
            ConsensusEvent::Precommit {
                height: 42,
                round: 0,
                validator: "val2".into(),
                block_hash: Some(Hash32([0xAB; 32])),
            },
            ConsensusEvent::Commit {
                height: 42,
                round: 0,
                block_hash: Hash32([0xAB; 32]),
                state_root: Hash32([0xCD; 32]),
                tx_count: 5,
                gas_used: 21000,
            },
            ConsensusEvent::Timeout {
                height: 42,
                round: 0,
                phase: "propose".into(),
            },
            ConsensusEvent::RoundSkip {
                height: 42,
                from_round: 0,
                to_round: 2,
                reason: "timeout + no proposal".into(),
            },
        ];

        for event in &events {
            let s = format!("{event}");
            assert!(s.starts_with("[CONSENSUS]"), "event display: {s}");
        }
    }

    #[test]
    fn test_tracer_clear() {
        let mut tracer = ConsensusTracer::new(true, 100);
        tracer.trace_new_height(1);
        assert_eq!(tracer.events().len(), 1);
        tracer.clear();
        assert!(tracer.events().is_empty());
    }

    #[test]
    fn test_tracer_timeout_and_round_skip() {
        let mut tracer = ConsensusTracer::new(true, 100);
        tracer.trace_timeout(1, 0, "propose");
        tracer.trace_round_skip(1, 0, 1, "proposal timeout");

        assert_eq!(tracer.events().len(), 2);
        match &tracer.events()[0] {
            ConsensusEvent::Timeout { phase, .. } => assert_eq!(phase, "propose"),
            _ => panic!("expected Timeout"),
        }
    }

    #[test]
    fn test_state_root_log() {
        let mut log = StateRootLog::new(true);

        log.log(1, Hash32([0x01; 32]), 1000);
        log.log(2, Hash32([0x02; 32]), 2000);
        log.log(3, Hash32([0x03; 32]), 3000);

        assert_eq!(log.len(), 3);
        assert_eq!(log.latest_height(), Some(3));

        let entry = log.get(2).unwrap();
        assert_eq!(entry.height, 2);
        assert_eq!(entry.state_root, Hash32([0x02; 32]));
    }

    #[test]
    fn test_state_root_log_disabled() {
        let mut log = StateRootLog::new(false);
        log.log(1, Hash32([0x01; 32]), 1000);
        assert!(log.is_empty());
    }

    #[test]
    fn test_state_root_log_export() {
        let mut log = StateRootLog::new(true);
        log.log(1, Hash32([0xAA; 32]), 1000);
        log.log(2, Hash32([0xBB; 32]), 2000);

        let text = log.export_text();
        assert!(text.contains("height=1"));
        assert!(text.contains("height=2"));
        assert!(text.contains("root=0x"));
    }

    #[test]
    fn test_state_root_log_roots_for_compare() {
        let mut log = StateRootLog::new(true);
        log.log(1, Hash32([0x01; 32]), 1000);
        log.log(2, Hash32([0x02; 32]), 2000);

        let roots = log.roots();
        assert_eq!(roots.len(), 2);
        assert_eq!(roots[&1], Hash32([0x01; 32]));
        assert_eq!(roots[&2], Hash32([0x02; 32]));
    }

    #[test]
    fn test_state_root_entry_display() {
        let entry = StateRootLogEntry {
            height: 42,
            state_root: Hash32([0xAB; 32]),
            timestamp: 1000,
        };
        let s = format!("{entry}");
        assert!(s.contains("height=42"));
        assert!(s.contains("root=0x"));
    }

    #[test]
    fn test_nil_prevote_display() {
        let event = ConsensusEvent::Prevote {
            height: 1,
            round: 0,
            validator: "val2".into(),
            block_hash: None,
        };
        let s = format!("{event}");
        assert!(s.contains("NIL"));
    }
}
