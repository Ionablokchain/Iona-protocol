//! P2P state sync (snapshot download) client.
//!
//! This module implements a client for downloading state snapshots and delta updates
//! from peers in the P2P network. It is used when a node's local state is missing
//! or outdated.
//!
//! # Features
//!
//! - Peer selection uses *height* first, then measured manifest RTT (latency) and a small throughput probe.
//! - Incremental verification: each *full* manifest chunk is verified against per-chunk hashes.
//! - Resume supports partial chunks: if a download is interrupted mid-chunk, we request only the missing tail,
//!   then verify the assembled full chunk (no boundary-only truncation).
//! - Multi-peer fallback: on timeouts/mismatches, switch to the next best peer; retries can re-request partial
//!   tails or whole chunks without discarding previously verified data.
//! - Delta sync: if local snapshots exist, the client attempts to download delta updates instead of a full snapshot.
//! - Optional Prometheus metrics for observability.
//! - Configurable timeouts, chunk sizes, and peer selection limits.
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::net::state_sync::{try_p2p_restore_state, StateSyncConfig};
//!
//! let config = StateSyncConfig::default();
//! let restored = try_p2p_restore_state(
//!     "./data/node",
//!     "./data/node/state_full.json",
//!     vec![multiaddr1, multiaddr2],
//!     config,
//! ).await?;
//! ```

use crate::net::p2p::{
    proto_state, Codec, DeltaChunkRequest, DeltaChunkResponse, DeltaManifestRequest,
    DeltaManifestResponse, Req, Resp, StateChunkRequest, StateChunkResponse, StateIndexRequest,
    StateIndexResponse, StateManifestRequest, StateManifestResponse, StateReq, StateResp,
};
use crate::storage::snapshots;
use libp2p::futures::StreamExt;
use libp2p::{
    core::upgrade,
    noise,
    request_response::{
        self, Behaviour as RequestResponse, Event as RequestResponseEvent,
        Message as RequestResponseMessage, ProtocolSupport,
    },
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, Swarm, Transport,
};
use prometheus::{register_counter, register_gauge, Counter, Gauge};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io;
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::time::timeout;
use tracing::{debug, info, warn};

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for state sync client.
#[derive(Debug, Clone)]
pub struct StateSyncConfig {
    /// Timeout for individual requests (seconds).
    pub request_timeout_secs: u64,
    /// Maximum chunk size to request (bytes). The manifest's chunk size takes precedence.
    pub max_chunk_bytes: usize,
    /// Maximum number of candidate peers to consider before ranking.
    pub max_candidates: usize,
    /// Probe length for throughput measurement (bytes).
    pub probe_len: u32,
    /// Whether to enable Prometheus metrics.
    pub enable_metrics: bool,
}

impl Default for StateSyncConfig {
    fn default() -> Self {
        Self {
            request_timeout_secs: 30,
            max_chunk_bytes: 1024 * 1024,
            max_candidates: 6,
            probe_len: 262_144, // 256 KiB
            enable_metrics: false,
        }
    }
}

impl StateSyncConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.request_timeout_secs == 0 {
            return Err("request_timeout_secs must be > 0".into());
        }
        if self.max_chunk_bytes == 0 {
            return Err("max_chunk_bytes must be > 0".into());
        }
        if self.max_candidates == 0 {
            return Err("max_candidates must be > 0".into());
        }
        if self.probe_len == 0 {
            return Err("probe_len must be > 0".into());
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Metrics
// -----------------------------------------------------------------------------

/// Prometheus metrics for state sync operations.
#[derive(Clone)]
pub struct StateSyncMetrics {
    /// Number of snapshot manifests received.
    pub manifests_received: Counter,
    /// Number of full snapshot downloads started.
    pub full_snapshot_downloads: Counter,
    /// Number of delta sync attempts.
    pub delta_sync_attempts: Counter,
    /// Number of delta sync successes.
    pub delta_sync_successes: Counter,
    /// Total bytes downloaded (across all methods).
    pub bytes_downloaded: Counter,
    /// Number of chunk verification failures.
    pub chunk_verification_failures: Counter,
    /// Number of peer timeouts encountered.
    pub peer_timeouts: Counter,
    /// Current number of connected peers during sync.
    pub active_peers: Gauge,
}

impl StateSyncMetrics {
    /// Create and register metrics with the global Prometheus registry.
    pub fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            manifests_received: register_counter!(
                "iona_statesync_manifests_received_total",
                "Total snapshot manifests received"
            )?,
            full_snapshot_downloads: register_counter!(
                "iona_statesync_full_snapshot_downloads_total",
                "Total full snapshot download attempts"
            )?,
            delta_sync_attempts: register_counter!(
                "iona_statesync_delta_sync_attempts_total",
                "Total delta sync attempts"
            )?,
            delta_sync_successes: register_counter!(
                "iona_statesync_delta_sync_successes_total",
                "Total successful delta syncs"
            )?,
            bytes_downloaded: register_counter!(
                "iona_statesync_bytes_downloaded_total",
                "Total bytes downloaded"
            )?,
            chunk_verification_failures: register_counter!(
                "iona_statesync_chunk_verification_failures_total",
                "Total chunk verification failures"
            )?,
            peer_timeouts: register_counter!(
                "iona_statesync_peer_timeouts_total",
                "Total peer timeouts"
            )?,
            active_peers: register_gauge!(
                "iona_statesync_active_peers",
                "Number of active peers during state sync"
            )?,
        })
    }

    /// Create an unregistered metrics instance (for tests or disabled metrics).
    pub fn new_unregistered() -> Self {
        Self {
            manifests_received: Counter::new("iona_statesync_manifests_received_total", "Manifests").unwrap(),
            full_snapshot_downloads: Counter::new("iona_statesync_full_snapshot_downloads_total", "Full downloads").unwrap(),
            delta_sync_attempts: Counter::new("iona_statesync_delta_sync_attempts_total", "Delta attempts").unwrap(),
            delta_sync_successes: Counter::new("iona_statesync_delta_sync_successes_total", "Delta successes").unwrap(),
            bytes_downloaded: Counter::new("iona_statesync_bytes_downloaded_total", "Bytes").unwrap(),
            chunk_verification_failures: Counter::new("iona_statesync_chunk_verification_failures_total", "Verification failures").unwrap(),
            peer_timeouts: Counter::new("iona_statesync_peer_timeouts_total", "Timeouts").unwrap(),
            active_peers: Gauge::new("iona_statesync_active_peers", "Active peers").unwrap(),
        }
    }
}

// -----------------------------------------------------------------------------
// Network behaviour
// -----------------------------------------------------------------------------

#[derive(NetworkBehaviour)]
struct Behaviour {
    rr: RequestResponse<Codec>,
}

// -----------------------------------------------------------------------------
// Candidate peer for snapshot download
// -----------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Candidate {
    peer: PeerId,
    mani: StateManifestResponse,
    rtt_ms: u64,
    throughput_bps: u64,
}

// -----------------------------------------------------------------------------
// Resume information for interrupted downloads
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct ResumeInfo {
    /// Start of the (possibly partial) current chunk boundary (aligned)
    chunk_start: u64,
    /// How many bytes already present in the current chunk tail (0 if aligned)
    partial_len: u64,
}

// -----------------------------------------------------------------------------
// Helper functions
// -----------------------------------------------------------------------------

/// Compute the chunk index for a given offset.
#[must_use]
fn chunk_index(offset: u64, chunk_size: u32) -> usize {
    (offset / chunk_size as u64) as usize
}

/// Verify that a full chunk matches the expected hash from the manifest.
#[must_use]
fn verify_full_chunk_hash(manifest: &StateManifestResponse, chunk_start: u64, data: &[u8]) -> bool {
    let idx = chunk_index(chunk_start, manifest.chunk_size);
    if idx >= manifest.chunk_hashes.len() {
        return false;
    }
    if data.len() != manifest.chunk_size as usize
        && (chunk_start + data.len() as u64) < manifest.total_bytes
    {
        // We only verify full-sized chunks (except possibly the last partial chunk at EOF).
        return false;
    }
    let got = blake3::hash(data);
    let got_hex = hex::encode(got.as_bytes());
    manifest.chunk_hashes[idx] == got_hex
}

/// Verify that a delta chunk matches the expected hash.
#[must_use]
fn verify_delta_chunk_hash(delta_manifest: &DeltaManifestResponse, offset: u64, data: &[u8]) -> bool {
    let idx = (offset / delta_manifest.chunk_size as u64) as usize;
    if idx >= delta_manifest.chunk_hashes.len() {
        return false;
    }
    let got = blake3::hash(data);
    delta_manifest.chunk_hashes[idx] == hex::encode(got.as_bytes())
}

/// Resume information for a partially downloaded snapshot file.
fn resume_info(tmp_path: &str, manifest: &StateManifestResponse) -> anyhow::Result<ResumeInfo> {
    if !Path::new(tmp_path).exists() {
        return Ok(ResumeInfo {
            chunk_start: 0,
            partial_len: 0,
        });
    }
    let meta = std::fs::metadata(tmp_path)?;
    let len = meta.len();
    if len == 0 {
        return Ok(ResumeInfo {
            chunk_start: 0,
            partial_len: 0,
        });
    }

    let cs = manifest.chunk_size as u64;
    let full = (len / cs) * cs;
    let partial = len - full;

    // Verify existing *full* chunks. If something is corrupt, truncate back to last valid boundary.
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(tmp_path)?;
    let mut off = 0u64;
    let mut buf = vec![0u8; manifest.chunk_size as usize];

    while off < full {
        f.seek(SeekFrom::Start(off))?;
        f.read_exact(&mut buf)?;
        if !verify_full_chunk_hash(manifest, off, &buf) {
            warn!(
                offset = off,
                "statesync: resume verification failed; truncating to last valid boundary"
            );
            std::fs::OpenOptions::new()
                .write(true)
                .open(tmp_path)?
                .set_len(off)?;
            return Ok(ResumeInfo {
                chunk_start: off,
                partial_len: 0,
            });
        }
        off += cs;
    }

    // Keep the partial tail (if any). We'll request the missing part on resume.
    Ok(ResumeInfo {
        chunk_start: full,
        partial_len: partial,
    })
}

/// Find a path of delta edges from `from` to `to` using BFS.
fn find_delta_path(edges: &[(u64, u64)], from: u64, to: u64) -> Option<Vec<(u64, u64)>> {
    if from == to {
        return Some(vec![]);
    }
    let mut adj: HashMap<u64, Vec<u64>> = HashMap::new();
    for (a, b) in edges {
        adj.entry(*a).or_default().push(*b);
    }
    let mut queue = VecDeque::new();
    let mut prev: HashMap<u64, u64> = HashMap::new();
    queue.push_back(from);
    prev.insert(from, from);

    while let Some(x) = queue.pop_front() {
        let Some(neighbors) = adj.get(&x) else {
            continue;
        };
        for &n in neighbors {
            if prev.contains_key(&n) {
                continue;
            }
            prev.insert(n, x);
            if n == to {
                break;
            }
            queue.push_back(n);
        }
        if prev.contains_key(&to) {
            break;
        }
    }
    if !prev.contains_key(&to) {
        return None;
    }
    // reconstruct heights
    let mut heights = vec![to];
    let mut cur = to;
    while cur != from {
        let p = *prev.get(&cur).unwrap();
        heights.push(p);
        cur = p;
    }
    heights.reverse();
    // edges
    let mut path = vec![];
    for w in heights.windows(2) {
        path.push((w[0], w[1]));
    }
    Some(path)
}

// -----------------------------------------------------------------------------
// Low‑level response waiters
// -----------------------------------------------------------------------------

async fn wait_for_state_manifest_response(
    swarm: &mut Swarm<Behaviour>,
    peer: PeerId,
    timeout_s: u64,
) -> Option<StateManifestResponse> {
    let deadline = Instant::now() + Duration::from_secs(timeout_s.max(3));
    while Instant::now() < deadline {
        let ev = timeout(Duration::from_millis(250), swarm.select_next_some()).await;
        let Ok(ev) = ev else {
            continue;
        };
        if let SwarmEvent::Behaviour(BehaviourEvent::Rr(RequestResponseEvent::Message {
            peer: p,
            message,
        })) = ev
        {
            if p != peer {
                continue;
            }
            if let RequestResponseMessage::Response { response, .. } = message {
                if let Resp::State(StateResp::Manifest(m)) = response {
                    return Some(m);
                }
            }
        }
    }
    None
}

async fn wait_for_state_chunk_response(
    swarm: &mut Swarm<Behaviour>,
    peer: PeerId,
    expected_offset: u64,
    timeout_s: u64,
) -> Option<StateChunkResponse> {
    let deadline = Instant::now() + Duration::from_secs(timeout_s.max(3));
    while Instant::now() < deadline {
        let ev = timeout(Duration::from_millis(250), swarm.select_next_some()).await;
        let Ok(ev) = ev else {
            continue;
        };
        if let SwarmEvent::Behaviour(BehaviourEvent::Rr(RequestResponseEvent::Message {
            peer: p,
            message,
        })) = ev
        {
            if p != peer {
                continue;
            }
            if let RequestResponseMessage::Response { response, .. } = message {
                if let Resp::State(StateResp::Chunk(c)) = response {
                    if c.offset == expected_offset {
                        return Some(c);
                    }
                }
            }
        }
    }
    None
}

async fn wait_for_state_index_response(
    swarm: &mut Swarm<Behaviour>,
    peer: PeerId,
    timeout_s: u64,
) -> Option<StateIndexResponse> {
    let deadline = Instant::now() + Duration::from_secs(timeout_s.max(3));
    while Instant::now() < deadline {
        let ev = timeout(Duration::from_millis(250), swarm.select_next_some()).await;
        let Ok(ev) = ev else {
            continue;
        };
        if let SwarmEvent::Behaviour(BehaviourEvent::Rr(RequestResponseEvent::Message {
            peer: p,
            message,
        })) = ev
        {
            if p != peer {
                continue;
            }
            if let RequestResponseMessage::Response { response, .. } = message {
                if let Resp::State(StateResp::Index(ix)) = response {
                    return Some(ix);
                }
            }
        }
    }
    None
}

async fn wait_for_delta_manifest_response(
    swarm: &mut Swarm<Behaviour>,
    peer: PeerId,
    timeout_s: u64,
) -> Option<DeltaManifestResponse> {
    let deadline = Instant::now() + Duration::from_secs(timeout_s.max(3));
    while Instant::now() < deadline {
        let ev = timeout(Duration::from_millis(250), swarm.select_next_some()).await;
        let Ok(ev) = ev else {
            continue;
        };
        if let SwarmEvent::Behaviour(BehaviourEvent::Rr(RequestResponseEvent::Message {
            peer: p,
            message,
        })) = ev
        {
            if p != peer {
                continue;
            }
            if let RequestResponseMessage::Response { response, .. } = message {
                if let Resp::State(StateResp::DeltaManifest(m)) = response {
                    return Some(m);
                }
            }
        }
    }
    None
}

async fn wait_for_delta_chunk_response(
    swarm: &mut Swarm<Behaviour>,
    peer: PeerId,
    expected_offset: u64,
    timeout_s: u64,
) -> Option<DeltaChunkResponse> {
    let deadline = Instant::now() + Duration::from_secs(timeout_s.max(3));
    while Instant::now() < deadline {
        let ev = timeout(Duration::from_millis(250), swarm.select_next_some()).await;
        let Ok(ev) = ev else {
            continue;
        };
        if let SwarmEvent::Behaviour(BehaviourEvent::Rr(RequestResponseEvent::Message {
            peer: p,
            message,
        })) = ev
        {
            if p != peer {
                continue;
            }
            if let RequestResponseMessage::Response { response, .. } = message {
                if let Resp::State(StateResp::DeltaChunk(c)) = response {
                    if c.offset == expected_offset {
                        return Some(c);
                    }
                }
            }
        }
    }
    None
}

// -----------------------------------------------------------------------------
// Throughput probe
// -----------------------------------------------------------------------------

/// Small throughput probe (best-effort) used for peer ordering.
/// We request a small prefix slice and measure wall-time.
async fn probe_throughput_bps(
    swarm: &mut Swarm<Behaviour>,
    peer: PeerId,
    height: u64,
    probe_len: u32,
    timeout_s: u64,
) -> u64 {
    let start = Instant::now();
    let req = Req::State(StateReq::Chunk(StateChunkRequest {
        height,
        offset: 0,
        len: probe_len,
    }));
    swarm.behaviour_mut().rr.send_request(&peer, req);
    let Some(chunk) = wait_for_state_chunk_response(swarm, peer, 0, timeout_s).await else {
        return 0;
    };
    let ms = start.elapsed().as_millis().max(1) as u64;
    // bytes per second, coarse
    (chunk.data.len() as u64) * 1000 / ms
}

// -----------------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------------

/// Try to download the latest snapshot via P2P and materialize `state_full.json`.
///
/// Returns `Ok(true)` if the state was restored, `Ok(false)` if no snapshot was found
/// or no suitable peer, and `Err` on network or I/O errors.
///
/// This is a convenience wrapper around [`try_p2p_restore_state_with_config`] using
/// default configuration.
pub async fn try_p2p_restore_state(
    data_dir: &str,
    state_full_path: &str,
    peers: Vec<Multiaddr>,
    timeout_s: u64,
    chunk_bytes: usize,
) -> anyhow::Result<bool> {
    let config = StateSyncConfig {
        request_timeout_secs: timeout_s,
        max_chunk_bytes: chunk_bytes,
        ..Default::default()
    };
    try_p2p_restore_state_with_config(data_dir, state_full_path, peers, config).await
}

/// Try to download the latest snapshot via P2P and materialize `state_full.json`.
///
/// Returns `Ok(true)` if the state was restored, `Ok(false)` if no snapshot was found
/// or no suitable peer, and `Err` on network or I/O errors.
pub async fn try_p2p_restore_state_with_config(
    data_dir: &str,
    state_full_path: &str,
    peers: Vec<Multiaddr>,
    config: StateSyncConfig,
) -> anyhow::Result<bool> {
    config.validate().map_err(|e| anyhow::anyhow!("invalid state sync config: {}", e))?;

    if Path::new(state_full_path).exists() {
        debug!("state_full.json already exists, skipping restore");
        return Ok(false);
    }
    if peers.is_empty() {
        debug!("no peers provided for state sync");
        return Ok(false);
    }

    info!(peer_count = peers.len(), "starting P2P state sync");

    let local_key = libp2p::identity::Keypair::generate_ed25519();
    let peer_id = PeerId::from(local_key.public());

    let transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
        .upgrade(upgrade::Version::V1)
        .authenticate(
            noise::Config::new(&local_key).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?,
        )
        .multiplex(yamux::Config::default())
        .boxed();

    let protocols = vec![(proto_state(), ProtocolSupport::Full)];
    let mut rr_cfg = request_response::Config::default();
    rr_cfg.set_request_timeout(Duration::from_secs(config.request_timeout_secs.max(3)));
    let rr = RequestResponse::with_codec(Codec, protocols, rr_cfg);

    let behaviour = Behaviour { rr };
    let mut swarm = Swarm::new(
        transport,
        behaviour,
        peer_id,
        libp2p::swarm::Config::with_tokio_executor(),
    );

    let _ = swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?);
    for addr in peers.iter().cloned() {
        let _ = swarm.dial(addr);
    }

    // Metrics setup
    let metrics = if config.enable_metrics {
        Some(StateSyncMetrics::new()?)
    } else {
        None
    };

    // Phase 1: collect manifests + RTT
    let mut inflight_manifest: BTreeMap<PeerId, Instant> = BTreeMap::new();
    let mut candidates: Vec<Candidate> = vec![];

    let deadline = Instant::now() + Duration::from_secs(config.request_timeout_secs.max(3) * 2);

    while Instant::now() < deadline {
        let ev = timeout(Duration::from_millis(250), swarm.select_next_some()).await;
        let Ok(ev) = ev else {
            continue;
        };

        match ev {
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                debug!(%peer_id, "statesync: connection established");
                let req = Req::State(StateReq::Manifest(StateManifestRequest {}));
                inflight_manifest.insert(peer_id, Instant::now());
                swarm.behaviour_mut().rr.send_request(&peer_id, req);
            }
            SwarmEvent::Behaviour(BehaviourEvent::Rr(RequestResponseEvent::Message {
                peer,
                message,
            })) => {
                if let RequestResponseMessage::Response { response, .. } = message {
                    if let Resp::State(StateResp::Manifest(m)) = response {
                        let start = inflight_manifest.remove(&peer);
                        let rtt_ms = start
                            .map(|s| s.elapsed().as_millis() as u64)
                            .unwrap_or(9_999);
                        if m.height > 0
                            && m.total_bytes > 0
                            && m.chunk_size > 0
                            && !m.chunk_hashes.is_empty()
                        {
                            candidates.push(Candidate {
                                peer,
                                mani: m,
                                rtt_ms,
                                throughput_bps: 0,
                            });
                            if let Some(metrics) = &metrics {
                                metrics.manifests_received.inc();
                            }
                        } else {
                            debug!(%peer, "statesync: invalid manifest, ignoring");
                        }
                    }
                }
            }
            _ => {}
        }

        if candidates.len() >= config.max_candidates {
            debug!("statesync: collected enough candidates, stopping discovery");
            break;
        }
    }

    if candidates.is_empty() {
        warn!("statesync: no valid snapshot manifests found");
        return Ok(false);
    }

    // Prefer best height; keep only peers at that height.
    candidates.sort_by(|a, b| {
        b.mani
            .height
            .cmp(&a.mani.height)
            .then_with(|| a.rtt_ms.cmp(&b.rtt_ms))
    });
    let best_height = candidates[0].mani.height;
    let mut best: Vec<Candidate> = candidates
        .into_iter()
        .filter(|c| c.mani.height == best_height)
        .collect();

    if let Some(metrics) = &metrics {
        metrics.active_peers.set(best.len() as f64);
    }

    // Throughput probe (best-effort) on a few best RTT peers.
    for c in best.iter_mut().take(3) {
        let tp =
            probe_throughput_bps(&mut swarm, c.peer, c.mani.height, config.probe_len, config.request_timeout_secs).await;
        c.throughput_bps = tp;
        debug!(%c.peer, throughput = tp, "statesync: throughput probe");
    }

    // Final ordering: throughput desc, then RTT asc (height is equal here).
    best.sort_by(|a, b| {
        b.throughput_bps
            .cmp(&a.throughput_bps)
            .then_with(|| a.rtt_ms.cmp(&b.rtt_ms))
    });

    let manifest = best[0].mani.clone();

    let snap_dir = snapshots::snapshots_dir(data_dir);
    std::fs::create_dir_all(&snap_dir)?;

    // --- Delta sync fast-path (delta chains) ---
    if let Ok(Some(local_h)) = snapshots::latest_snapshot_height(data_dir) {
        if local_h > 0 && local_h < manifest.height {
            info!(
                from = local_h,
                to = manifest.height,
                "statesync: attempting delta-chain sync"
            );
            if let Some(metrics) = &metrics {
                metrics.delta_sync_attempts.inc();
            }

            // Collect state indexes from a few best peers.
            let mut all_edges: Vec<(u64, u64)> = vec![];
            let mut edge_peers: HashMap<(u64, u64), Vec<PeerId>> = HashMap::new();

            for c in best.iter().take(6) {
                let peer = c.peer;
                swarm
                    .behaviour_mut()
                    .rr
                    .send_request(&peer, Req::State(StateReq::Index(StateIndexRequest {})));
                if let Some(ix) = wait_for_state_index_response(&mut swarm, peer, config.request_timeout_secs).await {
                    for e in ix.delta_edges {
                        all_edges.push(e);
                        edge_peers.entry(e).or_default().push(peer);
                    }
                } else {
                    if let Some(metrics) = &metrics {
                        metrics.peer_timeouts.inc();
                    }
                }
            }

            all_edges.sort_unstable();
            all_edges.dedup();

            if let Some(path) = find_delta_path(&all_edges, local_h, manifest.height) {
                info!(hops = path.len(), "statesync: found delta path");
                // Load base snapshot state.
                let mut state = snapshots::read_snapshot_state(data_dir, local_h)?;

                let mut ok = true;
                for (from_h, to_h) in path {
                    // Choose a peer for this edge: prefer highest throughput, then lowest RTT.
                    let peers_for_edge = edge_peers.get(&(from_h, to_h)).cloned().unwrap_or_default();
                    let mut chosen: Option<PeerId> = None;
                    let mut chosen_score: (u64, u64) = (0, u64::MAX); // (throughput, rtt)
                    for p in peers_for_edge {
                        if let Some(c) = best.iter().find(|c| c.peer == p) {
                            let score = (c.throughput_bps, c.rtt_ms);
                            if score.0 > chosen_score.0
                                || (score.0 == chosen_score.0 && score.1 < chosen_score.1)
                            {
                                chosen = Some(p);
                                chosen_score = score;
                            }
                        } else {
                            // Unknown peer; still usable.
                            chosen = Some(p);
                        }
                    }
                    let Some(peer) = chosen else {
                        warn!(
                            from = from_h,
                            to = to_h,
                            "statesync: no peer for delta edge; falling back"
                        );
                        ok = false;
                        break;
                    };

                    // Request delta manifest
                    swarm.behaviour_mut().rr.send_request(
                        &peer,
                        Req::State(StateReq::DeltaManifest(DeltaManifestRequest {
                            from_height: from_h,
                            to_height: to_h,
                        })),
                    );
                    let Some(dm) =
                        wait_for_delta_manifest_response(&mut swarm, peer, config.request_timeout_secs).await
                    else {
                        warn!(
                            from = from_h,
                            to = to_h,
                            "statesync: delta manifest timeout; falling back"
                        );
                        if let Some(metrics) = &metrics {
                            metrics.peer_timeouts.inc();
                        }
                        ok = false;
                        break;
                    };
                    if dm.total_bytes == 0 || dm.chunk_hashes.is_empty() {
                        warn!(
                            from = from_h,
                            to = to_h,
                            "statesync: invalid delta manifest; falling back"
                        );
                        ok = false;
                        break;
                    }

                    // Download & verify delta file.
                    let tmp_delta = format!("{}/statesync_delta_{}_{}.zst", snap_dir, from_h, to_h);
                    let mut f = std::fs::OpenOptions::new()
                        .create(true)
                        .write(true)
                        .truncate(true)
                        .open(&tmp_delta)?;
                    let mut off = 0u64;
                    while off < dm.total_bytes {
                        let len = (dm.chunk_size as u64).min(dm.total_bytes - off) as u32;
                        swarm.behaviour_mut().rr.send_request(
                            &peer,
                            Req::State(StateReq::DeltaChunk(DeltaChunkRequest {
                                from_height: from_h,
                                to_height: to_h,
                                offset: off,
                                len,
                            })),
                        );
                        let Some(chunk) =
                            wait_for_delta_chunk_response(&mut swarm, peer, off, config.request_timeout_secs).await
                        else {
                            warn!(
                                from = from_h,
                                to = to_h,
                                offset = off,
                                "statesync: delta chunk timeout; falling back"
                            );
                            if let Some(metrics) = &metrics {
                                metrics.peer_timeouts.inc();
                            }
                            ok = false;
                            break;
                        };
                        if !verify_delta_chunk_hash(&dm, off, &chunk.data) {
                            warn!(
                                from = from_h,
                                to = to_h,
                                offset = off,
                                "statesync: delta chunk hash mismatch; falling back"
                            );
                            if let Some(metrics) = &metrics {
                                metrics.chunk_verification_failures.inc();
                            }
                            ok = false;
                            break;
                        }
                        use std::io::Write;
                        f.write_all(&chunk.data)?;
                        if let Some(metrics) = &metrics {
                            metrics.bytes_downloaded.inc_by(chunk.data.len() as u64);
                        }
                        off = off.saturating_add(chunk.data.len() as u64);
                        if chunk.done {
                            break;
                        }
                    }
                    if !ok {
                        break;
                    }

                    let bytes = std::fs::read(&tmp_delta)?;
                    let json = zstd::decode_all(&bytes[..])
                        .map_err(|e| anyhow::anyhow!("delta decode: {e}"))?;
                    let delta: snapshots::StateDelta = serde_json::from_slice(&json)
                        .map_err(|e| anyhow::anyhow!("delta json: {e}"))?;
                    state = snapshots::apply_delta(&state, &delta);
                    let got_root = hex::encode(state.root().0);
                    if got_root != dm.to_state_root_hex {
                        warn!(
                            from = from_h,
                            to = to_h,
                            "statesync: delta root mismatch; falling back"
                        );
                        ok = false;
                        break;
                    }
                }

                // If we successfully applied the chain, persist state_full.
                if ok {
                    let root_ok = match &manifest.state_root_hex {
                        Some(r) => hex::encode(state.root().0) == *r,
                        None => true,
                    };
                    if root_ok {
                        let json = serde_json::to_vec(&state)?;
                        std::fs::write(state_full_path, json)?;
                        info!(
                            height = manifest.height,
                            "statesync: delta-chain sync completed"
                        );
                        if let Some(metrics) = &metrics {
                            metrics.delta_sync_successes.inc();
                        }
                        return Ok(true);
                    } else {
                        warn!(
                            expected = ?manifest.state_root_hex,
                            "statesync: final state root mismatch after delta chain"
                        );
                    }
                }
            } else {
                warn!(
                    from = local_h,
                    to = manifest.height,
                    "statesync: no delta path; falling back to full snapshot"
                );
            }
        }
    }

    // Full snapshot download (fallback or no local snapshot)
    if let Some(metrics) = &metrics {
        metrics.full_snapshot_downloads.inc();
    }

    let req_chunk = (manifest.chunk_size as usize).min(config.max_chunk_bytes.max(1));
    if req_chunk != manifest.chunk_size as usize {
        warn!(
            manifest_chunk = manifest.chunk_size,
            local_chunk = config.max_chunk_bytes as u32,
            "statesync: local chunk_bytes differs; using manifest chunk_size for correctness"
        );
    }

    let tmp_path = format!("{}/statesync_{}.zst", snap_dir, manifest.height);

    // Resume info (verify full chunks; keep partial tail)
    let mut resume = resume_info(&tmp_path, &manifest)?;
    info!(
        height = manifest.height,
        bytes = manifest.total_bytes,
        chunk_start = resume.chunk_start,
        partial_len = resume.partial_len,
        peers = best.len(),
        "statesync: starting full snapshot download"
    );

    use std::io::{Read, Seek, SeekFrom, Write};
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(&tmp_path)?;

    // Ensure file length matches resume state
    let cur_len = std::fs::metadata(&tmp_path)?.len();
    if cur_len < resume.chunk_start + resume.partial_len {
        resume = ResumeInfo {
            chunk_start: (cur_len / manifest.chunk_size as u64) * manifest.chunk_size as u64,
            partial_len: cur_len % manifest.chunk_size as u64,
        };
    }

    let total = manifest.total_bytes;
    let cs = manifest.chunk_size as u64;

    // If we have a partial tail, complete it first by requesting only the missing bytes.
    let mut offset = resume.chunk_start;
    if resume.partial_len > 0 && offset < total {
        let tail_off = offset + resume.partial_len;
        let missing = (cs - resume.partial_len).min(total.saturating_sub(tail_off));
        let mut peer_idx = 0usize;

        'tail: loop {
            if peer_idx >= best.len() {
                warn!(offset = tail_off, "statesync: no peers left to complete partial tail");
                return Ok(false);
            }
            let peer = best[peer_idx].peer;
            let req = Req::State(StateReq::Chunk(StateChunkRequest {
                height: manifest.height,
                offset: tail_off,
                len: missing as u32,
            }));
            swarm.behaviour_mut().rr.send_request(&peer, req);

            let Some(chunk) =
                wait_for_state_chunk_response(&mut swarm, peer, tail_off, config.request_timeout_secs).await
            else {
                warn!(%peer, offset = tail_off, "statesync: tail timeout; switching peer");
                if let Some(metrics) = &metrics {
                    metrics.peer_timeouts.inc();
                }
                peer_idx += 1;
                continue;
            };

            f.seek(SeekFrom::Start(tail_off))?;
            f.write_all(&chunk.data)?;
            f.flush()?;
            if let Some(metrics) = &metrics {
                metrics.bytes_downloaded.inc_by(chunk.data.len() as u64);
            }

            // Verify assembled full chunk (read from disk).
            if (tail_off + chunk.data.len() as u64) >= (offset + cs).min(total) {
                let want_len = ((total - offset).min(cs)) as usize;
                let mut buf = vec![0u8; want_len];
                f.seek(SeekFrom::Start(offset))?;
                f.read_exact(&mut buf)?;
                if want_len == manifest.chunk_size as usize || (offset + want_len as u64) == total {
                    if want_len == manifest.chunk_size as usize
                        && !verify_full_chunk_hash(&manifest, offset, &buf)
                    {
                        warn!(%peer, chunk_start = offset, "statesync: assembled chunk hash mismatch; re-requesting whole chunk");
                        if let Some(metrics) = &metrics {
                            metrics.chunk_verification_failures.inc();
                        }
                        peer_idx += 1;
                        continue 'tail;
                    }
                }
            }

            // Tail done; advance to next chunk boundary
            offset += cs.min(total - offset);
            break;
        }
    }

    // Download remaining full chunks.
    let mut peer_idx = 0;
    while offset < total {
        if peer_idx >= best.len() {
            warn!(offset, "statesync: no peers left to try");
            return Ok(false);
        }
        let peer = best[peer_idx].peer;

        let len = (total - offset).min(cs) as u32;
        let req = Req::State(StateReq::Chunk(StateChunkRequest {
            height: manifest.height,
            offset,
            len,
        }));
        swarm.behaviour_mut().rr.send_request(&peer, req);

        let Some(chunk) = wait_for_state_chunk_response(&mut swarm, peer, offset, config.request_timeout_secs).await
        else {
            warn!(%peer, offset, "statesync: chunk timeout; switching peer");
            if let Some(metrics) = &metrics {
                metrics.peer_timeouts.inc();
            }
            peer_idx += 1;
            continue;
        };

        if (len as u64) == cs && !verify_full_chunk_hash(&manifest, offset, &chunk.data) {
            warn!(%peer, offset, "statesync: chunk hash mismatch; switching peer");
            if let Some(metrics) = &metrics {
                metrics.chunk_verification_failures.inc();
            }
            peer_idx += 1;
            continue;
        }

        f.seek(SeekFrom::Start(offset))?;
        f.write_all(&chunk.data)?;
        f.flush()?;
        if let Some(metrics) = &metrics {
            metrics.bytes_downloaded.inc_by(chunk.data.len() as u64);
        }

        offset += chunk.data.len() as u64;
        peer_idx = 0; // reset to best peer on success

        if chunk.done {
            break;
        }
    }

    drop(f);

    // Final file hash verify.
    let bytes = std::fs::read(&tmp_path)?;
    let final_hash = blake3::hash(&bytes);
    let final_hash_hex = hex::encode(final_hash.as_bytes());
    if !manifest.blake3_hex.is_empty() && manifest.blake3_hex != final_hash_hex {
        warn!(
            expected = %manifest.blake3_hex,
            got = %final_hash_hex,
            "statesync: final file hash mismatch"
        );
        return Ok(false);
    }

    // Materialize canonical state_full.json by decoding snapshot.
    let json = zstd::decode_all(&bytes[..])?;
    let _state: crate::execution::KvState = serde_json::from_slice(&json)?;
    std::fs::write(state_full_path, json)?;

    info!(
        height = manifest.height,
        "statesync: state_full.json restored via P2P snapshot"
    );
    Ok(true)
}
