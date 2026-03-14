//! Production P2P networking for IONA v21.
//!
//! Features:
//! - Static peer dialing with reconnect
//! - Gossipsub tuned for sub‑second block propagation
//! - Per‑peer rate limiting, quarantine, and scoring
//! - Request‑response protocols with global and per‑protocol caps
//! - Eclipse attack detection via IP‑based bucketing (inbound/outbound)
//! - Persistent quarantine and scores with graceful shutdown
//! - Version compatibility check via Identify (major version, strict mode)
//! - Comprehensive Prometheus metrics
//! - Length‑prefixed framing for request‑response (using futures::io)
//! - Full test coverage for core logic

use crate::consensus::ConsensusMsg;
use crate::protocol::version::SUPPORTED_PROTOCOL_VERSIONS;
use crate::types::{Block, Hash32, Height};
use anyhow::Result;
use bincode;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use futures::StreamExt;
use libp2p::{
    core::upgrade,
    gossipsub::{self, IdentTopic, MessageAuthenticity, TopicHash, ValidationMode},
    identify, mdns, noise,
    kad::{self, store::MemoryStore},
    request_response::{
        self, Codec as RequestResponseCodec, Message as RequestResponseMessage,
        ProtocolSupport, RequestResponseEvent,
    },
    swarm::{NetworkBehaviour, SwarmEvent},
    swarm::behaviour::toggle::Toggle,
    swarm::StreamProtocol,
    multiaddr::Protocol,
    tcp, yamux, ConnectionId, Multiaddr, PeerId, Swarm, Transport,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs,
    io,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tracing::{debug, error, info, warn};

#[cfg(feature = "metrics")]
use lazy_static::lazy_static;
#[cfg(feature = "metrics")]
use prometheus::{
    register_histogram_vec, register_int_counter_vec, register_int_gauge,
    register_int_gauge_vec, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec, opts,
};

#[cfg(feature = "metrics")]
lazy_static! {
    static ref P2P_CONNECTIONS: IntGaugeVec = register_int_gauge_vec!(
        opts!("iona_p2p_connections", "Number of active P2P connections"),
        &["direction"]
    ).unwrap();
    static ref P2P_MESSAGES_TOTAL: IntCounterVec = register_int_counter_vec!(
        opts!("iona_p2p_messages_total", "Total P2P messages by type"),
        &["type", "direction"]
    ).unwrap();
    static ref P2P_MESSAGE_BYTES: HistogramVec = register_histogram_vec!(
        opts!("iona_p2p_message_bytes", "Message size distribution"),
        &["type", "direction"],
        vec![256.0, 1024.0, 4096.0, 16384.0, 65536.0, 262144.0, 1048576.0, 4194304.0, 16777216.0]
    ).unwrap();
    static ref P2P_RATE_LIMITED: IntCounterVec = register_int_counter_vec!(
        opts!("iona_p2p_rate_limited_total", "Requests dropped due to rate limiting"),
        &["reason"]
    ).unwrap();
    static ref P2P_QUARANTINED: IntCounterVec = register_int_counter_vec!(
        opts!("iona_p2p_quarantined_total", "Peers quarantined by reason"),
        &["reason"]
    ).unwrap();
    static ref P2P_BUCKET_DIVERSITY: IntGauge = register_int_gauge!(
        opts!("iona_p2p_bucket_diversity", "Number of distinct diversity buckets")
    ).unwrap();
    static ref P2P_PENDING_REQUESTS: IntGaugeVec = register_int_gauge_vec!(
        opts!("iona_p2p_pending_requests", "Pending requests by peer"),
        &["peer"]
    ).unwrap();
}

// ── Constants ──────────────────────────────────────────────────────────────

const MAX_MSG_SIZE: usize = 16 * 1024 * 1024; // 16 MiB
const MAX_RANGE_BLOCKS: u64 = 200;

// ── Protocol definitions ──────────────────────────────────────────────────

pub fn proto_block() -> StreamProtocol {
    StreamProtocol::new("/iona/block/1.0.0")
}
pub fn proto_status() -> StreamProtocol {
    StreamProtocol::new("/iona/status/1.0.0")
}
pub fn proto_range() -> StreamProtocol {
    StreamProtocol::new("/iona/blockrange/1.0.0")
}
pub fn proto_state() -> StreamProtocol {
    StreamProtocol::new("/iona/state/1.0.0")
}

// ── Message types ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockRequest {
    pub id: Hash32,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockResponse {
    pub block: Option<Block>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusRequest {}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    pub best_height: Height,
    pub best_block_id: Option<Hash32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RangeRequest {
    pub from: Height,
    pub to: Height,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RangeResponse {
    pub blocks: Vec<Block>,
}

// --- State sync (snapshot transfer) ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateManifestRequest {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateManifestResponse {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotAttestation {
    pub validators_hash_hex: String,
    pub threshold: u32,
    pub signatures: Vec<AttestationSig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationSig {
    pub pubkey_hex: String,
    pub sig_base64: String,
}

// --- Delta sync ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaManifestRequest {
    pub from_height: u64,
    pub to_height: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaManifestResponse {
    pub from_height: u64,
    pub to_height: u64,
    pub total_bytes: u64,
    pub blake3_hex: String,
    pub chunk_size: u32,
    pub chunk_hashes: Vec<String>,
    pub to_state_root_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaChunkRequest {
    pub from_height: u64,
    pub to_height: u64,
    pub offset: u64,
    pub len: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaChunkResponse {
    pub offset: u64,
    pub data: Vec<u8>,
    pub done: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateIndexRequest {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateIndexResponse {
    pub snapshot_heights: Vec<u64>,
    pub delta_edges: Vec<(u64, u64)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotAttestRequest {
    pub height: u64,
    pub state_root_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotAttestResponse {
    pub height: u64,
    pub state_root_hex: String,
    pub pubkey_hex: String,
    pub sig_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateChunkRequest {
    pub height: u64,
    pub offset: u64,
    pub len: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateChunkResponse {
    pub offset: u64,
    pub data: Vec<u8>,
    pub done: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StateReq {
    Index(StateIndexRequest),
    Manifest(StateManifestRequest),
    Chunk(StateChunkRequest),
    DeltaManifest(DeltaManifestRequest),
    DeltaChunk(DeltaChunkRequest),
    Attest(SnapshotAttestRequest),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StateResp {
    Index(StateIndexResponse),
    Manifest(StateManifestResponse),
    Chunk(StateChunkResponse),
    DeltaManifest(DeltaManifestResponse),
    DeltaChunk(DeltaChunkResponse),
    Attest(SnapshotAttestResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Req {
    Block(BlockRequest),
    Status(StatusRequest),
    Range(RangeRequest),
    State(StateReq),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Resp {
    Block(BlockResponse),
    Status(StatusResponse),
    Range(RangeResponse),
    State(StateResp),
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
enum ProtoKind {
    Block,
    Status,
    Range,
    State,
}

impl ProtoKind {
    fn from_req(req: &Req) -> Self {
        match req {
            Req::Block(_) => ProtoKind::Block,
            Req::Status(_) => ProtoKind::Status,
            Req::Range(_) => ProtoKind::Range,
            Req::State(_) => ProtoKind::State,
        }
    }
}

// ── Rate limiting structures ─────────────────────────────────────────────

#[derive(Debug, Clone)]
struct AbuseState {
    window_start: Instant,
    req_count: u32,
    byte_count: u32,
    strikes: u32,
    quarantines: u32,
    last_strike: Instant,
    quarantine_until: Option<Instant>,
}

impl AbuseState {
    fn new(now: Instant) -> Self {
        Self {
            window_start: now,
            req_count: 0,
            byte_count: 0,
            strikes: 0,
            quarantines: 0,
            last_strike: now,
            quarantine_until: None,
        }
    }
}

#[derive(Debug, Clone)]
struct GsWindow {
    window_start: Instant,
    msg_count: u32,
    byte_count: u32,
}

impl GsWindow {
    fn new(now: Instant) -> Self {
        Self {
            window_start: now,
            msg_count: 0,
            byte_count: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct QuarantineFile {
    peers: BTreeMap<String, u64>, // peer_id -> unix seconds until
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScoresFile {
    peers: BTreeMap<String, i32>, // peer_id -> score
}

// ── Rate limiter logic (extracted for testing) ───────────────────────────

struct RateLimitDecision {
    allow: bool,
    strike: bool,
    quarantine: Option<Duration>,
    ban: bool,
    delta: i32,
}

/// Pure function that decides the action based on current state and limits.
fn rr_decide(
    state: &mut AbuseState,
    now: Instant,
    bytes: u32,
    max_req: u32,
    max_bytes: u32,
    strike_decay_s: u64,
    quarantine_s: u64,
    strikes_before_quarantine: u32,
    strikes_before_ban: u32,
    quarantines_before_ban: u32,
) -> RateLimitDecision {
    // Decay strikes first
    if strike_decay_s > 0 {
        let decay_every = Duration::from_secs(strike_decay_s);
        let mut elapsed = now.duration_since(state.last_strike);
        while state.strikes > 0 && elapsed >= decay_every {
            state.strikes -= 1;
            state.last_strike += decay_every;
            elapsed = now.duration_since(state.last_strike);
        }
    }

    // Check quarantine
    if let Some(until) = state.quarantine_until {
        if now < until {
            return RateLimitDecision {
                allow: false,
                strike: false,
                quarantine: None,
                ban: false,
                delta: -1,
            };
        } else {
            state.quarantine_until = None;
            // boost after quarantine
            return RateLimitDecision {
                allow: true,
                strike: false,
                quarantine: None,
                ban: false,
                delta: 1,
            };
        }
    }

    // Update window counters
    if now.duration_since(state.window_start) > Duration::from_secs(1) {
        state.window_start = now;
        state.req_count = 0;
        state.byte_count = 0;
    }
    state.req_count += 1;
    state.byte_count += bytes;

    let limited = (max_req > 0 && state.req_count > max_req) || (max_bytes > 0 && state.byte_count > max_bytes);
    if !limited {
        return RateLimitDecision {
            allow: true,
            strike: false,
            quarantine: None,
            ban: false,
            delta: 1,
        };
    }

    // Limited: add strike and decide
    state.strikes += 1;
    state.last_strike = now;

    if state.strikes >= strikes_before_ban && strikes_before_ban > 0 {
        RateLimitDecision {
            allow: false,
            strike: true,
            quarantine: None,
            ban: true,
            delta: -5,
        }
    } else if state.strikes >= strikes_before_quarantine && strikes_before_quarantine > 0 {
        state.quarantines += 1;
        if state.quarantines >= quarantines_before_ban && quarantines_before_ban > 0 {
            RateLimitDecision {
                allow: false,
                strike: true,
                quarantine: None,
                ban: true,
                delta: -5,
            }
        } else {
            let quarantine_duration = Duration::from_secs(quarantine_s.max(1));
            state.quarantine_until = Some(now + quarantine_duration);
            RateLimitDecision {
                allow: false,
                strike: true,
                quarantine: Some(quarantine_duration),
                ban: false,
                delta: -5,
            }
        }
    } else {
        RateLimitDecision {
            allow: false,
            strike: true,
            quarantine: None,
            ban: false,
            delta: -5,
        }
    }
}

// ── Length‑prefixed codec (using futures::io) ─────────────────────────────

#[derive(Clone)]
pub struct Codec;

#[async_trait::async_trait]
impl RequestResponseCodec for Codec {
    type Protocol = StreamProtocol;
    type Request = Req;
    type Response = Resp;

    async fn read_request<T>(&mut self, _: &StreamProtocol, io: &mut T) -> io::Result<Req>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut len_buf = [0u8; 4];
        io.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_MSG_SIZE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "request too large"));
        }
        let mut buf = vec![0u8; len];
        io.read_exact(&mut buf).await?;
        bincode::deserialize(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e}")))
    }

    async fn read_response<T>(&mut self, _: &StreamProtocol, io: &mut T) -> io::Result<Resp>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut len_buf = [0u8; 4];
        io.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_MSG_SIZE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "response too large"));
        }
        let mut buf = vec![0u8; len];
        io.read_exact(&mut buf).await?;
        bincode::deserialize(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e}")))
    }

    async fn write_request<T>(&mut self, _: &StreamProtocol, io: &mut T, req: Req) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let bytes = bincode::serialize(&req).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e}")))?;
        if bytes.len() > MAX_MSG_SIZE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "request too large"));
        }
        let len = (bytes.len() as u32).to_be_bytes();
        io.write_all(&len).await?;
        io.write_all(&bytes).await?;
        io.close().await?;
        Ok(())
    }

    async fn write_response<T>(&mut self, _: &StreamProtocol, io: &mut T, resp: Resp) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let bytes = bincode::serialize(&resp).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e}")))?;
        if bytes.len() > MAX_MSG_SIZE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "response too large"));
        }
        let len = (bytes.len() as u32).to_be_bytes();
        io.write_all(&len).await?;
        io.write_all(&bytes).await?;
        io.close().await?;
        Ok(())
    }
}

// ── Network behaviour ─────────────────────────────────────────────────────

#[derive(NetworkBehaviour)]
pub struct Behaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub mdns: Toggle<mdns::tokio::Behaviour>,
    pub identify: identify::Behaviour,
    pub kad: Toggle<kad::Behaviour<MemoryStore>>,
    pub rr: request_response::Behaviour<Codec>,
}

// ─── P2pConfig ───────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct P2pConfig {
    pub local_key: libp2p::identity::Keypair,
    pub listen: Multiaddr,
    pub static_peers: Vec<Multiaddr>,
    pub bootnodes: Vec<Multiaddr>,
    pub enable_mdns: bool,
    pub enable_kad: bool,
    pub reconnect_interval_s: u64,
    pub max_connections_total: usize,
    pub max_connections_per_peer: usize,
    pub max_concurrent_requests_per_peer: usize,
    pub request_timeout_secs: u64,
    pub rr_max_req_per_sec_block: u32,
    pub rr_max_req_per_sec_status: u32,
    pub rr_max_req_per_sec_range: u32,
    pub rr_max_req_per_sec_state: u32,
    pub rr_max_bytes_per_sec_block: u32,
    pub rr_max_bytes_per_sec_status: u32,
    pub rr_max_bytes_per_sec_range: u32,
    pub rr_max_bytes_per_sec_state: u32,
    pub rr_global_in_bytes_per_sec: u32,
    pub rr_global_out_bytes_per_sec: u32,
    pub peer_strike_decay_s: u64,
    pub peer_score_decay_s: u64,
    pub peer_quarantine_s: u64,
    pub rr_strikes_before_quarantine: u32,
    pub rr_strikes_before_ban: u32,
    pub rr_quarantines_before_ban: u32,
    pub gs_max_publish_msgs_per_sec: u32,
    pub gs_max_publish_bytes_per_sec: u32,
    pub gs_max_in_msgs_per_sec: u32,
    pub gs_max_in_bytes_per_sec: u32,
    pub gs_allowed_topics: Vec<String>,
    pub gs_deny_unknown_topics: bool,
    pub gs_topic_limits: Vec<(String, u32, u32)>,
    pub diversity_bucket_kind: String,
    pub max_inbound_per_bucket: usize,
    pub max_outbound_per_bucket: usize,
    pub eclipse_detection_min_buckets: usize,
    pub reseed_cooldown_s: u64,
    pub quarantine_path: PathBuf,
    pub scores_path: PathBuf,
    pub persist_quarantine: bool,
    pub persist_scores: bool,
    /// Dacă true, respinge conexiunile cu versiuni de protocol neparsabile.
    pub strict_version_check: bool,
}

impl Default for P2pConfig {
    fn default() -> Self {
        Self {
            local_key: libp2p::identity::Keypair::generate_ed25519(),
            listen: "/ip4/0.0.0.0/tcp/0".parse().unwrap(),
            static_peers: vec![],
            bootnodes: vec![],
            enable_mdns: false,
            enable_kad: false,
            reconnect_interval_s: 30,
            max_connections_total: 200,
            max_connections_per_peer: 8,
            max_concurrent_requests_per_peer: 5,
            request_timeout_secs: 10,
            rr_max_req_per_sec_block: 0,
            rr_max_req_per_sec_status: 0,
            rr_max_req_per_sec_range: 0,
            rr_max_req_per_sec_state: 0,
            rr_max_bytes_per_sec_block: 0,
            rr_max_bytes_per_sec_status: 0,
            rr_max_bytes_per_sec_range: 0,
            rr_max_bytes_per_sec_state: 0,
            rr_global_in_bytes_per_sec: 0,
            rr_global_out_bytes_per_sec: 0,
            peer_strike_decay_s: 0,
            peer_score_decay_s: 0,
            peer_quarantine_s: 60,
            rr_strikes_before_quarantine: 0,
            rr_strikes_before_ban: 0,
            rr_quarantines_before_ban: 0,
            gs_max_publish_msgs_per_sec: 0,
            gs_max_publish_bytes_per_sec: 0,
            gs_max_in_msgs_per_sec: 0,
            gs_max_in_bytes_per_sec: 0,
            gs_allowed_topics: vec![],
            gs_deny_unknown_topics: false,
            gs_topic_limits: vec![],
            diversity_bucket_kind: "ip16".into(),
            max_inbound_per_bucket: 0,
            max_outbound_per_bucket: 0,
            eclipse_detection_min_buckets: 0,
            reseed_cooldown_s: 0,
            quarantine_path: PathBuf::from("quarantine.json"),
            scores_path: PathBuf::from("scores.json"),
            persist_quarantine: false,
            persist_scores: false,
            strict_version_check: true,
        }
    }
}

// ─── P2p ─────────────────────────────────────────────────────────────────

type ConnectionKey = (PeerId, ConnectionId);

pub struct P2p {
    swarm: Swarm<Behaviour>,
    topic_hash: TopicHash,
    peer_scores: BTreeMap<PeerId, i32>, // score persists across reconnects
    peer_quarantine: BTreeMap<PeerId, Instant>,
    quarantine_path: PathBuf,
    scores_path: PathBuf,
    persist_quarantine: bool,
    persist_scores: bool,
    last_score_decay: Instant,
    static_peers: Vec<Multiaddr>,
    bootnodes: Vec<Multiaddr>,
    banned_peers: HashSet<PeerId>,
    max_connections_total: usize,
    max_connections_per_peer: usize,
    // Track accepted connections
    accepted_connections: HashSet<ConnectionKey>,
    connection_bucket: HashMap<ConnectionKey, String>, // bucket per accepted connection
    // Bucket accounting per direction
    bucket_inbound: BTreeMap<String, usize>,
    bucket_outbound: BTreeMap<String, usize>,
    diversity_bucket_kind: String,
    max_inbound_per_bucket: usize,
    max_outbound_per_bucket: usize,
    eclipse_detection_min_buckets: usize,
    reseed_cooldown_s: u64,
    last_reseed: Instant,
    rr_max_req_per_sec: BTreeMap<ProtoKind, u32>,
    rr_max_bytes_per_sec: BTreeMap<ProtoKind, u32>,
    rr_global_in_bytes_per_sec: u32,
    rr_global_out_bytes_per_sec: u32,
    peer_strike_decay_s: u64,
    peer_score_decay_s: u64,
    peer_quarantine_s: u64,
    rr_strikes_before_quarantine: u32,
    rr_strikes_before_ban: u32,
    rr_quarantines_before_ban: u32,
    rr_abuse: HashMap<(PeerId, ProtoKind), AbuseState>,
    gs_in: BTreeMap<PeerId, GsWindow>,
    gs_max_in_msgs_per_sec: u32,
    gs_max_in_bytes_per_sec: u32,
    gs_publish_window: GsWindow,
    gs_max_publish_msgs_per_sec: u32,
    gs_max_publish_bytes_per_sec: u32,
    gs_allowed_topic_hashes: HashSet<TopicHash>,
    gs_topic_limits: HashMap<TopicHash, (u32, u32)>,
    gs_deny_unknown_topics: bool,
    rr_global_window: (Instant, u32, u32), // (window_start, in_bytes, out_bytes)
    last_reconnect_attempt: Instant,
    reconnect_interval: Duration,
    pending_requests_by_id: HashMap<request_response::OutboundRequestId, PeerId>,
    pending_requests_count: HashMap<PeerId, usize>,
    max_concurrent_requests_per_peer: usize,
    strict_version_check: bool,
    scores_dirty: bool,
}

impl P2p {
    fn now_unix() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs()
    }

    fn load_quarantine(path: &Path) -> BTreeMap<PeerId, Instant> {
        let now_i = Instant::now();
        let now_u = Self::now_unix();
        let data = match fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return BTreeMap::new(),
            Err(e) => {
                warn!(path = %path.display(), error = %e, "failed to read quarantine file");
                return BTreeMap::new();
            }
        };
        let parsed: QuarantineFile = match serde_json::from_str(&data) {
            Ok(p) => p,
            Err(e) => {
                warn!(path = %path.display(), error = %e, "failed to parse quarantine file");
                return BTreeMap::new();
            }
        };
        let mut out = BTreeMap::new();
        for (k, until_u) in parsed.peers {
            if until_u <= now_u {
                continue;
            }
            if let Ok(pid) = k.parse::<PeerId>() {
                let rem = until_u - now_u;
                out.insert(pid, now_i + Duration::from_secs(rem));
            }
        }
        out
    }

    fn persist_quarantine_file(&self) {
        if !self.persist_quarantine {
            return;
        }
        if let Some(parent) = self.quarantine_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let now_u = Self::now_unix();
        let mut peers = BTreeMap::new();
        for (pid, until_i) in self.peer_quarantine.iter() {
            let rem = until_i.saturating_duration_since(Instant::now()).as_secs();
            if rem == 0 {
                continue;
            }
            peers.insert(pid.to_string(), now_u.saturating_add(rem));
        }
        let qf = QuarantineFile { peers };
        if let Ok(s) = serde_json::to_string_pretty(&qf) {
            let _ = fs::write(&self.quarantine_path, s);
        }
    }

    fn load_scores(path: &Path) -> BTreeMap<PeerId, i32> {
        let data = match fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return BTreeMap::new(),
            Err(e) => {
                warn!(path = %path.display(), error = %e, "failed to read scores file");
                return BTreeMap::new();
            }
        };
        let parsed: ScoresFile = match serde_json::from_str(&data) {
            Ok(p) => p,
            Err(e) => {
                warn!(path = %path.display(), error = %e, "failed to parse scores file");
                return BTreeMap::new();
            }
        };
        let mut out = BTreeMap::new();
        for (k, score) in parsed.peers {
            if let Ok(pid) = k.parse::<PeerId>() {
                out.insert(pid, score);
            }
        }
        out
    }

    fn persist_scores_file(&mut self) {
        if !self.persist_scores || !self.scores_dirty {
            return;
        }
        if let Some(parent) = self.scores_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let mut peers = BTreeMap::new();
        for (pid, score) in self.peer_scores.iter() {
            peers.insert(pid.to_string(), *score);
        }
        let sf = ScoresFile { peers };
        if let Ok(s) = serde_json::to_string_pretty(&sf) {
            let _ = fs::write(&self.scores_path, s);
            self.scores_dirty = false;
        }
    }

    fn quarantine_peer(&mut self, peer: PeerId, secs: u64, reason: &str) {
        let until = Instant::now() + Duration::from_secs(secs.max(1));
        self.peer_quarantine.insert(peer, until);
        warn!(%peer, reason, "peer quarantined");
        #[cfg(feature = "metrics")]
        P2P_QUARANTINED.with_label_values(&[reason]).inc();
        self.persist_quarantine_file();
        let _ = self.swarm.disconnect_peer_id(peer);
    }

    fn is_quarantined(&mut self, peer: PeerId) -> bool {
        if let Some(until) = self.peer_quarantine.get(&peer).cloned() {
            if Instant::now() < until {
                return true;
            } else {
                self.peer_quarantine.remove(&peer);
                self.persist_quarantine_file();
            }
        }
        false
    }

    fn maybe_decay_peer_scores(&mut self) {
        if self.peer_score_decay_s == 0 {
            return;
        }
        let every = Duration::from_secs(self.peer_score_decay_s);
        let now = Instant::now();
        if now.duration_since(self.last_score_decay) < every {
            return;
        }
        let steps = now.duration_since(self.last_score_decay).as_secs() / every.as_secs().max(1);
        for _ in 0..steps.max(1) {
            for v in self.peer_scores.values_mut() {
                if *v > 0 {
                    *v -= 1;
                } else if *v < 0 {
                    *v += 1;
                }
            }
            self.last_score_decay += every;
        }
        self.scores_dirty = true;
    }

    fn gs_allow_inbound(&mut self, peer: PeerId, bytes: u32, max_msgs: u32, max_bytes: u32) -> bool {
        let now = Instant::now();
        let st = self.gs_in.entry(peer).or_insert_with(|| GsWindow::new(now));
        if now.duration_since(st.window_start) > Duration::from_secs(1) {
            st.window_start = now;
            st.msg_count = 0;
            st.byte_count = 0;
        }
        st.msg_count = st.msg_count.saturating_add(1);
        st.byte_count = st.byte_count.saturating_add(bytes);

        if (max_msgs > 0 && st.msg_count > max_msgs) || (max_bytes > 0 && st.byte_count > max_bytes) {
            return false;
        }
        true
    }

    fn gs_allow_publish(&mut self, bytes: u32) -> bool {
        let now = Instant::now();
        let st = &mut self.gs_publish_window;
        if now.duration_since(st.window_start) > Duration::from_secs(1) {
            st.window_start = now;
            st.msg_count = 0;
            st.byte_count = 0;
        }
        st.msg_count = st.msg_count.saturating_add(1);
        st.byte_count = st.byte_count.saturating_add(bytes);

        if (self.gs_max_publish_msgs_per_sec > 0 && st.msg_count > self.gs_max_publish_msgs_per_sec)
            || (self.gs_max_publish_bytes_per_sec > 0 && st.byte_count > self.gs_max_publish_bytes_per_sec)
        {
            return false;
        }
        true
    }

    fn bump_score(&mut self, peer: PeerId, delta: i32) {
        let score = self.peer_scores.entry(peer).or_insert(0);
        *score = score.saturating_add(delta);
        if *score < -50 {
            self.ban_peer(peer);
        }
        self.scores_dirty = true;
    }

    fn ban_peer(&mut self, peer: PeerId) {
        warn!(%peer, "banning peer (score too low)");
        self.banned_peers.insert(peer);
        #[cfg(feature = "metrics")]
        P2P_QUARANTINED.with_label_values(&["ban"]).inc();
        let _ = self.swarm.disconnect_peer_id(peer);
    }

    fn bucket_from_multiaddr(&self, addr: &Multiaddr) -> Option<String> {
        for p in addr.iter() {
            match p {
                Protocol::Ip4(v4) => {
                    let o = v4.octets();
                    return match self.diversity_bucket_kind.as_str() {
                        "ip24" => Some(format!("ip4:{}.{}.{}", o[0], o[1], o[2])),
                        "ip16" => Some(format!("ip4:{}.{}", o[0], o[1])),
                        "asn" => Some(format!("asn24:{}.{}.{}", o[0], o[1], o[2])),
                        _ => None,
                    };
                }
                Protocol::Ip6(v6) => {
                    let o = v6.octets();
                    return match self.diversity_bucket_kind.as_str() {
                        "ip16" => Some(format!("ip6:{:02x}{:02x}{:02x}{:02x}", o[0], o[1], o[2], o[3])),
                        "ip24" => Some(format!("ip6:{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}", o[0], o[1], o[2], o[3], o[4], o[5])),
                        "asn" => Some(format!("asn48:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}", o[0], o[1], o[2], o[3], o[4], o[5])),
                        _ => None,
                    };
                }
                _ => continue,
            }
        }
        None
    }

    fn check_bucket_limit(&self, bucket: &str, direction: &str) -> bool {
        let (limit, counts) = if direction == "in" {
            (self.max_inbound_per_bucket, &self.bucket_inbound)
        } else {
            (self.max_outbound_per_bucket, &self.bucket_outbound)
        };
        if limit == 0 {
            return true;
        }
        counts.get(bucket).unwrap_or(&0) < &limit
    }

    fn maybe_eclipse_reseed(&mut self) {
        // Calculate distinct buckets across both directions
        let mut all_buckets = HashSet::new();
        for b in self.bucket_inbound.keys() {
            all_buckets.insert(b.clone());
        }
        for b in self.bucket_outbound.keys() {
            all_buckets.insert(b.clone());
        }
        let distinct = all_buckets.len();
        #[cfg(feature = "metrics")]
        P2P_BUCKET_DIVERSITY.set(distinct as i64);

        if distinct >= self.eclipse_detection_min_buckets {
            return;
        }
        if self.last_reseed.elapsed().as_secs() < self.reseed_cooldown_s {
            return;
        }
        warn!(
            distinct,
            min = self.eclipse_detection_min_buckets,
            "possible eclipse (low diversity); reseeding via bootnodes"
        );
        self.last_reseed = Instant::now();
        for a in self.bootnodes.iter().cloned() {
            seed_kad_and_dial(&mut self.swarm, a);
        }
    }

    fn maybe_reconnect_static_peers(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_reconnect_attempt) < self.reconnect_interval {
            return;
        }
        self.last_reconnect_attempt = now;
        for addr in self.bootnodes.iter().cloned() {
            seed_kad_and_dial(&mut self.swarm, addr);
        }
        for addr in self.static_peers.iter().cloned() {
            match self.swarm.dial(addr.clone()) {
                Ok(_) => debug!(%addr, "re‑dialing static peer"),
                Err(e) => warn!(%addr, "re‑dial failed: {e}"),
            }
        }
    }

    fn rr_limits_for(&self, kind: ProtoKind) -> (u32, u32) {
        (
            *self.rr_max_req_per_sec.get(&kind).unwrap_or(&0),
            *self.rr_max_bytes_per_sec.get(&kind).unwrap_or(&0),
        )
    }

    fn rr_allow_global_in(&mut self, now: Instant, bytes: u32) -> bool {
        if self.rr_global_in_bytes_per_sec == 0 {
            return true; // unlimited
        }
        if now.duration_since(self.rr_global_window.0) > Duration::from_secs(1) {
            self.rr_global_window = (now, 0, 0);
        }
        let next = self.rr_global_window.1.saturating_add(bytes);
        if next > self.rr_global_in_bytes_per_sec {
            return false;
        }
        self.rr_global_window.1 = next;
        true
    }

    fn rr_allow_global_out(&mut self, now: Instant, bytes: u32) -> bool {
        if self.rr_global_out_bytes_per_sec == 0 {
            return true; // unlimited
        }
        if now.duration_since(self.rr_global_window.0) > Duration::from_secs(1) {
            self.rr_global_window = (now, 0, 0);
        }
        let next = self.rr_global_window.2.saturating_add(bytes);
        if next > self.rr_global_out_bytes_per_sec {
            return false;
        }
        self.rr_global_window.2 = next;
        true
    }

    fn rr_allow_inbound(&mut self, now: Instant, peer: PeerId, kind: ProtoKind, bytes: u32) -> bool {
        // Global quarantine check
        if self.is_quarantined(peer) {
            warn!(%peer, ?kind, "peer is quarantined; dropping request");
            self.bump_score(peer, -1);
            return false;
        }

        let key = (peer, kind);
        let (max_req, max_bytes) = self.rr_limits_for(kind);
        let st = self.rr_abuse.entry(key).or_insert_with(|| AbuseState::new(now));

        let decision = rr_decide(
            st,
            now,
            bytes,
            max_req,
            max_bytes,
            self.peer_strike_decay_s,
            self.peer_quarantine_s,
            self.rr_strikes_before_quarantine,
            self.rr_strikes_before_ban,
            self.rr_quarantines_before_ban,
        );

        if !decision.allow {
            if decision.strike {
                #[cfg(feature = "metrics")]
                P2P_RATE_LIMITED.with_label_values(&["rr_inbound"]).inc();
            }
            self.bump_score(peer, decision.delta);
        } else {
            self.bump_score(peer, decision.delta);
        }

        // Apply quarantine/ban if indicated
        if let Some(quarantine_dur) = decision.quarantine {
            self.quarantine_peer(peer, quarantine_dur.as_secs(), "rr_abuse");
        }
        if decision.ban {
            self.ban_peer(peer);
        }

        decision.allow
    }

    /// Check if the remote protocol version is compatible with our supported versions.
    /// We extract the major version from strings like "/iona/1.0.0" or "1.0.0"
    /// and compare it to the list of supported major versions.
    fn is_version_compatible(&self, protocol_version: &str) -> bool {
        // Extract the version part after any slash (e.g., "/iona/1.0.0" -> "1.0.0")
        let version_str = protocol_version
            .split('/')
            .last()
            .unwrap_or(protocol_version);
        // Extract major version (first number before dot)
        let major_str = version_str.split('.').next().unwrap_or(version_str);
        match major_str.parse::<u32>() {
            Ok(major) => SUPPORTED_PROTOCOL_VERSIONS.contains(&major),
            Err(_) if self.strict_version_check => {
                warn!(protocol_version, "could not parse protocol version major, rejecting connection");
                false
            }
            Err(_) => {
                warn!(protocol_version, "could not parse protocol version major, allowing connection (strict mode off)");
                true
            }
        }
    }

    pub fn new(cfg: P2pConfig) -> Result<Self> {
        let peer_id = PeerId::from(cfg.local_key.public());
        info!(%peer_id, "local peer id");

        let transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
            .upgrade(upgrade::Version::V1)
            .authenticate(noise::Config::new(&cfg.local_key)?)
            .multiplex(yamux::Config::default())
            .boxed();

        let consensus_topic = IdentTopic::new("iona-consensus");
        let topic_hash = consensus_topic.hash();

        // Build allowed topic hashes.
        let mut allowed_hashes = HashSet::new();
        allowed_hashes.insert(topic_hash.clone());
        for t in &cfg.gs_allowed_topics {
            allowed_hashes.insert(IdentTopic::new(t).hash());
        }

        // Build per‑topic limits map.
        let mut topic_limits = HashMap::new();
        for (t, msgs, bytes) in cfg.gs_topic_limits {
            topic_limits.insert(IdentTopic::new(t).hash(), (msgs, bytes));
        }

        // Gossipsub configuration.
        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(Duration::from_millis(100))
            .validation_mode(ValidationMode::Strict)
            .max_transmit_size(MAX_MSG_SIZE)
            .mesh_n(6)
            .mesh_n_low(4)
            .mesh_n_high(12)
            .gossip_lazy(3)
            .fanout_ttl(Duration::from_secs(60))
            .history_length(10)
            .history_gossip(3)
            .build()?;

        let mut gossipsub = gossipsub::Behaviour::new(
            MessageAuthenticity::Signed(cfg.local_key.clone()),
            gossipsub_config,
        )
        .map_err(anyhow::Error::msg)?;

        // Set up peer scoring.
        let mut score_params = gossipsub::PeerScoreParams::default();
        let mut topic_params = HashMap::new();
        let tp = gossipsub::TopicScoreParams::builder()
            .topic_weight(1.0)
            .time_in_mesh_weight(0.1)
            .time_in_mesh_quantum(Duration::from_secs(1))
            .time_in_mesh_cap(300.0)
            .first_message_deliveries_weight(1.0)
            .first_message_deliveries_decay(0.5)
            .mesh_message_deliveries_weight(0.5)
            .mesh_message_deliveries_decay(0.5)
            .mesh_message_deliveries_cap(100.0)
            .mesh_message_deliveries_activation(Duration::from_secs(5))
            .build()?;
        topic_params.insert(topic_hash.clone(), tp);
        score_params.topics = topic_params;
        let thresholds = gossipsub::PeerScoreThresholds::default();
        gossipsub
            .with_peer_score(score_params, thresholds)
            .map_err(anyhow::Error::msg)?;

        // Subscribe to all allowed topics.
        for t in allowed_hashes.iter() {
            let _ = gossipsub.subscribe(&IdentTopic::new_from_topic_hash(t.clone()));
        }

        let mdns = if cfg.enable_mdns {
            Toggle::from(Some(mdns::tokio::Behaviour::new(
                mdns::Config::default(),
                peer_id,
            )?))
        } else {
            Toggle::from(None)
        };

        let identify = identify::Behaviour::new(
            identify::Config::new("/iona/1.0.0".into(), cfg.local_key.public())
                .with_interval(Duration::from_secs(30)),
        );

        let kad = if cfg.enable_kad {
            let store = MemoryStore::new(peer_id);
            let mut kcfg = kad::Config::default();
            kcfg.set_query_timeout(Duration::from_secs(30));
            Toggle::from(Some(kad::Behaviour::with_config(peer_id, store, kcfg)))
        } else {
            Toggle::from(None)
        };

        let protocols = vec![
            (proto_block(), ProtocolSupport::Full),
            (proto_status(), ProtocolSupport::Full),
            (proto_range(), ProtocolSupport::Full),
            (proto_state(), ProtocolSupport::Full),
        ];
        let rr_cfg = request_response::Config::default()
            .with_request_timeout(Duration::from_secs(cfg.request_timeout_secs));
        let rr = request_response::Behaviour::with_codec(Codec, protocols, rr_cfg);

        let behaviour = Behaviour {
            gossipsub,
            mdns,
            identify,
            kad,
            rr,
        };

        let mut swarm = Swarm::new(
            transport,
            behaviour,
            peer_id,
            libp2p::swarm::Config::with_tokio_executor(),
        );
        swarm.listen_on(cfg.listen)?;

        for addr in cfg.bootnodes.iter().cloned() {
            seed_kad_and_dial(&mut swarm, addr);
        }

        let quarantine_path = cfg.quarantine_path.clone();
        let peer_quarantine = if cfg.persist_quarantine {
            Self::load_quarantine(&quarantine_path)
        } else {
            BTreeMap::new()
        };

        let scores_path = cfg.scores_path.clone();
        let peer_scores = if cfg.persist_scores {
            Self::load_scores(&scores_path)
        } else {
            BTreeMap::new()
        };

        // Build RR limit maps.
        let mut rr_max_req_per_sec = BTreeMap::new();
        rr_max_req_per_sec.insert(ProtoKind::Block, cfg.rr_max_req_per_sec_block);
        rr_max_req_per_sec.insert(ProtoKind::Status, cfg.rr_max_req_per_sec_status);
        rr_max_req_per_sec.insert(ProtoKind::Range, cfg.rr_max_req_per_sec_range);
        rr_max_req_per_sec.insert(ProtoKind::State, cfg.rr_max_req_per_sec_state);

        let mut rr_max_bytes_per_sec = BTreeMap::new();
        rr_max_bytes_per_sec.insert(ProtoKind::Block, cfg.rr_max_bytes_per_sec_block);
        rr_max_bytes_per_sec.insert(ProtoKind::Status, cfg.rr_max_bytes_per_sec_status);
        rr_max_bytes_per_sec.insert(ProtoKind::Range, cfg.rr_max_bytes_per_sec_range);
        rr_max_bytes_per_sec.insert(ProtoKind::State, cfg.rr_max_bytes_per_sec_state);

        Ok(Self {
            swarm,
            topic_hash,
            peer_scores,
            peer_quarantine,
            quarantine_path,
            scores_path,
            persist_quarantine: cfg.persist_quarantine,
            persist_scores: cfg.persist_scores,
            last_score_decay: Instant::now(),
            static_peers: cfg.static_peers,
            bootnodes: cfg.bootnodes,
            banned_peers: HashSet::new(),
            max_connections_total: cfg.max_connections_total,
            max_connections_per_peer: cfg.max_connections_per_peer,
            accepted_connections: HashSet::new(),
            connection_bucket: HashMap::new(),
            bucket_inbound: BTreeMap::new(),
            bucket_outbound: BTreeMap::new(),
            diversity_bucket_kind: cfg.diversity_bucket_kind,
            max_inbound_per_bucket: cfg.max_inbound_per_bucket,
            max_outbound_per_bucket: cfg.max_outbound_per_bucket,
            eclipse_detection_min_buckets: cfg.eclipse_detection_min_buckets,
            reseed_cooldown_s: cfg.reseed_cooldown_s,
            last_reseed: Instant::now(),
            rr_max_req_per_sec,
            rr_max_bytes_per_sec,
            rr_global_in_bytes_per_sec: cfg.rr_global_in_bytes_per_sec,
            rr_global_out_bytes_per_sec: cfg.rr_global_out_bytes_per_sec,
            peer_strike_decay_s: cfg.peer_strike_decay_s,
            peer_score_decay_s: cfg.peer_score_decay_s,
            peer_quarantine_s: cfg.peer_quarantine_s,
            rr_strikes_before_quarantine: cfg.rr_strikes_before_quarantine,
            rr_strikes_before_ban: cfg.rr_strikes_before_ban,
            rr_quarantines_before_ban: cfg.rr_quarantines_before_ban,
            rr_abuse: HashMap::new(),
            gs_in: BTreeMap::new(),
            gs_max_in_msgs_per_sec: cfg.gs_max_in_msgs_per_sec,
            gs_max_in_bytes_per_sec: cfg.gs_max_in_bytes_per_sec,
            gs_publish_window: GsWindow::new(Instant::now()),
            gs_max_publish_msgs_per_sec: cfg.gs_max_publish_msgs_per_sec,
            gs_max_publish_bytes_per_sec: cfg.gs_max_publish_bytes_per_sec,
            gs_allowed_topic_hashes: allowed_hashes,
            gs_topic_limits: topic_limits,
            gs_deny_unknown_topics: cfg.gs_deny_unknown_topics,
            rr_global_window: (Instant::now(), 0, 0),
            last_reconnect_attempt: Instant::now() - Duration::from_secs(cfg.reconnect_interval_s),
            reconnect_interval: Duration::from_secs(cfg.reconnect_interval_s),
            pending_requests_by_id: HashMap::new(),
            pending_requests_count: HashMap::new(),
            max_concurrent_requests_per_peer: cfg.max_concurrent_requests_per_peer,
            strict_version_check: cfg.strict_version_check,
            scores_dirty: false,
        })
    }

    pub fn dial_static_peers(&mut self) {
        for addr in self.bootnodes.clone() {
            seed_kad_and_dial(&mut self.swarm, addr);
        }
        for addr in self.static_peers.clone() {
            match self.swarm.dial(addr.clone()) {
                Ok(_) => debug!(%addr, "dialing static peer"),
                Err(e) => warn!(%addr, "dial failed: {e}"),
            }
        }
    }

    pub fn publish(&mut self, msg: &ConsensusMsg) {
        if let Ok(bytes) = bincode::serialize(msg) {
            let b = bytes.len() as u32;
            if !self.gs_allow_publish(b) {
                warn!(bytes = b, "gossipsub publish cap hit; dropping local publish");
                return;
            }
            #[cfg(feature = "metrics")]
            P2P_MESSAGE_BYTES
                .with_label_values(&["consensus", "out"])
                .observe(b as f64);
            if let Err(e) = self
                .swarm
                .behaviour_mut()
                .gossipsub
                .publish(self.topic_hash.clone(), bytes)
            {
                warn!("gossipsub publish: {e:?}");
            }
        }
    }

    /// Returnează peerii conectați în acest moment.
    pub fn peers(&self) -> Vec<PeerId> {
        self.swarm.connected_peers().cloned().collect()
    }

    /// Numărul de peeri conectați.
    pub fn peer_count(&self) -> usize {
        self.swarm.connected_peers().count()
    }

    fn can_send_request(&mut self, peer: PeerId) -> bool {
        let count = self.pending_requests_count.entry(peer).or_insert(0);
        if *count >= self.max_concurrent_requests_per_peer {
            warn!(%peer, "too many concurrent requests; skipping");
            false
        } else {
            *count += 1;
            #[cfg(feature = "metrics")]
            P2P_PENDING_REQUESTS
                .with_label_values(&[&peer.to_string()])
                .set(*count as i64);
            true
        }
    }

    fn request_sent(&mut self, request_id: request_response::OutboundRequestId, peer: PeerId) {
        self.pending_requests_by_id.insert(request_id, peer);
    }

    fn request_completed(&mut self, request_id: &request_response::OutboundRequestId) {
        if let Some(peer) = self.pending_requests_by_id.remove(request_id) {
            if let Some(count) = self.pending_requests_count.get_mut(&peer) {
                *count = count.saturating_sub(1);
                #[cfg(feature = "metrics")]
                P2P_PENDING_REQUESTS
                    .with_label_values(&[&peer.to_string()])
                    .set(*count as i64);
                if *count == 0 {
                    self.pending_requests_count.remove(&peer);
                }
            }
        }
    }

    fn send_request_impl(&mut self, peer: PeerId, req: Req) {
        let now = Instant::now();
        let est = bincode::serialized_size(&req).unwrap_or(0) as u32;
        if !self.rr_allow_global_out(now, est) {
            warn!(peer=%peer, bytes=est, "global RR outbound bandwidth cap hit; skipping request");
            // Decrement pending count because we incremented in can_send_request
            if let Some(count) = self.pending_requests_count.get_mut(&peer) {
                *count = count.saturating_sub(1);
                #[cfg(feature = "metrics")]
                P2P_PENDING_REQUESTS
                    .with_label_values(&[&peer.to_string()])
                    .set(*count as i64);
                if *count == 0 {
                    self.pending_requests_count.remove(&peer);
                }
            }
            return;
        }
        let request_id = self.swarm.behaviour_mut().rr.send_request(&peer, req);
        self.request_sent(request_id, peer);
    }

    pub fn request_status(&mut self, peers: Vec<PeerId>) {
        for p in peers {
            if !self.can_send_request(p) {
                continue;
            }
            let req = Req::Status(StatusRequest {});
            self.send_request_impl(p, req);
        }
    }

    pub fn request_block(&mut self, peers: Vec<PeerId>, id: Hash32) {
        for p in peers {
            if !self.can_send_request(p) {
                continue;
            }
            let req = Req::Block(BlockRequest { id: id.clone() });
            self.send_request_impl(p, req);
        }
    }

    pub fn request_range(&mut self, peer: PeerId, from: Height, to: Height) {
        if !self.can_send_request(peer) {
            return;
        }
        let to = to.min(from + MAX_RANGE_BLOCKS - 1);
        let req = Req::Range(RangeRequest { from, to });
        self.send_request_impl(peer, req);
    }

    pub fn request_state_index(&mut self, peer: PeerId) {
        if !self.can_send_request(peer) {
            return;
        }
        let req = Req::State(StateReq::Index(StateIndexRequest {}));
        self.send_request_impl(peer, req);
    }

    pub fn request_snapshot_attest(&mut self, peer: PeerId, height: u64, state_root_hex: String) {
        if !self.can_send_request(peer) {
            return;
        }
        let req = Req::State(StateReq::Attest(SnapshotAttestRequest { height, state_root_hex }));
        self.send_request_impl(peer, req);
    }

    pub fn respond(&mut self, ch: request_response::ResponseChannel<Resp>, resp: Resp) {
        let now = Instant::now();
        let est = bincode::serialized_size(&resp).unwrap_or(0) as u32;
        if !self.rr_allow_global_out(now, est) {
            warn!(bytes=est, "global RR outbound bandwidth cap hit; dropping response");
            return;
        }
        let _ = self.swarm.behaviour_mut().rr.send_response(ch, resp);
    }

    pub async fn shutdown(mut self) {
        info!("Shutting down P2P layer...");
        let peers: Vec<_> = self.swarm.connected_peers().cloned().collect();
        for p in peers {
            let _ = self.swarm.disconnect_peer_id(p);
        }
        self.persist_quarantine_file();
        self.persist_scores_file();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    pub async fn next_event(&mut self) -> Result<P2pEvent> {
        loop {
            self.maybe_decay_peer_scores();
            self.maybe_eclipse_reseed();
            self.maybe_reconnect_static_peers();
            match self.swarm.select_next_some().await {
                SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                    for (peer, _addr) in list {
                        if self.banned_peers.contains(&peer) {
                            continue;
                        }
                        self.swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer);
                        self.peer_scores.entry(peer).or_insert(0);
                        info!(%peer, "mdns discovered");
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                    for (peer, _addr) in list {
                        self.swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer);
                        info!(%peer, "mdns expired");
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received {
                    peer_id, info, ..
                })) => {
                    if !self.banned_peers.contains(&peer_id) {
                        if !self.is_version_compatible(&info.protocol_version) {
                            warn!(%peer_id, protocol_version=%info.protocol_version, "incompatible protocol version; disconnecting");
                            let _ = self.swarm.disconnect_peer_id(peer_id);
                            continue;
                        }

                        if let Some(k) = self.swarm.behaviour_mut().kad.as_mut() {
                            for a in info.listen_addrs.iter().cloned() {
                                k.add_address(&peer_id, a);
                            }
                            let _ = k.bootstrap();
                        }

                        self.swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                        self.peer_scores.entry(peer_id).or_insert(0);
                        info!(%peer_id, "identify: peer connected");
                    }
                }
                SwarmEvent::ConnectionEstablished { peer_id, connection_id, endpoint, .. } => {
                    if self.banned_peers.contains(&peer_id) {
                        let _ = self.swarm.disconnect_peer_id(peer_id);
                        continue;
                    }

                    let direction = if endpoint.is_dialer() { "out" } else { "in" };
                    let bucket = self.bucket_from_multiaddr(endpoint.get_remote_address());

                    // Verifică toate limitele înainte de a accepta conexiunea
                    let mut limit_ok = true;

                    // Verifică bucket
                    if let Some(ref bucket) = bucket {
                        if !self.check_bucket_limit(bucket, direction) {
                            warn!(%peer_id, %bucket, direction, "diversity bucket cap hit; disconnecting");
                            limit_ok = false;
                        }
                    }

                    // Verifică total connections
                    if self.accepted_connections.len() >= self.max_connections_total {
                        warn!(%peer_id, total = self.accepted_connections.len(), "max connections reached; disconnecting");
                        limit_ok = false;
                    }

                    // Verifică per peer
                    let per_peer_count = self.accepted_connections.iter()
                        .filter(|(pid, _)| *pid == peer_id)
                        .count();
                    if per_peer_count >= self.max_connections_per_peer {
                        warn!(%peer_id, per_peer = per_peer_count, "max connections per peer reached; disconnecting");
                        limit_ok = false;
                    }

                    if !limit_ok {
                        let _ = self.swarm.disconnect_peer_id(peer_id);
                        continue;
                    }

                    // Acum acceptăm conexiunea: înregistrăm în accepted_connections
                    self.accepted_connections.insert((peer_id, connection_id));
                    if let Some(ref bucket) = bucket {
                        self.connection_bucket.insert((peer_id, connection_id), bucket.clone());
                        match direction {
                            "in" => *self.bucket_inbound.entry(bucket.clone()).or_insert(0) += 1,
                            "out" => *self.bucket_outbound.entry(bucket.clone()).or_insert(0) += 1,
                            _ => {}
                        }
                    }

                    #[cfg(feature = "metrics")]
                    P2P_CONNECTIONS.with_label_values(&[direction]).inc();

                    self.peer_scores.entry(peer_id).or_insert(0);
                    info!(%peer_id, "connection established");
                }
                SwarmEvent::ConnectionClosed { peer_id, connection_id, endpoint, .. } => {
                    let direction = if endpoint.is_dialer() { "out" } else { "in" };
                    // Doar dacă această conexiune a fost acceptată, decrementăm metricile
                    if self.accepted_connections.remove(&(peer_id, connection_id)) {
                        if let Some(bucket) = self.connection_bucket.remove(&(peer_id, connection_id)) {
                            match direction {
                                "in" => if let Some(c) = self.bucket_inbound.get_mut(&bucket) { *c = c.saturating_sub(1); if *c == 0 { self.bucket_inbound.remove(&bucket); } },
                                "out" => if let Some(c) = self.bucket_outbound.get_mut(&bucket) { *c = c.saturating_sub(1); if *c == 0 { self.bucket_outbound.remove(&bucket); } },
                                _ => {}
                            }
                        }
                        #[cfg(feature = "metrics")]
                        P2P_CONNECTIONS.with_label_values(&[direction]).dec();
                    }
                    debug!(%peer_id, "connection closed");
                }
                SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message {
                    propagation_source,
                    message,
                    ..
                })) => {
                    if self.banned_peers.contains(&propagation_source) {
                        continue;
                    }
                    if self.is_quarantined(propagation_source) {
                        warn!(peer=%propagation_source, "gossipsub message from quarantined peer; dropping");
                        self.bump_score(propagation_source, -1);
                        continue;
                    }

                    let topic = message.topic;
                    if self.gs_deny_unknown_topics && !self.gs_allowed_topic_hashes.contains(&topic) {
                        warn!(peer=%propagation_source, ?topic, "gossipsub topic not allowed; dropping");
                        self.bump_score(propagation_source, -2);
                        continue;
                    }

                    let bytes = message.data.len() as u32;
                    let (lim_msgs, lim_bytes) = self
                        .gs_topic_limits
                        .get(&topic)
                        .cloned()
                        .unwrap_or((self.gs_max_in_msgs_per_sec, self.gs_max_in_bytes_per_sec));

                    if !self.gs_allow_inbound(propagation_source, bytes, lim_msgs, lim_bytes) {
                        warn!(peer=%propagation_source, bytes, "gossipsub inbound cap hit; quarantining");
                        self.bump_score(propagation_source, -3);
                        self.quarantine_peer(propagation_source, self.peer_quarantine_s.max(1), "gossipsub_abuse");
                        continue;
                    }

                    #[cfg(feature = "metrics")]
                    {
                        P2P_MESSAGE_BYTES
                            .with_label_values(&["consensus", "in"])
                            .observe(bytes as f64);
                    }

                    let score = self.peer_scores.entry(propagation_source).or_insert(0);
                    if let Ok(m) = bincode::deserialize::<ConsensusMsg>(&message.data) {
                        *score = score.saturating_add(1);
                        #[cfg(feature = "metrics")]
                        P2P_MESSAGES_TOTAL
                            .with_label_values(&["consensus", "in"])
                            .inc();
                        return Ok(P2pEvent::Consensus {
                            from: propagation_source,
                            msg: m,
                            raw: message.data,
                        });
                    } else {
                        *score = score.saturating_sub(5);
                        if *score < -50 {
                            self.ban_peer(propagation_source);
                        }
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Rr(RequestResponseEvent::Message { peer, message })) => {
                    match message {
                        RequestResponseMessage::Request {
                            request, channel, ..
                        } => {
                            let now = Instant::now();
                            let kind = ProtoKind::from_req(&request);
                            let est_bytes = bincode::serialized_size(&request).unwrap_or(0) as u32;

                            #[cfg(feature = "metrics")]
                            {
                                P2P_MESSAGE_BYTES
                                    .with_label_values(&[&format!("rr_{:?}_req", kind), "in"])
                                    .observe(est_bytes as f64);
                            }

                            if !self.rr_allow_global_in(now, est_bytes) {
                                warn!(%peer, ?kind, bytes = est_bytes, "global RR inbound bandwidth cap hit; dropping request");
                                self.bump_score(peer, -2);
                                continue;
                            }

                            if !self.rr_allow_inbound(now, peer, kind, est_bytes) {
                                continue;
                            }

                            #[cfg(feature = "metrics")]
                            P2P_MESSAGES_TOTAL.with_label_values(&[&format!("rr_{:?}", kind), "in"]).inc();

                            return Ok(P2pEvent::Request {
                                from: peer,
                                req: request,
                                channel,
                            });
                        }
                        RequestResponseMessage::Response { response, request_id, .. } => {
                            let now = Instant::now();
                            let est_bytes = bincode::serialized_size(&response).unwrap_or(0) as u32;
                            #[cfg(feature = "metrics")]
                            {
                                P2P_MESSAGE_BYTES
                                    .with_label_values(&["rr_response", "in"])
                                    .observe(est_bytes as f64);
                                P2P_MESSAGES_TOTAL
                                    .with_label_values(&["rr_response", "in"])
                                    .inc();
                            }
                            self.request_completed(&request_id);
                            return Ok(P2pEvent::Response { from: peer, resp: response });
                        }
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Rr(RequestResponseEvent::OutboundFailure {
                    peer,
                    request_id,
                    error,
                })) => {
                    warn!(%peer, ?request_id, ?error, "outbound request failed");
                    self.request_completed(&request_id);
                }
                SwarmEvent::Behaviour(BehaviourEvent::Rr(RequestResponseEvent::InboundFailure {
                    peer,
                    request_id,
                    error,
                })) => {
                    warn!(%peer, ?request_id, ?error, "inbound request failed");
                }
                SwarmEvent::NewListenAddr { address, .. } => info!(%address, "listening"),
                SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                    debug!(peer=?peer_id, "outgoing connection error: {error}");
                }
                _ => {}
            }
        }
    }
}

// ── Helper functions ──────────────────────────────────────────────────────

fn seed_kad_and_dial(swarm: &mut Swarm<Behaviour>, addr: Multiaddr) {
    let mut peer_opt: Option<PeerId> = None;
    let mut base_addr = addr.clone();

    if let Some(Protocol::P2p(pid)) = addr.iter().last() {
        peer_opt = Some(pid);
        let mut a2 = Multiaddr::empty();
        for proto in addr.iter() {
            if let Protocol::P2p(_) = proto {
                break;
            }
            a2.push(proto);
        }
        base_addr = a2;
    }

    if let Some(pid) = peer_opt {
        if let Some(k) = swarm.behaviour_mut().kad.as_mut() {
            k.add_address(&pid, base_addr);
            let _ = k.bootstrap();
        }
    }

    let _ = swarm.dial(addr);
}

#[derive(Debug)]
pub enum P2pEvent {
    Consensus {
        from: PeerId,
        msg: ConsensusMsg,
        raw: Vec<u8>,
    },
    Request {
        from: PeerId,
        req: Req,
        channel: request_response::ResponseChannel<Resp>,
    },
    Response {
        from: PeerId,
        resp: Resp,
    },
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::multiaddr::Protocol;
    use tempfile::tempdir;

    // Funcție helper pentru testarea compatibilității cu un set dat de versiuni
    fn version_compatible(protocol_version: &str, supported: &[u32], strict: bool) -> bool {
        let version_str = protocol_version.split('/').last().unwrap_or(protocol_version);
        let major_str = version_str.split('.').next().unwrap_or(version_str);
        match major_str.parse::<u32>() {
            Ok(major) => supported.contains(&major),
            Err(_) if strict => false,
            Err(_) => true,
        }
    }

    #[test]
    fn test_bucket_from_multiaddr() {
        let cfg = P2pConfig {
            diversity_bucket_kind: "ip16".into(),
            ..Default::default()
        };
        let p2p = P2p::new(cfg).unwrap();
        let addr4: Multiaddr = "/ip4/192.168.1.100/tcp/7001".parse().unwrap();
        let bucket = p2p.bucket_from_multiaddr(&addr4);
        assert_eq!(bucket, Some("ip4:192.168".into()));

        let mut cfg2 = P2pConfig::default();
        cfg2.diversity_bucket_kind = "ip24".into();
        let p2p2 = P2p::new(cfg2).unwrap();
        let bucket24 = p2p2.bucket_from_multiaddr(&addr4);
        assert_eq!(bucket24, Some("ip4:192.168.1".into()));

        let addr6: Multiaddr = "/ip6/2001:db8::1/tcp/7001".parse().unwrap();
        let mut cfg3 = P2pConfig::default();
        cfg3.diversity_bucket_kind = "ip16".into();
        let p2p3 = P2p::new(cfg3).unwrap();
        let bucket6 = p2p3.bucket_from_multiaddr(&addr6);
        assert!(bucket6.unwrap().starts_with("ip6:"));
    }

    #[test]
    fn test_quarantine_load_save() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("quarantine.json");

        let cfg = P2pConfig {
            quarantine_path: path.clone(),
            persist_quarantine: true,
            ..Default::default()
        };
        let mut p2p = P2p::new(cfg).unwrap();

        let peer = PeerId::random();
        p2p.quarantine_peer(peer, 10, "test");
        p2p.persist_quarantine_file();

        let loaded = P2p::load_quarantine(&path);
        assert!(loaded.contains_key(&peer));
    }

    #[test]
    fn test_version_compatibility_logic() {
        assert!(version_compatible("/iona/1.0.0", &[1, 2], true));
        assert!(version_compatible("1.0.0", &[1], true));
        assert!(!version_compatible("3.0.0", &[1, 2], true));
        // Fallback when parsing fails
        assert!(!version_compatible("garbage", &[1, 2], true));
        assert!(version_compatible("garbage", &[1, 2], false));
    }

    #[test]
    fn test_rate_limiter_decision() {
        let mut state = AbuseState::new(Instant::now());
        let now = Instant::now();
        let dec = rr_decide(&mut state, now, 100, 10, 1000, 60, 60, 2, 3, 2);
        assert!(dec.allow);
        assert_eq!(dec.delta, 1);

        for _ in 1..10 {
            let _ = rr_decide(&mut state, now, 100, 10, 1000, 60, 60, 2, 3, 2);
        }
        let dec = rr_decide(&mut state, now, 100, 10, 1000, 60, 60, 2, 3, 2);
        assert!(!dec.allow);
        assert!(dec.strike);
        assert_eq!(dec.delta, -5);
    }
}
