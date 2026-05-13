//! Production P2P networking for IONA v28.
//!
//! This module implements the libp2p-based peer-to-peer networking stack,
//! including:
//! - Gossipsub for consensus message broadcasting
//! - Request‑response protocols for blocks, status, ranges, and state sync
//! - Peer scoring, rate limiting, quarantine, and banning
//! - Eclipse attack protection via diversity buckets
//! - Static peer dialing and reconnection
//! - Kademlia DHT for peer discovery (optional)
//! - mDNS for local network discovery (optional)
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::net::p2p::{P2p, P2pConfig, P2pError};
//!
//! let config = P2pConfig::default();
//! let mut p2p = P2p::new(config)?;
//! p2p.dial_static_peers();
//! while let Some(event) = p2p.next_event().await {
//!     match event {
//!         P2pEvent::Consensus { from, msg, .. } => { /* handle consensus message */ }
//!         // ...
//!     }
//! }
//! # Ok::<(), P2pError>(())
//! ```

use crate::consensus::ConsensusMsg;
use crate::types::{Block, Hash32, Height};
use bincode;
use futures::AsyncReadExt;
use futures::StreamExt;
use libp2p::{
    core::upgrade,
    gossipsub::{self, IdentTopic, MessageAuthenticity, ValidationMode},
    identify,
    kad::{self, store::MemoryStore},
    mdns,
    multiaddr::Protocol,
    noise,
    request_response::{
        self, Behaviour as RequestResponse, Codec as RequestResponseCodec,
        Event as RequestResponseEvent, Message as RequestResponseMessage, ProtocolSupport,
    },
    swarm::behaviour::toggle::Toggle,
    swarm::StreamProtocol,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, Swarm, Transport,
};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::{
    collections::{BTreeMap, HashSet},
    io,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tracing::{debug, error, info, warn};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Maximum message size for request/response (16 MiB).
pub const MAX_MSG_SIZE: usize = 16 * 1024 * 1024;

/// Maximum number of blocks served or accepted in a single range response.
pub const MAX_RANGE_BLOCKS: u64 = 200;

/// Default heartbeat interval for Gossipsub (ms).
const GOSSIPSUB_HEARTBEAT_MS: u64 = 100;

/// Default mesh parameters.
const GOSSIPSUB_MESH_N: usize = 6;
const GOSSIPSUB_MESH_N_LOW: usize = 4;
const GOSSIPSUB_MESH_N_HIGH: usize = 12;
const GOSSIPSUB_GOSSIP_LAZY: usize = 3;
const GOSSIPSUB_FANOUT_TTL_SECS: u64 = 60;
const GOSSIPSUB_HISTORY_LENGTH: usize = 10;
const GOSSIPSUB_HISTORY_GOSSIP: usize = 3;

/// Identify protocol interval (seconds).
const IDENTIFY_INTERVAL_SECS: u64 = 30;

/// Kademlia query timeout (seconds).
const KAD_QUERY_TIMEOUT_SECS: u64 = 30;

/// Request‑response timeout (seconds).
const RR_TIMEOUT_SECS: u64 = 10;

/// Minimum quarantine seconds.
const MIN_QUARANTINE_SECS: u64 = 1;

/// Minimum score before banning.
const BAN_THRESHOLD: i32 = -50;

// -----------------------------------------------------------------------------
// Protocol definitions
// -----------------------------------------------------------------------------

/// Block request/response protocol name.
#[must_use]
pub fn proto_block() -> StreamProtocol {
    StreamProtocol::new("/iona/block/1.0.0")
}

/// Node status protocol name.
#[must_use]
pub fn proto_status() -> StreamProtocol {
    StreamProtocol::new("/iona/status/1.0.0")
}

/// Block range protocol name.
#[must_use]
pub fn proto_range() -> StreamProtocol {
    StreamProtocol::new("/iona/blockrange/1.0.0")
}

/// State sync protocol name.
#[must_use]
pub fn proto_state() -> StreamProtocol {
    StreamProtocol::new("/iona/state/1.0.0")
}

// -----------------------------------------------------------------------------
// Message types (unchanged)
// -----------------------------------------------------------------------------

/// Request for a single block by hash.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BlockRequest {
    pub id: Hash32,
}

/// Response containing a block (or `None` if not found).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BlockResponse {
    pub block: Option<Block>,
}

/// Request for node status.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StatusRequest {}

/// Node status response.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StatusResponse {
    pub best_height: Height,
    pub best_block_id: Option<Hash32>,
}

/// Request for a range of blocks.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RangeRequest {
    pub from: Height,
    pub to: Height,
}

/// Response containing a list of blocks.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RangeResponse {
    pub blocks: Vec<Block>,
}

// -----------------------------------------------------------------------------
// State sync message types
// -----------------------------------------------------------------------------

/// Request the latest snapshot manifest.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StateManifestRequest {}

/// Snapshot manifest response.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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

/// Snapshot attestation (validator signatures).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SnapshotAttestation {
    pub validators_hash_hex: String,
    pub threshold: u32,
    pub signatures: Vec<AttestationSig>,
}

/// Attestation signature.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AttestationSig {
    pub pubkey_hex: String,
    pub sig_base64: String,
}

/// Request a delta manifest.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeltaManifestRequest {
    pub from_height: u64,
    pub to_height: u64,
}

/// Delta manifest response.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeltaManifestResponse {
    pub from_height: u64,
    pub to_height: u64,
    pub total_bytes: u64,
    pub blake3_hex: String,
    pub chunk_size: u32,
    pub chunk_hashes: Vec<String>,
    pub to_state_root_hex: String,
}

/// Request a delta chunk.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeltaChunkRequest {
    pub from_height: u64,
    pub to_height: u64,
    pub offset: u64,
    pub len: u32,
}

/// Delta chunk response.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeltaChunkResponse {
    pub offset: u64,
    pub data: Vec<u8>,
    pub done: bool,
}

/// Request state index (available snapshots and delta edges).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StateIndexRequest {}

/// State index response.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StateIndexResponse {
    pub snapshot_heights: Vec<u64>,
    pub delta_edges: Vec<(u64, u64)>,
}

/// Request a snapshot attestation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SnapshotAttestRequest {
    pub height: u64,
    pub state_root_hex: String,
}

/// Snapshot attestation response.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SnapshotAttestResponse {
    pub height: u64,
    pub state_root_hex: String,
    pub pubkey_hex: String,
    pub sig_b64: String,
}

/// Request a snapshot chunk.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StateChunkRequest {
    pub height: u64,
    pub offset: u64,
    pub len: u32,
}

/// Snapshot chunk response.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StateChunkResponse {
    pub offset: u64,
    pub data: Vec<u8>,
    pub done: bool,
}

// -----------------------------------------------------------------------------
// Enums for request/response
// -----------------------------------------------------------------------------

/// State sync request variants.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum StateReq {
    Index(StateIndexRequest),
    Manifest(StateManifestRequest),
    Chunk(StateChunkRequest),
    DeltaManifest(DeltaManifestRequest),
    DeltaChunk(DeltaChunkRequest),
    Attest(SnapshotAttestRequest),
}

/// State sync response variants.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum StateResp {
    Index(StateIndexResponse),
    Manifest(StateManifestResponse),
    Chunk(StateChunkResponse),
    DeltaManifest(DeltaManifestResponse),
    DeltaChunk(DeltaChunkResponse),
    Attest(SnapshotAttestResponse),
}

/// Top‑level request enum.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum Req {
    Block(BlockRequest),
    Status(StatusRequest),
    Range(RangeRequest),
    State(StateReq),
}

/// Top‑level response enum.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum Resp {
    Block(BlockResponse),
    Status(StatusResponse),
    Range(RangeResponse),
    State(StateResp),
}

// -----------------------------------------------------------------------------
// Internal protocol kind
// -----------------------------------------------------------------------------

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

// -----------------------------------------------------------------------------
// Abuse tracking structures
// -----------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct AbuseState {
    window_start: std::time::Instant,
    req_count: u32,
    byte_count: u32,
    strikes: u32,
    quarantines: u32,
    last_strike: std::time::Instant,
    quarantine_until: Option<std::time::Instant>,
}

impl AbuseState {
    fn new(now: std::time::Instant) -> Self {
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
    window_start: std::time::Instant,
    msg_count: u32,
    byte_count: u32,
}

impl GsWindow {
    fn new(now: std::time::Instant) -> Self {
        Self {
            window_start: now,
            msg_count: 0,
            byte_count: 0,
        }
    }
}

// -----------------------------------------------------------------------------
// Quarantine persistence
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct QuarantineFile {
    peers: BTreeMap<String, u64>, // peer_id (base58) -> unix_seconds_until
}

// -----------------------------------------------------------------------------
// Codec
// -----------------------------------------------------------------------------

/// Request‑response codec using bincode serialization.
#[derive(Clone)]
pub struct Codec;

#[async_trait::async_trait]
impl RequestResponseCodec for Codec {
    type Protocol = StreamProtocol;
    type Request = Req;
    type Response = Resp;

    async fn read_request<T>(&mut self, _: &StreamProtocol, io: &mut T) -> io::Result<Req>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        let mut limited = io.take(MAX_MSG_SIZE as u64 + 1);
        futures::AsyncReadExt::read_to_end(&mut limited, &mut buf).await?;
        if buf.len() > MAX_MSG_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request too large",
            ));
        }
        bincode::deserialize(&buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e}")))
    }

    async fn read_response<T>(&mut self, _: &StreamProtocol, io: &mut T) -> io::Result<Resp>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        let mut limited = io.take(MAX_MSG_SIZE as u64 + 1);
        futures::AsyncReadExt::read_to_end(&mut limited, &mut buf).await?;
        if buf.len() > MAX_MSG_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "response too large",
            ));
        }
        bincode::deserialize(&buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e}")))
    }

    async fn write_request<T>(&mut self, _: &StreamProtocol, io: &mut T, req: Req) -> io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        let bytes = bincode::serialize(&req)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e}")))?;
        futures::AsyncWriteExt::write_all(io, &bytes).await?;
        futures::AsyncWriteExt::close(io).await
    }

    async fn write_response<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        resp: Resp,
    ) -> io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        let bytes = bincode::serialize(&resp)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e}")))?;
        futures::AsyncWriteExt::write_all(io, &bytes).await?;
        futures::AsyncWriteExt::close(io).await
    }
}

// -----------------------------------------------------------------------------
// Network behaviour
// -----------------------------------------------------------------------------

#[derive(NetworkBehaviour)]
pub struct Behaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub mdns: Toggle<mdns::tokio::Behaviour>,
    pub identify: identify::Behaviour,
    pub kad: Toggle<kad::Behaviour<MemoryStore>>,
    pub rr: RequestResponse<Codec>,
}

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for the P2P stack.
#[derive(Debug, Clone)]
pub struct P2pConfig {
    pub local_key: libp2p::identity::Keypair,
    pub listen: Multiaddr,
    pub static_peers: Vec<Multiaddr>,
    pub bootnodes: Vec<Multiaddr>,
    pub enable_mdns: bool,
    pub enable_kad: bool,
    pub reconnect_s: u64,
    pub max_connections_total: usize,
    pub max_connections_per_peer: usize,
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
    pub persist_quarantine: bool,
}

impl Default for P2pConfig {
    fn default() -> Self {
        Self {
            local_key: libp2p::identity::Keypair::generate_ed25519(),
            listen: "/ip4/0.0.0.0/tcp/0".parse().unwrap(),
            static_peers: vec![],
            bootnodes: vec![],
            enable_mdns: false,
            enable_kad: true,
            reconnect_s: 30,
            max_connections_total: 200,
            max_connections_per_peer: 8,
            rr_max_req_per_sec_block: 15,
            rr_max_req_per_sec_status: 30,
            rr_max_req_per_sec_range: 5,
            rr_max_req_per_sec_state: 10,
            rr_max_bytes_per_sec_block: 2_000_000,
            rr_max_bytes_per_sec_status: 200_000,
            rr_max_bytes_per_sec_range: 4_000_000,
            rr_max_bytes_per_sec_state: 8_000_000,
            rr_global_in_bytes_per_sec: 10_000_000,
            rr_global_out_bytes_per_sec: 10_000_000,
            peer_strike_decay_s: 30,
            peer_score_decay_s: 60,
            peer_quarantine_s: 60,
            rr_strikes_before_quarantine: 2,
            rr_strikes_before_ban: 3,
            rr_quarantines_before_ban: 2,
            gs_max_publish_msgs_per_sec: 50,
            gs_max_publish_bytes_per_sec: 5_242_880,
            gs_max_in_msgs_per_sec: 100,
            gs_max_in_bytes_per_sec: 10_485_760,
            gs_allowed_topics: vec!["iona/tx".into(), "iona/blocks".into(), "iona/evidence".into()],
            gs_deny_unknown_topics: true,
            gs_topic_limits: vec![],
            diversity_bucket_kind: "ip16".into(),
            max_inbound_per_bucket: 4,
            max_outbound_per_bucket: 4,
            eclipse_detection_min_buckets: 3,
            reseed_cooldown_s: 60,
            quarantine_path: PathBuf::from("./data/quarantine.json"),
            persist_quarantine: true,
        }
    }
}

impl P2pConfig {
    /// Validate the configuration, returning an error if any parameter is invalid.
    pub fn validate(&self) -> Result<(), P2pError> {
        if self.max_connections_total == 0 {
            return Err(P2pError::InvalidConfig("max_connections_total must be > 0"));
        }
        if self.max_connections_per_peer == 0 {
            return Err(P2pError::InvalidConfig("max_connections_per_peer must be > 0"));
        }
        if self.peer_quarantine_s == 0 {
            return Err(P2pError::InvalidConfig("peer_quarantine_s must be > 0"));
        }
        if self.rr_strikes_before_ban == 0 && self.rr_strikes_before_quarantine == 0 {
            return Err(P2pError::InvalidConfig("at least one of rr_strikes_before_ban or rr_strikes_before_quarantine must be > 0"));
        }
        if self.gs_max_publish_msgs_per_sec == 0 {
            return Err(P2pError::InvalidConfig("gs_max_publish_msgs_per_sec must be > 0"));
        }
        if self.gs_max_in_msgs_per_sec == 0 {
            return Err(P2pError::InvalidConfig("gs_max_in_msgs_per_sec must be > 0"));
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// P2p error
// -----------------------------------------------------------------------------

/// Errors that can occur during P2P operations.
#[derive(Debug, Error)]
pub enum P2pError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("libp2p error: {0}")]
    Libp2p(String),

    #[error("serialisation error: {0}")]
    Serialization(#[from] bincode::Error),

    #[error("Gossipsub configuration error: {0}")]
    Gossipsub(String),

    #[error("MDNS error: {0}")]
    Mdns(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(&'static str),

    #[error("Peer not found: {0}")]
    PeerNotFound(PeerId),
}

pub type P2pResult<T> = Result<T, P2pError>;

// -----------------------------------------------------------------------------
// Helper: extract IP bucket from multiaddress
// -----------------------------------------------------------------------------

fn bucket_from_multiaddr(addr: &Multiaddr, kind: &str) -> Option<String> {
    let mut ip4: Option<[u8; 4]> = None;
    let mut ip6: Option<[u8; 16]> = None;
    for p in addr.iter() {
        match p {
            Protocol::Ip4(v4) => {
                ip4 = Some(v4.octets());
                break;
            }
            Protocol::Ip6(v6) => {
                ip6 = Some(v6.octets());
                break;
            }
            _ => {}
        }
    }
    match (kind, ip4, ip6) {
        ("ip24", Some(o), _) => Some(format!("ip4:{}.{}.{}", o[0], o[1], o[2])),
        ("ip16", Some(o), _) => Some(format!("ip4:{}.{}", o[0], o[1])),
        ("ip16", None, Some(o)) => Some(format!(
            "ip6:{:02x}{:02x}{:02x}{:02x}",
            o[0], o[1], o[2], o[3]
        )),
        ("ip24", None, Some(o)) => Some(format!(
            "ip6:{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            o[0], o[1], o[2], o[3], o[4], o[5]
        )),
        ("asn", Some(o), _) => Some(format!("asn_scaffold:{}.{}", o[0], o[1])),
        ("asn", None, Some(o)) => Some(format!("asn_scaffold:{:02x}{:02x}", o[0], o[1])),
        _ => None,
    }
}

// -----------------------------------------------------------------------------
// P2p main struct
// -----------------------------------------------------------------------------

/// Main P2P networking handle.
pub struct P2p {
    swarm: Swarm<Behaviour>,
    topic: IdentTopic,
    peer_scores: BTreeMap<PeerId, i32>,
    peer_quarantine: BTreeMap<PeerId, std::time::Instant>,
    quarantine_path: PathBuf,
    persist_quarantine: bool,
    last_score_decay: std::time::Instant,
    static_peers: Vec<Multiaddr>,
    bootnodes: Vec<Multiaddr>,
    banned_peers: HashSet<PeerId>,
    max_connections_total: usize,
    max_connections_per_peer: usize,
    connections_total: usize,
    connections_per_peer: BTreeMap<PeerId, usize>,
    diversity_bucket_kind: String,
    max_inbound_per_bucket: usize,
    max_outbound_per_bucket: usize,
    eclipse_detection_min_buckets: usize,
    reseed_cooldown_s: u64,
    bucket_counts: BTreeMap<String, usize>,
    peer_bucket: BTreeMap<PeerId, String>,
    last_reseed: std::time::Instant,
    rr_max_req_per_sec_block: u32,
    rr_max_req_per_sec_status: u32,
    rr_max_req_per_sec_range: u32,
    rr_max_req_per_sec_state: u32,
    rr_max_bytes_per_sec_block: u32,
    rr_max_bytes_per_sec_status: u32,
    rr_max_bytes_per_sec_range: u32,
    rr_max_bytes_per_sec_state: u32,
    rr_global_in_bytes_per_sec: u32,
    rr_global_out_bytes_per_sec: u32,
    peer_strike_decay_s: u64,
    peer_score_decay_s: u64,
    peer_quarantine_s: u64,
    rr_strikes_before_quarantine: u32,
    rr_strikes_before_ban: u32,
    rr_quarantines_before_ban: u32,
    rr_abuse: BTreeMap<(PeerId, ProtoKind), AbuseState>,
    gs_in: BTreeMap<PeerId, GsWindow>,
    gs_max_in_msgs_per_sec: u32,
    gs_max_in_bytes_per_sec: u32,
    gs_publish_window: GsWindow,
    gs_max_publish_msgs_per_sec: u32,
    gs_max_publish_bytes_per_sec: u32,
    gs_allowed_topics: HashSet<String>,
    gs_deny_unknown_topics: bool,
    gs_topic_limits: BTreeMap<String, (u32, u32)>,
    rr_global_window: (std::time::Instant, u32, u32),
}

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

impl P2p {
    /// Current Unix timestamp in seconds.
    fn now_unix() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs()
    }

    /// Load quarantine list from disk.
    fn load_quarantine(path: &PathBuf) -> BTreeMap<PeerId, std::time::Instant> {
        let now_i = std::time::Instant::now();
        let now_u = Self::now_unix();
        let data = match fs::read_to_string(path) {
            Ok(s) => s,
            Err(_) => return BTreeMap::new(),
        };
        let parsed: QuarantineFile = match serde_json::from_str(&data) {
            Ok(p) => p,
            Err(_) => return BTreeMap::new(),
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

    /// Persist the quarantine list to disk.
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
            let rem = until_i
                .saturating_duration_since(std::time::Instant::now())
                .as_secs();
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

    /// Quarantine a peer for a given number of seconds.
    fn quarantine_peer(&mut self, peer: PeerId, secs: u64, reason: &str) {
        let until = std::time::Instant::now() + Duration::from_secs(secs.max(MIN_QUARANTINE_SECS));
        self.peer_quarantine.insert(peer, until);
        warn!(%peer, reason, "peer quarantined");
        self.persist_quarantine_file();
        let _ = self.swarm.disconnect_peer_id(peer);
    }

    /// Check if a peer is currently quarantined.
    fn is_quarantined(&mut self, peer: PeerId) -> bool {
        if let Some(until) = self.peer_quarantine.get(&peer).cloned() {
            if std::time::Instant::now() < until {
                return true;
            } else {
                self.peer_quarantine.remove(&peer);
                self.persist_quarantine_file();
            }
        }
        false
    }

    /// Decay peer scores periodically.
    fn maybe_decay_peer_scores(&mut self) {
        if self.peer_score_decay_s == 0 {
            return;
        }
        let every = Duration::from_secs(self.peer_score_decay_s);
        let now = std::time::Instant::now();
        if now.duration_since(self.last_score_decay) < every {
            return;
        }
        let steps = now.duration_since(self.last_score_decay).as_secs() / every.as_secs().max(1);
        let steps = steps.max(1);
        for _ in 0..steps {
            for v in self.peer_scores.values_mut() {
                if *v > 0 {
                    *v -= 1;
                } else if *v < 0 {
                    *v += 1;
                }
            }
            self.last_score_decay += every;
        }
    }

    /// Check inbound Gossipsub message quota.
    fn gs_allow_inbound(
        &mut self,
        peer: PeerId,
        bytes: u32,
        max_msgs: u32,
        max_bytes: u32,
    ) -> bool {
        let now = std::time::Instant::now();
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

    /// Check local publish quota.
    fn gs_allow_publish(&mut self, bytes: u32) -> bool {
        let now = std::time::Instant::now();
        if now.duration_since(self.gs_publish_window.window_start) > Duration::from_secs(1) {
            self.gs_publish_window.window_start = now;
            self.gs_publish_window.msg_count = 0;
            self.gs_publish_window.byte_count = 0;
        }
        self.gs_publish_window.msg_count = self.gs_publish_window.msg_count.saturating_add(1);
        self.gs_publish_window.byte_count = self.gs_publish_window.byte_count.saturating_add(bytes);

        if (self.gs_max_publish_msgs_per_sec > 0
            && self.gs_publish_window.msg_count > self.gs_max_publish_msgs_per_sec)
            || (self.gs_max_publish_bytes_per_sec > 0
                && self.gs_publish_window.byte_count > self.gs_max_publish_bytes_per_sec)
        {
            return false;
        }
        true
    }

    /// Create a new P2P instance.
    pub fn new(cfg: P2pConfig) -> P2pResult<Self> {
        cfg.validate()?;

        let peer_id = PeerId::from(cfg.local_key.public());
        info!(%peer_id, "local peer id");

        let transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
            .upgrade(upgrade::Version::V1)
            .authenticate(noise::Config::new(&cfg.local_key).map_err(|e| P2pError::Libp2p(e.to_string()))?)
            .multiplex(yamux::Config::default())
            .boxed();

        let consensus_topic = IdentTopic::new("iona-consensus");
        let allowed_topics: Vec<IdentTopic> = cfg
            .gs_allowed_topics
            .iter()
            .cloned()
            .map(IdentTopic::new)
            .collect();

        let mut gs_config = gossipsub::ConfigBuilder::default();
        gs_config
            .heartbeat_interval(Duration::from_millis(GOSSIPSUB_HEARTBEAT_MS))
            .validation_mode(ValidationMode::Strict)
            .max_transmit_size(MAX_MSG_SIZE)
            .mesh_n(GOSSIPSUB_MESH_N)
            .mesh_n_low(GOSSIPSUB_MESH_N_LOW)
            .mesh_n_high(GOSSIPSUB_MESH_N_HIGH)
            .gossip_lazy(GOSSIPSUB_GOSSIP_LAZY)
            .fanout_ttl(Duration::from_secs(GOSSIPSUB_FANOUT_TTL_SECS))
            .history_length(GOSSIPSUB_HISTORY_LENGTH)
            .history_gossip(GOSSIPSUB_HISTORY_GOSSIP);
        let gs_config = gs_config.build().map_err(|e| P2pError::Gossipsub(e.to_string()))?;

        let mut gossipsub = gossipsub::Behaviour::new(
            MessageAuthenticity::Signed(cfg.local_key.clone()),
            gs_config,
        )
        .map_err(|e| P2pError::Gossipsub(e.to_string()))?;

        gossipsub
            .with_peer_score(
                gossipsub::PeerScoreParams::default(),
                gossipsub::PeerScoreThresholds::default(),
            )
            .map_err(|e| P2pError::Gossipsub(e.to_string()))?;
        for topic in allowed_topics.iter() {
            gossipsub.subscribe(topic).map_err(|e| P2pError::Gossipsub(e.to_string()))?;
        }
        gossipsub.subscribe(&consensus_topic).map_err(|e| P2pError::Gossipsub(e.to_string()))?;

        let mdns = if cfg.enable_mdns {
            let mdns_behaviour =
                mdns::tokio::Behaviour::new(mdns::Config::default(), peer_id)
                    .map_err(|e| P2pError::Mdns(e.to_string()))?;
            Toggle::from(Some(mdns_behaviour))
        } else {
            Toggle::from(None)
        };

        let identify = identify::Behaviour::new(
            identify::Config::new("/iona/1.0.0".into(), cfg.local_key.public())
                .with_interval(Duration::from_secs(IDENTIFY_INTERVAL_SECS)),
        );

        let kad = if cfg.enable_kad {
            let store = MemoryStore::new(peer_id);
            let mut kad_config = kad::Config::default();
            kad_config.set_query_timeout(Duration::from_secs(KAD_QUERY_TIMEOUT_SECS));
            Toggle::from(Some(kad::Behaviour::with_config(peer_id, store, kad_config)))
        } else {
            Toggle::from(None)
        };

        let protocols = vec![
            (proto_block(), ProtocolSupport::Full),
            (proto_status(), ProtocolSupport::Full),
            (proto_range(), ProtocolSupport::Full),
            (proto_state(), ProtocolSupport::Full),
        ];
        let rr_config = request_response::Config::default()
            .with_request_timeout(Duration::from_secs(RR_TIMEOUT_SECS));
        let rr = RequestResponse::with_codec(Codec, protocols, rr_config);

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
        swarm.listen_on(cfg.listen.clone()).map_err(|e| P2pError::Libp2p(e.to_string()))?;

        for addr in cfg.bootnodes.iter().cloned() {
            Self::seed_kad_and_dial(&mut swarm, addr);
        }

        let quarantine_path = cfg.quarantine_path.clone();
        let peer_quarantine = if cfg.persist_quarantine {
            Self::load_quarantine(&quarantine_path)
        } else {
            BTreeMap::new()
        };

        Ok(Self {
            swarm,
            topic: consensus_topic,
            peer_scores: BTreeMap::new(),
            peer_quarantine,
            quarantine_path,
            persist_quarantine: cfg.persist_quarantine,
            last_score_decay: std::time::Instant::now(),
            static_peers: cfg.static_peers,
            bootnodes: cfg.bootnodes,
            banned_peers: HashSet::new(),
            max_connections_total: cfg.max_connections_total,
            max_connections_per_peer: cfg.max_connections_per_peer,
            connections_total: 0,
            connections_per_peer: BTreeMap::new(),
            diversity_bucket_kind: cfg.diversity_bucket_kind,
            max_inbound_per_bucket: cfg.max_inbound_per_bucket,
            max_outbound_per_bucket: cfg.max_outbound_per_bucket,
            eclipse_detection_min_buckets: cfg.eclipse_detection_min_buckets,
            reseed_cooldown_s: cfg.reseed_cooldown_s,
            bucket_counts: BTreeMap::new(),
            peer_bucket: BTreeMap::new(),
            last_reseed: std::time::Instant::now(),
            rr_max_req_per_sec_block: cfg.rr_max_req_per_sec_block,
            rr_max_req_per_sec_status: cfg.rr_max_req_per_sec_status,
            rr_max_req_per_sec_range: cfg.rr_max_req_per_sec_range,
            rr_max_req_per_sec_state: cfg.rr_max_req_per_sec_state,
            rr_max_bytes_per_sec_block: cfg.rr_max_bytes_per_sec_block,
            rr_max_bytes_per_sec_status: cfg.rr_max_bytes_per_sec_status,
            rr_max_bytes_per_sec_range: cfg.rr_max_bytes_per_sec_range,
            rr_max_bytes_per_sec_state: cfg.rr_max_bytes_per_sec_state,
            rr_global_in_bytes_per_sec: cfg.rr_global_in_bytes_per_sec,
            rr_global_out_bytes_per_sec: cfg.rr_global_out_bytes_per_sec,
            peer_strike_decay_s: cfg.peer_strike_decay_s,
            peer_score_decay_s: cfg.peer_score_decay_s,
            peer_quarantine_s: cfg.peer_quarantine_s,
            rr_strikes_before_quarantine: cfg.rr_strikes_before_quarantine,
            rr_strikes_before_ban: cfg.rr_strikes_before_ban,
            rr_quarantines_before_ban: cfg.rr_quarantines_before_ban,
            rr_abuse: BTreeMap::new(),
            gs_in: BTreeMap::new(),
            gs_max_in_msgs_per_sec: cfg.gs_max_in_msgs_per_sec,
            gs_max_in_bytes_per_sec: cfg.gs_max_in_bytes_per_sec,
            gs_publish_window: GsWindow::new(std::time::Instant::now()),
            gs_max_publish_msgs_per_sec: cfg.gs_max_publish_msgs_per_sec,
            gs_max_publish_bytes_per_sec: cfg.gs_max_publish_bytes_per_sec,
            gs_allowed_topics: cfg.gs_allowed_topics.iter().cloned().collect(),
            gs_deny_unknown_topics: cfg.gs_deny_unknown_topics,
            gs_topic_limits: cfg
                .gs_topic_limits
                .iter()
                .cloned()
                .map(|(t, m, b)| (t, (m, b)))
                .collect(),
            rr_global_window: (std::time::Instant::now(), 0, 0),
        })
    }

    /// Helper: seed Kademlia and dial a multiaddress.
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
            if let Some(kad) = swarm.behaviour_mut().kad.as_mut() {
                kad.add_address(&pid, base_addr);
                let _ = kad.bootstrap();
            }
        }

        let _ = swarm.dial(addr);
    }

    /// Dial all static peers and bootnodes. Call at startup and periodically for reconnects.
    pub fn dial_static_peers(&mut self) {
        for addr in self.bootnodes.clone() {
            Self::seed_kad_and_dial(&mut self.swarm, addr);
        }
        for addr in self.static_peers.clone() {
            match self.swarm.dial(addr.clone()) {
                Ok(_) => debug!(%addr, "dialing static peer"),
                Err(e) => warn!(%addr, "dial failed: {e}"),
            }
        }
    }

    /// Publish a consensus message via Gossipsub.
    pub fn publish(&mut self, msg: &ConsensusMsg) {
        let bytes = match bincode::serialize(msg) {
            Ok(b) => b,
            Err(e) => {
                warn!("failed to serialize consensus message: {e}");
                return;
            }
        };
        let b = bytes.len() as u32;
        if !self.gs_allow_publish(b) {
            warn!(bytes = b, "gossipsub publish cap hit; dropping local publish");
            return;
        }
        if let Err(e) = self
            .swarm
            .behaviour_mut()
            .gossipsub
            .publish(self.topic.clone(), bytes)
        {
            warn!("gossipsub publish: {e:?}");
        }
    }

    /// Return a list of connected peer IDs (excluding banned).
    #[must_use]
    pub fn peers(&self) -> Vec<PeerId> {
        self.peer_scores
            .keys()
            .filter(|p| !self.banned_peers.contains(p))
            .cloned()
            .collect()
    }

    /// Number of connected peers.
    #[must_use]
    pub fn peer_count(&self) -> usize {
        self.peers().len()
    }

    /// Send status requests to a list of peers.
    pub fn request_status(&mut self, peers: Vec<PeerId>) {
        for p in peers {
            let req = Req::Status(StatusRequest {});
            let now = std::time::Instant::now();
            let est = bincode::serialized_size(&req).unwrap_or(0) as u32;
            if self.rr_allow_global_out(now, est) {
                self.swarm.behaviour_mut().rr.send_request(&p, req);
            } else {
                warn!(peer=%p, bytes=est, "global RR outbound bandwidth cap hit; skipping status request");
            }
        }
    }

    /// Send block requests to a list of peers.
    pub fn request_block(&mut self, peers: Vec<PeerId>, id: Hash32) {
        for p in peers {
            let req = Req::Block(BlockRequest { id: id.clone() });
            let now = std::time::Instant::now();
            let est = bincode::serialized_size(&req).unwrap_or(0) as u32;
            if self.rr_allow_global_out(now, est) {
                self.swarm.behaviour_mut().rr.send_request(&p, req);
            } else {
                warn!(peer=%p, bytes=est, "global RR outbound bandwidth cap hit; skipping block request");
            }
        }
    }

    /// Send a range request to a specific peer (capped to `MAX_RANGE_BLOCKS`).
    pub fn request_range(&mut self, peer: PeerId, from: Height, to: Height) {
        let to = to.min(from + MAX_RANGE_BLOCKS - 1);
        let req = Req::Range(RangeRequest { from, to });
        let now = std::time::Instant::now();
        let est = bincode::serialized_size(&req).unwrap_or(0) as u32;
        if self.rr_allow_global_out(now, est) {
            self.swarm.behaviour_mut().rr.send_request(&peer, req);
        } else {
            warn!(%peer, bytes=est, "global RR outbound bandwidth cap hit; skipping range request");
        }
    }

    /// Request state index from a peer.
    pub fn request_state_index(&mut self, peer: PeerId) {
        let req = Req::State(StateReq::Index(StateIndexRequest {}));
        let now = std::time::Instant::now();
        let est = bincode::serialized_size(&req).unwrap_or(0) as u32;
        if self.rr_allow_global_out(now, est) {
            self.swarm.behaviour_mut().rr.send_request(&peer, req);
        } else {
            warn!(%peer, bytes=est, "global RR outbound bandwidth cap hit; skipping state index request");
        }
    }

    /// Request a snapshot attestation from a peer.
    pub fn request_snapshot_attest(&mut self, peer: PeerId, height: u64, state_root_hex: String) {
        let req = Req::State(StateReq::Attest(SnapshotAttestRequest {
            height,
            state_root_hex,
        }));
        let now = std::time::Instant::now();
        let est = bincode::serialized_size(&req).unwrap_or(0) as u32;
        if self.rr_allow_global_out(now, est) {
            self.swarm.behaviour_mut().rr.send_request(&peer, req);
        } else {
            warn!(%peer, bytes=est, "global RR outbound bandwidth cap hit; skipping snapshot attest request");
        }
    }

    /// Send a response on a given request channel.
    pub fn respond(&mut self, channel: request_response::ResponseChannel<Resp>, resp: Resp) {
        let now = std::time::Instant::now();
        let est = bincode::serialized_size(&resp).unwrap_or(0) as u32;
        if self.rr_allow_global_out(now, est) {
            let _ = self.swarm.behaviour_mut().rr.send_response(channel, resp);
        } else {
            warn!(bytes = est, "global RR outbound bandwidth cap hit; dropping response");
        }
    }

    // -------------------------------------------------------------------------
    // Internal rate‑limit helpers
    // -------------------------------------------------------------------------

    fn rr_limits_for(&self, kind: ProtoKind) -> (u32, u32) {
        match kind {
            ProtoKind::Block => (self.rr_max_req_per_sec_block, self.rr_max_bytes_per_sec_block),
            ProtoKind::Status => (self.rr_max_req_per_sec_status, self.rr_max_bytes_per_sec_status),
            ProtoKind::Range => (self.rr_max_req_per_sec_range, self.rr_max_bytes_per_sec_range),
            ProtoKind::State => (self.rr_max_req_per_sec_state, self.rr_max_bytes_per_sec_state),
        }
    }

    fn rr_allow_global_in(&mut self, now: std::time::Instant, bytes: u32) -> bool {
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

    fn rr_allow_global_out(&mut self, now: std::time::Instant, bytes: u32) -> bool {
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

    fn rr_allow_inbound(
        &mut self,
        now: std::time::Instant,
        peer: PeerId,
        kind: ProtoKind,
        bytes: u32,
    ) -> bool {
        if self.is_quarantined(peer) {
            warn!(%peer, ?kind, "peer is quarantined; dropping request");
            self.bump_score(peer, -1);
            return false;
        }

        let (max_req, max_bytes) = self.rr_limits_for(kind);
        let key = (peer, kind);

        #[derive(Debug)]
        enum Act {
            Allow,
            Boost(i32),
            Drop(i32),
            Disconnect(i32),
            Quarantine(i32),
            Ban(i32),
        }

        let mut act = Act::Allow;
        let mut do_quarantine = false;
        let mut do_ban = false;

        {
            let st = self
                .rr_abuse
                .entry(key)
                .or_insert_with(|| AbuseState::new(now));

            if let Some(until) = st.quarantine_until {
                if now < until {
                    act = Act::Drop(-1);
                } else {
                    st.quarantine_until = None;
                    act = Act::Boost(1);
                }
            }

            if self.peer_strike_decay_s > 0 {
                let decay_every = Duration::from_secs(self.peer_strike_decay_s);
                let mut elapsed = now.duration_since(st.last_strike);
                while st.strikes > 0 && elapsed >= decay_every {
                    st.strikes = st.strikes.saturating_sub(1);
                    st.last_strike += decay_every;
                    elapsed = now.duration_since(st.last_strike);
                }
            }

            if now.duration_since(st.window_start) > Duration::from_secs(1) {
                st.window_start = now;
                st.req_count = 0;
                st.byte_count = 0;
            }
            st.req_count = st.req_count.saturating_add(1);
            st.byte_count = st.byte_count.saturating_add(bytes);

            let mut limited = false;
            if max_req > 0 && st.req_count > max_req {
                limited = true;
            }
            if max_bytes > 0 && st.byte_count > max_bytes {
                limited = true;
            }

            if matches!(act, Act::Drop(_)) {
                // already quarantined
            } else if !limited {
                if !matches!(act, Act::Boost(_)) {
                    act = Act::Allow;
                }
            } else {
                st.strikes = st.strikes.saturating_add(1);
                st.last_strike = now;
                warn!(%peer, ?kind, reqs = st.req_count, bytes = st.byte_count, strikes = st.strikes, "RR limited; dropping request");

                act = Act::Disconnect(-5);

                if st.strikes >= self.rr_strikes_before_ban && self.rr_strikes_before_ban > 0 {
                    do_ban = true;
                    act = Act::Ban(-5);
                } else if st.strikes >= self.rr_strikes_before_quarantine
                    && self.rr_strikes_before_quarantine > 0
                {
                    st.quarantines = st.quarantines.saturating_add(1);
                    if st.quarantines >= self.rr_quarantines_before_ban
                        && self.rr_quarantines_before_ban > 0
                    {
                        do_ban = true;
                        act = Act::Ban(-5);
                    } else {
                        do_quarantine = true;
                        let until = now + Duration::from_secs(self.peer_quarantine_s.max(1));
                        st.quarantine_until = Some(until);
                        warn!(%peer, ?kind, quarantines = st.quarantines, "quarantining peer temporarily");
                        act = Act::Quarantine(-5);
                    }
                }
            }
        }

        match act {
            Act::Allow => true,
            Act::Boost(delta) => {
                self.bump_score(peer, delta);
                true
            }
            Act::Drop(delta) => {
                self.bump_score(peer, delta);
                false
            }
            Act::Disconnect(delta) => {
                self.bump_score(peer, delta);
                let _ = self.swarm.disconnect_peer_id(peer);
                false
            }
            Act::Quarantine(delta) => {
                self.bump_score(peer, delta);
                if do_quarantine {
                    self.quarantine_peer(peer, self.peer_quarantine_s.max(1), "rr_abuse");
                }
                false
            }
            Act::Ban(delta) => {
                self.bump_score(peer, delta);
                if do_ban {
                    self.ban_peer(peer);
                }
                false
            }
        }
    }

    fn bump_score(&mut self, peer: PeerId, delta: i32) {
        let score = self.peer_scores.entry(peer).or_insert(0);
        *score = score.saturating_add(delta);
        if *score < BAN_THRESHOLD {
            self.ban_peer(peer);
        }
    }

    fn ban_peer(&mut self, peer: PeerId) {
        warn!(%peer, "banning peer (score too low)");
        self.banned_peers.insert(peer);
        let _ = self.swarm.disconnect_peer_id(peer);
    }

    fn bucket_from_addrs(&self, addrs: &[Multiaddr]) -> Option<String> {
        for a in addrs {
            if let Some(b) = bucket_from_multiaddr(a, &self.diversity_bucket_kind) {
                return Some(b);
            }
        }
        None
    }

    fn maybe_eclipse_reseed(&mut self) {
        let distinct = self.bucket_counts.len();
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
        self.last_reseed = std::time::Instant::now();
        for addr in self.bootnodes.iter().cloned() {
            Self::seed_kad_and_dial(&mut self.swarm, addr);
        }
    }

    /// Process the next network event.
    pub async fn next_event(&mut self) -> P2pResult<P2pEvent> {
        loop {
            self.maybe_decay_peer_scores();
            self.maybe_eclipse_reseed();
            match self.swarm.select_next_some().await {
                SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                    for (peer, _addr) in list {
                        if self.banned_peers.contains(&peer) {
                            continue;
                        }
                        self.swarm
                            .behaviour_mut()
                            .gossipsub
                            .add_explicit_peer(&peer);
                        self.peer_scores.entry(peer).or_insert(0);
                        info!(%peer, "mdns discovered");
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                    for (peer, _addr) in list {
                        self.swarm
                            .behaviour_mut()
                            .gossipsub
                            .remove_explicit_peer(&peer);
                        info!(%peer, "mdns expired");
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received {
                    peer_id,
                    info,
                    ..
                })) => {
                    if self.banned_peers.contains(&peer_id) {
                        continue;
                    }
                    if let Some(kad) = self.swarm.behaviour_mut().kad.as_mut() {
                        for a in info.listen_addrs.iter().cloned() {
                            kad.add_address(&peer_id, a);
                        }
                        let _ = kad.bootstrap();
                    }

                    if let Some(bucket) = self.bucket_from_addrs(&info.listen_addrs) {
                        let c = self.bucket_counts.entry(bucket.clone()).or_insert(0);
                        *c = c.saturating_add(1);
                        if *c > self.max_inbound_per_bucket.max(1) {
                            warn!(%peer_id, bucket=%bucket, count=*c, "diversity bucket cap hit; disconnecting");
                            *c = c.saturating_sub(1);
                            let _ = self.swarm.disconnect_peer_id(peer_id);
                            continue;
                        }
                        self.peer_bucket.insert(peer_id, bucket);
                    }
                    self.swarm
                        .behaviour_mut()
                        .gossipsub
                        .add_explicit_peer(&peer_id);
                    self.peer_scores.entry(peer_id).or_insert(0);
                    info!(%peer_id, "identify: peer connected");
                }

                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    if self.banned_peers.contains(&peer_id) {
                        let _ = self.swarm.disconnect_peer_id(peer_id);
                        continue;
                    }

                    self.connections_total = self.connections_total.saturating_add(1);
                    let per = self.connections_per_peer.entry(peer_id).or_insert(0);
                    *per = per.saturating_add(1);

                    if self.connections_total > self.max_connections_total
                        || *per > self.max_connections_per_peer
                    {
                        warn!(%peer_id, total = self.connections_total, per_peer = *per, "connection limit exceeded; disconnecting");
                        self.connections_total = self.connections_total.saturating_sub(1);
                        *per = per.saturating_sub(1);
                        let _ = self.swarm.disconnect_peer_id(peer_id);
                        continue;
                    }

                    self.peer_scores.entry(peer_id).or_insert(0);
                    info!(%peer_id, "connection established");
                }

                SwarmEvent::ConnectionClosed { peer_id, .. } => {
                    self.peer_scores.remove(&peer_id);

                    if let Some(bucket) = self.peer_bucket.remove(&peer_id) {
                        if let Some(c) = self.bucket_counts.get_mut(&bucket) {
                            *c = c.saturating_sub(1);
                            if *c == 0 {
                                self.bucket_counts.remove(&bucket);
                            }
                        }
                    }

                    self.connections_total = self.connections_total.saturating_sub(1);
                    if let Some(v) = self.connections_per_peer.get_mut(&peer_id) {
                        *v = v.saturating_sub(1);
                        if *v == 0 {
                            self.connections_per_peer.remove(&peer_id);
                        }
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

                    let topic_s = message.topic.to_string();
                    if self.gs_deny_unknown_topics
                        && !self.gs_allowed_topics.contains(&topic_s)
                        && topic_s != self.topic.hash().to_string()
                    {
                        warn!(peer=%propagation_source, topic=%topic_s, "gossipsub topic not allowed; dropping");
                        self.bump_score(propagation_source, -2);
                        continue;
                    }
                    let bytes = message.data.len() as u32;
                    let (lim_msgs, lim_bytes) = self
                        .gs_topic_limits
                        .get(&topic_s)
                        .cloned()
                        .unwrap_or((self.gs_max_in_msgs_per_sec, self.gs_max_in_bytes_per_sec));
                    if !self.gs_allow_inbound(propagation_source, bytes, lim_msgs, lim_bytes) {
                        warn!(peer=%propagation_source, bytes, "gossipsub inbound cap hit; quarantining");
                        self.bump_score(propagation_source, -3);
                        self.quarantine_peer(
                            propagation_source,
                            self.peer_quarantine_s.max(1),
                            "gossipsub_abuse",
                        );
                        continue;
                    }

                    let score = self.peer_scores.entry(propagation_source).or_insert(0);
                    match bincode::deserialize::<ConsensusMsg>(&message.data) {
                        Ok(msg) => {
                            *score = (*score).saturating_add(1);
                            return Ok(P2pEvent::Consensus {
                                from: propagation_source,
                                msg,
                                raw: message.data,
                            });
                        }
                        Err(e) => {
                            warn!(peer=%propagation_source, "failed to decode consensus message: {e}");
                            *score = (*score).saturating_sub(5);
                            if *score < BAN_THRESHOLD {
                                self.ban_peer(propagation_source);
                            }
                        }
                    }
                }

                SwarmEvent::Behaviour(BehaviourEvent::Rr(RequestResponseEvent::Message {
                    peer,
                    message,
                })) => {
                    match message {
                        RequestResponseMessage::Request {
                            request, channel, ..
                        } => {
                            let now = std::time::Instant::now();
                            let kind = ProtoKind::from_req(&request);
                            let est_bytes = bincode::serialized_size(&request).unwrap_or(0) as u32;

                            if !self.rr_allow_global_in(now, est_bytes) {
                                warn!(%peer, ?kind, bytes = est_bytes, "global RR inbound bandwidth cap hit; dropping request");
                                self.bump_score(peer, -2);
                                continue;
                            }

                            if !self.rr_allow_inbound(now, peer, kind, est_bytes) {
                                continue;
                            }

                            return Ok(P2pEvent::Request {
                                from: peer,
                                req: request,
                                channel,
                            });
                        }
                        RequestResponseMessage::Response { response, .. } => {
                            return Ok(P2pEvent::Response {
                                from: peer,
                                resp: response,
                            });
                        }
                    }
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

// -----------------------------------------------------------------------------
// P2pEvent
// -----------------------------------------------------------------------------

/// Events produced by the P2p layer.
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

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bucket_from_multiaddr_ip4() {
        let addr: Multiaddr = "/ip4/192.168.1.100/tcp/7001".parse().unwrap();
        let bucket = bucket_from_multiaddr(&addr, "ip16");
        assert_eq!(bucket, Some("ip4:192.168".to_string()));
        let bucket24 = bucket_from_multiaddr(&addr, "ip24");
        assert_eq!(bucket24, Some("ip4:192.168.1".to_string()));
    }

    #[test]
    fn test_bucket_from_multiaddr_ip6() {
        let addr: Multiaddr = "/ip6/2001:0db8:85a3:0000:0000:8a2e:0370:7334/tcp/7001".parse().unwrap();
        let bucket = bucket_from_multiaddr(&addr, "ip16");
        assert_eq!(bucket, Some("ip6:20010db8".to_string()));
        let bucket24 = bucket_from_multiaddr(&addr, "ip24");
        assert_eq!(bucket24, Some("ip6:20010db885a3".to_string()));
    }

    #[test]
    fn test_proto_constants() {
        assert_eq!(proto_block().as_ref(), "/iona/block/1.0.0");
        assert_eq!(proto_status().as_ref(), "/iona/status/1.0.0");
        assert_eq!(proto_range().as_ref(), "/iona/blockrange/1.0.0");
        assert_eq!(proto_state().as_ref(), "/iona/state/1.0.0");
    }

    #[test]
    fn test_config_validation() {
        let mut cfg = P2pConfig::default();
        cfg.max_connections_total = 0;
        assert!(cfg.validate().is_err());
        cfg.max_connections_total = 10;

        cfg.max_connections_per_peer = 0;
        assert!(cfg.validate().is_err());
        cfg.max_connections_per_peer = 8;

        cfg.peer_quarantine_s = 0;
        assert!(cfg.validate().is_err());
        cfg.peer_quarantine_s = 60;

        cfg.rr_strikes_before_ban = 0;
        cfg.rr_strikes_before_quarantine = 0;
        assert!(cfg.validate().is_err());
    }
}
