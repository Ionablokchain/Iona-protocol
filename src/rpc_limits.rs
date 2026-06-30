//! Quantum RPC hardening: rate limiting, IP ban/quarantine, request budgets,
//! concurrency cap, structured violation tracking, and request‑ID generation.
//!
//! # Production Features
//! - Thread‑safe with `parking_lot::Mutex` and atomic counters.
//! - Persistent state (banned/quarantined IPs) with atomic writes and file locking.
//! - Configurable parameters via `RpcHardeningConfig`.
//! - Whitelist and blacklist support (static IP overrides).
//! - Background cleanup of idle IP entries.
//! - Structured logging with `tracing`.
//! - Versioned serialization for forward compatibility.

use fs2::FileExt;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{BufReader, BufWriter, Write},
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use thiserror::Error;
use tracing::{debug, error, info, trace, warn};

// -----------------------------------------------------------------------------
// Constants (defaults)
// -----------------------------------------------------------------------------

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Default max body bytes before rejection.
const DEFAULT_MAX_BODY_BYTES: usize = 4_096;

/// Default max items in a batch RPC call.
const DEFAULT_MAX_BATCH_ITEMS: usize = 10;

/// Default max pubkey bytes.
const DEFAULT_MAX_TX_PUBKEY_BYTES: usize = 64;

/// Default global max concurrent requests.
const DEFAULT_MAX_CONCURRENT_REQUESTS: usize = 100;

/// Default submit rate per second per IP.
const DEFAULT_SUBMIT_RATE_PER_SEC: u32 = 100;

/// Default read rate per second per IP.
const DEFAULT_READ_RATE_PER_SEC: u32 = 500;

/// Default violations before quarantine.
const DEFAULT_VIOLATIONS_BEFORE_QUARANTINE: u32 = 20;

/// Default quarantines before ban.
const DEFAULT_QUARANTINE_BEFORE_BAN: u32 = 3;

/// Default quarantine duration.
const DEFAULT_QUARANTINE_DURATION: Duration = Duration::from_secs(300);

/// Default idle timeout before IP entry cleanup.
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(600);

/// Default cleanup interval.
const DEFAULT_CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

/// Default decoherence rate for idle IPs.
const DEFAULT_IDLE_DECOHERENCE_RATE: f64 = 0.001;

/// Default persistence file name.
const DEFAULT_PERSIST_FILE: &str = "rpc_hardening_state.json";

/// Default lock timeout in seconds.
const LOCK_TIMEOUT_SECS: u64 = 10;

/// Temporary file extension for atomic writes.
const TEMP_EXT: &str = ".tmp";

/// Current serialization version.
const CURRENT_VERSION: u32 = 1;

/// Max number of IPs to persist (to avoid unbounded file growth).
const MAX_PERSISTED_IPS: usize = 10_000;

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for the quantum RPC hardening.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcHardeningConfig {
    /// Maximum request body size in bytes.
    pub max_body_bytes: usize,
    /// Maximum number of items in a batch request.
    pub max_batch_items: usize,
    /// Maximum public key bytes for a transaction.
    pub max_tx_pubkey_bytes: usize,
    /// Global maximum concurrent requests.
    pub max_concurrent_requests: usize,
    /// Submit rate per second per IP.
    pub submit_rate_per_sec: u32,
    /// Read rate per second per IP.
    pub read_rate_per_sec: u32,
    /// Number of rate limit violations before quarantine.
    pub violations_before_quarantine: u32,
    /// Number of quarantines before permanent ban.
    pub quarantine_before_ban: u32,
    /// Duration of a quarantine.
    #[serde(with = "humantime_serde")]
    pub quarantine_duration: Duration,
    /// Idle timeout before IP entry cleanup.
    #[serde(with = "humantime_serde")]
    pub idle_timeout: Duration,
    /// Cleanup interval for stale entries.
    #[serde(with = "humantime_serde")]
    pub cleanup_interval: Duration,
    /// Decoherence rate for idle IPs (0.0 – 1.0).
    pub idle_decoherence_rate: f64,
    /// Whether to persist state to disk.
    pub persist_state: bool,
    /// Static whitelist of IPs (never blocked).
    pub whitelist: Vec<IpAddr>,
    /// Static blacklist of IPs (always blocked).
    pub blacklist: Vec<IpAddr>,
}

impl Default for RpcHardeningConfig {
    fn default() -> Self {
        Self {
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            max_batch_items: DEFAULT_MAX_BATCH_ITEMS,
            max_tx_pubkey_bytes: DEFAULT_MAX_TX_PUBKEY_BYTES,
            max_concurrent_requests: DEFAULT_MAX_CONCURRENT_REQUESTS,
            submit_rate_per_sec: DEFAULT_SUBMIT_RATE_PER_SEC,
            read_rate_per_sec: DEFAULT_READ_RATE_PER_SEC,
            violations_before_quarantine: DEFAULT_VIOLATIONS_BEFORE_QUARANTINE,
            quarantine_before_ban: DEFAULT_QUARANTINE_BEFORE_BAN,
            quarantine_duration: DEFAULT_QUARANTINE_DURATION,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            cleanup_interval: DEFAULT_CLEANUP_INTERVAL,
            idle_decoherence_rate: DEFAULT_IDLE_DECOHERENCE_RATE,
            persist_state: true,
            whitelist: Vec::new(),
            blacklist: Vec::new(),
        }
    }
}

impl RpcHardeningConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_body_bytes == 0 {
            return Err("max_body_bytes must be > 0".into());
        }
        if self.max_batch_items == 0 {
            return Err("max_batch_items must be > 0".into());
        }
        if self.max_tx_pubkey_bytes == 0 {
            return Err("max_tx_pubkey_bytes must be > 0".into());
        }
        if self.max_concurrent_requests == 0 {
            return Err("max_concurrent_requests must be > 0".into());
        }
        if self.submit_rate_per_sec == 0 {
            return Err("submit_rate_per_sec must be > 0".into());
        }
        if self.read_rate_per_sec == 0 {
            return Err("read_rate_per_sec must be > 0".into());
        }
        if self.violations_before_quarantine == 0 {
            return Err("violations_before_quarantine must be > 0".into());
        }
        if self.quarantine_before_ban == 0 {
            return Err("quarantine_before_ban must be > 0".into());
        }
        if self.quarantine_duration.is_zero() {
            return Err("quarantine_duration must be > 0".into());
        }
        if self.idle_timeout.is_zero() {
            return Err("idle_timeout must be > 0".into());
        }
        if self.cleanup_interval.is_zero() {
            return Err("cleanup_interval must be > 0".into());
        }
        if !(0.0..=1.0).contains(&self.idle_decoherence_rate) {
            return Err("idle_decoherence_rate must be between 0.0 and 1.0".into());
        }
        Ok(())
    }

    /// Convert to an immutable config.
    pub fn freeze(self) -> Arc<Self> {
        Arc::new(self)
    }
}

// -----------------------------------------------------------------------------
// Persistent State (versioned)
// -----------------------------------------------------------------------------

/// Persistent IP state for bans and quarantines.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistentIpEntry {
    /// IP address (string form).
    address: String,
    /// Status: "banned" or "quarantined".
    status: String,
    /// For quarantined: expiry timestamp (Unix seconds).
    until: Option<u64>,
    /// Escalation count.
    escalation_count: u32,
}

/// Persistent state file format.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistentStateV1 {
    version: u32,
    entries: Vec<PersistentIpEntry>,
    last_modified: u64,
}

impl PersistentStateV1 {
    fn from_limiter(limiter: &RpcLimiter) -> Self {
        let ips = limiter.ips.lock();
        let mut entries = Vec::new();
        for (ip, entry) in ips.iter() {
            match &entry.status {
                IpStatus::Banned => {
                    entries.push(PersistentIpEntry {
                        address: ip.to_string(),
                        status: "banned".to_string(),
                        until: None,
                        escalation_count: 0,
                    });
                }
                IpStatus::Quarantined { until, escalation_count } => {
                    entries.push(PersistentIpEntry {
                        address: ip.to_string(),
                        status: "quarantined".to_string(),
                        until: Some(until.elapsed().as_secs()),
                        escalation_count: *escalation_count,
                    });
                }
                _ => {}
            }
        }
        // Cap entries to avoid unlimited growth.
        if entries.len() > MAX_PERSISTED_IPS {
            entries.truncate(MAX_PERSISTED_IPS);
        }
        Self {
            version: CURRENT_VERSION,
            entries,
            last_modified: current_timestamp(),
        }
    }

    fn apply_to_limiter(&self, limiter: &RpcLimiter) {
        let mut ips = limiter.ips.lock();
        for entry in &self.entries {
            let ip: IpAddr = match entry.address.parse() {
                Ok(ip) => ip,
                Err(_) => continue,
            };
            match entry.status.as_str() {
                "banned" => {
                    let e = ips.entry(ip).or_insert_with(QuantumIpEntry::new);
                    e.status = IpStatus::Banned;
                    e.coherence = 0.0;
                }
                "quarantined" => {
                    let until = entry
                        .until
                        .map(|secs| Instant::now() + Duration::from_secs(secs))
                        .unwrap_or_else(|| Instant::now() + DEFAULT_QUARANTINE_DURATION);
                    let e = ips.entry(ip).or_insert_with(QuantumIpEntry::new);
                    e.status = IpStatus::Quarantined {
                        until,
                        escalation_count: entry.escalation_count,
                    };
                    e.coherence = 0.5;
                }
                _ => {}
            }
        }
    }
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── File I/O with locking ──────────────────────────────────────────────

fn acquire_lock(path: &Path) -> Result<File, String> {
    let lock_path = path.with_extension("lock");
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .open(&lock_path)
        .map_err(|e| format!("cannot open lock file: {}", e))?;
    let timeout = Duration::from_secs(LOCK_TIMEOUT_SECS);
    let start = Instant::now();
    loop {
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(file),
            Err(_) => {
                if start.elapsed() > timeout {
                    return Err(format!("lock timeout after {}s", LOCK_TIMEOUT_SECS));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

fn release_lock(file: File) -> Result<(), String> {
    file.unlock().map_err(|e| format!("unlock error: {}", e))
}

fn load_state(path: &Path) -> Result<PersistentStateV1, String> {
    if !path.exists() {
        return Err("file not found".into());
    }
    let _lock = acquire_lock(path)?;
    let file = File::open(path).map_err(|e| format!("open error: {}", e))?;
    let reader = BufReader::new(file);
    let raw: serde_json::Value = serde_json::from_reader(reader)
        .map_err(|e| format!("parse error: {}", e))?;
    if let Some(version) = raw.get("version").and_then(|v| v.as_u64()) {
        if version != CURRENT_VERSION as u64 {
            return Err(format!(
                "unsupported version: {} (expected {})",
                version, CURRENT_VERSION
            ));
        }
        let st: PersistentStateV1 = serde_json::from_value(raw)
            .map_err(|e| format!("deserialize error: {}", e))?;
        Ok(st)
    } else {
        // Legacy: no version, treat as empty.
        Err("legacy format not supported".into())
    }
}

fn save_state(path: &Path, state: &PersistentStateV1) -> Result<(), String> {
    let json = serde_json::to_string_pretty(state)
        .map_err(|e| format!("serialize error: {}", e))?;
    let _lock = acquire_lock(path)?;
    let temp_path = path.with_extension(TEMP_EXT);
    fs::write(&temp_path, &json).map_err(|e| format!("write temp error: {}", e))?;
    fs::rename(&temp_path, path).map_err(|e| format!("rename error: {}", e))?;
    Ok(())
}

// -----------------------------------------------------------------------------
// Quantum Token Bucket
// -----------------------------------------------------------------------------

/// Quantum token bucket — a harmonic oscillator model for rate limiting.
struct QuantumTokenBucket {
    tokens: f64,
    max: f64,
    last: Instant,
    rate_per_sec: f64,
    violation_streak: u32,
    coherence: f64,
}

impl QuantumTokenBucket {
    fn new(rate_per_sec: u32) -> Self {
        let r = rate_per_sec as f64;
        Self {
            tokens: r,
            max: r,
            last: Instant::now(),
            rate_per_sec: r,
            violation_streak: 0,
            coherence: 1.0,
        }
    }

    fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        let refill = elapsed * self.rate_per_sec;
        self.tokens = (self.tokens + refill).min(self.max);
        self.coherence *= 1.0 - (elapsed * DEFAULT_IDLE_DECOHERENCE_RATE).min(0.1);

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            self.violation_streak = 0;
            self.coherence = (self.coherence + 0.01).min(1.0);
            true
        } else {
            self.violation_streak = self.violation_streak.saturating_add(1);
            self.coherence *= 0.95;
            false
        }
    }
}

// -----------------------------------------------------------------------------
// Quantum IP State
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpStatus {
    Allowed,
    Quarantined { until: Instant, escalation_count: u32 },
    Banned,
}

struct QuantumIpEntry {
    submit: QuantumTokenBucket,
    read: QuantumTokenBucket,
    status: IpStatus,
    total_rejections: u64,
    coherence: f64,
    entanglement_entropy: f64,
}

impl QuantumIpEntry {
    fn new() -> Self {
        Self {
            submit: QuantumTokenBucket::new(DEFAULT_SUBMIT_RATE_PER_SEC),
            read: QuantumTokenBucket::new(DEFAULT_READ_RATE_PER_SEC),
            status: IpStatus::Allowed,
            total_rejections: 0,
            coherence: 1.0,
            entanglement_entropy: 0.0,
        }
    }

    fn is_blocked(&mut self) -> bool {
        match &self.status {
            IpStatus::Banned => {
                self.coherence = 0.0;
                true
            }
            IpStatus::Quarantined { until, escalation_count } => {
                if Instant::now() < *until {
                    self.coherence *= 0.99;
                    true
                } else {
                    let count = *escalation_count;
                    self.status = IpStatus::Allowed;
                    self.submit.tokens = self.submit.max / 2.0;
                    self.read.tokens = self.read.max / 2.0;
                    self.coherence = 0.5;
                    if count >= DEFAULT_QUARANTINE_BEFORE_BAN {
                        self.status = IpStatus::Banned;
                        self.coherence = 0.0;
                        return true;
                    }
                    false
                }
            }
            IpStatus::Allowed => false,
        }
    }

    fn maybe_escalate(&mut self, streak: u32, config: &RpcHardeningConfig) {
        if streak < config.violations_before_quarantine {
            self.coherence *= 0.98;
            return;
        }

        match &self.status {
            IpStatus::Allowed => {
                warn!(
                    streak,
                    coherence = self.coherence,
                    "rpc::limiter: IP entering quantum quarantine"
                );
                self.status = IpStatus::Quarantined {
                    until: Instant::now() + config.quarantine_duration,
                    escalation_count: 1,
                };
                self.coherence *= 0.7;
                self.entanglement_entropy += 0.1;
            }
            IpStatus::Quarantined { until, escalation_count } => {
                let new_count = escalation_count + 1;
                if new_count >= config.quarantine_before_ban {
                    warn!(
                        escalations = new_count,
                        "rpc::limiter: IP wavefunction collapsed to |banned⟩"
                    );
                    self.status = IpStatus::Banned;
                    self.coherence = 0.0;
                    self.entanglement_entropy = 0.0;
                } else {
                    self.status = IpStatus::Quarantined {
                        until: (*until).max(Instant::now()) + config.quarantine_duration,
                        escalation_count: new_count,
                    };
                    self.coherence *= 0.8;
                    self.entanglement_entropy += 0.05;
                }
            }
            IpStatus::Banned => {
                self.coherence = 0.0;
            }
        }
    }

    fn apply_idle_decoherence(&mut self, elapsed: Duration, rate: f64) {
        let dt = elapsed.as_secs_f64();
        self.coherence *= (-rate * dt).exp().max(0.0);
        self.entanglement_entropy = -self.coherence * self.coherence.ln().max(0.0);
    }
}

// -----------------------------------------------------------------------------
// Concurrency Guard
// -----------------------------------------------------------------------------

#[derive(Clone)]
pub struct ConcurrencyGuard {
    current: Arc<AtomicUsize>,
    max: usize,
}

impl ConcurrencyGuard {
    pub const fn new(max: usize) -> Self {
        Self {
            current: Arc::new(AtomicUsize::new(0)),
            max,
        }
    }

    pub fn try_acquire(&self) -> Option<ConcurrencyTicket> {
        let mut cur = self.current.load(Ordering::Relaxed);
        loop {
            if cur >= self.max {
                return None;
            }
            match self.current.compare_exchange_weak(
                cur,
                cur + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return Some(ConcurrencyTicket {
                        guard: self.current.clone(),
                    });
                }
                Err(actual) => cur = actual,
            }
        }
    }

    pub fn current(&self) -> usize {
        self.current.load(Ordering::Relaxed)
    }
}

pub struct ConcurrencyTicket {
    guard: Arc<AtomicUsize>,
}

impl Drop for ConcurrencyTicket {
    fn drop(&mut self) {
        self.guard.fetch_sub(1, Ordering::AcqRel);
    }
}

// -----------------------------------------------------------------------------
// Request ID Generator
// -----------------------------------------------------------------------------

static REQUEST_COUNTER: AtomicUsize = AtomicUsize::new(1);

#[must_use]
pub fn new_request_id() -> String {
    let seq = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_millis();
    format!("req-{seq}-{ts:04x}")
}

// -----------------------------------------------------------------------------
// RPC Limit Result
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcLimitResult {
    Allowed,
    RateLimited,
    Blocked,
}

impl RpcLimitResult {
    pub const fn is_allowed(self) -> bool {
        matches!(self, Self::Allowed)
    }

    pub const fn http_status(self) -> u16 {
        match self {
            Self::Allowed => 200,
            Self::RateLimited => 429,
            Self::Blocked => 403,
        }
    }
}

// -----------------------------------------------------------------------------
// Validation Error
// -----------------------------------------------------------------------------

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ValidationError {
    #[error("PAYLOAD_TOO_LONG: {len} > {max}")]
    PayloadTooLong { len: usize, max: usize },

    #[error("INVALID_ENCODING")]
    InvalidUtf8,

    #[error("PUBKEY_TOO_LONG")]
    PubkeyTooLong,

    #[error("GAS_LIMIT_ZERO")]
    GasLimitZero,

    #[error("MAX_FEE_ZERO")]
    MaxFeeZero,

    #[error("CHAIN_ID_MISMATCH: got={got} expected={expected}")]
    ChainIdMismatch { got: u64, expected: u64 },

    #[error("NONCE_GAP: sender={sender} expected={expected} got={got}")]
    NonceGap {
        sender: String,
        expected: u64,
        got: u64,
    },

    #[error("BATCH_TOO_LARGE: {count} > {max}")]
    BatchTooLarge { count: usize, max: usize },
}

// -----------------------------------------------------------------------------
// Metrics Snapshot
// -----------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct RpcMetrics {
    pub rate_limit_hits: usize,
    pub payload_too_large: usize,
    pub decode_errors: usize,
    pub concurrency_rejected: usize,
    pub ips_quarantined: usize,
    pub ips_banned: usize,
    pub concurrent_requests: usize,
    pub average_coherence: f64,
    pub total_entanglement_entropy: f64,
}

// -----------------------------------------------------------------------------
// Main RpcLimiter
// -----------------------------------------------------------------------------

pub struct RpcLimiter {
    ips: Mutex<HashMap<IpAddr, QuantumIpEntry>>,
    last_cleanup: Mutex<Instant>,
    pub concurrency: ConcurrencyGuard,
    config: Arc<RpcHardeningConfig>,
    persist_path: Option<PathBuf>,

    // Atomic metrics
    metric_rate_limit_hits: Arc<AtomicUsize>,
    metric_quarantine_total: Arc<AtomicUsize>,
    metric_ban_total: Arc<AtomicUsize>,
    metric_payload_too_large: Arc<AtomicUsize>,
    metric_decode_errors: Arc<AtomicUsize>,
    metric_concurrency_rejected: Arc<AtomicUsize>,
}

impl RpcLimiter {
    /// Create a new limiter with the given configuration.
    pub fn new(config: RpcHardeningConfig) -> Result<Self, String> {
        config.validate()?;
        let config = Arc::new(config);
        let limiter = Self {
            ips: Mutex::new(HashMap::new()),
            last_cleanup: Mutex::new(Instant::now()),
            concurrency: ConcurrencyGuard::new(config.max_concurrent_requests),
            config: config.clone(),
            persist_path: None,
            metric_rate_limit_hits: Arc::new(AtomicUsize::new(0)),
            metric_quarantine_total: Arc::new(AtomicUsize::new(0)),
            metric_ban_total: Arc::new(AtomicUsize::new(0)),
            metric_payload_too_large: Arc::new(AtomicUsize::new(0)),
            metric_decode_errors: Arc::new(AtomicUsize::new(0)),
            metric_concurrency_rejected: Arc::new(AtomicUsize::new(0)),
        };
        // Apply whitelist/blacklist
        limiter.apply_static_lists();
        Ok(limiter)
    }

    /// Create with persistence to disk.
    pub fn with_persistence(
        data_dir: &str,
        config: RpcHardeningConfig,
    ) -> Result<Self, String> {
        config.validate()?;
        let config = Arc::new(config);
        let path = PathBuf::from(data_dir).join(DEFAULT_PERSIST_FILE);
        let mut limiter = Self {
            ips: Mutex::new(HashMap::new()),
            last_cleanup: Mutex::new(Instant::now()),
            concurrency: ConcurrencyGuard::new(config.max_concurrent_requests),
            config: config.clone(),
            persist_path: Some(path.clone()),
            metric_rate_limit_hits: Arc::new(AtomicUsize::new(0)),
            metric_quarantine_total: Arc::new(AtomicUsize::new(0)),
            metric_ban_total: Arc::new(AtomicUsize::new(0)),
            metric_payload_too_large: Arc::new(AtomicUsize::new(0)),
            metric_decode_errors: Arc::new(AtomicUsize::new(0)),
            metric_concurrency_rejected: Arc::new(AtomicUsize::new(0)),
        };

        // Load persistent state
        if config.persist_state && path.exists() {
            match load_state(&path) {
                Ok(state) => {
                    state.apply_to_limiter(&limiter);
                    info!(path = %path.display(), "loaded RPC hardening state");
                }
                Err(e) => {
                    warn!(error = %e, "failed to load RPC hardening state, starting fresh");
                }
            }
        }

        // Apply static lists
        limiter.apply_static_lists();
        Ok(limiter)
    }

    /// Apply whitelist and blacklist from config.
    fn apply_static_lists(&self) {
        let mut ips = self.ips.lock();
        // Remove blacklisted IPs if present (they get re‑inserted as banned)
        for ip in &self.config.blacklist {
            let entry = ips.entry(*ip).or_insert_with(QuantumIpEntry::new);
            entry.status = IpStatus::Banned;
            entry.coherence = 0.0;
        }
        // Whitelist: ensure they are allowed (override any existing state)
        for ip in &self.config.whitelist {
            let entry = ips.entry(*ip).or_insert_with(QuantumIpEntry::new);
            entry.status = IpStatus::Allowed;
            entry.coherence = 1.0;
            entry.entanglement_entropy = 0.0;
        }
    }

    // ── Check methods ──────────────────────────────────────────────────

    pub fn check_submit(&self, ip: IpAddr, req_id: &str) -> RpcLimitResult {
        self.cleanup_if_needed();
        // Check static lists first
        if self.config.blacklist.contains(&ip) {
            return RpcLimitResult::Blocked;
        }
        if self.config.whitelist.contains(&ip) {
            return RpcLimitResult::Allowed;
        }

        let mut ips = self.ips.lock();
        let entry = ips.entry(ip).or_insert_with(QuantumIpEntry::new);

        if entry.is_blocked() {
            entry.total_rejections += 1;
            self.metric_rate_limit_hits.fetch_add(1, Ordering::Relaxed);
            warn!(%ip, %req_id, coherence = entry.coherence, "rpc::limiter: blocked IP attempted submit");
            return RpcLimitResult::Blocked;
        }

        if entry.submit.try_consume() {
            RpcLimitResult::Allowed
        } else {
            entry.total_rejections += 1;
            let streak = entry.submit.violation_streak;
            entry.maybe_escalate(streak, &self.config);

            self.metric_rate_limit_hits.fetch_add(1, Ordering::Relaxed);
            if matches!(entry.status, IpStatus::Quarantined { .. }) {
                self.metric_quarantine_total.fetch_add(1, Ordering::Relaxed);
            } else if entry.status == IpStatus::Banned {
                self.metric_ban_total.fetch_add(1, Ordering::Relaxed);
            }

            warn!(%ip, %req_id, streak, coherence = entry.coherence, "rpc::limiter: submit rate limit hit");
            RpcLimitResult::RateLimited
        }
    }

    pub fn check_read(&self, ip: IpAddr, req_id: &str) -> RpcLimitResult {
        self.cleanup_if_needed();
        if self.config.blacklist.contains(&ip) {
            return RpcLimitResult::Blocked;
        }
        if self.config.whitelist.contains(&ip) {
            return RpcLimitResult::Allowed;
        }

        let mut ips = self.ips.lock();
        let entry = ips.entry(ip).or_insert_with(QuantumIpEntry::new);

        if entry.is_blocked() {
            entry.total_rejections += 1;
            self.metric_rate_limit_hits.fetch_add(1, Ordering::Relaxed);
            warn!(%ip, %req_id, coherence = entry.coherence, "rpc::limiter: blocked IP attempted read");
            return RpcLimitResult::Blocked;
        }

        if entry.read.try_consume() {
            RpcLimitResult::Allowed
        } else {
            entry.total_rejections += 1;
            let streak = entry.read.violation_streak;
            entry.maybe_escalate(streak, &self.config);

            self.metric_rate_limit_hits.fetch_add(1, Ordering::Relaxed);
            if matches!(entry.status, IpStatus::Quarantined { .. }) {
                self.metric_quarantine_total.fetch_add(1, Ordering::Relaxed);
            } else if entry.status == IpStatus::Banned {
                self.metric_ban_total.fetch_add(1, Ordering::Relaxed);
            }

            warn!(%ip, %req_id, streak, coherence = entry.coherence, "rpc::limiter: read rate limit hit");
            RpcLimitResult::RateLimited
        }
    }

    // ── Recording violations ──────────────────────────────────────────

    pub fn record_decode_error(&self, ip: IpAddr, req_id: &str) {
        self.metric_decode_errors.fetch_add(1, Ordering::Relaxed);
        warn!(%ip, %req_id, "rpc::limiter: decode error");

        let mut ips = self.ips.lock();
        let entry = ips.entry(ip).or_insert_with(QuantumIpEntry::new);
        entry.submit.violation_streak = entry.submit.violation_streak.saturating_add(5);
        entry.coherence *= 0.8;
        let streak = entry.submit.violation_streak;
        entry.maybe_escalate(streak, &self.config);
    }

    pub fn record_payload_too_large(&self, ip: IpAddr, req_id: &str, size: usize) {
        self.metric_payload_too_large.fetch_add(1, Ordering::Relaxed);
        warn!(%ip, %req_id, size, "rpc::limiter: payload too large");

        let mut ips = self.ips.lock();
        let entry = ips.entry(ip).or_insert_with(QuantumIpEntry::new);
        entry.submit.violation_streak = entry.submit.violation_streak.saturating_add(3);
        entry.coherence *= 0.85;
        let streak = entry.submit.violation_streak;
        entry.maybe_escalate(streak, &self.config);
    }

    // ── Concurrency ────────────────────────────────────────────────────

    pub fn try_concurrency_slot(&self, req_id: &str) -> Option<ConcurrencyTicket> {
        match self.concurrency.try_acquire() {
            Some(t) => Some(t),
            None => {
                self.metric_concurrency_rejected.fetch_add(1, Ordering::Relaxed);
                warn!(
                    %req_id,
                    current = self.concurrency.current(),
                    max = self.config.max_concurrent_requests,
                    "rpc::limiter: concurrency cap reached"
                );
                None
            }
        }
    }

    // ── Cleanup ─────────────────────────────────────────────────────────

    fn cleanup_if_needed(&self) {
        let mut last = self.last_cleanup.lock();
        if last.elapsed() < self.config.cleanup_interval {
            return;
        }
        *last = Instant::now();
        drop(last);

        let cutoff = self.config.idle_timeout;
        let mut ips = self.ips.lock();
        ips.retain(|_, entry| {
            if entry.status == IpStatus::Banned {
                return true;
            }
            let idle_time = entry.submit.last.elapsed().min(entry.read.last.elapsed());
            let keep = idle_time < cutoff;
            if !keep {
                entry.apply_idle_decoherence(idle_time, self.config.idle_decoherence_rate);
            }
            keep
        });

        // Persist if needed
        if self.config.persist_state {
            if let Some(path) = &self.persist_path {
                let state = PersistentStateV1::from_limiter(self);
                if let Err(e) = save_state(path, &state) {
                    warn!(error = %e, "failed to persist RPC hardening state");
                }
            }
        }
    }

    // ── Metrics ────────────────────────────────────────────────────────

    pub fn metrics_snapshot(&self) -> RpcMetrics {
        let ips = self.ips.lock();
        let quarantined = ips
            .values()
            .filter(|e| matches!(e.status, IpStatus::Quarantined { .. }))
            .count();
        let banned = ips
            .values()
            .filter(|e| e.status == IpStatus::Banned)
            .count();

        let total_coherence: f64 = ips.values().map(|e| e.coherence).sum();
        let total_entropy: f64 = ips.values().map(|e| e.entanglement_entropy).sum();
        let count = ips.len().max(1);
        let avg_coherence = total_coherence / count as f64;

        RpcMetrics {
            rate_limit_hits: self.metric_rate_limit_hits.load(Ordering::Relaxed),
            payload_too_large: self.metric_payload_too_large.load(Ordering::Relaxed),
            decode_errors: self.metric_decode_errors.load(Ordering::Relaxed),
            concurrency_rejected: self.metric_concurrency_rejected.load(Ordering::Relaxed),
            ips_quarantined: quarantined,
            ips_banned: banned,
            concurrent_requests: self.concurrency.current(),
            average_coherence: avg_coherence,
            total_entanglement_entropy: total_entropy,
        }
    }

    /// Force persistence to disk.
    pub fn flush(&self) -> Result<(), String> {
        if let Some(path) = &self.persist_path {
            let state = PersistentStateV1::from_limiter(self);
            save_state(path, &state)?;
        }
        Ok(())
    }

    /// Get configuration.
    pub fn config(&self) -> &RpcHardeningConfig {
        &self.config
    }
}

// -----------------------------------------------------------------------------
// Validation Functions
// -----------------------------------------------------------------------------

pub fn validate_tx(
    tx: &crate::types::Tx,
    expected_chain_id: u64,
    sender_nonce: u64,
    config: &RpcHardeningConfig,
) -> Result<(), ValidationError> {
    if tx.payload.len() > config.max_body_bytes {
        return Err(ValidationError::PayloadTooLong {
            len: tx.payload.len(),
            max: config.max_body_bytes,
        });
    }
    if std::str::from_utf8(tx.payload.as_bytes()).is_err() {
        return Err(ValidationError::InvalidUtf8);
    }
    if tx.pubkey.len() > config.max_tx_pubkey_bytes {
        return Err(ValidationError::PubkeyTooLong);
    }
    if tx.gas_limit == 0 {
        return Err(ValidationError::GasLimitZero);
    }
    if tx.max_fee_per_gas == 0 {
        return Err(ValidationError::MaxFeeZero);
    }
    if tx.chain_id != expected_chain_id {
        return Err(ValidationError::ChainIdMismatch {
            got: tx.chain_id,
            expected: expected_chain_id,
        });
    }
    if tx.nonce < sender_nonce {
        return Err(ValidationError::NonceGap {
            sender: tx.from.clone(),
            expected: sender_nonce,
            got: tx.nonce,
        });
    }
    Ok(())
}

pub fn validate_body_size(body: &[u8], config: &RpcHardeningConfig) -> Result<(), ValidationError> {
    if body.len() > config.max_body_bytes {
        Err(ValidationError::PayloadTooLong {
            len: body.len(),
            max: config.max_body_bytes,
        })
    } else {
        Ok(())
    }
}

pub fn validate_batch_size(count: usize, config: &RpcHardeningConfig) -> Result<(), ValidationError> {
    if count > config.max_batch_items {
        Err(ValidationError::BatchTooLarge {
            count,
            max: config.max_batch_items,
        })
    } else {
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tempfile::tempdir;

    fn test_config() -> RpcHardeningConfig {
        let mut cfg = RpcHardeningConfig::default();
        cfg.submit_rate_per_sec = 10;
        cfg.read_rate_per_sec = 20;
        cfg.violations_before_quarantine = 5;
        cfg.quarantine_before_ban = 2;
        cfg.quarantine_duration = Duration::from_secs(1);
        cfg.idle_timeout = Duration::from_secs(5);
        cfg.cleanup_interval = Duration::from_secs(1);
        cfg.persist_state = false;
        cfg
    }

    fn ip(a: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, a))
    }

    #[test]
    fn test_submit_rate_limit_allows_up_to_burst() {
        let cfg = test_config();
        let limiter = RpcLimiter::new(cfg).unwrap();
        let peer = ip(1);
        for _ in 0..10 {
            assert_eq!(limiter.check_submit(peer, "req-0"), RpcLimitResult::Allowed);
        }
    }

    #[test]
    fn test_submit_rate_limit_rejects_after_burst() {
        let cfg = test_config();
        let limiter = RpcLimiter::new(cfg).unwrap();
        let peer = ip(2);
        for _ in 0..10 {
            limiter.check_submit(peer, "req-x");
        }
        let result = limiter.check_submit(peer, "req-x");
        assert!(matches!(result, RpcLimitResult::RateLimited | RpcLimitResult::Blocked));
    }

    #[test]
    fn test_quarantine_after_violations() {
        let cfg = test_config();
        let limiter = RpcLimiter::new(cfg).unwrap();
        let peer = ip(3);
        // Violate 5 times
        for _ in 0..15 {
            limiter.check_submit(peer, "req-x");
        }
        let result = limiter.check_submit(peer, "req-x");
        assert!(matches!(result, RpcLimitResult::RateLimited | RpcLimitResult::Blocked));
    }

    #[test]
    fn test_whitelist_overrides() {
        let mut cfg = test_config();
        cfg.whitelist.push(ip(10));
        let limiter = RpcLimiter::new(cfg).unwrap();
        for _ in 0..100 {
            assert_eq!(limiter.check_submit(ip(10), "req"), RpcLimitResult::Allowed);
        }
    }

    #[test]
    fn test_blacklist_blocks() {
        let mut cfg = test_config();
        cfg.blacklist.push(ip(20));
        let limiter = RpcLimiter::new(cfg).unwrap();
        assert_eq!(limiter.check_submit(ip(20), "req"), RpcLimitResult::Blocked);
    }

    #[test]
    fn test_persistence() {
        let dir = tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        let mut cfg = test_config();
        cfg.persist_state = true;

        // Create limiter and record some state.
        let limiter = RpcLimiter::with_persistence(path, cfg.clone()).unwrap();
        let peer = ip(30);
        for _ in 0..15 {
            limiter.check_submit(peer, "req");
        }
        limiter.flush().unwrap();

        // Create new limiter that loads state.
        let limiter2 = RpcLimiter::with_persistence(path, cfg).unwrap();
        let metrics = limiter2.metrics_snapshot();
        assert!(metrics.ips_banned > 0 || metrics.ips_quarantined > 0);
    }

    #[test]
    fn test_validation_errors() {
        let cfg = test_config();
        let tx = crate::types::Tx {
            payload: "".into(),
            pubkey: vec![0; 65],
            gas_limit: 0,
            max_fee_per_gas: 0,
            chain_id: 1,
            nonce: 5,
            from: "sender".into(),
            signature: vec![],
        };
        assert!(validate_tx(&tx, 1, 5, &cfg).is_err());
        assert!(validate_tx(&tx, 1, 0, &cfg).is_err());
    }

    #[test]
    fn test_concurrency_cap() {
        let cfg = test_config();
        let limiter = RpcLimiter::new(cfg).unwrap();
        let mut tickets = Vec::new();
        for _ in 0..DEFAULT_MAX_CONCURRENT_REQUESTS {
            tickets.push(limiter.try_concurrency_slot("req").expect("slot"));
        }
        assert!(limiter.try_concurrency_slot("overflow").is_none());
        drop(tickets);
        assert!(limiter.try_concurrency_slot("after").is_some());
    }

    #[test]
    fn test_request_id_uniqueness() {
        let ids: Vec<_> = (0..100).map(|_| new_request_id()).collect();
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(ids.len(), unique.len());
    }

    #[test]
    fn test_metrics() {
        let cfg = test_config();
        let limiter = RpcLimiter::new(cfg).unwrap();
        let peer = ip(40);
        limiter.check_submit(peer, "req");
        let metrics = limiter.metrics_snapshot();
        assert!(metrics.average_coherence >= 0.0);
        assert!(metrics.total_entanglement_entropy >= 0.0);
    }
}
