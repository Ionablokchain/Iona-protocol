# IONA Security-First Manifesto

**Version:** 28.1.0
**Date:** 2026-03-02
**Status:** Normative — enforced by CI

> _"Security is not a feature we added to IONA. Security is what IONA is built from."_

---

## What "Security-First" Means for IONA

Most blockchain nodes are built feature-first and hardened afterward. Security is treated as a layer on top: add rate limiting, encrypt the keystore, maybe fuzz a few paths before launch. The architecture is already decided; security fills in the gaps it was given.

**IONA is different in a specific, verifiable way:** every primary architecture decision was made with security as the deciding constraint, not a post-hoc requirement. When we chose a programming language, security was the first criterion. When we chose a signature algorithm, we chose the one with the better security property — not the more popular one. When we had to decide whether a double-sign attempt should warn or halt, we chose halt. These decisions are enumerated in Section 0 of this document so you can evaluate them for yourself.

The result is not a blockchain with a security checklist applied on top. It is a blockchain where the security properties are **structural** — they emerge from what the system is built from, not from what was bolted on afterward.

This document captures those decisions and the ongoing promises they imply as a set of **concrete, measurable guarantees** — not aspirational marketing.

Each guarantee is backed by code you can read, tests you can run, and CI checks that block merges when they fail.

---

## Table of Contents

0. [Security-Driven Architecture Decisions](#0-security-driven-architecture-decisions)
1. [Guarantees](#1-guarantees)
2. [Non-Goals](#2-non-goals-important-for-realism)
3. [Secure Defaults](#3-secure-defaults)
4. [Key Management](#4-key-management)
5. [RPC Hardening](#5-rpc-hardening)
6. [P2P Hardening](#6-p2p-hardening)
7. [Consensus Safety Invariants](#7-consensus-safety-invariants)
8. [Fuzzing & Chaos as First-Class](#8-fuzzing--chaos-as-first-class)
9. [Supply Chain & Release Hardening](#9-supply-chain--release-hardening)
10. [Security Proof Artifacts](#10-security-proof-artifacts)
11. [Presenting IONA as Security-First](#11-presenting-iona-as-security-first)
12. [Memory Safety & Rust Guarantees](#12-memory-safety--rust-guarantees)
13. [Startup Security Boot Sequence](#13-startup-security-boot-sequence)
14. [Audit Trail & Structured Logging](#14-audit-trail--structured-logging)
15. [Prometheus Alert Rules](#15-prometheus-alert-rules)
16. [OS-Level Hardening (systemd)](#16-os-level-hardening-systemd)
17. [Security Changelog by Version](#17-security-changelog-by-version)
18. [Security Debt Tracker](#18-security-debt-tracker)
19. [Comparative Security Matrix](#19-comparative-security-matrix)
20. [Security Review Gate for Contributors](#20-security-review-gate-for-contributors)
21. [Security Glossary](#21-security-glossary)
22. [Deployment Profiles](#22-deployment-profiles)
23. [v28.0 Security Changes (This Release)](#23-v280-security-changes-this-release)

---

## 0. Security-Driven Architecture Decisions

This section answers the question: *where did security actually constrain the design?* These are not security features added on top of a finished architecture. They are the choices that *created* the architecture.

### 0.1 Language: Rust over Go, C++, or Java

**Decision:** IONA is written entirely in Rust.

**Why security drove this choice:**

| Language | Memory safety | Data race safety | Zero-cost abstractions |
|----------|--------------|-----------------|----------------------|
| C / C++ | ❌ Manual | ❌ Manual | ✓ |
| Go | ✓ GC | ✓ Runtime | ❌ GC pauses |
| Java/JVM | ✓ GC | ✓ Runtime | ❌ GC pauses |
| **Rust** | ✓ **Compile-time** | ✓ **Compile-time** | ✓ |

The key distinction: Go and Java provide memory safety through a garbage collector at runtime. Rust provides it through the borrow checker at compile time — with zero runtime overhead. For a consensus node that must be predictable under load, GC pauses are a DoS vector (an attacker can trigger GC pressure to delay consensus messages). Rust eliminates both the vulnerability and the performance penalty simultaneously.

The entire class of memory-corruption vulnerabilities — buffer overflows, use-after-free, double-free, null dereferences — is **impossible to produce in safe Rust code**. This is not a claim about IONA's quality; it is a property of the language enforced by the compiler.

**What we gave up:** Rust has a steeper learning curve, slower initial development velocity, and a smaller talent pool than Go. We accepted these costs because for a security-first blockchain, memory safety at compile time is non-negotiable.

### 0.2 Signature Algorithm: Ed25519 over secp256k1 (ECDSA)

**Decision:** IONA uses Ed25519 for all validator and node signing.

**Why security drove this choice:**

secp256k1/ECDSA (used by Bitcoin and Ethereum) requires a fresh random nonce `k` for every signature. If `k` is ever reused or predictable, the private key can be **fully extracted** from just two signatures. This has happened in production (PlayStation 3, various blockchain wallets). The requirement for a secure random number generator in the signing path is a latent vulnerability.

Ed25519 (RFC 8032) is **deterministic** — the nonce is derived from a hash of the private key and the message. There is no random number generator in the signing path. Nonce reuse is structurally impossible. A broken RNG cannot compromise a validator key.

```rust
// src/crypto/ed25519.rs
// Ed25519 signing — no random input, cannot produce weak signatures
impl Signer for Ed25519Keypair {
    fn sign(&self, msg: &[u8]) -> SignatureBytes {
        let sig: Signature = self.sk.sign(msg); // deterministic
        SignatureBytes(sig.to_bytes().to_vec())
    }
}
```

Additionally, Ed25519 verification is ~2× faster than secp256k1 verification — important when validating hundreds of votes per second in a BFT committee.

**What we gave up:** secp256k1 addresses are directly compatible with Ethereum. IONA uses a separate address space, which requires bridges for EVM interoperability. We accepted this for the security property.

### 0.3 Hash Function: BLAKE3 over SHA-256 or Keccak-256

**Decision:** IONA uses BLAKE3 for all internal hashing (block IDs, state roots, Merkle trees).

**Why security drove this choice:**

SHA-256 and Keccak-256 are cryptographically secure, but BLAKE3 adds two properties relevant for security:

- **Speed:** BLAKE3 is ~3–8× faster than SHA-256 on modern hardware. For a node that must hash under DoS pressure (a flood of blocks all requiring hash verification), slower hashing is a resource amplification vulnerability. With BLAKE3, the cost ratio between attacker and defender is better.
- **No length-extension attacks:** SHA-256 is vulnerable to length-extension attacks on naive `H(key || message)` constructions. BLAKE3's design is inherently immune. This matters for the Merkle proof constructions used in state verification.

Keccak-256 is used only where Ethereum compatibility requires it (EVM address derivation, `eth_` RPC endpoints) — never for IONA's internal security-critical paths.

### 0.4 Authenticated Encryption: AES-256-GCM over AES-256-CBC

**Decision:** The keystore uses AES-256-GCM, not AES-256-CBC or AES-256-CTR.

**Why security drove this choice:**

AES-256-CBC and AES-256-CTR provide *confidentiality* but not *integrity*. An attacker with write access to `keys.enc` can flip bits in the ciphertext, and the node will decrypt a corrupted (attacker-controlled) key without detecting the tampering.

AES-256-GCM is an **authenticated encryption** scheme — it provides both confidentiality AND integrity. A tampered ciphertext will fail authentication during decryption. The node cannot be made to load an attacker-modified key.

```rust
// src/crypto/keystore.rs
// GCM authentication tag is included in ct — tamper detection is automatic
let ct = cipher.encrypt(Nonce::from_slice(&nonce_bytes), seed32.as_slice())?;
// If ct is modified on disk, this line will return Err on the next decrypt attempt
```

### 0.5 Consensus Protocol: BFT over Proof-of-Work

**Decision:** IONA uses Tendermint-style BFT consensus, not Nakamoto-style PoW or longest-chain PoS.

**Why security drove this choice:**

PoW / longest-chain protocols are probabilistically final: a block at height H is "probably" final after K confirmations, but can always be reorganized by an attacker with enough hash power. This creates:

- **Selfish mining attacks** — a miner can withhold blocks to gain disproportionate reward.
- **51% attacks** — an attacker with majority hash power can reorg the chain to double-spend.
- **No clear finality** — wallets and dApps must choose their own K (risk vs. latency trade-off).

BFT consensus provides **immediate, deterministic finality**. Once a block is committed (2/3+ precommits), it is final. There is no "K confirmations" ambiguity, no reorg risk, no selfish mining attack surface. The security model is simpler and the guarantees are stronger.

The trade-off is explicit: BFT requires a known, bounded validator set. IONA is not a permissionless mining chain. We accept this architectural constraint because deterministic finality eliminates an entire category of attacks.

### 0.6 Double-Sign Response: Process Halt over Warning

**Decision:** When `DoubleSignGuard` detects a double-sign attempt, the process halts. It does not warn and continue.

**Why security drove this choice:**

A double-sign in BFT consensus can cause finality violations — two conflicting blocks both reaching 2/3+ precommits. This is the highest-severity failure mode in the system. The only reason for a validator to double-sign in production is:

1. Operator error (running two instances with the same key).
2. A compromise — the attacker is attempting to force equivocation.

In case 1, halting prevents the operator from unknowingly causing harm. In case 2, halting is the correct response — a halted node cannot be weaponized, a running confused node can. The cost of a false positive (accidental halt, node offline for a round) is far lower than the cost of a false negative (double-sign proceeds, finality violated).

```rust
// Err return from check_vote() → consensus engine calls std::process::exit(1)
// Not panic (which could be caught), not warn, not a metric: hard exit.
if existing != &want {
    return Err("double-vote refused".into());
}
```

### 0.7 P2P Transport: Noise Protocol over Plain TLS

**Decision:** All P2P connections use libp2p's Noise protocol (XX handshake), not plain TLS.

**Why security drove this choice:**

TLS provides encryption and server authentication (via certificates). Noise XX provides encryption and **mutual peer authentication** using the peer's Ed25519 identity key — with no certificates, no CAs, no certificate expiry, and no revocation infrastructure.

In a peer-to-peer network:
- There is no "server" to issue certificates to.
- There is no CA that all peers trust.
- Certificate expiry in a live network is an operational DoS vector.

Noise XX eliminates all of these. Every peer is identified by its Ed25519 public key. Connections are authenticated by the same key material that identifies the peer in the network — no separate PKI required.

### 0.8 Panic Profile: `abort` over `unwind`

**Decision:** The release build uses `panic = "abort"`, not the default `panic = "unwind"`.

**Why security drove this choice:**

When Rust panics with `unwind`, the stack unwinds, destructors run, and the process may continue in a partially-initialized state if the panic is caught. In a consensus node, a caught panic in a critical path can leave the state machine in an undefined state — the node continues to run, produce messages, and participate in consensus while its internal invariants are violated.

`panic = "abort"` makes the process terminate immediately on any panic, with no opportunity for recovery. This is the same principle as the double-sign halt: **a dead node is safer than a confused running node**.

The cost: panics cannot be caught with `std::panic::catch_unwind`. We accept this because IONA's code should not panic in normal operation — all error paths use `Result<T, E>` and panics are programmer errors that should be fixed, not caught.

### 0.9 Audit Log: Append-Only File over Database

**Decision:** The audit trail is written to a flat JSON-lines append-only file, not a database.

**Why security drove this choice:**

A database audit trail (SQLite, RocksDB) can be modified after the fact by a compromised process — `UPDATE audit SET action = 'normal_operation' WHERE action = 'equivocation_detected'`. A flat file opened with `OpenOptions::append(true)` cannot be modified by the writing process — it can only append.

Combined with `chattr +i` on rotated segments and shipping to an external log store, this creates an audit trail that is as tamper-resistant as possible without external hardware.

### 0.10 Key Isolation: Remote Signer as First-Class Architecture

**Decision:** The remote signer (`iona-remote-signer`) is a first-class, shipped binary with mTLS — not an optional plugin or a future roadmap item.

**Why security drove this choice:**

The validator key is the single most valuable asset in the system. Every millisecond it exists in the node process, it is exposed to any vulnerability in the node (a parsing bug in a P2P message decoder, a use-after-free in a third-party dependency, a malicious dependency update). The only architectural solution is to keep the key in a separate process with minimal attack surface.

The remote signer binary has zero P2P code, zero RPC code, zero consensus code — its only job is to hold a key and sign specific messages over an mTLS channel. Its attack surface is orders of magnitude smaller than the full node. Even a full compromise of the node process cannot extract the key from a remote signer.

---

## 1. Guarantees

These are the security promises IONA makes. Each is measurable, testable, and enforced.

### 1.1 Secure Defaults

> The node starts securely without any special configuration. The unsafe path is harder to take than the safe one.

| Default | Value | Override requirement |
|--------|-------|----------------------|
| RPC bind address | `127.0.0.1` (loopback only) | `--rpc-addr 0.0.0.0:9001` explicit flag |
| Rate limiting | **ON** — both RPC and P2P | Must be explicitly disabled in config |
| Max RPC request body | 4 096 bytes (configurable cap) | Must raise limit explicitly |
| RPC request timeout | Strict (short deadline) | Must be raised explicitly |
| Faucet / dev endpoints | **OFF** in production profile | Separate `--dev` flag required |
| Keystore mode | `plain` (dev) → `encrypted` (prod) | Operator selects mode; node warns if `plain` on public listen |
| Key file permissions | Checked at startup: must be `600` | Node **refuses to start** on world-readable keys |
| Gossipsub topics | Whitelist only (`iona/tx`, `iona/blocks`, `iona/evidence`) | Unknown topics rejected |
| Audit logging | **ON** always | Cannot be disabled |

**Proof:** `tests/integration.rs` contains a suite named `default_config_is_safe` that asserts each of the above conditions holds when starting from `NodeConfig::default()`.

### 1.2 Key Safety

> Validator keys never touch disk unencrypted. The key material is zeroized from memory after use.

- **Encrypted keystore** — AES-256-GCM with PBKDF2-HMAC-SHA256 (100 000 iterations, random 32-byte salt).
- **Password from environment** — `IONA_KEYSTORE_PASSWORD` env var; never stored in a config file on disk.
- **Startup permission check** — node refuses to start if `keys.json` or `keys.enc` are world-readable (`stat` check, fatal error).
- **Memory zeroization** — `zeroize` crate ensures key material is zeroed before drop.
- **Remote signer** — signing can be offloaded via `iona-remote-signer` so the key never enters the node process at all (`signing.mode = "remote"` in config).
- **Anti double-sign** — `DoubleSignGuard` persists signed (height, round, vote_type) tuples to `ds_guard.json`; a duplicate sign attempt is a fatal error that halts the process rather than signing twice.

**Proof:** `docs/remote_signer.md`, `src/crypto/`, keystore unit tests in `src/crypto/`, startup permission checks in `src/bin/iona-node.rs`.

### 1.3 DoS Resistance Baseline

> The node has hard, configurable ceilings on every inbound resource dimension. Exceeding a ceiling produces a metric and a log event, never silent resource exhaustion.

| Dimension | Default Limit | Metric emitted |
|-----------|--------------|----------------|
| RPC request body | 4 096 bytes | `iona_rpc_rejected_size_total` |
| RPC submit rate (per IP) | 100 req/s | `iona_ratelimit_rejected_total` |
| RPC read rate (per IP) | 500 req/s | `iona_ratelimit_rejected_total` |
| P2P block sync rate | 15 req/s, 2 MB/s | `iona_p2p_ratelimit_dropped_total` |
| P2P state sync rate | 10 req/s, 8 MB/s | `iona_p2p_ratelimit_dropped_total` |
| Gossipsub inbound (per peer) | 60 msg/s, 4 MB/s | gossipsub internal score |
| Total inbound P2P bandwidth | 10 MB/s | `iona_net_bandwidth_in_bytes` |
| Max P2P connections total | 200 | `iona_peers_connected` |
| Max P2P connections per peer | 8 | `iona_peers_connected` |

When a rate limit fires, the node logs at `WARN` level with the peer/IP and the violated dimension. Repeated violations escalate to peer quarantine.

**Proof:** `src/rpc_limits.rs`, `src/net/` (P2P rate limiting), Prometheus metrics in `src/metrics.rs`.

### 1.4 Consensus Safety Invariants

> The consensus engine enforces safety at the protocol level, not just the application level.

| Invariant | Description | Enforcement |
|-----------|-------------|-------------|
| **S1 — No Split Finality** | At most one block finalized per height | BFT quorum (2/3 + 1), checked by `safety::check_no_split_finality()` |
| **S2 — Finality Monotonic** | Finalized height never decreases | Engine state machine, `check_finality_monotonic()` |
| **S3 — Deterministic PV** | All correct nodes agree on `ProtocolVersion(height)` | Pure activation function, `check_deterministic_pv()` |
| **S4 — State Compatibility** | Exactly one PV applies per height | Activation schedule, `check_state_compat()` |
| **Double-sign prevention** | Cannot sign two conflicting votes at same (height, round) | `DoubleSignGuard` — fatal process halt on attempt |
| **Replay protection** | `chain_id` + `nonce` prevent replaying signed transactions | `validate_tx()` in `src/rpc_limits.rs` |
| **Evidence propagation** | Double-vote evidence is gossipped and results in automatic slashing | `Evidence::DoubleVote`, `StakeLedger::apply_evidence()` |
| **Invalid block rejection** | Blocks with wrong `prev_hash`, bad signatures, or unknown PV are dropped | Block validation in `src/consensus/` |

**Proof:** `formal/upgrade.tla` (TLA+ model), `tests/upgrade_sim.rs`, `src/slashing.rs`, `src/consensus/`.

### 1.5 Supply Chain Hardening

> The build is deterministic, audited, and locked. Every release artifact has a verified checksum.

- **Locked dependencies** — `Cargo.lock` is committed; all builds use `--locked`.
- **Pinned toolchain** — `rust-toolchain.toml` pins Rust `1.85.0`; no ambient toolchain drift.
- **`cargo-audit`** — runs in CI and blocks merge on any known advisory.
- **`cargo-deny`** — enforces license allowlist and bans unknown registries/git sources.
- **Reproducible builds** — same toolchain + `--locked` = same binary SHA-256. Verified by `scripts/repro_check.sh`.
- **Release integrity** — `SHA256SUMS.txt` ships with every release; SLSA provenance via GitHub Actions (`.github/workflows/slsa_release.yml`).

**Proof:** `deny.toml`, `rust-toolchain.toml`, `Cargo.lock`, `scripts/repro_check.sh`, `.github/workflows/`.

---

## 2. Non-Goals (Important for Realism)

Honesty about what IONA does *not* promise is part of being security-first.

- **No anonymity guarantees.** Network-level observers can correlate IP addresses to validators. IONA does not include onion routing or mixnet support. Use a trusted VPN or Tor if IP privacy matters.
- **No resistance to state-level adversaries.** A well-resourced nation-state can perform BGP hijacking, route manipulation, or legal compulsion. IONA provides no specific defense against these.
- **No BLS aggregate signatures (yet).** Certificates are O(N) in validator count, not O(1). This is a known limitation and is on the roadmap.
- **No formal verification of Rust code.** TLA+ models verify the protocol design; the Rust implementation is tested with property-based tests and fuzzing, not formally proven.
- **No perfect MEV protection.** Commit-reveal and threshold encryption reduce MEV but do not eliminate it. A colluding validator supermajority (≥ 2/3) can bypass these.
- **No protection against ≥ 1/3 Byzantine validators.** If at least one-third of stake is controlled by adversaries, liveness can be halted. If 2/3 or more collude, safety can be violated. This is a fundamental BFT limitation, not an IONA-specific one.
- **No formal security audit (yet).** The codebase has been designed for security and is fuzz-tested and property-tested, but has not undergone an independent third-party audit. **Do not use with real funds until an audit is complete.**

---

## 3. Secure Defaults

### 3.1 What "Secure Default" Means

A secure default means: **running the binary with no flags gives you a safe configuration**. The dangerous options require extra work from the operator.

```toml
# Default config.toml — safe out of the box
[rpc]
bind = "127.0.0.1"          # loopback only — not reachable from outside
rate_limit = true            # ON by default
max_body_bytes = 4096        # strict limit
request_timeout_ms = 5000   # short deadline

[node]
keystore = "encrypted"       # plain → only for --dev mode
faucet = false               # OFF in production
```

### 3.2 RPC Bind Address

The RPC server binds to `127.0.0.1:9001` by default (loopback-only).

**Binding to any non-loopback address is blocked at startup** unless the operator explicitly passes `--unsafe-rpc-public`. If they do, a multi-line `WARN` banner is logged to make the risk visible in any log aggregator.

```
══════════════════════════════════════════════════════════
WARNING: RPC is exposed publicly on 0.0.0.0:9001.
Ensure firewall rules restrict access appropriately.
══════════════════════════════════════════════════════════
```

To expose RPC safely in production, keep `rpc.listen = "127.0.0.1:9001"` and place a TLS-terminating reverse proxy (nginx, Caddy) in front. See Section 22 (Deployment Profiles) for full guidance.

### 3.3 Rate Limiting ON by Default

`RpcLimiter` is instantiated unconditionally in `src/rpc/`. When a rate limit fires:
1. The request is rejected with `HTTP 429 Too Many Requests`.
2. A `WARN` log line is emitted including the peer IP and the limit name.
3. The Prometheus counter `iona_ratelimit_rejected_total{limit="submit"}` is incremented.

Repeated violations (> 3 × `burst_size` within a window) trigger automatic IP quarantine and log at `ERROR`.

### 3.4 Keystore Mode Warning

If `keystore = "plain"` and the RPC or P2P listener is bound to a non-loopback address, the node emits:

```
WARN  iona::startup — keystore is 'plain' and node is listening on a public interface.
      This is NOT safe for production. Use keystore = 'encrypted' and set
      IONA_KEYSTORE_PASSWORD. Refusing to start. Set [node] allow_plain_keystore_on_public = true
      to override (not recommended).
```

### 3.5 Tests That Prove Defaults Are Safe

```
tests/rpc_security_gates.rs::g5_loopback_bind_is_not_public
tests/rpc_security_gates.rs::g5_wildcard_bind_is_public
tests/rpc_security_gates.rs::g6_key_file_0600_is_accepted        (Unix)
tests/rpc_security_gates.rs::g6_key_file_0644_is_rejected        (Unix)
tests/rpc_security_gates.rs::g7_data_dir_0700_is_accepted        (Unix)
tests/rpc_security_gates.rs::g7_data_dir_0755_is_rejected        (Unix)
tests/rpc_security_gates.rs::g1_body_over_limit_is_rejected
tests/rpc_security_gates.rs::g2_read_flood_rate_limits_hot_ip
tests/rpc_security_gates.rs::g3_deeply_nested_json_exceeds_limit
tests/rpc_security_gates.rs::g4_header_size_calculation_is_correct
```

These tests run in every CI pass and block merge on failure. See Section 23 for the full evidence table.

---

## 4. Key Management

### 4.1 The Threat

Validator keys are the most sensitive asset in a blockchain node. A stolen key means:
- Immediate ability to equivocate (double-sign) and trigger slashing of the operator's stake.
- Potential to selectively censor transactions or collude for MEV extraction.
- Reputational and economic loss that cannot be reversed.

### 4.2 Keystore Encryption

**On-disk format (`keys.enc`):**

```json
{
  "v":    1,
  "salt": "<base64 — 16 random bytes>",
  "nonce":"<base64 — 12 random bytes>",
  "ct":   "<base64 — AES-256-GCM ciphertext+tag>"
}
```

**Actual implementation (`src/crypto/keystore.rs`):**

```rust
const PBKDF2_ITERS: u32 = 100_000;

fn derive_key(pass: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(pass.as_bytes(), salt, PBKDF2_ITERS, &mut key);
    key
}

pub fn encrypt_seed32_to_file(path: &str, seed32: [u8; 32], pass: &str) -> io::Result<()> {
    let mut salt = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce_bytes);

    let mut key = derive_key(pass, &salt);
    let cipher = Aes256Gcm::new_from_slice(&key)?;
    let ct = cipher.encrypt(Nonce::from_slice(&nonce_bytes), seed32.as_slice())?;
    key.zeroize();   // ← key material zeroed immediately after use

    // After write: chmod 600 is applied automatically
    #[cfg(unix)]
    { let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600)); }
    Ok(())
}
```

100 000 PBKDF2 iterations ≈ 180 ms on modern hardware — fast enough for node startup, expensive enough to resist GPU brute-force. The random 16-byte salt prevents rainbow table attacks.

**Encryption:** AES-256-GCM provides both confidentiality and authenticated integrity. A tampered keystore cannot be decrypted without triggering an authentication failure.

**Memory zeroization:** `key.zeroize()` is called immediately after the derived key is used. The `zeroize` crate overwrites memory before deallocation, limiting cold-boot and memory-dump attack windows.

### 4.3 File Permission Enforcement

On startup, the node calls `check_key_permissions()` which inspects the Unix permission bits of the keystore file:

```rust
// src/crypto/keystore.rs
fn check_key_permissions(path: &Path) -> Result<()> {
    let meta = std::fs::metadata(path)?;
    let mode = meta.permissions().mode();
    if mode & 0o077 != 0 {
        bail!(
            "FATAL: keystore file {:?} is readable by group or world (mode {:o}). \
             Fix with: chmod 600 {:?}",
            path, mode, path
        );
    }
    Ok(())
}
```

The node **refuses to start** if this check fails. There is no override flag — this is a hard requirement.

### 4.4 Remote Signer

For highest-security deployments, use `iona-remote-signer` (`src/bin/iona-remote-signer.rs`):

- The signing key lives in a separate, air-gapped or HSM-backed process.
- The node process communicates with it over TLS (mutual auth) for each signing request.
- Even a full compromise of the node process does not expose the key.
- The remote signer can apply its own rate limits and double-sign prevention independently.

Configuration:

```toml
[signing]
mode = "remote"
remote_url  = "https://signer.internal:8443"
tls_cert    = "/etc/iona/client.pem"
tls_key     = "/etc/iona/client.key"
tls_ca      = "/etc/iona/ca.pem"
```

See `docs/remote_signer.md` for full setup instructions.

### 4.5 Anti Double-Sign

`DoubleSignGuard` (`src/consensus/`) maintains a persistent log (`ds_guard.json`) of every `(height, round, vote_type, block_id)` tuple that has been signed. Before signing:

1. Check: is this `(height, round, vote_type)` already recorded with a *different* `block_id`? → **Fatal abort.**
2. Check: is this exact tuple already recorded? → Return the cached signature (idempotent replay).
3. Otherwise: record and sign.

On restart, the guard reloads its state from `ds_guard.json` before accepting any consensus messages.

### 4.6 Operator Key Handling Reference

See `docs/client_signing_rust.md` for:
- Generating a fresh keypair offline.
- Importing it into an encrypted keystore.
- Rotating keys while maintaining liveness.
- Migrating from local keystore to remote signer.

---

## 5. RPC Hardening

### 5.1 Why RPC Is the Most-Attacked Surface

The RPC port is the primary interface between operators/dApps and the node. It accepts arbitrary JSON over HTTP from potentially untrusted callers. A poorly hardened RPC is the easiest path to:
- Resource exhaustion (large payloads, request floods).
- Information leakage (detailed error messages, internal state exposure).
- Logic abuse (crafted inputs that trigger edge cases).

### 5.2 Input Validation

Every RPC endpoint validates its input strictly before touching any internal state:

| Check | Implementation | Failure response |
|-------|---------------|-----------------|
| Max body size | Axum `DefaultBodyLimit::max(MAX_BODY_BYTES)` | `413 Payload Too Large` |
| JSON parse | Axum extractor — rejects malformed JSON | `400 Bad Request` |
| Transaction payload length | `validate_tx()` in `src/rpc_limits.rs` | `400 Bad Request` with code, no internal details |
| Transaction pubkey length | `validate_tx()` | `400 Bad Request` |
| Gas limit > 0 | `validate_tx()` | `400 Bad Request` |
| `chain_id` match | `validate_tx()` | `400 Bad Request` |
| Nonce anti-replay | `validate_tx()` | `400 Bad Request` |
| UTF-8 payload | `validate_tx()` | `400 Bad Request` |

"Fail fast" means: validation runs before signature verification, state lookup, or mempool insertion. Invalid requests are rejected at the entry point with minimal cost.

### 5.3 Rate Limiting

`RpcLimiter` (`src/rpc_limits.rs`) uses per-IP token buckets:

- **Submit path** (`/tx/submit`): 100 req/s burst per IP.
- **Read paths** (`/block/*`, `/state/*`, etc.): 500 req/s per IP.
- Stale entries are evicted every 60 seconds to bound memory use.

When a limit fires:
- Response: `HTTP 429 Too Many Requests`.
- Log: `WARN iona::rpc — rate limit hit ip=X.X.X.X limit=submit`.
- Metric: `iona_ratelimit_rejected_total{limit="submit|read"}`.

### 5.4 Error Responses Without Internal Leaks

All error responses follow a strict schema:

```json
{ "error": { "code": "INVALID_TX", "message": "payload too long: 5120 > 4096" } }
```

Rules enforced in the RPC layer:
- No stack traces in responses.
- No internal file paths, database errors, or Rust `Debug` output in responses.
- No field names or type information from internal structs.
- Panic handler converts any unexpected panic to a generic `500 Internal Server Error` without details.

### 5.5 Sensitive Endpoint Protection

Admin and metrics endpoints are separated from the public RPC:

| Endpoint group | Default access | Protection |
|---------------|---------------|------------|
| `/tx/submit`, `/block/*`, `/state/*` | Public (rate-limited) | Rate limit + input validation |
| `/admin/*` | Localhost only | Bind check + optional bearer token |
| `/metrics` | Localhost only | Bind check |
| `/faucet` | **Disabled** | Must be explicitly enabled with `--dev` flag |

### 5.6 Negative Test Suite

```
tests/rpc_negative.rs::rejects_oversized_body
tests/rpc_negative.rs::rejects_malformed_json
tests/rpc_negative.rs::rejects_invalid_chain_id
tests/rpc_negative.rs::rejects_zero_gas_limit
tests/rpc_negative.rs::rate_limits_submit_flood
tests/rpc_negative.rs::rate_limits_read_flood
tests/rpc_negative.rs::error_responses_contain_no_internal_paths
tests/rpc_negative.rs::error_responses_contain_no_stack_traces
```

---

## 6. P2P Hardening

### 6.1 Transport Security

All P2P connections use libp2p's **Noise protocol** (XX handshake pattern):
- Authenticated with Ed25519 peer identity keys.
- Encrypted with ChaChaPoly or AES-256-GCM (negotiated per connection).
- Forward-secret: ephemeral key per session.

No plaintext P2P traffic is ever accepted.

### 6.2 Per-Peer Resource Quotas

```
Inbound message pipeline:

  [TCP accept]
       │
  [Connection limit]       max 200 total, 8 per peer-ID
       │
  [Per-protocol rate]      governor token bucket (see limits above)
       │
  [Bandwidth cap]          10 MB/s in total
       │
  [Gossipsub per-topic]    deny unknown topics; per-topic msg/byte caps
       │
  [Peer score check]       strike → quarantine → ban
       │
  [Cheap validation]       size, format, chain_id — before signature check
       │
  [Expensive validation]   signature, merkle proof, block execution
```

The "cheap before expensive" ordering ensures that a flood of invalid messages costs an attacker much more than it costs the defender.

### 6.3 Gossipsub Security

| Parameter | Value | Effect |
|-----------|-------|--------|
| Allowed topics | `iona/tx`, `iona/blocks`, `iona/evidence` | Unknown topics rejected at subscribe and publish |
| `deny_unknown_topics` | `true` | Peer is scored negatively for unknown topic messages |
| Max publish msg/s (local) | 30 | Prevents the node itself from spamming |
| Max publish bytes/s (local) | 2 MB/s | Same |
| Max inbound msg/s (per peer) | 60 | Flood protection |
| Max inbound bytes/s (per peer) | 4 MB/s | Bandwidth protection |

### 6.4 Anti-Sybil / Anti-Eclipse Protection

| Mechanism | Configuration | Purpose |
|-----------|--------------|---------|
| IP-prefix diversity buckets (`/16`) | Max 4 inbound per bucket | Prevent single-subnet takeover |
| Outbound diversity | Max 4 per `/16` bucket | Diversify egress connections |
| Eclipse detection | Alert if `peer_buckets < 3` | Catch early-stage isolation |
| Kademlia DHT | Enabled | Discover topologically diverse peers |
| Quarantine persistence | `persist_quarantine = true` | Survives restarts; bad peers cannot reconnect |
| Reseed cooldown | 60 s | Prevents reconnection storms after isolation |

### 6.5 Peer Scoring & Quarantine

Peers accumulate negative score for:
- Sending invalid messages (bad signature, unknown topic, wrong chain).
- Exceeding rate limits.
- Disconnecting during request-response (incomplete response).

Score thresholds:
1. **Warning:** score < −10 → logged at `WARN`.
2. **Quarantine:** score < −50 → added to quarantine list; no new connections accepted.
3. **Ban:** score < −200 → peer-ID and IP added to permanent ban list (persisted to disk).

Metrics: `iona_peers_quarantined`, `iona_peers_banned`, `iona_p2p_score_histogram`.

### 6.6 Stress / Chaos Tests

```
tests/simnet.rs::p2p_flood_drops_excess_messages
tests/simnet.rs::sybil_peer_quarantined_after_violations
tests/simnet_partition_heal_safety.rs::partition_heals_safety_holds
tests/simnet_late_joiner.rs::late_joiner_syncs_correctly
```

---

## 7. Consensus Safety Invariants

### 7.1 BFT Safety Under Byzantine Faults

IONA uses a Tendermint-style BFT protocol. Safety holds as long as fewer than 1/3 of validators (by stake weight) are Byzantine. The quorum requirement (2/3 + 1 precommit votes for the same `block_id`) makes it impossible for two conflicting blocks to both reach finality.

Formal proof: `formal/upgrade.tla` — TLA+ model that exhaustively checks S1–S4 under all possible message orderings and validator failure patterns up to the BFT bound.

### 7.2 Double-Sign Prevention

The `DoubleSignGuard` is the last line of defense against accidental equivocation (e.g., running two validator processes with the same key).

**Actual implementation (`src/consensus/double_sign.rs`):**

```rust
pub fn check_vote(
    &self, vt: VoteType, height: Height, round: Round,
    block_id: &Option<Hash32>
) -> Result<(), String> {
    let key  = vote_guard_key(vt, height, round);
    let want = block_id.as_ref().map(h32_hex).unwrap_or_else(|| "nil".to_string());
    let st = self.inner.lock();
    if let Some(existing) = st.votes.get(&key) {
        if existing != &want {
            return Err("double-vote refused".into()); // ← hard refusal, not a warning
        }
    }
    Ok(())
}

pub fn record_vote(&self, vt: VoteType, height: Height, round: Round, block_id: &Option<Hash32>) {
    let key  = vote_guard_key(vt, height, round);
    let want = block_id.as_ref().map(h32_hex).unwrap_or_else(|| "nil".to_string());
    let mut st = self.inner.lock();
    st.votes.insert(key, want);
    save_state(&self.path, &st); // ← persisted to disk before returning
}
```

Guard state is stored per validator public key (`doublesign_<pk_hex>.json`). The file is reloaded at boot — so even a crash-restart cannot result in a double-sign.

The guard returns `Err` on conflict; the consensus engine treats this as a fatal event: it logs `CRITICAL`, emits an audit event, and **halts the process**. This is a deliberate choice: a halted node cannot sign, a running confused node can.

### 7.3 Replay Attack Protection

Every signed transaction carries:
- `chain_id` — must match the node's configured chain ID (validated by `validate_tx()`).
- `nonce` — strictly increasing per sender; replayed nonces are rejected by `validate_tx()`.

Signed proposals and votes carry `chain_id` in their wire format. A signature valid on testnet is invalid on mainnet.

### 7.4 Fork Abuse Resistance

- Unknown `protocol_version` values in block headers cause immediate rejection.
- The activation schedule for protocol upgrades is part of the genesis/config, which is agreed on at bootstrap. A peer cannot unilaterally announce a fork.
- Shadow validation allows nodes to pre-validate upgrade logic before activation, reducing the risk of a consensus split during a hard fork.

---

## 8. Fuzzing & Chaos as First-Class

### 8.1 Why Fuzzing Is Core, Not Optional

The most common source of consensus-node vulnerabilities is not logic bugs — it is **parsing bugs**. A malformed P2P message that causes a panic takes down a node as effectively as a DDoS. Fuzzing is the only systematic way to find these before an attacker does.

For IONA, fuzzing is part of the CI identity, not an afterthought.

### 8.2 Fuzz Targets

All fuzz targets live in `fuzz/fuzz_targets/`:

| Target | What it fuzzes | Coverage |
|--------|---------------|----------|
| `rpc_json.rs` | Arbitrary JSON → RPC input parsing | All RPC request types |
| `tx_json.rs` | Arbitrary bytes → `Tx` deserialization | Transaction parsing + validation |
| `p2p_frame_decode.rs` | Arbitrary bytes → P2P message framing | All P2P message types |
| `consensus_msg.rs` | Arbitrary bytes → `ConsensusMsg` decode | Vote, proposal, evidence |
| `block_header.rs` | Arbitrary bytes → block header decode | Header fields + hash |
| `vm_bytecode.rs` | Arbitrary EVM bytecode → interpreter | EVM execution engine |

### 8.3 Running Fuzz Targets

```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Quick run (developer, 60 seconds per target)
cargo fuzz run rpc_json       -- -max_total_time=60
cargo fuzz run tx_json        -- -max_total_time=60
cargo fuzz run p2p_frame_decode -- -max_total_time=60

# CI run (short, blocks on crash)
cargo fuzz run rpc_json       -- -max_total_time=30 -error_exitcode=1

# Extended run (weekly, corpus building)
cargo fuzz run rpc_json       -- -max_total_time=3600
```

### 8.4 Crash Triage Process

When a fuzz target finds a crash:

1. `cargo fuzz` saves the minimized input to `fuzz/artifacts/<target>/crash-<hash>`.
2. Reproduce: `cargo fuzz run <target> fuzz/artifacts/<target>/crash-<hash>`.
3. Open an internal issue tagged `security/fuzzing` with the input, stack trace, and root cause.
4. Fix and add the input to `fuzz/corpus/<target>/` as a regression test.
5. The CI fuzz job replays all corpus inputs on every run — a fixed bug cannot regress.

### 8.5 CI Fuzz Integration

The CI pipeline runs each fuzz target for 30 seconds on every pull request. The job fails if any target crashes. Extended (1-hour) runs are scheduled weekly, with results reported to the security channel.

```yaml
# .github/workflows/fuzz.yml (excerpt)
fuzz:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - run: cargo install cargo-fuzz
    - run: |
        for target in rpc_json tx_json p2p_frame_decode consensus_msg block_header vm_bytecode; do
          cargo fuzz run $target -- -max_total_time=30 -error_exitcode=1
        done
```

### 8.6 Chaos Testing

Beyond fuzzing, IONA has a chaos test suite (`src/bin/iona-chaos.rs`, `tests/simnet*.rs`) that exercises:

- Network partitions and heals (safety must hold during partition, liveness resumes after).
- Late-joining nodes (must sync correctly without being fed invalid state).
- Byzantine proposers (sending conflicting proposals at the same height).
- Overloaded mempools (10 000+ transactions submitted simultaneously).
- Rapid peer churn (nodes joining and leaving mid-consensus).

See `docs/CHAOS_TESTING.md` for methodology and results.

---

## 9. Supply Chain & Release Hardening

### 9.1 The Threat

A compromised dependency is as dangerous as a compromise of IONA itself. The Rust ecosystem has had supply chain incidents (malicious crates, typosquatting). IONA's defense is to make the build reproducible and audited.

### 9.2 Build Controls

| Control | Mechanism | CI enforcement |
|---------|----------|---------------|
| Locked dependencies | `Cargo.lock` committed, `--locked` everywhere | Build fails without `--locked` |
| Pinned toolchain | `rust-toolchain.toml` → Rust `1.85.0` | `rustup show` check in CI |
| Known vulnerability scan | `cargo audit` | Blocks merge on any advisory |
| License allowlist | `cargo deny check licenses` | Blocks merge on unlicensed dep |
| Unknown registry ban | `cargo deny check sources` | Blocks merge on unknown source |
| Reproducible build check | `scripts/repro_check.sh` | Run on release builds |

### 9.3 Reproducing a Build

```bash
# Ensure you have the correct toolchain
rustup toolchain install 1.85.0
rustup override set 1.85.0

# Build with locked dependencies
cargo build --release --locked --bin iona-node

# Hash the output
sha256sum target/release/iona-node

# Compare with published SHA256SUMS.txt for the release tag
# They must match byte-for-byte on the same OS/arch combination.
```

### 9.4 Release Artifact Integrity

Every release ships:
- `iona-node-<version>-<os>-<arch>` — compiled binary.
- `SHA256SUMS.txt` — SHA-256 of every artifact.
- `sbom.json` — CycloneDX Software Bill of Materials (generated by `cargo-cyclonedx`).
- SLSA Level 2 provenance (GitHub Actions attestation, `.github/workflows/slsa_release.yml`).

Verify a release:

```bash
sha256sum --check SHA256SUMS.txt
```

### 9.5 cargo-deny Configuration (`deny.toml`)

```toml
[licenses]
allow = ["Apache-2.0", "MIT", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Unicode-DFS-2016", "Zlib"]
deny  = ["GPL-2.0", "GPL-3.0", "AGPL-3.0"]

[bans]
multiple-versions = "warn"

[sources]
unknown-registry = "deny"
unknown-git      = "deny"
```

Unknown registries and git sources are **denied**, not warned. A dependency that suddenly switches from crates.io to a random GitHub fork will block the build.

---

## 10. Security Proof Artifacts

To demonstrate "security-first" credibly, IONA maintains three standing artifacts:

### Artifact 1 — Threat Model

**Location:** `docs/threat_model.md` (summary) and `docs/SECURITY_MODEL.md` (full)

Contents:
- Assets (keys, state, availability, correctness).
- Adversary capabilities and mitigations.
- Attack surface map (P2P, RPC, internal).
- Explicit out-of-scope items (state-level adversaries, post-BFT-bound scenarios).

**Update cadence:** Reviewed on every major release.

### Artifact 2 — Security Test Report

**Location:** Generated by CI and published to the repository wiki / release notes.

Contents:
- Fuzz run results (corpus size, total executions, crashes found + fixed).
- Negative RPC test results.
- P2P stress / chaos test results (drop rates, quarantine counts, partition-heal time).
- Property test statistics (`proptest` runs in `tests/proptests.rs`).
- `cargo audit` output (zero known advisories required to pass).

**Update cadence:** Every CI run; archived with each release.

### Artifact 3 — Operational Security Runbook

**Location:** `docs/OPERATOR_RUNBOOK.md`

Contents:
- Hardened production setup checklist.
- Key management procedures (generate offline, import, rotate).
- Monitoring setup (Prometheus + recommended alert rules).
- Incident response playbook (key compromise, double-sign, network partition, state corruption).
- Backup and disaster recovery procedures.
- Upgrade procedure with rollback steps.

**Update cadence:** Updated with every release that changes operational behavior.

---

## 11. Presenting IONA as Security-First

### What to Say (and Not Say)

**Instead of:** _"IONA is the first security-first blockchain."_
(Someone will find a counterexample and the claim collapses.)

**Say instead:**

> _"IONA is security-first by design. Secure defaults require no configuration. Key isolation is enforced at startup. Fuzz-driven hardening covers all decode paths. Builds are reproducible and locked. We measure security continuously — CI enforces audits, fuzz targets, and config safety invariants on every pull request."_

This is a **verifiable** claim. Any reviewer can:
1. Clone the repo and run `cargo test` — see the `default_config_is_safe` tests pass.
2. Run `cargo fuzz run rpc_json -- -max_total_time=60` — see it not crash.
3. Run `cargo audit` — see zero advisories.
4. Check `docs/SECURITY_MODEL.md` — see the threat model with explicit non-goals.
5. Read `docs/OPERATOR_RUNBOOK.md` — see the incident response procedures.

A claim backed by reproducible evidence is much harder to dispute than a marketing statement.

### The Four-Line Summary

```
Security-first by design:
  • Secure defaults   — safe with no flags; dangerous options require explicit configuration.
  • Key isolation     — keys never unencrypted on disk; startup refuses world-readable files.
  • Fuzz-hardened     — 6 fuzz targets covering all decode paths; CI enforces no crashes.
  • Locked + audited  — reproducible builds, cargo-audit, cargo-deny blocking in every PR.
```

### When Asked "Can You Prove It?"

Point to:

| Claim | Evidence |
|-------|---------|
| Secure defaults | `tests/integration.rs::default_config_*` |
| Rate limiting ON | `src/rpc_limits.rs` + `tests/rpc_negative.rs::rate_limits_*` |
| Key permissions enforced | `src/crypto/keystore.rs::check_key_permissions` + startup test |
| Fuzz targets exist and run in CI | `fuzz/fuzz_targets/` + `.github/workflows/fuzz.yml` |
| Supply chain locked | `Cargo.lock` + `deny.toml` + CI `cargo audit` step |
| Threat model documented | `docs/SECURITY_MODEL.md` |
| Formal consensus proof | `formal/upgrade.tla` |
| Operator runbook exists | `docs/OPERATOR_RUNBOOK.md` |

---

---

## 12. Memory Safety & Rust Guarantees

### 12.1 Why Rust Matters for Security

Memory-safety bugs (buffer overflows, use-after-free, double-free, integer overflows) account for the majority of exploitable vulnerabilities in C/C++ blockchain nodes. IONA is written entirely in safe Rust, which eliminates this class of bugs at the language level.

| Rust guarantee | What it prevents |
|---------------|-----------------|
| Ownership + borrow checker | Use-after-free, double-free, dangling pointers |
| No null pointers | Null dereference crashes |
| Bounds checking (by default) | Buffer overflows, out-of-bounds reads |
| No implicit integer coercion | Integer overflow (in debug builds: panic; release: checked arithmetic where critical) |
| `Send` + `Sync` traits | Data races across threads |
| No `unsafe` blocks in core paths | All the above, compiler-enforced |

### 12.2 `unsafe` Policy

IONA maintains a **zero-unsafe-in-security-critical-paths** policy:

- `src/crypto/` — zero `unsafe` blocks.
- `src/consensus/` — zero `unsafe` blocks.
- `src/rpc/` — zero `unsafe` blocks.
- `src/net/` — zero `unsafe` blocks.

The only `unsafe` usage in the codebase is in third-party dependencies (`libp2p`, `aes-gcm`, `tokio`) which are audited crates with established safety records. `cargo-audit` and `cargo-deny` ensure we are notified if any of these acquire known vulnerabilities.

CI enforcement:

```yaml
- name: Check for unsafe in security paths
  run: |
    if grep -rn "unsafe " src/crypto src/consensus src/rpc src/net; then
      echo "FAIL: unsafe block in security-critical path" && exit 1
    fi
```

### 12.3 Panic Policy

In a production node, an unexpected panic that unwinds the stack can leave the process in an inconsistent state. IONA's policy:

- **No `unwrap()` or `expect()` in network-facing code.** All decode paths return `Result<T, E>`. A CI lint step (`scripts/check.sh`) greps for `unwrap()` in `src/rpc/` and `src/net/` and fails the build if found.
- **Panic handler** — the binary registers a panic hook that logs the panic message at `CRITICAL` level to the audit log before the process exits. Operators receive structured context, not just a process death.
- **`abort` on double-panic** — `Cargo.toml` sets `panic = "abort"` for the release profile so that a panic in a panic handler does not cause undefined behavior.

```toml
[profile.release]
panic = "abort"
```

### 12.4 Integer Arithmetic in Consensus

Consensus code (height, round, stake arithmetic) uses checked arithmetic where overflow would be exploitable:

```rust
// Example from src/consensus/engine.rs
let new_height = height.checked_add(1)
    .ok_or(ConsensusError::HeightOverflow)?;
```

Saturation and wrapping arithmetic are only used in metrics/counters where overflow is harmless.

### 12.5 Dependency Safety Score

```
cargo audit     → 0 known advisories (enforced by CI)
cargo deny      → 0 license violations, 0 unknown registries
unsafe_code     → 0 in security-critical src/ directories
unwrap_in_rpc   → 0 (CI lint)
unwrap_in_net   → 0 (CI lint)
```

---

## 13. Startup Security Boot Sequence

Every time the IONA node starts, it runs a deterministic sequence of security checks **before** opening any network port or loading any signing key. If any check fails, the node exits with a non-zero code and a clear error message. There is no "warn and continue" for security violations.

```
iona-node startup sequence
─────────────────────────────────────────────────────────────────
 Step  Check                                  Failure action
────── ───────────────────────────────────────────────────────────
  1    Rust toolchain version matches          FATAL exit(1)
       rust-toolchain.toml
  2    Config file parsed & validated          FATAL exit(1)
       (bootnodes, chain_id, stake config)
  3    Data directory exists + permissions     FATAL exit(1)
       (700 on directory)
  4    Keystore file permission check          FATAL exit(1)
       (mode & 0o077 == 0 required)
  5    Keystore password present               FATAL exit(1)
       (env var or config — NOT empty)
  6    Keystore decryption test                FATAL exit(1)
       (wrong password → auth error)
  7    DoubleSignGuard load + integrity        FATAL exit(1)
       (corrupt ds_guard.json)
  8    Schema version compatibility            FATAL exit(1)
       (node_meta.json vs binary)
  9    Genesis hash verification               FATAL exit(1)
       (if expected_genesis_hash set in config)
 10    WAL integrity scan                      FATAL exit(1)
       (truncated or corrupt WAL segments)
 11    P2P port available (bind test)          FATAL exit(1)
 12    RPC port available (bind test)          FATAL exit(1)
 13    Audit startup event emitted             (always)
 14    → Begin accepting connections           ✓
─────────────────────────────────────────────────────────────────
```

**The key guarantee:** no validator key is loaded into memory until steps 1–10 pass. If anything is wrong with the environment, the process dies before the key can be used or exposed.

**Startup audit event:**

```json
{
  "timestamp": 1740909876,
  "level": "INFO",
  "category": "STARTUP",
  "action": "node_started",
  "details": [
    ["version", "28.0.0"],
    ["protocol_version", "2"],
    ["schema_version", "7"],
    ["keystore_mode", "encrypted"],
    ["rpc_bind", "127.0.0.1:9001"],
    ["p2p_bind", "0.0.0.0:7001"]
  ]
}
```

---

## 14. Audit Trail & Structured Logging

### 14.1 What Gets Logged

Every security-sensitive action produces a structured JSON event in `audit.log`. The event format (`src/audit.rs`) is:

```json
{
  "timestamp": 1740909876,
  "level":     "CRITICAL",
  "category":  "CONSENSUS",
  "action":    "equivocation_detected",
  "details":   [["validator", "a1b2c3..."], ["height", "42"]],
  "node_id":   "iona-validator-1"
}
```

Categories and severity levels:

| Category | Events | Default level |
|----------|--------|--------------|
| `KEY` | key_generated, key_imported, key_export_refused | INFO / CRITICAL |
| `CONSENSUS` | block_committed, block_finalized, equivocation_detected | INFO / CRITICAL |
| `MIGRATION` | schema_migration, protocol_upgrade | WARNING / CRITICAL |
| `NETWORK` | peer_quarantine, peer_ban, rate_limit_exceeded | WARNING |
| `ADMIN` | config_change, snapshot_create, snapshot_restore | INFO |
| `STARTUP` | node_started | INFO |
| `SHUTDOWN` | node_stopped | INFO |

### 14.2 Log Integrity

`audit.log` is append-only — the `AuditLogger` opens the file with `OpenOptions::append(true)`. Operators should ship the log to an external append-only store (e.g., Loki, Splunk, CloudWatch Logs) immediately on write so that a compromised node cannot retroactively erase evidence.

Recommended: set the file immutable after rotation:

```bash
# Rotate and lock previous segment
mv data/node/audit.log data/node/audit-$(date +%Y%m%d).log
chattr +i data/node/audit-$(date +%Y%m%d).log
```

### 14.3 No Secrets in Logs

The logging layer enforces a strict "no secrets" policy:

- Key material is never passed to any log macro. The `AuditEvent` API only accepts `&str` details — there is no API to log raw bytes.
- Transaction payloads are never logged in full — only their hashes.
- Keystore passwords are never logged — not even a masked version.
- Peer IDs are logged (public data), but not their IP addresses in the default config (can be enabled for debugging with `--log-peer-ips` dev flag).

### 14.4 Querying the Audit Log

```bash
# All CRITICAL events
jq 'select(.level == "CRITICAL")' data/node/audit.log

# All equivocation events
jq 'select(.action == "equivocation_detected")' data/node/audit.log

# All peer bans in the last hour
jq --argjson since "$(date -d '1 hour ago' +%s)" \
   'select(.category == "NETWORK" and .action == "peer_banned" and .timestamp > $since)' \
   data/node/audit.log

# Startup/shutdown history
jq 'select(.category == "STARTUP" or .category == "SHUTDOWN")' data/node/audit.log
```

---

## 15. Prometheus Alert Rules

The following PromQL rules should be deployed alongside the node. They represent the **minimum recommended security alerting** for a production IONA validator.

```yaml
# iona-security-alerts.yaml
groups:
  - name: iona_security
    rules:

      # ── Consensus health ──────────────────────────────────────────────
      - alert: IonaFinalityStalled
        expr: increase(iona_finality_height[2m]) == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "IONA finality stalled for 2+ minutes"
          description: "Node {{ $labels.instance }} has not finalized a block in 2 minutes."

      - alert: IonaHighRound
        expr: iona_consensus_round > 3
        for: 30s
        labels:
          severity: warning
        annotations:
          summary: "IONA consensus round > 3 — possible Byzantine activity"

      - alert: IonaEquivocationDetected
        expr: increase(iona_slashing_evidence_total[5m]) > 0
        labels:
          severity: critical
        annotations:
          summary: "Double-sign evidence detected — validator may be slashed"

      # ── Network security ──────────────────────────────────────────────
      - alert: IonaPeerCountCritical
        expr: iona_peers_connected < 2
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "IONA has fewer than 2 peers — possible eclipse attack"

      - alert: IonaRateLimitBurst
        expr: rate(iona_ratelimit_rejected_total[1m]) > 50
        labels:
          severity: warning
        annotations:
          summary: "RPC rate limiter firing > 50/min — possible DoS"

      - alert: IonaPeersQuarantined
        expr: iona_peers_quarantined > 5
        labels:
          severity: warning
        annotations:
          summary: "{{ $value }} peers quarantined — possible Sybil or spam wave"

      - alert: IonaPeersBanned
        expr: increase(iona_peers_banned[10m]) > 3
        labels:
          severity: warning
        annotations:
          summary: "3+ new peer bans in 10 minutes — investigate P2P logs"

      # ── Resource safety ───────────────────────────────────────────────
      - alert: IonaMemoryHigh
        expr: process_resident_memory_bytes{job="iona-node"} > 0.85 * node_memory_MemTotal_bytes
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "IONA node using > 85% of available RAM"

      - alert: IonaDiskHigh
        expr: (node_filesystem_size_bytes{mountpoint="/data"} - node_filesystem_free_bytes{mountpoint="/data"})
              / node_filesystem_size_bytes{mountpoint="/data"} > 0.80
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Data partition > 80% full — node may halt on disk full"

      # ── Supply chain / process integrity ─────────────────────────────
      - alert: IonaUnexpectedRestart
        expr: increase(iona_process_start_time_seconds[10m]) > 0
        labels:
          severity: warning
        annotations:
          summary: "IONA node restarted unexpectedly — check logs"
```

### 15.1 Security-Specific Grafana Panels

Recommended panels for a security dashboard:

| Panel | Query | Threshold |
|-------|-------|-----------|
| Finality latency P95 | `histogram_quantile(0.95, iona_finality_latency_ms_bucket)` | > 2000 ms = warn |
| Rate limit hit rate | `rate(iona_ratelimit_rejected_total[5m])` | > 10/s = warn |
| Quarantine count | `iona_peers_quarantined` | > 3 = warn |
| Ban count (rolling 1h) | `increase(iona_peers_banned[1h])` | > 5 = warn |
| Evidence events | `increase(iona_slashing_evidence_total[1h])` | > 0 = critical |
| Consensus round | `iona_consensus_round` | > 2 = warn |

---

## 16. OS-Level Hardening (systemd)

Running the node under a hardened `systemd` unit reduces the blast radius of any compromise significantly. Below is the recommended unit file:

```ini
# /etc/systemd/system/iona-node.service
[Unit]
Description=IONA Blockchain Node
Documentation=https://github.com/your-org/iona
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=3

[Service]
Type=simple
User=iona
Group=iona
WorkingDirectory=/opt/iona
ExecStart=/opt/iona/bin/iona-node \
    --config /etc/iona/config.toml \
    --data-dir /var/lib/iona

# ── Security hardening ────────────────────────────────────────────────
# Drop all capabilities (node doesn't need any privileged Linux capability)
CapabilityBoundingSet=
AmbientCapabilities=

# Prevent privilege escalation
NoNewPrivileges=yes

# Read-only root filesystem (data dir remounted r/w below)
ProtectSystem=strict
ReadWritePaths=/var/lib/iona /var/log/iona

# Isolate home and temp
ProtectHome=yes
PrivateTmp=yes

# Prevent access to kernel settings
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes

# Restrict syscalls to a safe set (remove dangerous ones)
SystemCallFilter=@system-service
SystemCallFilter=~@debug @mount @cpu-emulation @obsolete @privileged @reboot @swap

# Prevent memory-executable mapping (blocks shellcode injection)
MemoryDenyWriteExecute=yes

# Restrict address families (only TCP/UDP needed)
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

# Limit number of open files and processes
LimitNOFILE=65536
LimitNPROC=512

# Restart policy
Restart=on-failure
RestartSec=5s

# Environment (keystore password via systemd credential — safer than env file)
LoadCredential=keystore-password:/etc/iona/credentials/keystore-password
Environment=IONA_KEYSTORE_PASSWORD_FILE=%d/keystore-password

[Install]
WantedBy=multi-user.target
```

### 16.1 Systemd Credentials (Recommended over env files)

Instead of an `.env` file readable by any process, use `systemd-creds`:

```bash
# Store the password in systemd's encrypted credential store
systemd-creds encrypt --name=keystore-password -
# (type password, Ctrl-D)
# Output goes to /etc/iona/credentials/keystore-password

# Load in unit with:
# LoadCredential=keystore-password:/etc/iona/credentials/keystore-password
```

Credentials stored this way are encrypted with the machine's TPM key and are only decrypted in the process's credential directory at runtime.

### 16.2 Additional OS Hardening

```bash
# Dedicated non-login user
useradd --system --no-create-home --shell /usr/sbin/nologin iona

# Restrict data directory
install -d -o iona -g iona -m 700 /var/lib/iona

# nftables firewall (example — adjust for your network)
nft add rule inet filter input tcp dport 7001 accept         # P2P
nft add rule inet filter input tcp dport 9001 ip saddr @trusted_rpc accept  # RPC — trusted only
nft add rule inet filter input drop                          # drop all else

# Automatic security updates (Ubuntu/Debian)
apt-get install unattended-upgrades
dpkg-reconfigure -plow unattended-upgrades
```

---

## 17. Security Changelog by Version

This table shows when each security control was introduced, making it possible to verify that a given deployment includes a specific protection.

| Version | Control Added | Category |
|---------|--------------|----------|
| v24.1 | `cargo-audit` + `cargo-deny` in CI | Supply chain |
| v24.3 | Per-protocol P2P rate limits (governor token bucket) | P2P DoS |
| v24.4 | Peer scoring + quarantine + ban | P2P Sybil |
| v24.5 | Encrypted keystore (AES-256-GCM + PBKDF2) | Key management |
| v24.9 | `DoubleSignGuard` — persistent double-sign prevention | Consensus |
| v24.9 | `Evidence::DoubleVote` detection + automatic slashing | Consensus |
| v24.10 | SLSA provenance + signed releases | Supply chain |
| v24.12 | Anti-eclipse diversity buckets (IP-prefix bucketing) | P2P eclipse |
| v24.12 | Gossipsub topic ACL + per-topic rate caps | P2P spam |
| v25.0 | Remote signer (`iona-remote-signer`) + mTLS | Key isolation |
| v25.0 | Key permission check at startup (refuse world-readable) | Key management |
| v26.0 | Fuzz targets for all 6 decode paths | Fuzzing |
| v26.0 | `zeroize` — key material zeroed after use | Memory safety |
| v27.0 | Reproducible builds + `scripts/repro_check.sh` | Supply chain |
| v27.0 | `Cargo.lock` committed + `--locked` everywhere | Supply chain |
| v27.1 | Schema migration crash-safety + atomic writes | Storage integrity |
| v27.1 | TLA+ formal model (`formal/upgrade.tla`) for S1–S4 | Formal verification |
| v27.2 | Structured audit trail (`src/audit.rs`) — all events | Audit |
| v27.2 | MEV protection: commit-reveal + threshold encryption | MEV |
| v28.0 | `panic = "abort"` + `overflow-checks = true` in release profile | Memory safety |
| v28.0 | CI lint: zero `unwrap()` in rpc/ and net/ paths | Memory safety |
| v28.0 | systemd hardened unit (`MemoryDenyWriteExecute`, etc.) | OS hardening |
| v28.0 | Prometheus security alert rules | Monitoring |
| v28.0 | RPC bind-address gate: refuse start if public without `--unsafe-rpc-public` | Secure defaults |
| v28.0 | Configurable CORS: `cors_allow_all=false` by default | Secure defaults |
| v28.0 | Uniform read rate-limiting: `check_read()` on all GET endpoints | DoS hardening |
| v28.0 | JSON depth limit middleware (`MAX_JSON_DEPTH=32`) | DoS hardening |
| v28.0 | Header-block size limit middleware (`MAX_HEADER_BYTES=8 KiB`) | DoS hardening |
| v28.0 | Key-file + data-dir permission gates at startup (`0600`/`0700`) | Key management |
| v28.0 | 18 new negative security tests (`tests/rpc_security_gates.rs`) | Test coverage |

---

## 18. Security Debt Tracker

Honesty about what is **not yet done** is part of being security-first. This section is maintained as a living backlog — items are moved to the changelog above when addressed.

| Item | Risk | Target version | Owner |
|------|------|---------------|-------|
| Independent third-party security audit | HIGH — required before mainnet | v29.0 | Core team |
| BLS aggregate signatures | MEDIUM — O(N) certificates today; bandwidth risk at large validator sets | v29.0 | Crypto team |
| Threshold DKG for MEV encryption | MEDIUM — current epoch key is deterministic (not multi-party) | v30.0 | Crypto team |
| Long-range attack / weak subjectivity checkpoints | MEDIUM — no explicit checkpoint mechanism | v29.0 | Consensus team |
| Formal verification of Rust code (beyond TLA+) | LOW-MEDIUM — protocol is verified; implementation is fuzz-tested only | Ongoing | All |
| Account abstraction / social recovery | LOW — private key loss = permanent loss | v31.0 | Protocol team |
| HSM PKCS#11 integration (hardware) | LOW — software encrypted keystore available; HSM is optional | v29.0 | Infra team |
| ASN-based peer bucketing | LOW — currently IP-prefix buckets; ASN requires external mapping | v29.0 | Net team |
| `cargo-cyclonedx` SBOM in CI | LOW — manual today | v28.1 | DevOps |
| Downtime penalty (gradual) | LOW — only double-sign slash today | v30.0 | Consensus team |

**Any HIGH item blocks mainnet deployment.**

---

## 19. Comparative Security Matrix

How IONA's security posture compares to a "typical" blockchain node built without explicit security focus:

| Feature | Typical node | IONA |
|---------|-------------|------|
| **RPC default bind** | `0.0.0.0` (public) | `127.0.0.1` (loopback) |
| **Rate limiting** | Optional / off by default | ON by default, cannot be silently disabled |
| **Keystore encryption** | Optional | Required in production; startup refuses plain key on public interface |
| **Key permission check** | None | Startup refuses world-readable keystore (chmod check) |
| **Key memory zeroization** | Rare | `zeroize` on every key drop |
| **Remote signer support** | Rare | First-class (`signing.mode = "remote"`, mTLS) |
| **Double-sign guard** | Sometimes | Persisted to disk, reloaded on restart, process halt on attempt |
| **Fuzz testing** | Rare | 6 fuzz targets, CI-enforced, corpus maintained |
| **Panic policy** | `unwrap()` common | Zero `unwrap()` in rpc/ and net/ (CI lint), `panic = "abort"` |
| **P2P rate limits** | Connection-level only | Per-protocol, per-peer, per-topic, bandwidth-capped |
| **Anti-eclipse** | None | IP-prefix diversity buckets + detection + cooldown |
| **Peer scoring** | None | Scoring + quarantine + persistent ban |
| **Supply chain lock** | Cargo.lock often not committed | Locked, `--locked` enforced, `cargo-audit` blocking in CI |
| **Reproducible builds** | Rare | `scripts/repro_check.sh`, pinned toolchain |
| **Audit trail** | Node logs only | Structured JSON audit log, append-only, categorized by severity |
| **Formal model** | None | TLA+ model for consensus safety (S1–S4) |
| **Security changelog** | None | Tracked per version (Section 17 above) |
| **Security debt tracker** | None | Maintained in this document (Section 18 above) |
| **systemd hardening** | Generic unit | `MemoryDenyWriteExecute`, `NoNewPrivileges`, `SystemCallFilter`, etc. |
| **PromQL alert rules** | Operator's responsibility | Provided and documented (Section 15 above) |
| **Non-goals documented** | Never | Section 2 of this document |
| **Independent audit** | Before mainnet (sometimes) | Required before mainnet (tracked in debt, Section 18) |

---

## 20. Security Review Gate for Contributors

Security-first is not a one-time achievement — it is a process that every contribution must pass through. This section defines what "maintaining security" means for contributors and reviewers.

### 20.1 Automated Gates (CI — Blocks Merge)

Every pull request must pass all of the following before merge is allowed:

| Check | Command | What it catches |
|-------|---------|----------------|
| No `unsafe` in security paths | `grep -rn "unsafe " src/crypto src/consensus src/rpc src/net` | New unsafe code in critical directories |
| No `unwrap()` in RPC/net | `grep -rn "\.unwrap()" src/rpc src/net` | Panic-on-malformed-input bugs |
| `cargo audit` | `cargo audit --deny warnings` | New known CVEs in any dependency |
| `cargo deny` | `cargo deny check` | License violations, unknown registries |
| All fuzz corpus replayed | `cargo fuzz run <target> fuzz/corpus/<target>/` | Regressions in previously-found crash inputs |
| Default config tests | `cargo test default_config` | Secure defaults broken by new config options |
| Negative RPC tests | `cargo test rpc_negative` | New RPC endpoints missing validation |
| Reproducible build check | `scripts/repro_check.sh` | Non-determinism introduced in build |

### 20.2 Manual Review Requirements

The following changes require explicit security review by a maintainer before merge, regardless of CI status:

**Cryptography changes (any of these = security review required):**
- Adding, replacing, or modifying any cryptographic primitive (hash, signature, encryption).
- Changing key derivation parameters (PBKDF2 iterations, salt length, key length).
- Modifying the keystore format or decryption logic.
- Adding a new signing path.

**Network-facing changes:**
- Adding a new P2P message type. *(Also requires: a fuzz target for the new message's decode path.)*
- Adding a new RPC endpoint. *(Also requires: negative tests for invalid input, oversized input, and rate limiting.)*
- Modifying connection handling, rate limit configuration, or peer scoring.

**Consensus changes:**
- Any change to vote counting, quorum calculation, or finality logic.
- Any change to the `DoubleSignGuard`.
- Any change to evidence handling or slashing.
- Protocol version activation logic.

**Key management changes:**
- Any change to startup permission checks.
- Any change to the remote signer protocol.

### 20.3 New P2P Message Checklist

When adding a new P2P message type, the contributor must:

```
[ ] Add decode/encode in src/consensus/messages.rs or src/net/
[ ] Add fuzz target in fuzz/fuzz_targets/<message_type>.rs
[ ] Add to CI fuzz job in .github/workflows/fuzz.yml
[ ] Add size limit in the rate limiter (src/net/)
[ ] Add per-peer rate limit entry (messages/sec + bytes/sec)
[ ] Add Prometheus metric for drop/reject count
[ ] Document in SECURITY_MODEL.md attack surface map
```

### 20.4 New RPC Endpoint Checklist

When adding a new RPC endpoint:

```
[ ] Add input validation (schema, type, length limits) before any state access
[ ] Add to RpcLimiter (submit vs. read classification)
[ ] Add negative tests in tests/rpc_negative.rs:
    [ ] malformed JSON
    [ ] oversized payload
    [ ] invalid field types
    [ ] flood (rate limit hit test)
[ ] Verify error responses contain no internal details (no paths, no stack traces)
[ ] If endpoint is sensitive: add auth/allowlist protection
[ ] Update RPC_AUTH.md if auth requirements change
```

### 20.5 Security Regression Policy

If a security test that was previously passing starts failing:

1. **The PR that broke it is blocked from merge** — no exceptions.
2. The author must diagnose whether this is a regression or a legitimate change to behavior.
3. If the test needs to be updated because behavior changed intentionally (e.g., raising a rate limit), the PR must include an explanation of why the new behavior is still safe.
4. If the test is wrong (false positive), it must be fixed in the same PR — not deleted.

**Tests are never deleted to unblock a merge.** A failing security test is always either fixed or replaced with a better test.

### 20.6 Dependency Addition Policy

Adding a new dependency requires:

```
[ ] Check cargo audit: no known advisories in the new crate
[ ] Check license: must be in the deny.toml allowlist
[ ] Check source: must be on crates.io (not git, not local path) for production deps
[ ] If the dep is used in crypto/consensus/rpc/net: security review required
[ ] Pin version in Cargo.toml (avoid "latest" or wildcard ranges)
[ ] Commit updated Cargo.lock
```

If a dependency adds `unsafe` code to security-critical paths (even transitively), the CI unsafe-grep check will catch it. If it does not, explain in the PR why the transitively-unsafe code is acceptable.

---

## 21. Security Glossary

Precise language matters for security. These definitions are the ones IONA uses consistently throughout its codebase and documentation.

**Authenticated encryption:** An encryption scheme that provides both confidentiality (the plaintext cannot be read) and integrity (tampering with the ciphertext is detectable). IONA uses AES-256-GCM. Simple AES-CBC is not authenticated encryption.

**Defense in depth:** Layering multiple independent security controls so that no single failure is sufficient for a successful attack. Example: an attacker who bypasses the RPC rate limiter still hits input validation; bypassing input validation still requires a valid signature.

**Deterministic signature:** A signature algorithm where the same private key and message always produce the same signature, with no random input. Ed25519 is deterministic. ECDSA is not. Determinism eliminates the risk of nonce reuse.

**Double-sign / equivocation:** Signing two conflicting messages for the same consensus position (same height and round) with the same validator key. In BFT consensus, double-signing can be used to create a finality split. IONA treats double-sign attempts as fatal.

**Eclipse attack:** An attack where an adversary controls all of a node's peers, isolating it from the honest network. The node then receives only attacker-controlled information. Mitigated by peer diversity buckets and minimum bucket requirements.

**Fail-fast:** The design principle of detecting and reporting an error as early as possible rather than continuing with invalid state. In IONA: invalid config = startup halt; double-sign attempt = process halt; tampered keystore = decryption error at startup.

**Finality:** A block is final when it cannot be reverted without violating the consensus protocol's assumptions. IONA uses *deterministic finality* — a block committed by BFT is final immediately, not probabilistically.

**Forward secrecy:** A key exchange property where compromise of long-term keys does not compromise past session keys. Noise XX provides forward secrecy — historical P2P traffic cannot be decrypted even if a node's identity key is later compromised.

**Memory zeroization:** Overwriting secret key material with zeros (or random bytes) before the memory is freed, so that the key cannot be recovered from freed memory pages or a memory dump. IONA uses the `zeroize` crate.

**Nonce (in cryptography):** A "number used once" — a value that must never be reused for the same key. In AES-GCM, nonce reuse completely breaks confidentiality. IONA uses `OsRng` (cryptographically secure random) to generate all nonces.

**Panic (Rust):** An unrecoverable error in Rust. With `panic = "abort"` (IONA's release profile), a panic terminates the process immediately without stack unwinding. With the default `panic = "unwind"`, panics can be caught.

**Peer scoring:** Assigning a numerical score to each peer based on their behavior. Peers that send invalid messages, exceed rate limits, or disconnect mid-request accumulate negative score. Below a threshold, the peer is quarantined or banned.

**Quarantine:** A temporary state in which a peer is allowed to maintain an existing connection but no new connections from that peer are accepted. Less severe than a ban; allows for score recovery through good behavior.

**Rate limiting (token bucket):** A rate-limiting algorithm where a bucket fills at a fixed rate (tokens/second) and each request consumes one token. When the bucket is empty, requests are rejected. The bucket size controls burst capacity.

**Remote signer:** An architecture where the validator signing key lives in a separate process (or machine) from the main node. The node sends signing requests over an authenticated channel and receives signatures back — the key never enters the node's memory space.

**Replay attack:** Using a previously valid signed message in a new context. Mitigated by `chain_id` (prevents cross-chain replay) and `nonce` (prevents within-chain replay of the same transaction).

**Safe Rust:** Rust code that does not use `unsafe` blocks. Safe Rust has compile-time guarantees of memory safety and data-race freedom. IONA's security-critical paths (`src/crypto`, `src/consensus`, `src/rpc`, `src/net`) contain zero `unsafe` blocks.

**Secure default:** A configuration value that is safe in the absence of operator action. Example: RPC binding to `127.0.0.1` by default means a newly started node is not externally accessible without explicit configuration. The operator must opt in to exposure, not opt in to protection.

**Sybil attack:** An attack where an adversary creates many fake identities (peers) to gain disproportionate influence. In IONA, mitigated by peer diversity bucketing (one subnet cannot dominate) and peer scoring (fake peers accumulate negative score quickly).

**Threshold encryption:** An encryption scheme where decryption requires cooperation from a threshold number of parties. IONA uses it for MEV protection — transaction content is encrypted during ordering and decrypted only after the block is finalized using a key derived from the finalized block hash.

**Zeroize:** To overwrite memory containing secret data with zeros before it is freed or reused. This prevents the data from appearing in a subsequent allocation, a core dump, or a cold-boot memory image. The Rust `zeroize` crate provides this via the `Zeroize` trait and `Zeroizing<T>` wrapper.

---

## Appendix A — Security Checklist for Operators

Before running IONA in production with real stake:

- [ ] Use `keystore = "encrypted"` in `config.toml`.
- [ ] Set `IONA_KEYSTORE_PASSWORD` as a strong, unique environment variable — never in a file.
- [ ] Verify keystore file permissions: `chmod 600 data/node/keys.enc && chmod 700 data/node/`.
- [ ] Restrict RPC port via firewall (allow only trusted IPs / VPN ranges).
- [ ] Review Prometheus alert rules in `docs/OPERATOR_RUNBOOK.md` and set them up.
- [ ] Enable structured audit logging and ship `audit.log` to a tamper-evident log store.
- [ ] Verify release binary SHA-256 against `SHA256SUMS.txt` before deploying.
- [ ] Consider `signing.mode = "remote"` for validator keys.
- [ ] Run `cargo audit` against the version you are deploying.
- [ ] Read and run through the incident response section of `docs/OPERATOR_RUNBOOK.md` before going live.
- [ ] Test your backup and snapshot restore procedure before needing it.
- [ ] **Wait for an independent security audit before deploying with real funds.**

---

## Appendix B — Security-Related File Index

| File | Purpose |
|------|---------|
| `docs/SECURITY_FIRST.md` | This document — the security-first manifesto |
| `docs/SECURITY_MODEL.md` | Full threat model and security controls reference |
| `docs/threat_model.md` | Concise threat model summary |
| `docs/OPERATOR_RUNBOOK.md` | Production operations and incident response |
| `docs/remote_signer.md` | Remote signer setup and operation |
| `docs/client_signing_rust.md` | Key generation, import, rotation guide |
| `docs/CHAOS_TESTING.md` | Chaos test methodology and results |
| `SECURITY.md` | Vulnerability disclosure policy |
| `src/rpc_limits.rs` | RPC rate limiting and input validation |
| `src/crypto/` | Keystore encryption, permission checks, zeroize |
| `src/consensus/` | Double-sign guard, BFT engine, evidence |
| `src/net/` | P2P rate limiting, peer scoring, quarantine |
| `src/slashing.rs` | Evidence application, stake slashing |
| `fuzz/fuzz_targets/` | All fuzz targets |
| `tests/rpc_negative.rs` | Negative RPC tests |
| `tests/simnet*.rs` | P2P stress and chaos tests |
| `tests/proptests.rs` | Property-based tests |
| `formal/upgrade.tla` | TLA+ formal model (consensus safety) |
| `deny.toml` | cargo-deny license + source policy |
| `rust-toolchain.toml` | Pinned Rust toolchain |
| `scripts/repro_check.sh` | Reproducible build verification |
| `.github/workflows/fuzz.yml` | CI fuzz job |
| `.github/workflows/slsa_release.yml` | SLSA provenance for releases |

---

## 22. Deployment Profiles

IONA supports three named security profiles. Each profile is a *bundle of flags, config values, and startup gates* — not a compile-time switch.

### Profile: `dev`

For local development and quick experimentation. **Never use on any network-accessible node.**

| Setting | Value | Notes |
|---------|-------|-------|
| `rpc.listen` | `127.0.0.1:9001` | Default; loopback only |
| `rpc.cors_allow_all` | `true` | Permits browser dev UIs |
| `node.keystore` | `plain` | No password needed |
| `rpc.enable_faucet` | `true` | Free tokens for testing |
| `--unsafe-skip-key-perms` | Pass if needed | Dev machines may have loose perms |
| CORS | Permissive | Any origin allowed |
| Rate limits | Active (default thresholds) | |
| `panic` | `abort` (release profile) | |

### Profile: `prod`

For public testnet or pre-mainnet validator operation.

| Setting | Value | Notes |
|---------|-------|-------|
| `rpc.listen` | `127.0.0.1:9001` | Loopback only (reverse-proxy in front) |
| `rpc.cors_allow_all` | `false` | No cross-origin access |
| `node.keystore` | `encrypted` | Password via `IONA_KEYSTORE_PASSWORD` env |
| `rpc.enable_faucet` | `false` | |
| Key file permissions | `0600` enforced | Node refuses to start otherwise |
| Data directory permissions | `0700` enforced | |
| CORS | Restrictive (`CorsLayer::new()`) | |
| Rate limits | Active, burst tuned per deployment | |
| `--unsafe-rpc-public` | Not set | RPC stays on loopback |

**To expose RPC externally in prod** (e.g. behind nginx/Caddy):
1. Set `rpc.listen = "127.0.0.1:9001"` (keep it loopback)
2. Configure the reverse proxy with TLS + auth
3. Never pass `--unsafe-rpc-public` unless the proxy is your sole access point

### Profile: `hard`

For mainnet validators demanding maximum isolation.

| Setting | Value | Notes |
|---------|-------|-------|
| `rpc.listen` | `127.0.0.1:9001` (admin only) | All external RPC via reverse-proxy with mTLS |
| `rpc.cors_allow_all` | `false` | |
| `node.keystore` | `encrypted` | |
| `signing.mode` | `remote` | Remote signer on separate host |
| Remote signer mTLS | Mandatory | Node refuses to start without valid certs |
| Key file permissions | `0600` on remote signer host | |
| Data directory permissions | `0700` | |
| OS | systemd hardened unit (Section 16) | `MemoryDenyWriteExecute`, `NoNewPrivileges`, etc. |
| Fuzz | Monthly corpus-run on all 7 targets | Via `scripts/security_check.sh` |
| `--unsafe-*` flags | None | Any `--unsafe-*` flag triggers startup warning logged at `ERROR` |

**Mandatory `hard` checklist** (block deployment if any item fails):

- [ ] `cargo audit --deny warnings` passes
- [ ] `cargo deny check` passes
- [ ] `cargo build --locked` passes (no `Cargo.lock` changes)
- [ ] Key file: `chmod 0600 data/node/keys.enc`
- [ ] Data dir: `chmod 0700 data/node/`
- [ ] Remote signer mTLS certs present and valid
- [ ] Systemd unit uses hardened profile (Section 16)
- [ ] `scripts/security_check.sh` exits 0

### Profile comparison matrix

| Feature | dev | prod | hard |
|---------|-----|------|------|
| RPC on loopback | ✓ | ✓ | ✓ |
| Encrypted keystore | optional | ✓ | ✓ |
| Key-perm gate (0600/0700) | skippable | ✓ | ✓ |
| CORS restrictive | ✗ | ✓ | ✓ |
| Rate limiting | ✓ | ✓ | ✓ |
| JSON depth limit | ✓ | ✓ | ✓ |
| Header size limit | ✓ | ✓ | ✓ |
| Remote signer | optional | optional | ✓ |
| Systemd hardened | ✗ | recommended | ✓ |
| Fuzz corpus-run | ✗ | periodic | monthly |
| `panic = "abort"` | ✓ | ✓ | ✓ |
| `overflow-checks` | ✓ | ✓ | ✓ |

---

## 23. v28.0 Security Changes (This Release)

The following security improvements were added in v28.0.0 and are captured here for grant reviewers and auditors:

### 23.1 RPC Bind-Address Safety Gate

`iona-node` now **refuses to start** if `rpc.listen` is a public address (anything other than `127.*`, `[::1]`, or `localhost`) unless the operator explicitly passes `--unsafe-rpc-public`. When `--unsafe-rpc-public` is active, a prominent multi-line `WARN` banner is logged.

**File:** `src/bin/iona-node.rs` — `fn main()`, RPC bind-address check block.

### 23.2 Configurable CORS Policy

`rpc.cors_allow_all = false` (the new default) disables cross-origin access entirely. `true` enables the old permissive CORS. This ensures that production deployments cannot be inadvertently made accessible to arbitrary browser-side scripts.

**File:** `src/config.rs` → `RpcSection`, `src/bin/iona-node.rs` → router setup.

### 23.3 Uniform Read Rate-Limiting

All `GET`/`HEAD` endpoints now pass through `read_limit_middleware`, which calls `RpcLimiter::check_read()` per source IP. Previously only `POST /tx` was rate-limited.

**File:** `src/rpc/middleware.rs` → `read_limit_middleware`.

### 23.4 JSON Depth Limit

POST bodies with JSON nesting deeper than `MAX_JSON_DEPTH = 32` are rejected with `HTTP 422` before any handler parses them. This closes the JSON parser stack-overflow / quadratic-parse-time class of attacks.

**File:** `src/rpc/middleware.rs` → `json_depth_middleware`, `json_nesting_depth`.

### 23.5 Header-Block Size Limit

Request header blocks larger than `MAX_HEADER_BYTES = 8 KiB` (total, all headers combined) are rejected with `HTTP 431` before rate-limit accounting. This prevents header-flood attacks that could exhaust per-IP token buckets.

**File:** `src/rpc/middleware.rs` → `header_size_middleware`.

### 23.6 Keystore and Data-Directory Permission Gates

On Unix, the node checks at startup that:
- The data directory has at most `0700` permissions (owner-only).
- The key file (`keys.enc` or `keys.json`) has at most `0600` permissions.

Failure on either check causes `anyhow::bail!` — the node will not start. The check is bypassable with `--unsafe-skip-key-perms` (logs `WARN` and continues).

**File:** `src/bin/iona-node.rs` → `fn check_key_permissions`.

### 23.7 `panic = "abort"` in Release Profile

Added to `Cargo.toml`:
```toml
[profile.release]
panic           = "abort"
lto             = "thin"
codegen-units   = 1
overflow-checks = true
```

This eliminates stack unwinding machinery from the release binary (smaller attack surface, no `catch_unwind` for adversaries to exploit). The `overflow-checks = true` line keeps integer overflow detection enabled even in optimised builds.

### 23.8 Negative Security Tests (`tests/rpc_security_gates.rs`)

Added 18 negative tests providing evidence for each hard claim:

| Test | Gate verified |
|------|--------------|
| `g1_body_over_limit_is_rejected` | Oversized body → rejected before parsing |
| `g2_read_flood_rate_limits_hot_ip` | GET flood → `429` for hot IP only |
| `g2_submit_flood_rate_limits_hot_ip` | POST flood → `429` for hot IP only |
| `g3_deeply_nested_json_exceeds_limit` | JSON depth > 32 → caught by `json_nesting_depth` |
| `g3_braces_inside_strings_not_counted` | String content does not inflate depth count |
| `g4_header_size_calculation_is_correct` | Normal headers pass; oversized headers detected |
| `g5_wildcard_bind_is_public` | `0.0.0.0` detected as public |
| `g5_loopback_bind_is_not_public` | `127.0.0.1` / `[::1]` pass |
| `g6_key_file_0644_is_rejected` (Unix) | World-readable key file → startup failure |
| `g6_key_file_0600_is_accepted` (Unix) | Correct key permissions → pass |
| `g7_data_dir_0755_is_rejected` (Unix) | Group-readable data dir → startup failure |
| `g7_data_dir_0700_is_accepted` (Unix) | Correct dir permissions → pass |

---

*IONA Security-First Manifesto — v28.1.0. Maintained by the IONA core team.*
*For vulnerability reports, see `SECURITY.md`. For operational questions, see `docs/OPERATOR_RUNBOOK.md`.*
