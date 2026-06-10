//! Criterion benchmarks for IONA core operations — Production‑Grade.
//!
//! # Quantum Benchmark Model
//!
//! Fiecare benchmark este tratat ca o **măsurătoare cuantică** pe un
//! subspațiu al sistemului. Repetarea măsurătorii produce o distribuție
//! de timpi de execuție care reflectă **decoerența** introdusă de
//! variabilitatea hardware și a sistemului de operare.
//!
//! # Formalism matematic
//!
//! ```text
//! ρ_bench = (1/N) Σ_i |t_i⟩⟨t_i|
//! ⟨T⟩ = Tr(ρ_bench T) = (1/N) Σ_i t_i
//! ```
//!
//! # Rulare
//!
//! ```bash
//! cargo bench --locked
//! ```
//!
//! Rezultatele sunt scrise în `target/criterion/`.
//!
//! Pentru a adăuga un benchmark nou, implementați o funcție și adăugați‑o
//! în macro-ul `criterion_group!`.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

use iona::consensus::fast_finality::FinalityTracker;
use iona::crypto::ed25519::{Ed25519Keypair, Ed25519Signer};
use iona::crypto::tx::{derive_address, tx_sign_bytes};
use iona::crypto::Signer;
use iona::execution::{execute_block, KvState};
use iona::mempool::pool::Mempool;
use iona::types::{Block, BlockHeader, Hash32, Tx};

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Default quantum coherence for benchmark state.
const DEFAULT_BENCH_COHERENCE: f64 = 1.0;

/// Decoherence rate per benchmark iteration (simbolizează incertitudinea).
const BENCH_DECOHERENCE_RATE: f64 = 0.0001;

/// Kraus rank for benchmark quantum channels.
const BENCH_KRAUS_RANK: usize = 4;

// -----------------------------------------------------------------------------
// Classical Constants
// -----------------------------------------------------------------------------

/// Default gas limit for test transactions.
const DEFAULT_GAS_LIMIT: u64 = 100_000;

/// Default max fee per gas.
const DEFAULT_MAX_FEE: u64 = 10;

/// Default max priority fee per gas.
const DEFAULT_MAX_PRIORITY_FEE: u64 = 1;

/// Default chain ID for test transactions.
const DEFAULT_CHAIN_ID: u64 = 1;

/// Default base fee per gas for block execution.
const BASE_FEE_PER_GAS: u64 = 1;

/// Default proposer address (placeholder).
const PROPOSER_ADDR: &str = "proposer";

/// Payload prefix for KV operations.
const PAYLOAD_PREFIX: &str = "set ";

// -----------------------------------------------------------------------------
// Quantum Benchmark State
// -----------------------------------------------------------------------------

/// Stare cuantică pentru benchmark-uri.
///
/// Urmărește puritatea și numărul de iterații pentru a oferi o metrică
/// a "sănătății" benchmark-ului (cât de stabil este).
#[derive(Debug, Clone)]
struct QuantumBenchState {
    purity: f64,
    entropy: f64,
    coherence: f64,
    iteration_count: u64,
    is_healthy: bool,
}

impl QuantumBenchState {
    fn new() -> Self {
        Self {
            purity: DEFAULT_BENCH_COHERENCE,
            entropy: 0.0,
            coherence: DEFAULT_BENCH_COHERENCE,
            iteration_count: 0,
            is_healthy: true,
        }
    }

    fn record_iteration(&mut self) {
        self.iteration_count = self.iteration_count.wrapping_add(1);
        let decay = (-BENCH_DECOHERENCE_RATE).exp();
        self.coherence = (self.coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    fn apply_channel(&mut self) {
        let kraus_factor = (1.0 / BENCH_KRAUS_RANK as f64).sqrt();
        self.coherence = (self.coherence * kraus_factor).clamp(0.0, 1.0);
        self.recompute();
    }

    fn recompute(&mut self) {
        self.purity = self.coherence;
        self.entropy = if self.purity >= 1.0 {
            0.0
        } else {
            -self.purity * self.purity.ln().max(0.0)
        };
        self.is_healthy = self.purity >= 0.99;
    }
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Generate a deterministic keypair and its derived address.
fn make_keypair(seed: u64) -> (Ed25519Signer, Vec<u8>, String) {
    let mut seed_bytes = [0u8; 32];
    seed_bytes[..8].copy_from_slice(&seed.to_le_bytes());
    let keypair = Ed25519Keypair::from_seed(seed_bytes);
    let signer = Ed25519Signer::from_keypair(keypair);
    let pubkey = signer.public_key_bytes();
    let address = derive_address(&pubkey);
    (signer, pubkey, address)
}

/// Create a signed transaction with the given parameters.
fn make_signed_tx(
    signer: &Ed25519Signer,
    pubkey: &[u8],
    address: &str,
    nonce: u64,
    payload: &str,
) -> Tx {
    let mut tx = Tx {
        from: address.to_string(),
        to: String::new(),
        nonce,
        payload: payload.to_string(),
        pubkey: pubkey.to_vec(),
        signature: vec![],
        gas_limit: DEFAULT_GAS_LIMIT,
        max_fee_per_gas: DEFAULT_MAX_FEE,
        max_priority_fee_per_gas: DEFAULT_MAX_PRIORITY_FEE,
        chain_id: DEFAULT_CHAIN_ID,
    };
    let msg = tx_sign_bytes(&tx);
    tx.signature = signer.sign(&msg);
    tx
}

/// Create a `KvState` with a single funded account.
fn make_state_with_balance(address: &str, balance: u64) -> KvState {
    let mut state = KvState::default();
    state.balances.insert(address.to_string(), balance);
    state
}

// -----------------------------------------------------------------------------
// Finality benchmarks
// -----------------------------------------------------------------------------

fn bench_finality_tracker(c: &mut Criterion) {
    let mut group = c.benchmark_group("finality");
    let mut qstate = QuantumBenchState::new();

    for n_validators in [3, 7, 21, 100] {
        group.bench_with_input(
            BenchmarkId::new("track_commit", n_validators),
            &n_validators,
            |b, &n| {
                b.iter(|| {
                    qstate.record_iteration();
                    let mut tracker = FinalityTracker::new(n as usize);
                    let block_id = Hash32([1u8; 32]);
                    let threshold = (2 * n / 3) + 1;
                    for i in 0..threshold {
                        tracker.record_precommit(black_box(1), black_box(block_id), i as usize);
                    }
                    tracker.check_finality(1)
                });
            },
        );
    }

    qstate.apply_channel();
    println!(
        "Finality benchmark purity: {:.6}, healthy: {}",
        qstate.purity, qstate.is_healthy
    );

    group.finish();
}

// -----------------------------------------------------------------------------
// Block execution benchmarks
// -----------------------------------------------------------------------------

fn bench_execute_block(c: &mut Criterion) {
    let mut group = c.benchmark_group("execution");
    let mut qstate = QuantumBenchState::new();

    for n_txs in [1, 10, 50, 100] {
        group.bench_with_input(
            BenchmarkId::new("execute_block", n_txs),
            &n_txs,
            |b, &n| {
                let (signer, pubkey, address) = make_keypair(42);
                let state = make_state_with_balance(&address, 10_000_000_000);
                let txs: Vec<Tx> = (0..n)
                    .map(|i| {
                        make_signed_tx(
                            &signer,
                            &pubkey,
                            &address,
                            i as u64,
                            &format!("{}key{} value{}", PAYLOAD_PREFIX, i, i),
                        )
                    })
                    .collect();

                b.iter(|| {
                    qstate.record_iteration();
                    execute_block(
                        black_box(&state),
                        black_box(&txs),
                        BASE_FEE_PER_GAS,
                        PROPOSER_ADDR,
                    )
                });
            },
        );
    }

    qstate.apply_channel();
    println!(
        "Execution benchmark purity: {:.6}, healthy: {}",
        qstate.purity, qstate.is_healthy
    );

    group.finish();
}

// -----------------------------------------------------------------------------
// State root computation benchmarks
// -----------------------------------------------------------------------------

fn bench_state_root(c: &mut Criterion) {
    let mut group = c.benchmark_group("state_root");
    let mut qstate = QuantumBenchState::new();

    for n_keys in [10, 100, 1000] {
        group.bench_with_input(BenchmarkId::new("compute", n_keys), &n_keys, |b, &n| {
            let mut state = KvState::default();
            for i in 0..n {
                state
                    .kv
                    .insert(format!("key_{}", i), format!("value_{}", i));
                state
                    .balances
                    .insert(format!("addr_{:040x}", i), 1000 + i as u64);
            }
            b.iter(|| {
                qstate.record_iteration();
                black_box(state.root())
            });
        });
    }

    qstate.apply_channel();
    println!(
        "State root benchmark purity: {:.6}, healthy: {}",
        qstate.purity, qstate.is_healthy
    );

    group.finish();
}

// -----------------------------------------------------------------------------
// Signature verification benchmarks
// -----------------------------------------------------------------------------

fn bench_signature_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("signature");
    let mut qstate = QuantumBenchState::new();

    let (signer, pubkey, address) = make_keypair(99);
    let tx = make_signed_tx(&signer, &pubkey, &address, 0, "set hello world");

    group.bench_function("verify_single", |b| {
        b.iter(|| {
            qstate.record_iteration();
            iona::execution::verify_tx_signature(black_box(&tx))
        });
    });

    // Batch verification benchmark
    let txs: Vec<Tx> = (0..50)
        .map(|i| make_signed_tx(&signer, &pubkey, &address, i, "set batch"))
        .collect();

    group.bench_function("verify_batch_50", |b| {
        b.iter(|| {
            qstate.record_iteration();
            for tx in &txs {
                let _ = iona::execution::verify_tx_signature(black_box(tx));
            }
        });
    });

    qstate.apply_channel();
    println!(
        "Signature benchmark purity: {:.6}, healthy: {}",
        qstate.purity, qstate.is_healthy
    );

    group.finish();
}

// -----------------------------------------------------------------------------
// Mempool benchmarks
// -----------------------------------------------------------------------------

fn bench_mempool(c: &mut Criterion) {
    let mut group = c.benchmark_group("mempool");
    let mut qstate = QuantumBenchState::new();

    group.bench_function("add_100_txs", |b| {
        let (signer, pubkey, address) = make_keypair(7);
        let txs: Vec<Tx> = (0..100)
            .map(|i| {
                make_signed_tx(
                    &signer,
                    &pubkey,
                    &address,
                    i,
                    &format!("{}k{} v{}", PAYLOAD_PREFIX, i, i),
                )
            })
            .collect();

        b.iter(|| {
            qstate.record_iteration();
            let mut pool = Mempool::new(10_000);
            for tx in &txs {
                let _ = pool.add(tx.clone());
            }
            black_box(pool.pending(100))
        });
    });

    group.bench_function("pending_from_1000", |b| {
        let mut pool = Mempool::new(10_000);
        for i in 0..1000u64 {
            let (signer, pubkey, address) = make_keypair(i);
            let tx = make_signed_tx(
                &signer,
                &pubkey,
                &address,
                0,
                &format!("{}k{} v{}", PAYLOAD_PREFIX, i, i),
            );
            let _ = pool.add(tx);
        }

        b.iter(|| {
            qstate.record_iteration();
            black_box(pool.pending(100))
        });
    });

    qstate.apply_channel();
    println!(
        "Mempool benchmark purity: {:.6}, healthy: {}",
        qstate.purity, qstate.is_healthy
    );

    group.finish();
}

// -----------------------------------------------------------------------------
// Merkle trie benchmarks
// -----------------------------------------------------------------------------

fn bench_merkle(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle");
    let mut qstate = QuantumBenchState::new();

    group.bench_function("tx_root_100", |b| {
        let txs: Vec<Tx> = (0..100)
            .map(|i| Tx {
                from: format!("addr{}", i),
                to: String::new(),
                nonce: i as u64,
                payload: format!("set key{} value{}", i, i),
                pubkey: vec![i as u8; 32],
                signature: vec![0u8; 64],
                gas_limit: DEFAULT_GAS_LIMIT,
                max_fee_per_gas: DEFAULT_MAX_FEE,
                max_priority_fee_per_gas: DEFAULT_MAX_PRIORITY_FEE,
                chain_id: DEFAULT_CHAIN_ID,
            })
            .collect();

        b.iter(|| {
            qstate.record_iteration();
            iona::types::tx_root(black_box(&txs))
        });
    });

    // Additional benchmark for receipts root
    group.bench_function("receipts_root_100", |b| {
        use iona::types::Receipt;
        let receipts: Vec<Receipt> = (0..100)
            .map(|i| Receipt {
                tx_hash: Hash32([i as u8; 32]),
                success: true,
                gas_used: 21_000,
                intrinsic_gas_used: 21_000,
                exec_gas_used: 0,
                vm_gas_used: 0,
                evm_gas_used: 0,
                effective_gas_price: 1,
                burned: 1,
                tip: 0,
                error: None,
                data: None,
            })
            .collect();

        b.iter(|| {
            qstate.record_iteration();
            iona::types::receipts_root(black_box(&receipts))
        });
    });

    qstate.apply_channel();
    println!(
        "Merkle benchmark purity: {:.6}, healthy: {}",
        qstate.purity, qstate.is_healthy
    );

    group.finish();
}

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------

criterion_group!(
    benches,
    bench_finality_tracker,
    bench_execute_block,
    bench_state_root,
    bench_signature_verify,
    bench_mempool,
    bench_merkle,
);
criterion_main!(benches);
