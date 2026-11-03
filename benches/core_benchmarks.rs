//! Criterion benchmarks for IONA core operations.
//!
//! # Scope
//!
//! Measures the operations that dominate consensus and execution:
//!
//! | Group        | Benchmarks |
//! |--------------|------------|
//! | `finality`   | `FinalityTracker::record_commit` under various window loads |
//! | `execution`  | `execute_block` with 1..100 transactions |
//! | `state_root` | `KvState::root()` at 10/100/1000 keys |
//! | `signature`  | Ed25519 verify (single + 50-batch) via a shared `TxManager` |
//! | `mempool`    | insert 100 txs into a fresh pool; read from a 1000-tx pool |
//! | `merkle`     | `tx_root` / `receipts_root` over 100 entries |
//!
//! # Running
//!
//! ```bash
//! cargo bench --locked
//! ```
//!
//! Results are written to `target/criterion/`.
//!
//! # Adding a benchmark
//!
//! 1. Write a `fn bench_xxx(c: &mut Criterion)`.
//! 2. Add it to the `criterion_group!` invocation at the bottom.
//!
//! # Setup vs. measurement
//!
//! Expensive setup (key derivation, signing 100 transactions, populating a
//! 1000-key state) runs **outside** `b.iter` so it is not timed. Operations
//! that must start from a fresh object on every iteration (e.g. inserting
//! 100 txs into a new `Mempool`) use `iter_batched` with an appropriate
//! `BatchSize`.
//!
//! # Determinism
//!
//! Every input is derived from a fixed seed. No RNG, no wall clock. Two
//! runs on the same hardware produce the same measured operations.

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use std::hint::black_box;

use iona::consensus::fast_finality::{FinalityConfig, FinalityTracker};
use iona::crypto::ed25519::Ed25519Signer;
use iona::crypto::tx::{derive_address, tx_sign_bytes, TxConfig, TxManager};
use iona::crypto::Signer;
use iona::execution::{execute_block, KvState};
use iona::mempool::pool::Mempool;
use iona::types::{Hash32, Receipt, Tx};

// ── Constants ─────────────────────────────────────────────────────────────

const DEFAULT_GAS_LIMIT: u64 = 100_000;
const DEFAULT_MAX_FEE: u64 = 10;
const DEFAULT_MAX_PRIORITY_FEE: u64 = 1;
const DEFAULT_CHAIN_ID: u64 = 1;
const BASE_FEE_PER_GAS: u64 = 1;

/// Proposer address used for `execute_block`. The 40-hex-digit form is the
/// canonical IONA address shape; `execute_block` accepts any `&str`, but
/// using a real-looking value keeps the benchmark aligned with production
/// call sites.
const PROPOSER_ADDR: &str = "0000000000000000000000000000000000000000";

const PAYLOAD_PREFIX: &str = "set ";

// ── Helpers ───────────────────────────────────────────────────────────────

/// Build a deterministic signer from `seed`.
///
/// Returns `(signer, pubkey_bytes, address)` where `address` is the
/// 40-hex-digit string derived from `pubkey_bytes`.
fn make_keypair(seed: u64) -> (Ed25519Signer, Vec<u8>, String) {
    let mut seed_bytes = [0u8; 32];
    seed_bytes[..8].copy_from_slice(&seed.to_le_bytes());
    let signer = Ed25519Signer::from_seed(seed_bytes);
    let pubkey = signer.public_key().0;
    let address = derive_address(&pubkey)
        .expect("derive_address is infallible for a 32-byte pubkey");
    (signer, pubkey, address)
}

/// Build a signed transaction whose signature covers its canonical
/// payload.
fn make_signed_tx(
    signer: &Ed25519Signer,
    pubkey: &[u8],
    address: &str,
    nonce: u64,
    payload: &str,
) -> Tx {
    let mut tx = Tx {
        from: address.to_string(),
        nonce,
        payload: payload.to_string(),
        pubkey: pubkey.to_vec(),
        signature: vec![],
        gas_limit: DEFAULT_GAS_LIMIT,
        max_fee_per_gas: DEFAULT_MAX_FEE,
        max_priority_fee_per_gas: DEFAULT_MAX_PRIORITY_FEE,
        chain_id: DEFAULT_CHAIN_ID,
    };
    let msg = tx_sign_bytes(&tx)
        .expect("tx_sign_bytes is infallible for a well-formed Tx");
    tx.signature = signer.sign(&msg).0;
    tx
}

/// `KvState` with a single funded account.
fn make_state_with_balance(address: &str, balance: u64) -> KvState {
    let mut state = KvState::default();
    state.balances.insert(address.to_string(), balance);
    state
}

// ── Finality ──────────────────────────────────────────────────────────────

fn bench_finality_tracker(c: &mut Criterion) {
    let mut group = c.benchmark_group("finality");
    let config = FinalityConfig::default();

    // `n_commits` controls how many commits are recorded on a fresh
    // tracker, so the measurement reflects the amortised cost of one
    // `record_commit` including rolling-window maintenance.
    for n_commits in [10u32, 100, 1_000, 10_000] {
        group.bench_with_input(
            BenchmarkId::new("record_commit", n_commits),
            &n_commits,
            |b, &n| {
                b.iter_batched(
                    || FinalityTracker::with_config(1, &config),
                    |mut tracker| {
                        for i in 0..n {
                            // Vary `finality_ms` in a small band so the
                            // best/worst/mean estimators all see work.
                            let finality_ms = 100 + (i as u64 % 50);
                            tracker.record_commit(finality_ms, 0, &config);
                        }
                        black_box(tracker)
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

// ── Block execution ───────────────────────────────────────────────────────

fn bench_execute_block(c: &mut Criterion) {
    let mut group = c.benchmark_group("execution");

    for n_txs in [1u64, 10, 50, 100] {
        group.bench_with_input(
            BenchmarkId::new("execute_block", n_txs),
            &n_txs,
            |b, &n| {
                // Setup: one signer, one funded account, N signed txs.
                let (signer, pubkey, address) = make_keypair(42);
                let state = make_state_with_balance(&address, 10_000_000_000);
                let txs: Vec<Tx> = (0..n)
                    .map(|i| {
                        make_signed_tx(
                            &signer,
                            &pubkey,
                            &address,
                            i,
                            &format!("{}key{} value{}", PAYLOAD_PREFIX, i, i),
                        )
                    })
                    .collect();

                // Measurement: just `execute_block`.
                b.iter(|| {
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

    group.finish();
}

// ── State root ────────────────────────────────────────────────────────────

fn bench_state_root(c: &mut Criterion) {
    let mut group = c.benchmark_group("state_root");

    for n_keys in [10usize, 100, 1_000] {
        group.bench_with_input(
            BenchmarkId::new("compute", n_keys),
            &n_keys,
            |b, &n| {
                let mut state = KvState::default();
                for i in 0..n {
                    state
                        .kv
                        .insert(format!("key_{i}"), format!("value_{i}"));
                    state
                        .balances
                        .insert(format!("addr_{:040x}", i), 1_000 + i as u64);
                }
                b.iter(|| black_box(state.root()));
            },
        );
    }

    group.finish();
}

// ── Signature verification ────────────────────────────────────────────────

fn bench_signature_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("signature");

    // A single `TxManager` shared across iterations. The previous benchmark
    // called `iona::execution::verify_tx_signature(&tx)`, which constructs
    // a fresh `TxManager` per iteration — measuring manager construction
    // (and its Prometheus registration attempt) rather than verification.
    let manager = TxManager::new(TxConfig {
        enable_metrics: false,
        ..Default::default()
    })
    .expect("TxManager::new with default config is infallible");

    let (signer, pubkey, address) = make_keypair(99);
    let tx = make_signed_tx(&signer, &pubkey, &address, 0, "set hello world");

    group.bench_function("verify_single", |b| {
        b.iter(|| manager.verify_tx(black_box(&tx)));
    });

    let batch: Vec<Tx> = (0..50u64)
        .map(|i| make_signed_tx(&signer, &pubkey, &address, i, "set batch"))
        .collect();

    group.bench_function("verify_batch_50", |b| {
        b.iter(|| manager.verify_batch(black_box(&batch)));
    });

    group.finish();
}

// ── Mempool ───────────────────────────────────────────────────────────────

fn bench_mempool(c: &mut Criterion) {
    let mut group = c.benchmark_group("mempool");

    group.bench_function("add_100_txs", |b| {
        let (signer, pubkey, address) = make_keypair(7);
        let txs: Vec<Tx> = (0..100u64)
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
            let mut pool = Mempool::new(10_000);
            for tx in &txs {
                let _ = pool.add(tx.clone());
            }
            black_box(pool.pending(100))
        });
    });

    group.bench_function("pending_from_1000", |b| {
        let mut pool = Mempool::new(10_000);
        for i in 0..1_000u64 {
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

        b.iter(|| black_box(pool.pending(100)));
    });

    group.finish();
}

// ── Merkle roots ──────────────────────────────────────────────────────────

fn bench_merkle(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle");

    let txs: Vec<Tx> = (0..100u64)
        .map(|i| Tx {
            from: format!("addr{i}"),
            nonce: i,
            payload: format!("set key{i} value{i}"),
            pubkey: vec![i as u8; 32],
            signature: vec![0u8; 64],
            gas_limit: DEFAULT_GAS_LIMIT,
            max_fee_per_gas: DEFAULT_MAX_FEE,
            max_priority_fee_per_gas: DEFAULT_MAX_PRIORITY_FEE,
            chain_id: DEFAULT_CHAIN_ID,
        })
        .collect();

    group.bench_function("tx_root_100", |b| {
        b.iter(|| iona::types::tx_root(black_box(&txs)));
    });

    let receipts: Vec<Receipt> = (0..100u8)
        .map(|i| Receipt {
            tx_hash: Hash32([i; 32]),
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

    group.bench_function("receipts_root_100", |b| {
        b.iter(|| iona::types::receipts_root(black_box(&receipts)));
    });

    group.finish();
}

// ── Main ──────────────────────────────────────────────────────────────────

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
