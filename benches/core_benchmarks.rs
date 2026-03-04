//! Criterion benchmarks for IONA core operations.
//!
//! Run: cargo bench --locked
//! Results written to target/criterion/

use iona::consensus::fast_finality::FinalityTracker;
use iona::execution::{execute_block, KvState};
use iona::mempool::pool::Mempool;
use iona::types::{Block, BlockHeader, Hash32, Tx};
use iona::crypto::tx::{derive_address, tx_sign_bytes};
use iona::crypto::ed25519::Ed25519Signer;
use iona::crypto::Signer;
use std::collections::BTreeMap;

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};

// ── Helpers ──────────────────────────────────────────────────────────────

fn make_keypair(seed: u64) -> (Ed25519Signer, Vec<u8>, String) {
    let mut seed_bytes = [0u8; 32];
    seed_bytes[..8].copy_from_slice(&seed.to_le_bytes());
    let signer = Ed25519Signer::from_seed(&seed_bytes);
    let pk = signer.public_key_bytes();
    let addr = derive_address(&pk);
    (signer, pk, addr)
}

fn make_signed_tx(signer: &Ed25519Signer, pk: &[u8], addr: &str, nonce: u64, payload: &str) -> Tx {
    let mut tx = Tx {
        from: addr.to_string(),
        to: String::new(),
        nonce,
        payload: payload.to_string(),
        pubkey: pk.to_vec(),
        signature: vec![],
        gas_limit: 100_000,
        max_fee_per_gas: 10,
        max_priority_fee_per_gas: 1,
        chain_id: 1,
    };
    let msg = tx_sign_bytes(&tx);
    tx.signature = signer.sign(&msg);
    tx
}

fn make_state_with_balance(addr: &str, balance: u64) -> KvState {
    let mut state = KvState::default();
    state.balances.insert(addr.to_string(), balance);
    state
}

// ── Finality benchmarks ─────────────────────────────────────────────────

fn bench_finality_tracker(c: &mut Criterion) {
    let mut group = c.benchmark_group("finality");

    for n_validators in [3, 7, 21, 100] {
        group.bench_with_input(
            BenchmarkId::new("track_commit", n_validators),
            &n_validators,
            |b, &n| {
                b.iter(|| {
                    let mut tracker = FinalityTracker::new(n as usize);
                    let block_id = Hash32([1u8; 32]);
                    // Simulate 2/3+1 validators committing
                    let threshold = (2 * n / 3) + 1;
                    for i in 0..threshold {
                        tracker.record_precommit(black_box(1), black_box(block_id), i as usize);
                    }
                    tracker.check_finality(1)
                });
            },
        );
    }

    group.finish();
}

// ── Execution benchmarks ────────────────────────────────────────────────

fn bench_execute_block(c: &mut Criterion) {
    let mut group = c.benchmark_group("execution");

    for n_txs in [1, 10, 50, 100] {
        group.bench_with_input(
            BenchmarkId::new("execute_block", n_txs),
            &n_txs,
            |b, &n| {
                let (signer, pk, addr) = make_keypair(42);
                let state = make_state_with_balance(&addr, 10_000_000_000);
                let txs: Vec<Tx> = (0..n)
                    .map(|i| make_signed_tx(&signer, &pk, &addr, i as u64, &format!("set key{i} val{i}")))
                    .collect();

                b.iter(|| {
                    execute_block(black_box(&state), black_box(&txs), 1, "proposer")
                });
            },
        );
    }

    group.finish();
}

fn bench_state_root(c: &mut Criterion) {
    let mut group = c.benchmark_group("state_root");

    for n_keys in [10, 100, 1000] {
        group.bench_with_input(
            BenchmarkId::new("compute", n_keys),
            &n_keys,
            |b, &n| {
                let mut state = KvState::default();
                for i in 0..n {
                    state.kv.insert(format!("key_{i}"), format!("value_{i}"));
                    state.balances.insert(format!("addr_{i:040x}"), 1000 + i as u64);
                }
                b.iter(|| {
                    black_box(state.root())
                });
            },
        );
    }

    group.finish();
}

// ── Signature verification benchmarks ───────────────────────────────────

fn bench_signature_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("signature");

    let (signer, pk, addr) = make_keypair(99);
    let tx = make_signed_tx(&signer, &pk, &addr, 0, "set hello world");

    group.bench_function("verify_single", |b| {
        b.iter(|| {
            iona::execution::verify_tx_signature(black_box(&tx))
        });
    });

    group.finish();
}

// ── Mempool benchmarks ──────────────────────────────────────────────────

fn bench_mempool(c: &mut Criterion) {
    let mut group = c.benchmark_group("mempool");

    group.bench_function("add_100_txs", |b| {
        let (signer, pk, addr) = make_keypair(7);
        let txs: Vec<Tx> = (0..100)
            .map(|i| make_signed_tx(&signer, &pk, &addr, i, &format!("set k{i} v{i}")))
            .collect();

        b.iter(|| {
            let mut pool = Mempool::new(10_000);
            for tx in &txs {
                pool.add(tx.clone());
            }
            black_box(pool.pending(100))
        });
    });

    group.bench_function("pending_from_1000", |b| {
        let mut pool = Mempool::new(10_000);
        for i in 0..1000u64 {
            let (signer, pk, addr) = make_keypair(i);
            let tx = make_signed_tx(&signer, &pk, &addr, 0, &format!("set k{i} v{i}"));
            pool.add(tx);
        }

        b.iter(|| {
            black_box(pool.pending(100))
        });
    });

    group.finish();
}

// ── Merkle benchmarks ───────────────────────────────────────────────────

fn bench_merkle(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle");

    group.bench_function("tx_root_100", |b| {
        let txs: Vec<Tx> = (0..100)
            .map(|i| Tx {
                from: format!("addr{i}"),
                to: String::new(),
                nonce: i as u64,
                payload: format!("set key{i} val{i}"),
                pubkey: vec![i as u8; 32],
                signature: vec![0u8; 64],
                gas_limit: 100_000,
                max_fee_per_gas: 10,
                max_priority_fee_per_gas: 1,
                chain_id: 1,
            })
            .collect();

        b.iter(|| {
            iona::types::tx_root(black_box(&txs))
        });
    });

    group.finish();
}

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
