//! Comparison benchmarks for JVT operations.
//!
//! Measures:
//! - Insert throughput (single key and batch)
//! - Get throughput
//! - Commitment update cost (single leaf modification)
//! - Commitment consistency verification
//! - Proof generation (single key)
//!
//! Run with mock:     cargo bench
//! Run with Pedersen: cargo bench --features pedersen
//! (Pedersen benchmarks will be significantly slower due to real EC operations)

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use jellyfish_verkle_tree::node::NodeKey;
use jellyfish_verkle_tree::proof;
use jellyfish_verkle_tree::{Key, MemoryStore, JVT};
use std::hint::black_box;

fn make_key(i: u32) -> Key {
    let mut key = [0u8; 32];
    key[0..4].copy_from_slice(&i.to_be_bytes());
    key[31] = (i & 0xFF) as u8;
    key
}

/// Build a tree with N keys for use in benchmarks.
fn build_tree(n: u32) -> JVT<MemoryStore> {
    let mut tree = JVT::new(MemoryStore::new());
    for i in 0..n {
        tree.insert(make_key(i), vec![(i & 0xFF) as u8; 32]);
    }
    tree
}

// ============================================================
// Insert benchmarks
// ============================================================

fn bench_insert_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("insert");

    for &n in &[10, 100, 1000] {
        group.bench_with_input(BenchmarkId::new("sequential", n), &n, |b, &n| {
            b.iter(|| {
                let mut tree = JVT::new(MemoryStore::new());
                for i in 0..n {
                    tree.insert(make_key(i), vec![(i & 0xFF) as u8; 32]);
                }
                black_box(tree.root_commitment());
            });
        });
    }

    // Single insert into an existing tree of various sizes
    for &n in &[100, 1000] {
        group.bench_with_input(BenchmarkId::new("single_into_existing", n), &n, |b, &n| {
            let tree = build_tree(n);
            let new_key = make_key(n + 1);
            b.iter_batched(
                || tree.clone(),
                |mut t| {
                    black_box(t.insert(new_key, vec![42; 32]));
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

// ============================================================
// Get benchmarks
// ============================================================

fn bench_get_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("get");

    for &n in &[100, 1000] {
        let tree = build_tree(n);
        group.bench_with_input(BenchmarkId::new("all_keys", n), &n, |b, &n| {
            b.iter(|| {
                for i in 0..n {
                    black_box(tree.get(&make_key(i)));
                }
            });
        });
    }

    // Single get from trees of various sizes
    for &n in &[100, 1000] {
        let tree = build_tree(n);
        let key = make_key(n / 2); // middle key
        group.bench_with_input(BenchmarkId::new("single_key", n), &n, |b, _| {
            b.iter(|| {
                black_box(tree.get(&key));
            });
        });
    }

    group.finish();
}

// ============================================================
// Commitment update cost (single leaf modification)
// ============================================================

fn bench_commitment_update(c: &mut Criterion) {
    let mut group = c.benchmark_group("commitment_update");

    for &n in &[100, 1000] {
        let tree = build_tree(n);
        let key = make_key(0); // update key 0
        group.bench_with_input(BenchmarkId::new("update_existing_key", n), &n, |b, _| {
            b.iter_batched(
                || tree.clone(),
                |mut t| {
                    black_box(t.insert(key, vec![99; 32]));
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

// ============================================================
// Proof generation benchmarks
// ============================================================

fn bench_proof_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof");

    for &n in &[100, 1000] {
        let tree = build_tree(n);
        let root_key = NodeKey::root(tree.current_version());
        let key = make_key(n / 2);

        group.bench_with_input(BenchmarkId::new("single_key", n), &n, |b, _| {
            b.iter(|| {
                black_box(proof::prove(&tree.store, &root_key, &key));
            });
        });
    }

    // Batch proof generation
    for &n in &[10, 50, 100] {
        let tree = build_tree(1000);
        let root_key = NodeKey::root(tree.current_version());
        let keys: Vec<Key> = (0..n).map(|i| make_key(i)).collect();

        group.bench_with_input(BenchmarkId::new("batch", n), &n, |b, _| {
            b.iter(|| {
                black_box(proof::prove_batch(&tree.store, &root_key, &keys));
            });
        });
    }

    group.finish();
}

// ============================================================
// Commitment consistency verification
// ============================================================

fn bench_verify_consistency(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify_consistency");

    for &n in &[100, 1000] {
        let tree = build_tree(n);
        group.bench_with_input(BenchmarkId::new("full_tree", n), &n, |b, _| {
            b.iter(|| {
                black_box(tree.verify_commitment_consistency());
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_insert_throughput,
    bench_get_throughput,
    bench_commitment_update,
    bench_proof_generation,
    bench_verify_consistency
);
criterion_main!(benches);
