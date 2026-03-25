//! Comparison benchmarks for JVT operations.

use std::collections::BTreeMap;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use jellyfish_verkle_tree::verkle_proof;
use jellyfish_verkle_tree::{
    apply_updates, get_committed_value, root_commitment_at, value_to_field,
    verify_commitment_consistency, Key, MemoryStore, Value,
};
use std::hint::black_box;

fn make_key(i: u32) -> Key {
    let mut key = [0u8; 32];
    key[0..4].copy_from_slice(&i.to_be_bytes());
    key[31] = (i & 0xFF) as u8;
    key
}

fn v(bytes: &[u8]) -> Value {
    value_to_field(bytes)
}

fn insert(store: &mut MemoryStore, key: &Key, value: Value) {
    let parent = store.latest_version();
    let new_version = parent.map_or(1, |v| v + 1);
    let mut updates = BTreeMap::new();
    updates.insert(*key, Some(value));
    let result = apply_updates(store, parent, new_version, updates);
    store.apply(&result);
}

fn build_store(n: u32) -> MemoryStore {
    let mut store = MemoryStore::new();
    for i in 0..n {
        insert(&mut store, &make_key(i), v(&[(i & 0xFF) as u8; 32]));
    }
    store
}

fn bench_insert_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("insert");

    for &n in &[10, 100, 1000] {
        group.bench_with_input(BenchmarkId::new("sequential", n), &n, |b, &n| {
            b.iter(|| {
                let mut store = MemoryStore::new();
                for i in 0..n {
                    insert(&mut store, &make_key(i), v(&[(i & 0xFF) as u8; 32]));
                }
                black_box(root_commitment_at(&store, store.latest_version().unwrap()));
            });
        });
    }

    for &n in &[100, 1000] {
        let store = build_store(n);
        let new_key = make_key(n + 1);
        group.bench_with_input(BenchmarkId::new("single_into_existing", n), &n, |b, _| {
            b.iter_batched(
                || store.clone(),
                |mut s| {
                    insert(&mut s, &new_key, v(&[42; 32]));
                    black_box(());
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    // Batch insert: single apply_updates call with many keys into an existing tree
    for &batch_n in &[10, 100] {
        let store = build_store(1000);
        let updates: BTreeMap<Key, Option<Value>> = (0..batch_n)
            .map(|i| (make_key(10_000 + i), Some(v(&[(i & 0xFF) as u8; 32]))))
            .collect();
        group.bench_with_input(
            BenchmarkId::new("batch_into_existing", batch_n),
            &batch_n,
            |b, _| {
                b.iter_batched(
                    || store.clone(),
                    |mut s| {
                        let parent = s.latest_version();
                        let new_version = parent.map_or(1, |v| v + 1);
                        let result = apply_updates(&s, parent, new_version, updates.clone());
                        s.apply(&result);
                        black_box(());
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

fn bench_get_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("get");

    for &n in &[100, 1000] {
        let store = build_store(n);
        let root_key = store.latest_root_key().unwrap().clone();
        group.bench_with_input(BenchmarkId::new("all_keys", n), &n, |b, &n| {
            b.iter(|| {
                for i in 0..n {
                    black_box(get_committed_value(&store, &root_key, &make_key(i)));
                }
            });
        });

        let mid_key = make_key(n / 2);
        group.bench_with_input(BenchmarkId::new("single_key", n), &n, |b, _| {
            b.iter(|| {
                black_box(get_committed_value(&store, &root_key, &mid_key));
            });
        });
    }

    group.finish();
}

fn bench_commitment_update(c: &mut Criterion) {
    let mut group = c.benchmark_group("commitment_update");

    for &n in &[100, 1000] {
        let store = build_store(n);
        let key = make_key(0);
        group.bench_with_input(BenchmarkId::new("update_existing_key", n), &n, |b, _| {
            b.iter_batched(
                || store.clone(),
                |mut s| {
                    insert(&mut s, &key, v(&[99; 32]));
                    black_box(());
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

fn bench_proof_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof");

    for &n in &[100, 1000] {
        let store = build_store(n);
        let root_key = store.latest_root_key().unwrap().clone();
        let key = make_key(n / 2);

        group.bench_with_input(BenchmarkId::new("single_key", n), &n, |b, _| {
            b.iter(|| {
                black_box(verkle_proof::prove_single(&store, &root_key, &key));
            });
        });
    }

    for &batch_n in &[10, 50, 100] {
        let store = build_store(1000);
        let root_key = store.latest_root_key().unwrap().clone();
        let keys: Vec<Key> = (0..batch_n).map(make_key).collect();

        group.bench_with_input(BenchmarkId::new("batch", batch_n), &batch_n, |b, _| {
            b.iter(|| {
                black_box(verkle_proof::prove(&store, &root_key, &keys));
            });
        });
    }

    group.finish();
}

fn bench_verify_consistency(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify_consistency");

    for &n in &[100, 1000] {
        let store = build_store(n);
        let root_key = store.latest_root_key().unwrap().clone();
        group.bench_with_input(BenchmarkId::new("full_tree", n), &n, |b, _| {
            b.iter(|| {
                black_box(verify_commitment_consistency(&store, &root_key));
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
