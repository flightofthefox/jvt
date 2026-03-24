//! Comparison benchmarks: JVT structural proof sizes and insert throughput.

use criterion::{criterion_group, criterion_main, Criterion};
use jellyfish_verkle_tree::{Key, MemoryStore, JVT};
use std::hint::black_box;

fn make_key(i: u32) -> Key {
    let mut key = [0u8; 32];
    key[0..4].copy_from_slice(&i.to_be_bytes());
    key[31] = (i & 0xFF) as u8;
    key
}

fn bench_insert(c: &mut Criterion) {
    c.bench_function("insert_1000_keys", |b| {
        b.iter(|| {
            let mut tree = JVT::new(MemoryStore::new());
            for i in 0..1000u32 {
                tree.insert(make_key(i), vec![(i & 0xFF) as u8]);
            }
            black_box(tree.root_commitment());
        });
    });
}

fn bench_get(c: &mut Criterion) {
    let mut tree = JVT::new(MemoryStore::new());
    for i in 0..1000u32 {
        tree.insert(make_key(i), vec![(i & 0xFF) as u8]);
    }

    c.bench_function("get_from_1000_keys", |b| {
        b.iter(|| {
            for i in 0..1000u32 {
                black_box(tree.get(&make_key(i)));
            }
        });
    });
}

fn bench_commitment_consistency(c: &mut Criterion) {
    let mut tree = JVT::new(MemoryStore::new());
    for i in 0..100u32 {
        tree.insert(make_key(i), vec![(i & 0xFF) as u8]);
    }

    c.bench_function("verify_commitment_consistency_100", |b| {
        b.iter(|| {
            black_box(tree.verify_commitment_consistency());
        });
    });
}

criterion_group!(
    benches,
    bench_insert,
    bench_get,
    bench_commitment_consistency
);
criterion_main!(benches);
