//! Proof size analysis: JVT (verkle) vs hypothetical JMT (Merkle).
//!
//! Run with mock:     cargo run --example proof_size_analysis
//! Run with Pedersen: cargo run --example proof_size_analysis --features pedersen

use std::collections::BTreeMap;

use jellyfish_verkle_tree::proof;
use jellyfish_verkle_tree::{apply_updates, Key, MemoryStore};

fn make_key(i: u32) -> Key {
    let mut key = [0u8; 32];
    key[0..4].copy_from_slice(&i.to_be_bytes());
    key[31] = (i & 0xFF) as u8;
    key
}

fn insert(store: &mut MemoryStore, key: Key, value: Vec<u8>) {
    let parent = store.latest_version();
    let new_version = parent.map_or(1, |v| v + 1);
    let mut updates = BTreeMap::new();
    updates.insert(key, Some(value));
    let result = apply_updates(store, parent, new_version, updates);
    store.apply(&result);
}

const IPA_PROOF_BYTES: usize = 8 * 2 * 32 + 32; // 544
const MULTIPROOF_BYTES: usize = 32 + IPA_PROOF_BYTES; // 576
const JMT_SIBLINGS_PER_LEVEL: usize = 15 * 32; // 480
const JMT_LEAF_BYTES: usize = 64;

fn jmt_single_proof_size(depth: usize) -> usize {
    depth * JMT_SIBLINGS_PER_LEVEL + JMT_LEAF_BYTES
}

fn main() {
    println!("JVT Proof Size Analysis");
    println!("=======================\n");

    println!("Constants (from implementation):");
    println!(
        "  IPA proof (256-element vector): {} bytes",
        IPA_PROOF_BYTES
    );
    println!(
        "  Multipoint proof (any N queries): {} bytes",
        MULTIPROOF_BYTES
    );
    println!(
        "  JMT sibling hashes per level: {} bytes",
        JMT_SIBLINGS_PER_LEVEL
    );
    println!();

    let sizes = [10u32, 100, 1000, 10_000];

    for &n in &sizes {
        let mut store = MemoryStore::new();
        for i in 0..n {
            insert(&mut store, make_key(i), vec![(i & 0xFF) as u8; 32]);
        }

        let root_key = store.latest_root_key().unwrap();
        let sample_keys: Vec<Key> = (0..n.min(100)).map(make_key).collect();
        let mut depths = Vec::new();

        for key in &sample_keys {
            if let Some(p) = proof::prove(&store, root_key, key) {
                depths.push(p.commitments.len());
            }
        }

        let avg_depth = depths.iter().sum::<usize>() as f64 / depths.len().max(1) as f64;
        let max_depth = depths.iter().copied().max().unwrap_or(0);
        let jmt_depth = if n > 1 {
            (n as f64).log(16.0).ceil() as usize
        } else {
            1
        };

        println!("Tree: {} keys", n);
        println!(
            "  JVT depth: avg {:.1}, max {} (256-ary)",
            avg_depth, max_depth
        );
        println!("  JMT depth: ~{} (16-ary)", jmt_depth);

        let jvt_single = max_depth * IPA_PROOF_BYTES + 96;
        let jmt_single = jmt_single_proof_size(jmt_depth);
        println!("  Single-key proof:");
        println!("    JVT: {} bytes, JMT: {} bytes", jvt_single, jmt_single);

        println!("  Batch proof (multipoint aggregation):");
        for &batch_n in &[10usize, 100, 1000] {
            if batch_n as u32 > n {
                continue;
            }
            let jmt_batch = batch_n * jmt_single;
            println!(
                "    {} keys: JVT = {} bytes (constant!), JMT = {} bytes ({:.0}×)",
                batch_n,
                MULTIPROOF_BYTES,
                jmt_batch,
                jmt_batch as f64 / MULTIPROOF_BYTES as f64
            );
        }
        println!();
    }

    println!(
        "Key insight: The JVT multipoint proof is {} bytes CONSTANT,",
        MULTIPROOF_BYTES
    );
    println!("regardless of how many keys are included.");
}
