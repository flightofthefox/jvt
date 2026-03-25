//! Benchmark: proof generation timing under production-like workloads.
//!
//! Simulates a typical block-oriented workload:
//! - Keys are BLAKE3 hashes (uniformly distributed [u8; 32])
//! - Values are field elements via value_to_field
//! - Tree grows across multiple block commits (up to 300K entries)
//! - Each block proves a batch of 7–200 keys
//!
//! Run: cargo run --example bench_proofs --release

use std::collections::BTreeMap;
use std::time::Instant;

use jellyfish_verkle_tree::{
    apply_updates, value_to_field, verkle_proof, Key, MemoryStore, TreeReader, Value,
};

/// Generate a deterministic key by hashing an index (simulates BLAKE3(storage_key)).
fn make_key(index: u32) -> Key {
    let hash = blake3::hash(&index.to_le_bytes());
    *hash.as_bytes()
}

/// Generate a deterministic value (simulates value_to_field(substate_bytes)).
fn make_value(index: u32) -> Value {
    let bytes = format!("substate-value-{index}-padding-to-make-it-longer-than-31-bytes");
    value_to_field(bytes.as_bytes())
}

fn main() {
    println!("=== JVT Proof Generation Benchmark ===\n");
    println!("Simulates production workload:\n");
    println!("  - Keys: BLAKE3 hashes (uniform [u8; 32])");
    println!("  - Values: field elements via value_to_field");
    println!("  - Tree grows across multiple block commits");
    println!("  - Each block proves a subset of keys\n");

    let mut store = MemoryStore::new();
    let mut version = 0u64;
    let mut all_keys: Vec<Key> = Vec::new();

    // ── Phase 1: Build up the tree (simulates genesis + early blocks) ──

    let tree_sizes = [1_000, 10_000, 100_000, 300_000];

    for &target_size in &tree_sizes {
        // Insert keys up to target_size
        let start_idx = all_keys.len() as u32;
        let end_idx = target_size as u32;
        if start_idx >= end_idx {
            continue;
        }

        let mut updates: BTreeMap<Key, Option<Value>> = BTreeMap::new();
        for i in start_idx..end_idx {
            let key = make_key(i);
            updates.insert(key, Some(make_value(i)));
            all_keys.push(key);
        }

        version += 1;
        let t = Instant::now();
        let result = apply_updates(
            &store,
            if version == 1 {
                None
            } else {
                Some(version - 1)
            },
            version,
            updates,
        );
        let apply_ms = t.elapsed().as_millis();
        store.apply(&result);

        println!(
            "Tree build: inserted {} keys (total {}), apply_updates={}ms",
            end_idx - start_idx,
            all_keys.len(),
            apply_ms
        );
    }

    println!();

    // ── Phase 2: Prove batches of varying sizes (simulates per-block proofs) ──

    let batch_sizes = [7, 14, 28, 56, 112, 196];
    let root_key = store.latest_root_key().expect("tree should have a root");
    let root_commitment = store
        .get_node(&root_key)
        .expect("root node should exist")
        .commitment();

    for &batch_size in &batch_sizes {
        if batch_size > all_keys.len() {
            continue;
        }

        // Pick keys spread across the tree
        let step = all_keys.len() / batch_size;
        let prove_keys: Vec<Key> = (0..batch_size).map(|i| all_keys[i * step]).collect();

        // Time the proof generation
        let t = Instant::now();
        let proof =
            verkle_proof::prove(&store, &root_key, &prove_keys).expect("prove should succeed");
        let prove_ms = t.elapsed().as_millis();

        // Time verification
        let values: Vec<Option<Value>> = prove_keys
            .iter()
            .map(|k| jellyfish_verkle_tree::get_committed_value(&store, &root_key, k))
            .collect();

        let t = Instant::now();
        let valid = verkle_proof::verify(&proof, root_commitment, &prove_keys, &values);
        let verify_ms = t.elapsed().as_millis();

        let num_commitments = proof.num_commitments();
        let proof_bytes = proof.total_byte_size();

        println!(
            "Prove {batch_size:>4} keys: prove={prove_ms:>6}ms  verify={verify_ms:>4}ms  \
             comms={num_commitments:>4}  proof_size={proof_bytes:>6}B  valid={valid}"
        );
    }

    println!();

    // ── Phase 3: Incremental block pattern ──
    // Simulates the actual production pattern: commit a block with new txns,
    // then immediately prove the new entries.

    println!("--- Incremental block pattern (commit then prove) ---\n");

    let txns_per_block = [7, 14, 28];
    // Each txn touches ~4 substates (typical Radix transfer)
    let substates_per_txn = 4;

    for &txn_count in &txns_per_block {
        let entry_count = txn_count * substates_per_txn;
        let start_idx = all_keys.len() as u32;

        // Commit new block
        let mut updates: BTreeMap<Key, Option<Value>> = BTreeMap::new();
        let mut block_keys: Vec<Key> = Vec::new();
        for i in start_idx..start_idx + entry_count as u32 {
            let key = make_key(i + 10000); // offset to avoid collisions
            updates.insert(key, Some(make_value(i)));
            block_keys.push(key);
            all_keys.push(key);
        }

        version += 1;
        let result = apply_updates(&store, Some(version - 1), version, updates);
        store.apply(&result);

        let root_key = store.latest_root_key().expect("root");
        let root_commitment = store.get_node(&root_key).unwrap().commitment();

        // Prove just the new block's entries
        let t = Instant::now();
        let proof =
            verkle_proof::prove(&store, &root_key, &block_keys).expect("prove should succeed");
        let prove_ms = t.elapsed().as_millis();

        let values: Vec<Option<Value>> = block_keys
            .iter()
            .map(|k| jellyfish_verkle_tree::get_committed_value(&store, &root_key, k))
            .collect();

        let t = Instant::now();
        let valid = verkle_proof::verify(&proof, root_commitment, &block_keys, &values);
        let verify_ms = t.elapsed().as_millis();

        println!(
            "Block: {txn_count:>3} txns × {substates_per_txn} substates = {entry_count:>4} keys  \
             (tree={})  prove={prove_ms:>5}ms  verify={verify_ms:>4}ms  valid={valid}",
            all_keys.len()
        );
    }
}
