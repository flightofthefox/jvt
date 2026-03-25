//! Versioning: time-travel queries, comparing roots across versions, and pruning.
//!
//! JVT stores every version of the tree persistently. Old versions remain
//! queryable until explicitly pruned — this is the "Jellyfish" part of the name.
//!
//! Run: cargo run --example versioning

use std::collections::BTreeMap;

use jellyfish_verkle_tree::{
    apply_updates, get_committed_value, root_commitment_at, value_to_field,
    verify_commitment_consistency, Key, MemoryStore, TreeReader,
};

fn make_key(stem: u8, suffix: u8) -> Key {
    let mut key = [0u8; 32];
    key[0] = stem;
    key[31] = suffix;
    key
}

fn main() {
    let mut store = MemoryStore::new();

    // ── Build up a history of versions ──────────────────────────
    println!("Building version history...\n");

    // v1: Insert account balances
    let key_a = make_key(0xAA, 0x01);
    let key_b = make_key(0xBB, 0x01);
    let mut updates = BTreeMap::new();
    updates.insert(key_a, Some(value_to_field(&1000u64.to_le_bytes())));
    updates.insert(key_b, Some(value_to_field(&500u64.to_le_bytes())));
    let r = apply_updates(&store, None, 1, updates);
    store.apply(&r);
    println!("v1: Created accounts A=1000, B=500");

    // v2: Transfer 200 from A to B
    let mut updates = BTreeMap::new();
    updates.insert(key_a, Some(value_to_field(&800u64.to_le_bytes())));
    updates.insert(key_b, Some(value_to_field(&700u64.to_le_bytes())));
    let r = apply_updates(&store, Some(1), 2, updates);
    store.apply(&r);
    println!("v2: Transfer 200 from A->B  (A=800, B=700)");

    // v3: Transfer 100 from B to A
    let mut updates = BTreeMap::new();
    updates.insert(key_a, Some(value_to_field(&900u64.to_le_bytes())));
    updates.insert(key_b, Some(value_to_field(&600u64.to_le_bytes())));
    let r = apply_updates(&store, Some(2), 3, updates);
    store.apply(&r);
    println!("v3: Transfer 100 from B->A  (A=900, B=600)");

    // v4: New account C created
    let key_c = make_key(0xCC, 0x01);
    let mut updates = BTreeMap::new();
    updates.insert(key_c, Some(value_to_field(&250u64.to_le_bytes())));
    let r = apply_updates(&store, Some(3), 4, updates);
    store.apply(&r);
    println!("v4: New account C=250");

    // v5: A sends 50 to C, B zeroed out
    let mut updates = BTreeMap::new();
    updates.insert(key_a, Some(value_to_field(&850u64.to_le_bytes())));
    updates.insert(key_b, Some(value_to_field(&0u64.to_le_bytes())));
    updates.insert(key_c, Some(value_to_field(&300u64.to_le_bytes())));
    let r = apply_updates(&store, Some(4), 5, updates);
    store.apply(&r);
    println!("v5: A sends 50 to C, B zeroed  (A=850, B=0, C=300)");

    // ── Time-travel: query any historical version ───────────────
    println!("\n-- Time-travel queries --");

    println!("\nAccount A value across versions:");
    for v in 1..=5 {
        let root_key = store.get_root_key(v).unwrap();
        let val = get_committed_value(&store, &root_key, &key_a);
        println!("  v{v}: {:?}", val);
    }

    println!("\nAccount B value across versions:");
    for v in 1..=5 {
        let root_key = store.get_root_key(v).unwrap();
        let val = get_committed_value(&store, &root_key, &key_b);
        println!("  v{v}: {:?}", val);
    }

    println!("\nAccount C value across versions:");
    for v in 1..=5 {
        let root_key = store.get_root_key(v).unwrap();
        let val = get_committed_value(&store, &root_key, &key_c);
        println!(
            "  v{v}: {}",
            val.map_or("(not yet created)".into(), |b| format!("{:?}", b))
        );
    }

    // ── Root commitments change with every version ──────────────
    println!("\n-- Root commitments per version --");
    for v in 1..=5 {
        let c = root_commitment_at(&store, v);
        println!("  v{v}: {c:?}");
    }

    // ── Verify consistency at every version ─────────────────────
    println!("\n-- Consistency checks --");
    for v in 1..=5 {
        let root_key = store.get_root_key(v).unwrap();
        let ok = verify_commitment_consistency(&store, &root_key);
        println!("  v{v}: consistent = {ok}");
    }

    // ── Pruning old versions ────────────────────────────────────
    println!("\n-- Pruning --");
    println!(
        "Before pruning: {} nodes, {} stale entries, versions: {:?}",
        store.node_count(),
        store.stale_count(),
        store.versions(),
    );

    // Prune versions 1-3 (keep only v4 and v5)
    store.prune(3);
    println!(
        "After prune(3): {} nodes, {} stale entries, versions: {:?}",
        store.node_count(),
        store.stale_count(),
        store.versions(),
    );

    // v4 and v5 are still fully queryable
    let val_a = get_committed_value(&store, &store.get_root_key(5).unwrap(), &key_a);
    let val_c = get_committed_value(&store, &store.get_root_key(5).unwrap(), &key_c);
    println!("\nPost-prune v5 reads: A={:?}, C={:?}", val_a, val_c);
    println!(
        "Post-prune v5 consistent: {}",
        verify_commitment_consistency(&store, &store.latest_root_key().unwrap())
    );
}
