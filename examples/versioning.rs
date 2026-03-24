//! Versioning: time-travel queries, comparing roots across versions, and pruning.
//!
//! JVT stores every version of the tree persistently. Old versions remain
//! queryable until explicitly pruned — this is the "Jellyfish" part of the name.
//!
//! Run: cargo run --example versioning

use std::collections::BTreeMap;

use jellyfish_verkle_tree::{
    apply_updates, get_value, root_commitment_at, verify_commitment_consistency, Key, MemoryStore,
    TreeReader,
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
    updates.insert(key_a, Some(1000u64.to_le_bytes().to_vec()));
    updates.insert(key_b, Some(500u64.to_le_bytes().to_vec()));
    let r = apply_updates(&store, None, 1, updates);
    store.apply(&r);
    println!("v1: Created accounts A=1000, B=500");

    // v2: Transfer 200 from A to B
    let mut updates = BTreeMap::new();
    updates.insert(key_a, Some(800u64.to_le_bytes().to_vec()));
    updates.insert(key_b, Some(700u64.to_le_bytes().to_vec()));
    let r = apply_updates(&store, Some(1), 2, updates);
    store.apply(&r);
    println!("v2: Transfer 200 from A→B  (A=800, B=700)");

    // v3: Transfer 100 from B to A
    let mut updates = BTreeMap::new();
    updates.insert(key_a, Some(900u64.to_le_bytes().to_vec()));
    updates.insert(key_b, Some(600u64.to_le_bytes().to_vec()));
    let r = apply_updates(&store, Some(2), 3, updates);
    store.apply(&r);
    println!("v3: Transfer 100 from B→A  (A=900, B=600)");

    // v4: New account C created
    let key_c = make_key(0xCC, 0x01);
    let mut updates = BTreeMap::new();
    updates.insert(key_c, Some(250u64.to_le_bytes().to_vec()));
    let r = apply_updates(&store, Some(3), 4, updates);
    store.apply(&r);
    println!("v4: New account C=250");

    // v5: A sends 50 to C, B zeroed out
    let mut updates = BTreeMap::new();
    updates.insert(key_a, Some(850u64.to_le_bytes().to_vec()));
    updates.insert(key_b, Some(0u64.to_le_bytes().to_vec())); // zero balance (delete not yet implemented)
    updates.insert(key_c, Some(300u64.to_le_bytes().to_vec()));
    let r = apply_updates(&store, Some(4), 5, updates);
    store.apply(&r);
    println!("v5: A sends 50 to C, B zeroed  (A=850, B=0, C=300)");

    // ── Time-travel: query any historical version ───────────────
    println!("\n── Time-travel queries ──────────────────────────────");

    fn read_balance(store: &MemoryStore, version: u64, key: &Key) -> Option<u64> {
        let root_key = store.get_root_key(version)?;
        get_value(store, &root_key, key).map(|v| {
            let mut buf = [0u8; 8];
            buf[..v.len().min(8)].copy_from_slice(&v[..v.len().min(8)]);
            u64::from_le_bytes(buf)
        })
    }

    println!("\nAccount A balance across versions:");
    for v in 1..=5 {
        let bal = read_balance(&store, v, &key_a);
        println!("  v{v}: {}", bal.map_or("n/a".into(), |b| b.to_string()));
    }

    println!("\nAccount B balance across versions:");
    for v in 1..=5 {
        let bal = read_balance(&store, v, &key_b);
        println!("  v{v}: {}", bal.map_or("n/a".into(), |b| b.to_string()));
    }

    println!("\nAccount C balance across versions:");
    for v in 1..=5 {
        let bal = read_balance(&store, v, &key_c);
        println!(
            "  v{v}: {}",
            bal.map_or("(not yet created)".into(), |b| b.to_string())
        );
    }

    // ── Root commitments change with every version ──────────────
    println!("\n── Root commitments per version ─────────────────────");
    for v in 1..=5 {
        let c = root_commitment_at(&store, v);
        println!("  v{v}: {c:?}");
    }

    // ── Verify consistency at every version ─────────────────────
    println!("\n── Consistency checks ───────────────────────────────");
    for v in 1..=5 {
        let root_key = store.get_root_key(v).unwrap();
        let ok = verify_commitment_consistency(&store, &root_key);
        println!("  v{v}: consistent = {ok}");
    }

    // ── Pruning old versions ────────────────────────────────────
    println!("\n── Pruning ──────────────────────────────────────────");
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
    let bal_a = read_balance(&store, 5, &key_a).unwrap();
    let bal_c = read_balance(&store, 5, &key_c).unwrap();
    println!("\nPost-prune v5 reads: A={bal_a}, C={bal_c}");
    println!(
        "Post-prune v5 consistent: {}",
        verify_commitment_consistency(&store, &store.latest_root_key().unwrap())
    );
}
