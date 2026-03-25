//! Basic usage: inserting, retrieving, and deleting key-value pairs.
//!
//! Run: cargo run --example basics

use std::collections::BTreeMap;

use jellyfish_verkle_tree::{
    apply_updates, get_committed_value, value_to_field, verify_commitment_consistency, Key,
    MemoryStore,
};

fn make_key(bytes: &[u8]) -> Key {
    let mut key = [0u8; 32];
    for (i, &b) in bytes.iter().enumerate().take(32) {
        key[i] = b;
    }
    key
}

fn main() {
    let mut store = MemoryStore::new();

    // ── 1. Single insert ────────────────────────────────────────
    println!("1. Single insert");

    let key_alice = make_key(b"alice");
    let mut updates = BTreeMap::new();
    updates.insert(key_alice, Some(value_to_field(b"alice's balance: 100")));

    let result = apply_updates(&store, None, 1, updates);
    println!("   Root commitment after v1: {:?}", result.root_commitment);
    store.apply(&result);

    let val = get_committed_value(&store, &store.latest_root_key().unwrap(), &key_alice);
    println!("   get(alice) = {:?}", val);

    // ── 2. Batch insert ─────────────────────────────────────────
    println!("\n2. Batch insert (multiple keys in one version)");

    let key_bob = make_key(b"bob");
    let key_charlie = make_key(b"charlie");
    let key_dave = make_key(b"dave");

    let mut updates = BTreeMap::new();
    updates.insert(key_bob, Some(value_to_field(b"bob's balance: 200")));
    updates.insert(key_charlie, Some(value_to_field(b"charlie's balance: 50")));
    updates.insert(key_dave, Some(value_to_field(b"dave's balance: 0")));

    let result = apply_updates(&store, Some(1), 2, updates);
    store.apply(&result);

    for (name, key) in [
        ("bob", key_bob),
        ("charlie", key_charlie),
        ("dave", key_dave),
    ] {
        let val = get_committed_value(&store, &store.latest_root_key().unwrap(), &key).unwrap();
        println!("   get({name}) = {:?}", val);
    }

    // ── 3. Update an existing key ───────────────────────────────
    println!("\n3. Update existing key");

    let mut updates = BTreeMap::new();
    updates.insert(key_alice, Some(value_to_field(b"alice's balance: 75")));

    let result = apply_updates(&store, Some(2), 3, updates);
    store.apply(&result);

    let val = get_committed_value(&store, &store.latest_root_key().unwrap(), &key_alice).unwrap();
    println!("   get(alice) = {:?} (updated)", val);

    // ── 4. Delete a key ──────────────────────────────────────────
    println!("\n4. Delete a key");

    let mut updates = BTreeMap::new();
    updates.insert(key_dave, None); // None = delete

    let result = apply_updates(&store, Some(3), 4, updates);
    store.apply(&result);

    let val = get_committed_value(&store, &store.latest_root_key().unwrap(), &key_dave);
    println!("   get(dave) = {:?} (expected None)", val);

    // ── 5. Non-existent key ─────────────────────────────────────
    println!("\n5. Non-existent key");

    let key_eve = make_key(b"eve");
    let val = get_committed_value(&store, &store.latest_root_key().unwrap(), &key_eve);
    println!("   get(eve) = {:?} (never inserted)", val);

    // ── 6. Verify tree integrity ────────────────────────────────
    println!("\n6. Commitment consistency check");

    let ok = verify_commitment_consistency(&store, &store.latest_root_key().unwrap());
    println!("   All commitments consistent: {ok}");

    // ── Summary ─────────────────────────────────────────────────
    println!(
        "\nStore stats: {} nodes across {} versions",
        store.node_count(),
        store.versions().len(),
    );
}
