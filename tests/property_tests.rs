//! Property-based tests mirroring Quint spec invariants.

use proptest::prelude::*;
use std::collections::{BTreeMap, HashMap};

use jellyfish_verkle_tree::{
    apply_updates, get_value, root_commitment_at, verify_commitment_consistency, zero_commitment,
    Key, MemoryStore, TreeReader, Value,
};

fn arb_key() -> impl Strategy<Value = Key> {
    (0u8..16, 0u8..16, any::<[u8; 28]>(), 0u8..=255).prop_map(|(b0, b1, mid, suffix)| {
        let mut key = vec![0u8; 32];
        key[0] = b0;
        key[1] = b1;
        key[2..30].copy_from_slice(&mid[..28]);
        key[30] = 0;
        key[31] = suffix;
        key
    })
}

fn arb_value() -> impl Strategy<Value = Value> {
    prop::collection::vec(any::<u8>(), 1..32)
}

fn arb_inserts(max_ops: usize) -> impl Strategy<Value = Vec<(Key, Value)>> {
    prop::collection::vec((arb_key(), arb_value()), 1..max_ops)
}

/// Helper: insert a single key into a store.
fn insert(store: &mut MemoryStore, key: &Key, value: Value) {
    let parent = store.latest_version();
    let new_version = parent.map_or(1, |v| v + 1);
    let mut updates = BTreeMap::new();
    updates.insert(key.clone(), Some(value));
    let result = apply_updates(store, parent, new_version, updates);
    store.apply(&result);
}

fn get(store: &MemoryStore, key: &Key) -> Option<Value> {
    let root_key = store.latest_root_key()?;
    get_value(store, &root_key, key)
}

proptest! {
    #[test]
    fn get_after_insert(ops in arb_inserts(100)) {
        let mut store = MemoryStore::new();
        let mut reference: HashMap<Key, Value> = HashMap::new();

        for (key, value) in &ops {
            insert(&mut store, key, value.clone());
            reference.insert(key.clone(), value.clone());
        }

        for (key, expected) in &reference {
            let actual = get(&store, key);
            prop_assert_eq!(actual.as_ref(), Some(expected));
        }
    }

    #[test]
    fn commitment_consistency(ops in arb_inserts(50)) {
        let mut store = MemoryStore::new();
        for (key, value) in &ops {
            insert(&mut store, key, value.clone());
        }
        let root = store.latest_root_key().unwrap();
        prop_assert!(verify_commitment_consistency(&store, &root));
    }

    #[test]
    fn root_commitment_changes(ops in arb_inserts(20)) {
        let mut store = MemoryStore::new();
        let mut prev_commitment = zero_commitment();

        for (key, value) in &ops {
            let parent = store.latest_version();
            let new_version = parent.map_or(1, |v| v + 1);
            let mut updates = BTreeMap::new();
            updates.insert(key.clone(), Some(value.clone()));
            let result = apply_updates(&store, parent, new_version, updates);
            store.apply(&result);

            prop_assert_ne!(result.root_commitment, prev_commitment);
            prev_commitment = result.root_commitment;
        }
    }

    #[test]
    fn version_monotonicity(ops in arb_inserts(50)) {
        let mut store = MemoryStore::new();
        for (i, (key, value)) in ops.iter().enumerate() {
            insert(&mut store, key, value.clone());
            prop_assert_eq!(store.latest_version(), Some((i + 1) as u64));
        }
    }

    #[test]
    fn versioned_reads_preserve_history(ops in arb_inserts(30)) {
        let mut store = MemoryStore::new();
        let mut version_snapshots: Vec<(u64, Key, Value)> = Vec::new();

        for (key, value) in &ops {
            insert(&mut store, key, value.clone());
            let v = store.latest_version().unwrap();
            version_snapshots.push((v, key.clone(), value.clone()));
        }

        for (version, key, expected_value) in &version_snapshots {
            let root_key = store.get_root_key(*version).unwrap();
            let actual = get_value(&store, &root_key, key);
            prop_assert_eq!(actual.as_ref(), Some(expected_value));
        }
    }

    #[test]
    fn nonexistent_keys_return_none(
        ops in arb_inserts(20),
        extra_keys in prop::collection::vec(arb_key(), 5..10)
    ) {
        let mut store = MemoryStore::new();
        let mut inserted: HashMap<Key, Value> = HashMap::new();

        for (key, value) in &ops {
            insert(&mut store, key, value.clone());
            inserted.insert(key.clone(), value.clone());
        }

        for key in &extra_keys {
            if !inserted.contains_key(key) {
                prop_assert_eq!(get(&store, key), None);
            }
        }
    }

    #[test]
    fn commitment_determinism(ops in arb_inserts(30)) {
        let mut store1 = MemoryStore::new();
        let mut store2 = MemoryStore::new();

        for (key, value) in &ops {
            insert(&mut store1, key, value.clone());
            insert(&mut store2, key, value.clone());
        }

        let v = store1.latest_version().unwrap();
        prop_assert_eq!(root_commitment_at(&store1, v), root_commitment_at(&store2, v));
    }

    #[test]
    fn update_overwrites(key in arb_key(), val1 in arb_value(), val2 in arb_value()) {
        let mut store = MemoryStore::new();
        insert(&mut store, &key, val1);
        insert(&mut store, &key, val2.clone());
        prop_assert_eq!(get(&store, &key), Some(val2));
    }

    #[test]
    fn proof_generation_succeeds(ops in arb_inserts(20)) {
        let mut store = MemoryStore::new();
        let mut inserted: HashMap<Key, Value> = HashMap::new();

        for (key, value) in &ops {
            insert(&mut store, key, value.clone());
            inserted.insert(key.clone(), value.clone());
        }

        let root_key = store.latest_root_key().unwrap();
        for (key, _value) in &inserted {
            let proof = jellyfish_verkle_tree::proof::prove(&store, &root_key, key);
            prop_assert!(proof.is_some());
            prop_assert!(proof.unwrap().inclusion);
        }
    }
}
