//! Property-based tests mirroring Quint spec invariants.

use proptest::prelude::*;
use std::collections::HashMap;

use jellyfish_verkle_tree::{Key, MemoryStore, Value, JVT};

/// Generate a random 32-byte key with controlled distribution.
/// We use small values for the first few bytes to force tree splits,
/// and random values for the rest.
fn arb_key() -> impl Strategy<Value = Key> {
    (
        0u8..16,           // first byte: small range to force collisions
        0u8..16,           // second byte
        any::<[u8; 28]>(), // remaining bytes
        0u8..=255,         // suffix byte
    )
        .prop_map(|(b0, b1, mid, suffix)| {
            let mut key = [0u8; 32];
            key[0] = b0;
            key[1] = b1;
            key[2..30].copy_from_slice(&mid[..28]);
            key[30] = 0; // keep byte 30 fixed for stem consistency
            key[31] = suffix;
            key
        })
}

/// Generate a random value (small for tractability).
fn arb_value() -> impl Strategy<Value = Value> {
    prop::collection::vec(any::<u8>(), 1..32)
}

/// Generate a list of insert operations.
fn arb_inserts(max_ops: usize) -> impl Strategy<Value = Vec<(Key, Value)>> {
    prop::collection::vec((arb_key(), arb_value()), 1..max_ops)
}

proptest! {
    /// PROPERTY: Get-after-insert.
    /// For all keys inserted, get returns the most recently inserted value.
    #[test]
    fn get_after_insert(ops in arb_inserts(100)) {
        let mut tree = JVT::new(MemoryStore::new());
        let mut reference: HashMap<Key, Value> = HashMap::new();

        for (key, value) in &ops {
            tree.insert(*key, value.clone());
            reference.insert(*key, value.clone());
        }

        for (key, expected) in &reference {
            let actual = tree.get(key);
            prop_assert_eq!(actual.as_ref(), Some(expected),
                "Key {:?} expected {:?} but got {:?}", key, expected, actual);
        }
    }

    /// PROPERTY: Commitment consistency.
    /// All stored commitments match recomputation from their children/values.
    #[test]
    fn commitment_consistency(ops in arb_inserts(50)) {
        let mut tree = JVT::new(MemoryStore::new());
        for (key, value) in &ops {
            tree.insert(*key, value.clone());
        }
        prop_assert!(tree.verify_commitment_consistency(),
            "Commitment consistency check failed after {} inserts", ops.len());
    }

    /// PROPERTY: Root commitment changes on every new distinct key.
    #[test]
    fn root_commitment_changes(ops in arb_inserts(20)) {
        let mut tree = JVT::new(MemoryStore::new());
        let mut prev_commitment = tree.root_commitment();

        for (key, value) in &ops {
            let new_commitment = tree.insert(*key, value.clone());
            // The root commitment should change (unless the exact same key-value
            // is re-inserted, which is astronomically unlikely with random values)
            prop_assert_ne!(new_commitment, prev_commitment,
                "Root commitment didn't change after inserting key {:?}", key);
            prev_commitment = new_commitment;
        }
    }

    /// PROPERTY: Version monotonicity.
    /// The current version equals the number of insert operations.
    #[test]
    fn version_monotonicity(ops in arb_inserts(50)) {
        let mut tree = JVT::new(MemoryStore::new());
        for (i, (key, value)) in ops.iter().enumerate() {
            tree.insert(*key, value.clone());
            prop_assert_eq!(tree.current_version(), (i + 1) as u64);
        }
    }

    /// PROPERTY: Versioned reads preserve history.
    /// A value inserted at version V is readable at version V even after
    /// subsequent inserts (as long as the key isn't overwritten).
    #[test]
    fn versioned_reads_preserve_history(ops in arb_inserts(30)) {
        let mut tree = JVT::new(MemoryStore::new());
        let mut version_snapshots: Vec<(u64, Key, Value)> = Vec::new();

        for (key, value) in &ops {
            tree.insert(*key, value.clone());
            version_snapshots.push((tree.current_version(), *key, value.clone()));
        }

        // Each key should be readable at the version it was inserted
        for (version, key, expected_value) in &version_snapshots {
            let actual = tree.get_at(key, *version);
            prop_assert_eq!(actual.as_ref(), Some(expected_value),
                "Key {:?} at version {} expected {:?} but got {:?}",
                key, version, expected_value, actual);
        }
    }

    /// PROPERTY: Non-existent keys return None.
    #[test]
    fn nonexistent_keys_return_none(
        ops in arb_inserts(20),
        extra_keys in prop::collection::vec(arb_key(), 5..10)
    ) {
        let mut tree = JVT::new(MemoryStore::new());
        let mut inserted: HashMap<Key, Value> = HashMap::new();

        for (key, value) in &ops {
            tree.insert(*key, value.clone());
            inserted.insert(*key, value.clone());
        }

        for key in &extra_keys {
            if !inserted.contains_key(key) {
                prop_assert_eq!(tree.get(key), None,
                    "Non-existent key {:?} returned a value", key);
            }
        }
    }

    /// PROPERTY: Commitment determinism.
    /// Inserting the same sequence of key-value pairs produces the same root commitment.
    #[test]
    fn commitment_determinism(ops in arb_inserts(30)) {
        let mut tree1 = JVT::new(MemoryStore::new());
        let mut tree2 = JVT::new(MemoryStore::new());

        for (key, value) in &ops {
            tree1.insert(*key, value.clone());
            tree2.insert(*key, value.clone());
        }

        prop_assert_eq!(tree1.root_commitment(), tree2.root_commitment(),
            "Two trees with identical insert sequences have different root commitments");
    }

    /// PROPERTY: Update overwrites previous value.
    #[test]
    fn update_overwrites(
        key in arb_key(),
        val1 in arb_value(),
        val2 in arb_value()
    ) {
        let mut tree = JVT::new(MemoryStore::new());
        tree.insert(key, val1);
        tree.insert(key, val2.clone());
        prop_assert_eq!(tree.get(&key), Some(val2));
    }

    /// PROPERTY: Proof generation succeeds for all inserted keys.
    #[test]
    fn proof_generation_succeeds(ops in arb_inserts(20)) {
        use jellyfish_verkle_tree::node::NodeKey;

        let mut tree = JVT::new(MemoryStore::new());
        let mut inserted: HashMap<Key, Value> = HashMap::new();

        for (key, value) in &ops {
            tree.insert(*key, value.clone());
            inserted.insert(*key, value.clone());
        }

        let root_key = NodeKey::root(tree.current_version());
        for (key, _value) in &inserted {
            let proof = jellyfish_verkle_tree::proof::prove(&tree.store, &root_key, key);
            prop_assert!(proof.is_some(),
                "Proof generation failed for key {:?}", key);
            let proof = proof.unwrap();
            prop_assert!(proof.inclusion,
                "Proof for inserted key {:?} is non-inclusion", key);
        }
    }
}
