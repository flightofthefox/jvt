//! Security and adversarial tests for the JVT proof system.
//!
//! These tests verify that the proof system rejects tampered, forged, or
//! mismatched proofs — not just that honest prove→verify roundtrips work.

use std::collections::BTreeMap;

use jellyfish_verkle_tree::verkle_proof;
use jellyfish_verkle_tree::{
    apply_updates, get_value, root_commitment_at, verify_commitment_consistency, Commitment, Key,
    MemoryStore, NodeKey, Value,
};

fn make_key(first: u8, second: u8, suffix: u8) -> Key {
    let mut key = vec![0u8; 32];
    key[0] = first;
    key[1] = second;
    key[31] = suffix;
    key
}

fn insert(store: &mut MemoryStore, key: &Key, value: Value) {
    let parent = store.latest_version();
    let new_version = parent.map_or(1, |v| v + 1);
    let mut updates = BTreeMap::new();
    updates.insert(key.clone(), Some(value));
    let result = apply_updates(store, parent, new_version, updates);
    store.apply(&result);
}

fn root_c(store: &MemoryStore) -> Commitment {
    root_commitment_at(store, store.latest_version().unwrap())
}

/// Build a store with N keys for testing.
fn build_store(n: u8) -> MemoryStore {
    let mut store = MemoryStore::new();
    for i in 0..n {
        insert(
            &mut store,
            &make_key(i, i.wrapping_mul(7), i.wrapping_mul(13)),
            vec![i],
        );
    }
    store
}

// ============================================================
// Adversarial: tampered proofs
// ============================================================

#[test]
fn reject_wrong_value_single_key() {
    let store = build_store(5);
    let rk = store.latest_root_key().unwrap();
    let key = make_key(0, 0, 0);
    let proof = verkle_proof::prove_single(&store, &rk, &key).unwrap();

    // Correct value verifies
    assert!(verkle_proof::verify_single(
        &proof,
        root_c(&store),
        &key,
        Some(&vec![0])
    ));

    // Wrong value rejected
    assert!(!verkle_proof::verify_single(
        &proof,
        root_c(&store),
        &key,
        Some(&vec![99])
    ));

    // None when value exists rejected
    assert!(!verkle_proof::verify_single(
        &proof,
        root_c(&store),
        &key,
        None
    ));
}

#[test]
fn reject_proof_against_wrong_root() {
    let mut store = build_store(5);
    let rk = store.latest_root_key().unwrap();
    let key = make_key(0, 0, 0);
    let proof = verkle_proof::prove_single(&store, &rk, &key).unwrap();

    // Insert more keys to change the root
    insert(&mut store, &make_key(50, 0, 0), vec![50]);
    let new_root = root_c(&store);

    // Proof against old root should fail against new root
    assert!(!verkle_proof::verify_single(
        &proof,
        new_root,
        &key,
        Some(&vec![0])
    ));
}

#[test]
fn reject_proof_for_wrong_key() {
    let store = build_store(5);
    let rk = store.latest_root_key().unwrap();
    let key_a = make_key(0, 0, 0);
    let key_b = make_key(1, 7, 13);

    let proof_a = verkle_proof::prove_single(&store, &rk, &key_a).unwrap();

    // Proof for key_a should not verify for key_b
    assert!(!verkle_proof::verify_single(
        &proof_a,
        root_c(&store),
        &key_b,
        Some(&vec![1])
    ));
}

#[test]
fn reject_batch_with_one_wrong_value() {
    let store = build_store(5);
    let rk = store.latest_root_key().unwrap();
    let keys: Vec<Key> = (0..5u8)
        .map(|i| make_key(i, i.wrapping_mul(7), i.wrapping_mul(13)))
        .collect();

    let proof = verkle_proof::prove(&store, &rk, &keys).unwrap();

    // All correct
    let correct: Vec<Option<Value>> = (0..5u8).map(|i| Some(vec![i])).collect();
    assert!(verkle_proof::verify(
        &proof,
        root_c(&store),
        &keys,
        &correct
    ));

    // One wrong value
    let mut wrong = correct.clone();
    wrong[2] = Some(vec![99]);
    assert!(!verkle_proof::verify(&proof, root_c(&store), &keys, &wrong));
}

#[test]
fn reject_batch_with_extra_key() {
    let store = build_store(5);
    let rk = store.latest_root_key().unwrap();
    let keys: Vec<Key> = (0..3u8)
        .map(|i| make_key(i, i.wrapping_mul(7), i.wrapping_mul(13)))
        .collect();

    let proof = verkle_proof::prove(&store, &rk, &keys).unwrap();

    // Verify with extra key should fail (length mismatch)
    let mut more_keys = keys.clone();
    more_keys.push(make_key(99, 0, 0));
    let values: Vec<Option<Value>> = (0..4u8).map(|i| Some(vec![i])).collect();
    assert!(!verkle_proof::verify(
        &proof,
        root_c(&store),
        &more_keys,
        &values
    ));
}

#[test]
fn reject_inclusion_for_absent_key() {
    let store = build_store(5);
    let rk = store.latest_root_key().unwrap();
    let absent_key = make_key(99, 99, 99);

    let proof = verkle_proof::prove_single(&store, &rk, &absent_key).unwrap();

    // Claiming a value exists when it doesn't should fail
    assert!(!verkle_proof::verify_single(
        &proof,
        root_c(&store),
        &absent_key,
        Some(&vec![42])
    ));

    // Correctly claiming None should pass
    assert!(verkle_proof::verify_single(
        &proof,
        root_c(&store),
        &absent_key,
        None
    ));
}

// ============================================================
// Edge cases
// ============================================================

#[test]
fn single_key_tree() {
    let mut store = MemoryStore::new();
    insert(&mut store, &make_key(42, 0, 0), vec![100]);

    let rk = store.latest_root_key().unwrap();
    let proof = verkle_proof::prove_single(&store, &rk, &make_key(42, 0, 0)).unwrap();

    // Root is an EaS — no internal nodes, but EaS openings exist
    // (marker byte, extension → c1/c2, c1/c2 → value)
    assert_eq!(proof.verifier_queries.len(), 3);
    assert!(verkle_proof::verify_single(
        &proof,
        root_c(&store),
        &make_key(42, 0, 0),
        Some(&vec![100])
    ));
}

#[test]
fn zero_value() {
    let mut store = MemoryStore::new();
    insert(&mut store, &make_key(1, 0, 0), vec![0]); // value is zero byte
    insert(&mut store, &make_key(2, 0, 0), vec![]); // value is empty vec

    let rk = store.latest_root_key().unwrap();

    let p1 = verkle_proof::prove_single(&store, &rk, &make_key(1, 0, 0)).unwrap();
    assert!(verkle_proof::verify_single(
        &p1,
        root_c(&store),
        &make_key(1, 0, 0),
        Some(&vec![0])
    ));

    let p2 = verkle_proof::prove_single(&store, &rk, &make_key(2, 0, 0)).unwrap();
    assert!(verkle_proof::verify_single(
        &p2,
        root_c(&store),
        &make_key(2, 0, 0),
        Some(&vec![])
    ));
}

#[test]
fn same_stem_different_suffixes() {
    // Many keys sharing the same stem (bytes 0..30) but different suffix (byte 31)
    let mut store = MemoryStore::new();
    for suffix in 0..10u8 {
        let mut key = vec![0u8; 32];
        key[0] = 1;
        key[31] = suffix;
        insert(&mut store, &key, vec![suffix]);
    }

    let rk = store.latest_root_key().unwrap();

    // All values stored in the same EaS node
    for suffix in 0..10u8 {
        let mut key = vec![0u8; 32];
        key[0] = 1;
        key[31] = suffix;
        assert_eq!(get_value(&store, &rk, &key), Some(vec![suffix]));
    }

    // Batch proof for all of them
    let keys: Vec<Key> = (0..10u8)
        .map(|s| {
            let mut k = vec![0u8; 32];
            k[0] = 1;
            k[31] = s;
            k
        })
        .collect();

    let proof = verkle_proof::prove(&store, &rk, &keys).unwrap();
    let expected: Vec<Option<Value>> = (0..10u8).map(|s| Some(vec![s])).collect();
    assert!(verkle_proof::verify(
        &proof,
        root_c(&store),
        &keys,
        &expected
    ));
}

#[test]
fn large_batch() {
    let store = build_store(50);
    let rk = store.latest_root_key().unwrap();

    let keys: Vec<Key> = (0..50u8)
        .map(|i| make_key(i, i.wrapping_mul(7), i.wrapping_mul(13)))
        .collect();

    let proof = verkle_proof::prove(&store, &rk, &keys).unwrap();
    assert_eq!(proof.proof_byte_size(), 576); // still constant

    let expected: Vec<Option<Value>> = (0..50u8).map(|i| Some(vec![i])).collect();
    assert!(verkle_proof::verify(
        &proof,
        root_c(&store),
        &keys,
        &expected
    ));
}

#[test]
fn commitment_consistency_after_many_operations() {
    let mut store = MemoryStore::new();

    // Insert, update, insert more
    for i in 0u8..30 {
        insert(&mut store, &make_key(i, 0, 0), vec![i]);
    }
    // Update some existing keys
    for i in 0u8..10 {
        insert(&mut store, &make_key(i, 0, 0), vec![i + 100]);
    }
    // Insert keys that cause splits at various depths
    for i in 0u8..10 {
        insert(&mut store, &make_key(0, i, 0), vec![i + 200]);
    }

    let rk = store.latest_root_key().unwrap();
    assert!(verify_commitment_consistency(&store, &rk));

    // Verify updated values
    assert_eq!(get_value(&store, &rk, &make_key(5, 0, 0)), Some(vec![105]));
    assert_eq!(get_value(&store, &rk, &make_key(15, 0, 0)), Some(vec![15]));
    assert_eq!(get_value(&store, &rk, &make_key(0, 5, 0)), Some(vec![205]));
}

#[test]
fn empty_tree_proof() {
    let store = MemoryStore::new();
    // No root key exists — prove should return None
    let fake_root = NodeKey::root(1);
    assert!(verkle_proof::prove_single(&store, &fake_root, &make_key(0, 0, 0)).is_none());
}

#[test]
fn versioned_proofs_independent() {
    let mut store = MemoryStore::new();
    // Need multiple keys so we have internal nodes (multiproof openings)
    insert(&mut store, &make_key(1, 0, 0), vec![10]);
    insert(&mut store, &make_key(2, 0, 0), vec![20]);
    let v2_root = store.latest_root_key().unwrap().clone();
    let v2_commitment = root_c(&store);

    // Update key 1 — changes the root commitment
    insert(&mut store, &make_key(1, 0, 0), vec![99]);
    let _v3_root = store.latest_root_key().unwrap().clone();
    let v3_commitment = root_c(&store);
    assert_ne!(v2_commitment, v3_commitment);

    // Proof at v2 (key 1 = [10])
    let proof_v2 = verkle_proof::prove_single(&store, &v2_root, &make_key(1, 0, 0)).unwrap();
    assert!(verkle_proof::verify_single(
        &proof_v2,
        v2_commitment,
        &make_key(1, 0, 0),
        Some(&vec![10])
    ));

    // v2 proof should NOT verify against v3 root
    assert!(!verkle_proof::verify_single(
        &proof_v2,
        v3_commitment,
        &make_key(1, 0, 0),
        Some(&vec![10])
    ));
}
