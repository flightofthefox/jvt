//! Verkle proofs: generate and verify inclusion/non-inclusion proofs.
//!
//! Demonstrates single-key proofs, batch proofs with constant 576-byte size,
//! and non-inclusion proofs for missing keys.
//!
//! Run: cargo run --example verkle_proofs

use std::collections::BTreeMap;

use jellyfish_verkle_tree::{apply_updates, get_value, verkle_proof, Key, MemoryStore};

fn make_key(prefix: &[u8]) -> Key {
    let mut key = vec![0u8; 32];
    for (i, &b) in prefix.iter().enumerate().take(32) {
        key[i] = b;
    }
    key
}

fn main() {
    let mut store = MemoryStore::new();

    // Populate the tree with varied data
    let entries: Vec<(Key, Vec<u8>)> = vec![
        (make_key(&[0x00, 0x11]), b"first".to_vec()),
        (make_key(&[0x00, 0x22]), b"second".to_vec()),
        (make_key(&[0x11, 0x00]), b"third".to_vec()),
        (make_key(&[0x22, 0x33, 0x44]), b"fourth".to_vec()),
        (make_key(&[0xFF, 0xEE, 0xDD]), b"fifth".to_vec()),
    ];

    let updates: BTreeMap<Key, Option<Vec<u8>>> = entries
        .iter()
        .map(|(k, v)| (k.clone(), Some(v.clone())))
        .collect();

    let result = apply_updates(&store, None, 1, updates);
    let root_commitment = result.root_commitment;
    store.apply(&result);

    let root_key = store.latest_root_key().unwrap();

    // ── 1. Single-key inclusion proof ───────────────────────────
    println!("1. Single-key inclusion proof");

    let key = entries[0].0.clone();
    let proof = verkle_proof::prove_single(&store, &root_key, &key).unwrap();
    let value = get_value(&store, &root_key, &key);

    println!("   Key:   0x{}", hex(&key[..3]));
    println!(
        "   Value: {:?}",
        value.as_ref().map(|v| String::from_utf8_lossy(v))
    );
    println!(
        "   Proof size: {} bytes (core) / {} bytes (total)",
        proof.proof_byte_size(),
        proof.total_byte_size()
    );

    let valid = verkle_proof::verify_single(&proof, root_commitment, &key, value.as_ref());
    println!("   Valid: {valid}");

    // ── 2. Single-key non-inclusion proof ───────────────────────
    println!("\n2. Single-key non-inclusion proof (key never inserted)");

    let missing_key = make_key(&[0xDE, 0xAD, 0xBE, 0xEF]);
    let proof = verkle_proof::prove_single(&store, &root_key, &missing_key).unwrap();

    println!("   Key:   0x{}", hex(&missing_key[..4]));
    println!("   Value: None (absent)");
    println!("   Proof size: {} bytes (core)", proof.proof_byte_size());

    let valid = verkle_proof::verify_single(&proof, root_commitment, &missing_key, None);
    println!("   Valid: {valid}");

    // Tamper check: claiming a value exists when it doesn't should fail
    let tampered = verkle_proof::verify_single(
        &proof,
        root_commitment,
        &missing_key,
        Some(&b"fake".to_vec()),
    );
    println!("   Tampered (claim value exists): {tampered}");

    // ── 3. Batch proof — constant size! ─────────────────────────
    println!("\n3. Batch proofs — constant 576-byte core regardless of count");

    for count in [2, 3, 5] {
        let keys: Vec<Key> = entries.iter().take(count).map(|(k, _)| k.clone()).collect();
        let values: Vec<Option<Vec<u8>>> = keys
            .iter()
            .map(|k| get_value(&store, &root_key, k))
            .collect();

        let proof = verkle_proof::prove(&store, &root_key, &keys).unwrap();
        let valid = verkle_proof::verify(&proof, root_commitment, &keys, &values);

        println!(
            "   {count} keys: proof = {} bytes (core) / {} bytes (total), valid = {valid}",
            proof.proof_byte_size(),
            proof.total_byte_size()
        );
    }

    // ── 4. Mixed batch: inclusion + non-inclusion ───────────────
    println!("\n4. Mixed batch: some keys present, some absent");

    let present_key = entries[2].0.clone();
    let absent_key = make_key(&[0x99, 0x99]);
    let keys = vec![present_key.clone(), absent_key.clone()];
    let values: Vec<Option<Vec<u8>>> = keys
        .iter()
        .map(|k| get_value(&store, &root_key, k))
        .collect();

    println!(
        "   Key 0x{}: {:?}",
        hex(&present_key[..2]),
        values[0]
            .as_ref()
            .map(|v| String::from_utf8_lossy(v).into_owned())
    );
    println!("   Key 0x{}: {:?}", hex(&absent_key[..2]), values[1]);

    let proof = verkle_proof::prove(&store, &root_key, &keys).unwrap();
    let valid = verkle_proof::verify(&proof, root_commitment, &keys, &values);
    println!(
        "   Proof size: {} bytes (core), valid: {valid}",
        proof.proof_byte_size()
    );

    // ── 5. Proof against wrong root fails ───────────────────────
    println!("\n5. Proof against wrong root commitment");

    // Create a different tree state
    let mut updates = BTreeMap::new();
    updates.insert(make_key(&[0xFF]), Some(b"extra".to_vec()));
    let result2 = apply_updates(&store, Some(1), 2, updates);
    let wrong_root = result2.root_commitment;

    let key = entries[0].0.clone();
    let proof = verkle_proof::prove_single(&store, &root_key, &key).unwrap();
    let value = get_value(&store, &root_key, &key);

    let valid_right = verkle_proof::verify_single(&proof, root_commitment, &key, value.as_ref());
    let valid_wrong = verkle_proof::verify_single(&proof, wrong_root, &key, value.as_ref());
    println!("   Against correct root: {valid_right}");
    println!("   Against wrong root:   {valid_wrong}");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
