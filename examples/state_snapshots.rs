//! State snapshots: using versioned trees for blockchain-style state management.
//!
//! Simulates a sequence of blocks, each producing a new tree version.
//! Shows how to compare state across blocks and audit changes.
//!
//! Run: cargo run --example state_snapshots

use std::collections::BTreeMap;

use jellyfish_verkle_tree::{
    apply_updates, get_value, root_commitment_at, verify_commitment_consistency, verkle_proof, Key,
    MemoryStore, TreeReader,
};

/// Encode an address + storage slot into a 32-byte key.
fn account_key(address: u8, slot: u8) -> Key {
    let mut key = [0u8; 32];
    key[0] = address;
    key[31] = slot;
    key
}

fn encode_u64(v: u64) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}

fn decode_u64(v: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    buf[..v.len().min(8)].copy_from_slice(&v[..v.len().min(8)]);
    u64::from_le_bytes(buf)
}

fn main() {
    let mut store = MemoryStore::new();

    // Addresses
    const ALICE: u8 = 0x0A;
    const BOB: u8 = 0x0B;
    const CONTRACT: u8 = 0xC0;

    // Storage slots
    const BALANCE: u8 = 0x00;
    const NONCE: u8 = 0x01;
    const TOTAL_SUPPLY: u8 = 0x10;

    // ── Block 1: Genesis ────────────────────────────────────────
    println!("Block 1 (genesis):");
    let mut updates = BTreeMap::new();
    updates.insert(account_key(ALICE, BALANCE), Some(encode_u64(10_000)));
    updates.insert(account_key(ALICE, NONCE), Some(encode_u64(0)));
    updates.insert(account_key(BOB, BALANCE), Some(encode_u64(5_000)));
    updates.insert(account_key(BOB, NONCE), Some(encode_u64(0)));
    updates.insert(
        account_key(CONTRACT, TOTAL_SUPPLY),
        Some(encode_u64(15_000)),
    );

    let r = apply_updates(&store, None, 1, updates);
    store.apply(&r);
    println!("  Alice: bal=10000, nonce=0");
    println!("  Bob:   bal=5000,  nonce=0");
    println!("  Contract total_supply=15000");
    println!("  State root: {:?}", r.root_commitment);

    // ── Block 2: Alice → Bob transfer ───────────────────────────
    println!("\nBlock 2 (transfer Alice→Bob 1500):");
    let mut updates = BTreeMap::new();
    updates.insert(account_key(ALICE, BALANCE), Some(encode_u64(8_500)));
    updates.insert(account_key(ALICE, NONCE), Some(encode_u64(1)));
    updates.insert(account_key(BOB, BALANCE), Some(encode_u64(6_500)));

    let r = apply_updates(&store, Some(1), 2, updates);
    store.apply(&r);
    println!("  Alice: bal=8500, nonce=1");
    println!("  Bob:   bal=6500");
    println!("  State root: {:?}", r.root_commitment);

    // ── Block 3: Bob → Alice transfer + new minting ─────────────
    println!("\nBlock 3 (Bob→Alice 500, mint 1000 to Bob):");
    let mut updates = BTreeMap::new();
    updates.insert(account_key(ALICE, BALANCE), Some(encode_u64(9_000)));
    updates.insert(account_key(BOB, BALANCE), Some(encode_u64(7_000)));
    updates.insert(account_key(BOB, NONCE), Some(encode_u64(1)));
    updates.insert(
        account_key(CONTRACT, TOTAL_SUPPLY),
        Some(encode_u64(16_000)),
    );

    let r = apply_updates(&store, Some(2), 3, updates);
    store.apply(&r);
    println!("  Alice: bal=9000");
    println!("  Bob:   bal=7000, nonce=1");
    println!("  Contract total_supply=16000");
    println!("  State root: {:?}", r.root_commitment);

    // ── Block 4: Account closure (sweep to Alice, zero Bob) ────
    println!("\nBlock 4 (close Bob's account, sweep to Alice):");
    let mut updates = BTreeMap::new();
    updates.insert(account_key(ALICE, BALANCE), Some(encode_u64(16_000)));
    updates.insert(account_key(BOB, BALANCE), Some(encode_u64(0)));
    updates.insert(account_key(BOB, NONCE), Some(encode_u64(0)));

    let r = apply_updates(&store, Some(3), 4, updates);
    store.apply(&r);
    println!("  Alice: bal=16000");
    println!("  Bob:   bal=0, nonce=0 (closed)");
    println!("  State root: {:?}", r.root_commitment);

    // ── Auditing: compare state across blocks ───────────────────
    println!("\n── Audit trail ─────────────────────────────────────");
    println!("\nAlice's balance over time:");
    for block in 1..=4 {
        let root_key = store.get_root_key(block).unwrap();
        let bal = get_value(&store, root_key, &account_key(ALICE, BALANCE))
            .map(|v| decode_u64(&v))
            .unwrap();
        println!("  Block {block}: {bal}");
    }

    println!("\nBob's balance over time:");
    for block in 1..=4 {
        let root_key = store.get_root_key(block).unwrap();
        let bal = get_value(&store, root_key, &account_key(BOB, BALANCE))
            .map(|v| decode_u64(&v))
            .unwrap();
        println!("  Block {block}: {bal}");
    }

    println!("\nTotal supply over time:");
    for block in 1..=4 {
        let root_key = store.get_root_key(block).unwrap();
        let supply = get_value(&store, root_key, &account_key(CONTRACT, TOTAL_SUPPLY))
            .map(|v| decode_u64(&v))
            .unwrap();
        println!("  Block {block}: {supply}");
    }

    // ── State proof for a light client ──────────────────────────
    println!("\n── Light client state proof ─────────────────────────");
    println!("A light client wants to verify Alice's balance at block 4.\n");

    let root_key = store.get_root_key(4).unwrap();
    let block4_root = root_commitment_at(&store, 4);
    let key = account_key(ALICE, BALANCE);
    let value = get_value(&store, root_key, &key);

    let proof = verkle_proof::prove_single(&store, root_key, &key).unwrap();
    println!("  Claimed value: {}", decode_u64(value.as_ref().unwrap()));
    println!("  Proof size: {} bytes", proof.proof_byte_size());

    let valid = verkle_proof::verify_single(&proof, block4_root, &key, value.as_ref());
    println!("  Verification: {valid}");

    // Batch proof: verify Alice + contract state in one shot
    println!("\nBatch proof: Alice balance + total supply (2 keys, 1 proof):");
    let keys = vec![
        account_key(ALICE, BALANCE),
        account_key(CONTRACT, TOTAL_SUPPLY),
    ];
    let values: Vec<Option<Vec<u8>>> = keys
        .iter()
        .map(|k| get_value(&store, root_key, k))
        .collect();
    let proof = verkle_proof::prove(&store, root_key, &keys).unwrap();
    let valid = verkle_proof::verify(&proof, block4_root, &keys, &values);
    println!(
        "  Proof size: {} bytes (same constant!)",
        proof.proof_byte_size()
    );
    println!("  Verification: {valid}");

    // ── Pruning for production use ──────────────────────────────
    println!("\n── Pruning old blocks ──────────────────────────────");
    println!(
        "Before: {} nodes, {} stale, versions {:?}",
        store.node_count(),
        store.stale_count(),
        store.versions()
    );

    store.prune(2); // drop blocks 1-2
    println!(
        "After prune(2): {} nodes, {} stale, versions {:?}",
        store.node_count(),
        store.stale_count(),
        store.versions()
    );

    // Latest state is still intact
    let ok = verify_commitment_consistency(&store, store.latest_root_key().unwrap());
    println!("Block 4 still consistent: {ok}");
}
