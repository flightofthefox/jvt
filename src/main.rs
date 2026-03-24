use std::collections::BTreeMap;

use jellyfish_verkle_tree::{
    apply_updates, get_value, verify_commitment_consistency, Key, MemoryStore,
};

fn main() {
    let mut store = MemoryStore::new();

    println!("Jellyfish Verkle Tree — Demo");
    println!("============================\n");

    // Insert keys one at a time
    let keys_and_values: Vec<(Key, Vec<u8>)> = (0..10u8)
        .map(|i| {
            let mut key = [0u8; 32];
            key[0] = i;
            key[31] = i;
            (key, vec![i * 10])
        })
        .collect();

    for (key, value) in &keys_and_values {
        let parent = store.latest_version();
        let new_version = parent.map_or(1, |v| v + 1);
        let mut updates = BTreeMap::new();
        updates.insert(*key, Some(value.clone()));
        let result = apply_updates(&store, parent, new_version, updates);
        println!(
            "Inserted key[0]={}, value={:?} → root commitment: {:?}",
            key[0], value, result.root_commitment
        );
        store.apply(&result);
    }

    println!("\nVersion: {:?}", store.latest_version());

    // Verify all values
    println!("\nVerifying all values...");
    let root_key = store.latest_root_key().unwrap();
    for (key, expected_value) in &keys_and_values {
        let actual = get_value(&store, root_key, key);
        assert_eq!(actual.as_ref(), Some(expected_value));
    }
    println!("All values verified correctly!");

    // Verify commitment consistency
    println!("\nVerifying commitment consistency...");
    assert!(verify_commitment_consistency(&store, root_key));
    println!("All commitments consistent!");
}
