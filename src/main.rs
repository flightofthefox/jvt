use jellyfish_verkle_tree::{Key, MemoryStore, JVT};

fn main() {
    let mut tree = JVT::new(MemoryStore::new());

    println!("Jellyfish Verkle Tree — Demo");
    println!("============================\n");

    // Insert some keys
    let keys_and_values: Vec<(Key, Vec<u8>)> = (0..10u8)
        .map(|i| {
            let mut key = [0u8; 32];
            key[0] = i;
            key[31] = i;
            (key, vec![i * 10])
        })
        .collect();

    for (key, value) in &keys_and_values {
        let commitment = tree.insert(*key, value.clone());
        println!(
            "Inserted key[0]={}, value={:?} → root commitment: {:?}",
            key[0], value, commitment
        );
    }

    println!("\nVersion: {}", tree.current_version());
    println!("Root commitment: {:?}", tree.root_commitment());

    // Verify all values
    println!("\nVerifying all values...");
    for (key, expected_value) in &keys_and_values {
        let actual = tree.get(key);
        assert_eq!(actual.as_ref(), Some(expected_value));
    }
    println!("All values verified correctly!");

    // Verify commitment consistency
    println!("\nVerifying commitment consistency...");
    assert!(tree.verify_commitment_consistency());
    println!("All commitments consistent!");
}
