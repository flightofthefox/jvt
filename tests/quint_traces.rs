//! Quint Connect: Replay Quint spec traces against the Rust JVT implementation.
//!
//! Uses the `quint-connect` crate to bridge the formal spec and implementation.
//! We use `State = ()` and verify correctness in the driver itself.

use std::collections::BTreeMap;

use quint_connect::*;

use jellyfish_verkle_tree::{
    apply_updates, get_value, verify_commitment_consistency, Key, MemoryStore,
};

struct JvtDriver {
    store: MemoryStore,
    inserted: Vec<(Key, i64)>,
}

impl Default for JvtDriver {
    fn default() -> Self {
        Self {
            store: MemoryStore::new(),
            inserted: Vec::new(),
        }
    }
}

impl JvtDriver {
    fn do_insert(&mut self, key0: i64, key1: i64, suffix: i64, value: i64) {
        let mut key = [0u8; 32];
        key[0] = key0 as u8;
        key[1] = key1 as u8;
        key[31] = suffix as u8;

        let parent = self.store.latest_version();
        let new_version = parent.map_or(1, |v| v + 1);
        let mut updates = BTreeMap::new();
        updates.insert(key, Some(value.to_le_bytes().to_vec()));
        let result = apply_updates(&self.store, parent, new_version, updates);
        self.store.apply(&result);

        self.inserted.retain(|(k, _)| k != &key);
        self.inserted.push((key, value));

        // Verify get-after-insert for ALL keys
        let root_key = self.store.latest_root_key().unwrap();
        for (k, expected_int) in &self.inserted {
            let actual = get_value(&self.store, root_key, k);
            assert!(actual.is_some(), "Key {:?} not found", &k[..4]);
            let actual_bytes = actual.unwrap();
            let actual_int = i64::from_le_bytes({
                let mut buf = [0u8; 8];
                let len = actual_bytes.len().min(8);
                buf[..len].copy_from_slice(&actual_bytes[..len]);
                buf
            });
            assert_eq!(actual_int, *expected_int);
        }

        // Verify commitment consistency
        assert!(verify_commitment_consistency(&self.store, root_key));
    }
}

impl Driver for JvtDriver {
    type State = ();

    fn step(&mut self, step: &Step) -> Result {
        switch!(step {
            step(key0: i64, key1: i64, suffix: i64, value: i64) => {
                self.do_insert(key0, key1, suffix, value);
            },
            _ => {}
        })
    }
}

#[quint_run(spec = "spec/jvt.qnt", main = "jvt", max_samples = 100, max_steps = 10)]
fn quint_connect_basic() -> impl Driver {
    JvtDriver::default()
}

#[quint_run(spec = "spec/jvt.qnt", main = "jvt", max_samples = 50, max_steps = 20)]
fn quint_connect_longer_traces() -> impl Driver {
    JvtDriver::default()
}
