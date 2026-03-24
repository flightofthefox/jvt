//! Quint Connect: Replay Quint spec traces against the Rust JVT implementation.
//!
//! Uses the `quint-connect` crate to bridge the formal spec and implementation.
//! The Quint spec is run in MBT mode, generating traces with action names and
//! nondeterministic picks. The Rust driver replays those actions and verifies
//! correctness after each step.
//!
//! We use `State = ()` to skip automatic state comparison (since kvMap uses
//! list keys that don't deserialize trivially, and commitment values differ).
//! Instead, we verify correctness in the driver itself: get-after-insert and
//! commitment consistency after every step.

use quint_connect::*;

use jellyfish_verkle_tree::{Key, MemoryStore, JVT};

// ============================================================
// Driver: replays Quint actions against the Rust JVT
// ============================================================

struct JvtDriver {
    tree: JVT<MemoryStore>,
    /// Track all inserted keys for verification after each step.
    inserted: Vec<(Key, i64)>,
}

impl Default for JvtDriver {
    fn default() -> Self {
        Self {
            tree: JVT::new(MemoryStore::new()),
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

        let value_bytes = value.to_le_bytes().to_vec();
        self.tree.insert(key, value_bytes);

        // Update our reference: remove old entry for this key if it exists
        self.inserted.retain(|(k, _)| k != &key);
        self.inserted.push((key, value));

        // Verify get-after-insert for ALL keys (not just the one we just inserted)
        for (k, expected_int) in &self.inserted {
            let actual = self.tree.get(k);
            assert!(
                actual.is_some(),
                "Key {:?} not found after insert (expected value {})",
                &k[..4],
                expected_int
            );
            let actual_bytes = actual.unwrap();
            let actual_int = i64::from_le_bytes({
                let mut buf = [0u8; 8];
                let len = actual_bytes.len().min(8);
                buf[..len].copy_from_slice(&actual_bytes[..len]);
                buf
            });
            assert_eq!(
                actual_int,
                *expected_int,
                "Key {:?} has value {} but expected {}",
                &k[..4],
                actual_int,
                expected_int
            );
        }

        // Verify commitment consistency after every insert
        assert!(
            self.tree.verify_commitment_consistency(),
            "Commitment consistency check failed after inserting key {:?}",
            &key[..4]
        );
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

// ============================================================
// Tests
// ============================================================

/// Replay 100 short traces (10 steps each) from the Quint spec.
#[quint_run(spec = "spec/jvt.qnt", main = "jvt", max_samples = 100, max_steps = 10)]
fn quint_connect_basic() -> impl Driver {
    JvtDriver::default()
}

/// Replay 50 longer traces (20 steps each) for deeper coverage.
#[quint_run(spec = "spec/jvt.qnt", main = "jvt", max_samples = 50, max_steps = 20)]
fn quint_connect_longer_traces() -> impl Driver {
    JvtDriver::default()
}
