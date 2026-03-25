//! Quint Connect: Replay Quint spec traces against the Rust JVT implementation.
//!
//! Bridges the formal spec and implementation with three verification layers:
//!
//! 1. **Bidirectional state comparison** — after every step, the Quint spec's `kvMap`
//!    and `currentVersion` are deserialized from the ITF trace and compared against
//!    the Rust driver's state. Any semantic divergence is caught immediately.
//!
//! 2. **Verkle proof cross-verification** — on the final step of each trace, batch
//!    proofs are generated and verified using the real IPA-based proof system,
//!    connecting the Quint abstract proof model to actual cryptographic proofs.
//!
//! 3. **History preservation** — past version snapshots are verified to ensure the
//!    versioned storage correctly preserves old state.

use std::collections::BTreeMap;

use quint_connect::*;
use serde::Deserialize;

use jellyfish_verkle_tree::verkle_proof::{prove, verify};
use jellyfish_verkle_tree::{
    apply_updates, get_committed_value, root_commitment_at, value_to_field,
    verify_commitment_consistency, Key, MemoryStore, NodeKey, Value as JvtValue,
};

// ============================================================
// Bidirectional State
// ============================================================

/// State extracted from both the Quint spec (via ITF deserialization) and
/// the Rust driver (via from_driver). Compared at every step.
#[derive(Debug, PartialEq, Deserialize)]
struct JvtState {
    #[serde(rename = "currentVersion")]
    current_version: i64,

    /// The key-value map: List[Byte] → int.
    /// In Quint, values are raw integers (1..10). In Rust, they're field elements.
    /// We compare the raw integer representation.
    #[serde(rename = "kvMap")]
    kv_map: BTreeMap<Vec<i64>, i64>,
}

impl State<JvtDriver> for JvtState {
    fn from_driver(driver: &JvtDriver) -> anyhow::Result<Self> {
        let mut kv_map = BTreeMap::new();
        for (key, value) in &driver.inserted {
            let key_vec: Vec<i64> = key.iter().map(|&b| b as i64).collect();
            kv_map.insert(key_vec, *value);
        }
        Ok(JvtState {
            current_version: driver.current_version as i64,
            kv_map,
        })
    }
}

// ============================================================
// Driver
// ============================================================

struct JvtDriver {
    store: MemoryStore,
    /// Current key-value pairs (raw integer values, not field elements).
    inserted: Vec<(Key, i64)>,
    /// Tracks the current version (including no-op deletes that advance it).
    current_version: u64,
    /// History snapshots: (version, root_key, snapshot of inserted).
    history: Vec<(u64, NodeKey, Vec<(Key, i64)>)>,
    /// Total steps in this trace (set by max_steps config, used for deferred proofs).
    step_count: usize,
}

impl Default for JvtDriver {
    fn default() -> Self {
        Self {
            store: MemoryStore::new(),
            inserted: Vec::new(),
            current_version: 0,
            history: Vec::new(),
            step_count: 0,
        }
    }
}

impl JvtDriver {
    fn make_key(key0: i64, key1: i64, suffix: i64) -> Key {
        let mut key = [0u8; 32];
        key[0] = key0 as u8;
        key[1] = key1 as u8;
        key[31] = suffix as u8;
        key
    }

    fn do_insert(&mut self, key0: i64, key1: i64, suffix: i64, value: i64) {
        let key = Self::make_key(key0, key1, suffix);
        let parent = self.store.latest_version();
        let new_version = parent.map_or(1, |v| v + 1);
        let mut updates = BTreeMap::new();
        updates.insert(key, Some(value_to_field(&value.to_le_bytes())));
        let result = apply_updates(&self.store, parent, new_version, updates);
        self.store.apply(&result);

        self.inserted.retain(|(k, _)| k != &key);
        self.inserted.push((key, value));
        self.current_version = new_version;
        self.history
            .push((new_version, result.root_key.clone(), self.inserted.clone()));
        self.step_count += 1;

        self.verify_core("insert");
    }

    fn do_delete(&mut self, key0: i64, key1: i64, suffix: i64) {
        let key = Self::make_key(key0, key1, suffix);
        let parent = self.store.latest_version();
        let new_version = parent.map_or(1, |v| v + 1);
        let mut updates = BTreeMap::new();
        updates.insert(key, None);
        let result = apply_updates(&self.store, parent, new_version, updates);
        self.store.apply(&result);

        let was_present = self.inserted.iter().any(|(k, _)| k == &key);
        self.inserted.retain(|(k, _)| k != &key);
        self.current_version = new_version;
        self.history
            .push((new_version, result.root_key.clone(), self.inserted.clone()));
        self.step_count += 1;

        // Deleted key should not be found
        if was_present {
            if let Some(root_key) = self.store.latest_root_key() {
                assert!(
                    get_committed_value(&self.store, &root_key, &key).is_none(),
                    "Deleted key still found"
                );
            }
        }

        self.verify_core("delete");
    }

    /// Cheap checks run at every step.
    fn verify_core(&self, op: &str) {
        if let Some(root_key) = self.store.latest_root_key() {
            // Get-after-insert for all keys
            for (k, expected_int) in &self.inserted {
                let actual = get_committed_value(&self.store, &root_key, k);
                assert!(actual.is_some(), "Key {:?} not found after {}", &k[..4], op);
                assert_eq!(actual.unwrap(), value_to_field(&expected_int.to_le_bytes()));
            }

            // Commitment consistency
            assert!(verify_commitment_consistency(&self.store, &root_key));

            // History preservation (spot-check last 3 versions)
            self.verify_recent_history();
        }
    }

    /// Expensive checks: proof generation + verification.
    /// Called once at trace end via `verify_proofs_at_end`.
    fn verify_proofs_at_end(&self) {
        let Some(root_key) = self.store.latest_root_key() else {
            return;
        };

        use jellyfish_verkle_tree::TreeReader;
        if self.store.get_node(&root_key).is_none() {
            return;
        }

        let version = self.store.latest_version().unwrap();
        let root_c = root_commitment_at(&self.store, version);

        // Batch proof for all present keys
        if !self.inserted.is_empty() {
            let keys: Vec<Key> = self.inserted.iter().map(|(k, _)| *k).collect();
            let expected: Vec<Option<JvtValue>> = self
                .inserted
                .iter()
                .map(|(_, v)| Some(value_to_field(&v.to_le_bytes())))
                .collect();
            let proof =
                prove(&self.store, &root_key, &keys).expect("Batch proof generation failed");
            assert!(
                verify(&proof, root_c, &keys, &expected),
                "Batch proof verification failed"
            );
        }

        // Absence proofs
        let mut absent_keys = Vec::new();
        for k0 in 0..4i64 {
            let ak = Self::make_key(k0, 3, 3);
            if !self.inserted.iter().any(|(k, _)| *k == ak) {
                absent_keys.push(ak);
                if absent_keys.len() >= 2 {
                    break;
                }
            }
        }
        if !absent_keys.is_empty() {
            let absent_expected: Vec<Option<JvtValue>> = vec![None; absent_keys.len()];
            let absent_proof =
                prove(&self.store, &root_key, &absent_keys).expect("Absence proof gen failed");
            assert!(
                verify(&absent_proof, root_c, &absent_keys, &absent_expected),
                "Absence proof verification failed"
            );
        }

        // Full history check at end
        for (version, root_key, snapshot) in &self.history {
            for (key, expected_int) in snapshot {
                let actual = get_committed_value(&self.store, root_key, key);
                assert!(
                    actual.is_some(),
                    "History broken: key {:?} not found at version {}",
                    &key[..4],
                    version
                );
                assert_eq!(
                    actual.unwrap(),
                    value_to_field(&expected_int.to_le_bytes()),
                    "History broken: wrong value at version {}",
                    version
                );
            }
        }
    }

    /// Spot-check last 3 versions for history preservation.
    fn verify_recent_history(&self) {
        let start = self.history.len().saturating_sub(3);
        for (version, root_key, snapshot) in &self.history[start..] {
            for (key, expected_int) in snapshot {
                let actual = get_committed_value(&self.store, root_key, key);
                assert!(
                    actual.is_some(),
                    "History broken: key {:?} not found at version {}",
                    &key[..4],
                    version
                );
                assert_eq!(
                    actual.unwrap(),
                    value_to_field(&expected_int.to_le_bytes()),
                    "History broken: wrong value at version {}",
                    version
                );
            }
        }
    }
}

impl Driver for JvtDriver {
    type State = JvtState;

    #[allow(non_snake_case)]
    fn step(&mut self, step: &Step) -> Result {
        switch!(step {
            init => {
                // Verify proofs from previous trace (if any) before resetting
                if self.current_version > 0 {
                    self.verify_proofs_at_end();
                }
                *self = JvtDriver::default();
            },
            step(opKind: i64, key0: i64, key1: i64, suffix: i64, value: i64) => {
                if opKind == 0 {
                    self.do_insert(key0, key1, suffix, value);
                } else {
                    self.do_delete(key0, key1, suffix);
                }
            },
            _ => {}
        })
    }
}

impl Drop for JvtDriver {
    fn drop(&mut self) {
        // Verify proofs for the final trace
        if self.current_version > 0 && !std::thread::panicking() {
            self.verify_proofs_at_end();
        }
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
