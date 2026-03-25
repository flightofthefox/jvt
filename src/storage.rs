//! Storage traits and in-memory backend.
//!
//! Two traits define the storage interface:
//! - `TreeReader` — read nodes and root keys
//! - `TreeWriter` — write nodes, root keys, and stale entries
//!
//! `MemoryStore` implements both using HashMaps.
//! A RocksDB backend would implement `TreeReader`/`TreeWriter` against
//! column families.

use std::collections::HashMap;
use std::sync::Arc;

use crate::node::{Node, NodeKey, StaleNodeIndex};

// ============================================================
// Traits
// ============================================================

/// Read-only storage interface.
pub trait TreeReader {
    fn get_node(&self, key: &NodeKey) -> Option<Arc<Node>>;
    fn get_root_key(&self, version: u64) -> Option<NodeKey>;
}

/// Write storage interface.
pub trait TreeWriter {
    fn put_node(&mut self, key: NodeKey, node: Node);
    fn set_root_key(&mut self, version: u64, key: NodeKey);
    fn record_stale(&mut self, entry: StaleNodeIndex);
}

// ============================================================
// MemoryStore
// ============================================================

/// In-memory storage backend.
#[derive(Clone, Debug, Default)]
pub struct MemoryStore {
    nodes: HashMap<NodeKey, Arc<Node>>,
    root_keys: HashMap<u64, NodeKey>,
    stale_index: Vec<StaleNodeIndex>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply an `UpdateResult` from `apply_updates` to this store.
    pub fn apply(&mut self, result: &crate::tree::UpdateResult) {
        for (nk, node) in &result.batch.new_nodes {
            self.put_node(nk.clone(), node.clone());
        }
        for stale in &result.batch.stale_nodes {
            self.record_stale(stale.clone());
        }
        if let Some((v, ref rk)) = result.batch.root_key {
            self.set_root_key(v, rk.clone());
        }
    }

    /// Prune all nodes that became stale at or before the given version.
    pub fn prune(&mut self, up_to_version: u64) {
        let (to_remove, to_keep): (Vec<_>, Vec<_>) = self
            .stale_index
            .drain(..)
            .partition(|e| e.stale_since_version <= up_to_version);
        for entry in &to_remove {
            self.nodes.remove(&entry.node_key);
        }
        self.stale_index = to_keep;
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn stale_count(&self) -> usize {
        self.stale_index.len()
    }

    pub fn versions(&self) -> Vec<u64> {
        let mut vs: Vec<u64> = self.root_keys.keys().copied().collect();
        vs.sort();
        vs
    }

    pub fn latest_root_key(&self) -> Option<NodeKey> {
        let max_version = self.root_keys.keys().max()?;
        self.root_keys.get(max_version).cloned()
    }

    pub fn latest_version(&self) -> Option<u64> {
        self.root_keys.keys().max().copied()
    }
}

// ============================================================
// Trait implementations for MemoryStore
// ============================================================

impl TreeReader for MemoryStore {
    fn get_node(&self, key: &NodeKey) -> Option<Arc<Node>> {
        self.nodes.get(key).cloned()
    }

    fn get_root_key(&self, version: u64) -> Option<NodeKey> {
        self.root_keys.get(&version).cloned()
    }
}

impl TreeWriter for MemoryStore {
    fn put_node(&mut self, key: NodeKey, node: Node) {
        self.nodes.insert(key, Arc::new(node));
    }

    fn set_root_key(&mut self, version: u64, key: NodeKey) {
        self.root_keys.insert(version, key);
    }

    fn record_stale(&mut self, entry: StaleNodeIndex) {
        self.stale_index.push(entry);
    }
}
