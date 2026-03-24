//! In-memory storage backend for the JVT prototype.
//!
//! Production deployments would use RocksDB with version-prefixed keys
//! for sequential writes. This in-memory implementation preserves the
//! same interface and versioning semantics.

use std::collections::HashMap;

use crate::node::{Node, NodeKey, StaleNodeIndex};

/// Read-only storage interface.
pub trait TreeReader {
    fn get_node(&self, key: &NodeKey) -> Option<&Node>;
    fn get_root_key(&self, version: u64) -> Option<&NodeKey>;
}

/// Write storage interface.
pub trait TreeWriter {
    fn put_node(&mut self, key: NodeKey, node: Node);
    fn set_root_key(&mut self, version: u64, key: NodeKey);
    fn record_stale(&mut self, entry: StaleNodeIndex);
}

/// In-memory storage backend.
#[derive(Clone, Debug, Default)]
pub struct MemoryStore {
    nodes: HashMap<NodeKey, Node>,
    root_keys: HashMap<u64, NodeKey>,
    stale_index: Vec<StaleNodeIndex>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
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

    /// Number of nodes currently stored.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Number of stale index entries.
    pub fn stale_count(&self) -> usize {
        self.stale_index.len()
    }

    /// All versions that have root keys.
    pub fn versions(&self) -> Vec<u64> {
        let mut vs: Vec<u64> = self.root_keys.keys().copied().collect();
        vs.sort();
        vs
    }
}

impl TreeReader for MemoryStore {
    fn get_node(&self, key: &NodeKey) -> Option<&Node> {
        self.nodes.get(key)
    }

    fn get_root_key(&self, version: u64) -> Option<&NodeKey> {
        self.root_keys.get(&version)
    }
}

impl TreeWriter for MemoryStore {
    fn put_node(&mut self, key: NodeKey, node: Node) {
        self.nodes.insert(key, node);
    }

    fn set_root_key(&mut self, version: u64, key: NodeKey) {
        self.root_keys.insert(version, key);
    }

    fn record_stale(&mut self, entry: StaleNodeIndex) {
        self.stale_index.push(entry);
    }
}
