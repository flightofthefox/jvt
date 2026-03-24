//! Storage traits and in-memory backend.
//!
//! Three traits define the storage interface:
//! - `TreeReader` — read nodes and root keys
//! - `TreeWriter` — write nodes, root keys, and stale entries
//! - `TreeIterator` — iterate leaves in lexicographic order
//!
//! `MemoryStore` implements all three using HashMaps.
//! A RocksDB backend would implement `TreeReader`/`TreeWriter` against
//! column families and `TreeIterator` via prefix scans.

use std::collections::HashMap;

use crate::node::{Key, Node, NodeKey, StaleNodeIndex, Value};

// ============================================================
// Traits
// ============================================================

/// Read-only storage interface.
pub trait TreeReader {
    fn get_node(&self, key: &NodeKey) -> Option<Node>;
    fn get_root_key(&self, version: u64) -> Option<NodeKey>;
}

/// Write storage interface.
pub trait TreeWriter {
    fn put_node(&mut self, key: NodeKey, node: Node);
    fn set_root_key(&mut self, version: u64, key: NodeKey);
    fn record_stale(&mut self, entry: StaleNodeIndex);
}

/// Leaf iterator. Backends implement this for efficient range scans.
///
/// - `MemoryStore`: recursive tree walk
/// - RocksDB: `seek` to version prefix + `next` through nodes
pub trait TreeIterator: TreeReader {
    fn iter_leaves(
        &self,
        root_key: &NodeKey,
        from: Option<&Key>,
    ) -> Box<dyn Iterator<Item = (Key, Value)> + '_>;
}

// ============================================================
// MemoryStore
// ============================================================

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
    fn get_node(&self, key: &NodeKey) -> Option<Node> {
        self.nodes.get(key).cloned()
    }

    fn get_root_key(&self, version: u64) -> Option<NodeKey> {
        self.root_keys.get(&version).cloned()
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

impl TreeIterator for MemoryStore {
    fn iter_leaves(
        &self,
        root_key: &NodeKey,
        from: Option<&Key>,
    ) -> Box<dyn Iterator<Item = (Key, Value)> + '_> {
        let mut results = Vec::new();
        collect_leaves(self, root_key, &[], from, &mut results);
        Box::new(results.into_iter())
    }
}

// ============================================================
// Tree-walk leaf collection (used by MemoryStore::iter_leaves)
// ============================================================

fn collect_leaves<S: TreeReader>(
    store: &S,
    node_key: &NodeKey,
    path_prefix: &[u8],
    from: Option<&Key>,
    results: &mut Vec<(Key, Value)>,
) {
    let node = match store.get_node(node_key) {
        Some(n) => n,
        None => return,
    };

    match &node {
        Node::Internal(internal) => {
            let mut child_indices: Vec<u8> = internal.children.keys().copied().collect();
            child_indices.sort();

            let depth = path_prefix.len();
            let min_child = from.filter(|_| depth < 31).and_then(|from_key| {
                if from_key[..depth] == path_prefix[..] {
                    Some(from_key[depth])
                } else {
                    None
                }
            });

            for &child_idx in &child_indices {
                if let Some(min) = min_child {
                    if child_idx < min {
                        continue;
                    }
                }

                let child = &internal.children[&child_idx];
                let mut child_path = path_prefix.to_vec();
                child_path.push(child_idx);
                let child_key = NodeKey::new(child.version, child_path.clone());

                let child_from = if min_child == Some(child_idx) {
                    from
                } else {
                    None
                };
                collect_leaves(store, &child_key, &child_path, child_from, results);
            }
        }
        Node::EaS(eas) => {
            let depth = path_prefix.len();
            let mut suffix_keys: Vec<u8> = eas.values.keys().copied().collect();
            suffix_keys.sort();

            for suffix in suffix_keys {
                let mut full_key = [0u8; 32];
                full_key[..depth].copy_from_slice(path_prefix);
                full_key[depth..31].copy_from_slice(&eas.stem);
                full_key[31] = suffix;

                if let Some(from_key) = from {
                    if full_key < *from_key {
                        continue;
                    }
                }

                results.push((full_key, eas.values[&suffix].clone()));
            }
        }
    }
}
