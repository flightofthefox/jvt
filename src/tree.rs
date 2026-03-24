//! Core JVT operations: insert, get, and commitment management.

use std::collections::HashMap;

use crate::commitment::*;
use crate::node::*;
use crate::storage::*;

/// The Jellyfish Verkle Tree.
pub struct JVT<S> {
    pub store: S,
    current_version: u64,
}

impl<S: Clone> Clone for JVT<S> {
    fn clone(&self) -> Self {
        Self {
            store: self.store.clone(),
            current_version: self.current_version,
        }
    }
}

impl<S: TreeReader + TreeWriter> JVT<S> {
    pub fn new(store: S) -> Self {
        Self {
            store,
            current_version: 0,
        }
    }

    pub fn current_version(&self) -> u64 {
        self.current_version
    }

    pub fn root_commitment(&self) -> Commitment {
        self.root_commitment_at(self.current_version)
    }

    pub fn root_commitment_at(&self, version: u64) -> Commitment {
        match self.store.get_root_key(version) {
            Some(root_key) => match self.store.get_node(root_key) {
                Some(node) => node.commitment(),
                None => zero_commitment(),
            },
            None => zero_commitment(),
        }
    }

    /// Insert a key-value pair, advancing to the next version.
    /// Returns the new root commitment.
    pub fn insert(&mut self, key: Key, value: Value) -> Commitment {
        let new_version = self.current_version + 1;
        let path = &key[..31]; // tree traversal bytes
        let suffix = key[31]; // value slot index

        if self.current_version == 0 {
            // First insert — tree is empty, create root EaS
            let stem = path.to_vec();
            let eas = EaSNode::new_single(stem, suffix, value);
            let root_commitment = eas.commitment();
            let root_key = NodeKey::root(new_version);
            self.store.put_node(root_key.clone(), Node::EaS(eas));
            self.store.set_root_key(new_version, root_key);
            self.current_version = new_version;
            return root_commitment;
        }

        let old_root_key = self
            .store
            .get_root_key(self.current_version)
            .expect("root key must exist for current version")
            .clone();

        let result = self.insert_recursive(&old_root_key, &key, value, 0, new_version);

        // Write all new nodes
        for (nk, node) in result.batch.new_nodes {
            self.store.put_node(nk, node);
        }
        for stale in result.batch.stale_nodes {
            self.store.record_stale(stale);
        }
        self.store
            .set_root_key(new_version, result.new_node_key.clone());
        self.current_version = new_version;
        result.new_commitment
    }

    /// Get the value for a key at the current version.
    pub fn get(&self, key: &Key) -> Option<Value> {
        self.get_at(key, self.current_version)
    }

    /// Get the value for a key at a specific version.
    pub fn get_at(&self, key: &Key, version: u64) -> Option<Value> {
        let root_key = self.store.get_root_key(version)?;
        let root_node = self.store.get_node(root_key)?;
        self.get_recursive(root_node, key, 0)
    }

    /// Verify that all commitments in the tree are consistent (for testing).
    pub fn verify_commitment_consistency(&self) -> bool {
        if self.current_version == 0 {
            return true;
        }
        let root_key = match self.store.get_root_key(self.current_version) {
            Some(k) => k.clone(),
            None => return true,
        };
        self.verify_node_commitment(&root_key)
    }

    fn verify_node_commitment(&self, node_key: &NodeKey) -> bool {
        let node = match self.store.get_node(node_key) {
            Some(n) => n,
            None => return true, // missing node treated as empty
        };

        match node {
            Node::Internal(n) => {
                // Check that stored commitment matches recomputation
                let recomputed = InternalNode::compute_commitment(&n.children);
                if n.commitment != recomputed {
                    return false;
                }
                // Recursively verify children
                for (&idx, child) in &n.children {
                    let mut child_path = node_key.byte_path.clone();
                    child_path.push(idx);
                    let child_key = NodeKey::new(child.version, child_path);
                    if !self.verify_node_commitment(&child_key) {
                        return false;
                    }
                }
                true
            }
            Node::EaS(eas) => {
                let c1 = EaSNode::compute_c1(&eas.values);
                let c2 = EaSNode::compute_c2(&eas.values);
                let ext = EaSNode::compute_extension_commitment(&eas.stem, c1, c2);
                eas.c1 == c1 && eas.c2 == c2 && eas.extension_commitment == ext
            }
        }
    }

    // --- Private helpers ---

    fn get_recursive(&self, node: &Node, key: &Key, depth: usize) -> Option<Value> {
        match node {
            Node::EaS(eas) => {
                let expected_stem = &key[depth..31];
                if eas.stem == expected_stem {
                    eas.values.get(&key[31]).cloned()
                } else {
                    None
                }
            }
            Node::Internal(n) => {
                let child_index = key[depth];
                let child = n.children.get(&child_index)?;
                let child_path: Vec<u8> = key[..depth + 1].to_vec();
                let child_key = NodeKey::new(child.version, child_path);
                let child_node = self.store.get_node(&child_key)?;
                self.get_recursive(child_node, key, depth + 1)
            }
        }
    }
}

/// Result of a recursive insert operation.
struct InsertResult {
    new_node_key: NodeKey,
    new_commitment: Commitment,
    batch: TreeUpdateBatch,
}

impl<S: TreeReader + TreeWriter> JVT<S> {
    fn insert_recursive(
        &self,
        current_key: &NodeKey,
        key: &Key,
        value: Value,
        depth: usize,
        version: u64,
    ) -> InsertResult {
        let current_node = self
            .store
            .get_node(current_key)
            .cloned()
            .unwrap_or_else(|| {
                // Treat missing node as empty — create new EaS
                panic!(
                    "node not found for key {:?} at depth {}",
                    current_key, depth
                );
            });

        match current_node {
            Node::EaS(eas) => {
                let expected_stem = &key[depth..31];
                if eas.stem == expected_stem {
                    // Case 2: Same stem — update value
                    self.insert_update_eas(current_key, eas, key, value, depth, version)
                } else {
                    // Case 3: Split
                    self.insert_split_eas(current_key, eas, key, value, depth, version)
                }
            }
            Node::Internal(internal) => {
                let child_index = key[depth];
                if internal.children.contains_key(&child_index) {
                    // Descend into existing child
                    self.insert_into_internal_existing(
                        current_key,
                        internal,
                        key,
                        value,
                        depth,
                        version,
                    )
                } else {
                    // Insert new EaS as child of this internal node
                    self.insert_into_internal_empty(
                        current_key,
                        internal,
                        key,
                        value,
                        depth,
                        version,
                    )
                }
            }
        }
    }

    /// Case 2: Update a value in an existing EaS (same stem).
    fn insert_update_eas(
        &self,
        old_key: &NodeKey,
        mut eas: EaSNode,
        key: &Key,
        value: Value,
        depth: usize,
        version: u64,
    ) -> InsertResult {
        let suffix = key[31];
        eas.update_value(suffix, value);

        let new_key = NodeKey::new(version, key[..depth].to_vec());
        let commitment = eas.commitment();

        let mut batch = TreeUpdateBatch::default();
        batch.put_node(new_key.clone(), Node::EaS(eas));
        batch.mark_stale(old_key.clone(), version);

        InsertResult {
            new_node_key: new_key,
            new_commitment: commitment,
            batch,
        }
    }

    /// Case 3: Split an EaS because the new key has a different stem.
    fn insert_split_eas(
        &self,
        old_key: &NodeKey,
        existing_eas: EaSNode,
        key: &Key,
        value: Value,
        depth: usize,
        version: u64,
    ) -> InsertResult {
        let existing_stem = &existing_eas.stem;
        let new_stem = &key[depth..31];

        let prefix_len = common_prefix_len(existing_stem, new_stem);

        // Byte indices at the divergence point
        let existing_byte = existing_stem[prefix_len];
        let new_byte = new_stem[prefix_len];

        // Create new EaS for existing data (with shortened stem)
        let existing_new_stem = existing_stem[prefix_len + 1..].to_vec();
        let existing_new_eas = EaSNode::from_values(existing_new_stem, existing_eas.values.clone());

        // Create new EaS for the new key
        let new_eas_stem = new_stem[prefix_len + 1..].to_vec();
        let new_eas = EaSNode::new_single(new_eas_stem, key[31], value);

        // Create the internal node at the divergence point
        let mut children = HashMap::new();
        children.insert(
            existing_byte,
            Child {
                version,
                commitment: existing_new_eas.commitment(),
            },
        );
        children.insert(
            new_byte,
            Child {
                version,
                commitment: new_eas.commitment(),
            },
        );
        let diverge_node = InternalNode::new(children);
        let diverge_commitment = diverge_node.commitment;

        let mut batch = TreeUpdateBatch::default();
        batch.mark_stale(old_key.clone(), version);

        // Store the two new EaS nodes
        let base_path = &key[..depth];
        let diverge_path: Vec<u8> = base_path
            .iter()
            .chain(key[depth..depth + prefix_len].iter())
            .copied()
            .collect();

        let existing_eas_path: Vec<u8> = diverge_path
            .iter()
            .chain(std::iter::once(&existing_byte))
            .copied()
            .collect();
        let new_eas_path: Vec<u8> = diverge_path
            .iter()
            .chain(std::iter::once(&new_byte))
            .copied()
            .collect();

        batch.put_node(
            NodeKey::new(version, existing_eas_path),
            Node::EaS(existing_new_eas),
        );
        batch.put_node(NodeKey::new(version, new_eas_path), Node::EaS(new_eas));

        // Build chain of single-child internal nodes for shared prefix (if any)
        if prefix_len == 0 {
            // Common case: diverge immediately at this depth
            let result_key = NodeKey::new(version, base_path.to_vec());
            batch.put_node(result_key.clone(), Node::Internal(diverge_node));

            InsertResult {
                new_node_key: result_key,
                new_commitment: diverge_commitment,
                batch,
            }
        } else {
            // Store the diverge node
            let diverge_key = NodeKey::new(version, diverge_path.clone());
            batch.put_node(diverge_key, Node::Internal(diverge_node));

            // Build intermediate single-child internals from depth upward
            let mut child_commitment = diverge_commitment;
            for i in (0..prefix_len).rev() {
                let path: Vec<u8> = base_path
                    .iter()
                    .chain(key[depth..depth + i].iter())
                    .copied()
                    .collect();
                let child_byte = key[depth + i];
                let mut children = HashMap::new();
                children.insert(
                    child_byte,
                    Child {
                        version,
                        commitment: child_commitment,
                    },
                );
                let intermediate = InternalNode::new(children);
                child_commitment = intermediate.commitment;
                let intermediate_key = NodeKey::new(version, path.clone());
                batch.put_node(intermediate_key, Node::Internal(intermediate));
            }

            let result_key = NodeKey::new(version, base_path.to_vec());
            InsertResult {
                new_node_key: result_key,
                new_commitment: child_commitment,
                batch,
            }
        }
    }

    /// Insert into an existing child of an internal node.
    fn insert_into_internal_existing(
        &self,
        old_key: &NodeKey,
        internal: InternalNode,
        key: &Key,
        value: Value,
        depth: usize,
        version: u64,
    ) -> InsertResult {
        let child_index = key[depth];
        let child = &internal.children[&child_index];
        let child_path: Vec<u8> = key[..depth + 1].to_vec();
        let child_key = NodeKey::new(child.version, child_path);

        // Recurse into child
        let child_result = self.insert_recursive(&child_key, key, value, depth + 1, version);

        // Update internal node with new child commitment
        let mut new_internal = internal.clone();
        new_internal.update_child(
            child_index,
            Child {
                version,
                commitment: child_result.new_commitment,
            },
        );

        let new_key = NodeKey::new(version, key[..depth].to_vec());
        let commitment = new_internal.commitment;

        let mut batch = child_result.batch;
        batch.put_node(new_key.clone(), Node::Internal(new_internal));
        batch.mark_stale(old_key.clone(), version);

        InsertResult {
            new_node_key: new_key,
            new_commitment: commitment,
            batch,
        }
    }

    /// Insert a new EaS as a child of an internal node (empty slot).
    fn insert_into_internal_empty(
        &self,
        old_key: &NodeKey,
        internal: InternalNode,
        key: &Key,
        value: Value,
        depth: usize,
        version: u64,
    ) -> InsertResult {
        let child_index = key[depth];
        let stem = key[depth + 1..31].to_vec();
        let suffix = key[31];
        let new_eas = EaSNode::new_single(stem, suffix, value);
        let eas_commitment = new_eas.commitment();

        // Store the new EaS
        let eas_path: Vec<u8> = key[..depth + 1].to_vec();
        let eas_key = NodeKey::new(version, eas_path);

        // Update internal node
        let mut new_internal = internal.clone();
        new_internal.update_child(
            child_index,
            Child {
                version,
                commitment: eas_commitment,
            },
        );

        let new_key = NodeKey::new(version, key[..depth].to_vec());
        let commitment = new_internal.commitment;

        let mut batch = TreeUpdateBatch::default();
        batch.put_node(eas_key, Node::EaS(new_eas));
        batch.put_node(new_key.clone(), Node::Internal(new_internal));
        batch.mark_stale(old_key.clone(), version);

        InsertResult {
            new_node_key: new_key,
            new_commitment: commitment,
            batch,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStore;

    fn make_key(first: u8, second: u8, suffix: u8) -> Key {
        let mut key = [0u8; 32];
        key[0] = first;
        key[1] = second;
        key[31] = suffix;
        key
    }

    #[test]
    fn insert_and_get_single() {
        let mut tree = JVT::new(MemoryStore::new());
        let key = make_key(1, 2, 3);
        let value = vec![42];

        tree.insert(key, value.clone());
        assert_eq!(tree.get(&key), Some(value));
    }

    #[test]
    fn insert_same_stem_different_suffix() {
        let mut tree = JVT::new(MemoryStore::new());
        let key1 = make_key(1, 2, 3);
        let key2 = make_key(1, 2, 4);
        let val1 = vec![10];
        let val2 = vec![20];

        tree.insert(key1, val1.clone());
        tree.insert(key2, val2.clone());

        assert_eq!(tree.get(&key1), Some(val1));
        assert_eq!(tree.get(&key2), Some(val2));
    }

    #[test]
    fn insert_different_first_byte_triggers_split() {
        let mut tree = JVT::new(MemoryStore::new());
        let key1 = make_key(1, 0, 0);
        let key2 = make_key(2, 0, 0);
        let val1 = vec![10];
        let val2 = vec![20];

        tree.insert(key1, val1.clone());
        tree.insert(key2, val2.clone());

        assert_eq!(tree.get(&key1), Some(val1));
        assert_eq!(tree.get(&key2), Some(val2));
    }

    #[test]
    fn insert_shared_prefix_split() {
        let mut tree = JVT::new(MemoryStore::new());
        // These keys share byte 0 but differ at byte 1
        let key1 = make_key(5, 10, 0);
        let key2 = make_key(5, 20, 0);
        let val1 = vec![100];
        let val2 = vec![200];

        tree.insert(key1, val1.clone());
        tree.insert(key2, val2.clone());

        assert_eq!(tree.get(&key1), Some(val1));
        assert_eq!(tree.get(&key2), Some(val2));
    }

    #[test]
    fn update_existing_key() {
        let mut tree = JVT::new(MemoryStore::new());
        let key = make_key(1, 2, 3);

        tree.insert(key, vec![10]);
        assert_eq!(tree.get(&key), Some(vec![10]));

        tree.insert(key, vec![20]);
        assert_eq!(tree.get(&key), Some(vec![20]));
    }

    #[test]
    fn get_nonexistent_key() {
        let mut tree = JVT::new(MemoryStore::new());
        let key1 = make_key(1, 2, 3);
        let key2 = make_key(4, 5, 6);

        tree.insert(key1, vec![42]);
        assert_eq!(tree.get(&key2), None);
    }

    #[test]
    fn commitment_changes_on_insert() {
        let mut tree = JVT::new(MemoryStore::new());
        let c0 = tree.root_commitment();
        assert_eq!(c0, zero_commitment());

        let c1 = tree.insert(make_key(1, 0, 0), vec![10]);
        assert_ne!(c1, zero_commitment());

        let c2 = tree.insert(make_key(2, 0, 0), vec![20]);
        assert_ne!(c2, c1);
    }

    #[test]
    fn commitment_consistency_after_operations() {
        let mut tree = JVT::new(MemoryStore::new());
        tree.insert(make_key(1, 0, 0), vec![10]);
        tree.insert(make_key(2, 0, 0), vec![20]);
        tree.insert(make_key(1, 5, 0), vec![30]);
        tree.insert(make_key(1, 0, 1), vec![40]);

        assert!(tree.verify_commitment_consistency());
    }

    #[test]
    fn versioned_reads() {
        let mut tree = JVT::new(MemoryStore::new());
        let key = make_key(1, 2, 3);

        tree.insert(key, vec![10]);
        let v1 = tree.current_version();

        tree.insert(key, vec![20]);
        let v2 = tree.current_version();

        assert_eq!(tree.get_at(&key, v1), Some(vec![10]));
        assert_eq!(tree.get_at(&key, v2), Some(vec![20]));
    }

    #[test]
    fn three_way_split() {
        let mut tree = JVT::new(MemoryStore::new());
        let key1 = make_key(1, 0, 0);
        let key2 = make_key(2, 0, 0);
        let key3 = make_key(3, 0, 0);

        tree.insert(key1, vec![10]);
        tree.insert(key2, vec![20]);
        tree.insert(key3, vec![30]);

        assert_eq!(tree.get(&key1), Some(vec![10]));
        assert_eq!(tree.get(&key2), Some(vec![20]));
        assert_eq!(tree.get(&key3), Some(vec![30]));
        assert!(tree.verify_commitment_consistency());
    }

    #[test]
    fn many_inserts_commitment_consistency() {
        let mut tree = JVT::new(MemoryStore::new());
        for i in 0u8..50 {
            let key = make_key(i, i.wrapping_mul(7), i.wrapping_mul(13));
            tree.insert(key, vec![i]);
        }
        assert!(tree.verify_commitment_consistency());

        // Verify all values are retrievable
        for i in 0u8..50 {
            let key = make_key(i, i.wrapping_mul(7), i.wrapping_mul(13));
            assert_eq!(tree.get(&key), Some(vec![i]));
        }
    }
}
