//! Core JVT operations: apply_updates, get_value, verify_commitment_consistency.
//!
//! All operations are stateless — they take a read-only store reference and
//! return results without mutations. The caller controls versioning and
//! applies writes to storage.

use std::collections::{BTreeMap, HashMap};

use crate::commitment::*;
use crate::node::*;
use crate::storage::*;

// ============================================================
// Public API
// ============================================================

/// Result of applying a batch of updates to the tree.
#[derive(Clone, Debug)]
pub struct UpdateResult {
    /// The new root commitment after applying updates.
    pub root_commitment: Commitment,
    /// The new root node key.
    pub root_key: NodeKey,
    /// All new nodes to persist and stale nodes to mark.
    pub batch: TreeUpdateBatch,
}

/// Apply a batch of key-value updates to the tree.
///
/// Takes a read-only store, returns the new root commitment and all writes
/// to persist. The caller is responsible for applying `result.batch` to storage.
///
/// # Arguments
/// * `store` - Read-only access to the current tree state
/// * `parent_version` - The version of the current root (`None` for empty tree)
/// * `new_version` - The version to stamp on new nodes (must be > parent_version)
/// * `updates` - Key-value pairs. `Some(value)` = upsert, `None` = reserved for delete.
pub fn apply_updates<S: TreeReader>(
    store: &S,
    parent_version: Option<u64>,
    new_version: u64,
    updates: BTreeMap<Key, Option<Value>>,
) -> UpdateResult {
    let mut overlay = OverlayStore::new(store);
    let mut current_root_key: Option<NodeKey> =
        parent_version.and_then(|v| store.get_root_key(v)).cloned();
    let mut batch = TreeUpdateBatch::default();

    for (key, value) in updates {
        let value = match value {
            Some(v) => v,
            None => continue, // TODO: delete support
        };

        let result = if let Some(ref root_key) = current_root_key {
            insert_single(&overlay, root_key, &key, value, 0, new_version)
        } else {
            // First insert into empty tree
            let stem = key[..31].to_vec();
            let suffix = key[31];
            let eas = EaSNode::new_single(stem, suffix, value);
            let commitment = eas.commitment();
            let root_key = NodeKey::root(new_version);
            let mut b = TreeUpdateBatch::default();
            b.put_node(root_key.clone(), Node::EaS(eas));
            InsertResult {
                new_node_key: root_key,
                new_commitment: commitment,
                batch: b,
            }
        };

        // Apply writes to overlay so subsequent inserts see them
        for (nk, node) in &result.batch.new_nodes {
            overlay.put(nk.clone(), node.clone());
        }
        current_root_key = Some(result.new_node_key.clone());

        batch.new_nodes.extend(result.batch.new_nodes);
        batch.stale_nodes.extend(result.batch.stale_nodes);
    }

    let root_key = current_root_key.unwrap_or_else(|| NodeKey::root(new_version));
    let root_commitment = batch
        .new_nodes
        .iter()
        .rev()
        .find(|(nk, _)| *nk == root_key)
        .map(|(_, node)| node.commitment())
        .unwrap_or_else(zero_commitment);

    batch.root_key = Some((new_version, root_key.clone()));

    UpdateResult {
        root_commitment,
        root_key,
        batch,
    }
}

/// Get a value from the tree.
pub fn get_value<S: TreeReader>(store: &S, root_key: &NodeKey, key: &Key) -> Option<Value> {
    let root_node = store.get_node(root_key)?;
    get_recursive(root_node, store, key, 0)
}

/// Verify that all commitments in the tree are consistent (recompute from
/// children/values and compare with stored commitments).
pub fn verify_commitment_consistency<S: TreeReader>(store: &S, root_key: &NodeKey) -> bool {
    verify_node_commitment(store, root_key)
}

/// Get the root commitment for a given version.
pub fn root_commitment_at<S: TreeReader>(store: &S, version: u64) -> Commitment {
    match store.get_root_key(version) {
        Some(root_key) => match store.get_node(root_key) {
            Some(node) => node.commitment(),
            None => zero_commitment(),
        },
        None => zero_commitment(),
    }
}

// ============================================================
// Internal: overlay store for batch updates
// ============================================================

/// A read-through overlay that layers uncommitted nodes on top of a base store.
struct OverlayStore<'a, S> {
    base: &'a S,
    overlay: HashMap<NodeKey, Node>,
}

impl<'a, S: TreeReader> OverlayStore<'a, S> {
    fn new(base: &'a S) -> Self {
        Self {
            base,
            overlay: HashMap::new(),
        }
    }

    fn put(&mut self, key: NodeKey, node: Node) {
        self.overlay.insert(key, node);
    }
}

impl<S: TreeReader> TreeReader for OverlayStore<'_, S> {
    fn get_node(&self, key: &NodeKey) -> Option<&Node> {
        self.overlay.get(key).or_else(|| self.base.get_node(key))
    }

    fn get_root_key(&self, version: u64) -> Option<&NodeKey> {
        self.base.get_root_key(version)
    }
}

// ============================================================
// Internal: get
// ============================================================

fn get_recursive<S: TreeReader>(node: &Node, store: &S, key: &Key, depth: usize) -> Option<Value> {
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
            let child_node = store.get_node(&child_key)?;
            get_recursive(child_node, store, key, depth + 1)
        }
    }
}

fn verify_node_commitment<S: TreeReader>(store: &S, node_key: &NodeKey) -> bool {
    let node = match store.get_node(node_key) {
        Some(n) => n,
        None => return true,
    };

    match node {
        Node::Internal(n) => {
            let recomputed = InternalNode::compute_commitment(&n.children);
            if n.commitment != recomputed {
                return false;
            }
            for (&idx, child) in &n.children {
                let mut child_path = node_key.byte_path.clone();
                child_path.push(idx);
                let child_key = NodeKey::new(child.version, child_path);
                if !verify_node_commitment(store, &child_key) {
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

// ============================================================
// Internal: single-key insert
// ============================================================

struct InsertResult {
    new_node_key: NodeKey,
    new_commitment: Commitment,
    batch: TreeUpdateBatch,
}

fn insert_single<S: TreeReader>(
    store: &S,
    current_key: &NodeKey,
    key: &Key,
    value: Value,
    depth: usize,
    version: u64,
) -> InsertResult {
    let current_node = store.get_node(current_key).cloned().unwrap_or_else(|| {
        panic!(
            "node not found for key {:?} at depth {}",
            current_key, depth
        );
    });

    match current_node {
        Node::EaS(eas) => {
            let expected_stem = &key[depth..31];
            if eas.stem == expected_stem {
                insert_update_eas(current_key, eas, key, value, depth, version)
            } else {
                insert_split_eas(current_key, eas, key, value, depth, version)
            }
        }
        Node::Internal(internal) => {
            let child_index = key[depth];
            if internal.children.contains_key(&child_index) {
                insert_into_internal_existing(
                    store,
                    current_key,
                    internal,
                    key,
                    value,
                    depth,
                    version,
                )
            } else {
                insert_into_internal_empty(current_key, internal, key, value, depth, version)
            }
        }
    }
}

fn insert_update_eas(
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

fn insert_split_eas(
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

    let existing_byte = existing_stem[prefix_len];
    let new_byte = new_stem[prefix_len];

    let existing_new_stem = existing_stem[prefix_len + 1..].to_vec();
    let existing_new_eas = EaSNode::from_values(existing_new_stem, existing_eas.values.clone());

    let new_eas_stem = new_stem[prefix_len + 1..].to_vec();
    let new_eas = EaSNode::new_single(new_eas_stem, key[31], value);

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

    if prefix_len == 0 {
        let result_key = NodeKey::new(version, base_path.to_vec());
        batch.put_node(result_key.clone(), Node::Internal(diverge_node));
        InsertResult {
            new_node_key: result_key,
            new_commitment: diverge_commitment,
            batch,
        }
    } else {
        let diverge_key = NodeKey::new(version, diverge_path.clone());
        batch.put_node(diverge_key, Node::Internal(diverge_node));

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
            batch.put_node(NodeKey::new(version, path), Node::Internal(intermediate));
        }

        let result_key = NodeKey::new(version, base_path.to_vec());
        InsertResult {
            new_node_key: result_key,
            new_commitment: child_commitment,
            batch,
        }
    }
}

fn insert_into_internal_existing<S: TreeReader>(
    store: &S,
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

    let child_result = insert_single(store, &child_key, key, value, depth + 1, version);

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

fn insert_into_internal_empty(
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

    let eas_path: Vec<u8> = key[..depth + 1].to_vec();
    let eas_key = NodeKey::new(version, eas_path);

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

// ============================================================
// Tests
// ============================================================

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

    /// Helper: insert a single key-value into a store, return the result.
    fn insert(store: &mut MemoryStore, key: Key, value: Value) -> UpdateResult {
        let parent = store.latest_version();
        let new_version = parent.map_or(1, |v| v + 1);
        let mut updates = BTreeMap::new();
        updates.insert(key, Some(value));
        let result = apply_updates(store, parent, new_version, updates);
        store.apply(&result);
        result
    }

    /// Helper: insert multiple keys at the same version.
    fn insert_batch(store: &mut MemoryStore, entries: Vec<(Key, Value)>) -> UpdateResult {
        let parent = store.latest_version();
        let new_version = parent.map_or(1, |v| v + 1);
        let updates: BTreeMap<Key, Option<Value>> =
            entries.into_iter().map(|(k, v)| (k, Some(v))).collect();
        let result = apply_updates(store, parent, new_version, updates);
        store.apply(&result);
        result
    }

    /// Helper: get a value at the latest version.
    fn get(store: &MemoryStore, key: &Key) -> Option<Value> {
        let root_key = store.latest_root_key()?;
        get_value(store, root_key, key)
    }

    #[test]
    fn insert_and_get_single() {
        let mut store = MemoryStore::new();
        let key = make_key(1, 2, 3);
        insert(&mut store, key, vec![42]);
        assert_eq!(get(&store, &key), Some(vec![42]));
    }

    #[test]
    fn insert_same_stem_different_suffix() {
        let mut store = MemoryStore::new();
        let key1 = make_key(1, 2, 3);
        let key2 = make_key(1, 2, 4);
        insert(&mut store, key1, vec![10]);
        insert(&mut store, key2, vec![20]);
        assert_eq!(get(&store, &key1), Some(vec![10]));
        assert_eq!(get(&store, &key2), Some(vec![20]));
    }

    #[test]
    fn insert_different_first_byte_triggers_split() {
        let mut store = MemoryStore::new();
        insert(&mut store, make_key(1, 0, 0), vec![10]);
        insert(&mut store, make_key(2, 0, 0), vec![20]);
        assert_eq!(get(&store, &make_key(1, 0, 0)), Some(vec![10]));
        assert_eq!(get(&store, &make_key(2, 0, 0)), Some(vec![20]));
    }

    #[test]
    fn insert_shared_prefix_split() {
        let mut store = MemoryStore::new();
        insert(&mut store, make_key(5, 10, 0), vec![100]);
        insert(&mut store, make_key(5, 20, 0), vec![200]);
        assert_eq!(get(&store, &make_key(5, 10, 0)), Some(vec![100]));
        assert_eq!(get(&store, &make_key(5, 20, 0)), Some(vec![200]));
    }

    #[test]
    fn update_existing_key() {
        let mut store = MemoryStore::new();
        let key = make_key(1, 2, 3);
        insert(&mut store, key, vec![10]);
        assert_eq!(get(&store, &key), Some(vec![10]));
        insert(&mut store, key, vec![20]);
        assert_eq!(get(&store, &key), Some(vec![20]));
    }

    #[test]
    fn get_nonexistent_key() {
        let mut store = MemoryStore::new();
        insert(&mut store, make_key(1, 2, 3), vec![42]);
        assert_eq!(get(&store, &make_key(4, 5, 6)), None);
    }

    #[test]
    fn commitment_changes_on_insert() {
        let mut store = MemoryStore::new();
        assert_eq!(root_commitment_at(&store, 0), zero_commitment());

        let r1 = insert(&mut store, make_key(1, 0, 0), vec![10]);
        assert_ne!(r1.root_commitment, zero_commitment());

        let r2 = insert(&mut store, make_key(2, 0, 0), vec![20]);
        assert_ne!(r2.root_commitment, r1.root_commitment);
    }

    #[test]
    fn commitment_consistency_after_operations() {
        let mut store = MemoryStore::new();
        insert(&mut store, make_key(1, 0, 0), vec![10]);
        insert(&mut store, make_key(2, 0, 0), vec![20]);
        insert(&mut store, make_key(1, 5, 0), vec![30]);
        insert(&mut store, make_key(1, 0, 1), vec![40]);

        let root = store.latest_root_key().unwrap();
        assert!(verify_commitment_consistency(&store, root));
    }

    #[test]
    fn versioned_reads() {
        let mut store = MemoryStore::new();
        let key = make_key(1, 2, 3);

        insert(&mut store, key, vec![10]);
        let v1_root = store.get_root_key(1).unwrap().clone();

        insert(&mut store, key, vec![20]);
        let v2_root = store.get_root_key(2).unwrap().clone();

        assert_eq!(get_value(&store, &v1_root, &key), Some(vec![10]));
        assert_eq!(get_value(&store, &v2_root, &key), Some(vec![20]));
    }

    #[test]
    fn three_way_split() {
        let mut store = MemoryStore::new();
        insert(&mut store, make_key(1, 0, 0), vec![10]);
        insert(&mut store, make_key(2, 0, 0), vec![20]);
        insert(&mut store, make_key(3, 0, 0), vec![30]);

        assert_eq!(get(&store, &make_key(1, 0, 0)), Some(vec![10]));
        assert_eq!(get(&store, &make_key(2, 0, 0)), Some(vec![20]));
        assert_eq!(get(&store, &make_key(3, 0, 0)), Some(vec![30]));
        let root = store.latest_root_key().unwrap();
        assert!(verify_commitment_consistency(&store, root));
    }

    #[test]
    fn many_inserts_commitment_consistency() {
        let mut store = MemoryStore::new();
        for i in 0u8..50 {
            insert(
                &mut store,
                make_key(i, i.wrapping_mul(7), i.wrapping_mul(13)),
                vec![i],
            );
        }
        let root = store.latest_root_key().unwrap();
        assert!(verify_commitment_consistency(&store, root));

        for i in 0u8..50 {
            let key = make_key(i, i.wrapping_mul(7), i.wrapping_mul(13));
            assert_eq!(get(&store, &key), Some(vec![i]));
        }
    }

    #[test]
    fn batch_insert_multiple_keys() {
        let mut store = MemoryStore::new();
        insert_batch(
            &mut store,
            vec![
                (make_key(1, 0, 0), vec![10]),
                (make_key(2, 0, 0), vec![20]),
                (make_key(3, 0, 0), vec![30]),
            ],
        );

        assert_eq!(get(&store, &make_key(1, 0, 0)), Some(vec![10]));
        assert_eq!(get(&store, &make_key(2, 0, 0)), Some(vec![20]));
        assert_eq!(get(&store, &make_key(3, 0, 0)), Some(vec![30]));
        let root = store.latest_root_key().unwrap();
        assert!(verify_commitment_consistency(&store, root));
    }

    #[test]
    fn batch_insert_same_version() {
        let mut store = MemoryStore::new();
        let entries: Vec<(Key, Value)> = (0u8..20)
            .map(|i| (make_key(i, i.wrapping_mul(3), i.wrapping_mul(7)), vec![i]))
            .collect();
        insert_batch(&mut store, entries);

        assert_eq!(store.latest_version(), Some(1)); // single version

        for i in 0u8..20 {
            let key = make_key(i, i.wrapping_mul(3), i.wrapping_mul(7));
            assert_eq!(get(&store, &key), Some(vec![i]));
        }
        let root = store.latest_root_key().unwrap();
        assert!(verify_commitment_consistency(&store, root));
    }
}
