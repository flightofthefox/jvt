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
    debug_assert!(
        updates.keys().all(|k| k.len() >= 2),
        "all keys must be at least 2 bytes (stem + suffix)"
    );

    let current_root_key: Option<NodeKey> = parent_version
        .and_then(|v| store.get_root_key(v))
        .filter(|rk| store.get_node(rk).is_some());

    let mut batch = TreeUpdateBatch::default();
    let updates_ref: Vec<(&Key, &Option<Value>)> = updates.iter().collect();

    let final_root = match current_root_key {
        Some(ref root_key) => {
            batch_apply_node(store, root_key, &updates_ref, 0, new_version, &mut batch)
        }
        None => {
            // Empty tree — filter to inserts only and create from scratch
            let inserts: Vec<(&Key, &Value)> = updates_ref
                .iter()
                .filter_map(|&(k, v)| v.as_ref().map(|val| (k, val)))
                .collect();
            if inserts.is_empty() {
                BatchResult::Removed
            } else {
                let r = batch_create_subtree(&inserts, 0, &[], new_version, &mut batch);
                BatchResult::Changed(r)
            }
        }
    };

    match final_root {
        BatchResult::Changed(r) => {
            batch.root_key = Some((new_version, r.node_key.clone()));
            UpdateResult {
                root_commitment: r.commitment,
                root_key: r.node_key,
                batch,
            }
        }
        BatchResult::Unchanged => {
            // Nothing changed — preserve existing root
            let root_key = current_root_key.unwrap_or_else(|| NodeKey::root(new_version));
            let root_commitment = store
                .get_node(&root_key)
                .map(|n| n.commitment())
                .unwrap_or_else(zero_commitment);
            batch.root_key = Some((new_version, root_key.clone()));
            UpdateResult {
                root_commitment,
                root_key,
                batch,
            }
        }
        BatchResult::Removed => {
            let root_key = NodeKey::root(new_version);
            batch.root_key = Some((new_version, root_key.clone()));
            UpdateResult {
                root_commitment: zero_commitment(),
                root_key,
                batch,
            }
        }
    }
}

/// Get a value from the tree.
pub fn get_value<S: TreeReader>(store: &S, root_key: &NodeKey, key: &Key) -> Option<Value> {
    let root_node = store.get_node(root_key)?;
    get_recursive(&root_node, store, key, 0)
}

/// Verify that all commitments in the tree are consistent (recompute from
/// children/values and compare with stored commitments).
pub fn verify_commitment_consistency<S: TreeReader>(store: &S, root_key: &NodeKey) -> bool {
    verify_node_commitment(store, root_key)
}

/// Get the root commitment for a given version.
pub fn root_commitment_at<S: TreeReader>(store: &S, version: u64) -> Commitment {
    match store.get_root_key(version) {
        Some(ref root_key) => match store.get_node(root_key) {
            Some(node) => node.commitment(),
            None => zero_commitment(),
        },
        None => zero_commitment(),
    }
}

// ============================================================
// Internal: get
// ============================================================

fn get_recursive<S: TreeReader>(node: &Node, store: &S, key: &Key, depth: usize) -> Option<Value> {
    match node {
        Node::EaS(eas) => {
            let expected_stem = &key[depth..key_stem_end(key)];
            if eas.stem == expected_stem {
                eas.values.get(&key_suffix(key)).cloned()
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
            get_recursive(&child_node, store, key, depth + 1)
        }
    }
}

fn verify_node_commitment<S: TreeReader>(store: &S, node_key: &NodeKey) -> bool {
    let node = match store.get_node(node_key) {
        Some(n) => n,
        None => return true,
    };

    match &*node {
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
// Internal: batch tree walk (handles inserts and deletes)
// ============================================================

struct BatchNodeResult {
    node_key: NodeKey,
    commitment: Commitment,
}

enum BatchResult {
    Changed(BatchNodeResult),
    Removed,
    Unchanged,
}

/// Apply a batch of updates (inserts + deletes) to an existing subtree.
fn batch_apply_node<S: TreeReader>(
    store: &S,
    node_key: &NodeKey,
    updates: &[(&Key, &Option<Value>)],
    depth: usize,
    version: u64,
    batch: &mut TreeUpdateBatch,
) -> BatchResult {
    if updates.is_empty() {
        return BatchResult::Unchanged;
    }

    let current_node = store.get_node(node_key).unwrap_or_else(|| {
        panic!("node not found for key {:?} at depth {}", node_key, depth);
    });

    match &*current_node {
        Node::Internal(internal) => {
            batch_apply_internal(store, node_key, internal, updates, depth, version, batch)
        }
        Node::EaS(eas) => batch_apply_eas(node_key, eas, updates, depth, version, batch),
    }
}

/// Batch apply updates to an internal node.
fn batch_apply_internal<S: TreeReader>(
    store: &S,
    node_key: &NodeKey,
    internal: &InternalNode,
    updates: &[(&Key, &Option<Value>)],
    depth: usize,
    version: u64,
    batch: &mut TreeUpdateBatch,
) -> BatchResult {
    let mut new_internal = internal.clone();
    let path = &node_key.byte_path;
    let mut changed = false;

    let mut i = 0;
    while i < updates.len() {
        let child_byte = updates[i].0[depth];
        let mut j = i + 1;
        while j < updates.len() && updates[j].0[depth] == child_byte {
            j += 1;
        }
        let group = &updates[i..j];
        i = j;

        let child_path: Vec<u8> = path
            .iter()
            .chain(std::iter::once(&child_byte))
            .copied()
            .collect();

        if let Some(child) = internal.children.get(&child_byte) {
            let child_key = NodeKey::new(child.version, child_path);
            match batch_apply_node(store, &child_key, group, depth + 1, version, batch) {
                BatchResult::Changed(r) => {
                    new_internal.update_child(child_byte, Child::new(version, r.commitment));
                    changed = true;
                }
                BatchResult::Removed => {
                    new_internal.children.remove(&child_byte);
                    new_internal.commitment =
                        InternalNode::compute_commitment(&new_internal.children);
                    changed = true;
                }
                BatchResult::Unchanged => {}
            }
        } else {
            // No existing child — filter to inserts only
            let inserts: Vec<(&Key, &Value)> = group
                .iter()
                .filter_map(|&(k, v)| v.as_ref().map(|val| (k, val)))
                .collect();
            if !inserts.is_empty() {
                let r = batch_create_subtree(&inserts, depth + 1, &child_path, version, batch);
                new_internal.update_child(child_byte, Child::new(version, r.commitment));
                changed = true;
            }
        }
    }

    if !changed {
        return BatchResult::Unchanged;
    }

    if new_internal.children.is_empty() {
        batch.mark_stale(node_key.clone(), version);
        return BatchResult::Removed;
    }

    // Collapse: single EaS child remaining → merge into one EaS with longer stem
    if new_internal.children.len() == 1 {
        let (&remaining_idx, remaining_child) = new_internal.children.iter().next().unwrap();
        let remaining_path: Vec<u8> = path
            .iter()
            .chain(std::iter::once(&remaining_idx))
            .copied()
            .collect();
        let remaining_key = NodeKey::new(remaining_child.version, remaining_path.clone());

        // Check batch first (child may have been created/modified in this batch),
        // then fall back to store
        let remaining_node = batch
            .new_nodes
            .iter()
            .rev()
            .find(|(nk, _)| *nk == remaining_key)
            .map(|(_, n)| n)
            .cloned()
            .or_else(|| store.get_node(&remaining_key).map(|arc| (*arc).clone()));

        if let Some(Node::EaS(remaining_eas)) = remaining_node.as_ref() {
            let mut new_stem = vec![remaining_idx];
            new_stem.extend_from_slice(&remaining_eas.stem);
            let collapsed = EaSNode::from_values(new_stem, remaining_eas.values.clone());
            let collapsed_key = NodeKey::new(version, path.clone());
            let commitment = collapsed.commitment();
            batch.put_node(collapsed_key.clone(), Node::EaS(Box::new(collapsed)));
            batch.mark_stale(node_key.clone(), version);
            batch.mark_stale(remaining_key, version);
            return BatchResult::Changed(BatchNodeResult {
                node_key: collapsed_key,
                commitment,
            });
        }
    }

    let new_key = NodeKey::new(version, path.clone());
    let commitment = new_internal.commitment;
    batch.put_node(new_key.clone(), Node::Internal(new_internal));
    batch.mark_stale(node_key.clone(), version);

    BatchResult::Changed(BatchNodeResult {
        node_key: new_key,
        commitment,
    })
}

/// Batch apply updates to an EaS node.
fn batch_apply_eas(
    node_key: &NodeKey,
    eas: &EaSNode,
    updates: &[(&Key, &Option<Value>)],
    depth: usize,
    version: u64,
    batch: &mut TreeUpdateBatch,
) -> BatchResult {
    let path = &node_key.byte_path;

    // Partition updates by whether they match the existing stem
    let mut same_stem_inserts: Vec<(u8, &Value)> = Vec::new();
    let mut same_stem_deletes: Vec<u8> = Vec::new();
    let mut divergent_inserts: Vec<(&Key, &Value)> = Vec::new();

    for &(key, value) in updates {
        let expected_stem = &key[depth..key_stem_end(key)];
        if eas.stem == expected_stem {
            match value {
                Some(v) => same_stem_inserts.push((key_suffix(key), v)),
                None => same_stem_deletes.push(key_suffix(key)),
            }
        } else if let Some(v) = value {
            divergent_inserts.push((key, v));
        }
        // Divergent deletes are no-ops (key doesn't exist)
    }

    if divergent_inserts.is_empty() {
        // All updates target the existing stem
        if same_stem_inserts.is_empty() && same_stem_deletes.is_empty() {
            return BatchResult::Unchanged;
        }

        let mut new_values = eas.values.clone();
        for suffix in &same_stem_deletes {
            new_values.remove(suffix);
        }
        // Check: did deletes remove values that inserts will re-add?
        // Apply inserts after deletes so inserts win
        for &(suffix, value) in &same_stem_inserts {
            new_values.insert(suffix, value.clone());
        }

        if new_values.is_empty() {
            batch.mark_stale(node_key.clone(), version);
            return BatchResult::Removed;
        }

        // Use homomorphic updates for pure inserts/updates on existing EaS
        if same_stem_deletes.is_empty() {
            let mut new_eas = (*eas).clone();
            new_eas.batch_update_values(
                same_stem_inserts
                    .iter()
                    .map(|&(suffix, value)| (suffix, value.clone())),
            );
            let new_key = NodeKey::new(version, path.clone());
            let commitment = new_eas.commitment();
            batch.put_node(new_key.clone(), Node::EaS(Box::new(new_eas)));
            batch.mark_stale(node_key.clone(), version);
            return BatchResult::Changed(BatchNodeResult {
                node_key: new_key,
                commitment,
            });
        }

        // Deletes present — recompute from scratch (simpler than tracking deltas)
        let new_eas = EaSNode::from_values(eas.stem.clone(), new_values);
        let new_key = NodeKey::new(version, path.clone());
        let commitment = new_eas.commitment();
        batch.put_node(new_key.clone(), Node::EaS(Box::new(new_eas)));
        batch.mark_stale(node_key.clone(), version);
        return BatchResult::Changed(BatchNodeResult {
            node_key: new_key,
            commitment,
        });
    }

    // Divergent inserts exist — rebuild the subtree from scratch.
    // Collect all surviving values (existing + inserts - deletes) as synthetic keys.
    let mut all_keys_and_values: Vec<(Key, Value)> = Vec::new();

    // Existing EaS values
    let delete_set: std::collections::HashSet<u8> = same_stem_deletes.iter().copied().collect();
    for (&suffix, value) in &eas.values {
        if !delete_set.contains(&suffix) {
            let mut full_key = path.to_vec();
            full_key.extend_from_slice(&eas.stem);
            full_key.push(suffix);
            all_keys_and_values.push((full_key, value.clone()));
        }
    }
    // Same-stem inserts (override any existing)
    for &(suffix, value) in &same_stem_inserts {
        let mut full_key = path.to_vec();
        full_key.extend_from_slice(&eas.stem);
        full_key.push(suffix);
        all_keys_and_values.push((full_key, value.clone()));
    }
    // Divergent inserts
    for &(key, value) in &divergent_inserts {
        all_keys_and_values.push((key.clone(), value.clone()));
    }

    all_keys_and_values.sort_by(|a, b| a.0.cmp(&b.0));
    all_keys_and_values.dedup_by(|a, b| {
        if a.0 == b.0 {
            std::mem::swap(&mut a.1, &mut b.1);
            true
        } else {
            false
        }
    });

    batch.mark_stale(node_key.clone(), version);

    if all_keys_and_values.is_empty() {
        return BatchResult::Removed;
    }

    let refs: Vec<(&Key, &Value)> = all_keys_and_values.iter().map(|(k, v)| (k, v)).collect();
    let result = batch_create_subtree(&refs, depth, path, version, batch);
    BatchResult::Changed(result)
}

/// Create a new subtree from scratch for a set of inserts.
fn batch_create_subtree(
    inserts: &[(&Key, &Value)],
    depth: usize,
    node_path: &[u8],
    version: u64,
    batch: &mut TreeUpdateBatch,
) -> BatchNodeResult {
    debug_assert!(!inserts.is_empty());

    let first_stem = &inserts[0].0[depth..key_stem_end(inserts[0].0)];
    let all_same_stem = inserts
        .iter()
        .all(|(k, _)| k[depth..key_stem_end(k)] == *first_stem);

    if all_same_stem {
        let stem = first_stem.to_vec();
        let mut values = HashMap::new();
        for (key, value) in inserts {
            values.insert(key_suffix(key), (*value).clone());
        }
        let eas = EaSNode::from_values(stem, values);
        let commitment = eas.commitment();
        let node_key = NodeKey::new(version, node_path.to_vec());
        batch.put_node(node_key.clone(), Node::EaS(Box::new(eas)));
        return BatchNodeResult {
            node_key,
            commitment,
        };
    }

    let mut children = HashMap::new();
    let mut i = 0;
    while i < inserts.len() {
        let child_byte = inserts[i].0[depth];
        let mut j = i + 1;
        while j < inserts.len() && inserts[j].0[depth] == child_byte {
            j += 1;
        }
        let group = &inserts[i..j];
        i = j;

        let child_path: Vec<u8> = node_path
            .iter()
            .chain(std::iter::once(&child_byte))
            .copied()
            .collect();
        let child_result = batch_create_subtree(group, depth + 1, &child_path, version, batch);
        children.insert(child_byte, Child::new(version, child_result.commitment));
    }

    let internal = InternalNode::new(children);
    let commitment = internal.commitment;
    let node_key = NodeKey::new(version, node_path.to_vec());
    batch.put_node(node_key.clone(), Node::Internal(internal));

    BatchNodeResult {
        node_key,
        commitment,
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
        let mut key = vec![0u8; 32];
        key[0] = first;
        key[1] = second;
        key[31] = suffix;
        key
    }

    /// Helper: insert a single key-value into a store, return the result.
    fn insert(store: &mut MemoryStore, key: &Key, value: Value) -> UpdateResult {
        let parent = store.latest_version();
        let new_version = parent.map_or(1, |v| v + 1);
        let mut updates = BTreeMap::new();
        updates.insert(key.clone(), Some(value));
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
        get_value(store, &root_key, key)
    }

    #[test]
    fn insert_and_get_single() {
        let mut store = MemoryStore::new();
        let key = make_key(1, 2, 3);
        insert(&mut store, &key, vec![42]);
        assert_eq!(get(&store, &key), Some(vec![42]));
    }

    #[test]
    fn insert_same_stem_different_suffix() {
        let mut store = MemoryStore::new();
        let key1 = make_key(1, 2, 3);
        let key2 = make_key(1, 2, 4);
        insert(&mut store, &key1, vec![10]);
        insert(&mut store, &key2, vec![20]);
        assert_eq!(get(&store, &key1), Some(vec![10]));
        assert_eq!(get(&store, &key2), Some(vec![20]));
    }

    #[test]
    fn insert_different_first_byte_triggers_split() {
        let mut store = MemoryStore::new();
        insert(&mut store, &make_key(1, 0, 0), vec![10]);
        insert(&mut store, &make_key(2, 0, 0), vec![20]);
        assert_eq!(get(&store, &make_key(1, 0, 0)), Some(vec![10]));
        assert_eq!(get(&store, &make_key(2, 0, 0)), Some(vec![20]));
    }

    #[test]
    fn insert_shared_prefix_split() {
        let mut store = MemoryStore::new();
        insert(&mut store, &make_key(5, 10, 0), vec![100]);
        insert(&mut store, &make_key(5, 20, 0), vec![200]);
        assert_eq!(get(&store, &make_key(5, 10, 0)), Some(vec![100]));
        assert_eq!(get(&store, &make_key(5, 20, 0)), Some(vec![200]));
    }

    #[test]
    fn update_existing_key() {
        let mut store = MemoryStore::new();
        let key = make_key(1, 2, 3);
        insert(&mut store, &key, vec![10]);
        assert_eq!(get(&store, &key), Some(vec![10]));
        insert(&mut store, &key, vec![20]);
        assert_eq!(get(&store, &key), Some(vec![20]));
    }

    #[test]
    fn get_nonexistent_key() {
        let mut store = MemoryStore::new();
        insert(&mut store, &make_key(1, 2, 3), vec![42]);
        assert_eq!(get(&store, &make_key(4, 5, 6)), None);
    }

    #[test]
    fn commitment_changes_on_insert() {
        let mut store = MemoryStore::new();
        assert_eq!(root_commitment_at(&store, 0), zero_commitment());

        let r1 = insert(&mut store, &make_key(1, 0, 0), vec![10]);
        assert_ne!(r1.root_commitment, zero_commitment());

        let r2 = insert(&mut store, &make_key(2, 0, 0), vec![20]);
        assert_ne!(r2.root_commitment, r1.root_commitment);
    }

    #[test]
    fn commitment_consistency_after_operations() {
        let mut store = MemoryStore::new();
        insert(&mut store, &make_key(1, 0, 0), vec![10]);
        insert(&mut store, &make_key(2, 0, 0), vec![20]);
        insert(&mut store, &make_key(1, 5, 0), vec![30]);
        insert(&mut store, &make_key(1, 0, 1), vec![40]);

        let root = store.latest_root_key().unwrap();
        assert!(verify_commitment_consistency(&store, &root));
    }

    #[test]
    fn versioned_reads() {
        let mut store = MemoryStore::new();
        let key = make_key(1, 2, 3);

        insert(&mut store, &key, vec![10]);
        let v1_root = store.get_root_key(1).unwrap().clone();

        insert(&mut store, &key, vec![20]);
        let v2_root = store.get_root_key(2).unwrap().clone();

        assert_eq!(get_value(&store, &v1_root, &key), Some(vec![10]));
        assert_eq!(get_value(&store, &v2_root, &key), Some(vec![20]));
    }

    #[test]
    fn three_way_split() {
        let mut store = MemoryStore::new();
        insert(&mut store, &make_key(1, 0, 0), vec![10]);
        insert(&mut store, &make_key(2, 0, 0), vec![20]);
        insert(&mut store, &make_key(3, 0, 0), vec![30]);

        assert_eq!(get(&store, &make_key(1, 0, 0)), Some(vec![10]));
        assert_eq!(get(&store, &make_key(2, 0, 0)), Some(vec![20]));
        assert_eq!(get(&store, &make_key(3, 0, 0)), Some(vec![30]));
        let root = store.latest_root_key().unwrap();
        assert!(verify_commitment_consistency(&store, &root));
    }

    #[test]
    fn many_inserts_commitment_consistency() {
        let mut store = MemoryStore::new();
        for i in 0u8..50 {
            insert(
                &mut store,
                &make_key(i, i.wrapping_mul(7), i.wrapping_mul(13)),
                vec![i],
            );
        }
        let root = store.latest_root_key().unwrap();
        assert!(verify_commitment_consistency(&store, &root));

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
        assert!(verify_commitment_consistency(&store, &root));
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
        assert!(verify_commitment_consistency(&store, &root));
    }

    // --- Delete tests ---

    /// Helper: delete a key.
    fn delete(store: &mut MemoryStore, key: &Key) {
        let parent = store.latest_version();
        let new_version = parent.map_or(1, |v| v + 1);
        let mut updates = BTreeMap::new();
        updates.insert(key.clone(), None);
        let result = apply_updates(store, parent, new_version, updates);
        store.apply(&result);
    }

    #[test]
    fn delete_single_key() {
        let mut store = MemoryStore::new();
        let key = make_key(1, 0, 0);
        insert(&mut store, &key, vec![42]);
        assert_eq!(get(&store, &key), Some(vec![42]));

        delete(&mut store, &key);
        assert_eq!(get(&store, &key), None);
    }

    #[test]
    fn delete_one_of_two_keys() {
        let mut store = MemoryStore::new();
        let key1 = make_key(1, 0, 0);
        let key2 = make_key(2, 0, 0);
        insert(&mut store, &key1, vec![10]);
        insert(&mut store, &key2, vec![20]);

        delete(&mut store, &key1);

        assert_eq!(get(&store, &key1), None);
        assert_eq!(get(&store, &key2), Some(vec![20]));

        let root = store.latest_root_key().unwrap();
        assert!(verify_commitment_consistency(&store, &root));
    }

    #[test]
    fn delete_triggers_collapse() {
        let mut store = MemoryStore::new();
        // Create an internal node with two EaS children
        let key1 = make_key(1, 0, 0);
        let key2 = make_key(2, 0, 0);
        insert(&mut store, &key1, vec![10]);
        insert(&mut store, &key2, vec![20]);

        // Delete one — should collapse the internal node back to a single EaS
        delete(&mut store, &key1);

        // key2 should still work
        assert_eq!(get(&store, &key2), Some(vec![20]));
        let root = store.latest_root_key().unwrap();
        assert!(verify_commitment_consistency(&store, &root));

        // The root should be an EaS now (collapsed), not an internal node
        let root_node = store.get_node(&root).unwrap();
        assert!(matches!(&*root_node, Node::EaS(_)));
    }

    #[test]
    fn delete_nonexistent_key_is_noop() {
        let mut store = MemoryStore::new();
        insert(&mut store, &make_key(1, 0, 0), vec![10]);
        let _v_before = store.latest_version();

        delete(&mut store, &make_key(99, 0, 0));

        // Version still advances (the update was applied), but tree is unchanged
        assert_eq!(get(&store, &make_key(1, 0, 0)), Some(vec![10]));
    }

    #[test]
    fn delete_same_stem_different_suffix() {
        let mut store = MemoryStore::new();
        let mut key1 = vec![0u8; 32];
        key1[0] = 1;
        key1[31] = 10;
        let mut key2 = vec![0u8; 32];
        key2[0] = 1;
        key2[31] = 20;

        insert(&mut store, &key1, vec![100]);
        insert(&mut store, &key2, vec![200]);

        // Delete one suffix, keep the other
        delete(&mut store, &key1);

        assert_eq!(get(&store, &key1), None);
        assert_eq!(get(&store, &key2), Some(vec![200]));
        let root = store.latest_root_key().unwrap();
        assert!(verify_commitment_consistency(&store, &root));
    }

    #[test]
    fn delete_all_keys() {
        let mut store = MemoryStore::new();
        let key1 = make_key(1, 0, 0);
        let key2 = make_key(2, 0, 0);
        insert(&mut store, &key1, vec![10]);
        insert(&mut store, &key2, vec![20]);

        delete(&mut store, &key1);
        delete(&mut store, &key2);

        assert_eq!(get(&store, &key1), None);
        assert_eq!(get(&store, &key2), None);
    }

    #[test]
    fn insert_after_delete() {
        let mut store = MemoryStore::new();
        let key = make_key(1, 0, 0);

        insert(&mut store, &key, vec![10]);
        delete(&mut store, &key);
        assert_eq!(get(&store, &key), None);

        insert(&mut store, &key, vec![20]);
        assert_eq!(get(&store, &key), Some(vec![20]));

        let root = store.latest_root_key().unwrap();
        assert!(verify_commitment_consistency(&store, &root));
    }

    #[test]
    fn batch_insert_and_delete() {
        let mut store = MemoryStore::new();
        insert(&mut store, &make_key(1, 0, 0), vec![10]);
        insert(&mut store, &make_key(2, 0, 0), vec![20]);
        insert(&mut store, &make_key(3, 0, 0), vec![30]);

        // Batch: delete key1, update key2, insert key4
        let parent = store.latest_version();
        let new_version = parent.map_or(1, |v| v + 1);
        let mut updates = BTreeMap::new();
        updates.insert(make_key(1, 0, 0), None);
        updates.insert(make_key(2, 0, 0), Some(vec![99]));
        updates.insert(make_key(4, 0, 0), Some(vec![40]));
        let result = apply_updates(&store, parent, new_version, updates);
        store.apply(&result);

        assert_eq!(get(&store, &make_key(1, 0, 0)), None);
        assert_eq!(get(&store, &make_key(2, 0, 0)), Some(vec![99]));
        assert_eq!(get(&store, &make_key(3, 0, 0)), Some(vec![30]));
        assert_eq!(get(&store, &make_key(4, 0, 0)), Some(vec![40]));

        let root = store.latest_root_key().unwrap();
        assert!(verify_commitment_consistency(&store, &root));
    }

    // --- Iterator tests ---

    #[test]
    fn iter_all_leaves() {
        use crate::storage::TreeIterator;

        let mut store = MemoryStore::new();
        insert(&mut store, &make_key(3, 0, 0), vec![30]);
        insert(&mut store, &make_key(1, 0, 0), vec![10]);
        insert(&mut store, &make_key(2, 0, 0), vec![20]);

        let root = store.latest_root_key().unwrap();
        let leaves: Vec<_> = store.iter_leaves(&root, None).collect();

        // Should be sorted lexicographically by key
        assert_eq!(leaves.len(), 3);
        assert_eq!(leaves[0].0[0], 1);
        assert_eq!(leaves[0].1, vec![10]);
        assert_eq!(leaves[1].0[0], 2);
        assert_eq!(leaves[1].1, vec![20]);
        assert_eq!(leaves[2].0[0], 3);
        assert_eq!(leaves[2].1, vec![30]);
    }

    #[test]
    fn iter_from_key() {
        use crate::storage::TreeIterator;

        let mut store = MemoryStore::new();
        for i in 0u8..10 {
            insert(&mut store, &make_key(i, 0, 0), vec![i]);
        }

        let root = store.latest_root_key().unwrap();

        // From key 5 onwards
        let from = make_key(5, 0, 0);
        let leaves: Vec<_> = store.iter_leaves(&root, Some(&from)).collect();

        assert_eq!(leaves.len(), 5); // keys 5, 6, 7, 8, 9
        assert_eq!(leaves[0].0[0], 5);
        assert_eq!(leaves[4].0[0], 9);
    }

    #[test]
    fn iter_same_stem_multiple_suffixes() {
        use crate::storage::TreeIterator;

        let mut store = MemoryStore::new();
        // All same stem, different suffixes
        for suffix in [3u8, 1, 4, 1, 5, 9, 2, 6] {
            let mut key = vec![0u8; 32];
            key[0] = 0xAA;
            key[31] = suffix;
            insert(&mut store, &key, vec![suffix]);
        }

        let root = store.latest_root_key().unwrap();
        let leaves: Vec<_> = store.iter_leaves(&root, None).collect();

        // Deduplicated (suffix 1 inserted twice) and sorted by suffix
        let suffixes: Vec<u8> = leaves.iter().map(|(k, _)| k[31]).collect();
        assert_eq!(suffixes, vec![1, 2, 3, 4, 5, 6, 9]);
    }

    #[test]
    fn iter_empty_tree() {
        use crate::storage::TreeIterator;

        let mut store = MemoryStore::new();
        insert(&mut store, &make_key(1, 0, 0), vec![10]);
        delete(&mut store, &make_key(1, 0, 0));

        let root = store.latest_root_key().unwrap();
        let leaves: Vec<_> = store.iter_leaves(&root, None).collect();
        assert_eq!(leaves.len(), 0);
    }

    #[test]
    fn iter_after_deletes() {
        use crate::storage::TreeIterator;

        let mut store = MemoryStore::new();
        for i in 0u8..5 {
            insert(&mut store, &make_key(i, 0, 0), vec![i]);
        }
        delete(&mut store, &make_key(1, 0, 0));
        delete(&mut store, &make_key(3, 0, 0));

        let root = store.latest_root_key().unwrap();
        let leaves: Vec<_> = store.iter_leaves(&root, None).collect();

        assert_eq!(leaves.len(), 3);
        assert_eq!(leaves[0].0[0], 0);
        assert_eq!(leaves[1].0[0], 2);
        assert_eq!(leaves[2].0[0], 4);
    }
}
