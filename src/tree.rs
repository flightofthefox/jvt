//! Core JVT operations: apply_updates, get_committed_value, verify_commitment_consistency.
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
pub fn apply_updates<S: TreeReader + Sync>(
    store: &S,
    parent_version: Option<u64>,
    new_version: u64,
    updates: BTreeMap<Key, Option<Value>>,
) -> UpdateResult {
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
pub fn get_committed_value<S: TreeReader + Sync>(
    store: &S,
    root_key: &NodeKey,
    key: &Key,
) -> Option<Value> {
    let root_node = store.get_node(root_key)?;
    get_recursive(&root_node, store, key, 0)
}

/// Verify that all commitments in the tree are consistent (recompute from
/// children/values and compare with stored commitments).
pub fn verify_commitment_consistency<S: TreeReader + Sync>(store: &S, root_key: &NodeKey) -> bool {
    verify_node_commitment(store, root_key)
}

/// Get the root commitment for a given version.
pub fn root_commitment_at<S: TreeReader + Sync>(store: &S, version: u64) -> Commitment {
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

fn get_recursive<S: TreeReader + Sync>(
    node: &Node,
    store: &S,
    key: &Key,
    depth: usize,
) -> Option<Value> {
    match node {
        Node::EaS(eas) => {
            let expected_stem = &key[depth..SUFFIX_INDEX];
            if eas.stem == expected_stem {
                eas.values.get(&key_suffix(key)).cloned()
            } else {
                None
            }
        }
        Node::Internal(n) => {
            let child_index = key[depth];
            let child = n.children.get(&child_index)?;
            let child_key = NodeKey::new(child.version, &key[..depth + 1]);
            let child_node = store.get_node(&child_key)?;
            get_recursive(&child_node, store, key, depth + 1)
        }
    }
}

fn verify_node_commitment<S: TreeReader + Sync>(store: &S, node_key: &NodeKey) -> bool {
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
                let child_key = node_key.child(child.version, idx);
                if !verify_node_commitment(store, &child_key) {
                    return false;
                }
            }
            true
        }
        Node::EaS(eas) => {
            let c1 = EaSNode::compute_c1(&eas.values);
            let c2 = EaSNode::compute_c2(&eas.values);
            let c1_field = commitment_to_field(c1);
            let c2_field = commitment_to_field(c2);
            let stem_c = EaSNode::compute_stem_commitment(&eas.stem);
            let ext = EaSNode::compute_extension_commitment_from_stem_cached(
                stem_c,
                eas.stem.len(),
                c1_field,
                c2_field,
            );
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
fn batch_apply_node<S: TreeReader + Sync>(
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
fn batch_apply_internal<S: TreeReader + Sync>(
    store: &S,
    node_key: &NodeKey,
    internal: &InternalNode,
    updates: &[(&Key, &Option<Value>)],
    depth: usize,
    version: u64,
    batch: &mut TreeUpdateBatch,
) -> BatchResult {
    let path = &node_key.byte_path();

    // Collect child updates/removals first (reads only from `internal`),
    // then clone and mutate only if something changed.
    // Partition updates into per-child groups
    enum ChildGroup<'a> {
        Existing {
            child_byte: u8,
            child_key: NodeKey,
            group: &'a [(&'a Key, &'a Option<Value>)],
        },
        New {
            child_byte: u8,
            inserts: Vec<(&'a Key, &'a Value)>,
        },
    }

    let mut child_groups: Vec<ChildGroup> = Vec::new();
    let mut i = 0;
    while i < updates.len() {
        let child_byte = updates[i].0[depth];
        let mut j = i + 1;
        while j < updates.len() && updates[j].0[depth] == child_byte {
            j += 1;
        }
        let group = &updates[i..j];
        i = j;

        if let Some(child) = internal.children.get(&child_byte) {
            child_groups.push(ChildGroup::Existing {
                child_byte,
                child_key: node_key.child(child.version, child_byte),
                group,
            });
        } else {
            let inserts: Vec<(&Key, &Value)> = group
                .iter()
                .filter_map(|&(k, v)| v.as_ref().map(|val| (k, val)))
                .collect();
            if !inserts.is_empty() {
                child_groups.push(ChildGroup::New {
                    child_byte,
                    inserts,
                });
            }
        }
    }

    enum ChildOutcome {
        Changed(u8, Commitment, TreeUpdateBatch),
        Removed(u8, TreeUpdateBatch),
        Unchanged,
    }

    // Process child groups — each is independent, parallelize when enabled.
    #[cfg(feature = "parallel")]
    let outcomes: Vec<ChildOutcome> = {
        use rayon::prelude::*;
        child_groups
            .par_iter()
            .map(|cg| {
                let mut child_batch = TreeUpdateBatch::default();
                match cg {
                    ChildGroup::Existing {
                        child_byte,
                        child_key,
                        group,
                    } => {
                        match batch_apply_node(
                            store,
                            child_key,
                            group,
                            depth + 1,
                            version,
                            &mut child_batch,
                        ) {
                            BatchResult::Changed(r) => {
                                ChildOutcome::Changed(*child_byte, r.commitment, child_batch)
                            }
                            BatchResult::Removed => ChildOutcome::Removed(*child_byte, child_batch),
                            BatchResult::Unchanged => ChildOutcome::Unchanged,
                        }
                    }
                    ChildGroup::New {
                        child_byte,
                        inserts,
                    } => {
                        let child_nk = node_key.child(version, *child_byte);
                        let r = batch_create_subtree(
                            inserts,
                            depth + 1,
                            child_nk.byte_path(),
                            version,
                            &mut child_batch,
                        );
                        ChildOutcome::Changed(*child_byte, r.commitment, child_batch)
                    }
                }
            })
            .collect()
    };
    #[cfg(not(feature = "parallel"))]
    let outcomes: Vec<ChildOutcome> = child_groups
        .iter()
        .map(|cg| {
            let mut child_batch = TreeUpdateBatch::default();
            match cg {
                ChildGroup::Existing {
                    child_byte,
                    child_key,
                    group,
                } => {
                    match batch_apply_node(
                        store,
                        child_key,
                        group,
                        depth + 1,
                        version,
                        &mut child_batch,
                    ) {
                        BatchResult::Changed(r) => {
                            ChildOutcome::Changed(*child_byte, r.commitment, child_batch)
                        }
                        BatchResult::Removed => ChildOutcome::Removed(*child_byte, child_batch),
                        BatchResult::Unchanged => ChildOutcome::Unchanged,
                    }
                }
                ChildGroup::New {
                    child_byte,
                    inserts,
                } => {
                    let child_nk = node_key.child(version, *child_byte);
                    let r = batch_create_subtree(
                        inserts,
                        depth + 1,
                        child_nk.byte_path(),
                        version,
                        &mut child_batch,
                    );
                    ChildOutcome::Changed(*child_byte, r.commitment, child_batch)
                }
            }
        })
        .collect();

    let mut child_updates: Vec<(u8, u64, Commitment)> = Vec::new();
    let mut removals: Vec<u8> = Vec::new();
    for outcome in outcomes {
        match outcome {
            ChildOutcome::Changed(child_byte, commitment, child_batch) => {
                child_updates.push((child_byte, version, commitment));
                batch.merge(child_batch);
            }
            ChildOutcome::Removed(child_byte, child_batch) => {
                removals.push(child_byte);
                batch.merge(child_batch);
            }
            ChildOutcome::Unchanged => {}
        }
    }

    if child_updates.is_empty() && removals.is_empty() {
        return BatchResult::Unchanged;
    }

    // Clone only when we know the node is changing.
    let mut new_internal = internal.clone();

    // Apply removals first (they affect the children map for batch_update_children)
    for idx in &removals {
        new_internal.children.remove(idx);
    }
    if !removals.is_empty() {
        // Recompute from scratch after removals (sparse children change)
        new_internal.commitment = InternalNode::compute_commitment(&new_internal.children);
    }

    // Apply updates in batch — single projective accumulation
    if !child_updates.is_empty() {
        new_internal.batch_update_children(child_updates);
    }

    if new_internal.children.is_empty() {
        batch.mark_stale(node_key.clone(), version);
        return BatchResult::Removed;
    }

    // Collapse: single EaS child remaining → merge into one EaS with longer stem
    if new_internal.children.len() == 1 {
        let (&remaining_idx, remaining_child) = new_internal.children.iter().next().unwrap();
        let remaining_key = node_key.child(remaining_child.version, remaining_idx);

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
            let collapsed = remaining_eas.with_prepended_stem(remaining_idx);
            let collapsed_key = NodeKey::new(version, path);
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

    let new_key = NodeKey::new(version, path);
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
    let path = &node_key.byte_path();

    // Partition updates by whether they match the existing stem
    let mut same_stem_inserts: Vec<(u8, &Value)> = Vec::new();
    let mut same_stem_deletes: Vec<u8> = Vec::new();
    let mut divergent_inserts: Vec<(&Key, &Value)> = Vec::new();

    for &(key, value) in updates {
        let expected_stem = &key[depth..SUFFIX_INDEX];
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

        // Homomorphic updates for inserts and deletes on existing EaS.
        // Delete is commit_update(c, idx, old, zero) — same math as insert.
        let mut new_eas = (*eas).clone();
        let updates = same_stem_deletes
            .iter()
            .map(|&suffix| (suffix, None))
            .chain(
                same_stem_inserts
                    .iter()
                    .map(|&(suffix, value)| (suffix, Some(*value))),
            );
        new_eas.batch_update_values(updates);

        if new_eas.values.is_empty() {
            batch.mark_stale(node_key.clone(), version);
            return BatchResult::Removed;
        }

        let new_key = NodeKey::new(version, path);
        let commitment = new_eas.commitment();
        batch.put_node(new_key.clone(), Node::EaS(Box::new(new_eas)));
        batch.mark_stale(node_key.clone(), version);
        return BatchResult::Changed(BatchNodeResult {
            node_key: new_key,
            commitment,
        });
    }

    // Divergent inserts exist — incremental split preserving c1/c2.
    // Instead of flattening all values and rebuilding from scratch (which
    // recomputes c1/c2 MSMs over all existing values), we apply same-stem
    // modifications homomorphically and re-stem the existing EaS at the
    // split point. Only the stem and extension commitments are recomputed.
    batch.mark_stale(node_key.clone(), version);

    if same_stem_inserts.is_empty() && same_stem_deletes.is_empty() {
        // No same-stem modifications — split directly, no clone needed.
        let result =
            split_eas_with_inserts(eas, 0, &divergent_inserts, depth, path, version, batch);
        return BatchResult::Changed(result);
    }

    // Apply same-stem modifications homomorphically.
    let mut modified = (*eas).clone();
    let mods = same_stem_deletes
        .iter()
        .map(|&suffix| (suffix, None))
        .chain(
            same_stem_inserts
                .iter()
                .map(|&(suffix, value)| (suffix, Some(*value))),
        );
    modified.batch_update_values(mods);

    if modified.values.is_empty() {
        // All existing values deleted — build from divergent inserts only.
        let result = batch_create_subtree(&divergent_inserts, depth, path, version, batch);
        return BatchResult::Changed(result);
    }

    let result = split_eas_with_inserts(
        &modified,
        0,
        &divergent_inserts,
        depth,
        path,
        version,
        batch,
    );
    BatchResult::Changed(result)
}

/// Split an existing EaS node with divergent inserts, preserving c1/c2.
///
/// Walks down the EaS stem one byte at a time. At each level, divergent keys
/// that differ at this byte are split off into new subtrees via
/// `batch_create_subtree`. Keys that share the byte recurse deeper. When no
/// more divergent keys share the current stem byte, the existing EaS is placed
/// directly with a trimmed stem — its c1/c2 sub-commitments are preserved,
/// avoiding expensive MSM recomputation.
fn split_eas_with_inserts(
    eas: &EaSNode,
    stem_offset: usize,
    divergent_inserts: &[(&Key, &Value)],
    depth: usize,
    node_path: &[u8],
    version: u64,
    batch: &mut TreeUpdateBatch,
) -> BatchNodeResult {
    debug_assert!(!divergent_inserts.is_empty());
    debug_assert!(stem_offset < eas.stem.len());

    let eas_byte = eas.stem[stem_offset];
    let parent_nk = NodeKey::new(version, node_path);

    // Group divergent inserts by key[depth] — they're sorted, so groups are contiguous.
    // Separate the cohabitant group (shares eas_byte) from purely divergent groups.
    let mut divergent_groups: Vec<(u8, &[(&Key, &Value)])> = Vec::new();
    let mut cohabitants: Option<&[(&Key, &Value)]> = None;

    let mut i = 0;
    while i < divergent_inserts.len() {
        let byte = divergent_inserts[i].0[depth];
        let mut j = i + 1;
        while j < divergent_inserts.len() && divergent_inserts[j].0[depth] == byte {
            j += 1;
        }
        let group = &divergent_inserts[i..j];

        if byte == eas_byte {
            cohabitants = Some(group);
        } else {
            divergent_groups.push((byte, group));
        }

        i = j;
    }

    // Each work item produces (byte, commitment, batch). The divergent groups
    // and the EaS slot are independent, so all can run in parallel.
    enum SplitWork<'a> {
        /// Divergent group — build subtree from scratch.
        Divergent(u8, &'a [(&'a Key, &'a Value)]),
        /// EaS slot with cohabitants — recurse deeper.
        EasRecurse(&'a [(&'a Key, &'a Value)]),
        /// EaS slot without cohabitants — place re-stemmed EaS directly.
        EasPlace,
    }

    let mut work_items: Vec<SplitWork> = divergent_groups
        .iter()
        .map(|&(byte, group)| SplitWork::Divergent(byte, group))
        .collect();

    match cohabitants {
        Some(group) => work_items.push(SplitWork::EasRecurse(group)),
        None => work_items.push(SplitWork::EasPlace),
    }

    let process_item = |item: &SplitWork| -> (u8, Commitment, TreeUpdateBatch) {
        let mut child_batch = TreeUpdateBatch::default();
        match item {
            SplitWork::Divergent(byte, group) => {
                let child_nk = parent_nk.child(version, *byte);
                let result = batch_create_subtree(
                    group,
                    depth + 1,
                    child_nk.byte_path(),
                    version,
                    &mut child_batch,
                );
                (*byte, result.commitment, child_batch)
            }
            SplitWork::EasRecurse(group) => {
                let child_nk = parent_nk.child(version, eas_byte);
                let result = split_eas_with_inserts(
                    eas,
                    stem_offset + 1,
                    group,
                    depth + 1,
                    child_nk.byte_path(),
                    version,
                    &mut child_batch,
                );
                (eas_byte, result.commitment, child_batch)
            }
            SplitWork::EasPlace => {
                let trimmed = eas.with_trimmed_stem(stem_offset + 1);
                let commitment = trimmed.commitment();
                let eas_child_nk = parent_nk.child(version, eas_byte);
                child_batch.put_node(eas_child_nk, Node::EaS(Box::new(trimmed)));
                (eas_byte, commitment, child_batch)
            }
        }
    };

    #[cfg(feature = "parallel")]
    let child_results: Vec<(u8, Commitment, TreeUpdateBatch)> = {
        use rayon::prelude::*;
        work_items.par_iter().map(process_item).collect()
    };
    #[cfg(not(feature = "parallel"))]
    let child_results: Vec<(u8, Commitment, TreeUpdateBatch)> =
        work_items.iter().map(process_item).collect();

    // Batch commitment_to_field for all children (1 inversion instead of N).
    let child_commitments: Vec<Commitment> = child_results.iter().map(|(_, c, _)| *c).collect();
    let fields = batch_commitment_to_field(&child_commitments);

    let mut children = HashMap::new();
    for (i, (byte, commitment, child_batch)) in child_results.into_iter().enumerate() {
        children.insert(byte, Child::new_with_field(version, commitment, fields[i]));
        batch.merge(child_batch);
    }

    let internal = InternalNode::new(children);
    let commitment = internal.commitment;
    batch.put_node(parent_nk.clone(), Node::Internal(internal));

    BatchNodeResult {
        node_key: parent_nk,
        commitment,
    }
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

    let first_stem = &inserts[0].0[depth..SUFFIX_INDEX];
    let all_same_stem = inserts
        .iter()
        .all(|(k, _)| k[depth..SUFFIX_INDEX] == *first_stem);

    if all_same_stem {
        let stem = first_stem.to_vec();
        let mut values = HashMap::new();
        for (key, value) in inserts {
            values.insert(key_suffix(key), *(*value));
        }
        let eas = EaSNode::from_values(stem, values);
        let commitment = eas.commitment();
        let node_key = NodeKey::new(version, node_path);
        batch.put_node(node_key.clone(), Node::EaS(Box::new(eas)));
        return BatchNodeResult {
            node_key,
            commitment,
        };
    }

    let parent_nk = NodeKey::new(version, node_path);

    // Partition inserts into per-child groups
    let mut groups: Vec<(u8, &[(&Key, &Value)])> = Vec::new();
    let mut i = 0;
    while i < inserts.len() {
        let child_byte = inserts[i].0[depth];
        let mut j = i + 1;
        while j < inserts.len() && inserts[j].0[depth] == child_byte {
            j += 1;
        }
        groups.push((child_byte, &inserts[i..j]));
        i = j;
    }

    // Build child subtrees — each is independent, so parallelize when enabled.
    #[cfg(feature = "parallel")]
    let child_results: Vec<(u8, BatchNodeResult, TreeUpdateBatch)> = {
        use rayon::prelude::*;
        groups
            .par_iter()
            .map(|&(child_byte, group)| {
                let child_nk = parent_nk.child(version, child_byte);
                let mut child_batch = TreeUpdateBatch::default();
                let result = batch_create_subtree(
                    group,
                    depth + 1,
                    child_nk.byte_path(),
                    version,
                    &mut child_batch,
                );
                (child_byte, result, child_batch)
            })
            .collect()
    };
    #[cfg(not(feature = "parallel"))]
    let child_results: Vec<(u8, BatchNodeResult, TreeUpdateBatch)> = groups
        .iter()
        .map(|&(child_byte, group)| {
            let child_nk = parent_nk.child(version, child_byte);
            let mut child_batch = TreeUpdateBatch::default();
            let result = batch_create_subtree(
                group,
                depth + 1,
                child_nk.byte_path(),
                version,
                &mut child_batch,
            );
            (child_byte, result, child_batch)
        })
        .collect();

    // Batch-convert child commitments to field elements (1 inversion instead of N)
    let child_commitments: Vec<Commitment> =
        child_results.iter().map(|(_, r, _)| r.commitment).collect();
    let child_fields = batch_commitment_to_field(&child_commitments);

    let mut children = HashMap::new();
    for (i, (child_byte, _result, child_batch)) in child_results.into_iter().enumerate() {
        children.insert(
            child_byte,
            Child::new_with_field(version, child_commitments[i], child_fields[i]),
        );
        batch.merge(child_batch);
    }

    let internal = InternalNode::new(children);
    let commitment = internal.commitment;
    let node_key = parent_nk;
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
        let mut key = [0u8; 32];
        key[0] = first;
        key[1] = second;
        key[SUFFIX_INDEX] = suffix;
        key
    }

    fn v(n: u8) -> Value {
        value_to_field(&[n])
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
        get_committed_value(store, &root_key, key)
    }

    #[test]
    fn insert_and_get_single() {
        let mut store = MemoryStore::new();
        let key = make_key(1, 2, 3);
        insert(&mut store, &key, v(42));
        assert_eq!(get(&store, &key), Some(v(42)));
    }

    #[test]
    fn insert_same_stem_different_suffix() {
        let mut store = MemoryStore::new();
        let key1 = make_key(1, 2, 3);
        let key2 = make_key(1, 2, 4);
        insert(&mut store, &key1, v(10));
        insert(&mut store, &key2, v(20));
        assert_eq!(get(&store, &key1), Some(v(10)));
        assert_eq!(get(&store, &key2), Some(v(20)));
    }

    #[test]
    fn insert_different_first_byte_triggers_split() {
        let mut store = MemoryStore::new();
        insert(&mut store, &make_key(1, 0, 0), v(10));
        insert(&mut store, &make_key(2, 0, 0), v(20));
        assert_eq!(get(&store, &make_key(1, 0, 0)), Some(v(10)));
        assert_eq!(get(&store, &make_key(2, 0, 0)), Some(v(20)));
    }

    #[test]
    fn insert_shared_prefix_split() {
        let mut store = MemoryStore::new();
        insert(&mut store, &make_key(5, 10, 0), v(100));
        insert(&mut store, &make_key(5, 20, 0), v(200));
        assert_eq!(get(&store, &make_key(5, 10, 0)), Some(v(100)));
        assert_eq!(get(&store, &make_key(5, 20, 0)), Some(v(200)));
    }

    #[test]
    fn update_existing_key() {
        let mut store = MemoryStore::new();
        let key = make_key(1, 2, 3);
        insert(&mut store, &key, v(10));
        assert_eq!(get(&store, &key), Some(v(10)));
        insert(&mut store, &key, v(20));
        assert_eq!(get(&store, &key), Some(v(20)));
    }

    #[test]
    fn get_nonexistent_key() {
        let mut store = MemoryStore::new();
        insert(&mut store, &make_key(1, 2, 3), v(42));
        assert_eq!(get(&store, &make_key(4, 5, 6)), None);
    }

    #[test]
    fn commitment_changes_on_insert() {
        let mut store = MemoryStore::new();
        assert_eq!(root_commitment_at(&store, 0), zero_commitment());

        let r1 = insert(&mut store, &make_key(1, 0, 0), v(10));
        assert_ne!(r1.root_commitment, zero_commitment());

        let r2 = insert(&mut store, &make_key(2, 0, 0), v(20));
        assert_ne!(r2.root_commitment, r1.root_commitment);
    }

    #[test]
    fn commitment_consistency_after_operations() {
        let mut store = MemoryStore::new();
        insert(&mut store, &make_key(1, 0, 0), v(10));
        insert(&mut store, &make_key(2, 0, 0), v(20));
        insert(&mut store, &make_key(1, 5, 0), v(30));
        insert(&mut store, &make_key(1, 0, 1), v(40));

        let root = store.latest_root_key().unwrap();
        assert!(verify_commitment_consistency(&store, &root));
    }

    #[test]
    fn versioned_reads() {
        let mut store = MemoryStore::new();
        let key = make_key(1, 2, 3);

        insert(&mut store, &key, v(10));
        let v1_root = store.get_root_key(1).unwrap().clone();

        insert(&mut store, &key, v(20));
        let v2_root = store.get_root_key(2).unwrap().clone();

        assert_eq!(get_committed_value(&store, &v1_root, &key), Some(v(10)));
        assert_eq!(get_committed_value(&store, &v2_root, &key), Some(v(20)));
    }

    #[test]
    fn three_way_split() {
        let mut store = MemoryStore::new();
        insert(&mut store, &make_key(1, 0, 0), v(10));
        insert(&mut store, &make_key(2, 0, 0), v(20));
        insert(&mut store, &make_key(3, 0, 0), v(30));

        assert_eq!(get(&store, &make_key(1, 0, 0)), Some(v(10)));
        assert_eq!(get(&store, &make_key(2, 0, 0)), Some(v(20)));
        assert_eq!(get(&store, &make_key(3, 0, 0)), Some(v(30)));
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
                v(i),
            );
        }
        let root = store.latest_root_key().unwrap();
        assert!(verify_commitment_consistency(&store, &root));

        for i in 0u8..50 {
            let key = make_key(i, i.wrapping_mul(7), i.wrapping_mul(13));
            assert_eq!(get(&store, &key), Some(v(i)));
        }
    }

    #[test]
    fn batch_insert_multiple_keys() {
        let mut store = MemoryStore::new();
        insert_batch(
            &mut store,
            vec![
                (make_key(1, 0, 0), v(10)),
                (make_key(2, 0, 0), v(20)),
                (make_key(3, 0, 0), v(30)),
            ],
        );

        assert_eq!(get(&store, &make_key(1, 0, 0)), Some(v(10)));
        assert_eq!(get(&store, &make_key(2, 0, 0)), Some(v(20)));
        assert_eq!(get(&store, &make_key(3, 0, 0)), Some(v(30)));
        let root = store.latest_root_key().unwrap();
        assert!(verify_commitment_consistency(&store, &root));
    }

    #[test]
    fn batch_insert_same_version() {
        let mut store = MemoryStore::new();
        let entries: Vec<(Key, Value)> = (0u8..20)
            .map(|i| (make_key(i, i.wrapping_mul(3), i.wrapping_mul(7)), v(i)))
            .collect();
        insert_batch(&mut store, entries);

        assert_eq!(store.latest_version(), Some(1)); // single version

        for i in 0u8..20 {
            let key = make_key(i, i.wrapping_mul(3), i.wrapping_mul(7));
            assert_eq!(get(&store, &key), Some(v(i)));
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
        insert(&mut store, &key, v(42));
        assert_eq!(get(&store, &key), Some(v(42)));

        delete(&mut store, &key);
        assert_eq!(get(&store, &key), None);
    }

    #[test]
    fn delete_one_of_two_keys() {
        let mut store = MemoryStore::new();
        let key1 = make_key(1, 0, 0);
        let key2 = make_key(2, 0, 0);
        insert(&mut store, &key1, v(10));
        insert(&mut store, &key2, v(20));

        delete(&mut store, &key1);

        assert_eq!(get(&store, &key1), None);
        assert_eq!(get(&store, &key2), Some(v(20)));

        let root = store.latest_root_key().unwrap();
        assert!(verify_commitment_consistency(&store, &root));
    }

    #[test]
    fn delete_triggers_collapse() {
        let mut store = MemoryStore::new();
        // Create an internal node with two EaS children
        let key1 = make_key(1, 0, 0);
        let key2 = make_key(2, 0, 0);
        insert(&mut store, &key1, v(10));
        insert(&mut store, &key2, v(20));

        // Delete one — should collapse the internal node back to a single EaS
        delete(&mut store, &key1);

        // key2 should still work
        assert_eq!(get(&store, &key2), Some(v(20)));
        let root = store.latest_root_key().unwrap();
        assert!(verify_commitment_consistency(&store, &root));

        // The root should be an EaS now (collapsed), not an internal node
        let root_node = store.get_node(&root).unwrap();
        assert!(matches!(&*root_node, Node::EaS(_)));
    }

    #[test]
    fn delete_nonexistent_key_is_noop() {
        let mut store = MemoryStore::new();
        insert(&mut store, &make_key(1, 0, 0), v(10));
        let _v_before = store.latest_version();

        delete(&mut store, &make_key(99, 0, 0));

        // Version still advances (the update was applied), but tree is unchanged
        assert_eq!(get(&store, &make_key(1, 0, 0)), Some(v(10)));
    }

    #[test]
    fn delete_same_stem_different_suffix() {
        let mut store = MemoryStore::new();
        let mut key1 = [0u8; 32];
        key1[0] = 1;
        key1[SUFFIX_INDEX] = 10;
        let mut key2 = [0u8; 32];
        key2[0] = 1;
        key2[SUFFIX_INDEX] = 20;

        insert(&mut store, &key1, v(100));
        insert(&mut store, &key2, v(200));

        // Delete one suffix, keep the other
        delete(&mut store, &key1);

        assert_eq!(get(&store, &key1), None);
        assert_eq!(get(&store, &key2), Some(v(200)));
        let root = store.latest_root_key().unwrap();
        assert!(verify_commitment_consistency(&store, &root));
    }

    #[test]
    fn delete_all_keys() {
        let mut store = MemoryStore::new();
        let key1 = make_key(1, 0, 0);
        let key2 = make_key(2, 0, 0);
        insert(&mut store, &key1, v(10));
        insert(&mut store, &key2, v(20));

        delete(&mut store, &key1);
        delete(&mut store, &key2);

        assert_eq!(get(&store, &key1), None);
        assert_eq!(get(&store, &key2), None);
    }

    #[test]
    fn insert_after_delete() {
        let mut store = MemoryStore::new();
        let key = make_key(1, 0, 0);

        insert(&mut store, &key, v(10));
        delete(&mut store, &key);
        assert_eq!(get(&store, &key), None);

        insert(&mut store, &key, v(20));
        assert_eq!(get(&store, &key), Some(v(20)));

        let root = store.latest_root_key().unwrap();
        assert!(verify_commitment_consistency(&store, &root));
    }

    #[test]
    fn batch_insert_and_delete() {
        let mut store = MemoryStore::new();
        insert(&mut store, &make_key(1, 0, 0), v(10));
        insert(&mut store, &make_key(2, 0, 0), v(20));
        insert(&mut store, &make_key(3, 0, 0), v(30));

        // Batch: delete key1, update key2, insert key4
        let parent = store.latest_version();
        let new_version = parent.map_or(1, |v| v + 1);
        let mut updates = BTreeMap::new();
        updates.insert(make_key(1, 0, 0), None);
        updates.insert(make_key(2, 0, 0), Some(v(99)));
        updates.insert(make_key(4, 0, 0), Some(v(40)));
        let result = apply_updates(&store, parent, new_version, updates);
        store.apply(&result);

        assert_eq!(get(&store, &make_key(1, 0, 0)), None);
        assert_eq!(get(&store, &make_key(2, 0, 0)), Some(v(99)));
        assert_eq!(get(&store, &make_key(3, 0, 0)), Some(v(30)));
        assert_eq!(get(&store, &make_key(4, 0, 0)), Some(v(40)));

        let root = store.latest_root_key().unwrap();
        assert!(verify_commitment_consistency(&store, &root));
    }
}
