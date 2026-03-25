//! Node types for the Jellyfish Verkle Tree.
//!
//! Three node types:
//! - `InternalNode`: Up to 256 children with a Pedersen vector commitment
//! - `EaSNode`: Extension-and-Suffix node with stem, values, and sub-commitments
//! - Empty: Represented as `None` in child slots

use std::collections::HashMap;

use crate::commitment::*;

/// A fixed-size 32-byte key. The last byte (index 31) is the suffix
/// (EaS value slot index), bytes 0..31 are the stem used for tree
/// traversal. Callers hash their variable-length keys to 32 bytes
/// before calling into the JVT.
pub type Key = [u8; 32];

/// A value stored in the tree — a pre-hashed field element.
/// Callers convert raw bytes to field elements via `value_to_field`
/// before insertion.
pub type Value = FieldElement;

/// The fixed index of the suffix byte in a key.
pub const SUFFIX_INDEX: usize = 31;

/// Key helper: the suffix byte (index 31, selects the EaS value slot).
pub fn key_suffix(key: &Key) -> u8 {
    key[SUFFIX_INDEX]
}

/// Key helper: the stem (bytes 0..31).
pub fn key_stem(key: &Key) -> &[u8] {
    &key[..SUFFIX_INDEX]
}

/// Maximum byte-path length (depth never exceeds 31 with 32-byte keys).
const MAX_PATH_LEN: usize = 31;

/// Node key: uniquely identifies a node in versioned storage.
/// Uses inline storage (no heap allocation) since paths are at most 31 bytes.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct NodeKey {
    pub version: u64,
    path_buf: [u8; MAX_PATH_LEN],
    path_len: u8,
}

impl std::fmt::Debug for NodeKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeKey")
            .field("version", &self.version)
            .field("byte_path", &self.byte_path())
            .finish()
    }
}

impl NodeKey {
    pub fn new(version: u64, byte_path: &[u8]) -> Self {
        debug_assert!(
            byte_path.len() <= MAX_PATH_LEN,
            "byte_path too long: {} > {}",
            byte_path.len(),
            MAX_PATH_LEN
        );
        let mut path_buf = [0u8; MAX_PATH_LEN];
        path_buf[..byte_path.len()].copy_from_slice(byte_path);
        Self {
            version,
            path_buf,
            path_len: byte_path.len() as u8,
        }
    }

    pub fn root(version: u64) -> Self {
        Self::new(version, &[])
    }

    /// The byte path as a slice.
    pub fn byte_path(&self) -> &[u8] {
        &self.path_buf[..self.path_len as usize]
    }

    /// Encode for storage: [version_be_8B][path_len_1B][path_bytes]
    pub fn encode(&self) -> Vec<u8> {
        let path = self.byte_path();
        let mut buf = Vec::with_capacity(8 + 1 + path.len());
        buf.extend_from_slice(&self.version.to_be_bytes());
        buf.push(self.path_len);
        buf.extend_from_slice(path);
        buf
    }

    pub fn depth(&self) -> usize {
        self.path_len as usize
    }

    /// Create a child key by appending one byte to this key's path.
    pub fn child(&self, version: u64, index: u8) -> Self {
        let len = self.path_len as usize;
        debug_assert!(len < MAX_PATH_LEN);
        let mut path_buf = self.path_buf;
        path_buf[len] = index;
        Self {
            version,
            path_buf,
            path_len: self.path_len + 1,
        }
    }
}

/// Reference to a child node stored in an internal node.
#[derive(Clone, Debug)]
pub struct Child {
    pub version: u64,
    pub commitment: Commitment,
    pub field: FieldElement,
}

impl PartialEq for Child {
    fn eq(&self, other: &Self) -> bool {
        self.version == other.version && self.commitment == other.commitment
    }
}

impl Eq for Child {}

impl Child {
    /// Create a child with a pre-computed field element (avoids EC inversion).
    pub fn new_with_field(version: u64, commitment: Commitment, field: FieldElement) -> Self {
        Self {
            version,
            commitment,
            field,
        }
    }

    /// Create a child, computing `commitment_to_field` (use only for fresh nodes).
    pub fn new(version: u64, commitment: Commitment) -> Self {
        Self::new_with_field(version, commitment, commitment_to_field(commitment))
    }
}

/// An internal node with up to 256 children.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InternalNode {
    /// Sparse map of child index (0..255) to child reference.
    pub children: HashMap<u8, Child>,
    /// Vector commitment over children: C = Σ children[i].commitment · G_i
    pub commitment: Commitment,
}

impl InternalNode {
    /// Create a new internal node and compute its commitment.
    pub fn new(children: HashMap<u8, Child>) -> Self {
        let commitment = Self::compute_commitment(&children);
        Self {
            children,
            commitment,
        }
    }

    /// Recompute the commitment from children.
    pub fn compute_commitment(children: &HashMap<u8, Child>) -> Commitment {
        commit(
            children
                .iter()
                .map(|(&idx, child)| (idx as usize, child.field)),
        )
    }

    /// Update a single child and recompute commitment homomorphically.
    pub fn update_child(&mut self, index: u8, new_child: Child) {
        let old_field = self
            .children
            .get(&index)
            .map(|c| c.field)
            .unwrap_or(field_zero());

        self.commitment =
            commit_update(self.commitment, index as usize, old_field, new_child.field);
        self.children.insert(index, new_child);
    }

    /// Update multiple children, accumulating commitment deltas in projective
    /// coordinates. Converts to affine once at the end, and computes
    /// `commitment_to_field` per child only after the affine conversion.
    ///
    /// Each entry is `(index, version, child_commitment)`. Avoids per-child
    /// affine↔projective round-trips and defers `commitment_to_field` calls.
    pub fn batch_update_children(
        &mut self,
        updates: impl IntoIterator<Item = (u8, u64, Commitment)>,
    ) {
        use ark_ec::CurveGroup;
        use ark_ed_on_bls12_381_bandersnatch::EdwardsProjective;

        let basis = get_basis();
        let mut acc: EdwardsProjective = self.commitment.0.into();

        // Collect updates, then batch-convert commitment_to_field using
        // Montgomery's trick (1 inversion instead of N).
        let entries: Vec<(u8, u64, Commitment)> = updates.into_iter().collect();
        let commitments: Vec<Commitment> = entries.iter().map(|e| e.2).collect();
        let fields = batch_commitment_to_field(&commitments);

        for (i, &(index, _, _)) in entries.iter().enumerate() {
            let old_field = self
                .children
                .get(&index)
                .map(|c| c.field)
                .unwrap_or(field_zero());

            let delta = fields[i].0 - old_field.0;
            acc += basis[index as usize] * delta;
        }

        // Single affine conversion for the accumulated node commitment
        self.commitment = Commitment(acc.into_affine());

        for (i, (index, version, commitment)) in entries.into_iter().enumerate() {
            self.children
                .insert(index, Child::new_with_field(version, commitment, fields[i]));
        }
    }

    pub fn child_count(&self) -> usize {
        self.children.len()
    }
}

/// Extension-and-Suffix (EaS) node.
///
/// Stores a stem (remaining key prefix bytes after tree depth), up to 256 values
/// (indexed by the final key byte), and sub-commitments c1 (lower 128) and c2 (upper 128).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EaSNode {
    /// Remaining key prefix bytes beyond this node's tree depth.
    pub stem: Vec<u8>,
    /// Sparse map of suffix byte (0..255) to value.
    pub values: HashMap<u8, Value>,
    /// Commitment over values[0..127].
    pub c1: Commitment,
    /// Commitment over values[128..255].
    pub c2: Commitment,
    pub c1_field: FieldElement,
    pub c2_field: FieldElement,
    /// Commitment over (1, stem_fields..., c1, c2).
    pub extension_commitment: Commitment,
}

impl EaSNode {
    /// Create a new EaS node with a single value and compute all commitments.
    pub fn new_single(stem: Vec<u8>, suffix: u8, value: Value) -> Self {
        let mut values = HashMap::new();
        values.insert(suffix, value);
        Self::from_values(stem, values)
    }

    /// Create an EaS node from existing values and compute all commitments.
    pub fn from_values(stem: Vec<u8>, values: HashMap<u8, Value>) -> Self {
        let c1 = Self::compute_c1(&values);
        let c2 = Self::compute_c2(&values);
        let c1_field = commitment_to_field(c1);
        let c2_field = commitment_to_field(c2);
        let stem_c = Self::compute_stem_commitment(&stem);
        let extension_commitment = Self::compute_extension_commitment_from_stem_cached(
            stem_c,
            stem.len(),
            c1_field,
            c2_field,
        );
        Self {
            stem,
            values,
            c1,
            c2,
            c1_field,
            c2_field,
            extension_commitment,
        }
    }

    /// Compute c1: commitment over values[0..127].
    pub fn compute_c1(values: &HashMap<u8, Value>) -> Commitment {
        commit(
            values
                .iter()
                .filter(|(&k, _)| k < 128)
                .map(|(&k, v)| (k as usize, *v)),
        )
    }

    /// Compute c2: commitment over values[128..255].
    pub fn compute_c2(values: &HashMap<u8, Value>) -> Commitment {
        commit(
            values
                .iter()
                .filter(|(&k, _)| k >= 128)
                .map(|(&k, v)| ((k - 128) as usize, *v)),
        )
    }

    /// Compute the stem-only portion of the extension commitment:
    /// commit(1, stem[0], ..., stem[n-1], 0, 0).
    ///
    /// Uses precomputed byte-basis table for fast point additions instead of
    /// scalar multiplications.
    pub fn compute_stem_commitment(stem: &[u8]) -> Commitment {
        use crate::commitment::{byte_basis_table, get_basis};
        use ark_ec::CurveGroup;
        use ark_ed_on_bls12_381_bandersnatch::EdwardsProjective;

        let table = byte_basis_table();
        let basis = get_basis();

        // marker byte (1) at index 0 — just the generator itself
        let mut acc: EdwardsProjective = basis[0];

        // stem bytes via precomputed table — point addition, not scalar mul
        for (i, &byte) in stem.iter().enumerate() {
            if byte != 0 {
                acc += table[i + 1][byte as usize];
            }
        }

        Commitment(acc.into_affine())
    }

    /// Compute the extension commitment from a precomputed stem commitment
    /// using pre-cached field elements for c1 and c2.
    pub fn compute_extension_commitment_from_stem_cached(
        stem_commitment: Commitment,
        stem_len: usize,
        c1_field: FieldElement,
        c2_field: FieldElement,
    ) -> Commitment {
        let c = commit_update(stem_commitment, stem_len + 1, field_zero(), c1_field);
        commit_update(c, stem_len + 2, field_zero(), c2_field)
    }

    /// Create an EaS node with a new stem but the same values and
    /// sub-commitments. Only recomputes the stem and extension commitments.
    /// Used during collapse when an internal node merges into its sole EaS child.
    pub fn with_prepended_stem(&self, prefix_byte: u8) -> Self {
        let mut new_stem = Vec::with_capacity(1 + self.stem.len());
        new_stem.push(prefix_byte);
        new_stem.extend_from_slice(&self.stem);
        let stem_c = Self::compute_stem_commitment(&new_stem);
        let extension_commitment = Self::compute_extension_commitment_from_stem_cached(
            stem_c,
            new_stem.len(),
            self.c1_field,
            self.c2_field,
        );
        Self {
            stem: new_stem,
            values: self.values.clone(),
            c1: self.c1,
            c2: self.c2,
            c1_field: self.c1_field,
            c2_field: self.c2_field,
            extension_commitment,
        }
    }

    /// Update a single value slot, recomputing commitments.
    pub fn update_value(&mut self, suffix: u8, new_value: Value) {
        self.batch_update_values(std::iter::once((suffix, Some(new_value))));
    }

    /// Update multiple value slots, deferring expensive commitment_to_field
    /// and extension_commitment updates until all sub-commitment updates are done.
    ///
    /// `Some(value)` upserts, `None` deletes. Homomorphic in both cases:
    /// delete is `commit_update(c, idx, old_field, field_zero())`.
    ///
    /// Accumulates c1/c2 deltas in projective to avoid per-update affine
    /// conversions (field inversions), converting to affine once at the end.
    pub fn batch_update_values(&mut self, updates: impl IntoIterator<Item = (u8, Option<Value>)>) {
        use ark_ec::CurveGroup;
        use ark_ed_on_bls12_381_bandersnatch::EdwardsProjective;

        let basis = get_basis();
        let mut c1_changed = false;
        let mut c2_changed = false;
        let old_c1_field = self.c1_field;
        let old_c2_field = self.c2_field;

        let mut c1_proj: EdwardsProjective = self.c1.0.into();
        let mut c2_proj: EdwardsProjective = self.c2.0.into();

        for (suffix, new_value) in updates {
            let old_field = self.values.get(&suffix).copied().unwrap_or(field_zero());
            let new_field = new_value.unwrap_or(field_zero());

            let delta = new_field.0 - old_field.0;
            if suffix < 128 {
                c1_proj += basis[suffix as usize] * delta;
                c1_changed = true;
            } else {
                c2_proj += basis[(suffix - 128) as usize] * delta;
                c2_changed = true;
            }

            match new_value {
                Some(v) => self.values.insert(suffix, v),
                None => self.values.remove(&suffix),
            };
        }

        // Convert to affine once, then update extension commitment
        if c1_changed {
            self.c1 = Commitment(c1_proj.into_affine());
            self.c1_field = commitment_to_field(self.c1);
            self.extension_commitment = commit_update(
                self.extension_commitment,
                self.stem.len() + 1,
                old_c1_field,
                self.c1_field,
            );
        }
        if c2_changed {
            self.c2 = Commitment(c2_proj.into_affine());
            self.c2_field = commitment_to_field(self.c2);
            self.extension_commitment = commit_update(
                self.extension_commitment,
                self.stem.len() + 2,
                old_c2_field,
                self.c2_field,
            );
        }
    }

    /// Get the overall commitment for this node (used as value in parent commitments).
    pub fn commitment(&self) -> Commitment {
        self.extension_commitment
    }
}

/// A tree node: either Internal, EaS, or Empty (represented as Option<Node>).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Node {
    Internal(InternalNode),
    EaS(Box<EaSNode>),
}

impl Node {
    /// Get the commitment for this node.
    pub fn commitment(&self) -> Commitment {
        match self {
            Node::Internal(n) => n.commitment,
            Node::EaS(n) => n.extension_commitment,
        }
    }
}

/// Entry in the stale node index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaleNodeIndex {
    /// The version at which this node became stale.
    pub stale_since_version: u64,
    /// The node key that is now stale.
    pub node_key: NodeKey,
}

/// Batch of tree updates produced by an insert operation.
#[derive(Clone, Debug, Default)]
pub struct TreeUpdateBatch {
    pub new_nodes: Vec<(NodeKey, Node)>,
    pub stale_nodes: Vec<StaleNodeIndex>,
    /// The root key for the new version (version, NodeKey).
    pub root_key: Option<(u64, NodeKey)>,
}

impl TreeUpdateBatch {
    pub fn put_node(&mut self, key: NodeKey, node: Node) {
        self.new_nodes.push((key, node));
    }

    pub fn mark_stale(&mut self, node_key: NodeKey, stale_since: u64) {
        self.stale_nodes.push(StaleNodeIndex {
            stale_since_version: stale_since,
            node_key,
        });
    }

    /// Merge another batch into this one.
    pub fn merge(&mut self, other: TreeUpdateBatch) {
        self.new_nodes.extend(other.new_nodes);
        self.stale_nodes.extend(other.stale_nodes);
        // root_key is only set at the top level, not in subtree batches
    }
}

/// Find the common prefix length between two byte slices.
pub fn common_prefix_len(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b.iter()).take_while(|(x, y)| x == y).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_key_encoding_roundtrip() {
        let nk = NodeKey::new(42, &[0xAB, 0xCD, 0xEF]);
        let encoded = nk.encode();
        assert_eq!(encoded.len(), 8 + 1 + 3);
        assert_eq!(&encoded[..8], &42u64.to_be_bytes());
        assert_eq!(encoded[8], 3);
        assert_eq!(&encoded[9..], &[0xAB, 0xCD, 0xEF]);
    }

    fn v(n: u8) -> Value {
        value_to_field(&[n])
    }

    #[test]
    fn eas_single_value() {
        let eas = EaSNode::new_single(vec![1, 2, 3], 42, v(100));
        assert_eq!(eas.values.len(), 1);
        assert_eq!(eas.values[&42], v(100));
        // c1 should be nonzero (suffix 42 < 128)
        assert_ne!(eas.c1, zero_commitment());
        // c2 should be zero (no values >= 128)
        assert_eq!(eas.c2, zero_commitment());
    }

    #[test]
    fn eas_update_homomorphic() {
        let mut eas = EaSNode::new_single(vec![1, 2], 10, v(5));
        let original_ext = eas.extension_commitment;

        // Update the value
        eas.update_value(10, v(20));

        // Recompute from scratch
        let fresh = EaSNode::from_values(vec![1, 2], eas.values.clone());

        assert_eq!(eas.c1, fresh.c1);
        assert_eq!(eas.c2, fresh.c2);
        assert_eq!(eas.extension_commitment, fresh.extension_commitment);
        assert_ne!(eas.extension_commitment, original_ext);
    }

    #[test]
    fn internal_node_update_homomorphic() {
        let c_a = commit(vec![(0, v(10))]);
        let c_b = commit(vec![(1, v(20))]);
        let c_c = commit(vec![(2, v(30))]);

        let mut children = HashMap::new();
        children.insert(0, Child::new(1, c_a));
        children.insert(5, Child::new(1, c_b));
        let mut node = InternalNode::new(children);

        // Update child 5
        let new_child = Child::new(2, c_c);
        node.update_child(5, new_child.clone());

        // Recompute from scratch
        let mut expected_children = HashMap::new();
        expected_children.insert(0, Child::new(1, c_a));
        expected_children.insert(5, new_child);
        let expected = InternalNode::new(expected_children);

        assert_eq!(node.commitment, expected.commitment);
    }

    #[test]
    fn common_prefix() {
        assert_eq!(common_prefix_len(&[1, 2, 3], &[1, 2, 4]), 2);
        assert_eq!(common_prefix_len(&[1, 2, 3], &[1, 2, 3]), 3);
        assert_eq!(common_prefix_len(&[1], &[2]), 0);
        assert_eq!(common_prefix_len(&[], &[1, 2]), 0);
    }
}
