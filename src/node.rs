//! Node types for the Jellyfish Verkle Tree.
//!
//! Three node types:
//! - `InternalNode`: Up to 256 children with a Pedersen vector commitment
//! - `EaSNode`: Extension-and-Suffix node with stem, values, and sub-commitments
//! - Empty: Represented as `None` in child slots

use std::collections::HashMap;

use crate::commitment::*;

/// Maximum stem length (31 bytes — key bytes 0..30 are for tree+stem, byte 31 is suffix).
pub const MAX_STEM_LEN: usize = 31;

/// A 32-byte key.
pub type Key = [u8; 32];

/// A value stored in the tree.
pub type Value = Vec<u8>;

/// Node key: uniquely identifies a node in versioned storage.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct NodeKey {
    pub version: u64,
    pub byte_path: Vec<u8>, // max length 31
}

impl NodeKey {
    pub fn new(version: u64, byte_path: Vec<u8>) -> Self {
        debug_assert!(byte_path.len() <= MAX_STEM_LEN);
        Self { version, byte_path }
    }

    pub fn root(version: u64) -> Self {
        Self::new(version, vec![])
    }

    /// Encode for storage: [version_be_8B][path_len_1B][path_bytes]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 + 1 + self.byte_path.len());
        buf.extend_from_slice(&self.version.to_be_bytes());
        buf.push(self.byte_path.len() as u8);
        buf.extend_from_slice(&self.byte_path);
        buf
    }

    pub fn depth(&self) -> usize {
        self.byte_path.len()
    }
}

/// Reference to a child node stored in an internal node.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Child {
    pub version: u64,
    pub commitment: Commitment,
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
                .map(|(&idx, child)| (idx as usize, commitment_to_field(child.commitment))),
        )
    }

    /// Update a single child and recompute commitment homomorphically.
    pub fn update_child(&mut self, index: u8, new_child: Child) {
        let old_field = self
            .children
            .get(&index)
            .map(|c| commitment_to_field(c.commitment))
            .unwrap_or(field_zero());
        let new_field = commitment_to_field(new_child.commitment);

        self.commitment = commit_update(self.commitment, index as usize, old_field, new_field);
        self.children.insert(index, new_child);
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
        let extension_commitment = Self::compute_extension_commitment(&stem, c1, c2);
        Self {
            stem,
            values,
            c1,
            c2,
            extension_commitment,
        }
    }

    /// Compute c1: commitment over values[0..127].
    pub fn compute_c1(values: &HashMap<u8, Value>) -> Commitment {
        commit(
            values
                .iter()
                .filter(|(&k, _)| k < 128)
                .map(|(&k, v)| (k as usize, value_to_field(v))),
        )
    }

    /// Compute c2: commitment over values[128..255].
    pub fn compute_c2(values: &HashMap<u8, Value>) -> Commitment {
        commit(
            values
                .iter()
                .filter(|(&k, _)| k >= 128)
                .map(|(&k, v)| ((k - 128) as usize, value_to_field(v))),
        )
    }

    /// Compute the extension commitment: commit(1, stem[0], ..., stem[n-1], c1, c2)
    pub fn compute_extension_commitment(stem: &[u8], c1: Commitment, c2: Commitment) -> Commitment {
        let mut entries: Vec<(usize, FieldElement)> = Vec::new();
        // Index 0: marker value 1
        entries.push((0, field_one()));
        // Indices 1..stem.len(): stem bytes as field elements
        for (i, &byte) in stem.iter().enumerate() {
            entries.push((i + 1, field_from_byte(byte)));
        }
        // c1 and c2 as field elements
        entries.push((stem.len() + 1, commitment_to_field(c1)));
        entries.push((stem.len() + 2, commitment_to_field(c2)));
        commit(entries)
    }

    /// Update a single value slot, recomputing commitments.
    pub fn update_value(&mut self, suffix: u8, new_value: Value) {
        let old_field = self
            .values
            .get(&suffix)
            .map(|v| value_to_field(v))
            .unwrap_or(field_zero());
        let new_field = value_to_field(&new_value);

        // Update c1 or c2 homomorphically
        let old_sub_commitment;
        let new_sub_commitment;
        if suffix < 128 {
            old_sub_commitment = self.c1;
            self.c1 = commit_update(self.c1, suffix as usize, old_field, new_field);
            new_sub_commitment = self.c1;
        } else {
            old_sub_commitment = self.c2;
            self.c2 = commit_update(self.c2, (suffix - 128) as usize, old_field, new_field);
            new_sub_commitment = self.c2;
        }

        // Update extension commitment homomorphically
        // c1 is at index stem.len() + 1, c2 is at index stem.len() + 2
        let sub_index = if suffix < 128 {
            self.stem.len() + 1
        } else {
            self.stem.len() + 2
        };
        self.extension_commitment = commit_update(
            self.extension_commitment,
            sub_index,
            commitment_to_field(old_sub_commitment),
            commitment_to_field(new_sub_commitment),
        );

        self.values.insert(suffix, new_value);
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
    EaS(EaSNode),
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
        let nk = NodeKey::new(42, vec![0xAB, 0xCD, 0xEF]);
        let encoded = nk.encode();
        assert_eq!(encoded.len(), 8 + 1 + 3);
        assert_eq!(&encoded[..8], &42u64.to_be_bytes());
        assert_eq!(encoded[8], 3);
        assert_eq!(&encoded[9..], &[0xAB, 0xCD, 0xEF]);
    }

    #[test]
    fn eas_single_value() {
        let eas = EaSNode::new_single(vec![1, 2, 3], 42, vec![100]);
        assert_eq!(eas.values.len(), 1);
        assert_eq!(eas.values[&42], vec![100]);
        // c1 should be nonzero (suffix 42 < 128)
        assert_ne!(eas.c1, zero_commitment());
        // c2 should be zero (no values >= 128)
        assert_eq!(eas.c2, zero_commitment());
    }

    #[test]
    fn eas_update_homomorphic() {
        let mut eas = EaSNode::new_single(vec![1, 2], 10, vec![5]);
        let original_ext = eas.extension_commitment;

        // Update the value
        eas.update_value(10, vec![20]);

        // Recompute from scratch
        let fresh = EaSNode::from_values(vec![1, 2], eas.values.clone());

        assert_eq!(eas.c1, fresh.c1);
        assert_eq!(eas.c2, fresh.c2);
        assert_eq!(eas.extension_commitment, fresh.extension_commitment);
        assert_ne!(eas.extension_commitment, original_ext);
    }

    #[test]
    fn internal_node_update_homomorphic() {
        // Use real commitments from the commit() function
        let c_a = commit(vec![(0, value_to_field(&[10]))]);
        let c_b = commit(vec![(1, value_to_field(&[20]))]);
        let c_c = commit(vec![(2, value_to_field(&[30]))]);

        let mut children = HashMap::new();
        children.insert(
            0,
            Child {
                version: 1,
                commitment: c_a,
            },
        );
        children.insert(
            5,
            Child {
                version: 1,
                commitment: c_b,
            },
        );
        let mut node = InternalNode::new(children);

        // Update child 5
        let new_child = Child {
            version: 2,
            commitment: c_c,
        };
        node.update_child(5, new_child.clone());

        // Recompute from scratch
        let mut expected_children = HashMap::new();
        expected_children.insert(
            0,
            Child {
                version: 1,
                commitment: c_a,
            },
        );
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
