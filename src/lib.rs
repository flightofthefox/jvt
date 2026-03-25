//! Jellyfish Verkle Tree (JVT) — a hybrid authenticated data structure.
//!
//! Combines JMT's version-based persistent storage with verkle tree
//! vector commitments for efficient proof aggregation.
//!
//! # API
//!
//! All operations are stateless:
//! - `apply_updates(store, parent_version, new_version, updates) -> UpdateResult`
//! - `get_committed_value(store, root_key, key) -> Option<Value>`
//! - `verify_commitment_consistency(store, root_key) -> bool`

pub mod commitment;
pub mod multiproof;
pub mod node;
pub mod storage;
pub mod tree;
pub mod verkle_proof;

// Core types
pub use commitment::{value_to_field, zero_commitment, Commitment, FieldElement};
pub use node::{
    Child, EaSNode, InternalNode, Key, Node, NodeKey, StaleNodeIndex, TreeUpdateBatch, Value,
};
pub use storage::{MemoryStore, TreeReader, TreeWriter};
pub use tree::{
    apply_updates, get_committed_value, root_commitment_at, verify_commitment_consistency,
    UpdateResult,
};
