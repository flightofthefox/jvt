//! Jellyfish Verkle Tree (JVT) — a hybrid authenticated data structure.
//!
//! Combines JMT's version-based persistent storage with verkle tree
//! vector commitments for efficient proof aggregation.

pub mod commitment;
pub mod node;
pub mod proof;
pub mod storage;
pub mod tree;

pub use commitment::{Commitment, ZERO_COMMITMENT};
pub use node::{Key, NodeKey, Value};
pub use storage::MemoryStore;
pub use tree::JVT;
