//! Multipoint proof aggregation for verkle trees (Dankrad Feist scheme).
//!
//! Compresses arbitrarily many IPA opening proofs into a single ~576-byte proof.

pub mod crs;
pub mod ipa;
pub mod lagrange;
pub mod prover;
pub mod transcript;

pub use prover::{MultiPointProof, MultiPointProver, ProverQuery, VerifierQuery};
