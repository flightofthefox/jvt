//! Multipoint proof aggregation for verkle trees (Dankrad Feist scheme).
//!
//! Compresses arbitrarily many IPA opening proofs into a single ~576-byte proof.
//! This is the core innovation that makes verkle trees practical for stateless
//! validation: a block touching 1000 keys produces a proof roughly the same size
//! as one touching 10.
//!
//! Implementation follows crate-crypto/rust-verkle (ipa-multipoint) and
//! crate-crypto/go-ipa, adapted for our arkworks-based Bandersnatch primitives.
//!
//! Only available with the `pedersen` feature.

#[cfg(feature = "pedersen")]
pub mod crs;
#[cfg(feature = "pedersen")]
pub mod ipa;
#[cfg(feature = "pedersen")]
pub mod lagrange;
#[cfg(feature = "pedersen")]
pub mod prover;
#[cfg(feature = "pedersen")]
pub mod transcript;

#[cfg(feature = "pedersen")]
pub use prover::{MultiPointProof, MultiPointProver, ProverQuery, VerifierQuery};
