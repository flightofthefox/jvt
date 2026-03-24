//! Commitment scheme abstraction.
//!
//! Two backends are available:
//! - `mock` (default): Additive homomorphism over a prime field. Fast, no crypto.
//! - `pedersen` (feature = "pedersen"): Real Pedersen commitments on Bandersnatch.
//!
//! Both export the same API: `Commitment`, `FieldElement`, `commit()`,
//! `commit_update()`, `value_to_field()`, `commitment_to_field()`.

pub mod mock;

#[cfg(feature = "pedersen")]
pub mod pedersen;

#[cfg(not(feature = "pedersen"))]
pub use mock::*;

#[cfg(feature = "pedersen")]
pub use pedersen::*;
