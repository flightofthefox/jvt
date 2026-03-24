//! Abstract commitment trait and mock implementation.
//!
//! The mock uses additive homomorphism over a prime field to validate
//! tree logic without real elliptic curve operations. The trait allows
//! swapping in real Pedersen/IPA commitments later.

use std::fmt;

/// A commitment value. In the mock, this is a field element (u128).
/// In a real implementation, this would be a compressed curve point (32 bytes).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, serde::Serialize, serde::Deserialize)]
pub struct Commitment(pub u128);

impl fmt::Debug for Commitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "C({})", self.0)
    }
}

/// A field element for commitment arithmetic.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, Debug)]
pub struct FieldElement(pub u128);

/// The prime modulus for our mock field.
/// Using a 64-bit prime to avoid overflow issues in u128 multiplication.
const MODULUS: u128 = 18_446_744_073_709_551_557; // largest prime < 2^64

/// Pre-computed basis "points" for the mock commitment scheme.
/// In a real implementation, these would be independent group generators
/// on the Bandersnatch curve.
///
/// We use `basis(i) = (i + 1) * 137 mod MODULUS` which gives 256 distinct
/// nonzero values since 137 is coprime to MODULUS.
fn basis(i: usize) -> u128 {
    ((i as u128 + 1) * 137) % MODULUS
}

/// The zero commitment (additive identity).
pub const ZERO_COMMITMENT: Commitment = Commitment(0);

/// Compute a vector commitment over sparse values.
///
/// `C = Σ values[i] * basis(i) mod MODULUS`
///
/// Only indices present in the iterator contribute.
pub fn commit<I>(values: I) -> Commitment
where
    I: IntoIterator<Item = (usize, FieldElement)>,
{
    let mut acc: u128 = 0;
    for (i, v) in values {
        debug_assert!(i < 256, "commitment index out of range");
        // Use wrapping arithmetic then mod to avoid overflow
        let term = mulmod(v.0, basis(i));
        acc = addmod(acc, term);
    }
    Commitment(acc)
}

/// Homomorphic commitment update.
///
/// `C_new = C_old + (new_value - old_value) * basis(index)`
pub fn commit_update(
    old_commitment: Commitment,
    index: usize,
    old_value: FieldElement,
    new_value: FieldElement,
) -> Commitment {
    debug_assert!(index < 256);
    // delta = new_value - old_value (mod MODULUS)
    let delta = addmod(new_value.0, MODULUS - old_value.0);
    let term = mulmod(delta, basis(index));
    Commitment(addmod(old_commitment.0, term))
}

/// Convert a byte slice to a field element.
///
/// For values ≤ 31 bytes, pack directly. For longer values, hash first.
pub fn value_to_field(value: &[u8]) -> FieldElement {
    if value.len() <= 16 {
        // Pack directly into u128
        let mut bytes = [0u8; 16];
        bytes[..value.len()].copy_from_slice(value);
        FieldElement(u128::from_le_bytes(bytes) % MODULUS)
    } else {
        // Hash and take the first 16 bytes
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(value);
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&hash[..16]);
        FieldElement(u128::from_le_bytes(bytes) % MODULUS)
    }
}

/// Convert an integer value to a field element.
pub fn int_to_field(v: u64) -> FieldElement {
    FieldElement(v as u128 % MODULUS)
}

/// Convert a commitment to a field element (for use in parent commitments).
pub fn commitment_to_field(c: Commitment) -> FieldElement {
    FieldElement(c.0 % MODULUS)
}

// --- Modular arithmetic helpers ---

fn addmod(a: u128, b: u128) -> u128 {
    // Both a, b < MODULUS, so a + b < 2 * MODULUS < 2^65 which fits u128
    (a + b) % MODULUS
}

fn mulmod(a: u128, b: u128) -> u128 {
    // a, b < MODULUS < 2^64, so a * b < 2^128 which fits u128
    (a * b) % MODULUS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_commitment_is_zero() {
        assert_eq!(commit(std::iter::empty()), ZERO_COMMITMENT);
    }

    #[test]
    fn homomorphic_property() {
        // commit({0: 5, 1: 10}) then update index 1 from 10 to 20
        // should equal commit({0: 5, 1: 20})
        let original = commit(vec![(0, FieldElement(5)), (1, FieldElement(10))]);
        let updated = commit_update(original, 1, FieldElement(10), FieldElement(20));
        let recomputed = commit(vec![(0, FieldElement(5)), (1, FieldElement(20))]);
        assert_eq!(updated, recomputed);
    }

    #[test]
    fn single_element() {
        let c = commit(vec![(3, FieldElement(42))]);
        assert_eq!(c.0, mulmod(42, basis(3)));
    }

    #[test]
    fn update_from_zero() {
        // Inserting into an empty slot: update(0, index, 0, value)
        let updated = commit_update(ZERO_COMMITMENT, 5, FieldElement(0), FieldElement(100));
        let direct = commit(vec![(5, FieldElement(100))]);
        assert_eq!(updated, direct);
    }

    #[test]
    fn basis_values_are_distinct() {
        let bases: Vec<u128> = (0..256).map(basis).collect();
        let unique: std::collections::HashSet<u128> = bases.iter().copied().collect();
        assert_eq!(unique.len(), 256);
    }
}
