//! Mock commitment scheme: additive homomorphism over a prime field.
//!
//! This is fast and sufficient for validating tree logic. Not cryptographically
//! secure — exists solely for structural testing and Quint spec alignment.

use std::fmt;

/// A mock commitment (field element).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, serde::Serialize, serde::Deserialize)]
pub struct Commitment(pub u128);

impl fmt::Debug for Commitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "C({})", self.0)
    }
}

/// A mock field element.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, Debug)]
pub struct FieldElement(pub u128);

/// Prime modulus (largest prime < 2^64).
const MODULUS: u128 = 18_446_744_073_709_551_557;

/// Basis "points": basis(i) = (i + 1) * 137 mod MODULUS.
fn basis(i: usize) -> u128 {
    ((i as u128 + 1) * 137) % MODULUS
}

/// The zero commitment (additive identity).
pub const ZERO_COMMITMENT: Commitment = Commitment(0);

/// Get the zero commitment (function form, for API compatibility with pedersen module).
pub fn zero_commitment() -> Commitment {
    ZERO_COMMITMENT
}

/// Compute a vector commitment: C = Σ values[i] * basis(i) mod MODULUS.
pub fn commit<I>(values: I) -> Commitment
where
    I: IntoIterator<Item = (usize, FieldElement)>,
{
    let mut acc: u128 = 0;
    for (i, v) in values {
        debug_assert!(i < 256, "commitment index out of range");
        let term = mulmod(v.0, basis(i));
        acc = addmod(acc, term);
    }
    Commitment(acc)
}

/// Homomorphic update: C_new = C_old + (new_value - old_value) * basis(index).
pub fn commit_update(
    old_commitment: Commitment,
    index: usize,
    old_value: FieldElement,
    new_value: FieldElement,
) -> Commitment {
    debug_assert!(index < 256);
    let delta = addmod(new_value.0, MODULUS - old_value.0);
    let term = mulmod(delta, basis(index));
    Commitment(addmod(old_commitment.0, term))
}

/// Convert a byte slice to a field element.
pub fn value_to_field(value: &[u8]) -> FieldElement {
    if value.len() <= 16 {
        let mut bytes = [0u8; 16];
        bytes[..value.len()].copy_from_slice(value);
        FieldElement(u128::from_le_bytes(bytes) % MODULUS)
    } else {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(value);
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&hash[..16]);
        FieldElement(u128::from_le_bytes(bytes) % MODULUS)
    }
}

/// Convert an integer to a field element.
pub fn int_to_field(v: u64) -> FieldElement {
    FieldElement(v as u128 % MODULUS)
}

/// Convert a commitment to a field element (for use in parent commitments).
pub fn commitment_to_field(c: Commitment) -> FieldElement {
    FieldElement(c.0 % MODULUS)
}

/// Create a zero field element.
pub fn field_zero() -> FieldElement {
    FieldElement(0)
}

/// Create a field element from a u8 byte.
pub fn field_from_byte(b: u8) -> FieldElement {
    FieldElement(b as u128 % MODULUS)
}

/// Create a field element representing the integer 1.
pub fn field_one() -> FieldElement {
    FieldElement(1)
}

fn addmod(a: u128, b: u128) -> u128 {
    (a + b) % MODULUS
}

fn mulmod(a: u128, b: u128) -> u128 {
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
