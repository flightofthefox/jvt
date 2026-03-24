//! Real Pedersen vector commitment scheme on the Bandersnatch curve.
//!
//! Uses the arkworks ecosystem for elliptic curve operations.
//! The Bandersnatch curve is defined over the BLS12-381 scalar field.
//!
//! Commitment = Σ values[i] * G_i where G_i are fixed independent generators.
//! Homomorphic update: C_new = C_old + (new - old) * G_index.

use std::fmt;
use std::sync::LazyLock;

use ark_ec::CurveGroup;
use ark_ed_on_bls12_381_bandersnatch::{EdwardsAffine, EdwardsProjective, Fr};
use ark_ff::{AdditiveGroup, PrimeField};
use ark_std::{UniformRand, Zero};

/// Number of basis points (one per child slot in 256-ary branching).
const WIDTH: usize = 256;

/// Pre-computed basis points G_0, G_1, ..., G_255.
/// Generated deterministically from a seed for reproducibility.
/// In a production system these would come from a trusted setup / hash-to-curve.
static BASIS: LazyLock<Vec<EdwardsProjective>> = LazyLock::new(|| {
    use ark_std::rand::SeedableRng;
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(0xBADE_5A7C);
    (0..WIDTH)
        .map(|_| EdwardsProjective::rand(&mut rng))
        .collect()
});

/// A Pedersen commitment (an elliptic curve point on Bandersnatch).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Commitment(pub EdwardsAffine);

impl Default for Commitment {
    fn default() -> Self {
        Self(EdwardsAffine::zero())
    }
}

impl fmt::Debug for Commitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let x = self.0.x;
        let s = format!("{:?}", x);
        let prefix = &s[..s.len().min(20)];
        write!(f, "C({}...)", prefix)
    }
}

// Manual serde: serialize as compressed point bytes.
impl serde::Serialize for Commitment {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use ark_serialize::CanonicalSerialize;
        let mut bytes = Vec::new();
        self.0
            .serialize_compressed(&mut bytes)
            .map_err(serde::ser::Error::custom)?;
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de> serde::Deserialize<'de> for Commitment {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use ark_serialize::CanonicalDeserialize;
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        let point =
            EdwardsAffine::deserialize_compressed(&bytes[..]).map_err(serde::de::Error::custom)?;
        Ok(Commitment(point))
    }
}

/// A scalar field element (Fr of Bandersnatch).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct FieldElement(pub Fr);

impl fmt::Debug for FieldElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "F({:?})", self.0)
    }
}

impl FieldElement {
    /// Create a field element from a u64 integer.
    pub fn from_u64(v: u64) -> Self {
        Self(Fr::from(v))
    }
}

/// The zero commitment (point at infinity = additive identity).
pub static ZERO_COMMITMENT_LAZY: LazyLock<Commitment> =
    LazyLock::new(|| Commitment(EdwardsAffine::zero()));

/// Get the zero commitment (point at infinity).
pub fn zero_commitment() -> Commitment {
    *ZERO_COMMITMENT_LAZY
}

/// Create a zero field element.
pub fn field_zero() -> FieldElement {
    FieldElement(Fr::ZERO)
}

/// Create a field element from a u8 byte.
pub fn field_from_byte(b: u8) -> FieldElement {
    FieldElement(Fr::from(b as u64))
}

/// Create a field element representing the integer 1.
pub fn field_one() -> FieldElement {
    FieldElement(Fr::from(1u64))
}

/// Compute a vector commitment: C = Σ values[i] * G_i.
pub fn commit<I>(values: I) -> Commitment
where
    I: IntoIterator<Item = (usize, FieldElement)>,
{
    let basis = &*BASIS;
    let mut acc = EdwardsProjective::zero();
    for (i, v) in values {
        debug_assert!(i < WIDTH, "commitment index out of range");
        acc += basis[i] * v.0;
    }
    Commitment(acc.into_affine())
}

/// Homomorphic update: C_new = C_old + (new_value - old_value) * G_index.
pub fn commit_update(
    old_commitment: Commitment,
    index: usize,
    old_value: FieldElement,
    new_value: FieldElement,
) -> Commitment {
    debug_assert!(index < WIDTH);
    let basis = &*BASIS;
    let delta = new_value.0 - old_value.0;
    let update = basis[index] * delta;
    let old_proj: EdwardsProjective = old_commitment.0.into();
    let new_point = old_proj + update;
    Commitment(new_point.into_affine())
}

/// Convert a byte slice to a field element.
pub fn value_to_field(value: &[u8]) -> FieldElement {
    if value.len() <= 31 {
        let mut bytes = [0u8; 32];
        bytes[..value.len()].copy_from_slice(value);
        bytes[31] = 0; // ensure fits in field
        FieldElement(Fr::from_le_bytes_mod_order(&bytes))
    } else {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(value);
        let mut bytes = [0u8; 32];
        bytes[..31].copy_from_slice(&hash[..31]);
        bytes[31] = 0;
        FieldElement(Fr::from_le_bytes_mod_order(&bytes))
    }
}

/// Convert an integer to a field element.
pub fn int_to_field(v: u64) -> FieldElement {
    FieldElement(Fr::from(v))
}

/// Convert a commitment (curve point) to a field element.
///
/// Maps via hashing the serialized point. In production, this would use
/// the Banderwagon "map to scalar" function.
pub fn commitment_to_field(c: Commitment) -> FieldElement {
    use ark_serialize::CanonicalSerialize;
    use sha2::{Digest, Sha256};

    let mut bytes = Vec::new();
    c.0.serialize_compressed(&mut bytes)
        .expect("serialization should not fail");
    let hash = Sha256::digest(&bytes);
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes[..31].copy_from_slice(&hash[..31]);
    scalar_bytes[31] = 0;
    FieldElement(Fr::from_le_bytes_mod_order(&scalar_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_commitment_is_zero() {
        let c = commit(std::iter::empty());
        assert_eq!(c, zero_commitment());
    }

    #[test]
    fn homomorphic_property() {
        let v0 = FieldElement(Fr::from(5u64));
        let v1_old = FieldElement(Fr::from(10u64));
        let v1_new = FieldElement(Fr::from(20u64));

        let original = commit(vec![(0, v0), (1, v1_old)]);
        let updated = commit_update(original, 1, v1_old, v1_new);
        let recomputed = commit(vec![(0, v0), (1, v1_new)]);
        assert_eq!(updated, recomputed);
    }

    #[test]
    fn update_from_zero() {
        let v = FieldElement(Fr::from(100u64));
        let updated = commit_update(zero_commitment(), 5, field_zero(), v);
        let direct = commit(vec![(5, v)]);
        assert_eq!(updated, direct);
    }

    #[test]
    fn commitment_changes_with_value() {
        let c1 = commit(vec![(0, FieldElement(Fr::from(1u64)))]);
        let c2 = commit(vec![(0, FieldElement(Fr::from(2u64)))]);
        assert_ne!(c1, c2);
    }

    #[test]
    fn multi_update_homomorphic() {
        let vals: Vec<(usize, FieldElement)> = (0..10)
            .map(|i| (i, FieldElement(Fr::from((i + 1) as u64))))
            .collect();

        let from_scratch = commit(vals.clone());

        let mut incremental = zero_commitment();
        for &(i, v) in &vals {
            incremental = commit_update(incremental, i, field_zero(), v);
        }
        assert_eq!(incremental, from_scratch);
    }
}
