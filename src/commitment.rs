//! Real Pedersen vector commitment scheme on the Bandersnatch curve.
//!
//! Uses the arkworks ecosystem for elliptic curve operations.
//! The Bandersnatch curve is defined over the BLS12-381 scalar field.
//!
//! Commitment = Σ values[i] * G_i where G_i are fixed independent generators.
//! Homomorphic update: C_new = C_old + (new - old) * G_index.

use std::fmt;
use std::sync::LazyLock;

use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ed_on_bls12_381_bandersnatch::{EdwardsAffine, EdwardsProjective, Fr};
use ark_ff::{AdditiveGroup, PrimeField};
use ark_std::Zero;

/// Number of basis points (one per child slot in 256-ary branching).
const WIDTH: usize = 256;

/// Get the pre-computed basis points (affine) from the shared CRS.
/// This ensures the tree's commitments use the same generators as the
/// multiproof system, so proofs verify correctly.
pub fn get_basis_affine() -> &'static [EdwardsAffine] {
    &crate::multiproof::crs::shared_crs().g
}

/// Get the pre-computed basis points in projective form for scalar multiplication.
static BASIS_PROJECTIVE: LazyLock<Vec<EdwardsProjective>> =
    LazyLock::new(|| get_basis_affine().iter().map(|p| (*p).into()).collect());

pub fn get_basis() -> &'static [EdwardsProjective] {
    &BASIS_PROJECTIVE
}

/// Precomputed table: `BYTE_BASIS[position][byte_value]` = `field_from_byte(byte_value) * G_position`.
/// This turns stem commitment computation from scalar multiplications into point additions.
/// Table size: 256 positions × 256 byte values × 1 projective point = ~4MB.
static BYTE_BASIS_TABLE: std::sync::LazyLock<Vec<Vec<EdwardsProjective>>> =
    std::sync::LazyLock::new(|| {
        let basis = get_basis();
        (0..WIDTH)
            .map(|pos| {
                (0..256)
                    .map(|byte_val| {
                        if byte_val == 0 {
                            EdwardsProjective::zero()
                        } else {
                            basis[pos] * Fr::from(byte_val as u64)
                        }
                    })
                    .collect()
            })
            .collect()
    });

/// Get the precomputed byte-basis table.
pub fn byte_basis_table() -> &'static Vec<Vec<EdwardsProjective>> {
    &BYTE_BASIS_TABLE
}

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
///
/// Uses Pippenger MSM for large inputs (>= 8 elements), naive scalar
/// multiplication for small sparse inputs.
pub fn commit<I>(values: I) -> Commitment
where
    I: IntoIterator<Item = (usize, FieldElement)>,
{
    let basis_affine = get_basis_affine();
    let pairs: Vec<(usize, FieldElement)> = values.into_iter().collect();

    if pairs.len() >= 8 {
        let points: Vec<EdwardsAffine> = pairs.iter().map(|(i, _)| basis_affine[*i]).collect();
        let scalars: Vec<Fr> = pairs.iter().map(|(_, v)| v.0).collect();
        let result = EdwardsProjective::msm(&points, &scalars).expect("length mismatch");
        Commitment(result.into_affine())
    } else {
        let basis = get_basis();
        let mut acc = EdwardsProjective::zero();
        for (i, v) in pairs {
            debug_assert!(i < WIDTH, "commitment index out of range");
            acc += basis[i] * v.0;
        }
        Commitment(acc.into_affine())
    }
}

/// Homomorphic update: C_new = C_old + (new_value - old_value) * G_index.
pub fn commit_update(
    old_commitment: Commitment,
    index: usize,
    old_value: FieldElement,
    new_value: FieldElement,
) -> Commitment {
    debug_assert!(index < WIDTH);
    let basis = get_basis();
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
        let hash = blake3::hash(value);
        let mut bytes = [0u8; 32];
        bytes[..31].copy_from_slice(&hash.as_bytes()[..31]);
        bytes[31] = 0;
        FieldElement(Fr::from_le_bytes_mod_order(&bytes))
    }
}

/// Convert an integer to a field element.
pub fn int_to_field(v: u64) -> FieldElement {
    FieldElement(Fr::from(v))
}

/// Convert a commitment (curve point) to a field element using the
/// Banderwagon mapping: `(x, y) → x / y`.
///
/// This is a canonical 2-to-1 map from the twisted Edwards curve to the
/// base field, which identifies `(x, y)` and `(-x, -y)`. The result is
/// serialized and interpreted as a scalar field element.
///
/// Follows the reference implementation in crate-crypto/rust-verkle.
pub fn commitment_to_field(c: Commitment) -> FieldElement {
    use ark_serialize::CanonicalSerialize;

    // Banderwagon map: x / y
    let x_div_y = c.0.x / c.0.y;

    let mut bytes = [0u8; 32];
    x_div_y
        .serialize_compressed(&mut bytes[..])
        .expect("could not serialize base field element");
    FieldElement(Fr::from_le_bytes_mod_order(&bytes))
}

/// Batch-convert commitments to field elements using Montgomery's trick.
/// One base field inversion + 3N multiplications instead of N inversions.
pub fn batch_commitment_to_field(commitments: &[Commitment]) -> Vec<FieldElement> {
    use ark_ed_on_bls12_381_bandersnatch::Fq;
    use ark_serialize::CanonicalSerialize;

    if commitments.is_empty() {
        return Vec::new();
    }

    // Collect y coordinates and batch-invert them
    let mut y_coords: Vec<Fq> = commitments.iter().map(|c| c.0.y).collect();
    ark_ff::batch_inversion(&mut y_coords);

    // Compute x * y_inv for each, then serialize → Fr
    commitments
        .iter()
        .zip(y_coords.iter())
        .map(|(c, y_inv)| {
            let x_div_y = c.0.x * y_inv;
            let mut bytes = [0u8; 32];
            x_div_y
                .serialize_compressed(&mut bytes[..])
                .expect("could not serialize base field element");
            FieldElement(Fr::from_le_bytes_mod_order(&bytes))
        })
        .collect()
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
