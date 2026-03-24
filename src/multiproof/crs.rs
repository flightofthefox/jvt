//! Common Reference String (CRS) for the IPA and multiproof.
//!
//! Contains the generator points G_0..G_{n-1} and the independent point Q
//! used for binding inner products to commitments.

use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ed_on_bls12_381_bandersnatch::{EdwardsAffine, EdwardsProjective, Fr};
use ark_std::UniformRand;

/// The Common Reference String: basis points and the Q point.
///
/// Generators are stored in affine form for efficient multi-scalar multiplication
/// (arkworks Pippenger uses affine bases for faster mixed addition).
#[derive(Clone)]
pub struct CRS {
    /// Generator points G_0, ..., G_{n-1} in affine form.
    pub g: Vec<EdwardsAffine>,
    /// Independent point Q for inner product binding.
    pub q: EdwardsProjective,
    /// Domain size.
    pub n: usize,
}

impl CRS {
    /// Create a new CRS with `n` generators, deterministically from a seed.
    /// NOT a secure setup — for prototype use only.
    pub fn new(n: usize, seed: &[u8]) -> Self {
        use ark_std::rand::SeedableRng;
        let hash = blake3::hash(seed);
        let rng_seed: [u8; 32] = *hash.as_bytes();
        let mut rng = ark_std::rand::rngs::StdRng::from_seed(rng_seed);

        let g_proj: Vec<EdwardsProjective> =
            (0..n).map(|_| EdwardsProjective::rand(&mut rng)).collect();
        let g = EdwardsProjective::normalize_batch(&g_proj);
        let q = EdwardsProjective::rand(&mut rng);

        Self { g, q, n }
    }

    /// Commit to a polynomial in Lagrange basis: C = Σ values[i] * G_i.
    pub fn commit_lagrange(&self, values: &[Fr]) -> EdwardsAffine {
        assert_eq!(values.len(), self.n);
        EdwardsProjective::msm(&self.g, values)
            .expect("length mismatch")
            .into_affine()
    }

    /// Multi-scalar multiplication using Pippenger's algorithm (affine bases).
    pub fn msm(scalars: &[Fr], points: &[EdwardsAffine]) -> EdwardsProjective {
        EdwardsProjective::msm(points, scalars).expect("length mismatch")
    }

    /// Multi-scalar multiplication with projective points.
    /// Used in the IPA prover where generators are folded into projective form.
    /// Falls back to naive summation for small inputs where Pippenger overhead
    /// (batch normalization) isn't worth it.
    pub fn msm_proj(scalars: &[Fr], points: &[EdwardsProjective]) -> EdwardsProjective {
        if scalars.len() < 8 {
            scalars
                .iter()
                .zip(points.iter())
                .map(|(s, p)| *p * *s)
                .sum()
        } else {
            let affine = EdwardsProjective::normalize_batch(points);
            EdwardsProjective::msm(&affine, scalars).expect("length mismatch")
        }
    }
}

/// Shared CRS instance for the verkle tree (256-element domain).
/// Uses the same seed as the Ethereum verkle spec for consistency.
static SHARED_CRS: std::sync::LazyLock<CRS> =
    std::sync::LazyLock::new(|| CRS::new(256, b"eth_verkle_oct_2021"));

/// Get the shared CRS instance.
pub fn shared_crs() -> &'static CRS {
    &SHARED_CRS
}
