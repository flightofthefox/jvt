//! Common Reference String (CRS) for the IPA and multiproof.
//!
//! Contains the generator points G_0..G_{n-1} and the independent point Q
//! used for binding inner products to commitments.

use ark_ec::CurveGroup;
use ark_ed_on_bls12_381_bandersnatch::{EdwardsAffine, EdwardsProjective, Fr};
use ark_std::UniformRand;

/// The Common Reference String: basis points and the Q point.
#[derive(Clone)]
pub struct CRS {
    /// Generator points G_0, ..., G_{n-1}.
    pub g: Vec<EdwardsProjective>,
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

        let g: Vec<EdwardsProjective> = (0..n).map(|_| EdwardsProjective::rand(&mut rng)).collect();
        let q = EdwardsProjective::rand(&mut rng);

        Self { g, q, n }
    }

    /// Commit to a polynomial in Lagrange basis: C = Σ values[i] * G_i.
    pub fn commit_lagrange(&self, values: &[Fr]) -> EdwardsAffine {
        assert_eq!(values.len(), self.n);
        let result: EdwardsProjective =
            values.iter().zip(self.g.iter()).map(|(v, g)| *g * *v).sum();
        result.into_affine()
    }

    /// Multi-scalar multiplication: Σ scalars[i] * points[i].
    pub fn msm(scalars: &[Fr], points: &[EdwardsProjective]) -> EdwardsProjective {
        scalars
            .iter()
            .zip(points.iter())
            .map(|(s, p)| *p * *s)
            .sum()
    }

    /// MSM with affine points (converts to projective internally).
    pub fn msm_affine(scalars: &[Fr], points: &[EdwardsAffine]) -> EdwardsProjective {
        scalars
            .iter()
            .zip(points.iter())
            .map(|(s, p)| {
                let proj: EdwardsProjective = (*p).into();
                proj * *s
            })
            .sum()
    }
}

/// Shared CRS instance for the verkle tree (256-element domain).
/// Uses the same seed as the Ethereum verkle spec for consistency.
static SHARED_CRS: std::sync::LazyLock<CRS> =
    std::sync::LazyLock::new(|| CRS::new(256, b"eth_verkle_oct_2021"));

/// Get the shared CRS instance.
pub fn shared_crs() -> &'static CRS {
    &*SHARED_CRS
}
