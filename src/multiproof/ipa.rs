//! Inner Product Argument (IPA) matching the crate-crypto/rust-verkle protocol.
//!
//! This IPA operates on polynomials in evaluation form (Lagrange basis).
//! It proves that <a, b> = output_point where:
//! - `a` is the polynomial's evaluation vector
//! - `b` is the evaluation of the Lagrange basis at the input point
//! - The commitment C = Σ a_i * G_i

use ark_ec::CurveGroup;
use ark_ed_on_bls12_381_bandersnatch::{EdwardsAffine, EdwardsProjective, Fr};
use ark_ff::Field;
use ark_std::Zero;

use super::crs::CRS;
use super::lagrange::inner_product;
use super::transcript::Transcript;

/// An IPA proof: L and R vectors plus the final scalar.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IPAProof {
    pub l_vec: Vec<EdwardsAffine>,
    pub r_vec: Vec<EdwardsAffine>,
    pub a_scalar: Fr,
}

impl IPAProof {
    /// Serialized size in bytes.
    pub fn byte_size(&self) -> usize {
        (self.l_vec.len() + self.r_vec.len()) * 32 + 32
    }
}

/// Create an IPA proof.
///
/// Proves that <a, b> = output_point where C = Σ a_i * G_i.
///
/// # Arguments
/// * `transcript` - Fiat-Shamir transcript (shared with caller)
/// * `crs` - Common reference string (will be mutated during folding)
/// * `a_vec` - The polynomial evaluations
/// * `a_comm` - The commitment to `a_vec`
/// * `b_vec` - The evaluation vector (Lagrange coefficients at the input point)
/// * `input_point` - The evaluation point (for transcript binding)
pub fn create(
    transcript: &mut Transcript,
    crs: &CRS,
    mut a_vec: Vec<Fr>,
    a_comm: EdwardsAffine,
    mut b_vec: Vec<Fr>,
    input_point: Fr,
) -> IPAProof {
    transcript.domain_sep(b"ipa");

    let mut g: Vec<EdwardsProjective> = crs.g.iter().map(|p| (*p).into()).collect();
    let n = g.len();
    assert_eq!(a_vec.len(), n);
    assert_eq!(b_vec.len(), n);
    assert!(n.is_power_of_two());

    let output_point = inner_product(&a_vec, &b_vec);

    transcript.append_point(b"C", &a_comm);
    transcript.append_scalar(b"input point", &input_point);
    transcript.append_scalar(b"output point", &output_point);

    let w = transcript.challenge_scalar(b"w");
    let q = crs.q * w;

    let num_rounds = log2(n);
    let mut l_vec = Vec::with_capacity(num_rounds);
    let mut r_vec = Vec::with_capacity(num_rounds);

    for _ in 0..num_rounds {
        let half = a_vec.len() / 2;

        let (a_l, a_r) = a_vec.split_at(half);
        let (b_l, b_r) = b_vec.split_at(half);
        let (g_l, g_r) = g.split_at(half);

        let z_l = inner_product(a_r, b_l);
        let z_r = inner_product(a_l, b_r);

        // L = <a_R, G_L> + z_L * Q
        // R = <a_L, G_R> + z_R * Q
        #[cfg(feature = "parallel")]
        let (l, r): (EdwardsProjective, EdwardsProjective) = rayon::join(
            || CRS::msm_proj(a_r, g_l) + q * z_l,
            || CRS::msm_proj(a_l, g_r) + q * z_r,
        );
        #[cfg(not(feature = "parallel"))]
        let (l, r): (EdwardsProjective, EdwardsProjective) = (
            CRS::msm_proj(a_r, g_l) + q * z_l,
            CRS::msm_proj(a_l, g_r) + q * z_r,
        );

        // Batch normalize L and R together (1 field inversion instead of 2)
        let lr_affine = EdwardsProjective::normalize_batch(&[l, r]);
        let l_affine = lr_affine[0];
        let r_affine = lr_affine[1];

        l_vec.push(l_affine);
        r_vec.push(r_affine);

        transcript.append_point(b"L", &l_affine);
        transcript.append_point(b"R", &r_affine);

        let x = transcript.challenge_scalar(b"x");
        let x_inv = x.inverse().unwrap();

        // Fold: a' = a_L + x * a_R, b' = b_L + x^{-1} * b_R, G' = G_L + x^{-1} * G_R
        let mut new_a = Vec::with_capacity(half);
        let mut new_b = Vec::with_capacity(half);
        let mut new_g = Vec::with_capacity(half);

        for i in 0..half {
            new_a.push(a_l[i] + x * a_r[i]);
            new_b.push(b_l[i] + x_inv * b_r[i]);
            new_g.push(g_l[i] + g_r[i] * x_inv);
        }

        a_vec = new_a;
        b_vec = new_b;
        g = new_g;
    }

    IPAProof {
        l_vec,
        r_vec,
        a_scalar: a_vec[0],
    }
}

/// Verify an IPA proof using the multiexponentiation method.
///
/// This is the efficient verification that avoids log(n) rounds of folding
/// by computing the final check in a single multi-scalar multiplication.
pub fn verify_multiexp(
    proof: &IPAProof,
    transcript: &mut Transcript,
    crs: &CRS,
    b_vec: Vec<Fr>,
    a_comm: EdwardsAffine,
    input_point: Fr,
    output_point: Fr,
) -> bool {
    transcript.domain_sep(b"ipa");

    let logn = proof.l_vec.len();
    let n = crs.n;

    if n != (1 << logn) {
        return false;
    }

    transcript.append_point(b"C", &a_comm);
    transcript.append_scalar(b"input point", &input_point);
    transcript.append_scalar(b"output point", &output_point);

    let w = transcript.challenge_scalar(b"w");

    // Generate all challenges
    let mut challenges = Vec::with_capacity(logn);
    for i in 0..logn {
        transcript.append_point(b"L", &proof.l_vec[i]);
        transcript.append_point(b"R", &proof.r_vec[i]);
        let x_i = transcript.challenge_scalar(b"x");
        challenges.push(x_i);
    }

    let mut challenges_inv = challenges.clone();
    super::lagrange::batch_inversion(&mut challenges_inv);

    // Compute the folded generator coefficients and b coefficients.
    // For each index, the coefficient is the product of x or x_inv depending on the bit.
    let mut g_coeffs = Vec::with_capacity(n);
    let mut b_coeffs = Vec::with_capacity(n);

    for index in 0..n {
        let mut coeff = -Fr::from(1u64);
        for (bit_idx, x_inv) in challenges_inv.iter().enumerate() {
            let bit = (index >> (logn - 1 - bit_idx)) & 1;
            if bit == 1 {
                coeff *= x_inv;
            }
        }
        b_coeffs.push(coeff);
        g_coeffs.push(proof.a_scalar * coeff);
    }

    let b_0 = inner_product(&b_vec, &b_coeffs);
    let q_scalar = w * (output_point + proof.a_scalar * b_0);

    // Final check: 0 = Σ x_i * L_i + Σ x_inv_i * R_i + 1 * a_comm + q_scalar * Q + Σ g_coeffs_i * G_i
    // All terms should sum to zero (the identity point).
    let mut scalars = Vec::with_capacity(2 * logn + 2 + n);
    let mut points: Vec<EdwardsAffine> = Vec::with_capacity(2 * logn + 2 + n);

    // L terms: x_i * L_i
    for (i, x) in challenges.iter().enumerate() {
        scalars.push(*x);
        points.push(proof.l_vec[i]);
    }
    // R terms: x_inv_i * R_i
    for (i, x_inv) in challenges_inv.iter().enumerate() {
        scalars.push(*x_inv);
        points.push(proof.r_vec[i]);
    }
    // a_comm term
    scalars.push(Fr::from(1u64));
    points.push(a_comm);
    // Q term
    scalars.push(q_scalar);
    points.push(crs.q.into_affine());
    // G terms
    for (i, coeff) in g_coeffs.iter().enumerate() {
        scalars.push(*coeff);
        points.push(crs.g[i]);
    }

    let result: EdwardsProjective = CRS::msm(&scalars, &points);
    result.is_zero()
}

fn log2(n: usize) -> usize {
    n.next_power_of_two().trailing_zeros() as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multiproof::crs::CRS;
    use crate::multiproof::lagrange::{inner_product, powers_of};
    use ark_std::{rand::SeedableRng, UniformRand};

    #[test]
    fn ipa_prove_and_verify() {
        let n = 8;
        let crs = CRS::new(n, b"test_ipa");

        let mut rng = ark_std::rand::rngs::StdRng::from_seed([0u8; 32]);
        let a: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let input_point = Fr::rand(&mut rng);

        let b = powers_of(input_point, n);
        let output_point = inner_product(&a, &b);

        let a_comm = crs.commit_lagrange(&a);

        let mut prover_transcript = Transcript::new(b"test");
        let proof = create(
            &mut prover_transcript,
            &crs,
            a,
            a_comm,
            b.clone(),
            input_point,
        );

        let mut verifier_transcript = Transcript::new(b"test");
        assert!(verify_multiexp(
            &proof,
            &mut verifier_transcript,
            &crs,
            b,
            a_comm,
            input_point,
            output_point,
        ));
    }

    #[test]
    fn ipa_256_elements() {
        let n = 256;
        let crs = CRS::new(n, b"test_ipa_256");

        let a: Vec<Fr> = (0..n).map(|i| Fr::from((i + 1) as u64)).collect();
        let input_point = Fr::from(9999u64);

        let b = powers_of(input_point, n);
        let output_point = inner_product(&a, &b);

        let a_comm = crs.commit_lagrange(&a);

        let mut pt = Transcript::new(b"test");
        let proof = create(&mut pt, &crs, a, a_comm, b.clone(), input_point);

        assert_eq!(proof.l_vec.len(), 8); // log2(256) = 8

        let mut vt = Transcript::new(b"test");
        assert!(verify_multiexp(
            &proof,
            &mut vt,
            &crs,
            b,
            a_comm,
            input_point,
            output_point
        ));
    }

    #[test]
    fn ipa_rejects_wrong_output() {
        let n = 8;
        let crs = CRS::new(n, b"test_ipa_reject");

        let a: Vec<Fr> = (0..n).map(|i| Fr::from(i as u64)).collect();
        let input_point = Fr::from(42u64);
        let b = powers_of(input_point, n);
        let output_point = inner_product(&a, &b);

        let a_comm = crs.commit_lagrange(&a);

        let mut pt = Transcript::new(b"test");
        let proof = create(&mut pt, &crs, a, a_comm, b.clone(), input_point);

        // Verify with wrong output
        let wrong_output = output_point + Fr::from(1u64);
        let mut vt = Transcript::new(b"test");
        assert!(!verify_multiexp(
            &proof,
            &mut vt,
            &crs,
            b,
            a_comm,
            input_point,
            wrong_output
        ));
    }
}
