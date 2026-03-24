//! Inner Product Argument (IPA) for Pedersen vector commitments.
//!
//! Proves that a Pedersen vector commitment `C = Σ a_i * G_i` has value
//! `v = a_j` at index `j`, with proof size O(log n) group elements.
//!
//! This is the core proof primitive for verkle trees. A single opening
//! proof is ~544 bytes (16 group elements + 1 scalar for n=256).
//!
//! The protocol follows the Bulletproofs-style IPA adapted for vector
//! commitment openings, using Fiat-Shamir for non-interactivity.
//!
//! Only available with the `pedersen` feature.

#[cfg(feature = "pedersen")]
pub mod inner {
    use ark_ec::CurveGroup;
    use ark_ed_on_bls12_381_bandersnatch::{EdwardsAffine, EdwardsProjective, Fr};
    use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField};
    use ark_std::Zero;
    use sha2::{Digest, Sha256};

    use crate::commitment::pedersen;

    /// An IPA opening proof for a Pedersen vector commitment.
    ///
    /// Proves that `C = Σ a_i * G_i` has `a_j = claimed_value` at index `j`.
    /// Proof size: 2 * log2(n) group elements + 1 scalar.
    /// For n=256: 2 * 8 = 16 group elements + 1 scalar ≈ 544 bytes.
    #[derive(Clone, Debug)]
    pub struct IpaProof {
        /// Left fold commitments, one per round (log2(n) total).
        pub l_vec: Vec<EdwardsAffine>,
        /// Right fold commitments, one per round (log2(n) total).
        pub r_vec: Vec<EdwardsAffine>,
        /// Final scalar after folding.
        pub a_final: Fr,
    }

    impl IpaProof {
        /// Serialized byte size of this proof.
        pub fn byte_size(&self) -> usize {
            // Each affine point: 32 bytes compressed. Scalar: 32 bytes.
            (self.l_vec.len() + self.r_vec.len()) * 32 + 32
        }
    }

    /// Fiat-Shamir transcript for non-interactive proof generation.
    struct Transcript {
        hasher: Sha256,
    }

    impl Transcript {
        fn new(domain: &[u8]) -> Self {
            let mut hasher = Sha256::new();
            hasher.update(domain);
            Self { hasher }
        }

        fn append_point(&mut self, point: &EdwardsAffine) {
            use ark_serialize::CanonicalSerialize;
            let mut buf = Vec::new();
            point.serialize_compressed(&mut buf).unwrap();
            self.hasher.update(&buf);
        }

        fn append_scalar(&mut self, scalar: &Fr) {
            let bytes = scalar.into_bigint().to_bytes_le();
            self.hasher.update(&bytes);
        }

        fn append_usize(&mut self, val: usize) {
            self.hasher.update(&val.to_le_bytes());
        }

        /// Generate a challenge scalar from the current transcript state.
        fn challenge(&mut self) -> Fr {
            let hash = self.hasher.clone().finalize();
            // Reset hasher with the hash as new state (chain hashing)
            self.hasher = Sha256::new();
            self.hasher.update(&hash);
            let mut bytes = [0u8; 32];
            bytes[..31].copy_from_slice(&hash[..31]);
            bytes[31] = 0; // ensure < field modulus
            Fr::from_le_bytes_mod_order(&bytes)
        }
    }

    /// Get the pre-computed basis points (borrowing from the pedersen module).
    fn get_basis() -> &'static [EdwardsProjective] {
        // Access the BASIS LazyLock from the pedersen module
        // We expose it through a helper function
        pedersen::get_basis()
    }

    /// Compute the inner product of two scalar vectors.
    fn inner_product(a: &[Fr], b: &[Fr]) -> Fr {
        a.iter().zip(b.iter()).map(|(x, y)| *x * *y).sum()
    }

    /// Multi-scalar multiplication: Σ scalars[i] * points[i].
    fn msm(scalars: &[Fr], points: &[EdwardsProjective]) -> EdwardsProjective {
        scalars
            .iter()
            .zip(points.iter())
            .map(|(s, p)| *p * *s)
            .sum()
    }

    /// Generate an IPA opening proof.
    ///
    /// Proves that the vector `a` (committed as `C = Σ a_i * G_i`) has
    /// value `a[index]` at the given index.
    ///
    /// # Arguments
    /// * `a` - The full value vector (256 scalars, sparse positions are 0)
    /// * `commitment` - The Pedersen commitment C = Σ a_i * G_i
    /// * `index` - The index being opened
    ///
    /// # Returns
    /// * `(claimed_value, proof)` - The value at the index and the IPA proof
    pub fn prove(a: &[Fr], commitment: &EdwardsAffine, index: usize) -> (Fr, IpaProof) {
        let n = a.len();
        assert!(n.is_power_of_two(), "vector length must be a power of 2");
        assert!(index < n);

        let claimed_value = a[index];

        // Build the evaluation vector b = e_index (standard basis vector)
        let mut b: Vec<Fr> = vec![Fr::ZERO; n];
        b[index] = Fr::from(1u64);

        // Get basis points
        let basis = get_basis();
        let mut g: Vec<EdwardsProjective> = basis[..n].to_vec();
        let mut a_vec = a.to_vec();
        let mut b_vec = b;

        // We need a "Q" point for binding the inner product to the commitment.
        // Q is a random group element independent of G_i. We derive it from hashing.
        let q_point = {
            let mut hasher = Sha256::new();
            hasher.update(b"JVT_IPA_Q_POINT");
            let hash = hasher.finalize();
            let mut bytes = [0u8; 32];
            bytes[..31].copy_from_slice(&hash[..31]);
            bytes[31] = 0;
            let scalar = Fr::from_le_bytes_mod_order(&bytes);
            basis[0] * scalar // Q = scalar * G_0 (not ideal but sufficient for prototype)
        };

        // Initialize transcript
        let mut transcript = Transcript::new(b"JVT_IPA_v1");
        transcript.append_point(commitment);
        transcript.append_usize(index);
        transcript.append_scalar(&claimed_value);

        // The commitment we're folding: P = C + v * Q
        // This binds the inner product value to the proof
        let p_initial: EdwardsProjective =
            Into::<EdwardsProjective>::into(*commitment) + q_point * claimed_value;

        let rounds = (n as f64).log2() as usize;
        let mut l_vec = Vec::with_capacity(rounds);
        let mut r_vec = Vec::with_capacity(rounds);

        let mut _current_p = p_initial;

        for _round in 0..rounds {
            let half = a_vec.len() / 2;

            let (a_lo, a_hi) = a_vec.split_at(half);
            let (b_lo, b_hi) = b_vec.split_at(half);
            let (g_lo, g_hi) = g.split_at(half);

            // L = <a_lo, G_hi> + <a_lo, b_hi> * Q
            let l_point = msm(a_lo, g_hi) + q_point * inner_product(a_lo, b_hi);

            // R = <a_hi, G_lo> + <a_hi, b_lo> * Q
            let r_point = msm(a_hi, g_lo) + q_point * inner_product(a_hi, b_lo);

            let l_affine = l_point.into_affine();
            let r_affine = r_point.into_affine();

            l_vec.push(l_affine);
            r_vec.push(r_affine);

            // Fiat-Shamir challenge
            transcript.append_point(&l_affine);
            transcript.append_point(&r_affine);
            let u = transcript.challenge();
            let u_inv = u.inverse().expect("challenge must be nonzero");

            // Fold vectors (Bulletproofs convention)
            // a' = x * a_L + x^{-1} * a_R
            a_vec = a_lo
                .iter()
                .zip(a_hi.iter())
                .map(|(lo, hi)| u * *lo + u_inv * *hi)
                .collect();

            // b' = x^{-1} * b_L + x * b_R
            b_vec = b_lo
                .iter()
                .zip(b_hi.iter())
                .map(|(lo, hi)| u_inv * *lo + u * *hi)
                .collect();

            // G' = x^{-1} * G_L + x * G_R
            g = g_lo
                .iter()
                .zip(g_hi.iter())
                .map(|(lo, hi)| *lo * u_inv + *hi * u)
                .collect();

            // P' = L * u^2 + P + R * u^{-2}
            _current_p = l_point * (u * u) + _current_p + r_point * (u_inv * u_inv);
        }

        assert_eq!(a_vec.len(), 1);
        let a_final = a_vec[0];

        (
            claimed_value,
            IpaProof {
                l_vec,
                r_vec,
                a_final,
            },
        )
    }

    /// Verify an IPA opening proof.
    ///
    /// Checks that `commitment = Σ a_i * G_i` has `a[index] = claimed_value`.
    ///
    /// # Arguments
    /// * `commitment` - The Pedersen vector commitment
    /// * `index` - The index being opened
    /// * `claimed_value` - The claimed value at the index
    /// * `proof` - The IPA proof
    /// * `n` - The vector length (must be power of 2)
    pub fn verify(
        commitment: &EdwardsAffine,
        index: usize,
        claimed_value: &Fr,
        proof: &IpaProof,
        n: usize,
    ) -> bool {
        assert!(n.is_power_of_two());
        let rounds = (n as f64).log2() as usize;

        if proof.l_vec.len() != rounds || proof.r_vec.len() != rounds {
            return false;
        }

        let basis = get_basis();
        let q_point = {
            let mut hasher = Sha256::new();
            hasher.update(b"JVT_IPA_Q_POINT");
            let hash = hasher.finalize();
            let mut bytes = [0u8; 32];
            bytes[..31].copy_from_slice(&hash[..31]);
            bytes[31] = 0;
            let scalar = Fr::from_le_bytes_mod_order(&bytes);
            basis[0] * scalar
        };

        // Rebuild transcript and extract challenges
        let mut transcript = Transcript::new(b"JVT_IPA_v1");
        transcript.append_point(commitment);
        transcript.append_usize(index);
        transcript.append_scalar(claimed_value);

        let mut challenges = Vec::with_capacity(rounds);
        for i in 0..rounds {
            transcript.append_point(&proof.l_vec[i]);
            transcript.append_point(&proof.r_vec[i]);
            let u = transcript.challenge();
            challenges.push(u);
        }

        // Compute the folded generator: G_final = fold of G basis with challenge inverses
        // And the folded evaluation: b_final = fold of b = e_index with challenges
        let mut b_vec: Vec<Fr> = vec![Fr::ZERO; n];
        b_vec[index] = Fr::from(1u64);

        let mut g: Vec<EdwardsProjective> = basis[..n].to_vec();

        for (round, u) in challenges.iter().enumerate() {
            let u_inv = u.inverse().expect("challenge nonzero");
            let half = g.len() / 2;

            let (b_lo, b_hi) = b_vec.split_at(half);
            let (g_lo, g_hi) = g.split_at(half);

            // Same folding convention as prover:
            // b' = x^{-1} * b_L + x * b_R
            b_vec = b_lo
                .iter()
                .zip(b_hi.iter())
                .map(|(lo, hi)| u_inv * *lo + *u * *hi)
                .collect();

            // G' = x^{-1} * G_L + x * G_R
            g = g_lo
                .iter()
                .zip(g_hi.iter())
                .map(|(lo, hi)| *lo * u_inv + *hi * *u)
                .collect();

            let _ = round;
        }

        assert_eq!(g.len(), 1);
        assert_eq!(b_vec.len(), 1);

        let g_final = g[0];
        let b_final = b_vec[0];

        // Verify: P' should equal a_final * G_final + (a_final * b_final) * Q
        // where P' = C + v*Q + Σ u_i^2 * L_i + Σ u_i^{-2} * R_i
        let p_initial: EdwardsProjective =
            Into::<EdwardsProjective>::into(*commitment) + q_point * *claimed_value;

        let mut p_folded = p_initial;
        for (i, u) in challenges.iter().enumerate() {
            let u_sq = *u * *u;
            let u_inv_sq = u_sq.inverse().expect("nonzero");
            let l: EdwardsProjective = proof.l_vec[i].into();
            let r: EdwardsProjective = proof.r_vec[i].into();
            p_folded = p_folded + l * u_sq + r * u_inv_sq;
        }

        let expected = g_final * proof.a_final + q_point * (proof.a_final * b_final);

        p_folded.into_affine() == expected.into_affine()
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::commitment::pedersen::{self as ped, FieldElement};

        #[test]
        fn prove_and_verify_single_element() {
            let mut a = vec![Fr::ZERO; 256];
            a[42] = Fr::from(100u64);

            let commitment = ped::commit(
                a.iter()
                    .enumerate()
                    .filter(|(_, v)| !v.is_zero())
                    .map(|(i, v)| (i, FieldElement(*v))),
            );

            let (value, proof) = prove(&a, &commitment.0, 42);
            assert_eq!(value, Fr::from(100u64));
            assert_eq!(proof.l_vec.len(), 8); // log2(256) = 8 rounds
            assert!(verify(&commitment.0, 42, &value, &proof, 256));
            println!("Proof size: {} bytes", proof.byte_size());
        }

        #[test]
        fn prove_and_verify_multiple_values() {
            let mut a = vec![Fr::ZERO; 256];
            for i in 0..10 {
                a[i] = Fr::from((i + 1) as u64);
            }

            let commitment = ped::commit(
                a.iter()
                    .enumerate()
                    .filter(|(_, v)| !v.is_zero())
                    .map(|(i, v)| (i, FieldElement(*v))),
            );

            // Prove and verify each populated index
            for i in 0..10 {
                let (value, proof) = prove(&a, &commitment.0, i);
                assert_eq!(value, Fr::from((i + 1) as u64));
                assert!(
                    verify(&commitment.0, i, &value, &proof, 256),
                    "Verification failed for index {}",
                    i
                );
            }
        }

        #[test]
        fn verify_rejects_wrong_value() {
            let mut a = vec![Fr::ZERO; 256];
            a[5] = Fr::from(42u64);

            let commitment = ped::commit(vec![(5, FieldElement(a[5]))]);

            let (_, proof) = prove(&a, &commitment.0, 5);

            // Try to verify with wrong value
            let wrong_value = Fr::from(999u64);
            assert!(!verify(&commitment.0, 5, &wrong_value, &proof, 256));
        }

        #[test]
        fn verify_rejects_wrong_index() {
            let mut a = vec![Fr::ZERO; 256];
            a[5] = Fr::from(42u64);
            a[10] = Fr::from(99u64);

            let commitment = ped::commit(vec![(5, FieldElement(a[5])), (10, FieldElement(a[10]))]);

            let (value, proof) = prove(&a, &commitment.0, 5);

            // Try to verify at wrong index (should fail)
            assert!(!verify(&commitment.0, 10, &value, &proof, 256));
        }

        #[test]
        fn proof_size_matches_expectation() {
            let mut a = vec![Fr::ZERO; 256];
            a[0] = Fr::from(1u64);

            let commitment = ped::commit(vec![(0, FieldElement(a[0]))]);
            let (_, proof) = prove(&a, &commitment.0, 0);

            // 16 group elements (32 bytes each) + 1 scalar (32 bytes) = 544 bytes
            assert_eq!(proof.byte_size(), 544);
        }
    }
}
