//! Multipoint proof: aggregates multiple polynomial openings into a single proof.
//!
//! Protocol (Dankrad Feist scheme):
//!
//! Prover has N queries (C_i, f_i, z_i, y_i) where C_i = commit(f_i), f_i(z_i) = y_i.
//! 1. Fiat-Shamir challenge `r` from all (C_i, z_i, y_i)
//! 2. Group polynomials by z, aggregate with powers of r
//! 3. Compute quotient g(X) = Σ_groups agg_f(X) / (X - z) via barycentric division
//! 4. D = commit(g), challenge t from transcript
//! 5. h(X) = Σ_groups agg_f(X) / (t - z), E = commit(h)
//! 6. Single IPA proof for h(X) - g(X) at point t
//! 7. Proof = (D, IPA_proof) — ~576 bytes total regardless of N

use ark_ec::CurveGroup;
use ark_ed_on_bls12_381_bandersnatch::{EdwardsAffine, EdwardsProjective, Fr};
use ark_ff::AdditiveGroup;
use ark_std::Zero;

use super::crs::CRS;
use super::ipa::{self, IPAProof};
use super::lagrange::*;
use super::transcript::Transcript;

/// A prover query: commitment, polynomial (evaluation form), evaluation point, result.
#[derive(Clone, Debug)]
pub struct ProverQuery {
    pub commitment: EdwardsAffine,
    pub poly: LagrangeBasis,
    pub point: usize, // evaluation point (domain index, 0..255)
    pub result: Fr,   // f(point)
}

/// A verifier query: commitment, evaluation point, result.
#[derive(Clone, Debug)]
pub struct VerifierQuery {
    pub commitment: EdwardsAffine,
    pub point: usize,
    pub result: Fr,
}

impl From<&ProverQuery> for VerifierQuery {
    fn from(pq: &ProverQuery) -> Self {
        VerifierQuery {
            commitment: pq.commitment,
            point: pq.point,
            result: pq.result,
        }
    }
}

/// The multipoint proof: a single IPA proof + the quotient commitment D.
#[derive(Clone, Debug)]
pub struct MultiPointProof {
    pub ipa_proof: IPAProof,
    pub d_comm: EdwardsAffine,
}

impl MultiPointProof {
    /// Serialized byte size: 1 point (D) + IPA proof.
    pub fn byte_size(&self) -> usize {
        32 + self.ipa_proof.byte_size()
    }
}

pub struct MultiPointProver;

impl MultiPointProver {
    /// Create a multipoint proof aggregating multiple polynomial openings.
    pub fn open(
        crs: &CRS,
        precomp: &PrecomputedWeights,
        transcript: &mut Transcript,
        queries: Vec<ProverQuery>,
    ) -> MultiPointProof {
        transcript.domain_sep(b"multiproof");

        let n = crs.n;

        // 1. Append all queries to transcript and get challenge r
        for query in &queries {
            transcript.append_point(b"C", &query.commitment);
            let z = Fr::from(query.point as u64);
            transcript.append_scalar(b"z", &z);
            transcript.append_scalar(b"y", &query.result);
        }

        let r = transcript.challenge_scalar(b"r");
        let powers_of_r = powers_of(r, queries.len());

        // 2. Group polynomials by evaluation point, aggregate with powers of r
        // grouped_fs[z] = Σ r^i * f_i(X) for all queries with point == z
        let mut grouped_fs: Vec<Option<Vec<Fr>>> = vec![None; n];
        for (i, query) in queries.iter().enumerate() {
            let z = query.point;
            let entry = grouped_fs[z].get_or_insert_with(|| vec![Fr::ZERO; n]);
            for (j, val) in query.poly.values.iter().enumerate() {
                entry[j] += powers_of_r[i] * *val;
            }
        }

        // 3. Compute g(X) = Σ_groups agg_f(X) / (X - z) via barycentric division
        let mut g_x = vec![Fr::ZERO; n];
        for (z, agg_f) in grouped_fs.iter().enumerate() {
            if let Some(agg_f) = agg_f {
                let poly = LagrangeBasis::new(agg_f.clone());
                let quotient = poly.divide_on_domain(precomp, z);
                for (j, val) in quotient.values.iter().enumerate() {
                    g_x[j] += val;
                }
            }
        }

        let d_comm = crs.commit_lagrange(&g_x);
        transcript.append_point(b"D", &d_comm);

        // 4. Get challenge t (evaluation point outside domain)
        let t = transcript.challenge_scalar(b"t");

        // 5. Compute h(X) = Σ_groups agg_f(X) / (t - z) (scalar division, t outside domain)
        // First compute 1/(t - z) for each referenced z
        let mut denominators: Vec<Fr> = Vec::new();
        let mut denom_indices: Vec<usize> = Vec::new();
        for (z, agg_f) in grouped_fs.iter().enumerate() {
            if agg_f.is_some() {
                denominators.push(t - Fr::from(z as u64));
                denom_indices.push(z);
            }
        }
        batch_inversion(&mut denominators);

        let mut h_x = vec![Fr::ZERO; n];
        for (idx, &z) in denom_indices.iter().enumerate() {
            let agg_f = grouped_fs[z].as_ref().unwrap();
            let den_inv = denominators[idx];
            for (j, val) in agg_f.iter().enumerate() {
                h_x[j] += *val * den_inv;
            }
        }

        let e_comm = crs.commit_lagrange(&h_x);
        transcript.append_point(b"E", &e_comm);

        // 6. Compute h(X) - g(X) and create IPA proof at point t
        let h_minus_g: Vec<Fr> = h_x.iter().zip(g_x.iter()).map(|(h, g)| *h - *g).collect();
        let e_minus_d: EdwardsAffine = (Into::<EdwardsProjective>::into(e_comm)
            - Into::<EdwardsProjective>::into(d_comm))
        .into_affine();

        let ipa_proof = ipa::create(
            transcript,
            crs,
            h_minus_g,
            e_minus_d,
            LagrangeBasis::evaluate_lagrange_coefficients(precomp, n, t),
            t,
        );

        MultiPointProof { ipa_proof, d_comm }
    }
}

impl MultiPointProof {
    /// Verify a multipoint proof.
    pub fn check(
        &self,
        crs: &CRS,
        precomp: &PrecomputedWeights,
        queries: &[VerifierQuery],
        transcript: &mut Transcript,
    ) -> bool {
        transcript.domain_sep(b"multiproof");
        let n = crs.n;

        // 1. Reconstruct transcript
        for query in queries {
            transcript.append_point(b"C", &query.commitment);
            let z = Fr::from(query.point as u64);
            transcript.append_scalar(b"z", &z);
            transcript.append_scalar(b"y", &query.result);
        }

        let r = transcript.challenge_scalar(b"r");
        let powers_of_r = powers_of(r, queries.len());

        // 2. Append D, get t
        transcript.append_point(b"D", &self.d_comm);
        let t = transcript.challenge_scalar(b"t");

        // 3. Compute g_2(t) = Σ r^i * y_i / (t - z_i)
        // Group by evaluation point for efficiency
        let mut grouped_evals = vec![Fr::ZERO; n];
        for (i, query) in queries.iter().enumerate() {
            grouped_evals[query.point] += powers_of_r[i] * query.result;
        }

        let mut helper_den: Vec<Fr> = (0..n).map(|i| t - Fr::from(i as u64)).collect();
        batch_inversion(&mut helper_den);

        let mut g_2_t = Fr::ZERO;
        for i in 0..n {
            if !grouped_evals[i].is_zero() {
                g_2_t += grouped_evals[i] * helper_den[i];
            }
        }

        // 4. Compute E = Σ C_i * (r^i / (t - z_i))
        let msm_scalars: Vec<Fr> = queries
            .iter()
            .enumerate()
            .map(|(i, q)| powers_of_r[i] * helper_den[q.point])
            .collect();

        let commitments: Vec<EdwardsAffine> = queries.iter().map(|q| q.commitment).collect();
        let e_comm: EdwardsAffine = CRS::msm(&msm_scalars, &commitments).into_affine();

        transcript.append_point(b"E", &e_comm);

        // 5. E - D
        let e_minus_d: EdwardsAffine = (Into::<EdwardsProjective>::into(e_comm)
            - Into::<EdwardsProjective>::into(self.d_comm))
        .into_affine();

        // 6. Verify IPA
        let b = LagrangeBasis::evaluate_lagrange_coefficients(precomp, n, t);
        ipa::verify_multiexp(&self.ipa_proof, transcript, crs, b, e_minus_d, t, g_2_t)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multiproof::crs::CRS;

    fn make_poly(crs: &CRS, values: Vec<Fr>) -> (EdwardsAffine, LagrangeBasis) {
        let commitment = crs.commit_lagrange(&values);
        (commitment, LagrangeBasis::new(values))
    }

    #[test]
    fn multiproof_single_query() {
        let n = 4;
        let crs = CRS::new(n, b"test_multi_1");
        let precomp = PrecomputedWeights::new(n);

        let values = vec![
            Fr::from(1u64),
            Fr::from(10u64),
            Fr::from(200u64),
            Fr::from(78u64),
        ];
        let (comm, poly) = make_poly(&crs, values);

        let point = 1;
        let result = poly.evaluate_in_domain(point);

        let query = ProverQuery {
            commitment: comm,
            poly,
            point,
            result,
        };

        let mut pt = Transcript::new(b"test");
        let proof = MultiPointProver::open(&crs, &precomp, &mut pt, vec![query.clone()]);

        let vq = VerifierQuery::from(&query);
        let mut vt = Transcript::new(b"test");
        assert!(proof.check(&crs, &precomp, &[vq], &mut vt));

        println!("Multiproof (1 query, n={}): {} bytes", n, proof.byte_size());
    }

    #[test]
    fn multiproof_two_polynomials() {
        let n = 4;
        let crs = CRS::new(n, b"test_multi_2");
        let precomp = PrecomputedWeights::new(n);

        let (comm_a, poly_a) = make_poly(
            &crs,
            vec![
                Fr::from(1u64),
                Fr::from(10u64),
                Fr::from(200u64),
                Fr::from(78u64),
            ],
        );
        let (comm_b, poly_b) = make_poly(
            &crs,
            vec![
                Fr::from(32u64),
                Fr::from(23u64),
                Fr::from(11u64),
                Fr::from(5u64),
            ],
        );

        let q_a = ProverQuery {
            commitment: comm_a,
            poly: poly_a.clone(),
            point: 0,
            result: poly_a.evaluate_in_domain(0),
        };
        let q_b = ProverQuery {
            commitment: comm_b,
            poly: poly_b.clone(),
            point: 2,
            result: poly_b.evaluate_in_domain(2),
        };

        let mut pt = Transcript::new(b"test");
        let proof = MultiPointProver::open(&crs, &precomp, &mut pt, vec![q_a.clone(), q_b.clone()]);

        let vqs: Vec<VerifierQuery> = vec![VerifierQuery::from(&q_a), VerifierQuery::from(&q_b)];
        let mut vt = Transcript::new(b"test");
        assert!(proof.check(&crs, &precomp, &vqs, &mut vt));

        println!(
            "Multiproof (2 queries, n={}): {} bytes",
            n,
            proof.byte_size()
        );
    }

    #[test]
    fn multiproof_same_point_different_polys() {
        let n = 4;
        let crs = CRS::new(n, b"test_multi_same_pt");
        let precomp = PrecomputedWeights::new(n);

        let (comm_a, poly_a) = make_poly(
            &crs,
            vec![
                Fr::from(5u64),
                Fr::from(15u64),
                Fr::from(25u64),
                Fr::from(35u64),
            ],
        );
        let (comm_b, poly_b) = make_poly(
            &crs,
            vec![
                Fr::from(100u64),
                Fr::from(200u64),
                Fr::from(300u64),
                Fr::from(400u64),
            ],
        );

        // Both opened at point 1
        let q_a = ProverQuery {
            commitment: comm_a,
            poly: poly_a.clone(),
            point: 1,
            result: poly_a.evaluate_in_domain(1),
        };
        let q_b = ProverQuery {
            commitment: comm_b,
            poly: poly_b.clone(),
            point: 1,
            result: poly_b.evaluate_in_domain(1),
        };

        let mut pt = Transcript::new(b"test");
        let proof = MultiPointProver::open(&crs, &precomp, &mut pt, vec![q_a.clone(), q_b.clone()]);

        let vqs: Vec<VerifierQuery> = vec![VerifierQuery::from(&q_a), VerifierQuery::from(&q_b)];
        let mut vt = Transcript::new(b"test");
        assert!(proof.check(&crs, &precomp, &vqs, &mut vt));
    }

    #[test]
    fn multiproof_rejects_wrong_result() {
        let n = 4;
        let crs = CRS::new(n, b"test_multi_reject");
        let precomp = PrecomputedWeights::new(n);

        let (comm, poly) = make_poly(
            &crs,
            vec![
                Fr::from(1u64),
                Fr::from(2u64),
                Fr::from(3u64),
                Fr::from(4u64),
            ],
        );

        let query = ProverQuery {
            commitment: comm,
            poly,
            point: 0,
            result: Fr::from(1u64), // correct
        };

        let mut pt = Transcript::new(b"test");
        let proof = MultiPointProver::open(&crs, &precomp, &mut pt, vec![query]);

        // Verify with wrong result
        let bad_vq = VerifierQuery {
            commitment: comm,
            point: 0,
            result: Fr::from(999u64), // wrong!
        };

        let mut vt = Transcript::new(b"test");
        assert!(!proof.check(&crs, &precomp, &[bad_vq], &mut vt));
    }

    #[test]
    fn multiproof_256_domain() {
        let n = 256;
        let crs = CRS::new(n, b"test_multi_256");
        let precomp = PrecomputedWeights::new(n);

        // Two polynomials over the full 256-element domain
        let vals_a: Vec<Fr> = (0..n).map(|i| Fr::from(((i % 32) + 1) as u64)).collect();
        let vals_b: Vec<Fr> = (0..n)
            .rev()
            .map(|i| Fr::from(((i % 32) + 1) as u64))
            .collect();

        let (comm_a, poly_a) = make_poly(&crs, vals_a);
        let (comm_b, poly_b) = make_poly(&crs, vals_b);

        let q_a = ProverQuery {
            commitment: comm_a,
            poly: poly_a.clone(),
            point: 0,
            result: poly_a.evaluate_in_domain(0),
        };
        let q_b = ProverQuery {
            commitment: comm_b,
            poly: poly_b.clone(),
            point: 100,
            result: poly_b.evaluate_in_domain(100),
        };

        let mut pt = Transcript::new(b"test");
        let proof = MultiPointProver::open(&crs, &precomp, &mut pt, vec![q_a.clone(), q_b.clone()]);

        println!("Multiproof (2 queries, n=256): {} bytes", proof.byte_size());

        let vqs: Vec<VerifierQuery> = vec![VerifierQuery::from(&q_a), VerifierQuery::from(&q_b)];
        let mut vt = Transcript::new(b"test");
        assert!(proof.check(&crs, &precomp, &vqs, &mut vt));
    }

    #[test]
    fn multiproof_many_queries_256() {
        let n = 256;
        let crs = CRS::new(n, b"test_multi_many");
        let precomp = PrecomputedWeights::new(n);

        // 10 different polynomials, each opened at a different point
        let mut queries = Vec::new();
        for i in 0..10 {
            let vals: Vec<Fr> = (0..n)
                .map(|j| Fr::from(((j + i * 7) % 100 + 1) as u64))
                .collect();
            let (comm, poly) = make_poly(&crs, vals);
            let point = (i * 25) % n;
            let result = poly.evaluate_in_domain(point);
            queries.push(ProverQuery {
                commitment: comm,
                poly,
                point,
                result,
            });
        }

        let mut pt = Transcript::new(b"test");
        let proof = MultiPointProver::open(&crs, &precomp, &mut pt, queries.clone());

        println!(
            "Multiproof (10 queries, n=256): {} bytes",
            proof.byte_size()
        );

        let vqs: Vec<VerifierQuery> = queries.iter().map(VerifierQuery::from).collect();
        let mut vt = Transcript::new(b"test");
        assert!(proof.check(&crs, &precomp, &vqs, &mut vt));
    }
}
