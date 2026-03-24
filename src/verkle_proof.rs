//! Verkle proof generation and verification using real IPA opening proofs.
//!
//! Two proof modes:
//! - Individual proofs: one IPA per tree level per key (~544 bytes/level)
//! - Aggregated multiproof: ALL openings across ALL keys compressed into
//!   a single 576-byte proof via the Dankrad Feist multipoint scheme.
//!
use std::collections::HashMap;

use ark_ed_on_bls12_381_bandersnatch::{EdwardsAffine, Fr};
use ark_ff::AdditiveGroup;

use crate::commitment::{commitment_to_field, Commitment};
use crate::ipa::{self as old_ipa, IpaProof};
use crate::multiproof::crs::shared_crs;
use crate::multiproof::lagrange::{LagrangeBasis, PrecomputedWeights};
use crate::multiproof::prover::{MultiPointProof, MultiPointProver, ProverQuery, VerifierQuery};
use crate::multiproof::transcript::Transcript;
use crate::node::*;
use crate::storage::*;

// ============================================================
// Shared precomputed weights (lazy-initialized)
// ============================================================

static PRECOMP: std::sync::LazyLock<PrecomputedWeights> =
    std::sync::LazyLock::new(|| PrecomputedWeights::new(256));

// ============================================================
// Individual proofs (per-level IPA, kept for single-key use)
// ============================================================

/// A single-level IPA opening proof with metadata.
#[derive(Clone, Debug)]
pub struct LevelProof {
    pub commitment: Commitment,
    pub index: u8,
    pub claimed_value: Fr,
    pub ipa_proof: IpaProof,
}

/// A complete verkle proof for a single key with real IPA opening proofs.
#[derive(Clone, Debug)]
pub struct RealVerkleProof {
    pub level_proofs: Vec<LevelProof>,
    pub eas_stem: Vec<u8>,
    pub value: Option<Value>,
    pub inclusion: bool,
    pub depth: usize,
}

impl RealVerkleProof {
    pub fn byte_size(&self) -> usize {
        let level_bytes: usize = self
            .level_proofs
            .iter()
            .map(|p| p.ipa_proof.byte_size())
            .sum();
        let stem_bytes = self.eas_stem.len();
        let value_bytes = self.value.as_ref().map_or(0, |v| v.len());
        level_bytes + stem_bytes + value_bytes + 8
    }
}

// ============================================================
// Helpers
// ============================================================

/// Reconstruct the 256-element scalar vector for an internal node.
fn internal_node_vector(internal: &InternalNode) -> Vec<Fr> {
    let mut v = vec![Fr::ZERO; 256];
    for (&idx, child) in &internal.children {
        v[idx as usize] = commitment_to_field(child.commitment).0;
    }
    v
}

/// Data collected during tree traversal for one key.
struct KeyTraversal {
    /// (commitment_affine, value_vector, child_index, child_value_as_scalar)
    openings: Vec<(EdwardsAffine, Vec<Fr>, usize, Fr)>,
    eas_stem: Vec<u8>,
    value: Option<Value>,
    inclusion: bool,
    depth: usize,
}

/// Walk the tree for a key, collecting opening data without generating proofs.
fn traverse_for_key<S: TreeReader>(
    store: &S,
    root_key: &NodeKey,
    key: &Key,
) -> Option<KeyTraversal> {
    let mut openings = Vec::new();
    let mut current_key = root_key.clone();
    let mut depth = 0;

    loop {
        let node = store.get_node(&current_key)?;

        match node {
            Node::Internal(internal) => {
                let child_index = key[depth];
                let a = internal_node_vector(internal);
                let claimed_value = a[child_index as usize];

                openings.push((
                    internal.commitment.0,
                    a,
                    child_index as usize,
                    claimed_value,
                ));

                match internal.children.get(&child_index) {
                    Some(child) => {
                        let child_path: Vec<u8> = key[..depth + 1].to_vec();
                        current_key = NodeKey::new(child.version, child_path);
                        depth += 1;
                    }
                    None => {
                        return Some(KeyTraversal {
                            openings,
                            eas_stem: vec![],
                            value: None,
                            inclusion: false,
                            depth,
                        });
                    }
                }
            }
            Node::EaS(eas) => {
                let expected_stem = &key[depth..31];
                if eas.stem == expected_stem {
                    let suffix = key[31];
                    let value = eas.values.get(&suffix).cloned();
                    return Some(KeyTraversal {
                        openings,
                        eas_stem: eas.stem.clone(),
                        value: value.clone(),
                        inclusion: value.is_some(),
                        depth,
                    });
                } else {
                    return Some(KeyTraversal {
                        openings,
                        eas_stem: eas.stem.clone(),
                        value: None,
                        inclusion: false,
                        depth,
                    });
                }
            }
        }
    }
}

// ============================================================
// Individual proof generation (single key)
// ============================================================

/// Generate a verkle proof with individual IPA proofs for a single key.
pub fn prove<S: TreeReader>(store: &S, root_key: &NodeKey, key: &Key) -> Option<RealVerkleProof> {
    let traversal = traverse_for_key(store, root_key, key)?;

    let level_proofs: Vec<LevelProof> = traversal
        .openings
        .iter()
        .map(|(comm, a, index, claimed)| {
            let (_, ipa_proof) = old_ipa::prove(a, comm, *index);
            LevelProof {
                commitment: Commitment(*comm),
                index: *index as u8,
                claimed_value: *claimed,
                ipa_proof,
            }
        })
        .collect();

    Some(RealVerkleProof {
        level_proofs,
        eas_stem: traversal.eas_stem,
        value: traversal.value,
        inclusion: traversal.inclusion,
        depth: traversal.depth,
    })
}

/// Verify a single-key verkle proof.
pub fn verify(
    proof: &RealVerkleProof,
    root_commitment: Commitment,
    key: &Key,
    expected_value: Option<&Value>,
) -> bool {
    if proof.value.as_ref() != expected_value {
        return false;
    }
    if proof.inclusion != expected_value.is_some() {
        return false;
    }

    let expected_commitment = root_commitment;
    for level_proof in &proof.level_proofs {
        if level_proof.commitment != expected_commitment {
            return false;
        }
        if !old_ipa::verify(
            &level_proof.commitment.0,
            level_proof.index as usize,
            &level_proof.claimed_value,
            &level_proof.ipa_proof,
            256,
        ) {
            return false;
        }
    }

    if proof.inclusion {
        let expected_stem = &key[proof.depth..31];
        if proof.eas_stem != expected_stem {
            return false;
        }
    }

    true
}

// ============================================================
// Aggregated multiproof (batch keys → single 576-byte proof)
// ============================================================

/// Per-key metadata included in the aggregated proof.
#[derive(Clone, Debug)]
pub struct KeyProofData {
    pub key: Key,
    pub eas_stem: Vec<u8>,
    pub value: Option<Value>,
    pub inclusion: bool,
    pub depth: usize,
}

/// An aggregated verkle proof using the Dankrad Feist multipoint scheme.
///
/// Contains a single `MultiPointProof` (~576 bytes) that covers ALL openings
/// across ALL keys, plus the per-key metadata and verifier query data needed
/// to reconstruct the transcript during verification.
#[derive(Clone, Debug)]
pub struct AggregatedMultiProof {
    /// The constant-size multipoint proof.
    pub multipoint_proof: MultiPointProof,
    /// Per-key proof data (stem, value, inclusion).
    pub key_data: Vec<KeyProofData>,
    /// Verifier query data: (commitment, point, result) for each opening.
    /// Shared across keys that traverse the same nodes.
    pub verifier_queries: Vec<(EdwardsAffine, usize, Fr)>,
}

impl AggregatedMultiProof {
    /// The multipoint proof size (constant regardless of key count).
    pub fn proof_byte_size(&self) -> usize {
        self.multipoint_proof.byte_size()
    }

    /// Total proof size including all metadata.
    pub fn total_byte_size(&self) -> usize {
        let proof_bytes = self.multipoint_proof.byte_size();
        // Per query: 32 (commitment) + 1 (point) + 32 (result) = 65
        let query_bytes = self.verifier_queries.len() * 65;
        // Per key: 32 (key) + stem + value + flags
        let key_bytes: usize = self
            .key_data
            .iter()
            .map(|kd| 32 + kd.eas_stem.len() + kd.value.as_ref().map_or(0, |v| v.len()) + 2)
            .sum();
        proof_bytes + query_bytes + key_bytes
    }
}

/// Generate an aggregated multiproof for multiple keys.
///
/// Traverses the tree for each key, collects all openings, deduplicates
/// shared nodes, and aggregates everything into a single multipoint proof.
pub fn prove_aggregated<S: TreeReader>(
    store: &S,
    root_key: &NodeKey,
    keys: &[Key],
) -> Option<AggregatedMultiProof> {
    let crs = shared_crs();
    let precomp = &*PRECOMP;

    // Traverse tree for each key
    let mut key_data = Vec::with_capacity(keys.len());
    let mut all_prover_queries = Vec::new();
    let mut verifier_queries_out = Vec::new();

    // Deduplicate: track which (commitment, index) pairs we've already seen
    // to avoid duplicate queries. Key = (commitment_bytes, index).
    let mut seen: HashMap<([u8; 32], usize), usize> = HashMap::new();

    for key in keys {
        let traversal = traverse_for_key(store, root_key, key)?;

        key_data.push(KeyProofData {
            key: *key,
            eas_stem: traversal.eas_stem,
            value: traversal.value,
            inclusion: traversal.inclusion,
            depth: traversal.depth,
        });

        for (comm, a, index, result) in &traversal.openings {
            // Deduplicate by commitment + index
            use ark_serialize::CanonicalSerialize;
            let mut comm_bytes = [0u8; 32];
            comm.serialize_compressed(&mut comm_bytes[..]).unwrap();
            let dedup_key = (comm_bytes, *index);

            if seen.contains_key(&dedup_key) {
                continue;
            }
            seen.insert(dedup_key, all_prover_queries.len());

            all_prover_queries.push(ProverQuery {
                commitment: *comm,
                poly: LagrangeBasis::new(a.clone()),
                point: *index,
                result: *result,
            });
            verifier_queries_out.push((*comm, *index, *result));
        }
    }

    if all_prover_queries.is_empty() {
        // All keys hit root EaS directly, no internal nodes to prove
        return Some(AggregatedMultiProof {
            multipoint_proof: MultiPointProof {
                ipa_proof: crate::multiproof::ipa::IPAProof {
                    l_vec: vec![],
                    r_vec: vec![],
                    a_scalar: Fr::ZERO,
                },
                d_comm: EdwardsAffine::default(),
            },
            key_data,
            verifier_queries: verifier_queries_out,
        });
    }

    // Generate the aggregated multipoint proof
    let mut transcript = Transcript::new(b"jvt_verkle_multiproof");
    let proof = MultiPointProver::open(crs, precomp, &mut transcript, all_prover_queries);

    Some(AggregatedMultiProof {
        multipoint_proof: proof,
        key_data,
        verifier_queries: verifier_queries_out,
    })
}

/// Verify an aggregated multiproof.
pub fn verify_aggregated(
    proof: &AggregatedMultiProof,
    root_commitment: Commitment,
    keys: &[Key],
    expected_values: &[Option<Value>],
) -> bool {
    if proof.key_data.len() != keys.len() || keys.len() != expected_values.len() {
        return false;
    }

    // Check per-key data
    for (i, kd) in proof.key_data.iter().enumerate() {
        if kd.key != keys[i] {
            return false;
        }
        if kd.value.as_ref() != expected_values[i].as_ref() {
            return false;
        }
        if kd.inclusion != expected_values[i].is_some() {
            return false;
        }
        if kd.inclusion {
            let expected_stem = &keys[i][kd.depth..31];
            if kd.eas_stem != expected_stem {
                return false;
            }
        }
    }

    // If no openings (all keys hit root EaS), just check per-key data
    if proof.verifier_queries.is_empty() {
        return true;
    }

    // Verify the first query's commitment matches the root
    if !proof.verifier_queries.is_empty() {
        let first_comm = Commitment(proof.verifier_queries[0].0);
        if first_comm != root_commitment {
            return false;
        }
    }

    // Reconstruct verifier queries and verify the multipoint proof
    let crs = shared_crs();
    let precomp = &*PRECOMP;

    let vqs: Vec<VerifierQuery> = proof
        .verifier_queries
        .iter()
        .map(|(comm, point, result)| VerifierQuery {
            commitment: *comm,
            point: *point,
            result: *result,
        })
        .collect();

    let mut transcript = Transcript::new(b"jvt_verkle_multiproof");
    proof
        .multipoint_proof
        .check(crs, precomp, &vqs, &mut transcript)
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStore;
    use crate::tree::{apply_updates, root_commitment_at};
    use std::collections::BTreeMap;

    fn make_key(first: u8, second: u8, suffix: u8) -> Key {
        let mut key = [0u8; 32];
        key[0] = first;
        key[1] = second;
        key[31] = suffix;
        key
    }

    fn insert(store: &mut MemoryStore, key: Key, value: Value) {
        let parent = store.latest_version();
        let new_version = parent.map_or(1, |v| v + 1);
        let mut updates = BTreeMap::new();
        updates.insert(key, Some(value));
        let result = apply_updates(store, parent, new_version, updates);
        store.apply(&result);
    }

    fn root_c(store: &MemoryStore) -> Commitment {
        root_commitment_at(store, store.latest_version().unwrap())
    }

    // --- Individual proof tests ---

    #[test]
    fn real_proof_single_key() {
        let mut store = MemoryStore::new();
        let key = make_key(1, 2, 3);
        let value = vec![42];
        insert(&mut store, key, value.clone());

        let rk = store.latest_root_key().unwrap();
        let proof = prove(&store, rk, &key).unwrap();
        assert!(proof.inclusion);
        assert_eq!(proof.value, Some(value.clone()));
        assert!(verify(&proof, root_c(&store), &key, Some(&value)));
    }

    #[test]
    fn real_proof_after_split() {
        let mut store = MemoryStore::new();
        insert(&mut store, make_key(1, 0, 0), vec![10]);
        insert(&mut store, make_key(2, 0, 0), vec![20]);

        let rk = store.latest_root_key().unwrap();
        let rc = root_c(&store);

        let p1 = prove(&store, rk, &make_key(1, 0, 0)).unwrap();
        assert!(verify(&p1, rc, &make_key(1, 0, 0), Some(&vec![10])));

        let p2 = prove(&store, rk, &make_key(2, 0, 0)).unwrap();
        assert!(verify(&p2, rc, &make_key(2, 0, 0), Some(&vec![20])));
    }

    // --- Aggregated multiproof tests ---

    #[test]
    fn aggregated_proof_single_key() {
        let mut store = MemoryStore::new();
        let key = make_key(1, 2, 3);
        let value = vec![42];
        insert(&mut store, key, value.clone());

        let rk = store.latest_root_key().unwrap();
        let proof = prove_aggregated(&store, rk, &[key]).unwrap();
        assert!(verify_aggregated(
            &proof,
            root_c(&store),
            &[key],
            &[Some(value)]
        ));
    }

    #[test]
    fn aggregated_proof_two_keys() {
        let mut store = MemoryStore::new();
        insert(&mut store, make_key(1, 0, 0), vec![10]);
        insert(&mut store, make_key(2, 0, 0), vec![20]);

        let rk = store.latest_root_key().unwrap();
        let rc = root_c(&store);

        let proof = prove_aggregated(&store, rk, &[make_key(1, 0, 0), make_key(2, 0, 0)]).unwrap();
        println!(
            "Aggregated proof (2 keys): {} bytes proof, {} bytes total",
            proof.proof_byte_size(),
            proof.total_byte_size()
        );
        assert_eq!(proof.proof_byte_size(), 576);
        assert!(verify_aggregated(
            &proof,
            rc,
            &[make_key(1, 0, 0), make_key(2, 0, 0)],
            &[Some(vec![10]), Some(vec![20])]
        ));
    }

    #[test]
    fn aggregated_proof_many_keys() {
        let mut store = MemoryStore::new();
        let keys: Vec<Key> = (0..20u8)
            .map(|i| make_key(i, i.wrapping_mul(7), i.wrapping_mul(13)))
            .collect();
        let values: Vec<Value> = (0..20u8).map(|i| vec![i]).collect();
        for (k, v) in keys.iter().zip(values.iter()) {
            insert(&mut store, *k, v.clone());
        }

        let rk = store.latest_root_key().unwrap();
        let proof = prove_aggregated(&store, rk, &keys).unwrap();
        println!(
            "Aggregated proof (20 keys): {} bytes proof, {} openings",
            proof.proof_byte_size(),
            proof.verifier_queries.len()
        );
        assert_eq!(proof.proof_byte_size(), 576);

        let expected: Vec<Option<Value>> = values.into_iter().map(Some).collect();
        assert!(verify_aggregated(&proof, root_c(&store), &keys, &expected));
    }

    #[test]
    fn aggregated_proof_rejects_wrong_value() {
        let mut store = MemoryStore::new();
        insert(&mut store, make_key(1, 0, 0), vec![10]);
        insert(&mut store, make_key(2, 0, 0), vec![20]);

        let rk = store.latest_root_key().unwrap();
        let proof = prove_aggregated(&store, rk, &[make_key(1, 0, 0), make_key(2, 0, 0)]).unwrap();
        assert!(!verify_aggregated(
            &proof,
            root_c(&store),
            &[make_key(1, 0, 0), make_key(2, 0, 0)],
            &[Some(vec![10]), Some(vec![99])]
        ));
    }

    #[test]
    fn aggregated_proof_with_shared_internal_nodes() {
        let mut store = MemoryStore::new();
        insert(&mut store, make_key(5, 1, 0), vec![10]);
        insert(&mut store, make_key(5, 2, 0), vec![20]);
        insert(&mut store, make_key(6, 0, 0), vec![30]);

        let rk = store.latest_root_key().unwrap();
        let proof = prove_aggregated(
            &store,
            rk,
            &[make_key(5, 1, 0), make_key(5, 2, 0), make_key(6, 0, 0)],
        )
        .unwrap();
        println!(
            "Shared nodes proof (3 keys): {} bytes proof, {} openings (deduplicated)",
            proof.proof_byte_size(),
            proof.verifier_queries.len()
        );
        assert!(verify_aggregated(
            &proof,
            root_c(&store),
            &[make_key(5, 1, 0), make_key(5, 2, 0), make_key(6, 0, 0)],
            &[Some(vec![10]), Some(vec![20]), Some(vec![30])]
        ));
    }

    #[test]
    fn aggregated_proof_nonexistent_key() {
        let mut store = MemoryStore::new();
        insert(&mut store, make_key(1, 0, 0), vec![10]);
        insert(&mut store, make_key(2, 0, 0), vec![20]);

        let rk = store.latest_root_key().unwrap();
        let key3 = make_key(1, 99, 0);
        let proof = prove_aggregated(&store, rk, &[make_key(1, 0, 0), key3]).unwrap();
        assert!(verify_aggregated(
            &proof,
            root_c(&store),
            &[make_key(1, 0, 0), key3],
            &[Some(vec![10]), None]
        ));
    }
}
