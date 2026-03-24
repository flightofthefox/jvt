//! Verkle proof generation and verification.
//!
//! All proofs use the Dankrad Feist multipoint scheme, producing a constant
//! 576-byte proof regardless of how many keys are included. Even single-key
//! proofs go through the multipoint system — there's no separate code path.

use std::collections::HashMap;

use ark_ed_on_bls12_381_bandersnatch::{EdwardsAffine, Fr};
use ark_ff::AdditiveGroup;

use crate::commitment::{commitment_to_field, Commitment};
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
// Proof types
// ============================================================

/// Per-key metadata included in the proof.
#[derive(Clone, Debug)]
pub struct KeyProofData {
    pub key: Key,
    pub eas_stem: Vec<u8>,
    pub value: Option<Value>,
    pub inclusion: bool,
    pub depth: usize,
}

/// A verkle proof using the Dankrad Feist multipoint scheme.
///
/// Contains a single `MultiPointProof` (~576 bytes) that covers ALL openings
/// across ALL keys, plus per-key metadata and verifier query data needed
/// to reconstruct the transcript during verification.
#[derive(Clone, Debug)]
pub struct VerkleProof {
    /// The constant-size multipoint proof.
    pub multipoint_proof: MultiPointProof,
    /// Per-key proof data (stem, value, inclusion).
    pub key_data: Vec<KeyProofData>,
    /// Verifier query data: (commitment, point, result) for each opening.
    pub verifier_queries: Vec<(EdwardsAffine, usize, Fr)>,
}

impl VerkleProof {
    /// The multipoint proof size (constant regardless of key count).
    pub fn proof_byte_size(&self) -> usize {
        self.multipoint_proof.byte_size()
    }

    /// Total proof size including all metadata.
    pub fn total_byte_size(&self) -> usize {
        let proof_bytes = self.multipoint_proof.byte_size();
        let query_bytes = self.verifier_queries.len() * 65;
        let key_bytes: usize = self
            .key_data
            .iter()
            .map(|kd| 32 + kd.eas_stem.len() + kd.value.as_ref().map_or(0, |v| v.len()) + 2)
            .sum();
        proof_bytes + query_bytes + key_bytes
    }
}

// ============================================================
// Proof generation and verification
// ============================================================

/// Generate a verkle proof for one or more keys.
///
/// All openings across all keys are aggregated into a single 576-byte
/// multipoint proof via the Dankrad Feist scheme.
pub fn prove<S: TreeReader>(store: &S, root_key: &NodeKey, keys: &[Key]) -> Option<VerkleProof> {
    let crs = shared_crs();
    let precomp = &*PRECOMP;

    let mut key_data = Vec::with_capacity(keys.len());
    let mut all_prover_queries = Vec::new();
    let mut verifier_queries_out = Vec::new();

    // Deduplicate: track (commitment, index) pairs we've already seen.
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
        // All keys hit root EaS directly — no internal nodes to prove
        return Some(VerkleProof {
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

    let mut transcript = Transcript::new(b"jvt_verkle_proof");
    let proof = MultiPointProver::open(crs, precomp, &mut transcript, all_prover_queries);

    Some(VerkleProof {
        multipoint_proof: proof,
        key_data,
        verifier_queries: verifier_queries_out,
    })
}

/// Verify a verkle proof.
pub fn verify(
    proof: &VerkleProof,
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
    let first_comm = Commitment(proof.verifier_queries[0].0);
    if first_comm != root_commitment {
        return false;
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

    let mut transcript = Transcript::new(b"jvt_verkle_proof");
    proof
        .multipoint_proof
        .check(crs, precomp, &vqs, &mut transcript)
}

// ============================================================
// Convenience: single-key prove/verify
// ============================================================

/// Generate a verkle proof for a single key.
pub fn prove_single<S: TreeReader>(
    store: &S,
    root_key: &NodeKey,
    key: &Key,
) -> Option<VerkleProof> {
    prove(store, root_key, &[*key])
}

/// Verify a single-key verkle proof.
pub fn verify_single(
    proof: &VerkleProof,
    root_commitment: Commitment,
    key: &Key,
    expected_value: Option<&Value>,
) -> bool {
    verify(proof, root_commitment, &[*key], &[expected_value.cloned()])
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

    // --- Single-key proof tests ---

    #[test]
    fn single_key_proof() {
        let mut store = MemoryStore::new();
        let key = make_key(1, 2, 3);
        let value = vec![42];
        insert(&mut store, key, value.clone());

        let rk = store.latest_root_key().unwrap();
        let proof = prove_single(&store, rk, &key).unwrap();

        assert_eq!(proof.key_data.len(), 1);
        assert!(proof.key_data[0].inclusion);
        assert_eq!(proof.key_data[0].value, Some(value.clone()));

        assert!(verify_single(&proof, root_c(&store), &key, Some(&value)));
    }

    #[test]
    fn single_key_after_split() {
        let mut store = MemoryStore::new();
        insert(&mut store, make_key(1, 0, 0), vec![10]);
        insert(&mut store, make_key(2, 0, 0), vec![20]);

        let rk = store.latest_root_key().unwrap();
        let rc = root_c(&store);

        let p1 = prove_single(&store, rk, &make_key(1, 0, 0)).unwrap();
        assert!(verify_single(&p1, rc, &make_key(1, 0, 0), Some(&vec![10])));

        let p2 = prove_single(&store, rk, &make_key(2, 0, 0)).unwrap();
        assert!(verify_single(&p2, rc, &make_key(2, 0, 0), Some(&vec![20])));
    }

    #[test]
    fn single_key_nonexistent() {
        let mut store = MemoryStore::new();
        insert(&mut store, make_key(1, 2, 3), vec![42]);

        let rk = store.latest_root_key().unwrap();
        let key2 = make_key(5, 6, 7);
        let proof = prove_single(&store, rk, &key2).unwrap();
        assert!(verify_single(&proof, root_c(&store), &key2, None));
    }

    // --- Batch proof tests ---

    #[test]
    fn batch_two_keys() {
        let mut store = MemoryStore::new();
        insert(&mut store, make_key(1, 0, 0), vec![10]);
        insert(&mut store, make_key(2, 0, 0), vec![20]);

        let rk = store.latest_root_key().unwrap();
        let keys = [make_key(1, 0, 0), make_key(2, 0, 0)];
        let proof = prove(&store, rk, &keys).unwrap();

        assert_eq!(proof.proof_byte_size(), 576);
        assert!(verify(
            &proof,
            root_c(&store),
            &keys,
            &[Some(vec![10]), Some(vec![20])],
        ));
    }

    #[test]
    fn batch_many_keys() {
        let mut store = MemoryStore::new();
        let keys: Vec<Key> = (0..20u8)
            .map(|i| make_key(i, i.wrapping_mul(7), i.wrapping_mul(13)))
            .collect();
        let values: Vec<Value> = (0..20u8).map(|i| vec![i]).collect();
        for (k, v) in keys.iter().zip(values.iter()) {
            insert(&mut store, *k, v.clone());
        }

        let rk = store.latest_root_key().unwrap();
        let proof = prove(&store, rk, &keys).unwrap();
        assert_eq!(proof.proof_byte_size(), 576);

        let expected: Vec<Option<Value>> = values.into_iter().map(Some).collect();
        assert!(verify(&proof, root_c(&store), &keys, &expected));
    }

    #[test]
    fn batch_rejects_wrong_value() {
        let mut store = MemoryStore::new();
        insert(&mut store, make_key(1, 0, 0), vec![10]);
        insert(&mut store, make_key(2, 0, 0), vec![20]);

        let rk = store.latest_root_key().unwrap();
        let keys = [make_key(1, 0, 0), make_key(2, 0, 0)];
        let proof = prove(&store, rk, &keys).unwrap();

        assert!(!verify(
            &proof,
            root_c(&store),
            &keys,
            &[Some(vec![10]), Some(vec![99])],
        ));
    }

    #[test]
    fn batch_shared_internal_nodes() {
        let mut store = MemoryStore::new();
        insert(&mut store, make_key(5, 1, 0), vec![10]);
        insert(&mut store, make_key(5, 2, 0), vec![20]);
        insert(&mut store, make_key(6, 0, 0), vec![30]);

        let rk = store.latest_root_key().unwrap();
        let keys = [make_key(5, 1, 0), make_key(5, 2, 0), make_key(6, 0, 0)];
        let proof = prove(&store, rk, &keys).unwrap();

        assert!(verify(
            &proof,
            root_c(&store),
            &keys,
            &[Some(vec![10]), Some(vec![20]), Some(vec![30])],
        ));
    }

    #[test]
    fn batch_with_nonexistent_key() {
        let mut store = MemoryStore::new();
        insert(&mut store, make_key(1, 0, 0), vec![10]);
        insert(&mut store, make_key(2, 0, 0), vec![20]);

        let rk = store.latest_root_key().unwrap();
        let key3 = make_key(1, 99, 0);
        let keys = [make_key(1, 0, 0), key3];
        let proof = prove(&store, rk, &keys).unwrap();

        assert!(verify(
            &proof,
            root_c(&store),
            &keys,
            &[Some(vec![10]), None],
        ));
    }
}
