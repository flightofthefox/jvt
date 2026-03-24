//! Verkle proof generation and verification.
//!
//! Proofs use the Dankrad Feist multipoint scheme (576 bytes constant).
//! The verifier checks:
//! 1. Each opening is cryptographically valid (multiproof)
//! 2. Openings chain: result[i] == commitment_to_field(commitment[i+1])
//! 3. First opening's commitment matches the root
//! 4. EaS marker byte == 1 (prevents internal/extension commitment confusion)
//! 5. Final opening's result matches the claimed value
//! 6. Empty-slot non-inclusion: the opening result is zero

use std::collections::HashMap;

use ark_ed_on_bls12_381_bandersnatch::{EdwardsAffine, Fr};
use ark_ff::AdditiveGroup;

use crate::commitment::{
    commitment_to_field, field_from_byte, field_one, value_to_field, Commitment,
};
use crate::multiproof::crs::shared_crs;
use crate::multiproof::lagrange::{LagrangeBasis, PrecomputedWeights};
use crate::multiproof::prover::{MultiPointProof, MultiPointProver, ProverQuery, VerifierQuery};
use crate::multiproof::transcript::Transcript;
use crate::node::*;
use crate::storage::*;

static PRECOMP: std::sync::LazyLock<PrecomputedWeights> =
    std::sync::LazyLock::new(|| PrecomputedWeights::new(256));

// ============================================================
// Vector reconstruction
// ============================================================

fn internal_node_vector(internal: &InternalNode) -> Vec<Fr> {
    let mut v = vec![Fr::ZERO; 256];
    for (&idx, child) in &internal.children {
        v[idx as usize] = child.field.0;
    }
    v
}

fn eas_extension_vector(eas: &EaSNode) -> Vec<Fr> {
    let mut v = vec![Fr::ZERO; 256];
    v[0] = field_one().0;
    for (i, &byte) in eas.stem.iter().enumerate() {
        v[i + 1] = field_from_byte(byte).0;
    }
    v[eas.stem.len() + 1] = eas.c1_field.0;
    v[eas.stem.len() + 2] = eas.c2_field.0;
    v
}

fn eas_sub_commitment_vector(eas: &EaSNode, is_c2: bool) -> Vec<Fr> {
    let mut v = vec![Fr::ZERO; 256];
    for (&suffix, val) in &eas.values {
        if is_c2 && suffix >= 128 {
            v[(suffix - 128) as usize] = value_to_field(val).0;
        } else if !is_c2 && suffix < 128 {
            v[suffix as usize] = value_to_field(val).0;
        }
    }
    v
}

// ============================================================
// Traversal
// ============================================================

type Opening = (EdwardsAffine, Vec<Fr>, usize, Fr);

/// How the key lookup terminated.
#[derive(Clone, Debug)]
pub enum TerminationKind {
    /// Found the EaS with matching stem. Value may or may not exist at suffix.
    FoundEaS,
    /// Hit an empty child slot in an internal node.
    EmptySlot,
    /// Found an EaS but stem doesn't match. `diverge_byte` is the first differing position.
    StemMismatch { diverge_byte: usize },
}

struct KeyTraversal {
    openings: Vec<Opening>,
    eas_stem: Vec<u8>,
    value: Option<Value>,
    depth: usize,
    termination: TerminationKind,
}

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

        match &*node {
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
                            depth,
                            termination: TerminationKind::EmptySlot,
                        });
                    }
                }
            }
            Node::EaS(eas) => {
                let expected_stem = &key[depth..key_stem_end(key)];
                if eas.stem == expected_stem {
                    let suffix = key_suffix(key);
                    let value = eas.values.get(&suffix).cloned();
                    let is_c2 = suffix >= 128;

                    // Open the marker byte (index 0) to prove this is an EaS, not an internal node
                    let ext_vec = eas_extension_vector(eas);
                    openings.push((
                        eas.extension_commitment.0,
                        ext_vec.clone(),
                        0, // marker index
                        field_one().0,
                    ));

                    // Open extension → c1 or c2
                    let sub_comm_index = if is_c2 {
                        eas.stem.len() + 2
                    } else {
                        eas.stem.len() + 1
                    };
                    openings.push((
                        eas.extension_commitment.0,
                        ext_vec,
                        sub_comm_index,
                        (if is_c2 { eas.c2_field } else { eas.c1_field }).0,
                    ));

                    // Open c1/c2 → value
                    let sub_vec = eas_sub_commitment_vector(eas, is_c2);
                    let sub_commitment = if is_c2 { eas.c2 } else { eas.c1 };
                    let sub_index = if is_c2 {
                        (suffix - 128) as usize
                    } else {
                        suffix as usize
                    };
                    let value_scalar = value
                        .as_ref()
                        .map(|v| value_to_field(v).0)
                        .unwrap_or(Fr::ZERO);
                    openings.push((sub_commitment.0, sub_vec, sub_index, value_scalar));

                    return Some(KeyTraversal {
                        openings,
                        eas_stem: eas.stem.clone(),
                        value,
                        depth,
                        termination: TerminationKind::FoundEaS,
                    });
                } else {
                    let diverge_pos = eas
                        .stem
                        .iter()
                        .zip(expected_stem.iter())
                        .position(|(a, b)| a != b)
                        .unwrap_or(eas.stem.len().min(expected_stem.len()));

                    // Open marker byte to prove this is an EaS, not an internal node
                    let ext_vec = eas_extension_vector(eas);
                    openings.push((
                        eas.extension_commitment.0,
                        ext_vec.clone(),
                        0,
                        field_one().0,
                    ));

                    // Open at the divergent stem byte
                    if diverge_pos < eas.stem.len() {
                        let stem_index = diverge_pos + 1;
                        openings.push((
                            eas.extension_commitment.0,
                            ext_vec,
                            stem_index,
                            field_from_byte(eas.stem[diverge_pos]).0,
                        ));
                    }

                    return Some(KeyTraversal {
                        openings,
                        eas_stem: eas.stem.clone(),
                        value: None,
                        depth,
                        termination: TerminationKind::StemMismatch {
                            diverge_byte: diverge_pos,
                        },
                    });
                }
            }
        }
    }
}

// ============================================================
// Proof types
// ============================================================

/// Per-key proof data with explicit path through the openings.
#[derive(Clone, Debug)]
pub struct KeyProofData {
    pub key: Key,
    pub eas_stem: Vec<u8>,
    pub value: Option<Value>,
    pub depth: usize,
    /// Indices into `VerkleProof::verifier_queries` forming this key's path.
    pub query_path: Vec<usize>,
    /// How the traversal terminated.
    pub termination: TerminationKind,
}

#[derive(Clone, Debug)]
pub struct VerkleProof {
    pub multipoint_proof: MultiPointProof,
    pub key_data: Vec<KeyProofData>,
    pub verifier_queries: Vec<(EdwardsAffine, usize, Fr)>,
}

impl VerkleProof {
    pub fn proof_byte_size(&self) -> usize {
        self.multipoint_proof.byte_size()
    }

    pub fn total_byte_size(&self) -> usize {
        let proof_bytes = self.multipoint_proof.byte_size();
        let query_bytes = self.verifier_queries.len() * 65;
        let key_bytes: usize = self
            .key_data
            .iter()
            .map(|kd| {
                32 + kd.eas_stem.len()
                    + kd.value.as_ref().map_or(0, |v| v.len())
                    + kd.query_path.len() * 8
                    + 4
            })
            .sum();
        proof_bytes + query_bytes + key_bytes
    }
}

// ============================================================
// Proof generation
// ============================================================

pub fn prove<S: TreeReader>(store: &S, root_key: &NodeKey, keys: &[Key]) -> Option<VerkleProof> {
    let crs = shared_crs();
    let precomp = &*PRECOMP;

    let mut key_data = Vec::with_capacity(keys.len());
    let mut all_prover_queries = Vec::new();
    let mut verifier_queries_out = Vec::new();
    let mut seen: HashMap<([u8; 32], usize), usize> = HashMap::new();

    for key in keys {
        let traversal = traverse_for_key(store, root_key, key)?;
        let mut query_path = Vec::with_capacity(traversal.openings.len());

        for (comm, a, index, result) in &traversal.openings {
            use ark_serialize::CanonicalSerialize;
            let mut comm_bytes = [0u8; 32];
            comm.serialize_compressed(&mut comm_bytes[..]).unwrap();
            let dedup_key = (comm_bytes, *index);

            let query_idx = if let Some(&existing_idx) = seen.get(&dedup_key) {
                existing_idx
            } else {
                let idx = all_prover_queries.len();
                seen.insert(dedup_key, idx);
                all_prover_queries.push(ProverQuery {
                    commitment: *comm,
                    poly: LagrangeBasis::new(a.clone()),
                    point: *index,
                    result: *result,
                });
                verifier_queries_out.push((*comm, *index, *result));
                idx
            };

            query_path.push(query_idx);
        }

        key_data.push(KeyProofData {
            key: key.clone(),
            eas_stem: traversal.eas_stem,
            value: traversal.value,
            depth: traversal.depth,
            query_path,
            termination: traversal.termination,
        });
    }

    if all_prover_queries.is_empty() {
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

// ============================================================
// Verification
// ============================================================

pub fn verify(
    proof: &VerkleProof,
    root_commitment: Commitment,
    keys: &[Key],
    expected_values: &[Option<Value>],
) -> bool {
    if proof.key_data.len() != keys.len() || keys.len() != expected_values.len() {
        return false;
    }

    let queries = &proof.verifier_queries;

    for (i, kd) in proof.key_data.iter().enumerate() {
        if kd.key != keys[i] {
            return false;
        }
        if kd.value.as_ref() != expected_values[i].as_ref() {
            return false;
        }

        // Stem check for inclusion
        match &kd.termination {
            TerminationKind::FoundEaS => {
                let expected_stem = &keys[i][kd.depth..key_stem_end(&keys[i])];
                if kd.eas_stem != expected_stem {
                    return false;
                }
            }
            _ => {
                // Non-inclusion: value must be None
                if expected_values[i].is_some() {
                    return false;
                }
            }
        }

        if kd.query_path.is_empty() {
            continue;
        }

        // --- Chain verification ---

        // 1. First opening must match the root
        let first_idx = kd.query_path[0];
        if first_idx >= queries.len() {
            return false;
        }
        if Commitment(queries[first_idx].0) != root_commitment {
            return false;
        }

        // 2. Consecutive openings chain together
        for j in 0..kd.query_path.len() - 1 {
            let curr_idx = kd.query_path[j];
            let next_idx = kd.query_path[j + 1];
            if curr_idx >= queries.len() || next_idx >= queries.len() {
                return false;
            }

            let curr_result = queries[curr_idx].2;
            let next_commitment_scalar = commitment_to_field(Commitment(queries[next_idx].0)).0;

            // Chain link: result of this opening == scalar form of next commitment
            // EXCEPT when two consecutive openings are on the SAME commitment
            // (e.g., marker byte and sub-commitment opening on the same extension commitment).
            // In that case, the chain link is that they share the same commitment, not
            // that one's result maps to the other's commitment.
            let same_commitment = queries[curr_idx].0 == queries[next_idx].0;
            if !same_commitment && curr_result != next_commitment_scalar {
                return false;
            }
        }

        // 3. Termination-specific checks
        let last_idx = *kd.query_path.last().unwrap();
        if last_idx >= queries.len() {
            return false;
        }
        let final_result = queries[last_idx].2;

        match &kd.termination {
            TerminationKind::FoundEaS => {
                // Final result must match value_to_field(value)
                let expected_scalar = kd
                    .value
                    .as_ref()
                    .map(|v| value_to_field(v).0)
                    .unwrap_or(Fr::ZERO);
                if final_result != expected_scalar {
                    return false;
                }

                // Verify marker byte == 1, proving this is an EaS (not an internal node)
                let marker_ok = kd.query_path.iter().any(|&idx| {
                    idx < queries.len() && queries[idx].1 == 0 && queries[idx].2 == field_one().0
                });
                if !marker_ok {
                    return false;
                }
            }
            TerminationKind::EmptySlot => {
                // Empty child slot: the opening result must be zero
                if final_result != Fr::ZERO {
                    return false;
                }
            }
            TerminationKind::StemMismatch { diverge_byte } => {
                // The opened stem byte must differ from the key's stem byte
                let key_stem_byte = keys[i][kd.depth + diverge_byte];
                let key_byte_scalar = field_from_byte(key_stem_byte).0;
                if final_result == key_byte_scalar {
                    return false;
                }

                // Verify marker byte == 1 for stem-mismatch too
                let marker_ok = kd.query_path.iter().any(|&idx| {
                    idx < queries.len() && queries[idx].1 == 0 && queries[idx].2 == field_one().0
                });
                if !marker_ok {
                    return false;
                }
            }
        }
    }

    if proof.verifier_queries.is_empty() {
        return true;
    }

    // Verify all openings cryptographically
    let crs = shared_crs();
    let precomp = &*PRECOMP;

    let vqs: Vec<VerifierQuery> = queries
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
// Convenience
// ============================================================

pub fn prove_single<S: TreeReader>(
    store: &S,
    root_key: &NodeKey,
    key: &Key,
) -> Option<VerkleProof> {
    prove(store, root_key, &[key.clone()])
}

pub fn verify_single(
    proof: &VerkleProof,
    root_commitment: Commitment,
    key: &Key,
    expected_value: Option<&Value>,
) -> bool {
    verify(
        proof,
        root_commitment,
        &[key.clone()],
        &[expected_value.cloned()],
    )
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
        let mut key = vec![0u8; 32];
        key[0] = first;
        key[1] = second;
        key[31] = suffix;
        key
    }

    fn insert(store: &mut MemoryStore, key: &Key, value: Value) {
        let parent = store.latest_version();
        let new_version = parent.map_or(1, |v| v + 1);
        let mut updates = BTreeMap::new();
        updates.insert(key.clone(), Some(value));
        let result = apply_updates(store, parent, new_version, updates);
        store.apply(&result);
    }

    fn root_c(store: &MemoryStore) -> Commitment {
        root_commitment_at(store, store.latest_version().unwrap())
    }

    #[test]
    fn single_key_proof() {
        let mut store = MemoryStore::new();
        let key = make_key(1, 2, 3);
        let value = vec![42];
        insert(&mut store, &key, value.clone());

        let rk = store.latest_root_key().unwrap();
        let proof = prove_single(&store, &rk, &key).unwrap();

        // marker + extension→c1 + c1→value = 3 openings
        assert_eq!(proof.key_data[0].query_path.len(), 3);
        assert!(verify_single(&proof, root_c(&store), &key, Some(&value)));
    }

    #[test]
    fn single_key_after_split() {
        let mut store = MemoryStore::new();
        insert(&mut store, &make_key(1, 0, 0), vec![10]);
        insert(&mut store, &make_key(2, 0, 0), vec![20]);

        let rk = store.latest_root_key().unwrap();
        let rc = root_c(&store);

        let p1 = prove_single(&store, &rk, &make_key(1, 0, 0)).unwrap();
        assert!(verify_single(&p1, rc, &make_key(1, 0, 0), Some(&vec![10])));

        let p2 = prove_single(&store, &rk, &make_key(2, 0, 0)).unwrap();
        assert!(verify_single(&p2, rc, &make_key(2, 0, 0), Some(&vec![20])));
    }

    #[test]
    fn nonexistent_stem_mismatch() {
        let mut store = MemoryStore::new();
        insert(&mut store, &make_key(1, 2, 3), vec![42]);

        let rk = store.latest_root_key().unwrap();
        let key2 = make_key(5, 6, 7);
        let proof = prove_single(&store, &rk, &key2).unwrap();

        assert!(matches!(
            proof.key_data[0].termination,
            TerminationKind::StemMismatch { .. }
        ));
        assert!(verify_single(&proof, root_c(&store), &key2, None));
    }

    #[test]
    fn nonexistent_empty_slot() {
        let mut store = MemoryStore::new();
        insert(&mut store, &make_key(1, 0, 0), vec![10]);
        insert(&mut store, &make_key(2, 0, 0), vec![20]);

        let rk = store.latest_root_key().unwrap();
        // Key with first byte 3 — not in the tree, hits empty child slot
        let key3 = make_key(3, 0, 0);
        let proof = prove_single(&store, &rk, &key3).unwrap();

        assert!(matches!(
            proof.key_data[0].termination,
            TerminationKind::EmptySlot
        ));
        assert!(verify_single(&proof, root_c(&store), &key3, None));
    }

    #[test]
    fn batch_two_keys() {
        let mut store = MemoryStore::new();
        insert(&mut store, &make_key(1, 0, 0), vec![10]);
        insert(&mut store, &make_key(2, 0, 0), vec![20]);

        let rk = store.latest_root_key().unwrap();
        let keys = [make_key(1, 0, 0), make_key(2, 0, 0)];
        let proof = prove(&store, &rk, &keys).unwrap();

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
            insert(&mut store, k, v.clone());
        }

        let rk = store.latest_root_key().unwrap();
        let proof = prove(&store, &rk, &keys).unwrap();
        assert_eq!(proof.proof_byte_size(), 576);

        let expected: Vec<Option<Value>> = values.into_iter().map(Some).collect();
        assert!(verify(&proof, root_c(&store), &keys, &expected));
    }

    #[test]
    fn batch_rejects_wrong_value() {
        let mut store = MemoryStore::new();
        insert(&mut store, &make_key(1, 0, 0), vec![10]);
        insert(&mut store, &make_key(2, 0, 0), vec![20]);

        let rk = store.latest_root_key().unwrap();
        let keys = [make_key(1, 0, 0), make_key(2, 0, 0)];
        let proof = prove(&store, &rk, &keys).unwrap();

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
        insert(&mut store, &make_key(5, 1, 0), vec![10]);
        insert(&mut store, &make_key(5, 2, 0), vec![20]);
        insert(&mut store, &make_key(6, 0, 0), vec![30]);

        let rk = store.latest_root_key().unwrap();
        let keys = [make_key(5, 1, 0), make_key(5, 2, 0), make_key(6, 0, 0)];
        let proof = prove(&store, &rk, &keys).unwrap();

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
        insert(&mut store, &make_key(1, 0, 0), vec![10]);
        insert(&mut store, &make_key(2, 0, 0), vec![20]);

        let rk = store.latest_root_key().unwrap();
        let key3 = make_key(1, 99, 0);
        let keys = [make_key(1, 0, 0), key3];
        let proof = prove(&store, &rk, &keys).unwrap();

        assert!(verify(
            &proof,
            root_c(&store),
            &keys,
            &[Some(vec![10]), None],
        ));
    }

    #[test]
    fn chain_catches_wrong_root() {
        let mut store = MemoryStore::new();
        insert(&mut store, &make_key(1, 0, 0), vec![10]);
        insert(&mut store, &make_key(2, 0, 0), vec![20]);

        let rk = store.latest_root_key().unwrap();
        let proof = prove_single(&store, &rk, &make_key(1, 0, 0)).unwrap();

        insert(&mut store, &make_key(3, 0, 0), vec![30]);
        let new_root = root_c(&store);

        assert!(!verify_single(
            &proof,
            new_root,
            &make_key(1, 0, 0),
            Some(&vec![10])
        ));
    }
}
