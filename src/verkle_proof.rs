//! Verkle proof generation and verification.
//!
//! Proofs use the Dankrad Feist multipoint scheme (576 bytes constant).
//!
//! The wire format is compact: a deduplicated commitment table plus per-key
//! path metadata. The verifier reconstructs the full set of `(C, z, y)`
//! opening triples from the compact data, then feeds them to the multipoint
//! verifier. This avoids transmitting redundant results and evaluation points
//! that the verifier can derive from the keys and commitment chain.

use std::collections::HashMap;
use std::rc::Rc;

use ark_ed_on_bls12_381_bandersnatch::{EdwardsAffine, Fr};
use ark_ff::AdditiveGroup;

use crate::commitment::{commitment_to_field, field_from_byte, field_one, Commitment};
use crate::multiproof::crs::shared_crs;
use crate::multiproof::lagrange::{LagrangeBasis, PrecomputedWeights};
use crate::multiproof::prover::{MultiPointProof, MultiPointProver, ProverQuery, VerifierQuery};
use crate::multiproof::transcript::Transcript;
use crate::node::*;
use crate::storage::*;

static PRECOMP: std::sync::LazyLock<PrecomputedWeights> =
    std::sync::LazyLock::new(|| PrecomputedWeights::new(256));

// ============================================================
// Vector reconstruction (prover-only)
// ============================================================

fn internal_node_vector(internal: &InternalNode) -> Rc<Vec<Fr>> {
    let mut v = vec![Fr::ZERO; 256];
    for (&idx, child) in &internal.children {
        v[idx as usize] = child.field.0;
    }
    Rc::new(v)
}

fn eas_extension_vector(eas: &EaSNode) -> Rc<Vec<Fr>> {
    let mut v = vec![Fr::ZERO; 256];
    v[0] = field_one().0;
    for (i, &byte) in eas.stem.iter().enumerate() {
        v[i + 1] = field_from_byte(byte).0;
    }
    v[eas.stem.len() + 1] = eas.c1_field.0;
    v[eas.stem.len() + 2] = eas.c2_field.0;
    Rc::new(v)
}

fn eas_sub_commitment_vector(eas: &EaSNode, is_c2: bool) -> Rc<Vec<Fr>> {
    let mut v = vec![Fr::ZERO; 256];
    for (&suffix, val) in &eas.values {
        if is_c2 && suffix >= 128 {
            v[(suffix - 128) as usize] = val.0;
        } else if !is_c2 && suffix < 128 {
            v[suffix as usize] = val.0;
        }
    }
    Rc::new(v)
}

// ============================================================
// Traversal
// ============================================================

/// (commitment, polynomial, evaluation_point, result)
type Opening = (EdwardsAffine, Rc<Vec<Fr>>, usize, Fr);

/// How the key lookup terminated.
#[derive(Clone, Debug)]
pub enum TerminationKind {
    /// Found the EaS with matching stem. Value may or may not exist at suffix.
    FoundEaS,
    /// Hit an empty child slot in an internal node.
    EmptySlot,
    /// Found an EaS but stem doesn't match.
    StemMismatch {
        /// Index within the stem where divergence occurs.
        diverge_byte: usize,
        /// The actual byte in the existing EaS stem at `diverge_byte`, if within stem length.
        actual_stem_byte: Option<u8>,
    },
}

struct KeyTraversal {
    openings: Vec<Opening>,
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
                        current_key = NodeKey::new(child.version, &key[..depth + 1]);
                        depth += 1;
                    }
                    None => {
                        return Some(KeyTraversal {
                            openings,
                            value: None,
                            depth,
                            termination: TerminationKind::EmptySlot,
                        });
                    }
                }
            }
            Node::EaS(eas) => {
                let expected_stem = &key[depth..SUFFIX_INDEX];
                if eas.stem == expected_stem {
                    let suffix = key_suffix(key);
                    let value = eas.values.get(&suffix).cloned();
                    let is_c2 = suffix >= 128;

                    let ext_vec = eas_extension_vector(eas);
                    // Marker byte opening
                    openings.push((
                        eas.extension_commitment.0,
                        ext_vec.clone(),
                        0,
                        field_one().0,
                    ));

                    // Extension → c1 or c2
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

                    // c1/c2 → value
                    let sub_vec = eas_sub_commitment_vector(eas, is_c2);
                    let sub_commitment = if is_c2 { eas.c2 } else { eas.c1 };
                    let sub_index = if is_c2 {
                        (suffix - 128) as usize
                    } else {
                        suffix as usize
                    };
                    let value_scalar = value.map(|v| v.0).unwrap_or(Fr::ZERO);
                    openings.push((sub_commitment.0, sub_vec, sub_index, value_scalar));

                    return Some(KeyTraversal {
                        openings,
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

                    let ext_vec = eas_extension_vector(eas);
                    // Marker byte opening
                    openings.push((
                        eas.extension_commitment.0,
                        ext_vec.clone(),
                        0,
                        field_one().0,
                    ));

                    // Divergent stem byte opening
                    let actual_byte = if diverge_pos < eas.stem.len() {
                        let stem_index = diverge_pos + 1;
                        openings.push((
                            eas.extension_commitment.0,
                            ext_vec,
                            stem_index,
                            field_from_byte(eas.stem[diverge_pos]).0,
                        ));
                        Some(eas.stem[diverge_pos])
                    } else {
                        None
                    };

                    return Some(KeyTraversal {
                        openings,
                        value: None,
                        depth,
                        termination: TerminationKind::StemMismatch {
                            diverge_byte: diverge_pos,
                            actual_stem_byte: actual_byte,
                        },
                    });
                }
            }
        }
    }
}

// ============================================================
// Proof types (compact wire format)
// ============================================================

/// Per-key proof metadata. Together with the key and the commitment table,
/// this is sufficient for the verifier to reconstruct all opening triples.
#[derive(Clone, Debug)]
pub struct KeyProofData {
    pub key: Key,
    pub value: Option<Value>,
    /// Depth of the EaS (or failing internal) node in the tree.
    pub depth: u8,
    /// Indices into `VerkleProof::commitments` along the path from root.
    ///
    /// Layout depends on termination kind:
    /// - `FoundEaS`: `[internal_0, .., internal_{d-1}, extension, sub_commitment]` — `d + 2` entries
    /// - `EmptySlot`: `[internal_0, .., internal_d]` — `d + 1` entries
    /// - `StemMismatch`: `[internal_0, .., internal_{d-1}, extension]` — `d + 1` entries
    pub commitment_path: Vec<u16>,
    /// How the traversal terminated.
    pub termination: TerminationKind,
}

/// Compact verkle proof.
///
/// The multipoint proof is constant-size (576 bytes). The `commitments` table
/// and `key_data` are the only variable-size components, and they are much
/// smaller than the old format which stored explicit `(C, z, y)` triples.
#[derive(Clone, Debug)]
pub struct VerkleProof {
    pub multipoint_proof: MultiPointProof,
    /// Deduplicated commitment table referenced by key paths.
    pub commitments: Vec<EdwardsAffine>,
    pub key_data: Vec<KeyProofData>,
}

impl VerkleProof {
    /// Size of just the multipoint proof (constant 576 bytes).
    pub fn proof_byte_size(&self) -> usize {
        self.multipoint_proof.byte_size()
    }

    /// Estimated total wire size of the proof.
    pub fn total_byte_size(&self) -> usize {
        let proof_bytes = self.multipoint_proof.byte_size();
        let commitment_bytes = self.commitments.len() * 32;
        let key_bytes: usize = self
            .key_data
            .iter()
            .map(|kd| {
                32 // key
                + 1 // has_value flag
                + kd.value.as_ref().map_or(0, |_| 32)
                + 1 // depth
                + 2 * kd.commitment_path.len() // u16 indices
                + match &kd.termination {
                    TerminationKind::FoundEaS => 1,
                    TerminationKind::EmptySlot => 1,
                    TerminationKind::StemMismatch { actual_stem_byte, .. } => {
                        2 + if actual_stem_byte.is_some() { 1 } else { 0 }
                    }
                }
            })
            .sum();
        proof_bytes + commitment_bytes + key_bytes
    }

    /// Number of unique commitments in the proof.
    pub fn num_commitments(&self) -> usize {
        self.commitments.len()
    }
}

// ============================================================
// Proof generation
// ============================================================

pub fn prove<S: TreeReader>(store: &S, root_key: &NodeKey, keys: &[Key]) -> Option<VerkleProof> {
    let crs = shared_crs();
    let precomp = &*PRECOMP;

    let mut key_data = Vec::with_capacity(keys.len());

    // Commitment dedup: bytes → index in commitment_table
    let mut commitment_table: Vec<EdwardsAffine> = Vec::new();
    let mut commitment_map: HashMap<[u8; 32], u16> = HashMap::new();

    // Query dedup: (commitment_bytes, eval_point) → index in prover_queries
    let mut prover_queries: Vec<ProverQuery> = Vec::new();
    let mut query_dedup: HashMap<([u8; 32], usize), usize> = HashMap::new();

    for key in keys {
        let traversal = traverse_for_key(store, root_key, key)?;

        let mut commitment_path = Vec::new();
        let mut last_comm_bytes: Option<[u8; 32]> = None;

        for (comm, poly, index, result) in &traversal.openings {
            use ark_serialize::CanonicalSerialize;
            let mut comm_bytes = [0u8; 32];
            comm.serialize_compressed(&mut comm_bytes[..]).unwrap();

            // Register commitment in the dedup table
            let comm_idx = *commitment_map.entry(comm_bytes).or_insert_with(|| {
                let idx = commitment_table.len() as u16;
                commitment_table.push(*comm);
                idx
            });

            // Build commitment_path: skip consecutive duplicates (extension
            // commitment appears in both marker and ext→sub openings).
            if last_comm_bytes != Some(comm_bytes) {
                commitment_path.push(comm_idx);
                last_comm_bytes = Some(comm_bytes);
            }

            // Dedup prover query by (commitment, eval_point)
            let dedup_key = (comm_bytes, *index);
            query_dedup.entry(dedup_key).or_insert_with(|| {
                let idx = prover_queries.len();
                prover_queries.push(ProverQuery {
                    commitment: *comm,
                    poly: LagrangeBasis::new(Rc::unwrap_or_clone(poly.clone())),
                    point: *index,
                    result: *result,
                });
                idx
            });
        }

        key_data.push(KeyProofData {
            key: *key,
            value: traversal.value,
            depth: traversal.depth as u8,
            commitment_path,
            termination: traversal.termination,
        });
    }

    if prover_queries.is_empty() {
        return Some(VerkleProof {
            multipoint_proof: MultiPointProof {
                ipa_proof: crate::multiproof::ipa::IPAProof {
                    l_vec: vec![],
                    r_vec: vec![],
                    a_scalar: Fr::ZERO,
                },
                d_comm: EdwardsAffine::default(),
            },
            commitments: commitment_table,
            key_data,
        });
    }

    let mut transcript = Transcript::new(b"jvt_verkle_proof");
    let proof = MultiPointProver::open(crs, precomp, &mut transcript, prover_queries);

    Some(VerkleProof {
        multipoint_proof: proof,
        commitments: commitment_table,
        key_data,
    })
}

// ============================================================
// Query reconstruction (verifier-side)
// ============================================================

/// Reconstruct the ordered, deduplicated `VerifierQuery` list from the compact
/// proof. The verifier walks each key's `commitment_path` and derives the
/// evaluation points and results from the keys, depths, and commitment chain.
///
/// The reconstruction visits keys and openings in the same order as the prover,
/// producing an identical Fiat-Shamir transcript.
fn reconstruct_verifier_queries(proof: &VerkleProof) -> Vec<VerifierQuery> {
    let comms = &proof.commitments;
    let mut queries = Vec::new();
    let mut seen: HashMap<(u16, usize), ()> = HashMap::new();

    // Helper: add a query if not already seen.
    macro_rules! add_query {
        ($comm_idx:expr, $point:expr, $result:expr) => {{
            let ci = $comm_idx;
            let pt = $point;
            if seen.insert((ci, pt), ()).is_none() {
                queries.push(VerifierQuery {
                    commitment: comms[ci as usize],
                    point: pt,
                    result: $result,
                });
            }
        }};
    }

    for kd in &proof.key_data {
        let key = &kd.key;
        let depth = kd.depth as usize;
        let path = &kd.commitment_path;

        match &kd.termination {
            TerminationKind::FoundEaS => {
                // path = [internal_0, .., internal_{d-1}, extension, sub]
                // Internal node openings: result = c2f(next commitment)
                for i in 0..depth {
                    let result = commitment_to_field(Commitment(comms[path[i + 1] as usize])).0;
                    add_query!(path[i], key[i] as usize, result);
                }

                let ext_idx = path[depth];
                let sub_idx = path[depth + 1];
                let suffix = key_suffix(key);
                let is_c2 = suffix >= 128;
                let stem_len = SUFFIX_INDEX - depth;

                // Marker byte: (extension, 0, 1)
                add_query!(ext_idx, 0, field_one().0);

                // Extension → sub-commitment
                let sub_point = if is_c2 { stem_len + 2 } else { stem_len + 1 };
                let sub_scalar = commitment_to_field(Commitment(comms[sub_idx as usize])).0;
                add_query!(ext_idx, sub_point, sub_scalar);

                // Value opening
                let val_point = if is_c2 {
                    (suffix - 128) as usize
                } else {
                    suffix as usize
                };
                let val_scalar = kd.value.map(|v| v.0).unwrap_or(Fr::ZERO);
                add_query!(sub_idx, val_point, val_scalar);
            }

            TerminationKind::EmptySlot => {
                // path = [internal_0, .., internal_d]
                for i in 0..=depth {
                    let result = if i < depth {
                        commitment_to_field(Commitment(comms[path[i + 1] as usize])).0
                    } else {
                        Fr::ZERO // empty child slot
                    };
                    add_query!(path[i], key[i] as usize, result);
                }
            }

            TerminationKind::StemMismatch {
                diverge_byte,
                actual_stem_byte,
            } => {
                // path = [internal_0, .., internal_{d-1}, extension]
                for i in 0..depth {
                    let result = commitment_to_field(Commitment(comms[path[i + 1] as usize])).0;
                    add_query!(path[i], key[i] as usize, result);
                }

                let ext_idx = path[depth];

                // Marker byte
                add_query!(ext_idx, 0, field_one().0);

                // Divergent stem byte (if within stem length)
                if let Some(actual) = actual_stem_byte {
                    let diverge_point = diverge_byte + 1;
                    add_query!(ext_idx, diverge_point, field_from_byte(*actual).0);
                }
            }
        }
    }

    queries
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

    // Semantic checks
    for (i, kd) in proof.key_data.iter().enumerate() {
        if kd.key != keys[i] {
            return false;
        }
        if kd.value.as_ref() != expected_values[i].as_ref() {
            return false;
        }

        let depth = kd.depth as usize;
        let path = &kd.commitment_path;

        // Root check: first commitment in path must match root
        if let Some(&first_idx) = path.first() {
            if first_idx as usize >= proof.commitments.len() {
                return false;
            }
            if Commitment(proof.commitments[first_idx as usize]) != root_commitment {
                return false;
            }
        }

        // Bounds check all commitment indices
        for &idx in path {
            if idx as usize >= proof.commitments.len() {
                return false;
            }
        }

        match &kd.termination {
            TerminationKind::FoundEaS => {
                if path.len() != depth + 2 {
                    return false;
                }
            }
            TerminationKind::EmptySlot => {
                if expected_values[i].is_some() {
                    return false;
                }
                if path.len() != depth + 1 {
                    return false;
                }
            }
            TerminationKind::StemMismatch {
                diverge_byte,
                actual_stem_byte,
            } => {
                if expected_values[i].is_some() {
                    return false;
                }
                if path.len() != depth + 1 {
                    return false;
                }
                // The actual stem byte must differ from the key's byte
                if let Some(actual) = actual_stem_byte {
                    let key_byte = keys[i][depth + diverge_byte];
                    if *actual == key_byte {
                        return false;
                    }
                }
            }
        }
    }

    // Reconstruct verifier queries from compact proof data
    let queries = reconstruct_verifier_queries(proof);

    if queries.is_empty() {
        return true;
    }

    // Cryptographic verification
    let crs = shared_crs();
    let precomp = &*PRECOMP;
    let mut transcript = Transcript::new(b"jvt_verkle_proof");
    proof
        .multipoint_proof
        .check(crs, precomp, &queries, &mut transcript)
}

// ============================================================
// Convenience
// ============================================================

pub fn prove_single<S: TreeReader>(
    store: &S,
    root_key: &NodeKey,
    key: &Key,
) -> Option<VerkleProof> {
    prove(store, root_key, std::slice::from_ref(key))
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
        std::slice::from_ref(key),
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
        let mut key = [0u8; 32];
        key[0] = first;
        key[1] = second;
        key[SUFFIX_INDEX] = suffix;
        key
    }

    fn v(n: u8) -> Value {
        crate::commitment::value_to_field(&[n])
    }

    fn insert(store: &mut MemoryStore, key: &Key, value: Value) {
        let parent = store.latest_version();
        let new_version = parent.map_or(1, |v| v + 1);
        let mut updates = BTreeMap::new();
        updates.insert(*key, Some(value));
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
        let value = v(42);
        insert(&mut store, &key, value);

        let rk = store.latest_root_key().unwrap();
        let proof = prove_single(&store, &rk, &key).unwrap();

        // Depth 0 (root is EaS): path = [extension, sub] = 2 commitments
        assert_eq!(proof.key_data[0].commitment_path.len(), 2);
        assert!(verify_single(&proof, root_c(&store), &key, Some(&value)));
    }

    #[test]
    fn single_key_after_split() {
        let mut store = MemoryStore::new();
        insert(&mut store, &make_key(1, 0, 0), v(10));
        insert(&mut store, &make_key(2, 0, 0), v(20));

        let rk = store.latest_root_key().unwrap();
        let rc = root_c(&store);

        let p1 = prove_single(&store, &rk, &make_key(1, 0, 0)).unwrap();
        assert!(verify_single(&p1, rc, &make_key(1, 0, 0), Some(&v(10))));

        let p2 = prove_single(&store, &rk, &make_key(2, 0, 0)).unwrap();
        assert!(verify_single(&p2, rc, &make_key(2, 0, 0), Some(&v(20))));
    }

    #[test]
    fn nonexistent_stem_mismatch() {
        let mut store = MemoryStore::new();
        insert(&mut store, &make_key(1, 2, 3), v(42));

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
        insert(&mut store, &make_key(1, 0, 0), v(10));
        insert(&mut store, &make_key(2, 0, 0), v(20));

        let rk = store.latest_root_key().unwrap();
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
        insert(&mut store, &make_key(1, 0, 0), v(10));
        insert(&mut store, &make_key(2, 0, 0), v(20));

        let rk = store.latest_root_key().unwrap();
        let keys = [make_key(1, 0, 0), make_key(2, 0, 0)];
        let proof = prove(&store, &rk, &keys).unwrap();

        assert_eq!(proof.proof_byte_size(), 576);
        assert!(verify(
            &proof,
            root_c(&store),
            &keys,
            &[Some(v(10)), Some(v(20))],
        ));
    }

    #[test]
    fn batch_many_keys() {
        let mut store = MemoryStore::new();
        let keys: Vec<Key> = (0..20u8)
            .map(|i| make_key(i, i.wrapping_mul(7), i.wrapping_mul(13)))
            .collect();
        let values: Vec<Value> = (0..20u8).map(|i| v(i)).collect();
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
        insert(&mut store, &make_key(1, 0, 0), v(10));
        insert(&mut store, &make_key(2, 0, 0), v(20));

        let rk = store.latest_root_key().unwrap();
        let keys = [make_key(1, 0, 0), make_key(2, 0, 0)];
        let proof = prove(&store, &rk, &keys).unwrap();

        assert!(!verify(
            &proof,
            root_c(&store),
            &keys,
            &[Some(v(10)), Some(v(99))],
        ));
    }

    #[test]
    fn batch_shared_internal_nodes() {
        let mut store = MemoryStore::new();
        insert(&mut store, &make_key(5, 1, 0), v(10));
        insert(&mut store, &make_key(5, 2, 0), v(20));
        insert(&mut store, &make_key(6, 0, 0), v(30));

        let rk = store.latest_root_key().unwrap();
        let keys = [make_key(5, 1, 0), make_key(5, 2, 0), make_key(6, 0, 0)];
        let proof = prove(&store, &rk, &keys).unwrap();

        assert!(verify(
            &proof,
            root_c(&store),
            &keys,
            &[Some(v(10)), Some(v(20)), Some(v(30))],
        ));
    }

    #[test]
    fn batch_with_nonexistent_key() {
        let mut store = MemoryStore::new();
        insert(&mut store, &make_key(1, 0, 0), v(10));
        insert(&mut store, &make_key(2, 0, 0), v(20));

        let rk = store.latest_root_key().unwrap();
        let key3 = make_key(1, 99, 0);
        let keys = [make_key(1, 0, 0), key3];
        let proof = prove(&store, &rk, &keys).unwrap();

        assert!(verify(&proof, root_c(&store), &keys, &[Some(v(10)), None]));
    }

    #[test]
    fn chain_catches_wrong_root() {
        let mut store = MemoryStore::new();
        insert(&mut store, &make_key(1, 0, 0), v(10));
        insert(&mut store, &make_key(2, 0, 0), v(20));

        let rk = store.latest_root_key().unwrap();
        let proof = prove_single(&store, &rk, &make_key(1, 0, 0)).unwrap();

        insert(&mut store, &make_key(3, 0, 0), v(30));
        let new_root = root_c(&store);

        assert!(!verify_single(
            &proof,
            new_root,
            &make_key(1, 0, 0),
            Some(&v(10))
        ));
    }
}
