# Jellyfish Verkle Tree (JVT) — Design Document

## 1. Overview

The Jellyfish Verkle Tree (JVT) is a hybrid authenticated data structure that combines:

- **From JMT**: Version-based node keys for LSM-tree-friendly sequential writes, single-leaf subtree collapsing for O(log n) average depth, persistent data structure with stale node tracking for efficient pruning.
- **From Verkle Trees**: Vector commitments (Pedersen commitments over the Bandersnatch curve) for constant-size per-level proofs, multipoint proof aggregation for compressed batch witnesses, and homomorphic commitment updates for O(1) single-value changes.

The result is a data structure with JMT's production-grade storage characteristics and verkle trees' proof-aggregation capabilities.

---

## 2. Compatibility Analysis

### 2.1 Version-Based Node Keys

| Aspect | JMT | JVT | Analysis |
|--------|-----|-----|----------|
| Key structure | `(version: u64, nibble_path: Vec<u4>)` | `(version: u64, byte_path: Vec<u8>)` | Direct transfer |
| Path unit | 4-bit nibble (radix-16) | 8-bit byte (radix-256) | Wider branching = shorter paths |
| Max depth | 64 (256 bits / 4 bits) | 31 (248 bits / 8 bits) + EaS stem | Much shallower tree |
| LSM property | Version prefix → sequential writes | Identical | **Fully compatible** |
| Range queries | Nibble-path prefix scan | Byte-path prefix scan | Same pattern, different granularity |

**Verdict: Fully compatible.** The version-based key scheme is a storage-layer optimization that is entirely commitment-scheme-agnostic. The only change is replacing nibble paths with byte paths to reflect 256-ary branching. The critical property — that monotonically increasing versions produce sequential RocksDB key prefixes — is preserved exactly.

### 2.2 Single-Leaf Subtree Collapsing

| Aspect | JMT | JVT | Analysis |
|--------|-----|-----|----------|
| Mechanism | Leaf node "floats" up to shallowest unique depth | Extension-and-Suffix (EaS) node at shallowest unique depth | Functionally equivalent |
| Node type | Simple `Leaf { key_hash, value_hash }` | `EaS { stem, c1, c2, values }` — richer structure | More complex but same purpose |
| Split on collision | Create chain of internal nodes down to divergence point | Create one internal node + two EaS children | Simpler due to wider branching |
| Commitment update on split | Rehash the new internal chain | Full recomputation of new internal node's commitment | Non-homomorphic — must compute from scratch |

**Verdict: Compatible with modification.** JMT's leaf-floating optimization maps directly to the EaS node pattern from Ethereum's verkle tree design. The key difference: JMT's collapsed leaf is a simple (key_hash, value_hash) pair, while an EaS node carries a 31-byte stem and two sub-commitments covering 256 value slots. This richer structure is necessary because verkle trees encode values within the commitment structure, not just as hashes.

The split case is the critical complexity point. When a new key shares a prefix with an existing EaS node, the EaS must be replaced by:
1. A new internal node at the shared prefix depth
2. Two new EaS children (one for the existing key's stem, one for the new key's stem)
3. A full commitment recomputation for the new internal node (not a homomorphic delta)

### 2.3 Persistent Data Structure / Stale Node Tracking

| Aspect | JMT | JVT | Analysis |
|--------|-----|-----|----------|
| Copy-on-write | O(m·log n) new nodes per batch of m updates | O(m·log₂₅₆ n) — fewer levels but same principle | **Fully compatible** |
| Shared subtrees | Unchanged children share nodes across versions | Identical | **Fully compatible** |
| StaleNodeIndex | `(version_stale: u64, node_key: NodeKey)` | Identical structure | **Fully compatible** |
| Node size | ~32-64 bytes (hashes) | ~32-48 bytes (curve points are 32 bytes compressed) | Comparable |
| Pruning | Delete all nodes with `version_stale <= target` | Identical | **Fully compatible** |

**Verdict: Fully compatible.** The persistent data structure pattern is entirely orthogonal to the commitment scheme. Compressed Bandersnatch points (32 bytes) are the same size as SHA-256 digests, so the StaleNodeIndex and pruning mechanisms work identically. The copy-on-write pattern actually produces *fewer* new nodes in JVT because 256-ary branching means fewer levels to copy.

### 2.4 Two Node Types Only (No Extensions)

| Aspect | JMT | JVT | Analysis |
|--------|-----|-----|----------|
| Node types | Internal (16 children) + Leaf | Internal (256 children) + EaS + Empty | **Must add extension-style nodes** |
| Rationale | With hashed 256-bit keys, long shared prefixes are rare at radix-16 | At radix-256, even 2 keys can share several byte prefixes | EaS nodes are essential |
| Extension mechanism | None needed | EaS nodes provide implicit path compression | Different from Ethereum's explicit extension nodes |

**Verdict: Not compatible — must add EaS nodes.** JMT's rationale for avoiding extension nodes is that with 256-bit hashed keys and radix-16 branching, the probability of long shared prefixes is negligible. This breaks down with radix-256 branching: with only 256 possible children per level, even a modest number of keys will produce many single-occupancy subtrees. Without path compression (via EaS nodes), the tree would contain long chains of internal nodes with only one populated child — wasting both storage and proof length.

The EaS node from Ethereum's verkle design solves this elegantly: it stores a stem (up to 31 bytes of key prefix beyond the tree traversal depth) and commits to 256 value slots. This combines JMT's leaf-floating idea with verkle-specific value commitment.

---

## 3. Node Type Definitions

### 3.1 InternalNode

```
InternalNode {
    children: SparseArray<256, Child>,  // Only populated slots stored
    commitment: Commitment,              // C = Σ children[i].commitment · G_i
}

Child {
    version: u64,          // Version at which this child was last modified
    commitment: Commitment, // The child node's commitment (curve point)
}
```

**Mapping to JMT:** Directly analogous to JMT's `InternalNode`, but with 256 children instead of 16. JMT stores children as `Option<Child>` for each of 16 slots; we do the same for 256 slots but use a sparse representation to avoid 256-entry arrays in the common case.

**Mapping to Ethereum verkle:** Identical to Ethereum's `InternalNode`. The commitment is a Pedersen vector commitment over the children's commitments: `C = Σ v_i · G_i` where `v_i` is the commitment of child `i` (as a scalar derived from the curve point) and `G_i` is the `i`-th basis element of the commitment scheme.

**Commitment computation:**
- For each child index `i` with a non-empty child: `v_i = child[i].commitment` (interpreted as a field element)
- For empty slots: `v_i = 0` (contributes nothing to the commitment)
- `C = pedersen_commit([v_0, v_1, ..., v_255])`

### 3.2 ExtensionAndSuffix (EaS) Node

```
ExtensionAndSuffix {
    stem: Vec<u8>,          // Up to 31 bytes of key prefix beyond this node's tree depth
    values: [Option<Vec<u8>>; 256],  // 256 value slots indexed by the final key byte
    c1: Commitment,         // Commitment over values[0..128] (lower half)
    c2: Commitment,         // Commitment over values[128..256] (upper half)
    extension_commitment: Commitment,  // Commitment over (1, stem, c1, c2)
}
```

**Mapping to JMT:** This is the JVT equivalent of JMT's "floating leaf." In JMT, when a subtree contains exactly one leaf, it's collapsed to that leaf with its full key hash. The EaS does the same thing but additionally:
1. Stores the remaining stem bytes (path compression)
2. Provides 256 value slots per stem (a stem groups keys that share the first 31 bytes)
3. Commits to the values via two sub-commitments (c1 for lower 128, c2 for upper 128)

**Mapping to Ethereum verkle:** This is Ethereum's Extension-and-Suffix node. The split into c1/c2 exists because the Pedersen commitment basis has 256 elements, but we need to commit to stem + values, so we split values into two groups of 128 and commit each separately, then commit the extension node as `extension_commitment = commit(1, stem_as_field_elements..., c1, c2)`.

**The marker value `1`:** The leading `1` in the extension commitment distinguishes EaS nodes from internal nodes in proofs. Internal nodes have no such marker. This prevents second-preimage attacks where an adversary presents an internal node as an EaS node or vice versa.

### 3.3 Empty Node

```
Empty  // Represents a missing subtree
```

**Commitment:** The empty node contributes `0` (the identity point on the curve) to its parent's commitment. This is the additive identity for Pedersen commitments, so empty slots require no scalar multiplication — they're simply omitted from the parent's commitment computation.

**Mapping to JMT:** Analogous to `None` in JMT's `Option<Child>` for internal node children. JMT doesn't have an explicit empty node type; `None` children are simply absent from the node's hash preimage. The JVT makes this explicit because the commitment scheme requires a well-defined value for every slot (even if that value is 0).

### 3.4 Summary of Node Type Relationships

```
                JMT                          JVT                          Eth Verkle
           ┌───────────┐               ┌──────────────┐               ┌──────────────┐
           │ Internal  │               │ InternalNode │               │ InternalNode │
           │ (16 kids) │      ←→       │ (256 kids)   │      ←→       │ (256 kids)   │
           └───────────┘               └──────────────┘               └──────────────┘
           ┌───────────┐               ┌──────────────┐               ┌──────────────┐
           │   Leaf    │               │     EaS      │               │     EaS      │
           │(key,val)  │      ←→       │(stem,values) │      ←→       │(stem,values) │
           └───────────┘               └──────────────┘               └──────────────┘
                                       ┌──────────────┐
              (None)         ←→        │    Empty     │      ←→         (nil child)
                                       └──────────────┘
```

---

## 4. Key Encoding Scheme

### 4.1 NodeKey Structure

```
NodeKey {
    version: u64,           // Monotonically increasing version number
    byte_path: Vec<u8>,     // Path from root, max length 31
}
```

**Binary encoding for storage:**
```
[version (8 bytes, big-endian)] [path_length (1 byte)] [byte_path (0-31 bytes)]
```

**Why big-endian version:** LSM-trees (RocksDB) use lexicographic key ordering. Big-endian version encoding ensures that newer versions sort after older versions, enabling:
1. Sequential writes always append to the end of the SST file
2. Version-range scans for pruning are a single prefix scan
3. State sync via range queries (all nodes at version ≥ V)

**Why max 31 bytes for byte_path:** With 256-ary branching and 32-byte keys:
- The first 31 bytes are used for tree traversal (one byte per level)
- The 32nd byte indexes into the EaS node's 256 value slots
- An EaS node at depth `d` has `byte_path.len() == d` and its `stem` covers bytes `d..31` of the key

### 4.2 Key Derivation

Given a raw 32-byte key `K = [k_0, k_1, ..., k_31]`:

1. **Tree traversal bytes:** `k_0, k_1, ..., k_{d-1}` where `d` is the depth of the EaS node
2. **EaS stem:** `k_d, k_{d+1}, ..., k_30` (the remaining prefix bytes after tree depth)
3. **Value index:** `k_31` (the final byte selects the value slot within the EaS)

This means:
- `NodeKey` for an internal node at depth 2 handling key `[0xAB, 0xCD, ...]` is `(version, [0xAB, 0xCD])`
- `NodeKey` for an EaS at depth 2 storing key `[0xAB, 0xCD, 0xEF, ...]` has `byte_path = [0xAB, 0xCD]` and `stem = [0xEF, ..., k_30]`

### 4.3 Comparison with JMT

| Property | JMT NodeKey | JVT NodeKey |
|----------|-------------|-------------|
| Version prefix | `u64` big-endian | `u64` big-endian (identical) |
| Path encoding | Nibble path (4 bits each) | Byte path (8 bits each) |
| Max path length | 64 nibbles | 31 bytes |
| Path corresponds to | Hash bits consumed during traversal | Key bytes consumed during traversal |
| Sequential write property | ✓ | ✓ (identical) |

---

## 5. Operations Specification

### 5.1 `insert(key: [u8; 32], value: Vec<u8>, version: u64) -> (RootCommitment, TreeUpdateBatch)`

Insert a key-value pair into the tree at the given version. Returns the new root commitment and a batch of node changes to persist.

**Algorithm:**

```
fn insert(key, value, version):
    path = key[0..31]      // traversal bytes
    suffix = key[31]        // value slot index

    // Walk from root, collecting the path of nodes
    (nodes_on_path, depth) = walk_to_leaf_or_empty(path, current_root)

    match nodes_on_path.last():
        Empty =>
            // Case 1: No existing node at this position
            // Create a new EaS node with the key's stem and value
            eas = new EaS(stem = path[depth..31], values[suffix] = value)
            compute_eas_commitments(eas)
            propagate_commitment_up(nodes_on_path, depth, eas, version)

        EaS(existing) =>
            if existing.stem == path[depth..31]:
                // Case 2: Same stem — update the value in the existing EaS
                old_value = existing.values[suffix]
                existing.values[suffix] = value
                update_eas_commitment_delta(existing, suffix, old_value, value)
                propagate_commitment_up(nodes_on_path, depth, existing, version)
            else:
                // Case 3: SPLIT — different stem, must create new internal node
                split_eas(existing, path, value, suffix, depth, version, nodes_on_path)

        InternalNode(node) =>
            // Should not happen — walk_to_leaf_or_empty descends through internals
            unreachable
```

**The Split Case (Case 3) — Critical Path:**

```
fn split_eas(existing_eas, new_key_path, new_value, new_suffix, depth, version, nodes_on_path):
    existing_stem = existing_eas.stem
    new_stem = new_key_path[depth..31]

    // Find the first byte where stems diverge
    common_prefix_len = common_prefix_length(existing_stem, new_stem)

    // Create the chain of internal nodes for the common prefix
    // (In practice, with 256-ary branching this is usually just one node)
    for i in 0..common_prefix_len:
        internal = new InternalNode(children = {})
        // This internal has exactly one child — will be filled in below

    // At the divergence point, create a new internal node with two children:
    diverge_internal = new InternalNode(children = {
        existing_stem[common_prefix_len]: new EaS(
            stem = existing_stem[common_prefix_len+1..],
            values = existing_eas.values,  // preserve all existing values
        ),
        new_stem[common_prefix_len]: new EaS(
            stem = new_stem[common_prefix_len+1..],
            values = { [new_suffix] = new_value },
        ),
    })

    // Compute commitments bottom-up for the entire new structure
    // This is a FULL RECOMPUTATION, not a homomorphic delta
    compute_commitment(diverge_internal)

    // Propagate the new commitment up to the root
    propagate_commitment_up(nodes_on_path, depth, diverge_internal, version)
```

**Complexity:** O(log₂₅₆ n) node reads + O(log₂₅₆ n) new nodes written + O(log₂₅₆ n) commitment updates propagated up.

### 5.2 `get(key: [u8; 32], version: u64) -> Option<Vec<u8>>`

Retrieve the value associated with a key at a specific version.

**Algorithm:**

```
fn get(key, version):
    path = key[0..31]
    suffix = key[31]

    current = load_node(root_key_at(version))
    depth = 0

    loop:
        match current:
            Empty => return None

            EaS(node) =>
                if node.stem == path[depth..31]:
                    return node.values[suffix]  // may be None if slot is empty
                else:
                    return None  // key doesn't exist (stem mismatch)

            InternalNode(node) =>
                child_index = path[depth]
                match node.children[child_index]:
                    None => return None
                    Some(child) =>
                        current = load_node(NodeKey(child.version, path[0..depth+1]))
                        depth += 1
```

**Complexity:** O(log₂₅₆ n) node reads. With 256-ary branching, a tree with 10⁹ entries has at most ~4 levels, so this is 4 reads in practice.

### 5.3 `prove(key: [u8; 32], version: u64) -> VerkleProof`

Generate a proof of inclusion (or non-inclusion) for a single key.

**Proof structure:**

```
VerkleProof {
    // For each level traversed (root to EaS):
    commitments: Vec<Commitment>,       // The commitment at each internal node
    opening_proofs: Vec<OpeningProof>,   // IPA proof that child_commitment is at index i

    // At the EaS level:
    eas_stem: Vec<u8>,
    eas_proof: EaSOpeningProof,         // Proof that (stem, c1, c2) are committed
    value_proof: OpeningProof,          // Proof that value is at the correct index in c1 or c2

    // The value itself (or absence marker)
    value: Option<Vec<u8>>,
}
```

**For each internal node on the path:** Generate an IPA opening proof showing that the child's commitment at index `path[depth]` is correctly committed within the parent's vector commitment.

**For the EaS node:** Generate proofs that:
1. The extension commitment correctly contains (1, stem, c1, c2)
2. The value is correctly committed within c1 (if suffix < 128) or c2 (if suffix ≥ 128)

**Non-inclusion proof:** If the key doesn't exist, the proof terminates at either:
- An empty child slot in an internal node (prove the slot is empty)
- An EaS node with a different stem (prove the stem doesn't match)

### 5.4 `prove_batch(keys: Vec<[u8; 32]>, version: u64) -> AggregatedVerkleProof`

Generate an aggregated proof for multiple keys. This is the killer feature of verkle trees.

**Algorithm (conceptual):**

1. For each key, collect the individual opening proofs (as in `prove`)
2. Group all opening proofs by their commitment (many keys may traverse the same internal node)
3. Use the **multipoint argument** (Dankrad Feist's scheme) to compress all opening proofs into a single ~200-byte proof

**Multipoint aggregation sketch:**
- Verifier sends random challenge `r`
- All openings `(C_i, z_i, y_i)` (commitment, evaluation point, claimed value) are combined:
  - `g(X) = Σ r^i · (f_i(X) - y_i) / (X - z_i)` — the aggregated quotient
- A single IPA proof for `g` suffices to verify all openings

**Implementation status:** Fully implemented following the crate-crypto/go-ipa and crate-crypto/rust-verkle reference implementations. Uses Blake3-based Fiat-Shamir transcripts. Produces a 576-byte constant-size proof. See `src/multiproof/prover.rs` for the implementation and `src/verkle_proof.rs` for tree-level integration.

### 5.5 `verify(proof: VerkleProof, root: RootCommitment, key, value) -> bool`

Verify a single-key proof against a root commitment.

```
fn verify(proof, root, key, value):
    path = key[0..31]
    suffix = key[31]

    // Verify each level's opening proof
    current_commitment = root
    for depth in 0..proof.commitments.len():
        child_index = path[depth]
        if !verify_opening(
            current_commitment,
            child_index,
            proof.commitments[depth],
            proof.opening_proofs[depth]
        ):
            return false
        current_commitment = proof.commitments[depth]

    // Verify the EaS opening
    if !verify_eas_opening(current_commitment, proof.eas_stem, proof.eas_proof):
        return false

    // Verify the value within the EaS
    sub_commitment = if suffix < 128 { proof.c1 } else { proof.c2 }
    sub_index = if suffix < 128 { suffix } else { suffix - 128 }
    if !verify_opening(sub_commitment, sub_index, value_to_field(value), proof.value_proof):
        return false

    return true
```

### 5.6 `verify_batch(proof: AggregatedVerkleProof, root, keys, values) -> bool`

Verify an aggregated multipoint proof. The verifier reconstructs `E = Σ C_i · (r^i / (t - z_i))` via MSM, computes `g_2(t) = Σ r^i · y_i / (t - z_i)`, and verifies a single IPA proof for `(E - D)` at point `t`. See `src/verkle_proof.rs::verify_aggregated`.

---

## 6. Commitment Update Protocol

This section documents exactly how commitments are maintained during tree mutations. **This is the most bug-prone area of the design.**

### 6.1 Value Update (Same EaS, Same Stem)

When updating a value at an existing key where the EaS stem matches:

```
// 1. Compute the delta at the value level
old_field = value_to_field(old_value)  // or 0 if slot was empty
new_field = value_to_field(new_value)
delta = new_field - old_field

// 2. Update the sub-commitment (c1 or c2) homomorphically
if suffix < 128:
    eas.c1 = eas.c1 + delta · G_{suffix}
else:
    eas.c2 = eas.c2 + delta · G_{suffix - 128}

// 3. Update the extension commitment
// The extension commitment = commit(1, stem_fields..., c1, c2)
// c1 is at a fixed index in this commitment (index after stem fields)
// The delta in c1/c2 propagates:
if suffix < 128:
    c1_index = <index of c1 in extension commitment>
    eas.extension_commitment += delta_c1 · G_{c1_index}
else:
    c2_index = <index of c2 in extension commitment>
    eas.extension_commitment += delta_c2 · G_{c2_index}

// 4. Propagate up to root
// For each ancestor internal node from EaS's parent up to root:
//   parent.commitment += delta_child · G_{child_index}
// where delta_child is the change in the child's commitment
for (parent, child_index) in ancestors.reverse():
    delta_child = new_child_commitment - old_child_commitment
    parent.commitment += commitment_to_field(delta_child) · G_{child_index}
```

**Key property:** Each level requires exactly **one scalar multiplication and one point addition** — O(1) per level, O(depth) total. No sibling data is needed.

### 6.2 New Key Insert (Empty Slot)

When inserting into an empty child slot of an internal node:

```
// 1. Create a new EaS node and compute its commitments from scratch
eas = new_eas(stem, value, suffix)
eas.c1 = compute_c1(eas.values[0..128])
eas.c2 = compute_c2(eas.values[128..256])
eas.extension_commitment = commit(1, stem_fields..., c1, c2)

// 2. The delta at the parent is simply the new child's commitment
// (the old child was Empty, contributing 0)
delta = commitment_to_field(eas.extension_commitment)

// 3. Propagate: parent.commitment += delta · G_{child_index}
// Continue up to root — same as 6.1 step 4
```

### 6.3 EaS Split (Key Collision on Different Stem)

**This is the non-homomorphic case.** When a new key collides with an existing EaS on the tree path but has a different stem:

```
// 1. Determine the divergence point
shared_prefix = common_prefix(existing.stem, new_stem)
diverge_byte_existing = existing.stem[shared_prefix.len()]
diverge_byte_new = new_stem[shared_prefix.len()]

// 2. Create new EaS nodes
existing_new_eas = EaS {
    stem: existing.stem[shared_prefix.len()+1..],
    values: existing.values,  // all values preserved
    c1: existing.c1,          // c1 preserved (values unchanged)
    c2: existing.c2,          // c2 preserved (values unchanged)
}
// Recompute extension_commitment with new (shorter) stem
existing_new_eas.extension_commitment = commit(1, new_stem_fields..., c1, c2)

new_eas = EaS {
    stem: new_stem[shared_prefix.len()+1..],
    values: { [suffix] = value },
}
compute_all_commitments(new_eas)  // fresh computation

// 3. Create new internal node(s) for the shared prefix
// Usually just one internal node at the divergence point
diverge_node = InternalNode {
    children: {
        diverge_byte_existing: Child(version, existing_new_eas.extension_commitment),
        diverge_byte_new: Child(version, new_eas.extension_commitment),
    },
}
// FULL RECOMPUTATION — cannot use homomorphic update
diverge_node.commitment = pedersen_commit(children_as_field_elements)

// 4. If shared_prefix.len() > 0, create a chain of single-child internal nodes
// (This is rare with 256-ary branching but possible)
// Each such node also needs full commitment computation

// 5. Propagate the commitment change from the divergence point up to root
// This part CAN use homomorphic updates:
delta = new_diverge_commitment - old_eas_commitment
for (parent, child_index) in ancestors_above_divergence.reverse():
    parent.commitment += commitment_to_field(delta) · G_{child_index}
    delta = new_parent_commitment - old_parent_commitment
```

**Why this can't be homomorphic:** The old node at this position was an EaS; the new node is an InternalNode. These are fundamentally different commitment structures — you can't express the difference as a scalar delta on a single basis element. The new internal node's commitment must be computed from scratch.

**However:** Only the node(s) at the split point require full recomputation. All ancestor nodes above the split can still use homomorphic delta updates. This limits the cost to O(1) full computations + O(depth) homomorphic updates.

### 6.4 Batch Updates

When applying multiple key-value updates at the same version:

```
fn batch_insert(updates: Vec<(Key, Value)>, version: u64):
    // Sort updates by key to minimize tree traversal
    updates.sort_by_key(|(k, _)| k)

    // Group updates that share the same EaS (same stem)
    // These can be applied as homomorphic deltas to the same EaS
    grouped = group_by_stem(updates)

    // Apply each group, collecting commitment deltas
    for group in grouped:
        apply_group(group, version)

    // Propagate all deltas up the tree
    // Multiple updates may share ancestor nodes — accumulate deltas
    propagate_all_deltas(version)
```

**Optimization:** When multiple updates affect the same internal node (common at upper levels), their deltas can be accumulated and applied in a single pass: `C_new = C_old + Σ delta_i · G_{index_i}`.

---

## 7. Proof Size Analysis

### 7.1 Single-Key Proof (Measured)

Each internal node level requires one IPA proof (Bulletproofs-style, 8 rounds for 256 elements):

| Component | JMT (Merkle) | JVT (Verkle) |
|-----------|--------------|--------------|
| Per internal level | 15 sibling hashes × 32B = 480B | 1 IPA proof = 544B |
| Levels (10⁹ entries) | ~8 (nibble-based) | ~4 (byte-based) |
| Leaf/EaS proof | 1 hash = 32B | ~96B (stem + c1/c2 openings) |
| **Total single proof** | **~3,904B** | **~2,272B** |

For single-key proofs, JVT's IPA proofs are larger per level (544B vs 480B) but the tree is shallower (256-ary vs 16-ary), so total proof size is comparable.

### 7.2 Batch Proof — Multipoint Aggregation (Measured)

The Dankrad Feist multipoint scheme compresses ALL openings across ALL keys into a single proof:

| Keys | JVT Multiproof | JMT (N × individual) | Compression |
|------|---------------|----------------------|-------------|
| 1 | 576 B | 544 B | 1× |
| 10 | 576 B | 5,440 B | 9× |
| 100 | 576 B | 102,400 B | 178× |
| 1,000 | 576 B | 1,504,000 B | 2,611× |

**The multipoint proof is 576 bytes constant** (1 group element D + 1 IPA proof with 8 rounds = 32 + 544 bytes), regardless of how many keys are included. This is the core verkle advantage.

The multiproof protocol:
1. Fiat-Shamir challenge `r` aggregates all openings via random linear combination
2. Polynomials grouped by evaluation point, combined into quotient `g(X)`
3. Challenge `t` (outside domain) produces `h(X) = Σ agg_f(X) / (t - z)`
4. Single IPA proof for `h(X) - g(X)` at point `t`
5. Verifier reconstructs `E` via MSM over commitments, checks single IPA

### 7.3 Notes

- All sizes measured from the implementation using real Bandersnatch curve operations
- JMT proof sizes assume radix-16 with 15 sibling hashes per level
- The 576B multiproof size does not include per-key metadata (stems, values) which the verifier also needs

---

## 8. Storage Layout

### 8.1 RocksDB Key-Value Mapping

```
Key: NodeKey (version, byte_path) → encoded as [version_be_8B][path_len_1B][path_0..31B]
Value: Node (serialized InternalNode | EaS | Empty marker)
```

**Column families:**
1. `nodes` — Primary node storage, keyed by NodeKey
2. `stale_index` — StaleNodeIndex entries, keyed by `(stale_version, node_key)`
3. `root_index` — Maps version → root NodeKey

### 8.2 Write Pattern

All writes at version `v` produce keys prefixed with `v` (big-endian). Since versions are monotonically increasing, all writes append to the end of the LSM tree's memtable/SST files. This gives:
- **Write amplification ≈ 1** (no compaction-induced rewrites of old data)
- **Sequential I/O** on the write path
- **Efficient pruning** via range deletion of all keys with `version < target`

This is JMT's most important production optimization, and it transfers to JVT unchanged.

---

## 9. Commitment Scheme

Pedersen vector commitments on the Bandersnatch curve (defined over the BLS12-381 scalar field), using the arkworks ecosystem.

**Basis generators:** 256 points `G_0, ..., G_255` generated deterministically from a seeded RNG via a Common Reference String (CRS). A separate independent point `Q` is used for inner product binding in the IPA.

**Commitment:** `C = Σ v_i · G_i` where `v_i` are scalars (field elements) and `G_i` are curve points.

**Homomorphic update:** `C_new = C_old + (v_new - v_old) · G_index` — one scalar multiplication and one point addition, regardless of vector width.

**Value encoding:** Values ≤ 31 bytes are packed directly as field elements. Longer values are hashed with Blake3 and truncated to 31 bytes.

**Commitment-to-scalar mapping:** `commitment_to_field(C)` uses the Banderwagon mapping `x / y` — the x-coordinate divided by the y-coordinate of the affine point. This is a canonical 2-to-1 map that identifies `(x, y)` and `(-x, -y)`, producing a unique scalar for each group element without hashing. Follows the reference implementation in crate-crypto/rust-verkle.

**Fiat-Shamir transcripts:** All non-interactive proofs use Blake3-based transcripts with an append-then-hash-then-clear pattern, following the protocol structure from crate-crypto/go-ipa.

---

## 10. Design Decisions and Rationale

### 10.1 Why 256-ary (not 1024-ary or configurable)?

Ethereum's verkle design uses 256-ary branching because:
- One byte per tree level = simple key encoding
- The IPA cost scales linearly with width, so 256 is a good tradeoff between depth and per-node proof cost
- The Pedersen commitment basis needs 256 elements, which is manageable

We follow this choice for compatibility with the Ethereum verkle ecosystem and tooling.

### 10.2 Why split c1/c2 in EaS (not a single c256)?

The extension commitment needs to commit to: 1 marker + stem fields + c1 + c2. If we used a single commitment for all 256 values, we'd need 256 + ~32 basis elements for the extension commitment, exceeding the 256-element basis. Splitting values into two groups of 128 keeps everything within the 256-element basis:
- c1 = commit(values[0..128]) using 128 basis elements
- c2 = commit(values[128..256]) using 128 basis elements
- extension = commit(1, stem[0], stem[1], ..., stem[30], c1, c2) using ≤256 basis elements

### 10.3 Why not hash the key before insertion?

JMT hashes keys to get a uniform 256-bit distribution, which ensures balanced trees. We could do the same, but verkle trees typically work with unhashed keys because:
- The EaS node's 256 value slots provide natural grouping for related keys
- Hashing destroys key locality, preventing efficient range proofs
- With 256-ary branching, even non-uniform key distributions produce shallow trees

For the prototype, we support both modes (hashed and unhashed keys) via a trait.

### 10.4 Value encoding in commitments

Values stored in EaS slots must be converted to field elements for commitment. For values ≤ 31 bytes, we encode them directly as a field element. For larger values, we store a hash of the value in the commitment and keep the full value separately. This follows Ethereum's approach.

```rust
fn value_to_field(value: &[u8]) -> FieldElement {
    if value.len() <= 31 {
        // Pack directly as field element (little-endian, top byte zeroed)
        FieldElement(Fr::from_le_bytes_mod_order(&padded_bytes))
    } else {
        // Hash with Blake3, take 31 bytes
        let hash = blake3::hash(value);
        FieldElement(Fr::from_le_bytes_mod_order(&hash.as_bytes()[..31]))
    }
}
```

---

## 11. Public API

All operations are stateless — no mutable tree struct, no hidden version tracking. The caller controls versioning and applies writes.

### 11.1 Core Operations

```rust
/// Apply a batch of updates. Returns new root commitment + writes to persist.
pub fn apply_updates<S: TreeReader>(
    store: &S,
    parent_version: Option<u64>,
    new_version: u64,
    updates: BTreeMap<Key, Option<Value>>,
) -> UpdateResult;

/// Read a value.
pub fn get_value<S: TreeReader>(store: &S, root_key: &NodeKey, key: &Key) -> Option<Value>;

/// Verify commitment integrity.
pub fn verify_commitment_consistency<S: TreeReader>(store: &S, root_key: &NodeKey) -> bool;
```

### 11.2 Two-Phase Commit Pattern

The `apply_updates` function takes a **read-only store** and returns an `UpdateResult` containing:
- `root_commitment`: the new root
- `root_key`: the new root's storage key
- `batch`: `TreeUpdateBatch` with all new nodes and stale node markers

The caller applies the batch to storage separately. This matches hyperscale-rs's existing two-phase commit pattern where the JMT computation is speculative (during verification) and writes are applied atomically (during commit).

For batch updates at the same version, an internal `OverlayStore` ensures each insert sees previous writes within the same batch.

### 11.3 Storage Traits

```rust
pub trait TreeReader {
    fn get_node(&self, key: &NodeKey) -> Option<&Node>;
    fn get_root_key(&self, version: u64) -> Option<&NodeKey>;
}

pub trait TreeWriter {
    fn put_node(&mut self, key: NodeKey, node: Node);
    fn set_root_key(&mut self, version: u64, key: NodeKey);
    fn record_stale(&mut self, entry: StaleNodeIndex);
}
```

### 11.4 Proof Generation

```rust
// Single-key proof (individual IPA per tree level)
pub fn prove<S: TreeReader>(store: &S, root_key: &NodeKey, key: &Key) -> Option<RealVerkleProof>;

// Aggregated multiproof (single 576-byte proof for any number of keys)
pub fn prove_aggregated<S: TreeReader>(store: &S, root_key: &NodeKey, keys: &[Key]) -> Option<AggregatedMultiProof>;

// Verification
pub fn verify_aggregated(proof: &AggregatedMultiProof, root: Commitment, keys: &[Key], values: &[Option<Value>]) -> bool;
```
