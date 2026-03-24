# Jellyfish Verkle Tree (JVT)

An authenticated data structure combining the storage-layer optimizations of the **Jellyfish Merkle Tree** (JMT) with the proof-aggregation capabilities of **verkle trees**.

## What is this?

JVT combines JMT's production-grade storage design with verkle tree proof aggregation:

**From JMT:**
- Version-based node keys for LSM-tree-friendly sequential writes (write amplification ≈ 1)
- Single-leaf subtree collapsing for O(log n) average depth
- Persistent data structure with stale node tracking for efficient pruning

**From Verkle Trees:**
- Pedersen vector commitments on the Bandersnatch curve
- IPA (Inner Product Argument) opening proofs — 544 bytes per opening
- Multipoint proof aggregation (Dankrad Feist scheme) — **576 bytes constant** regardless of key count
- Homomorphic commitment updates (O(1) per level for single-value changes)

## API

All operations are stateless — no hidden mutation:

```rust
// Apply a batch of updates (the core operation)
let result = apply_updates(&store, parent_version, new_version, updates);
store.apply(&result);

// Read a value
let value = get_value(&store, &root_key, &key);

// Verify tree integrity
assert!(verify_commitment_consistency(&store, &root_key));
```

## Project Structure

```
├── DESIGN.md                    # Design document
├── spec/
│   ├── jvt.qnt                  # Quint formal specification
│   └── commitment.qnt           # Abstract commitment model
├── src/
│   ├── lib.rs                   # Crate root and public exports
│   ├── commitment.rs            # Pedersen commitments on Bandersnatch
│   ├── node.rs                  # Node types (Internal, EaS)
│   ├── tree.rs                  # Core: apply_updates, get_value
│   ├── storage.rs               # TreeReader / TreeWriter traits + MemoryStore
│   ├── ipa.rs                   # Single-key IPA opening proofs
│   ├── verkle_proof.rs          # Tree proof generation (individual + aggregated)
│   ├── multiproof/              # Dankrad Feist multipoint aggregation
│   │   ├── crs.rs               # Common Reference String (basis generators)
│   │   ├── ipa.rs               # IPA matching reference protocol
│   │   ├── lagrange.rs          # Lagrange basis + barycentric weights
│   │   ├── prover.rs            # MultiPointProver::open / MultiPointProof::check
│   │   └── transcript.rs        # Fiat-Shamir transcript (Blake3)
│   └── proof.rs                 # Structural proof helpers
├── tests/
│   ├── property_tests.rs        # proptest property-based tests
│   └── quint_traces.rs          # Quint Connect trace replay
├── benches/
│   └── comparison.rs            # Criterion benchmarks
└── examples/
    └── proof_size_analysis.rs   # JVT vs JMT proof size comparison
```

## Quick Start

```bash
# Run all tests (64 tests — unit, property-based, Quint Connect)
cargo test

# Run benchmarks
cargo bench

# Run proof size analysis
cargo run --example proof_size_analysis

# Run Quint formal spec simulation (requires quint CLI)
cd spec && quint run --main=jvt --max-samples=10000 --invariant=allInvariants jvt.qnt
```

## Proof Sizes

The multipoint proof is **576 bytes constant**, regardless of how many keys are included:

| Keys proved | JVT multiproof | JMT (N × individual) | Compression |
|-------------|---------------|-----------------------|-------------|
| 10 | 576 B | 5,440 B | 9× |
| 100 | 576 B | 102,400 B | 178× |
| 1,000 | 576 B | 1,504,000 B | 2,611× |

## Cryptography

- **Curve**: Bandersnatch (defined over BLS12-381 scalar field) via arkworks
- **Commitments**: Pedersen vector commitments with 256 basis generators
- **Opening proofs**: Bulletproofs-style IPA (8 rounds for 256-element vectors = 544 bytes)
- **Aggregation**: Dankrad Feist multipoint scheme — single IPA + quotient commitment = 576 bytes
- **Hashing**: Blake3 for Fiat-Shamir transcripts and value-to-field mapping

## Formal Verification

The Quint specification (`spec/jvt.qnt`) models the tree state machine and checks invariants via simulation:

- **Get-after-insert**: All inserted keys are retrievable
- **Commitment consistency**: Stored commitments match recomputation from children
- **Version monotonicity**: Node versions never exceed current version
- **Root existence**: A root key exists for every committed version

The Quint Connect integration replays spec-generated traces against the Rust implementation, verifying behavioral equivalence.

## What's Left

- **Banderwagon mapping**: `commitment_to_field()` currently hashes the serialized point with Blake3. The proper construction uses the Banderwagon quotient group's canonical map (x-coordinate extraction), which is faster and aligns with the Ethereum verkle spec. Small, self-contained change.
- **Security audit**: Fiat-Shamir domain separation (are transcript labels collision-resistant across proof contexts?), CRS generation (deterministic RNG seed is not a proper trusted setup), and proof soundness (does the IPA folding match the Bulletproofs security proof?).

Storage backends and any tier frameworks are application-level concerns handled by the consumer.
