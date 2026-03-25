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
- Multipoint proof aggregation (Dankrad Feist scheme) — 576-byte constant cryptographic proof + compact witness data
- Homomorphic commitment updates (O(1) per level for single-value changes)

## API

The tree stores field elements, not raw bytes. Callers convert values before insertion:

```rust
use jellyfish_verkle_tree::{apply_updates, value_to_field, get_committed_value};

// Values are converted to field elements at the boundary
let field_val = value_to_field(&raw_bytes);
updates.insert(key, Some(field_val));

// Apply a batch of updates (the core operation)
let result = apply_updates(&store, parent_version, new_version, updates);
store.apply(&result);

// Read back a field element
let value = get_committed_value(&store, &root_key, &key);

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
│   ├── verkle_proof.rs          # Proof generation, query reconstruction, verification
│   └── multiproof/              # Dankrad Feist multipoint aggregation
│       ├── crs.rs               # Common Reference String (basis generators)
│       ├── ipa.rs               # IPA matching reference protocol
│       ├── lagrange.rs          # Lagrange basis + barycentric weights
│       ├── prover.rs            # MultiPointProver::open / MultiPointProof::check
│       └── transcript.rs        # Fiat-Shamir transcript (Blake3)
├── tests/
│   ├── property_tests.rs        # proptest property-based tests
│   ├── quint_traces.rs          # Quint Connect trace replay
│   └── security_tests.rs        # Proof soundness and rejection tests
├── benches/
│   └── comparison.rs            # Criterion benchmarks
└── examples/
    ├── basics.rs                # Insert, read, delete operations
    ├── bench_proofs.rs          # Production-workload proof timing
    ├── proof_size_analysis.rs   # JVT vs JMT proof size comparison
    ├── state_snapshots.rs       # Version-based state snapshots
    ├── verkle_proofs.rs         # Single and batch proof generation
    └── versioning.rs            # Multi-version reads and pruning
```

## Quick Start

```bash
# Run all tests (78 tests — unit, property-based, security, Quint Connect)
cargo test

# Run benchmarks
cargo bench

# Run proof size analysis
cargo run --example proof_size_analysis

# Run Quint formal spec simulation (requires quint CLI)
cd spec && quint run --main=jvt --max-samples=10000 --invariant=allInvariants jvt.qnt
```

## Proof Sizes

A proof consists of a **576-byte constant** multipoint proof plus per-key witness data (deduplicated commitment table + path metadata). Measured from a 300K-entry tree:

| Keys proved | JVT total | JMT (N × individual) | Compression |
|-------------|-----------|----------------------|-------------|
| 7 | 2.1 KB | 27 KB | 13× |
| 56 | 12 KB | 215 KB | 18× |
| 196 | 39 KB | 753 KB | 19× |

The cryptographic proof (576B) is amortized across all keys. The witness data scales sub-linearly because keys sharing internal nodes deduplicate their commitments. See DESIGN.md §7 for a full breakdown.

## Cryptography

- **Curve**: Bandersnatch (defined over BLS12-381 scalar field) via arkworks
- **Commitments**: Pedersen vector commitments with 256 basis generators
- **Opening proofs**: Bulletproofs-style IPA (8 rounds for 256-element vectors = 544 bytes)
- **Aggregation**: Dankrad Feist multipoint scheme — single IPA + quotient commitment = 576 bytes
- **Hashing**: Blake3 for Fiat-Shamir transcripts, CRS seed expansion, and value-to-field overflow (values >31 bytes)

## Formal Verification

The Quint specification (`spec/jvt.qnt`) models the tree state machine and checks invariants via simulation:

- **Get-after-insert**: All inserted keys are retrievable
- **Commitment consistency**: Stored commitments match recomputation from children
- **Version monotonicity**: Node versions never exceed current version
- **Root existence**: A root key exists for every committed version

The Quint Connect integration replays spec-generated traces against the Rust implementation, verifying behavioral equivalence.

## What's Left

- **Security audit**: Fiat-Shamir transcript framing (labels and data are concatenated without length prefixes — ambiguous parsing could allow transcript collisions), CRS canonicity (the deterministic seed `"eth_verkle_oct_2021"` and generation procedure should match the Ethereum verkle spec exactly — IPA does not require a trusted setup, but reproducibility matters), and IPA soundness (does the folding protocol match the Bulletproofs/Halo security proof for the Bandersnatch curve?).

- **Application-level concerns**: Storage backends and tier frameworks are application-level concerns handled by the consumer.
