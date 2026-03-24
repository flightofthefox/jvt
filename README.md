# Jellyfish Verkle Tree (JVT)

A novel authenticated data structure combining the storage-layer optimizations of the **Jellyfish Merkle Tree** (JMT) with the proof-aggregation capabilities of **verkle trees**.

## What is this?

JVT is a research prototype that answers: *can JMT's production-grade storage design be combined with verkle tree's constant-size proofs and multipoint aggregation?*

**From JMT:**
- Version-based node keys for LSM-tree-friendly sequential writes (write amplification ≈ 1)
- Single-leaf subtree collapsing for O(log n) average depth
- Persistent data structure with stale node tracking for efficient pruning

**From Verkle Trees:**
- Vector commitments (Pedersen) for constant-size per-level proofs
- Multipoint proof aggregation for compressed batch witnesses (~200 bytes for any number of keys)
- Homomorphic commitment updates (O(1) per level for single-value changes)

## Project Structure

```
├── DESIGN.md                    # Full design document (Phase 1)
├── spec/
│   ├── jvt.qnt                  # Core JVT Quint formal specification
│   ├── commitment.qnt           # Abstract commitment model
│   └── README.md                # How to run Quint simulations
├── src/
│   ├── lib.rs                   # Crate root
│   ├── commitment.rs            # Mock homomorphic commitment scheme
│   ├── node.rs                  # Node types (Internal, EaS, Empty)
│   ├── tree.rs                  # Core operations (insert, get)
│   ├── proof.rs                 # Proof generation/verification (mock)
│   └── storage.rs               # Version-based storage layer
├── tests/
│   └── property_tests.rs        # proptest property-based tests
└── benches/
    └── comparison.rs            # Criterion benchmarks
```

## Quick Start

```bash
# Run all tests (unit + property-based)
cargo test

# Run the demo
cargo run

# Run benchmarks
cargo bench

# Run Quint simulation (requires quint CLI)
cd spec && quint run --main=jvt --max-samples=10000 --invariant=allInvariants jvt.qnt
```

## Known Limitations

### What is mocked
- **Commitment scheme**: Uses additive homomorphism over a prime field instead of real Pedersen commitments on Bandersnatch. Structural correctness is preserved; cryptographic security is not.
- **Opening proofs**: The mock "proof" includes claimed values directly. Real IPA proofs would be ~64 bytes per opening.
- **Multipoint aggregation**: Batch proofs are concatenated individual proofs. Real aggregation compresses to ~200 bytes regardless of key count.

### What is verified
- **Get-after-insert**: All inserted keys are retrievable (proptest)
- **Commitment consistency**: All stored commitments match recomputation (proptest + unit tests)
- **Version monotonicity**: Node versions never exceed current version (proptest)
- **Versioned reads**: Historical values are preserved across updates (proptest)
- **Commitment determinism**: Same operations → same root commitment (proptest)
- **Structural invariants**: Modeled in Quint spec with simulation-based checking

### What would be needed for production
1. Real Pedersen commitments on the Bandersnatch curve (e.g., `banderwagon` crate)
2. IPA (Inner Product Argument) proof system for openings
3. Multipoint proof aggregation (Dankrad Feist's scheme)
4. RocksDB storage backend (replacing `MemoryStore`)
5. Security audit of the commitment scheme integration
6. Fiat-Shamir transcript binding for proof non-interactivity

### Quantum security
Ethereum is pivoting from verkle trees to binary hash trees + SNARK compression (EIP-7864) due to quantum concerns with ECC. Verkle trees remain optimal for systems not requiring post-quantum security.
