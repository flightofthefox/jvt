# JVT Quint Specifications

## Files

- `commitment.qnt` — Abstract vector commitment model (homomorphic, mock field arithmetic, `commitmentToField`)
- `jvt.qnt` — Core JVT specification: node types, insert, delete, proof model, and invariants

## Running Simulations

Install Quint:
```bash
npm install -g @informalsystems/quint
```

Type-check the spec:
```bash
quint typecheck jvt.qnt
```

Run simulation with all invariants:
```bash
quint run --main=jvt --max-samples=10000 --invariant=allInvariants jvt.qnt
```

Run invariant groups individually (faster):
```bash
quint run --main=jvt --max-samples=10000 --invariant=coreInvariants jvt.qnt
quint run --main=jvt --max-samples=10000 --invariant=structuralInvariants jvt.qnt
quint run --main=jvt --max-samples=10000 --invariant=proofInvariants jvt.qnt
quint run --main=jvt --max-samples=10000 --invariant=historyPreservation jvt.qnt
```

Run individual invariants:
```bash
quint run --main=jvt --max-samples=10000 --invariant=getAfterInsert jvt.qnt
quint run --main=jvt --max-samples=10000 --invariant=commitmentConsistency jvt.qnt
quint run --main=jvt --max-samples=10000 --invariant=versionMonotonicity jvt.qnt
quint run --main=jvt --max-samples=10000 --invariant=noUncollapsedSingleChild jvt.qnt
quint run --main=jvt --max-samples=10000 --invariant=staleNodesUnreachable jvt.qnt
quint run --main=jvt --max-samples=10000 --invariant=proofCompleteness jvt.qnt
quint run --main=jvt --max-samples=10000 --invariant=proofAbsenceCorrectness jvt.qnt
```

## Invariants

### Core

| Invariant | Description |
|-----------|-------------|
| `getAfterInsert` | All keys in the latest kvMap are retrievable with correct values |
| `versionMonotonicity` | All node keys have version ≤ current version |
| `commitmentConsistency` | All stored commitments match recomputation from children/values |
| `rootExistsForAllVersions` | A root key exists for every version from 1 to current |

### History

| Invariant | Description |
|-----------|-------------|
| `historyPreservation` | Reading at any past version returns the values that were current at that version |

### Structural

| Invariant | Description |
|-----------|-------------|
| `noUncollapsedSingleChild` | No internal node reachable from the current root has a single EaS child (should have been collapsed) |
| `staleNodesUnreachable` | No stale node is reachable from the current root |

### Proof Model

| Invariant | Description |
|-----------|-------------|
| `proofCompleteness` | For every key in kvMap, `generateProof` + `verifyProofChain` succeeds |
| `proofConsistency` | `generateProof` returns the same value/found status as `lookup` |
| `proofAbsenceCorrectness` | For keys not in kvMap, absence proofs generate and verify correctly |

### Commitment Scheme

| Invariant | Description |
|-----------|-------------|
| `homomorphicUpdateEquivalence` | `commitUpdate` matches full recomputation for test vectors |

### Groups

| Group | Contents |
|-------|----------|
| `coreInvariants` | getAfterInsert + versionMonotonicity + commitmentConsistency + rootExistsForAllVersions |
| `structuralInvariants` | noUncollapsedSingleChild + staleNodesUnreachable |
| `proofInvariants` | proofCompleteness + proofConsistency + proofAbsenceCorrectness |
| `allInvariants` | All of the above + historyPreservation + homomorphicUpdateEquivalence |

## Operations Modeled

The state machine (`step`) non-deterministically chooses between:

- **Insert**: Add or update a key-value pair, handling stem splits and chain propagation
- **Delete**: Remove a key, handling EaS value removal, node collapse (single-EaS-child internal → merged EaS), and empty tree cleanup

Both operations advance the version, update the stale index, and maintain kvHistory snapshots.

## Proof Model

The abstract proof model (`generateProof` + `verifyProofChain`) captures the essential structure of verkle proofs without real cryptography:

- **Proof generation** traverses the tree collecting `(commitment, eval_point, eval_result)` openings
- **Proof verification** checks the commitment chain from root to leaf without store access:
  - Internal nodes link via `commitmentToField`
  - EaS marker byte opens to 1
  - Sub-commitments link via `commitmentToField`
  - Value openings match expected values
  - Absence: empty slots open to 0, stem mismatches show divergent bytes

This models the structural checks that the real IPA-based multipoint proof provides, validating that the proof format is sound.

## Design Notes

The simulation uses small key spaces (4 possible values for each of the first 2 bytes and the suffix byte) to make state exploration tractable. The commitment scheme uses modular arithmetic over a small prime (104729) with a bijective `commitmentToField` mapping, rather than real elliptic curve operations. These simplifications preserve the structural properties being verified while keeping simulation feasible.
