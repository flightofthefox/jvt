# JVT Quint Specifications

## Files

- `commitment.qnt` — Abstract vector commitment model (homomorphic, mock field arithmetic)
- `jvt.qnt` — Core JVT specification: node types, insert, get, pruning, and invariants

## Running Simulations

Install Quint:
```bash
npm install -g @informalsystems/quint
```

Type-check the spec:
```bash
quint typecheck jvt.qnt
```

Run simulation with invariant checking:
```bash
quint run --main=jvt --max-samples=10000 --invariant=allInvariants jvt.qnt
```

Run individual invariants:
```bash
quint run --main=jvt --max-samples=10000 --invariant=getAfterInsert jvt.qnt
quint run --main=jvt --max-samples=10000 --invariant=commitmentConsistency jvt.qnt
quint run --main=jvt --max-samples=10000 --invariant=versionMonotonicity jvt.qnt
```

## Invariants

| Invariant | Description |
|-----------|-------------|
| `getAfterInsert` | For all keys inserted at the latest version, `get` returns the correct value |
| `versionMonotonicity` | All node keys have version ≤ current version |
| `commitmentConsistency` | All stored commitments match recomputation from children/values |
| `noSingleChildInternal` | No internal node has exactly one child (should be collapsed) |
| `rootExistsForAllVersions` | A root key exists for every version from 1 to current |
| `allInvariants` | Conjunction of the above (excluding `noSingleChildInternal` due to split intermediates) |

## Design Notes

The simulation uses small key spaces (4 possible values for each of the first 2 bytes and the suffix byte) to make state exploration tractable. The commitment scheme uses modular arithmetic over a small prime (104729) rather than real elliptic curve operations. These simplifications preserve the structural properties being verified while keeping simulation feasible.
