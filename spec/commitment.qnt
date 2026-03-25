// commitment.qnt — Abstract vector commitment model for JVT
//
// Models the Pedersen vector commitment scheme abstractly, without real
// elliptic curve arithmetic. Commitments are opaque integers satisfying
// the homomorphic property:
//
//   commitUpdate(commit(vs), i, vs[i], v') == commit(vs.set(i, v'))
//
// Also models commitment_to_field (EC point → field element) as a
// bijective map, enabling abstract proof chain verification.

module commitment {
    // A commitment is modeled as an opaque integer.
    type Commitment = int

    // The prime modulus for our mock field.
    pure val MODULUS: int = 104729

    // Basis "points": basis(i) = (i + 1) * 137 mod MODULUS
    // Gives 256 distinct nonzero values since gcd(137, MODULUS) = 1.
    pure def basis(i: int): int = ((i + 1) * 137) % MODULUS

    // Vector commitment: C = Σ values[i] * basis(i) mod MODULUS
    pure def commit(values: int -> int): Commitment = {
        values.keys().fold(0, (acc, i) => (acc + values.get(i) * basis(i)) % MODULUS)
    }

    // Homomorphic update: C_new = C_old + (new_value - old_value) * basis(index)
    // Uses double-mod to handle negative deltas safely.
    pure def commitUpdate(oldC: Commitment, index: int, oldVal: int, newVal: int): Commitment = {
        ((oldC + (newVal - oldVal) * basis(index)) % MODULUS + MODULUS) % MODULUS
    }

    pure val ZERO_COMMITMENT: Commitment = 0

    pure def valueToField(v: int): int = v % MODULUS

    // Maps a commitment to a field element, modeling commitment_to_field
    // in the Rust implementation (EC affine point → x-coordinate).
    // Uses a bijection mod MODULUS: c ↦ (c * 31337 + 42) mod p.
    // Bijective since gcd(31337, 104729) = 1.
    pure def commitmentToField(c: Commitment): int = (c * 31337 + 42) % MODULUS
}
