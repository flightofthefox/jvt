//! Fiat-Shamir transcript for non-interactive proofs.
//!
//! Matches the transcript protocol from crate-crypto/rust-verkle and go-ipa.
//! Uses SHA-256 with append-then-hash-then-clear pattern.

use ark_ed_on_bls12_381_bandersnatch::{EdwardsAffine, Fr};
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use sha2::{Digest, Sha256};

pub struct Transcript {
    state: Vec<u8>,
}

impl Transcript {
    pub fn new(label: &[u8]) -> Self {
        let mut state = Vec::new();
        state.extend_from_slice(label);
        Self { state }
    }

    pub fn domain_sep(&mut self, label: &[u8]) {
        self.state.extend_from_slice(label);
    }

    pub fn append_point(&mut self, label: &[u8], point: &EdwardsAffine) {
        self.state.extend_from_slice(label);
        let mut bytes = [0u8; 32];
        point.serialize_compressed(&mut bytes[..]).unwrap();
        self.state.extend_from_slice(&bytes);
    }

    pub fn append_scalar(&mut self, label: &[u8], scalar: &Fr) {
        self.state.extend_from_slice(label);
        let mut bytes = [0u8; 32];
        scalar.serialize_compressed(&mut bytes[..]).unwrap();
        self.state.extend_from_slice(&bytes);
    }

    /// Generate a challenge scalar by hashing the current state,
    /// then clearing and re-seeding with the challenge.
    pub fn challenge_scalar(&mut self, label: &[u8]) -> Fr {
        self.domain_sep(label);

        let mut hasher = Sha256::new();
        hasher.update(&self.state);
        let hash = hasher.finalize();

        self.state.clear();

        let scalar = Fr::from_le_bytes_mod_order(&hash);
        self.append_scalar(label, &scalar);

        scalar
    }
}
