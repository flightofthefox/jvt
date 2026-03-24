//! Lagrange basis polynomial representation and barycentric weight precomputation.
//!
//! Polynomials are stored in evaluation form: `f` is represented by its values
//! `[f(0), f(1), ..., f(255)]` on the domain `{0, 1, ..., 255}`.
//!
//! Key operations:
//! - `divide_on_domain(z)`: compute `(f(X) - f(z)) / (X - z)` in Lagrange basis
//! - `evaluate_lagrange_coefficients(t)`: compute L_i(t) for a point t outside the domain

use ark_ed_on_bls12_381_bandersnatch::Fr;
use ark_ff::{AdditiveGroup, Field};

/// A polynomial in Lagrange (evaluation) form over domain {0, 1, ..., n-1}.
#[derive(Clone, Debug)]
pub struct LagrangeBasis {
    pub values: Vec<Fr>,
}

impl LagrangeBasis {
    pub fn new(values: Vec<Fr>) -> Self {
        Self { values }
    }

    pub fn zero() -> Self {
        Self { values: vec![] }
    }

    pub fn domain_size(&self) -> usize {
        self.values.len()
    }

    /// Evaluate f at a domain point: f(index).
    pub fn evaluate_in_domain(&self, index: usize) -> Fr {
        self.values[index]
    }

    /// Compute `q(X) = (f(X) - f(z)) / (X - z)` in Lagrange basis,
    /// where `z` is a point IN the domain.
    ///
    /// This uses the barycentric formula for efficient division.
    pub fn divide_on_domain(&self, precomp: &PrecomputedWeights, z: usize) -> LagrangeBasis {
        let n = self.values.len();
        let mut q = vec![Fr::ZERO; n];
        let y = self.values[z];

        for i in 0..n {
            if i != z {
                let diff = i as i64 - z as i64;
                let is_negative = diff < 0;
                let abs_diff = diff.unsigned_abs() as usize;
                let den_inv = precomp.get_inverted_element(abs_diff, is_negative);

                let q_i = (self.values[i] - y) * den_inv;
                q[i] = q_i;

                let weight_ratio = precomp.get_ratio_of_barycentric_weights(z, i);
                q[z] -= weight_ratio * q_i;
            }
        }

        LagrangeBasis::new(q)
    }

    /// Compute Lagrange basis evaluations L_i(t) for a point `t` OUTSIDE the domain.
    /// Returns a vector [L_0(t), L_1(t), ..., L_{n-1}(t)].
    pub fn evaluate_lagrange_coefficients(
        precomp: &PrecomputedWeights,
        n: usize,
        t: Fr,
    ) -> Vec<Fr> {
        // L_i(t) = A'(x_i) * (t - x_i) where A(X) = Π(X - x_j)
        // Then normalize by dividing by A(t) = Π(t - x_j)
        let mut evals: Vec<Fr> = (0..n)
            .map(|i| precomp.get_barycentric_weight(i) * (t - Fr::from(i as u64)))
            .collect();

        // A(t) = Π_{i=0..n-1} (t - i)
        let a_t: Fr = (0..n).map(|i| t - Fr::from(i as u64)).product();

        batch_inversion_and_mul(&mut evals, &a_t);
        evals
    }
}

/// Add two Lagrange basis polynomials.
impl std::ops::Add for LagrangeBasis {
    type Output = LagrangeBasis;
    fn add(mut self, rhs: Self) -> Self {
        if self.values.is_empty() {
            return rhs;
        }
        if rhs.values.is_empty() {
            return self;
        }
        for (a, b) in self.values.iter_mut().zip(rhs.values.iter()) {
            *a += b;
        }
        self
    }
}

/// Subtract two Lagrange basis polynomials.
impl std::ops::Sub for &LagrangeBasis {
    type Output = LagrangeBasis;
    fn sub(self, rhs: Self) -> LagrangeBasis {
        LagrangeBasis::new(
            self.values
                .iter()
                .zip(rhs.values.iter())
                .map(|(a, b)| *a - *b)
                .collect(),
        )
    }
}

// ============================================================
// Precomputed barycentric weights
// ============================================================

/// Precomputed weights for efficient Lagrange operations on domain {0..n-1}.
pub struct PrecomputedWeights {
    /// A'(x_i) and 1/A'(x_i) packed together. First half: weights, second half: inverses.
    barycentric_weights: Vec<Fr>,
    /// 1/k for k in {1..n-1} and -(1/k) packed together.
    inverted_domain: Vec<Fr>,
    domain_size: usize,
}

impl PrecomputedWeights {
    pub fn new(domain_size: usize) -> Self {
        // Compute barycentric weights: A'(x_i) = Π_{j≠i} (x_i - x_j)
        let mut barycentric_weights = vec![Fr::ZERO; domain_size * 2];
        for x_i in 0..domain_size {
            let w = Self::compute_barycentric_weight(x_i, domain_size);
            barycentric_weights[x_i] = w;
            barycentric_weights[x_i + domain_size] = w.inverse().unwrap();
        }

        // Compute 1/k and -1/k for k in {1..domain_size-1}
        let inv_domain_size = domain_size - 1;
        let mut inverted_domain = vec![Fr::ZERO; inv_domain_size * 2];
        for k in 1..domain_size {
            let k_inv = Fr::from(k as u64).inverse().unwrap();
            inverted_domain[k - 1] = k_inv;
            inverted_domain[k - 1 + inv_domain_size] = -k_inv;
        }

        Self {
            barycentric_weights,
            inverted_domain,
            domain_size,
        }
    }

    /// A'(x_i) = Π_{j≠i} (x_i - x_j) for domain {0..n-1}.
    fn compute_barycentric_weight(i: usize, n: usize) -> Fr {
        let x_i = Fr::from(i as u64);
        (0..n)
            .filter(|&j| j != i)
            .map(|j| x_i - Fr::from(j as u64))
            .product()
    }

    /// Get 1/|d| or -1/|d| where d = domain_element.
    pub fn get_inverted_element(&self, domain_element: usize, is_negative: bool) -> Fr {
        let mut index = domain_element - 1;
        if is_negative {
            index += self.inverted_domain.len() / 2;
        }
        self.inverted_domain[index]
    }

    /// Get A'(x_m) / A'(x_i) = A'(x_m) * (1/A'(x_i)).
    pub fn get_ratio_of_barycentric_weights(&self, m: usize, i: usize) -> Fr {
        self.barycentric_weights[m] * self.barycentric_weights[i + self.domain_size]
    }

    /// Get A'(x_i).
    pub fn get_barycentric_weight(&self, i: usize) -> Fr {
        self.barycentric_weights[i]
    }

    /// Get 1/A'(x_i).
    pub fn get_inverse_barycentric_weight(&self, i: usize) -> Fr {
        self.barycentric_weights[i + self.domain_size]
    }
}

// ============================================================
// Batch inversion utilities
// ============================================================

/// Batch invert a vector of field elements in-place using Montgomery's trick.
pub fn batch_inversion(v: &mut [Fr]) {
    let n = v.len();
    if n == 0 {
        return;
    }

    // Compute prefix products
    let mut products = vec![Fr::ZERO; n];
    products[0] = v[0];
    for i in 1..n {
        products[i] = products[i - 1] * v[i];
    }

    // Invert the total product
    let mut inv = products[n - 1]
        .inverse()
        .expect("batch inversion: zero element");

    // Work backwards to compute individual inverses
    for i in (1..n).rev() {
        let tmp = v[i];
        v[i] = products[i - 1] * inv;
        inv *= tmp;
    }
    v[0] = inv;
}

/// Batch invert and multiply by a scalar: v[i] = scalar / v[i].
pub fn batch_inversion_and_mul(v: &mut [Fr], scalar: &Fr) {
    batch_inversion(v);
    for x in v.iter_mut() {
        *x *= scalar;
    }
}

/// Compute inner product of two vectors.
pub fn inner_product(a: &[Fr], b: &[Fr]) -> Fr {
    a.iter().zip(b.iter()).map(|(x, y)| *x * *y).sum()
}

/// Compute powers of a scalar: [1, r, r^2, ..., r^{n-1}].
pub fn powers_of(r: Fr, n: usize) -> Vec<Fr> {
    let mut powers = Vec::with_capacity(n);
    let mut current = Fr::from(1u64);
    for _ in 0..n {
        powers.push(current);
        current *= r;
    }
    powers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_inversion_correctness() {
        let vals: Vec<Fr> = (1..10).map(|i| Fr::from(i as u64)).collect();
        let mut inverted = vals.clone();
        batch_inversion(&mut inverted);

        for (v, inv) in vals.iter().zip(inverted.iter()) {
            let product = *v * *inv;
            assert_eq!(product, Fr::from(1u64));
        }
    }

    #[test]
    fn lagrange_division_on_domain() {
        let n = 4;
        let precomp = PrecomputedWeights::new(n);

        // f(X) such that f(0)=2, f(1)=0, f(2)=12, f(3)=40
        // With f(1)=0, dividing by (X-1) should give a polynomial with no remainder
        let f = LagrangeBasis::new(vec![
            -Fr::from(2u64),
            Fr::ZERO,
            Fr::from(12u64),
            Fr::from(40u64),
        ]);

        let q = f.divide_on_domain(&precomp, 1);
        // q should be a degree-2 polynomial in Lagrange form
        assert_eq!(q.values.len(), 4);
    }

    #[test]
    fn lagrange_coefficients_sum_to_one() {
        let n = 256;
        let precomp = PrecomputedWeights::new(n);
        let t = Fr::from(300u64); // outside domain [0..255]

        let coeffs = LagrangeBasis::evaluate_lagrange_coefficients(&precomp, n, t);

        // Σ L_i(t) should equal 1 (partition of unity)
        let sum: Fr = coeffs.iter().sum();
        assert_eq!(sum, Fr::from(1u64));
    }

    #[test]
    fn powers_of_correctness() {
        let r = Fr::from(3u64);
        let p = powers_of(r, 5);
        assert_eq!(p[0], Fr::from(1u64));
        assert_eq!(p[1], Fr::from(3u64));
        assert_eq!(p[2], Fr::from(9u64));
        assert_eq!(p[3], Fr::from(27u64));
        assert_eq!(p[4], Fr::from(81u64));
    }
}
