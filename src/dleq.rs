//! Discrete Log Equality (DLEQ) proofs.
//!
//! Prove that two commitments share the same discrete log without
//! revealing the secret: given `P1 = x * G1` and `P2 = x * G2`,
//! prove knowledge of `x` such that both hold.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};

/// A DLEQ proof.
#[derive(Debug, Clone)]
pub struct DLEQProof {
    /// Commitment to first generator: R1 = k * G1.
    pub r1: RistrettoPoint,
    /// Commitment to second generator: R2 = k * G2.
    pub r2: RistrettoPoint,
    /// Response scalar.
    pub s: Scalar,
}

impl DLEQProof {
    /// Create a DLEQ proof for the same secret `x` with two generators.
    pub fn prove(
        x: &Scalar,
        g1: &RistrettoPoint,
        g2: &RistrettoPoint,
    ) -> (Self, RistrettoPoint, RistrettoPoint) {
        let p1 = x * g1;
        let p2 = x * g2;
        let proof = Self::prove_with_publics(x, g1, g2, &p1, &p2);
        (proof, p1, p2)
    }

    /// Create a DLEQ proof given all components.
    pub fn prove_with_publics(
        x: &Scalar,
        g1: &RistrettoPoint,
        g2: &RistrettoPoint,
        p1: &RistrettoPoint,
        p2: &RistrettoPoint,
    ) -> Self {
        let k = Scalar::random(&mut OsRng);
        let r1 = k * g1;
        let r2 = k * g2;

        let challenge = Self::compute_challenge(g1, g2, p1, p2, &r1, &r2);
        let s = k + challenge * x;

        DLEQProof { r1, r2, s }
    }

    /// Verify a DLEQ proof.
    pub fn verify(
        &self,
        g1: &RistrettoPoint,
        g2: &RistrettoPoint,
        p1: &RistrettoPoint,
        p2: &RistrettoPoint,
    ) -> bool {
        let challenge = Self::compute_challenge(g1, g2, p1, p2, &self.r1, &self.r2);

        // Check: s * G1 == R1 + c * P1
        let lhs1 = self.s * g1;
        let rhs1 = self.r1 + challenge * p1;
        if lhs1 != rhs1 {
            return false;
        }

        // Check: s * G2 == R2 + c * P2
        let lhs2 = self.s * g2;
        let rhs2 = self.r2 + challenge * p2;
        lhs2 == rhs2
    }

    /// Compute the Fiat-Shamir challenge for DLEQ.
    fn compute_challenge(
        g1: &RistrettoPoint,
        g2: &RistrettoPoint,
        p1: &RistrettoPoint,
        p2: &RistrettoPoint,
        r1: &RistrettoPoint,
        r2: &RistrettoPoint,
    ) -> Scalar {
        let mut hasher = Sha256::new();
        hasher.update(g1.compress().as_bytes());
        hasher.update(g2.compress().as_bytes());
        hasher.update(p1.compress().as_bytes());
        hasher.update(p2.compress().as_bytes());
        hasher.update(r1.compress().as_bytes());
        hasher.update(r2.compress().as_bytes());
        let hash = hasher.finalize();
        Scalar::from_bytes_mod_order(hash.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn second_generator() -> RistrettoPoint {
        let hash = Sha256::digest(RISTRETTO_BASEPOINT_POINT.compress().as_bytes());
        let scalar = Scalar::from_bytes_mod_order(hash.into());
        scalar * RISTRETTO_BASEPOINT_POINT
    }

    #[test]
    fn valid_dleq_verifies() {
        let x = Scalar::random(&mut OsRng);
        let g1 = RISTRETTO_BASEPOINT_POINT;
        let g2 = second_generator();
        let (proof, p1, p2) = DLEQProof::prove(&x, &g1, &g2);
        assert!(proof.verify(&g1, &g2, &p1, &p2));
    }

    #[test]
    fn dleq_wrong_p1_fails() {
        let x = Scalar::random(&mut OsRng);
        let g1 = RISTRETTO_BASEPOINT_POINT;
        let g2 = second_generator();
        let (proof, _, p2) = DLEQProof::prove(&x, &g1, &g2);
        let wrong_p1 = Scalar::random(&mut OsRng) * g1;
        assert!(!proof.verify(&g1, &g2, &wrong_p1, &p2));
    }

    #[test]
    fn dleq_wrong_p2_fails() {
        let x = Scalar::random(&mut OsRng);
        let g1 = RISTRETTO_BASEPOINT_POINT;
        let g2 = second_generator();
        let (proof, p1, _) = DLEQProof::prove(&x, &g1, &g2);
        let wrong_p2 = Scalar::random(&mut OsRng) * g2;
        assert!(!proof.verify(&g1, &g2, &p1, &wrong_p2));
    }

    #[test]
    fn dleq_tampered_response_fails() {
        let x = Scalar::random(&mut OsRng);
        let g1 = RISTRETTO_BASEPOINT_POINT;
        let g2 = second_generator();
        let (mut proof, p1, p2) = DLEQProof::prove(&x, &g1, &g2);
        proof.s = proof.s + Scalar::from(1u64);
        assert!(!proof.verify(&g1, &g2, &p1, &p2));
    }
}
