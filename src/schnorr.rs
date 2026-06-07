//! Schnorr proof of knowledge of a discrete logarithm.
//!
//! Prove knowledge of `x` such that `P = x * G` without revealing `x`,
//! using the Schnorr identification protocol with Fiat-Shamir.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};

/// The basepoint generator G.
pub const G: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;

/// A Schnorr proof of knowledge.
#[derive(Debug, Clone)]
pub struct SchnorrProof {
    /// The commitment: R = k * G.
    pub commitment: RistrettoPoint,
    /// The response: s = k + c * x.
    pub response: Scalar,
}

impl SchnorrProof {
    /// Create a Schnorr proof for secret key `x` with public key `P = x * G`.
    pub fn prove(x: &Scalar) -> (Self, RistrettoPoint) {
        let public_key = x * G;
        let proof = Self::prove_with_public(x, &public_key);
        (proof, public_key)
    }

    /// Create a Schnorr proof given both the secret and public key.
    pub fn prove_with_public(x: &Scalar, public_key: &RistrettoPoint) -> Self {
        // 1. Choose random nonce k
        let k = Scalar::random(&mut OsRng);
        // 2. Compute commitment R = k * G
        let commitment = k * G;
        // 3. Fiat-Shamir challenge: c = H(G || P || R)
        let challenge = Self::compute_challenge(public_key, &commitment);
        // 4. Response: s = k + c * x
        let response = k + challenge * x;

        SchnorrProof { commitment, response }
    }

    /// Verify a Schnorr proof against a public key.
    pub fn verify(&self, public_key: &RistrettoPoint) -> bool {
        // Recompute challenge
        let challenge = Self::compute_challenge(public_key, &self.commitment);
        // Check: s * G == R + c * P
        let lhs = self.response * G;
        let rhs = self.commitment + challenge * public_key;
        lhs == rhs
    }

    /// Compute the Fiat-Shamir challenge.
    fn compute_challenge(public_key: &RistrettoPoint, commitment: &RistrettoPoint) -> Scalar {
        let mut hasher = Sha256::new();
        hasher.update(G.compress().as_bytes());
        hasher.update(public_key.compress().as_bytes());
        hasher.update(commitment.compress().as_bytes());
        let hash = hasher.finalize();
        Scalar::from_bytes_mod_order(hash.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_proof_verifies() {
        let x = Scalar::random(&mut OsRng);
        let (proof, public_key) = SchnorrProof::prove(&x);
        assert!(proof.verify(&public_key));
    }

    #[test]
    fn wrong_public_key_fails() {
        let x = Scalar::random(&mut OsRng);
        let (proof, _) = SchnorrProof::prove(&x);
        let wrong_pk = Scalar::random(&mut OsRng) * G;
        assert!(!proof.verify(&wrong_pk));
    }

    #[test]
    fn tampered_response_fails() {
        let x = Scalar::random(&mut OsRng);
        let (mut proof, public_key) = SchnorrProof::prove(&x);
        proof.response = proof.response + Scalar::from(1u64);
        assert!(!proof.verify(&public_key));
    }

    #[test]
    fn multiple_proofs_same_key() {
        let x = Scalar::random(&mut OsRng);
        let pk = x * G;
        for _ in 0..5 {
            let proof = SchnorrProof::prove_with_public(&x, &pk);
            assert!(proof.verify(&pk));
        }
    }
}
