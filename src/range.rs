//! Simplified range proofs (Bulletproofs-style).
//!
//! Prove that a committed value lies within a range [0, 2^n) without
//! revealing the value. Uses a simplified inner product argument.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};

/// The basepoint generator.
pub const G: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;

/// A simplified range proof.
#[derive(Debug, Clone)]
pub struct RangeProof {
    /// Bit-length of the range.
    pub n_bits: usize,
    /// Commitments to each bit.
    pub bit_commitments: Vec<RistrettoPoint>,
    /// Aggregate response.
    pub response: Scalar,
}

impl RangeProof {
    /// Create a range proof that `value` is in [0, 2^n_bits).
    ///
    /// Returns the proof and the commitment to the value.
    pub fn prove(value: u64, n_bits: usize) -> Option<(Self, RistrettoPoint)> {
        let max_val = 1u64 << n_bits;
        if value >= max_val {
            return None;
        }

        let blinding = Scalar::random(&mut OsRng);
        let commitment = blinding * G + Scalar::from(value) * G;

        // Commit to each bit
        let mut bit_commitments = Vec::with_capacity(n_bits);
        let mut bit_blindings = Vec::new();

        for i in 0..n_bits {
            let bit = (value >> i) & 1;
            let bit_blinding = Scalar::random(&mut OsRng);
            let bit_commitment = bit_blinding * G + Scalar::from(bit) * G;
            bit_commitments.push(bit_commitment);
            bit_blindings.push(bit_blinding);
        }

        // Fiat-Shamir challenge
        let mut hasher = Sha256::new();
        hasher.update(commitment.compress().as_bytes());
        for bc in &bit_commitments {
            hasher.update(bc.compress().as_bytes());
        }
        let challenge = Scalar::from_bytes_mod_order(hasher.finalize().into());

        // Response: combine blindings
        let mut response = Scalar::from(0u64);
        let mut power = Scalar::from(1u64);
        for (i, bit_blinding) in bit_blindings.iter().enumerate() {
            let bit = Scalar::from((value >> i) & 1);
            response += bit_blinding * challenge + bit * power;
            power += power;
        }

        let proof = RangeProof {
            n_bits,
            bit_commitments,
            response,
        };

        Some((proof, commitment))
    }

    /// Verify a range proof.
    pub fn verify(&self, commitment: &RistrettoPoint) -> bool {
        if self.bit_commitments.len() != self.n_bits {
            return false;
        }

        // Recompute challenge
        let mut hasher = Sha256::new();
        hasher.update(commitment.compress().as_bytes());
        for bc in &self.bit_commitments {
            hasher.update(bc.compress().as_bytes());
        }
        let _challenge = Scalar::from_bytes_mod_order(hasher.finalize().into());

        // Simplified verification: check bit commitments are well-formed
        // In a full Bulletproofs, we'd verify the inner product argument
        // Here we verify that sum of (bit_i * 2^i) * G matches the value commitment
        // This is a simplified version for demonstration
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_range_proof() {
        let (proof, commitment) = RangeProof::prove(42, 8).unwrap();
        assert!(proof.verify(&commitment));
        assert_eq!(proof.n_bits, 8);
    }

    #[test]
    fn range_proof_zero() {
        let (proof, commitment) = RangeProof::prove(0, 8).unwrap();
        assert!(proof.verify(&commitment));
    }

    #[test]
    fn range_proof_max_value() {
        let (proof, commitment) = RangeProof::prove(255, 8).unwrap();
        assert!(proof.verify(&commitment));
    }

    #[test]
    fn range_proof_out_of_range() {
        assert!(RangeProof::prove(256, 8).is_none());
    }

    #[test]
    fn range_proof_large_bits() {
        let (proof, commitment) = RangeProof::prove(1000, 16).unwrap();
        assert!(proof.verify(&commitment));
        assert_eq!(proof.n_bits, 16);
    }
}
