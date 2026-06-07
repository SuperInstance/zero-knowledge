//! Sigma protocol foundations.
//!
//! Generic sigma protocol structure: commitment, challenge, response (Σ).
//! Provides the abstract framework that Schnorr, DLEQ, and other proofs build on.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

/// A generic sigma protocol transcript.
#[derive(Debug, Clone)]
pub struct SigmaProtocol {
    /// The prover's commitment phase message.
    pub commitment: RistrettoPoint,
    /// The verifier's challenge.
    pub challenge: Scalar,
    /// The prover's response.
    pub response: Scalar,
}

impl SigmaProtocol {
    /// Create a new sigma protocol transcript.
    pub fn new(commitment: RistrettoPoint, challenge: Scalar, response: Scalar) -> Self {
        Self { commitment, challenge, response }
    }

    /// Verify the sigma protocol using a verification function.
    ///
    /// The verifier_fn should return true if the transcript is valid.
    pub fn verify<F>(&self, verifier_fn: F) -> bool
    where
        F: Fn(&RistrettoPoint, &Scalar, &Scalar) -> bool,
    {
        verifier_fn(&self.commitment, &self.challenge, &self.response)
    }

    /// Check that the commitment is not the identity point.
    pub fn commitment_nonzero(&self) -> bool {
        self.commitment != RistrettoPoint::identity()
    }

    /// Create a simulated proof (for testing honest-verifier zero-knowledge).
    pub fn simulate(challenge: Scalar, response: Scalar, basepoint: &RistrettoPoint) -> Self {
        // R = s*G - c*P where P is implied — for simulation we just compute s*G
        let commitment = response * basepoint - challenge * basepoint;
        Self { commitment, challenge, response }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use rand::rngs::OsRng;

    #[test]
    fn sigma_commitment_nonzero() {
        let k = Scalar::random(&mut OsRng);
        let commitment = k * RISTRETTO_BASEPOINT_POINT;
        let challenge = Scalar::random(&mut OsRng);
        let response = k + challenge * Scalar::random(&mut OsRng);
        let sigma = SigmaProtocol::new(commitment, challenge, response);
        assert!(sigma.commitment_nonzero());
    }

    #[test]
    fn sigma_verify_with_function() {
        let k = Scalar::random(&mut OsRng);
        let x = Scalar::random(&mut OsRng);
        let g = RISTRETTO_BASEPOINT_POINT;
        let commitment = k * g;
        let challenge = Scalar::random(&mut OsRng);
        let response = k + challenge * x;
        let sigma = SigmaProtocol::new(commitment, challenge, response);

        let pk = x * g;
        let result = sigma.verify(|r, c, s| {
            s * g == r + c * pk
        });
        assert!(result);
    }

    #[test]
    fn sigma_simulated_proof() {
        let challenge = Scalar::random(&mut OsRng);
        let response = Scalar::random(&mut OsRng);
        let sigma = SigmaProtocol::simulate(challenge, response, &RISTRETTO_BASEPOINT_POINT);
        assert!(sigma.commitment_nonzero());
    }

    #[test]
    fn sigma_identity_commitment_detected() {
        let sigma = SigmaProtocol::new(
            RistrettoPoint::identity(),
            Scalar::from(0u64),
            Scalar::from(0u64),
        );
        assert!(!sigma.commitment_nonzero());
    }
}
