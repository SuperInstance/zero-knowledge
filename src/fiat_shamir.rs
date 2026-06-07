//! Fiat-Shamir transform for non-interactive proofs.
//!
//! Convert interactive sigma protocols into non-interactive proofs
//! by deriving the challenge from a hash of the transcript.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use sha2::{Sha256, Digest};

/// Fiat-Shamir hash utility for generating challenges from transcripts.
#[derive(Debug, Clone)]
pub struct FiatShamirHash {
    /// Domain separator / context string.
    pub context: String,
}

impl FiatShamirHash {
    /// Create a new Fiat-Shamir hasher with a domain separator.
    pub fn new(context: &str) -> Self {
        Self { context: context.to_string() }
    }

    /// Hash a single point into a scalar challenge.
    pub fn hash_point(&self, point: &RistrettoPoint) -> Scalar {
        let mut hasher = Sha256::new();
        hasher.update(self.context.as_bytes());
        hasher.update(point.compress().as_bytes());
        let hash = hasher.finalize();
        Scalar::from_bytes_mod_order(hash.into())
    }

    /// Hash two points into a scalar challenge.
    pub fn hash_points(&self, p1: &RistrettoPoint, p2: &RistrettoPoint) -> Scalar {
        let mut hasher = Sha256::new();
        hasher.update(self.context.as_bytes());
        hasher.update(p1.compress().as_bytes());
        hasher.update(p2.compress().as_bytes());
        let hash = hasher.finalize();
        Scalar::from_bytes_mod_order(hash.into())
    }

    /// Hash multiple points into a scalar challenge.
    pub fn hash_many(&self, points: &[RistrettoPoint]) -> Scalar {
        let mut hasher = Sha256::new();
        hasher.update(self.context.as_bytes());
        for p in points {
            hasher.update(p.compress().as_bytes());
        }
        let hash = hasher.finalize();
        Scalar::from_bytes_mod_order(hash.into())
    }

    /// Hash arbitrary bytes with the context.
    pub fn hash_bytes(&self, data: &[u8]) -> Scalar {
        let mut hasher = Sha256::new();
        hasher.update(self.context.as_bytes());
        hasher.update(data);
        let hash = hasher.finalize();
        Scalar::from_bytes_mod_order(hash.into())
    }
}

impl Default for FiatShamirHash {
    fn default() -> Self {
        Self::new("fiat-shamir-default")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::scalar::Scalar;
    use rand::rngs::OsRng;

    #[test]
    fn hash_point_deterministic() {
        let fs = FiatShamirHash::new("test");
        let p = Scalar::random(&mut OsRng) * RISTRETTO_BASEPOINT_POINT;
        let c1 = fs.hash_point(&p);
        let c2 = fs.hash_point(&p);
        assert_eq!(c1, c2);
    }

    #[test]
    fn hash_point_different_contexts() {
        let fs1 = FiatShamirHash::new("context-a");
        let fs2 = FiatShamirHash::new("context-b");
        let p = Scalar::random(&mut OsRng) * RISTRETTO_BASEPOINT_POINT;
        assert_ne!(fs1.hash_point(&p), fs2.hash_point(&p));
    }

    #[test]
    fn hash_points_consistent() {
        let fs = FiatShamirHash::new("test");
        let p1 = Scalar::random(&mut OsRng) * RISTRETTO_BASEPOINT_POINT;
        let p2 = Scalar::random(&mut OsRng) * RISTRETTO_BASEPOINT_POINT;
        let c = fs.hash_points(&p1, &p2);
        let c2 = fs.hash_many(&[p1, p2]);
        assert_eq!(c, c2);
    }

    #[test]
    fn hash_bytes_deterministic() {
        let fs = FiatShamirHash::new("test");
        let c1 = fs.hash_bytes(b"hello world");
        let c2 = fs.hash_bytes(b"hello world");
        assert_eq!(c1, c2);
    }

    #[test]
    fn default_context_works() {
        let fs = FiatShamirHash::default();
        let p = RISTRETTO_BASEPOINT_POINT;
        let c = fs.hash_point(&p);
        assert_ne!(c, Scalar::from(0u64));
    }
}
