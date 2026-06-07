//! # si-zero-knowledge
//!
//! Zero-knowledge proof primitives including Schnorr proofs, discrete log
//! equality proofs (DLEQ), simplified range proofs, sigma protocol
//! foundations, and the Fiat-Shamir transform.
//!
//! ## Modules
//!
//! - [`schnorr`] — Schnorr proof of knowledge of discrete log
//! - [`dleq`] — Discrete log equality proofs
//! - [`range`] — Simplified range proofs (Bulletproofs-style)
//! - [`sigma`] — Sigma protocol foundations
//! - [`fiat_shamir`] — Fiat-Shamir heuristic for non-interactive proofs

pub mod schnorr;
pub mod dleq;
pub mod range;
pub mod sigma;
pub mod fiat_shamir;

pub use schnorr::SchnorrProof;
pub use dleq::DLEQProof;
pub use range::RangeProof;
pub use sigma::SigmaProtocol;
pub use fiat_shamir::FiatShamirHash;
