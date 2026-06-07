# si-zero-knowledge

Schnorr proofs, DLEQ proofs, range proofs, sigma protocol foundations,
and Fiat-Shamir transform in Rust.

## Features

- **Schnorr proofs** — proof of knowledge of discrete logarithm
- **DLEQ proofs** — discrete log equality across two generators
- **Range proofs** — simplified Bulletproofs-style range proofs
- **Sigma protocols** — generic commitment-challenge-response framework
- **Fiat-Shamir** — non-interactive proof transform via hashing

## Usage

```rust
use si_zero_knowledge::SchnorrProof;
use curve25519_dalek::scalar::Scalar;

let secret = Scalar::random(&mut rand::rngs::OsRng);
let (proof, public_key) = SchnorrProof::prove(&secret);
assert!(proof.verify(&public_key));
```

## License

MIT OR Apache-2.0
