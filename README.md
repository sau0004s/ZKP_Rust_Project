# ZKP-Toy-RS

[![Rust](https://img.shields.io/badge/Rust-1.72.0-blue?logo=rust)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Zero-Knowledge Proof Demo in Rust**  

A lightweight Rust library demonstrating **Schnorr-style non-interactive zero-knowledge proofs (ZKP)**.  
It allows proving knowledge of a secret scalar without revealing it, simulating a simple blockchain “seller network”.

---

## 🔹 Features

- Schnorr-style **zero-knowledge proofs** on the Ristretto255 curve.
- Non-interactive proofs using the **Fiat-Shamir heuristic**.
- Modular design:
  - `lib.rs` =  core cryptographic logic.
  - `test.rs` = prover-verifier demo.
- Cryptographically secure random number generation with `OsRng`.
- Base64 encoding/decoding and JSON serialization (`serde`, `base64`).
- Deterministic proof verification.
- Easily extendable for blockchain and cryptography projects.

---

##  Tech Stack

- **Language:** Rust (Edition 2021)  
- **Crypto Libraries:** `curve25519-dalek`, `sha2`  
- **Serialization:** `serde`, `base64`  
- **Randomness:** `rand` (cryptographically secure RNG)  
- **Build:** Cargo  

---

## ⚡ Installation

Clone the repository:

```bash
git clone https://github.com/sau0004s/ZKP_Rust_Project.git
cd ZKP_Rust_Project
