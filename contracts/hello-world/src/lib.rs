use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha512};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct ProofMessage {
    pub pub_pk_b64: String,
    pub commit_b64: String,
    pub response_hex: String,
    pub message: String,
}

/// Encode Ristretto point as base64
pub fn encode_point(p: &RistrettoPoint) -> String {
    general_purpose::STANDARD.encode(p.compress().to_bytes())
}

/// Decode base64 Ristretto point
pub fn decode_point(b64: &str) -> Result<RistrettoPoint> {
    let bytes = general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| anyhow!("invalid base64 point: {}", e))?;
    let mut arr = [0u8; 32];
    if bytes.len() != 32 {
        return Err(anyhow!("point bytes not 32"));
    }
    arr.copy_from_slice(&bytes);
    let cp = curve25519_dalek::ristretto::CompressedRistretto(arr);
    cp.decompress().ok_or_else(|| anyhow!("failed to decompress point"))
}

/// Convert scalar to hex
pub fn scalar_to_hex(s: &Scalar) -> String {
    hex::encode(s.to_bytes())
}

/// Convert hex to scalar
pub fn scalar_from_hex(h: &str) -> Result<Scalar> {
    let b = hex::decode(h).map_err(|e| anyhow!("invalid hex: {}", e))?;
    if b.len() != 32 {
        return Err(anyhow!("scalar not 32 bytes"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&b);
    Ok(Scalar::from_bytes_mod_order(arr))
}

/// Compute Fiat-Shamir challenge scalar
pub fn compute_challenge_scalar(X: &RistrettoPoint, R: &RistrettoPoint, msg: &str) -> Scalar {
    let mut hasher = Sha512::new();
    Digest::update(&mut hasher, X.compress().as_bytes());
    Digest::update(&mut hasher, R.compress().as_bytes());
    Digest::update(&mut hasher, msg.as_bytes());
    let hash_bytes = hasher.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hash_bytes);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Generate a random scalar
pub fn random_scalar() -> Scalar {
    let mut rng = OsRng;
    let mut bytes = [0u8; 64];
    rng.fill_bytes(&mut bytes);
    Scalar::from_bytes_mod_order_wide(&bytes)
}

/// Create a Schnorr-style non-interactive proof
pub fn create_proof(secret: &Scalar, msg: &str) -> (String, String, String) {
    let X = secret * G;
    let r = random_scalar();
    let R = r * G;
    let c = compute_challenge_scalar(&X, &R, msg);
    let s = r + c * secret;
    (encode_point(&X), encode_point(&R), scalar_to_hex(&s))
}

/// Verify a Schnorr-style proof
pub fn verify_proof(pub_b64: &str, commit_b64: &str, response_hex: &str, msg: &str) -> Result<bool> {
    let X = decode_point(pub_b64)?;
    let R = decode_point(commit_b64)?;
    let s = scalar_from_hex(response_hex)?;
    let c = compute_challenge_scalar(&X, &R, msg);
    Ok(s * G == R + c * X)
}
