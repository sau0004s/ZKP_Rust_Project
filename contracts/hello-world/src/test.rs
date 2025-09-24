use zkp_toy_rs::{create_proof, verify_proof, random_scalar, scalar_to_hex};

fn main() {
    println!("--- Zero-Knowledge Proof Toy Demo ---");

    // Prover generates a secret
    let secret = random_scalar();

    let message = "Hello from seller network";

    let (pub_b64, commit_b64, response_hex) = create_proof(&secret, message);

    println!("Secret scalar (hex): {}", scalar_to_hex(&secret));
    println!("Public key (base64): {}", pub_b64);
    println!("Commitment (base64): {}", commit_b64);
    println!("Response s (hex): {}", response_hex);
    println!("Message: {}", message);

    // Verifier checks the proof
    match verify_proof(&pub_b64, &commit_b64, &response_hex, message) {
        Ok(true) => println!("Proof verified: ACCEPTED "),
        Ok(false) => println!("Proof verified: REJECTED "),
        Err(e) => println!("Error verifying proof: {}", e),
    }
}
