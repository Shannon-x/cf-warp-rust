//! X25519 key generation for WireGuard.

use x25519_dalek::{PublicKey, StaticSecret};

/// Generate a new X25519 keypair for WireGuard.
///
/// Returns `(private_key, public_key)` as 32-byte arrays.
pub fn generate_keypair() -> ([u8; 32], [u8; 32]) {
    let private = StaticSecret::random_from_rng(rand_core::OsRng);
    let public = PublicKey::from(&private);
    (private.to_bytes(), public.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let (private, public) = generate_keypair();

        // Keys should be 32 bytes
        assert_eq!(private.len(), 32);
        assert_eq!(public.len(), 32);

        // Keys should not be all zeros
        assert!(private.iter().any(|&b| b != 0));
        assert!(public.iter().any(|&b| b != 0));

        // Private and public should be different
        assert_ne!(private, public);
    }

    #[test]
    fn test_keypair_deterministic_public() {
        let (private, public) = generate_keypair();

        // Verify that the same private key produces the same public key
        let secret = StaticSecret::from(private);
        let derived_public = PublicKey::from(&secret);
        assert_eq!(public, derived_public.to_bytes());
    }
}
