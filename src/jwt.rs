//! JWT helpers.
//!
//! [`hash_token`] is functional; [`sign`] and [`verify`] are placeholders until
//! Ed25519 and HS256 implementations land.

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

const HEX: &[u8; 16] = b"0123456789abcdef";

/// SHA-256 hash of a token, hex-encoded. Useful for storing refresh tokens
/// by hash (one-way lookup with zero plaintext retention at rest).
#[must_use]
pub fn hash_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    let mut s = String::with_capacity(digest.len() * 2);
    for &b in &digest {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Sign a JWT. **Not yet implemented.**
///
/// # Errors
/// Always returns [`Error::Crypto`] until the real implementation lands.
pub fn sign(_header_json: &str, _claims_json: &str, _key: &[u8]) -> Result<String> {
    Err(Error::Crypto("jwt::sign not yet implemented"))
}

/// Verify a JWT. **Not yet implemented.**
///
/// # Errors
/// Always returns [`Error::Crypto`] until the real implementation lands.
pub fn verify(_token: &str, _key: &[u8]) -> Result<String> {
    Err(Error::Crypto("jwt::verify not yet implemented"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_token_is_64_hex() {
        let h = hash_token("something");
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hash_token_deterministic() {
        assert_eq!(hash_token("same"), hash_token("same"));
    }

    #[test]
    fn hash_token_differs_for_different_inputs() {
        assert_ne!(hash_token("a"), hash_token("b"));
    }
}
