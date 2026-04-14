//! OAuth 2.0 PKCE (RFC 7636) S256 challenge.

use base64ct::{Base64UrlUnpadded, Encoding};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// Generate a random 43-char URL-safe PKCE code verifier (32 bytes of entropy).
///
/// # Errors
/// Returns [`Error::Crypto`] if the OS RNG is unavailable.
pub fn verifier() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|_| Error::Crypto("rng failure"))?;
    Ok(Base64UrlUnpadded::encode_string(&bytes))
}

/// Compute the S256 challenge for a verifier: `base64url(sha256(verifier))`.
#[must_use]
pub fn challenge_s256(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    Base64UrlUnpadded::encode_string(&digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifier_is_43_chars() {
        assert_eq!(verifier().unwrap().len(), 43);
    }

    #[test]
    fn verifiers_are_unique() {
        assert_ne!(verifier().unwrap(), verifier().unwrap());
    }

    /// RFC 7636 Appendix B.
    #[test]
    fn rfc7636_appendix_b() {
        assert_eq!(
            challenge_s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }
}
