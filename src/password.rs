//! Argon2id password hashing.
//!
//! Uses INTERACTIVE parameters (t=2, m=64 MiB, p=1), producing ~30-100 ms hashes
//! depending on hardware. Output is a standard PHC-format string.

use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use rand_core::OsRng;

use crate::error::{Error, Result};

fn hasher() -> Argon2<'static> {
    let params = Params::new(64 * 1024, 2, 1, None).expect("valid argon2 params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Hash a password with a fresh random salt.
///
/// Returns a PHC-format string: `$argon2id$v=19$m=65536,t=2,p=1$salt$hash`.
///
/// # Errors
/// Returns [`Error::Crypto`] if Argon2 hashing fails (out of memory, etc.).
pub fn hash(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = hasher()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| Error::Crypto("argon2 hash failed"))?;
    Ok(hash.to_string())
}

/// Verify a password against a PHC hash.
///
/// # Errors
/// - [`Error::InvalidInput`] if `phc_hash` is not a valid PHC string.
/// - [`Error::Mismatch`] if the password does not match.
pub fn verify(password: &str, phc_hash: &str) -> Result<()> {
    let parsed =
        PasswordHash::new(phc_hash).map_err(|_| Error::InvalidInput("invalid PHC hash"))?;
    hasher()
        .verify_password(password.as_bytes(), &parsed)
        .map_err(|_| Error::Mismatch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_argon2id_phc() {
        let h = hash("test").unwrap();
        assert!(h.starts_with("$argon2id$"), "got: {h}");
    }

    #[test]
    fn verify_correct() {
        let h = hash("secret").unwrap();
        assert!(verify("secret", &h).is_ok());
    }

    #[test]
    fn verify_wrong() {
        let h = hash("secret").unwrap();
        assert_eq!(verify("wrong", &h), Err(Error::Mismatch));
    }

    #[test]
    fn verify_malformed_hash() {
        assert!(matches!(
            verify("x", "not-a-phc-hash"),
            Err(Error::InvalidInput(_))
        ));
    }

    #[test]
    fn hash_unique_salts() {
        assert_ne!(hash("same").unwrap(), hash("same").unwrap());
    }
}
