//! Recovery codes with O(1) prefix lookup.
//!
//! Each entry is stored as `sha256_prefix:argon2_hash`. Verification computes
//! the prefix, narrows to at most one candidate, then runs a single Argon2
//! verify. Without the prefix, verifying a wrong code requires N Argon2 checks.

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::password;

/// SHA-256 prefix length in hex characters (4 bytes).
pub const PREFIX_LEN: usize = 8;

/// Generate a single 8-char hex backup code (4 random bytes).
///
/// # Errors
/// Returns [`Error::Crypto`] if the OS RNG is unavailable.
pub fn generate() -> Result<String> {
    let mut bytes = [0u8; 4];
    getrandom::getrandom(&mut bytes).map_err(|_| Error::Crypto("rng failure"))?;
    Ok(hex_encode(&bytes))
}

/// Hash a backup code for storage: `sha256_prefix:argon2_hash`.
///
/// # Errors
/// Propagates [`password::hash`] errors.
pub fn hash(code: &str) -> Result<String> {
    let prefix = sha256_prefix(code);
    let argon = password::hash(code)?;
    Ok(format!("{prefix}:{argon}"))
}

/// Verify `code` against a list of stored entries; return the matched index.
///
/// Entries are `sha256_prefix:argon2_hash`. Legacy entries without the prefix
/// (starting with `$argon2`) are also accepted for backward compatibility.
///
/// # Errors
/// Returns [`Error::Mismatch`] if no entry matches.
pub fn verify(code: &str, entries: &[String]) -> Result<usize> {
    let prefix = sha256_prefix(code);

    for (idx, entry) in entries.iter().enumerate() {
        if let Some((stored_prefix, phc)) = entry.split_once(':') {
            if stored_prefix.len() == PREFIX_LEN
                && stored_prefix == prefix
                && password::verify(code, phc).is_ok()
            {
                return Ok(idx);
            }
        } else if password::verify(code, entry).is_ok() {
            return Ok(idx);
        }
    }

    Err(Error::Mismatch)
}

fn sha256_prefix(code: &str) -> String {
    let digest = Sha256::digest(code.as_bytes());
    hex_encode(&digest[..(PREFIX_LEN / 2)])
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_is_8_hex() {
        let c = generate().unwrap();
        assert_eq!(c.len(), 8);
        assert!(c.chars().all(|ch| ch.is_ascii_hexdigit()));
    }

    #[test]
    fn hash_verify_round_trip() {
        let entry = hash("abcd1234").unwrap();
        assert_eq!(verify("abcd1234", &[entry]).unwrap(), 0);
    }

    #[test]
    fn verify_rejects_wrong() {
        let entry = hash("real").unwrap();
        assert_eq!(verify("fake", &[entry]), Err(Error::Mismatch));
    }

    #[test]
    fn entry_format_is_prefix_colon_phc() {
        let entry = hash("abc12345").unwrap();
        let (prefix, phc) = entry.split_once(':').unwrap();
        assert_eq!(prefix.len(), PREFIX_LEN);
        assert!(phc.starts_with("$argon2id$"));
    }

    #[test]
    fn prefix_deterministic() {
        assert_eq!(sha256_prefix("abc123"), sha256_prefix("abc123"));
    }

    #[test]
    fn empty_list_returns_mismatch() {
        assert_eq!(verify("any", &[]), Err(Error::Mismatch));
    }
}
