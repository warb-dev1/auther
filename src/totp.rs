//! Time-based One-Time Password (RFC 6238).
//!
//! HMAC-SHA1, with caller-provided Unix timestamp so the module stays I/O-free
//! and deterministic for tests.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use subtle::ConstantTimeEq;

use crate::error::{Error, Result};

type HmacSha1 = Hmac<Sha1>;

/// Default TOTP period in seconds.
pub const DEFAULT_PERIOD: u64 = 30;
/// Default TOTP digit count.
pub const DEFAULT_DIGITS: u32 = 6;

/// Generate a TOTP code for the given Unix timestamp.
///
/// `secret` is the raw secret bytes (post-base32 decode).
///
/// # Errors
/// Returns [`Error::InvalidInput`] if `period == 0`, `digits` is outside `1..=10`,
/// or `secret` is empty.
pub fn generate(secret: &[u8], unix_seconds: u64, period: u64, digits: u32) -> Result<String> {
    if period == 0 || !(1..=10).contains(&digits) {
        return Err(Error::InvalidInput("invalid period or digits"));
    }
    let counter = unix_seconds / period;
    let code = hotp(secret, counter, digits)?;
    Ok(format_code(code, digits))
}

/// Verify a TOTP code with `window` steps of drift tolerance on each side.
///
/// # Errors
/// Returns [`Error::Mismatch`] if the code does not match any candidate in the
/// window, or if the code's shape is wrong (length/digits).
pub fn verify(
    secret: &[u8],
    code: &str,
    unix_seconds: u64,
    period: u64,
    digits: u32,
    window: u64,
) -> Result<()> {
    if code.len() != digits as usize || !code.chars().all(|c| c.is_ascii_digit()) {
        return Err(Error::Mismatch);
    }
    let counter = unix_seconds / period;

    let try_counter = |c: u64| -> Result<bool> {
        let cand = format_code(hotp(secret, c, digits)?, digits);
        Ok(bool::from(cand.as_bytes().ct_eq(code.as_bytes())))
    };

    if try_counter(counter)? {
        return Ok(());
    }
    for offset in 1..=window {
        if try_counter(counter.wrapping_sub(offset))? {
            return Ok(());
        }
        if try_counter(counter.wrapping_add(offset))? {
            return Ok(());
        }
    }

    Err(Error::Mismatch)
}

fn hotp(secret: &[u8], counter: u64, digits: u32) -> Result<u32> {
    let mut mac = <HmacSha1 as Mac>::new_from_slice(secret)
        .map_err(|_| Error::InvalidInput("empty secret"))?;
    mac.update(&counter.to_be_bytes());
    let result = mac.finalize().into_bytes();

    let offset = (result[result.len() - 1] & 0x0f) as usize;
    let dbc = ((u32::from(result[offset]) & 0x7f) << 24)
        | (u32::from(result[offset + 1]) << 16)
        | (u32::from(result[offset + 2]) << 8)
        | u32::from(result[offset + 3]);

    let modulo = 10u32.pow(digits);
    Ok(dbc % modulo)
}

fn format_code(n: u32, digits: u32) -> String {
    format!("{n:0>width$}", width = digits as usize)
}

/// Build an `otpauth://` URL for Google Authenticator / Authy / 1Password.
#[must_use]
pub fn otpauth_url(issuer: &str, account: &str, secret_base32: &str) -> String {
    format!(
        "otpauth://totp/{issuer}:{account}?secret={secret_base32}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 Appendix B secret.
    const SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn rfc6238_vector_t59() {
        // RFC lists 8-digit value 94287082 at T=59; last 6 digits are 287082.
        assert_eq!(generate(SECRET, 59, 30, 6).unwrap(), "287082");
    }

    #[test]
    fn verify_round_trip() {
        let code = generate(SECRET, 1_000_000, 30, 6).unwrap();
        assert!(verify(SECRET, &code, 1_000_000, 30, 6, 1).is_ok());
    }

    #[test]
    fn verify_within_window() {
        let code = generate(SECRET, 1_000_000, 30, 6).unwrap();
        assert!(verify(SECRET, &code, 1_000_030, 30, 6, 1).is_ok());
    }

    #[test]
    fn verify_outside_window_fails() {
        let code = generate(SECRET, 1_000_000, 30, 6).unwrap();
        assert_eq!(
            verify(SECRET, &code, 1_000_120, 30, 6, 1),
            Err(Error::Mismatch)
        );
    }

    #[test]
    fn verify_wrong_length_fails() {
        assert_eq!(
            verify(SECRET, "12345", 1_000_000, 30, 6, 1),
            Err(Error::Mismatch)
        );
    }

    #[test]
    fn generate_rejects_zero_period() {
        assert!(matches!(
            generate(SECRET, 0, 0, 6),
            Err(Error::InvalidInput(_))
        ));
    }

    #[test]
    fn otpauth_url_format() {
        let url = otpauth_url("acme", "user@example.com", "JBSWY3DPEHPK3PXP");
        assert!(url.starts_with("otpauth://totp/acme:user@example.com?"));
        assert!(url.contains("secret=JBSWY3DPEHPK3PXP"));
    }
}
