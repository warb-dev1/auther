//! Crate error type.

use core::fmt;

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors produced by `auther`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Input failed validation (malformed hash, bad secret, wrong digits).
    InvalidInput(&'static str),
    /// Cryptographic operation failed (not a credential mismatch).
    Crypto(&'static str),
    /// Credential did not match (password, code, signature).
    Mismatch,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(s) => write!(f, "invalid input: {s}"),
            Self::Crypto(s) => write!(f, "crypto failure: {s}"),
            Self::Mismatch => write!(f, "credential mismatch"),
        }
    }
}

impl core::error::Error for Error {}
