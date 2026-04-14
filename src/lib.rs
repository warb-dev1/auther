//! Authentication primitives.
//!
//! - [`password`] — Argon2id hashing.
//! - [`totp`] — RFC 6238 time-based one-time passwords.
//! - [`backup_codes`] — recovery codes with O(1) prefix lookup.
//! - [`pkce`] — OAuth 2.0 PKCE (RFC 7636) S256 challenge.
//! - [`jwt`] — JWT helpers (in progress).
//!
//! Every primitive is stateless and I/O-free. Wire them into your own flows.

#![doc(html_root_url = "https://docs.rs/auther")]

pub mod backup_codes;
pub mod error;
pub mod jwt;
pub mod password;
pub mod pkce;
pub mod totp;

pub use error::{Error, Result};
