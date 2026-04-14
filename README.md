# auther

Authentication primitives — Argon2id, TOTP, backup codes, PKCE, JWT — in one small Rust crate.

**Status: pre-alpha, work in progress.**

## What this is

A focused library of stateless, audit-friendly auth primitives. No database, no HTTP, no sessions. Just the cryptographic and protocol building blocks you need to implement auth flows in your own app.

- **Password hashing** — Argon2id via [RustCrypto `argon2`](https://crates.io/crates/argon2).
- **TOTP** — RFC 6238, HMAC-SHA1, 6-digit, 30-second period by default.
- **Backup codes** — O(1) SHA-256 prefix lookup with Argon2id verify.
- **OAuth PKCE** — RFC 7636 S256 challenge/verifier.
- **JWT** — Ed25519 + HS256 _(in progress)_.

## What this is not

- Not a framework. No `User`, no `Session`, no `login()`.
- Not an auth server. It gives you primitives; you wire the flows.
- Not feature-complete against Better Auth or Passport.js yet.

## Design goals

1. **Zero `unsafe`** — `#![forbid(unsafe_code)]`.
2. **One crate** — no workspace, no sub-crates.
3. **Cross-language** — C FFI + UniFFI bindings (Python, Node, Swift, Kotlin) planned.
4. **`no_std`-friendly** — v0 uses `std`; `no_std + alloc` planned for v0.2.
5. **Deterministic where possible** — timestamps are caller-provided, not read from the clock.

## Usage

```rust
use auther::{password, totp, pkce, backup_codes};

// Password
let phc = password::hash("correct horse battery staple")?;
password::verify("correct horse battery staple", &phc)?;

// TOTP (RFC 6238)
let secret = b"12345678901234567890";
let code = totp::generate(secret, 1_700_000_000, 30, 6)?;
totp::verify(secret, &code, 1_700_000_000, 30, 6, 1)?;

// PKCE (RFC 7636)
let v = pkce::verifier()?;
let c = pkce::challenge_s256(&v);

// Backup codes
let entry = backup_codes::hash(&backup_codes::generate()?)?;
# Ok::<(), auther::Error>(())
```

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option. Contributions are accepted under the same terms.
