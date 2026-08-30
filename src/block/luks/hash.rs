//! Runtime hash selection for LUKS.
//!
//! Everything in a LUKS header names its hash by string — `"sha256"` in
//! the LUKS1 `hash-spec` field, `"sha512"` in a LUKS2 digest object,
//! `"ripemd160"` in an anti-forensic stripe. `purecrypto` already has the
//! runtime-selectable [`HashAlgorithm`] enum plus the `dispatch_digest!`
//! bridge into its `Digest`-generic primitives, so this module is a thin
//! adapter: name → algorithm, and the two derived operations LUKS needs
//! (PBKDF2 and a plain digest) with fstool's error type.

use purecrypto::hash::HashAlgorithm;

use crate::Result;

/// Resolve a LUKS hash-spec string. Accepts the canonical `purecrypto`
/// names and their common spellings (`"sha-256"`, `"sha3_512"`, …), which
/// is a superset of what cryptsetup writes.
pub fn parse(name: &str) -> Result<HashAlgorithm> {
    HashAlgorithm::from_name(name.trim())
        .ok_or_else(|| crate::Error::Unsupported(format!("luks: unknown hash `{name}`")))
}

/// Digest `data` with `alg`.
pub fn digest(alg: HashAlgorithm, data: &[u8]) -> Vec<u8> {
    alg.digest(data).as_slice().to_vec()
}

/// PBKDF2-HMAC-`alg` into `out`.
///
/// `iterations` must be at least 1 — `purecrypto`'s `pbkdf2` panics on
/// zero, and a header claiming zero rounds is malformed, so it is rejected
/// here as [`crate::Error::InvalidImage`] instead.
pub fn pbkdf2(
    alg: HashAlgorithm,
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    out: &mut [u8],
) -> Result<()> {
    if iterations == 0 {
        return Err(crate::Error::InvalidImage(
            "luks: PBKDF2 iteration count is zero".into(),
        ));
    }
    purecrypto::dispatch_digest!(
        alg,
        |D| {
            purecrypto::kdf::pbkdf2::<D>(password, salt, iterations, out);
        },
        _ => {
            return Err(crate::Error::Unsupported(format!(
                "luks: hash `{}` has no PBKDF2 binding in this build",
                alg.name()
            )));
        }
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_hashes_cryptsetup_writes() {
        for name in [
            "sha1",
            "sha256",
            "sha512",
            "ripemd160",
            "whirlpool",
            "sha3-256",
            "sha3-512",
        ] {
            assert!(parse(name).is_ok(), "{name} should resolve");
        }
        assert!(parse("nosuchhash").is_err());
    }

    /// RFC 6070 PBKDF2-HMAC-SHA1 vector, reached through the runtime
    /// dispatch rather than the generic call — proves the bridge wires the
    /// name to the right hasher.
    #[test]
    fn pbkdf2_matches_rfc6070() {
        let alg = parse("sha1").unwrap();
        let mut out = [0u8; 20];
        pbkdf2(alg, b"password", b"salt", 2, &mut out).unwrap();
        assert_eq!(
            out,
            [
                0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c, 0xcd, 0x1e, 0xd9, 0x2a, 0xce, 0x1d,
                0x41, 0xf0, 0xd8, 0xde, 0x89, 0x57,
            ]
        );
    }

    #[test]
    fn rejects_zero_iterations() {
        let alg = parse("sha256").unwrap();
        let mut out = [0u8; 32];
        assert!(matches!(
            pbkdf2(alg, b"pw", b"salt", 0, &mut out),
            Err(crate::Error::InvalidImage(_))
        ));
    }
}
