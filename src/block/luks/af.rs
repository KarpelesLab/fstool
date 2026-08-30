//! The LUKS anti-forensic splitter (AF-split / AF-merge).
//!
//! A LUKS keyslot does not store the master key directly. If it did, a
//! single 32- or 64-byte remnant recovered from a wear-levelling flash
//! block would be enough to open the volume forever, even after the slot
//! was "wiped". Instead the key is first *inflated* into `stripes` copies'
//! worth of material — 4000 stripes by default, so a 64-byte key becomes
//! 250 KiB — in a way that needs **every** byte back to reconstruct the
//! original. Losing any one stripe loses the key.
//!
//! The construction is Clemens Fruhwirth's, from the LUKS on-disk
//! specification:
//!
//! ```text
//!   split:  s_0 … s_{n-2}  are random; d = 0
//!           for i in 0..n-1:  d = H(d ⊕ s_i)
//!           s_{n-1} = key ⊕ d
//!   merge:  d = 0
//!           for i in 0..n-1:  d = H(d ⊕ s_i)
//!           key = d ⊕ s_{n-1}
//! ```
//!
//! where `H` is the *diffuse* function: the block is cut into
//! digest-length pieces, and piece *j* is replaced by
//! `hash(BE32(j) ‖ piece_j)`. A trailing piece shorter than the digest is
//! hashed the same way and truncated.
//!
//! Both directions are pure byte transforms — no key material of ours
//! enters or leaves beyond the caller's buffers — so the module has no
//! I/O and no dependency on the container version. LUKS1 and LUKS2 use
//! the identical algorithm (LUKS2 spells it `"af": {"type": "luks1"}`).

use purecrypto::hash::HashAlgorithm;

use crate::Result;

/// Diffuse `buf` in place: piece *j* becomes `hash(BE32(j) ‖ piece_j)`,
/// with a short trailing piece hashed whole and truncated to its length.
fn diffuse(alg: HashAlgorithm, buf: &mut [u8]) {
    let dlen = alg.output_len();
    let mut scratch = Vec::with_capacity(4 + dlen);
    for (j, piece) in buf.chunks_mut(dlen).enumerate() {
        scratch.clear();
        scratch.extend_from_slice(&(j as u32).to_be_bytes());
        scratch.extend_from_slice(piece);
        let d = alg.digest(&scratch);
        // The final piece may be shorter than the digest; take its prefix.
        piece.copy_from_slice(&d.as_slice()[..piece.len()]);
    }
}

fn xor_into(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src) {
        *d ^= s;
    }
}

/// Recover a `block_size`-byte key from `stripes` consecutive stripes.
///
/// `src.len()` must be exactly `block_size * stripes`.
pub fn merge(alg: HashAlgorithm, src: &[u8], block_size: usize, stripes: u32) -> Result<Vec<u8>> {
    let expect = block_size
        .checked_mul(stripes as usize)
        .ok_or_else(|| crate::Error::InvalidImage("luks: AF material size overflows".into()))?;
    if src.len() != expect {
        return Err(crate::Error::InvalidImage(format!(
            "luks: AF material is {} bytes, expected {block_size} × {stripes} = {expect}",
            src.len()
        )));
    }
    if stripes == 0 || block_size == 0 {
        return Err(crate::Error::InvalidImage(
            "luks: AF stripe count and key size must both be non-zero".into(),
        ));
    }

    let mut d = vec![0u8; block_size];
    for i in 0..(stripes as usize - 1) {
        xor_into(&mut d, &src[i * block_size..(i + 1) * block_size]);
        diffuse(alg, &mut d);
    }
    xor_into(&mut d, &src[(stripes as usize - 1) * block_size..]);
    Ok(d)
}

/// Inflate `key` into `stripes` stripes of `key.len()` bytes each.
///
/// `random` supplies the `stripes - 1` leading stripes; it must be exactly
/// `key.len() * (stripes - 1)` bytes of *cryptographically random* data —
/// the anti-forensic property rests entirely on it. The caller draws it
/// (see [`super::format`], which uses `purecrypto`'s `OsRng`) rather than
/// this module, so the transform stays deterministic and testable.
pub fn split(alg: HashAlgorithm, key: &[u8], stripes: u32, random: &[u8]) -> Result<Vec<u8>> {
    if stripes == 0 || key.is_empty() {
        return Err(crate::Error::InvalidArgument(
            "luks: AF stripe count and key size must both be non-zero".into(),
        ));
    }
    let block_size = key.len();
    let lead = block_size
        .checked_mul(stripes as usize - 1)
        .ok_or_else(|| crate::Error::InvalidArgument("luks: AF material size overflows".into()))?;
    if random.len() != lead {
        return Err(crate::Error::InvalidArgument(format!(
            "luks: AF needs {lead} random bytes for {stripes} stripes, got {}",
            random.len()
        )));
    }

    let mut out = vec![0u8; lead + block_size];
    out[..lead].copy_from_slice(random);

    let mut d = vec![0u8; block_size];
    for i in 0..(stripes as usize - 1) {
        xor_into(&mut d, &out[i * block_size..(i + 1) * block_size]);
        diffuse(alg, &mut d);
    }
    // Final stripe carries the key masked by the accumulated diffusion.
    let last = &mut out[lead..];
    last.copy_from_slice(key);
    xor_into(last, &d);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pseudo_random(len: usize, seed: u8) -> Vec<u8> {
        // Deterministic filler for the split → merge round-trip. Real
        // splits draw from OsRng; the transform doesn't care where the
        // leading stripes come from.
        (0..len)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
            .collect()
    }

    #[test]
    fn split_then_merge_recovers_the_key() {
        for hash in ["sha1", "sha256", "sha512", "ripemd160", "whirlpool"] {
            let alg = super::super::hash::parse(hash).unwrap();
            for (key_len, stripes) in [(32usize, 4000u32), (64, 4000), (16, 1), (64, 2), (20, 7)] {
                let key: Vec<u8> = (0..key_len).map(|i| (i as u8) ^ 0x5a).collect();
                let random = pseudo_random(key_len * (stripes as usize - 1), 3);
                let split = split(alg, &key, stripes, &random).unwrap();
                assert_eq!(split.len(), key_len * stripes as usize);
                let merged = merge(alg, &split, key_len, stripes).unwrap();
                assert_eq!(merged, key, "{hash} {key_len}×{stripes}");
            }
        }
    }

    /// One stripe = the key itself; the LUKS spec's degenerate case.
    #[test]
    fn single_stripe_is_the_key_verbatim() {
        let alg = super::super::hash::parse("sha256").unwrap();
        let key = vec![0xabu8; 32];
        let split = split(alg, &key, 1, &[]).unwrap();
        assert_eq!(split, key);
    }

    /// Losing any single stripe must destroy the key — that is the whole
    /// point of the splitter.
    #[test]
    fn corrupting_one_stripe_destroys_the_key() {
        let alg = super::super::hash::parse("sha256").unwrap();
        let key = vec![7u8; 32];
        let random = pseudo_random(32 * 9, 11);
        let split = split(alg, &key, 10, &random).unwrap();
        for stripe in 0..10usize {
            let mut damaged = split.clone();
            damaged[stripe * 32] ^= 1;
            let merged = merge(alg, &damaged, 32, 10).unwrap();
            assert_ne!(
                merged, key,
                "flipping a bit in stripe {stripe} was harmless"
            );
        }
        // Sanity: undamaged material still merges.
        assert_eq!(merge(alg, &split, 32, 10).unwrap(), key);
    }

    #[test]
    fn rejects_mis_sized_material() {
        let alg = super::super::hash::parse("sha256").unwrap();
        assert!(merge(alg, &[0u8; 31], 32, 1).is_err());
        assert!(split(alg, &[0u8; 32], 4, &[0u8; 10]).is_err());
    }

    /// The diffuse helper must be sensitive to the piece index: two
    /// identical pieces at different positions diffuse differently.
    #[test]
    fn diffuse_is_position_dependent() {
        let alg = super::super::hash::parse("sha256").unwrap();
        let mut buf = vec![0u8; 64];
        diffuse(alg, &mut buf);
        assert_ne!(&buf[..32], &buf[32..]);
    }
}
