//! CRC-32 variants the filesystems need, in the flavours `compcol` does
//! not expose.
//!
//! Three different CRC-32s show up across the formats fstool writes, and
//! they are not interchangeable — a checksum computed with the wrong
//! polynomial, seed or final XOR is silently wrong, and `e2fsck` /
//! `xfs_repair` / `fsck.f2fs` reject the image.
//!
//! | Flavour | Polynomial (reflected) | Seed | Final XOR | Used by |
//! |---|---|---|---|---|
//! | IEEE, finalised | `0xEDB88320` | `!0` | `!0` | GPT, ZIP — see below |
//! | IEEE, raw | `0xEDB88320` | caller's | none | littlefs, F2FS |
//! | Castagnoli | `0x82F63B78` | `!0` | `!0` | ext4 `metadata_csum`, XFS v5 |
//!
//! `compcol` exposes the finalised IEEE one as
//! [`compcol::checksum::Crc32`], but it is an *optional* dependency here
//! — a `--no-default-features` build has no codecs and so no compcol,
//! while GPT and ZIP are always compiled. So all three flavours live
//! here, sharing one table set. `compcol`'s implementation still earns
//! its keep as an independent oracle: `raw_ieee_agrees_with_compcol`
//! below checks the two against each other whenever the `gzip` feature
//! puts compcol in the build.
//!
//! The raw IEEE variant is the one no general-purpose crate offers:
//! littlefs commits a CRC that is deliberately un-XORed so the running
//! state can be threaded straight into the next chunk, and F2FS seeds
//! with its superblock magic instead of `!0`.
//!
//! ## Correctness
//!
//! Both are pinned to the CRC catalogue's check value — the CRC of
//! `"123456789"` — in the tests below, and every user of them is
//! cross-validated against the real fsck for its format in
//! `tests/*_external.rs`.
//!
//! ## Performance
//!
//! Slice-by-8: eight bytes per iteration through eight tables, which
//! shortens the dependency chain versus a byte-at-a-time loop. That is
//! roughly a gigabyte a second, against maybe twenty for the SSE4.2
//! `crc32` instruction a hardware-accelerated implementation would reach
//! on Castagnoli. Every caller here checksums metadata — a 4 KiB ext4
//! block, a 512-byte XFS sector, a littlefs commit — so the constant
//! factor never lands anywhere hot.

/// Build a slice-by-8 table set for a reflected polynomial.
///
/// Row 0 is the ordinary byte-at-a-time table; row *n* is row *n-1* fed
/// through one more byte of zeros, which is what lets the inner loop
/// consume eight bytes at once.
const fn tables(poly: u32) -> [[u32; 256]; 8] {
    let mut t = [[0u32; 256]; 8];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = (c >> 1) ^ ((c & 1).wrapping_neg() & poly);
            k += 1;
        }
        t[0][i] = c;
        i += 1;
    }
    let mut n = 1;
    while n < 8 {
        let mut i = 0;
        while i < 256 {
            let prev = t[n - 1][i];
            t[n][i] = (prev >> 8) ^ t[0][(prev & 0xFF) as usize];
            i += 1;
        }
        n += 1;
    }
    t
}

/// Reflected IEEE 802.3 polynomial — gzip, GPT, ZIP, littlefs, F2FS.
const IEEE: [[u32; 256]; 8] = tables(0xEDB8_8320);
/// Reflected Castagnoli polynomial — ext4 `metadata_csum`, XFS v5.
const CASTAGNOLI: [[u32; 256]; 8] = tables(0x82F6_3B78);

/// Fold `data` into the running state `s` using `t`. Pure state
/// transform: no seeding, no final XOR — the callers below apply those.
#[inline]
fn fold(t: &[[u32; 256]; 8], mut s: u32, data: &[u8]) -> u32 {
    let (chunks, tail) = data.as_chunks::<8>();
    for c in chunks {
        let lo = u32::from_le_bytes([c[0], c[1], c[2], c[3]]) ^ s;
        let hi = u32::from_le_bytes([c[4], c[5], c[6], c[7]]);
        s = t[7][(lo & 0xFF) as usize]
            ^ t[6][((lo >> 8) & 0xFF) as usize]
            ^ t[5][((lo >> 16) & 0xFF) as usize]
            ^ t[4][(lo >> 24) as usize]
            ^ t[3][(hi & 0xFF) as usize]
            ^ t[2][((hi >> 8) & 0xFF) as usize]
            ^ t[1][((hi >> 16) & 0xFF) as usize]
            ^ t[0][(hi >> 24) as usize];
    }
    for &b in tail {
        s = (s >> 8) ^ t[0][((s ^ b as u32) & 0xFF) as usize];
    }
    s
}

/// CRC-32C (Castagnoli) over `data`.
///
/// Seeded `!0` and finalised with `!0`, the usual framing — this is the
/// value ext4 and XFS store.
pub fn crc32c(data: &[u8]) -> u32 {
    crc32c_append(0, data)
}

/// Continue a CRC-32C from `crc`, the value a previous call returned.
///
/// Both ends of the framing are undone and redone around the fold, so
/// `crc32c_append(crc32c(a), b) == crc32c(a ++ b)`.
pub fn crc32c_append(crc: u32, data: &[u8]) -> u32 {
    !fold(&CASTAGNOLI, !crc, data)
}

/// CRC-32 (IEEE 802.3) over `data` — the finalised flavour, seeded `!0`
/// and XORed `!0`. GPT header/entry checksums and ZIP entry CRCs.
pub fn crc32(data: &[u8]) -> u32 {
    crc32_append(0, data)
}

/// Continue a [`crc32`] from the value a previous call returned, so
/// `crc32_append(crc32(a), b) == crc32(a ++ b)`. ZIP streams entry
/// bodies through this.
pub fn crc32_append(crc: u32, data: &[u8]) -> u32 {
    !fold(&IEEE, !crc, data)
}

/// Raw reflected-IEEE CRC-32: no seeding and no final XOR, so the
/// returned value *is* the internal state and feeds straight back in.
///
/// This is the shape littlefs and F2FS want. littlefs starts from
/// `0xFFFFFFFF` and stores the un-XORed state in its commit tag; F2FS
/// starts from its own superblock magic. Neither matches the finalised
/// convention [`compcol::checksum::Crc32`] implements, which is why they
/// come through here.
pub fn crc32_ieee_raw(state: u32, data: &[u8]) -> u32 {
    fold(&IEEE, state, data)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The CRC catalogue's check value: the CRC of the nine ASCII bytes
    /// `"123456789"`. Getting this right means polynomial, reflection,
    /// seed and final XOR are all correct.
    #[test]
    fn matches_the_catalogue_check_values() {
        assert_eq!(crc32c(b"123456789"), 0xE306_9283, "CRC-32C");
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926, "CRC-32");
        // The raw state, framed the standard way, is the same value.
        assert_eq!(!crc32_ieee_raw(!0, b"123456789"), 0xCBF4_3926, "raw CRC-32");
    }

    /// …and it must agree with `compcol`, which fstool uses for the
    /// finalised IEEE flavour. Two implementations of the same
    /// polynomial disagreeing would mean one of them is wrong.
    #[test]
    #[cfg(feature = "gzip")]
    fn raw_ieee_agrees_with_compcol() {
        for data in [
            &b""[..],
            b"123456789",
            b"the quick brown fox jumps over the lazy dog",
            &[0xFFu8; 1024][..],
        ] {
            let mut c = compcol::checksum::Crc32::new();
            c.update(data);
            assert_eq!(crc32(data), c.finalize(), "{} bytes", data.len());
            assert_eq!(
                !crc32_ieee_raw(!0, data),
                c.finalize(),
                "{} bytes",
                data.len()
            );
        }
    }

    /// Splitting the input anywhere must not change the answer — the
    /// property every streaming caller relies on.
    #[test]
    fn appending_matches_one_shot() {
        let data: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
        for cut in [0, 1, 7, 8, 9, 63, 64, 512, 999, 1000] {
            let (a, b) = data.split_at(cut);
            assert_eq!(
                crc32c_append(crc32c(a), b),
                crc32c(&data),
                "crc32c split at {cut}"
            );
            assert_eq!(
                crc32_append(crc32(a), b),
                crc32(&data),
                "crc32 split at {cut}"
            );
            assert_eq!(
                crc32_ieee_raw(crc32_ieee_raw(!0, a), b),
                crc32_ieee_raw(!0, &data),
                "raw ieee split at {cut}"
            );
        }
    }

    /// The two polynomials must not accidentally be the same table.
    #[test]
    fn the_polynomials_differ() {
        assert_ne!(crc32c(b"fstool"), !crc32_ieee_raw(!0, b"fstool"));
    }

    /// Every input length through the slice-by-8 boundary, against a
    /// plain byte-at-a-time reference.
    #[test]
    fn slice_by_eight_matches_the_naive_loop() {
        fn naive(poly: u32, mut s: u32, data: &[u8]) -> u32 {
            for &b in data {
                s ^= b as u32;
                for _ in 0..8 {
                    s = (s >> 1) ^ ((s & 1).wrapping_neg() & poly);
                }
            }
            s
        }
        let data: Vec<u8> = (0..40u8).map(|i| i.wrapping_mul(37)).collect();
        for n in 0..data.len() {
            assert_eq!(
                crc32c(&data[..n]),
                !naive(0x82F6_3B78, !0, &data[..n]),
                "crc32c len {n}"
            );
            assert_eq!(
                crc32_ieee_raw(!0, &data[..n]),
                naive(0xEDB8_8320, !0, &data[..n]),
                "raw ieee len {n}"
            );
        }
    }
}
