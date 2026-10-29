//! DMG chunk decoders for the compressed entry types that aren't
//! zero / raw / zlib.
//!
//! Each function takes the raw compressed payload as recorded in the
//! data fork and writes exactly `plain_len` decoded bytes back. The
//! callers in [`crate::block::dmg`] derive `plain_len` from
//! `chunk.sector_count * 512`, which is the contract every BLKX entry
//! advertises.
//!
//! ## Codec choices
//!
//! - **bzip2**: `compcol` bzip2 decoder.
//! - **LZFSE**: `compcol` LZFSE decoder.
//! - **LZMA**: `compcol` `.lzma` (alone) decoder over the raw LZMA1
//!   frame (DMG never uses the XZ container).
//! - **ADC**: implemented in this file from the public spec described
//!   in Apple's `imageformat.h`; no external dep.
//!
//! When a build is configured without one of the optional codec deps
//! the corresponding `decode_*` function returns
//! [`crate::Error::Unsupported`] so a slim binary can still open zlib
//! / raw / zero-only images.

use crate::Result;

/// Decode an ADC (Apple Data Compression) stream into `out`.
///
/// ADC is a tiny LZ77 variant. The encoder emits one of three opcodes:
///
/// - `0x80..=0xFF` (bit 7 set): literal run. `(opcode & 0x7F) + 1`
///   (1..=128) bytes follow directly in the stream and are copied
///   verbatim.
/// - `0x40..=0x7F` (bit 7 clear, bit 6 set): long back-reference. Two
///   additional bytes follow (big-endian).
///   - length = (opcode & 0x3F) + 4               →  4..=67
///   - distance = ((hi << 8) | lo) + 1            →  1..=65536
/// - `0x00..=0x3F` (bits 7 and 6 clear): short back-reference. One
///   additional byte follows.
///   - length = ((opcode >> 2) & 0x0F) + 3        →  3..=18
///   - distance = (((opcode & 0x03) << 8) | next) + 1  →  1..=1024
///
/// e.g. `81 41 42 00 01` is literal "AB" followed by a short reference
/// of length 3 / distance 2, decoding to `ABABA`.
///
/// The back-reference distance is measured from the **current write
/// position**, looking backward into already-decoded bytes. Length and
/// distance can overlap (`distance < length`); when they do, the copy
/// must propagate forward byte-by-byte so each freshly written byte is
/// visible to the rest of the run. That's how ADC encodes simple runs
/// like `aaaa` (distance 1, length 4).
///
/// The function writes into the prefix of `out`, returning the number
/// of bytes produced. Callers should size `out` to the chunk's expected
/// plain length and treat any short / long result as a malformed image.
pub fn decode_adc(src: &[u8], out: &mut [u8]) -> Result<usize> {
    let mut sp = 0usize;
    let mut dp = 0usize;
    while sp < src.len() {
        let op = src[sp];
        sp += 1;

        if op & 0x80 != 0 {
            // Literal run of ((op & 0x7F) + 1) bytes.
            let len = (op & 0x7F) as usize + 1;
            if sp + len > src.len() {
                return Err(crate::Error::InvalidImage(format!(
                    "dmg/adc: literal run of {len} bytes runs past source ({} of {} consumed)",
                    sp,
                    src.len()
                )));
            }
            if dp + len > out.len() {
                return Err(crate::Error::InvalidImage(format!(
                    "dmg/adc: literal run of {len} bytes overflows output ({}+{}>{})",
                    dp,
                    len,
                    out.len()
                )));
            }
            out[dp..dp + len].copy_from_slice(&src[sp..sp + len]);
            sp += len;
            dp += len;
        } else if op & 0x40 != 0 {
            // Long reference: op + two trailing big-endian bytes.
            if sp + 2 > src.len() {
                return Err(crate::Error::InvalidImage(
                    "dmg/adc: long reference truncated".into(),
                ));
            }
            let hi = src[sp] as usize;
            let lo = src[sp + 1] as usize;
            sp += 2;
            let len = ((op & 0x3F) as usize) + 4;
            let dist = ((hi << 8) | lo) + 1;
            adc_copy(out, &mut dp, dist, len)?;
        } else {
            // Short reference: op + one trailing byte.
            if sp >= src.len() {
                return Err(crate::Error::InvalidImage(
                    "dmg/adc: short reference truncated".into(),
                ));
            }
            let b = src[sp];
            sp += 1;
            let len = (((op >> 2) & 0x0F) as usize) + 3;
            let dist = ((((op & 0x03) as usize) << 8) | b as usize) + 1;
            adc_copy(out, &mut dp, dist, len)?;
        }
    }
    Ok(dp)
}

/// Inner copy helper for ADC back-references. Propagates byte-by-byte
/// so overlapping copies (distance < length) replicate the source run
/// the way ADC encoders rely on.
fn adc_copy(out: &mut [u8], dp: &mut usize, dist: usize, len: usize) -> Result<()> {
    if dist == 0 || dist > *dp {
        return Err(crate::Error::InvalidImage(format!(
            "dmg/adc: back-reference distance {dist} out of range (dp = {dp})",
            dp = *dp
        )));
    }
    if *dp + len > out.len() {
        return Err(crate::Error::InvalidImage(format!(
            "dmg/adc: back-reference of {len} bytes overflows output ({}+{}>{})",
            *dp,
            len,
            out.len()
        )));
    }
    for i in 0..len {
        out[*dp + i] = out[*dp + i - dist];
    }
    *dp += len;
    Ok(())
}

/// Encode `src` as an ADC stream that [`decode_adc`] (and Apple's own
/// decoder) expands back to exactly `src`.
///
/// A greedy single-candidate LZ77: a hash of the next three bytes names
/// the most recent position with the same prefix; if it is within the
/// 64 KiB window the match is extended (up to the 67-byte long-form
/// cap) and emitted in the cheapest opcode that can carry it — the
/// two-byte short form for distance ≤ 1024 and length ≤ 18, the
/// three-byte long form otherwise (which needs length ≥ 4). Everything
/// else goes out as literal runs of at most 128 bytes. The output is at
/// worst `src.len() + ceil(src.len() / 128)` bytes.
#[cfg(feature = "dmg-write")]
pub fn encode_adc(src: &[u8]) -> Vec<u8> {
    const HASH_BITS: u32 = 14;
    const NONE: u32 = u32::MAX;
    const MAX_DIST: usize = 65_536;
    const SHORT_MAX_DIST: usize = 1024;
    const SHORT_MAX_LEN: usize = 18;
    const LONG_MAX_LEN: usize = 67;
    const MAX_LITERAL: usize = 128;

    fn hash(b: &[u8]) -> usize {
        let v = u32::from(b[0]) | (u32::from(b[1]) << 8) | (u32::from(b[2]) << 16);
        (v.wrapping_mul(0x9E37_79B1) >> (32 - HASH_BITS)) as usize
    }
    fn literals(out: &mut Vec<u8>, mut lit: &[u8]) {
        while !lit.is_empty() {
            let take = lit.len().min(MAX_LITERAL);
            out.push(0x80 | (take - 1) as u8);
            out.extend_from_slice(&lit[..take]);
            lit = &lit[take..];
        }
    }

    let n = src.len();
    // Positions are stored as u32; a DMG chunk is far below 4 GiB (the
    // writer caps it), but fall back to all-literal output rather than
    // mis-encode if someone hands us more.
    if n >= NONE as usize {
        let mut out = Vec::with_capacity(n + n.div_ceil(MAX_LITERAL));
        literals(&mut out, src);
        return out;
    }
    let mut table = vec![NONE; 1 << HASH_BITS];
    let mut out = Vec::with_capacity(n / 2 + 16);
    let mut lit_start = 0usize;
    let mut i = 0usize;
    while i + 3 <= n {
        let h = hash(&src[i..]);
        let cand = table[h];
        table[h] = i as u32;
        let mut best = None;
        if cand != NONE {
            let c = cand as usize;
            let dist = i - c;
            if dist <= MAX_DIST && src[c..c + 3] == src[i..i + 3] {
                let max = (n - i).min(LONG_MAX_LEN);
                let mut len = 3;
                while len < max && src[c + len] == src[i + len] {
                    len += 1;
                }
                // A 3-byte match only fits the short form (distance ≤ 1024).
                if dist <= SHORT_MAX_DIST || len >= 4 {
                    best = Some((dist, len));
                }
            }
        }
        let Some((dist, len)) = best else {
            i += 1;
            continue;
        };
        literals(&mut out, &src[lit_start..i]);
        let d = dist - 1;
        if dist <= SHORT_MAX_DIST && len <= SHORT_MAX_LEN {
            out.push((((len - 3) as u8) << 2) | (d >> 8) as u8);
            out.push(d as u8);
        } else {
            out.push(0x40 | (len - 4) as u8);
            out.push((d >> 8) as u8);
            out.push(d as u8);
        }
        // Index the positions the match skipped over so later data can
        // refer back into it.
        let end = i + len;
        for j in i + 1..end.min(n - 2) {
            table[hash(&src[j..])] = j as u32;
        }
        i = end;
        lit_start = i;
    }
    literals(&mut out, &src[lit_start..]);
    out
}

/// Decode an in-memory compcol-codec chunk into a `Vec`, refusing to expand
/// past `plain_len` (a decompression-bomb guard for the bounded per-chunk
/// case). A manual `decode`/`finish` loop with an explicit size check —
/// rather than `LimitedDecoder`, which stalls codecs (e.g. bzip2) that need
/// a post-output call to consume their trailer when the cap is exact.
#[cfg(any(feature = "dmg-bzip2", feature = "dmg-lzfse"))]
fn decode_chunk<A: compcol::Algorithm>(
    src: &[u8],
    plain_len: usize,
    label: &str,
) -> Result<Vec<u8>> {
    use compcol::{Decoder, Status};
    let mut dec = A::decoder();
    let mut out = Vec::with_capacity(plain_len);
    let mut scratch = vec![0u8; 64 * 1024];
    let mut consumed = 0usize;
    let err = |e| crate::Error::InvalidImage(format!("dmg: {label} chunk decode failed: {e}"));
    let overflow = || {
        crate::Error::InvalidImage(format!(
            "dmg: {label} chunk expanded past {plain_len} bytes"
        ))
    };
    loop {
        let (p, status) = dec.decode(&src[consumed..], &mut scratch).map_err(err)?;
        out.extend_from_slice(&scratch[..p.written]);
        consumed += p.consumed;
        if out.len() > plain_len {
            return Err(overflow());
        }
        match status {
            Status::StreamEnd => return Ok(out),
            Status::OutputFull => continue,
            Status::InputEmpty => break,
        }
    }
    loop {
        let (p, status) = dec.finish(&mut scratch).map_err(err)?;
        out.extend_from_slice(&scratch[..p.written]);
        if out.len() > plain_len {
            return Err(overflow());
        }
        if matches!(status, Status::StreamEnd) || p.written == 0 {
            break;
        }
    }
    Ok(out)
}

/// Decode a bzip2 chunk payload into a vector of exactly `plain_len`
/// bytes. DMG bz2 chunks are standalone bzip2 streams (BZh magic,
/// no additional framing).
#[cfg(feature = "dmg-bzip2")]
pub fn decode_bzip2(src: &[u8], plain_len: usize) -> Result<Vec<u8>> {
    let out = decode_chunk::<compcol::bzip2::Bzip2>(src, plain_len, "bzip2")?;
    if out.len() != plain_len {
        return Err(crate::Error::InvalidImage(format!(
            "dmg: bzip2 chunk inflated to {} bytes but sector_count*512 = {}",
            out.len(),
            plain_len
        )));
    }
    Ok(out)
}

/// Stub when the bzip2 dep was compiled out.
#[cfg(not(feature = "dmg-bzip2"))]
pub fn decode_bzip2(_src: &[u8], _plain_len: usize) -> Result<Vec<u8>> {
    Err(crate::Error::Unsupported(
        "dmg: bzip2 chunks require the `dmg-bzip2` Cargo feature".into(),
    ))
}

/// Decode an LZFSE chunk payload into a vector of exactly `plain_len`
/// bytes. DMG LZFSE chunks are standalone bvxN/bvx2/bvx1/bvx- framed
/// blocks; decoded via `compcol::lzfse` (decode-only).
#[cfg(feature = "dmg-lzfse")]
pub fn decode_lzfse(src: &[u8], plain_len: usize) -> Result<Vec<u8>> {
    let out = decode_chunk::<compcol::lzfse::Lzfse>(src, plain_len, "lzfse")?;
    if out.len() != plain_len {
        return Err(crate::Error::InvalidImage(format!(
            "dmg: lzfse chunk inflated to {} bytes but sector_count*512 = {}",
            out.len(),
            plain_len
        )));
    }
    Ok(out)
}

/// Stub when the LZFSE dep was compiled out.
#[cfg(not(feature = "dmg-lzfse"))]
pub fn decode_lzfse(_src: &[u8], _plain_len: usize) -> Result<Vec<u8>> {
    Err(crate::Error::Unsupported(
        "dmg: LZFSE chunks require the `dmg-lzfse` Cargo feature".into(),
    ))
}

/// Decode an LZMA chunk (ULMO) payload into a vector of exactly
/// `plain_len` bytes. Current `hdiutil` writes each chunk as an XZ
/// container; the raw LZMA1 frame (the legacy `.lzma` shape: a 13-byte
/// header with properties, dictionary size and length) is accepted too.
/// Which one it is follows from the XZ magic.
pub fn decode_lzma(src: &[u8], plain_len: usize) -> Result<Vec<u8>> {
    use crate::compression::Algo;
    let (algo, feature) = if src.starts_with(b"\xFD7zXZ\x00") {
        (Algo::Xz, "xz")
    } else {
        (Algo::Lzma, "lzma")
    };
    if !algo.enabled() {
        return Err(crate::Error::Unsupported(format!(
            "dmg: this LZMA chunk is {}-framed and needs the `{feature}` Cargo feature",
            algo.name()
        )));
    }
    let out = crate::compression::decompress(algo, src, plain_len)?;
    if out.len() != plain_len {
        return Err(crate::Error::InvalidImage(format!(
            "dmg: lzma chunk inflated to {} bytes but sector_count*512 = {}",
            out.len(),
            plain_len
        )));
    }
    Ok(out)
}

/// Decode an ADC chunk into a vector of exactly `plain_len` bytes.
/// Wraps [`decode_adc`] so the call site mirrors the other codec
/// helpers.
pub fn decode_adc_chunk(src: &[u8], plain_len: usize) -> Result<Vec<u8>> {
    let mut out = vec![0u8; plain_len];
    let n = decode_adc(src, &mut out)?;
    if n != plain_len {
        return Err(crate::Error::InvalidImage(format!(
            "dmg: ADC chunk produced {n} bytes but sector_count*512 = {plain_len}"
        )));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode `data` as a single ADC literal run. Caller must keep
    /// `data.len() <= 128`. Used by the tests to build minimal vectors.
    fn adc_literal(data: &[u8]) -> Vec<u8> {
        assert!(!data.is_empty() && data.len() <= 128);
        let mut v = Vec::with_capacity(1 + data.len());
        v.push(0x80 | (data.len() - 1) as u8);
        v.extend_from_slice(data);
        v
    }

    #[test]
    fn adc_literal_only() {
        let payload = b"hello world";
        let stream = adc_literal(payload);
        let mut out = vec![0u8; payload.len()];
        let n = decode_adc(&stream, &mut out).unwrap();
        assert_eq!(n, payload.len());
        assert_eq!(&out[..], payload);
    }

    #[test]
    fn adc_long_literal_run() {
        // 128-byte literal run, the maximum a single opcode can carry.
        let payload: Vec<u8> = (0..128u8).collect();
        let stream = adc_literal(&payload);
        let mut out = vec![0u8; 128];
        let n = decode_adc(&stream, &mut out).unwrap();
        assert_eq!(n, 128);
        assert_eq!(out, payload);
    }

    #[test]
    fn adc_short_reference() {
        // First emit "ABCD" as a literal, then a short reference of
        // length 4 / distance 4 — should reproduce "ABCD" again.
        // op = ((len-3) << 2) | ((dist-1) >> 8)
        // len = 4 → (len-3) = 1
        // dist = 4 → (dist-1) = 3 → hi 0, lo 3
        // op = (1 << 2) | 0 = 0x04, trailing byte = 3.
        let mut stream = adc_literal(b"ABCD");
        stream.push(0x04);
        stream.push(0x03);
        let mut out = vec![0u8; 8];
        let n = decode_adc(&stream, &mut out).unwrap();
        assert_eq!(n, 8);
        assert_eq!(&out[..], b"ABCDABCD");
    }

    #[test]
    fn adc_short_reference_overlap_run() {
        // Encode "a" then back-reference dist=1 len=3 — should give
        // "aaaa". op = ((3-3)<<2) | 0 = 0x00, trailing = 0.
        let mut stream = adc_literal(b"a");
        stream.push(0x00);
        stream.push(0x00);
        let mut out = vec![0u8; 4];
        let n = decode_adc(&stream, &mut out).unwrap();
        assert_eq!(n, 4);
        assert_eq!(&out[..], b"aaaa");
    }

    #[test]
    fn adc_long_reference() {
        // Build a 200-byte literal preamble of 0xAA, then a long
        // reference len=67 dist=200 reproducing the first 67 bytes.
        let mut stream = Vec::new();
        // Two 100-byte literal runs (literal opcode max length 128).
        stream.push(0x80 | 99u8); // run of 100 bytes
        stream.extend(std::iter::repeat_n(0xAA, 100));
        stream.push(0x80 | 99u8);
        stream.extend(std::iter::repeat_n(0xBB, 100));

        // Long reference: op = 0x40 | (len-4) = 0x40 | 63 = 0x7F.
        // dist - 1 = 199 → 0x00C7.
        stream.push(0x40 | 63); // len = 67
        stream.push(0x00);
        stream.push(0xC7);

        let mut out = vec![0u8; 267];
        let n = decode_adc(&stream, &mut out).unwrap();
        assert_eq!(n, 267);
        // First 100 bytes 0xAA, next 100 bytes 0xBB, last 67 bytes
        // are the AAs from distance-200 = the start of the buffer.
        assert!(out[0..100].iter().all(|&b| b == 0xAA));
        assert!(out[100..200].iter().all(|&b| b == 0xBB));
        assert!(out[200..267].iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn adc_rejects_distance_zero() {
        // Short reference with zero in the trailing byte AND zero in
        // the opcode low bits ⇒ distance = 0 + 1 = 1, fine. So we have
        // to construct an actual zero-distance case. That requires
        // dp = 0 and any reference — pick a short ref at start of
        // stream which must fail since there's nothing to reference.
        let stream = vec![0x00, 0x00];
        let mut out = vec![0u8; 4];
        let err = decode_adc(&stream, &mut out).unwrap_err();
        match err {
            crate::Error::InvalidImage(_) => {}
            _ => panic!("expected InvalidImage, got {err:?}"),
        }
    }

    #[test]
    fn adc_rejects_truncated_short_reference() {
        // Opcode 0x00 marks a short reference but the trailing byte is
        // missing.
        let stream = vec![0x81, b'A', b'B', 0x00];
        let mut out = vec![0u8; 4];
        assert!(decode_adc(&stream, &mut out).is_err());
    }

    #[test]
    fn adc_rejects_truncated_long_reference() {
        // Long reference opcode with only one trailing byte.
        let stream = vec![0x81, b'A', b'B', 0x40, 0x00];
        let mut out = vec![0u8; 4];
        assert!(decode_adc(&stream, &mut out).is_err());
    }

    #[test]
    fn adc_rejects_literal_overrun() {
        // Literal opcode promises 5 bytes but only 2 are present.
        let stream = vec![0x84, 0x01, 0x02];
        let mut out = vec![0u8; 8];
        assert!(decode_adc(&stream, &mut out).is_err());
    }

    /// The two vectors from issue #54, hand-written (no helper).
    #[test]
    fn adc_issue_54_vectors() {
        // literal "AB", short ref len 3 dist 2.
        let mut out = vec![0u8; 5];
        let n = decode_adc(&[0x81, 0x41, 0x42, 0x00, 0x01], &mut out).unwrap();
        assert_eq!(&out[..n], b"ABABA");
        // literal "AB", long ref len 5 dist 2.
        let mut out = vec![0u8; 7];
        let n = decode_adc(&[0x81, 0x41, 0x42, 0x41, 0x00, 0x01], &mut out).unwrap();
        assert_eq!(&out[..n], b"ABABABA");
    }

    /// Every opcode class with the bit-6 boundary exercised: 0x3F is the
    /// longest short reference, 0x40 the shortest long reference, 0x80
    /// the shortest literal and 0xFF the longest.
    #[test]
    fn adc_opcode_class_boundaries() {
        // 0x3F: short, len ((0x3F>>2)&0xF)+3 = 18, dist ((3<<8)|0xFF)+1 = 1024.
        let mut stream = vec![0xFF];
        stream.extend((0..128u8).collect::<Vec<_>>());
        for _ in 0..7 {
            stream.push(0xFF);
            stream.extend((0..128u8).collect::<Vec<_>>());
        }
        // 8 × 128 = 1024 bytes of output so far.
        stream.extend_from_slice(&[0x3F, 0xFF]);
        // 0x40: long, len 4, dist 0x0000+1 = 1.
        stream.extend_from_slice(&[0x40, 0x00, 0x00]);
        let mut out = vec![0u8; 1024 + 18 + 4];
        let n = decode_adc(&stream, &mut out).unwrap();
        assert_eq!(n, out.len());
        assert_eq!(&out[1024..1042], &out[0..18]);
        assert!(out[1042..].iter().all(|&b| b == out[1041]));
    }

    #[test]
    fn adc_rejects_reference_before_output_start() {
        // Short ref at dp=2 asking for distance 3.
        let mut out = vec![0u8; 8];
        assert!(decode_adc(&[0x81, b'A', b'B', 0x00, 0x02], &mut out).is_err());
        // Long ref at dp=2 asking for distance 0x100.
        assert!(decode_adc(&[0x81, b'A', b'B', 0x40, 0x00, 0xFF], &mut out).is_err());
        // Reference that would run past the output buffer.
        let mut small = vec![0u8; 4];
        assert!(decode_adc(&[0x81, b'A', b'B', 0x00, 0x01], &mut small).is_err());
        // Short output via decode_adc_chunk is also an error.
        assert!(decode_adc_chunk(&[0x81, b'A', b'B'], 512).is_err());
    }

    #[cfg(feature = "dmg-bzip2")]
    #[test]
    fn bzip2_roundtrip_via_libbz2_independent_vector() {
        // Pre-computed bzip2 stream of the ASCII text "hello world\n"
        // produced by the bzip2 reference CLI. Inline so the test
        // doesn't depend on a write-side encoder.
        let compressed: &[u8] = &[
            0x42, 0x5A, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0x4E, 0xEC, 0xE8, 0x36,
            0x00, 0x00, 0x02, 0x51, 0x80, 0x00, 0x10, 0x40, 0x00, 0x06, 0x44, 0x90, 0x80, 0x20,
            0x00, 0x31, 0x06, 0x4C, 0x41, 0x01, 0xA7, 0xA9, 0xA5, 0x80, 0xBB, 0x94, 0x31, 0xF8,
            0xBB, 0x92, 0x29, 0xC2, 0x84, 0x82, 0x77, 0x67, 0x41, 0xB0,
        ];
        let plain = decode_bzip2(compressed, b"hello world\n".len()).unwrap();
        assert_eq!(plain, b"hello world\n");
    }

    #[cfg(feature = "xz")]
    #[test]
    fn xz_framed_lzma_chunk_decodes() {
        // Native ULMO chunks are XZ containers.
        let plain: Vec<u8> = (0..4096u32).map(|i| (i % 7) as u8).collect();
        let compressed =
            crate::compression::compress(crate::compression::Algo::Xz, &plain).unwrap();
        assert!(compressed.starts_with(b"\xFD7zXZ\x00"));
        assert_eq!(decode_lzma(&compressed, plain.len()).unwrap(), plain);
    }

    #[cfg(feature = "lzma")]
    #[test]
    fn lzma_roundtrip() {
        // Build a raw-LZMA1 (.lzma alone) stream and round-trip it through
        // decode_lzma (both via compcol).
        let plain = b"the quick brown fox jumps over the lazy dog".repeat(8);
        let compressed =
            crate::compression::compress(crate::compression::Algo::Lzma, &plain).unwrap();
        let out = decode_lzma(&compressed, plain.len()).unwrap();
        assert_eq!(out, plain);
    }

    /// Deterministic mixed corpus: runs, text, short/long distances and
    /// incompressible noise, so every ADC opcode class is exercised.
    #[cfg(feature = "dmg-write")]
    fn adc_corpus() -> Vec<Vec<u8>> {
        let mut x: u64 = 0x2545_F491_4F6C_DD1D;
        let mut noise = |n: usize| -> Vec<u8> {
            (0..n)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    x as u8
                })
                .collect()
        };
        let mut far = noise(3000);
        far.extend_from_slice(&noise(2000));
        let head = far[..3000].to_vec();
        far.extend_from_slice(&head); // match at distance 5000 (long form)
        let mut text = Vec::new();
        for i in 0..2000 {
            text.extend_from_slice(format!("line {i}: the quick brown fox\n").as_bytes());
        }
        vec![
            Vec::new(),
            vec![7],
            vec![1, 2],
            b"abc".to_vec(),
            vec![0u8; 1 << 20],
            vec![0xAA; 70_000],
            b"ABABABABABABABABABABABABAB".to_vec(),
            text,
            noise(100_000),
            far,
            (0..200_000u32).map(|i| (i / 300) as u8).collect(),
        ]
    }

    #[cfg(feature = "dmg-write")]
    #[test]
    fn adc_encoder_roundtrips_through_decoder() {
        for plain in adc_corpus() {
            let enc = encode_adc(&plain);
            assert!(
                enc.len() <= plain.len() + plain.len().div_ceil(128),
                "ADC expansion bound violated"
            );
            let dec = decode_adc_chunk(&enc, plain.len()).unwrap();
            assert_eq!(dec, plain, "ADC round trip of {} bytes", plain.len());
        }
        // Compressible input must actually shrink.
        assert!(encode_adc(&vec![0u8; 4096]).len() < 4096 / 16);
    }
}
