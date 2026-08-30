//! Standard-alphabet base64 (RFC 4648) encode + decode.
//!
//! Two callers today: the UDIF resource-fork plist (`<data>` elements
//! holding mish blocks) and the LUKS2 JSON metadata (salts, digests and
//! master-key material are base64 strings). Both use the standard
//! alphabet with `'='` padding, so one 60-line helper serves them and
//! pulling in the `base64` crate would be gratuitous.
//!
//! [`decode`] tolerates whitespace anywhere in the input because the
//! plist serialiser splits long payloads across many indented lines;
//! anything else outside the alphabet is a hard error. [`encode`] emits
//! a single unbroken line.
//!
//! Cross-check: the tests below pin both directions to the RFC 4648 §10
//! reference vectors, so any drift in alphabet or padding handling is
//! caught locally.

use crate::Result;

/// Standard base64 alphabet. Index = 6-bit value, value = ASCII byte.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Decode a base64 string. Whitespace (space, tab, CR, LF) inside the
/// input is silently skipped — Apple's plist serialiser splits long
/// base64 payloads across many indented lines. Anything else that
/// isn't an alphabet byte or `=` padding is a hard error.
pub fn decode(input: &str) -> Result<Vec<u8>> {
    // Build a reverse lookup table once per call. 256 bytes; cheap.
    // 0xFF marks "not in alphabet" — `=` is also 0xFF, but we treat it
    // separately below.
    let mut lookup = [0xFFu8; 256];
    for (i, &b) in ALPHABET.iter().enumerate() {
        lookup[b as usize] = i as u8;
    }

    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    // 24-bit accumulator + count of 6-bit groups buffered (0..4).
    let mut acc: u32 = 0;
    let mut groups: u32 = 0;
    let mut pad: u32 = 0;

    for &c in input.as_bytes() {
        match c {
            b' ' | b'\t' | b'\r' | b'\n' => continue,
            b'=' => {
                pad += 1;
                if pad > 2 {
                    return Err(crate::Error::InvalidImage(
                        "base64: more than two '=' padding bytes".into(),
                    ));
                }
                // Padding still contributes a (zero) sextet to the
                // accumulator so the group bookkeeping stays in sync;
                // we trim the unused output bytes below.
                acc <<= 6;
                groups += 1;
            }
            _ => {
                if pad > 0 {
                    return Err(crate::Error::InvalidImage(
                        "base64: non-padding bytes after '='".into(),
                    ));
                }
                let v = lookup[c as usize];
                if v == 0xFF {
                    return Err(crate::Error::InvalidImage(format!("base64: invalid byte {c:#x}")));
                }
                acc = (acc << 6) | (v as u32);
                groups += 1;
            }
        }
        if groups == 4 {
            out.push(((acc >> 16) & 0xFF) as u8);
            out.push(((acc >> 8) & 0xFF) as u8);
            out.push((acc & 0xFF) as u8);
            acc = 0;
            groups = 0;
        }
    }

    if groups != 0 {
        return Err(crate::Error::InvalidImage(
            "base64: input length not a multiple of 4 after stripping whitespace".into(),
        ));
    }

    // Trim padding bytes from the tail. `pad` is 1 or 2 means we
    // accidentally emitted 1 or 2 zero bytes — drop them.
    for _ in 0..pad {
        out.pop();
    }
    Ok(out)
}

/// Encode `bytes` as standard-alphabet base64 with `=` padding, on one
/// unbroken line. The inverse of [`decode`].
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let (b0, b1, b2) = (
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        );
        let v = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
        out.push(ALPHABET[((v >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((v >> 12) & 0x3F) as usize] as char);
        out.push(if chunk.len() >= 2 {
            ALPHABET[((v >> 6) & 0x3F) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() == 3 {
            ALPHABET[(v & 0x3F) as usize] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_known_vectors() {
        // RFC 4648 §10 reference vectors.
        assert_eq!(decode("").unwrap(), b"");
        assert_eq!(decode("Zg==").unwrap(), b"f");
        assert_eq!(decode("Zm8=").unwrap(), b"fo");
        assert_eq!(decode("Zm9v").unwrap(), b"foo");
        assert_eq!(decode("Zm9vYg==").unwrap(), b"foob");
        assert_eq!(decode("Zm9vYmE=").unwrap(), b"fooba");
        assert_eq!(decode("Zm9vYmFy").unwrap(), b"foobar");
    }

    #[test]
    fn tolerates_whitespace_and_line_breaks() {
        let s = "Zm9v\n\tYmFy\r\n";
        assert_eq!(decode(s).unwrap(), b"foobar");
    }

    #[test]
    fn rejects_invalid_bytes() {
        assert!(decode("Zm9v!").is_err());
        assert!(decode("Zm===").is_err()); // 3 padding bytes
        assert!(decode("Zm9vA").is_err()); // wrong length
    }

    #[test]
    fn encodes_known_vectors() {
        // Same RFC 4648 §10 vectors, the other way round.
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"f"), "Zg==");
        assert_eq!(encode(b"fo"), "Zm8=");
        assert_eq!(encode(b"foo"), "Zm9v");
        assert_eq!(encode(b"foob"), "Zm9vYg==");
        assert_eq!(encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn round_trips_every_byte_value() {
        let all: Vec<u8> = (0..=255u8).collect();
        for cut in [0usize, 1, 2, 3, 17, 128, 255, 256] {
            let src = &all[..cut];
            assert_eq!(decode(&encode(src)).unwrap(), src, "cut={cut}");
        }
    }
}
