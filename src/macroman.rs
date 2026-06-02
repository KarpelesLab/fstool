//! MacRoman → Unicode decoding for classic-Mac byte strings.
//!
//! Classic Mac OS stored text (HFS filenames, `STR`/`vers` resource payloads,
//! resource names, …) as MacRoman (8-bit). Bytes `0x00–0x7F` are ASCII;
//! `0x80–0xFF` map to the Unicode code points below (the standard Apple
//! MacRoman table).

/// Unicode code points for MacRoman bytes `0x80..=0xFF`.
#[rustfmt::skip]
const HIGH: [char; 128] = [
    'Ä','Å','Ç','É','Ñ','Ö','Ü','á','à','â','ä','ã','å','ç','é','è',
    'ê','ë','í','ì','î','ï','ñ','ó','ò','ô','ö','õ','ú','ù','û','ü',
    '†','°','¢','£','§','•','¶','ß','®','©','™','´','¨','≠','Æ','Ø',
    '∞','±','≤','≥','¥','µ','∂','∑','∏','π','∫','ª','º','Ω','æ','ø',
    '¿','¡','¬','√','ƒ','≈','∆','«','»','…','\u{00A0}','À','Ã','Õ','Œ','œ',
    '–','—','“','”','‘','’','÷','◊','ÿ','Ÿ','⁄','€','‹','›','ﬁ','ﬂ',
    '‡','·','‚','„','‰','Â','Ê','Á','Ë','È','Í','Î','Ï','Ì','Ó','Ô',
    '\u{F8FF}','Ò','Ú','Û','Ù','ı','ˆ','˜','¯','˘','˙','˚','¸','˝','˛','ˇ',
];

/// Decode a MacRoman byte string to a UTF-8 `String`.
pub fn decode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| {
            if b < 0x80 {
                b as char
            } else {
                HIGH[(b - 0x80) as usize]
            }
        })
        .collect()
}

/// Case-insensitive equality used for path-component matching. Folds ASCII
/// letters (sufficient for the System-disk style names this reader targets);
/// other characters compare exactly after MacRoman decoding.
pub fn eq_ignore_case(a: &str, b: &str) -> bool {
    let fold = |c: char| {
        if c.is_ascii_uppercase() {
            c.to_ascii_lowercase()
        } else {
            c
        }
    };
    a.chars().map(fold).eq(b.chars().map(fold))
}

/// Encode a UTF-8 string to MacRoman bytes (the inverse of [`decode`]).
///
/// Returns [`crate::Error::InvalidArgument`] if `s` contains a character with
/// no MacRoman representation — classic HFS names can only hold MacRoman, so a
/// name with such a character cannot be written.
pub fn encode(s: &str) -> crate::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len());
    for c in s.chars() {
        if (c as u32) < 0x80 {
            out.push(c as u8);
        } else if let Some(i) = HIGH.iter().position(|&h| h == c) {
            out.push(0x80 + i as u8);
        } else {
            return Err(crate::Error::InvalidArgument(format!(
                "macroman: character {c:?} is not representable in MacRoman"
            )));
        }
    }
    Ok(out)
}

/// Case fold for a single MacRoman byte used by [`cmp_ci`]: ASCII lowercase
/// `a..=z` fold to uppercase `A..=Z`; every other byte keeps its value.
///
/// This is exact for the ASCII range (which covers the overwhelming majority of
/// real Mac filenames). High-MacRoman bytes (accented letters, symbols) keep
/// their raw value rather than Apple's accent-grouped sort weight — a faithful,
/// self-consistent total order, but not byte-for-byte the classic `FastRelString`
/// collation for non-ASCII names. See `hfs-collation-highbytes` follow-up.
#[inline]
fn fold(b: u8) -> u8 {
    if b.is_ascii_lowercase() { b - 0x20 } else { b }
}

/// Compare two MacRoman byte strings the way the classic HFS catalog B-tree
/// orders names: case-insensitively, byte by byte, with a shorter prefix
/// sorting before a longer string. The in-memory catalog key order must match
/// this so the written B-tree is valid for `fsck`/Mac OS.
pub fn cmp_ci(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    for (&x, &y) in a.iter().zip(b.iter()) {
        match fold(x).cmp(&fold(y)) {
            Ordering::Equal => {}
            other => return other,
        }
    }
    a.len().cmp(&b.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;

    #[test]
    fn encode_decode_round_trip() {
        for s in [
            "hello.txt",
            "System Folder",
            "A/ROSE Includes",
            "TokenTalk™ Prep",
        ] {
            let bytes = encode(s).unwrap();
            assert_eq!(decode(&bytes), s, "round-trip {s:?}");
        }
        // High-byte chars map back to their single MacRoman byte.
        assert_eq!(encode("™").unwrap(), vec![0xAA]);
        assert_eq!(encode("©").unwrap(), vec![0xA9]);
        // Un-representable characters error rather than corrupt.
        assert!(encode("emoji 😀").is_err());
    }

    #[test]
    fn cmp_ci_is_case_insensitive_and_ordered() {
        assert_eq!(cmp_ci(b"Apple", b"apple"), Ordering::Equal);
        assert_eq!(cmp_ci(b"Apple", b"BOB"), Ordering::Less);
        assert_eq!(cmp_ci(b"bob", b"Apple"), Ordering::Greater);
        // Prefix sorts before the longer string.
        assert_eq!(cmp_ci(b"file", b"file.txt"), Ordering::Less);
        assert_eq!(cmp_ci(b"", b"x"), Ordering::Less);
        // Digits before letters (ASCII order preserved).
        assert_eq!(cmp_ci(b"1file", b"afile"), Ordering::Less);
    }
}
