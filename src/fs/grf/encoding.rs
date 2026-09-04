//! CP949 ↔ UTF-8 helpers for GRF filenames.
//!
//! Ragnarok Online's `.grf` archives store filenames in CP949 — the
//! Microsoft Korean codepage, a superset of EUC-KR with extra
//! private-use mappings. Filenames seen on disk are CP949 bytes; the
//! fstool `Filesystem` trait surface is UTF-8 strings. Conversion
//! happens once at the GRF boundary (during table parse / write).
//!
//! We use `charcode::EUC_KR`. The WHATWG `euc-kr` label is intentionally
//! defined to be CP949 for web-compatibility — the spec mapping is the
//! union we want.

use std::borrow::Cow;

use charcode::{Bom, DecodeOptions, EUC_KR};

/// Decode a CP949 byte slice into UTF-8. Stray bytes that don't map
/// (corruption, truncation) are replaced with U+FFFD — we don't
/// surface decoding errors because GRFs in the wild ship occasional
/// junk filenames and refusing the whole archive helps nobody.
pub fn cp949_to_utf8(bytes: &[u8]) -> Cow<'_, str> {
    // `Bom::Ignore`: a filename is not a document, so a leading EF BB BF
    // is content to decode, not a declaration that switches encoding.
    let (decoded, _, _tally) = EUC_KR.decode_with(bytes, DecodeOptions::new().bom(Bom::Ignore));
    decoded
}

/// Encode a UTF-8 string to CP949 bytes, failing on the first character
/// the codepage cannot represent.
///
/// Failing is the point. The WHATWG `encode` hook — what `encoding_rs`
/// gave us and what `charcode`'s `encode_html_form` still gives — writes
/// a decimal numeric character reference instead, so `café.txt` would go
/// to disk as `caf&#233;.txt`. That is the right answer for an HTML form
/// and the wrong one for a filesystem: the archive would hold a filename
/// nobody asked for and no reader would undo. CP949 is wide (all of
/// Hangul, and the CJK ideographs with it), so this only rejects names
/// genuinely outside it — accented Latin, emoji.
pub fn utf8_to_cp949(s: &str) -> crate::Result<Vec<u8>> {
    match EUC_KR.encode(s) {
        Ok((encoded, _, _)) => Ok(encoded.into_owned()),
        Err(e) => Err(crate::Error::InvalidArgument(format!(
            "grf: filename {s:?} cannot be stored — {e}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_round_trip() {
        let plain = b"data/info.txt";
        let utf = cp949_to_utf8(plain);
        assert_eq!(utf, "data/info.txt");
        let back = utf8_to_cp949(&utf).unwrap();
        assert_eq!(back, plain);
    }

    /// An unrepresentable name is refused, not silently mangled.
    ///
    /// This is the WHATWG-vs-filesystem split in one test: the standard's
    /// `encode` hook would write `caf&#233;.txt`, which is right for an
    /// HTML form and wrong for an archive.
    #[test]
    fn unrepresentable_names_are_refused() {
        for name in ["café.txt", "😀.txt", "Ω\u{303}.txt"] {
            let err = utf8_to_cp949(name).unwrap_err();
            assert!(
                matches!(err, crate::Error::InvalidArgument(_)),
                "{name:?}: {err}"
            );
            let msg = err.to_string();
            // The message names the file and says which character stopped
            // it. (`{:?}` escapes a bare combining mark rather than
            // emitting it into a terminal, so match on the debug form.)
            assert!(
                msg.contains(&format!("{name:?}")),
                "should name the file: {msg}"
            );
            assert!(
                msg.contains("cannot be represented"),
                "should say why: {msg}"
            );
        }
    }

    /// CP949 is Unified Hangul Code — wider than EUC-KR, and it carries
    /// the CJK ideographs too, so these are *not* rejected.
    #[test]
    fn cp949_covers_hangul_and_hanja() {
        for name in ["한국어.txt", "日本.txt", "Ω.txt", "plain.txt"] {
            let bytes = utf8_to_cp949(name).expect("representable");
            assert_eq!(cp949_to_utf8(&bytes), name, "round-trip {name:?}");
        }
    }

    /// Every valid two-byte CP949 sequence must survive decode → encode
    /// unchanged. Byte-exact round-tripping is what a filesystem needs
    /// and what a web decoder is not obliged to give.
    #[test]
    fn every_two_byte_sequence_round_trips() {
        let mut checked = 0u32;
        for hi in 0x81u8..=0xFE {
            for lo in 0x41u8..=0xFE {
                let src = [hi, lo];
                let text = cp949_to_utf8(&src);
                if text.contains('\u{FFFD}') {
                    continue; // not a valid sequence
                }
                let back = utf8_to_cp949(&text).expect("decoded, so representable");
                assert_eq!(back, &src[..], "round-trip {src:02x?}");
                checked += 1;
            }
        }
        assert!(
            checked > 17_000,
            "expected the full CP949 table, saw {checked}"
        );
    }
}
