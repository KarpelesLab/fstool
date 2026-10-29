//! HFS+ file-name normalisation.
//!
//! HFS+ stores every catalog name in a *variant* of Unicode Normalization
//! Form D (TN1150, "Unicode Subtleties"): characters are canonically
//! decomposed using the Unicode 3.2 decomposition data, **except** that
//! nothing in these ranges is decomposed:
//!
//! * U+2000 – U+2FFF (punctuation, symbols, CJK radicals …),
//! * U+F900 – U+FAFF (CJK compatibility ideographs),
//! * U+2F800 – U+2FAFF (CJK compatibility ideographs supplement).
//!
//! The macOS kernel (`utf8_decodestr` with `UTF_DECOMPOSED`) works on
//! UTF-16 code units, so it never decomposes anything outside the BMP —
//! which covers the third range and every supplementary character that
//! later Unicode versions gave a decomposition. Inside the BMP the only
//! characters that gained a canonical decomposition after Unicode 3.2 and
//! fall outside the excluded ranges are the Balinese vowel signs
//! (U+1B00 – U+1B7F, Unicode 5.0), so those are held back too. Hangul
//! syllables *are* decomposed (algorithmically), and runs of combining
//! marks are put in canonical order.
//!
//! The kernel normalises every name it is handed — on create *and* on
//! lookup — so a name written in any other form is unreachable through
//! the VFS even though it lists fine. [`normalize_name`] produces the
//! exact form a name must be stored in.
//!
//! Known gap: canonical-ordering uses today's combining classes, so a
//! name with *several* combining marks that were unassigned in Unicode
//! 3.2 may be ordered differently from the kernel. Such names are
//! vanishingly rare in practice.

use super::catalog::UniStr;

/// Longest catalog name HFS+ can hold, in UTF-16 code units
/// (`HFSUniStr255`).
pub const MAX_NAME_UNITS: usize = 255;

/// `true` when `c` must be passed through undecomposed (see module docs).
fn is_excluded(c: char) -> bool {
    let u = c as u32;
    u > 0xFFFF
        || (0x2000..=0x2FFF).contains(&u)
        || (0xF900..=0xFAFF).contains(&u)
        || (0x1B00..=0x1B7F).contains(&u)
}

/// Canonical combining class as the kernel sees it: supplementary
/// characters are surrogate pairs to it, which never reorder.
fn ccc(c: char) -> u8 {
    if (c as u32) > 0xFFFF {
        0
    } else {
        intl::unicode::normalize::canonical_combining_class(c)
    }
}

/// Decompose `s` into the HFS+ variant of NFD, returning Unicode scalars.
fn decompose_chars(s: &str) -> Vec<char> {
    let mut out: Vec<char> = Vec::with_capacity(s.len());
    for c in s.chars() {
        if is_excluded(c) {
            out.push(c);
        } else {
            out.extend(intl::unicode::normalize::nfd(core::iter::once(c)));
        }
    }
    // Canonical ordering: stable-sort every maximal run of non-starters
    // by combining class (UAX #15 §3.11). Starters (class 0) delimit runs.
    let mut i = 0;
    while i < out.len() {
        if ccc(out[i]) == 0 {
            i += 1;
            continue;
        }
        let start = i;
        while i < out.len() && ccc(out[i]) != 0 {
            i += 1;
        }
        out[start..i].sort_by_key(|&c| ccc(c));
    }
    out
}

/// Normalise `name` to the form HFS+ stores on disk (the decomposed
/// variant described in the [module docs](self)).
///
/// The result is what macOS reports back from `readdir` for a name that
/// was created as `name`, so callers that record names elsewhere — Finder
/// aliases, `.DS_Store` records — should record this form. Validation
/// (length, emptiness) is not done here; see [`validate_name`].
pub fn normalize_name(name: &str) -> String {
    decompose_chars(name).into_iter().collect()
}

/// Normalise `name` and check it is a storable HFS+ catalog name:
/// non-empty, free of NUL, and at most 255 UTF-16 code units **after**
/// normalisation (decomposition can lengthen a name — `é` becomes two
/// units). Returns the normalised UTF-16 code units.
pub fn validate_name(name: &str) -> crate::Result<Vec<u16>> {
    if name.is_empty() {
        return Err(crate::Error::InvalidArgument(
            "hfs+: empty file name".into(),
        ));
    }
    if name.contains('\0') {
        return Err(crate::Error::InvalidArgument(format!(
            "hfs+: file name {name:?} contains NUL"
        )));
    }
    let units: Vec<u16> = normalize_name(name).encode_utf16().collect();
    if units.len() > MAX_NAME_UNITS {
        return Err(crate::Error::InvalidArgument(format!(
            "hfs+: file name {name:?} is {} UTF-16 code units after HFS+ \
             normalisation; the limit is {MAX_NAME_UNITS}",
            units.len()
        )));
    }
    Ok(units)
}

/// Turn a canonical fstool path component into the catalog name to store:
/// undo the `:`↔`/` display swap (see [`UniStr::from_path_component`]),
/// normalise, and validate.
pub(crate) fn component_to_unistr(component: &str) -> crate::Result<UniStr> {
    let swapped = component.replace(':', "/");
    Ok(UniStr {
        code_units: validate_name(&swapped)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn units(s: &str) -> Vec<u32> {
        normalize_name(s).chars().map(|c| c as u32).collect()
    }

    #[test]
    fn precomposed_latin_decomposes() {
        assert_eq!(units("caf\u{e9}"), vec![0x63, 0x61, 0x66, 0x65, 0x301]);
        // Already-decomposed input is a fixed point.
        assert_eq!(normalize_name("cafe\u{301}"), normalize_name("caf\u{e9}"));
    }

    #[test]
    fn hangul_decomposes_algorithmically() {
        // U+AC01 GAG = U+1100 U+1161 U+11A8
        assert_eq!(units("\u{AC01}"), vec![0x1100, 0x1161, 0x11A8]);
    }

    #[test]
    fn excluded_ranges_pass_through() {
        // U+2126 OHM SIGN and U+212B ANGSTROM SIGN have canonical
        // singleton decompositions, but sit in U+2000–U+2FFF.
        assert_eq!(units("\u{2126}\u{212B}"), vec![0x2126, 0x212B]);
        // CJK compatibility ideograph U+F900 → U+8C48 in NFD; not here.
        assert_eq!(units("\u{F900}"), vec![0xF900]);
        // Supplementary compatibility ideograph U+2F800.
        assert_eq!(units("\u{2F800}"), vec![0x2F800]);
        // Musical symbol with a canonical decomposition (non-BMP).
        assert_eq!(units("\u{1D15E}"), vec![0x1D15E]);
        // Balinese (post-3.2 decomposition).
        assert_eq!(units("\u{1B06}"), vec![0x1B06]);
    }

    #[test]
    fn singleton_outside_exclusions_decomposes() {
        // U+212B is excluded, but U+00C5 (Å) decomposes.
        assert_eq!(units("\u{C5}"), vec![0x41, 0x30A]);
        // U+0344 COMBINING GREEK DIALYTIKA TONOS → U+0308 U+0301.
        assert_eq!(units("a\u{344}"), vec![0x61, 0x308, 0x301]);
    }

    #[test]
    fn combining_marks_are_reordered() {
        // dot below (220) must precede acute (230).
        assert_eq!(units("a\u{301}\u{323}"), vec![0x61, 0x323, 0x301]);
        // ệ (U+1EC7) = e + dot below + circumflex.
        assert_eq!(units("\u{1EC7}"), vec![0x65, 0x323, 0x302]);
    }

    #[test]
    fn length_is_checked_after_normalisation() {
        let ok = "\u{e9}".repeat(127); // 254 units decomposed
        assert_eq!(validate_name(&ok).unwrap().len(), 254);
        let too_long = "\u{e9}".repeat(128); // 128 chars, 256 units decomposed
        assert!(validate_name(&too_long).is_err());
        assert!(validate_name("").is_err());
        assert!(validate_name("a\0b").is_err());
    }

    #[test]
    fn colon_maps_to_slash() {
        let u = component_to_unistr("a:b").unwrap();
        assert_eq!(u.to_string_lossy(), "a/b");
    }
}
