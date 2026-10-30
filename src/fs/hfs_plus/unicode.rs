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
//! What macOS actually stores is whatever the kernel's
//! `utf8_decodestr(…, UTF_DECOMPOSED)` (xnu `bsd/vfs/vfs_utfconv.c`)
//! produces, and it normalises every name it is handed — on create *and*
//! on lookup — so a name stored in any other form lists fine but is
//! unreachable through the VFS. This module is a line-for-line port of
//! that routine, driven by the kernel's own data tables
//! (`vfs_utfconvdata.h`, transcribed by `tools/gen_hfs_unicode.py`).
//! Consequently:
//!
//! * Only BMP characters are decomposed; supplementary characters are
//!   surrogate pairs to the kernel and pass through untouched.
//! * The decomposable set is exactly Unicode 3.2's canonical
//!   decompositions minus the ranges above (the generator cross-checks
//!   this against `UnicodeData-3.2.0.txt`). Characters unassigned in 3.2
//!   — including those that later gained a decomposition, such as the
//!   Balinese vowel signs — pass through unchanged.
//! * Hangul syllables are decomposed algorithmically.
//! * Runs of *combining* characters (the kernel's 3.2-era combining set,
//!   which also counts the Hangul medial/final jamo) are put in canonical
//!   order by combining class. The class table is the kernel's: Unicode
//!   3.2 plus the 25 marks Unicode 4.0 added (U+0350 – U+0357, …). A
//!   mark outside the combining set (anything added after 3.2) ends a
//!   run, so `a` U+0351 U+0323 is stored as typed, where today's NFD
//!   would swap the two marks.
//! * U+2400 (SYMBOL FOR NULL) is stored as U+0000 — the kernel's
//!   `UCS_ALT_NULL` mapping (it is how the hard-link directory
//!   `\0\0\0\0HFS+ Private Data` is named from user space).
//!
//! [`normalize_name`] / [`normalize_units`] produce the exact form a name
//! must be stored in.

use super::catalog::UniStr;
use super::unicode_tables::{
    COMBINING_BITMAP, COMBINING_PROPERTY_BITMAP, DECOMPOSABLE_BITMAP, DECOMPOSITION_TABLE,
    MULTIPLE_DECOMPOSITION_TABLE,
};

/// Longest catalog name HFS+ can hold, in UTF-16 code units
/// (`HFSUniStr255`).
pub const MAX_NAME_UNITS: usize = 255;

/// The kernel's `UCS_ALT_NULL`: U+2400 in a name stands for a NUL.
const UCS_ALT_NULL: u16 = 0x2400;

const HANGUL_SBASE: u16 = 0xAC00;
const HANGUL_LBASE: u16 = 0x1100;
const HANGUL_VBASE: u16 = 0x1161;
const HANGUL_TBASE: u16 = 0x11A7;
const HANGUL_SCOUNT: u16 = 11172;
const HANGUL_TCOUNT: u16 = 28;
const HANGUL_NCOUNT: u16 = 21 * HANGUL_TCOUNT;

/// Look `c` up in one of the kernel's two-level bitmaps
/// (`unicode_combinable` / `unicode_decomposeable`). `floor` is the
/// first code point the kernel tests at all.
fn bitmap_test(bitmap: &[u8], floor: u16, c: u16) -> bool {
    if c < floor {
        return false;
    }
    match bitmap[usize::from(c >> 8)] {
        0 => false,
        0xFF => true,
        v => {
            let sub = 256 + (usize::from(v) - 1) * 32;
            bitmap[sub + usize::from(c & 0xFF) / 8] & (1 << (c % 8)) != 0
        }
    }
}

/// `unicode_combinable`: does `c` continue a combining run?
fn is_combinable(c: u16) -> bool {
    bitmap_test(&COMBINING_BITMAP, 0x0300, c)
}

/// `unicode_decomposeable`: does the kernel decompose `c`?
fn is_decomposable(c: u16) -> bool {
    bitmap_test(&DECOMPOSABLE_BITMAP, 0x00C0, c)
}

/// `get_combining_class`.
fn combining_class(c: u16) -> u8 {
    let page = COMBINING_PROPERTY_BITMAP[usize::from(c >> 8)];
    if page == 0 {
        0
    } else {
        COMBINING_PROPERTY_BITMAP[usize::from(page) * 256 + usize::from(c & 0xFF)]
    }
}

/// `getmappedvalue16` over the `(key, value)` pairs of
/// `DECOMPOSITION_TABLE`; 0 when `c` is not in it.
fn decomposition_value(c: u16) -> u16 {
    let (mut lo, mut hi) = (0usize, DECOMPOSITION_TABLE.len() / 2);
    while lo < hi {
        let mid = (lo + hi) / 2;
        match DECOMPOSITION_TABLE[2 * mid].cmp(&c) {
            core::cmp::Ordering::Less => lo = mid + 1,
            core::cmp::Ordering::Greater => hi = mid,
            core::cmp::Ordering::Equal => return DECOMPOSITION_TABLE[2 * mid + 1],
        }
    }
    0
}

/// `unicode_recursive_decompose`: append the decomposition of `c` to
/// `out`, returning how many units it produced (0 when `c` has none).
fn recursive_decompose(c: u16, out: &mut Vec<u16>) -> usize {
    const RECURSIVE: u16 = 1 << 15;
    let value = decomposition_value(c);
    let mut length = usize::from((value >> 12) & 0x7);
    let first = value & 0x0FFF;
    let single = [first];
    let mut mappings: &[u16] = if length == 1 {
        &single
    } else {
        &MULTIPLE_DECOMPOSITION_TABLE[usize::from(first)..]
    };
    let mut used = 0;
    if value & RECURSIVE != 0 {
        used = recursive_decompose(mappings[0], out);
        length -= 1;
        if used == 0 {
            return 0;
        }
        mappings = &mappings[1..];
    }
    out.extend_from_slice(&mappings[..length]);
    used + length
}

/// `unicode_decompose`: the decomposition of a decomposable `c`.
fn decompose(c: u16, out: &mut Vec<u16>) {
    // The kernel's bound is inclusive (`<= SBASE + SCOUNT`); that extra
    // code point is not in the decomposable bitmap, so never gets here.
    if (HANGUL_SBASE..=HANGUL_SBASE + HANGUL_SCOUNT).contains(&c) {
        let s = c - HANGUL_SBASE;
        out.push(s / HANGUL_NCOUNT + HANGUL_LBASE);
        out.push((s % HANGUL_NCOUNT) / HANGUL_TCOUNT + HANGUL_VBASE);
        if !s.is_multiple_of(HANGUL_TCOUNT) {
            out.push(s % HANGUL_TCOUNT + HANGUL_TBASE);
        }
    } else {
        recursive_decompose(c, out);
    }
}

/// `prioritysort`: bubble-sort a combining run by combining class,
/// never moving a class-0 character.
fn priority_sort(run: &mut [u16]) {
    if run.len() < 2 {
        return;
    }
    loop {
        let mut changed = false;
        let mut p2 = combining_class(run[0]);
        for i in 1..run.len() {
            let p1 = p2;
            p2 = combining_class(run[i]);
            if p1 > p2 && p2 != 0 {
                run.swap(i - 1, i);
                changed = true;
                p2 = p1;
            }
        }
        if !changed {
            break;
        }
    }
}

/// The kernel's `push`: append `c`, tracking (and canonically ordering)
/// runs of combining characters.
fn push(out: &mut Vec<u16>, run: &mut usize, c: u16) {
    if is_combinable(c) {
        *run += 1;
    } else {
        if *run > 1 {
            let n = out.len();
            priority_sort(&mut out[n - *run..]);
        }
        *run = 0;
    }
    out.push(c);
}

/// Normalise `name` into the UTF-16 code units HFS+ stores — a port of
/// xnu's `utf8_decodestr` with `UTF_DECOMPOSED` (and no `altslash`: the
/// `:` ↔ `/` swap is done by the callers that deal in path components).
pub fn normalize_units(name: &str) -> Vec<u16> {
    let mut out: Vec<u16> = Vec::with_capacity(name.len());
    let mut run = 0usize;
    let mut scratch: Vec<u16> = Vec::with_capacity(8);
    for ch in name.chars() {
        let u = ch as u32;
        if u >= 0x1_0000 {
            // Surrogate pair: the high half goes through `push` (ending
            // any combining run), the low half is appended raw.
            let mut pair = [0u16; 2];
            ch.encode_utf16(&mut pair);
            push(&mut out, &mut run, pair[0]);
            out.push(pair[1]);
            continue;
        }
        let mut c = u as u16;
        if u >= 0x80 {
            if is_decomposable(c) {
                scratch.clear();
                decompose(c, &mut scratch);
                for &d in &scratch {
                    push(&mut out, &mut run, d);
                }
                continue;
            }
            if c == UCS_ALT_NULL {
                c = 0;
            }
        }
        push(&mut out, &mut run, c);
    }
    if run > 1 {
        let n = out.len();
        priority_sort(&mut out[n - run..]);
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
    String::from_utf16_lossy(&normalize_units(name))
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
    let units = normalize_units(name);
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
        // U+AC00 GA (no final) = U+1100 U+1161; last syllable U+D7A3.
        assert_eq!(units("\u{AC00}"), vec![0x1100, 0x1161]);
        assert_eq!(units("\u{D7A3}"), vec![0x1112, 0x1175, 0x11C2]);
        // U+D7A4 is past the syllable block: untouched.
        assert_eq!(units("\u{D7A4}"), vec![0xD7A4]);
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
        // U+1E09 (ḉ) decomposes recursively: C-cedilla + acute.
        assert_eq!(units("\u{1E09}"), vec![0x63, 0x327, 0x301]);
    }

    #[test]
    fn combining_marks_are_reordered() {
        // dot below (220) must precede acute (230).
        assert_eq!(units("a\u{301}\u{323}"), vec![0x61, 0x323, 0x301]);
        // ệ (U+1EC7) = e + dot below + circumflex.
        assert_eq!(units("\u{1EC7}"), vec![0x65, 0x323, 0x302]);
    }

    #[test]
    fn post_3_2_marks_follow_the_kernel() {
        // U+0351 (Unicode 4.0, class 230) is not in the kernel's 3.2-era
        // combining set: it ends the run, so nothing is reordered.
        assert_eq!(units("a\u{351}\u{323}"), vec![0x61, 0x351, 0x323]);
        // U+1DC0 (Unicode 5.0, class 230): same — today's NFD would
        // move the dot below first.
        assert_eq!(units("a\u{1DC0}\u{323}"), vec![0x61, 0x1DC0, 0x323]);
        // Unassigned in 3.2 and later given a decomposition: untouched.
        assert_eq!(units("\u{1B3B}"), vec![0x1B3B]);
    }

    #[test]
    fn alt_null_becomes_nul() {
        assert_eq!(normalize_units("a\u{2400}b"), vec![0x61, 0, 0x62]);
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
