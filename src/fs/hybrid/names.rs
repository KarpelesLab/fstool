//! Per-view name mapping: ECMA-119 d-character identifiers, Joliet UCS-2
//! names and HFS+ catalog names, each with collision resolution inside
//! a directory.

use std::collections::HashSet;

use super::IsoLevel;

/// Outcome of mapping one name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Mapped<T> {
    /// The encoded name.
    pub(crate) value: T,
    /// The name as a reader of the view displays it.
    pub(crate) display: String,
    /// Lossy beyond the view's inherent conventions.
    pub(crate) changed: bool,
    /// Shortened to fit.
    pub(crate) truncated: bool,
}

fn d_char(c: char) -> char {
    match c {
        'A'..='Z' | '0'..='9' | '_' => c,
        'a'..='z' => c.to_ascii_uppercase(),
        _ => '_',
    }
}

/// Split at the last dot not at position 0.
fn split_ext(name: &str) -> (&str, &str) {
    match name.rfind('.') {
        Some(i) if i > 0 => (&name[..i], &name[i + 1..]),
        _ => (name, ""),
    }
}

/// Per-directory allocator of primary (ECMA-119) identifiers.
#[derive(Default)]
pub(crate) struct IsoNamer {
    taken: HashSet<String>,
}

impl IsoNamer {
    /// Map `name` to a d-character identifier unique in this directory.
    /// Files get `NAME.EXT;1`, directories `NAME`.
    pub(crate) fn map(&mut self, name: &str, is_dir: bool, level: IsoLevel) -> Mapped<Vec<u8>> {
        let (max_base, max_ext, max_total) = match (level, is_dir) {
            (IsoLevel::L1, true) => (8, 0, 8),
            (IsoLevel::L1, false) => (8, 3, 11),
            (_, true) => (31, 0, 31),
            (_, false) => (30, 30, 30),
        };
        let (base, ext) = if is_dir { (name, "") } else { split_ext(name) };
        let mut b: String = base.chars().map(d_char).collect();
        let mut e: String = ext.chars().map(d_char).collect();
        let mut truncated = false;
        if e.len() > max_ext {
            e.truncate(max_ext);
            truncated = true;
        }
        let room = max_total - e.len();
        let room = room.min(max_base);
        if b.len() > room {
            b.truncate(room);
            truncated = true;
        }
        if b.is_empty() && e.is_empty() {
            b.push('_');
        }
        let render = |b: &str, e: &str| -> String {
            if is_dir {
                b.to_string()
            } else {
                format!("{b}.{e}")
            }
        };
        let mut ident = render(&b, &e);
        let mut collided = false;
        let mut n = 1u32;
        while self.taken.contains(&ident) {
            collided = true;
            let suffix = format!("_{n}");
            let keep = room.saturating_sub(suffix.len()).min(b.len());
            let mut nb: String = b.chars().take(keep).collect();
            nb.push_str(&suffix);
            ident = render(&nb, &e);
            n += 1;
        }
        self.taken.insert(ident.clone());
        let display = if is_dir {
            ident.clone()
        } else {
            ident.trim_end_matches('.').to_string()
        };
        let changed = collided || truncated || display != name.to_ascii_uppercase();
        let mut bytes = ident.into_bytes();
        if !is_dir {
            bytes.extend_from_slice(b";1");
        }
        Mapped {
            value: bytes,
            display,
            changed,
            truncated,
        }
    }
}

/// Map a primary volume identifier to 32 d-characters.
pub(crate) fn iso_label(label: &str) -> String {
    let mut s: String = label.chars().map(d_char).collect();
    s.truncate(32);
    s
}

/// Per-directory allocator of Joliet names.
#[derive(Default)]
pub(crate) struct JolietNamer {
    taken: HashSet<Vec<u16>>,
}

fn joliet_char(u: u16) -> u16 {
    match u {
        0..=0x1F | 0x2A | 0x2F | 0x3A | 0x3B | 0x3F | 0x5C => u16::from(b'_'),
        _ => u,
    }
}

/// Truncate UTF-16 `units` to `max` without splitting a surrogate pair.
fn cut(units: &mut Vec<u16>, max: usize) {
    if units.len() > max {
        units.truncate(max);
        if let Some(&last) = units.last()
            && (0xD800..0xDC00).contains(&last)
        {
            units.pop();
        }
    }
}

impl JolietNamer {
    /// Map `name` to UCS-2 units unique in this directory, at most `max`
    /// units (64 per the Joliet specification, 103 for "long" Joliet).
    pub(crate) fn map(&mut self, name: &str, max: usize) -> Mapped<Vec<u8>> {
        let (base, ext) = split_ext(name);
        let conv = |s: &str| -> Vec<u16> { s.encode_utf16().map(joliet_char).collect() };
        let mut b = conv(base);
        let e = if ext.is_empty() && !name.ends_with('.') {
            Vec::new()
        } else {
            conv(ext)
        };
        let dotted = !e.is_empty() || (base.len() < name.len());
        let mut truncated = false;
        let render = |b: &[u16], e: &[u16]| -> Vec<u16> {
            let mut v = b.to_vec();
            if dotted {
                v.push(u16::from(b'.'));
                v.extend_from_slice(e);
            }
            v
        };
        let mut units = render(&b, &e);
        if units.len() > max {
            truncated = true;
            let keep = max.saturating_sub(e.len() + usize::from(dotted));
            if keep == 0 {
                cut(&mut units, max);
            } else {
                cut(&mut b, keep);
                units = render(&b, &e);
            }
        }
        let mut n = 1u32;
        let mut collided = false;
        while self.taken.contains(&units) {
            collided = true;
            let suffix: Vec<u16> = format!("_{n}").encode_utf16().collect();
            let mut nb = b.clone();
            let keep = max.saturating_sub(e.len() + usize::from(dotted) + suffix.len());
            cut(&mut nb, keep);
            nb.extend_from_slice(&suffix);
            units = render(&nb, &e);
            cut(&mut units, max);
            n += 1;
        }
        self.taken.insert(units.clone());
        let display = String::from_utf16_lossy(&units);
        Mapped {
            changed: collided || truncated || display != name,
            truncated,
            display,
            value: units.iter().flat_map(|u| u.to_be_bytes()).collect(),
        }
    }
}

/// Map a Joliet volume identifier to at most 16 UCS-2 units.
pub(crate) fn joliet_label(label: &str) -> String {
    let mut u: Vec<u16> = label.encode_utf16().collect();
    cut(&mut u, 16);
    String::from_utf16_lossy(&u)
}

/// Per-directory allocator of HFS+ names, colliding the way the catalog
/// does (case-insensitively on plain HFS+, after normalisation).
pub(crate) struct HfsNamer {
    taken: HashSet<Vec<u16>>,
    case_sensitive: bool,
}

impl HfsNamer {
    pub(crate) fn new(case_sensitive: bool) -> Self {
        Self {
            taken: HashSet::new(),
            case_sensitive,
        }
    }

    fn key(&self, name: &str) -> Vec<u16> {
        let units = crate::fs::hfs_plus::unicode::normalize_units(&name.replace(':', "/"));
        crate::fs::hfs_plus::catalog::sort_units(
            &crate::fs::hfs_plus::catalog::UniStr { code_units: units },
            self.case_sensitive,
        )
    }

    fn fits(name: &str) -> bool {
        crate::fs::hfs_plus::unicode::normalize_units(&name.replace(':', "/")).len()
            <= crate::fs::hfs_plus::unicode::MAX_NAME_UNITS
    }

    /// Map `name` to a catalog name (POSIX spelling: `:` is fine, the
    /// writer swaps it for the catalog's `/`) unique in this directory.
    pub(crate) fn map(&mut self, name: &str) -> Mapped<String> {
        let (base, ext) = split_ext(name);
        let dotted = !ext.is_empty();
        let render = |b: &str| -> String {
            if dotted {
                format!("{b}.{ext}")
            } else {
                b.to_string()
            }
        };
        let mut b = base.to_string();
        let mut truncated = false;
        let mut cand = name.to_string();
        while !Self::fits(&cand) {
            truncated = true;
            if b.pop().is_none() {
                // The extension alone is too long: cut the whole name.
                let mut c = cand.clone();
                while !Self::fits(&c) {
                    c.pop();
                }
                cand = c;
                break;
            }
            cand = render(&b);
        }
        let mut n = 2u32;
        let mut collided = false;
        let stem = if truncated && b.is_empty() {
            cand.clone()
        } else {
            b.clone()
        };
        while self.taken.contains(&self.key(&cand)) {
            collided = true;
            let mut nb = stem.clone();
            loop {
                let c = if truncated && b.is_empty() {
                    format!("{nb} {n}")
                } else {
                    render(&format!("{nb} {n}"))
                };
                if Self::fits(&c) || nb.pop().is_none() {
                    cand = c;
                    break;
                }
            }
            n += 1;
        }
        let k = self.key(&cand);
        self.taken.insert(k);
        Mapped {
            changed: collided || truncated,
            truncated,
            display: cand.clone(),
            value: cand,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level1_is_eight_dot_three_and_unique() {
        let mut n = IsoNamer::default();
        let a = n.map("readme.markdown", false, IsoLevel::L1);
        assert_eq!(a.value, b"README.MAR;1");
        assert!(a.changed && a.truncated);
        let b = n.map("readme.markdown2", false, IsoLevel::L1);
        assert_eq!(b.value, b"README_1.MAR;1");
        let c = n.map("Makefile", false, IsoLevel::L1);
        assert_eq!(c.value, b"MAKEFILE.;1");
        assert_eq!(c.display, "MAKEFILE");
        assert!(!c.changed);
        let d = n.map("a very long directory", true, IsoLevel::L1);
        assert_eq!(d.value, b"A_VERY_L");
        let e = n.map(".hidden", false, IsoLevel::L2);
        assert_eq!(e.value, b"_HIDDEN.;1");
        let f = n.map("naïve.txt", false, IsoLevel::L2);
        assert_eq!(f.value, b"NA_VE.TXT;1");
    }

    #[test]
    fn joliet_keeps_unicode_and_bounds_length() {
        let mut n = JolietNamer::default();
        let a = n.map("naïve file.txt", 64);
        assert_eq!(a.display, "naïve file.txt");
        assert!(!a.changed);
        let long = format!("{}.txt", "x".repeat(80));
        let b = n.map(&long, 64);
        assert_eq!(b.display.encode_utf16().count(), 64);
        assert!(b.display.ends_with(".txt") && b.truncated);
        let c = n.map(&long, 64);
        assert_ne!(c.display, b.display);
        assert!(c.display.ends_with("_1.txt"));
        assert_eq!(n.map("a;b?.txt", 64).display, "a_b_.txt");
        // A surrogate pair is never split.
        let emoji = "\u{1F600}".repeat(40);
        let d = n.map(&emoji, 64);
        assert!(!d.display.contains('\u{FFFD}'));
    }

    #[test]
    fn hfs_collides_case_insensitively() {
        let mut n = HfsNamer::new(false);
        assert_eq!(n.map("README").value, "README");
        let b = n.map("readme");
        assert_eq!(b.value, "readme 2");
        assert!(b.changed);
        let mut cs = HfsNamer::new(true);
        cs.map("README");
        assert_eq!(cs.map("readme").value, "readme");
        let long = format!("{}.txt", "é".repeat(200));
        let t = n.map(&long);
        assert!(t.truncated && t.value.ends_with(".txt"));
        assert!(HfsNamer::fits(&t.value));
    }
}
