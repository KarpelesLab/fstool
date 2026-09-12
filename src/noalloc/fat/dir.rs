//! Directories: the 32-byte entry, long names, lookup, creation, removal
//! and listing — all without allocating.
//!
//! Two things shape this code. First, a long name is spread over up to 20
//! entries that precede the short one, stored in descending ordinal order,
//! so a forward scan sees the *last* chunk of the name first. Second,
//! there is nowhere to put a name while scanning: the buffers a lookup
//! would need are exactly what a no-alloc driver cannot have. So lookup
//! never materialises a name — it compares each long-name chunk against
//! the slice of the target it covers, which its ordinal gives away — and
//! only [`DirIter`], whose caller has already paid for the buffer, builds
//! a `&str`.

use super::boot::Geometry;
use super::{Attributes, Dir, EntryLoc, Error, FatKind, Metadata, SectorDriver, Timestamp, Volume};

/// Bytes in a directory entry.
const ENTRY: usize = 32;

/// UTF-16 units a long name can hold.
pub(crate) const MAX_NAME_UNITS: usize = 255;

/// UTF-8 bytes those units can need (three per unit, plus room for a
/// replacement character per unpaired surrogate).
pub(crate) const MAX_NAME_BYTES: usize = MAX_NAME_UNITS * 3;

/// UTF-16 units in one long-name entry.
const LFN_CHUNK: usize = 13;

/// Long-name entries needed for the longest name, plus the short entry.
const MAX_SLOTS: usize = MAX_NAME_UNITS.div_ceil(LFN_CHUNK) + 1;

/// Marks the entry carrying the final chunk of a name.
const LAST_LONG_ENTRY: u8 = 0x40;

/// `name[0]` of a deleted entry.
const DELETED: u8 = 0xE5;

/// `name[0]` of a never-used entry, which also ends the directory.
const END: u8 = 0x00;

/// CP437's upper half, the default OEM code page short names are written
/// in. Without it, every accented character on a DOS-era volume with no
/// long names would read as a replacement character.
#[rustfmt::skip]
const CP437_HIGH: [char; 128] = [
    'Ç', 'ü', 'é', 'â', 'ä', 'à', 'å', 'ç', 'ê', 'ë', 'è', 'ï', 'î', 'ì', 'Ä', 'Å',
    'É', 'æ', 'Æ', 'ô', 'ö', 'ò', 'û', 'ù', 'ÿ', 'Ö', 'Ü', '¢', '£', '¥', '₧', 'ƒ',
    'á', 'í', 'ó', 'ú', 'ñ', 'Ñ', 'ª', 'º', '¿', '⌐', '¬', '½', '¼', '¡', '«', '»',
    '░', '▒', '▓', '│', '┤', '╡', '╢', '╖', '╕', '╣', '║', '╗', '╝', '╜', '╛', '┐',
    '└', '┴', '┬', '├', '─', '┼', '╞', '╟', '╚', '╔', '╩', '╦', '╠', '═', '╬', '╧',
    '╨', '╤', '╥', '╙', '╘', '╒', '╓', '╫', '╪', '┘', '┌', '█', '▄', '▌', '▐', '▀',
    'α', 'ß', 'Γ', 'π', 'Σ', 'σ', 'µ', 'τ', 'Φ', 'Θ', 'Ω', 'δ', '∞', 'φ', 'ε', '∩',
    '≡', '±', '≥', '≤', '⌠', '⌡', '÷', '≈', '°', '∙', '·', '√', 'ⁿ', '²', '■', '\u{a0}',
];

/// Characters a short name may not contain (beyond the control range).
const SHORT_INVALID: &[u8] = b"\"*+,./:;<=>?[\\]|";

/// Characters a long name may not contain.
const LONG_INVALID: &[u8] = b"\"*/:<>?\\|";

/// The checksum every long-name entry of a run carries, computed over the
/// short name it belongs to.
fn lfn_checksum(short: &[u8; 11]) -> u8 {
    let mut sum = 0u8;
    for &b in short.iter() {
        sum = sum.rotate_right(1).wrapping_add(b);
    }
    sum
}

/// Push one `char` as UTF-8, returning how many bytes it took (0 when it
/// would not fit).
fn push_char(out: &mut [u8], at: usize, c: char) -> usize {
    let mut tmp = [0u8; 4];
    let s = c.encode_utf8(&mut tmp);
    if at + s.len() > out.len() {
        return 0;
    }
    out[at..at + s.len()].copy_from_slice(s.as_bytes());
    s.len()
}

/// Decode one OEM (CP437) byte.
fn oem_char(b: u8) -> char {
    if b < 0x80 {
        b as char
    } else {
        CP437_HIGH[(b - 0x80) as usize]
    }
}

/// ASCII-only case folding, matching the hosted driver's rule.
fn fold(c: char) -> char {
    if c.is_ascii() {
        c.to_ascii_uppercase()
    } else {
        c
    }
}

/// Write a short name into `out` as `BASE.EXT`, honouring the two NT
/// case flags, and return its length in bytes.
fn short_name(raw: &[u8; ENTRY], out: &mut [u8]) -> usize {
    let nt = raw[12];
    let lower_base = nt & 0x08 != 0;
    let lower_ext = nt & 0x10 != 0;
    let mut at = 0;

    let base_len = (0..8).rev().find(|&i| raw[i] != b' ').map_or(0, |i| i + 1);
    for i in 0..base_len {
        // 0x05 in the first byte stands for a leading 0xE5, which would
        // otherwise read as "deleted".
        let b = if i == 0 && raw[0] == 0x05 {
            0xE5
        } else {
            raw[i]
        };
        let c = oem_char(b);
        let c = if lower_base {
            c.to_lowercase().next().unwrap_or(c)
        } else {
            c
        };
        at += push_char(out, at, c);
    }

    let ext_len = (8..11).rev().find(|&i| raw[i] != b' ').map_or(0, |i| i - 7);
    if ext_len > 0 {
        at += push_char(out, at, '.');
        for &b in raw.iter().skip(8).take(ext_len) {
            let c = oem_char(b);
            let c = if lower_ext {
                c.to_lowercase().next().unwrap_or(c)
            } else {
                c
            };
            at += push_char(out, at, c);
        }
    }
    at
}

/// The 13 UTF-16 units a long-name entry carries.
fn lfn_units(raw: &[u8; ENTRY]) -> [u16; LFN_CHUNK] {
    let mut units = [0u16; LFN_CHUNK];
    // 5 units at 1, 6 at 14, 2 at 28 — the layout works around the fields
    // a short entry would have at 11..13 and 26..28.
    const SPANS: [(usize, usize); 3] = [(1, 5), (14, 6), (28, 2)];
    let mut n = 0;
    for (off, count) in SPANS {
        for i in 0..count {
            let at = off + i * 2;
            units[n] = u16::from_le_bytes([raw[at], raw[at + 1]]);
            n += 1;
        }
    }
    units
}

/// Store 13 UTF-16 units into a long-name entry.
fn set_lfn_units(raw: &mut [u8; ENTRY], units: &[u16; LFN_CHUNK]) {
    const SPANS: [(usize, usize); 3] = [(1, 5), (14, 6), (28, 2)];
    let mut n = 0;
    for (off, count) in SPANS {
        for i in 0..count {
            let at = off + i * 2;
            raw[at..at + 2].copy_from_slice(&units[n].to_le_bytes());
            n += 1;
        }
    }
}

/// How many of a chunk's units belong to the name: everything before the
/// first NUL terminator, with 0xFFFF as padding.
fn chunk_len(units: &[u16; LFN_CHUNK]) -> usize {
    units
        .iter()
        .position(|&u| u == 0 || u == 0xFFFF)
        .unwrap_or(LFN_CHUNK)
}

/// Decode a short entry's metadata. `loc` is where the entry lives.
fn decode_short(raw: &[u8; ENTRY], kind: FatKind, loc: EntryLoc) -> Metadata {
    let attrs = Attributes(raw[11]);
    let lo = u16::from_le_bytes([raw[26], raw[27]]) as u32;
    // The high half is reserved on FAT12/FAT16 (OS/2 stored an EA handle
    // there), so only FAT32 may read it.
    let hi = if kind == FatKind::Fat32 {
        u16::from_le_bytes([raw[20], raw[21]]) as u32
    } else {
        0
    };
    Metadata {
        attrs,
        len: u32::from_le_bytes([raw[28], raw[29], raw[30], raw[31]]),
        created: Timestamp {
            date: u16::from_le_bytes([raw[16], raw[17]]),
            time: u16::from_le_bytes([raw[14], raw[15]]),
            tenths: raw[13],
        },
        modified: Timestamp {
            date: u16::from_le_bytes([raw[24], raw[25]]),
            time: u16::from_le_bytes([raw[22], raw[23]]),
            tenths: 0,
        },
        first_cluster: (hi << 16) | lo,
        loc,
    }
}

/// True when the entry is a long-name fragment rather than a file.
fn is_lfn(raw: &[u8; ENTRY]) -> bool {
    raw[11] == Attributes::LONG_NAME
}

/// Whether `name` is a valid long name, and how many UTF-16 units it
/// needs.
fn check_long_name(name: &str) -> Option<usize> {
    if name.is_empty() || name == "." || name == ".." {
        return None;
    }
    // Trailing dots and spaces cannot be stored faithfully.
    if name.ends_with(' ') || name.ends_with('.') {
        return None;
    }
    let mut units = 0;
    for c in name.chars() {
        if (c as u32) < 0x20 || (c.is_ascii() && LONG_INVALID.contains(&(c as u8))) {
            return None;
        }
        units += c.len_utf16();
    }
    if units > MAX_NAME_UNITS {
        return None;
    }
    Some(units)
}

/// Try to express `name` as a short name, returning the 11 padded bytes
/// and the NT case flags. `None` when it needs a long name.
fn try_short_name(name: &str) -> Option<([u8; 11], u8)> {
    if name.is_empty() || name.len() > 12 {
        return None;
    }
    let (base, ext) = match name.rsplit_once('.') {
        // A name may not start with the dot that separates the extension.
        Some(("", _)) => return None,
        Some((b, e)) => (b, e),
        None => (name, ""),
    };
    if base.is_empty() || base.len() > 8 || ext.len() > 3 {
        return None;
    }

    let mut out = [b' '; 11];
    let mut flags = 0u8;
    for (part, span, lower_flag) in [(base, 0..8, 0x08u8), (ext, 8..11, 0x10u8)] {
        if part.is_empty() {
            continue;
        }
        let mut seen_lower = false;
        let mut seen_upper = false;
        for (i, c) in part.chars().enumerate() {
            if !c.is_ascii() {
                return None;
            }
            let b = c as u8;
            if b <= 0x20 || SHORT_INVALID.contains(&b) {
                return None;
            }
            if c.is_ascii_lowercase() {
                seen_lower = true;
            }
            if c.is_ascii_uppercase() {
                seen_upper = true;
            }
            out[span.start + i] = b.to_ascii_uppercase();
        }
        // A part that mixes cases cannot be recovered from one flag.
        if seen_lower && seen_upper {
            return None;
        }
        if seen_lower {
            flags |= lower_flag;
        }
    }
    Some((out, flags))
}

/// Build the 11 short-name bytes for `name`'s basis, before the `~N` tail
/// is applied: uppercase, invalid characters replaced, spaces and extra
/// dots dropped.
fn short_basis(name: &str) -> ([u8; 11], usize) {
    let stripped = name.trim_matches(|c| c == ' ' || c == '.');
    let (base, ext) = match stripped.rsplit_once('.') {
        Some((b, e)) if !b.is_empty() => (b, e),
        _ => (stripped, ""),
    };
    let mut out = [b' '; 11];
    let mut base_len = 0;
    for c in base.chars() {
        if base_len == 8 {
            break;
        }
        if c == ' ' || c == '.' {
            continue;
        }
        let b = if c.is_ascii() && !SHORT_INVALID.contains(&(c as u8)) && (c as u32) >= 0x20 {
            (c as u8).to_ascii_uppercase()
        } else {
            b'_'
        };
        out[base_len] = b;
        base_len += 1;
    }
    if base_len == 0 {
        out[0] = b'_';
        base_len = 1;
    }
    let mut ext_len = 0;
    for c in ext.chars() {
        if ext_len == 3 {
            break;
        }
        if c == ' ' || c == '.' {
            continue;
        }
        let b = if c.is_ascii() && !SHORT_INVALID.contains(&(c as u8)) && (c as u32) >= 0x20 {
            (c as u8).to_ascii_uppercase()
        } else {
            b'_'
        };
        out[8 + ext_len] = b;
        ext_len += 1;
    }
    (out, base_len)
}

/// Splice `~n` into a short-name basis.
fn apply_tail(basis: &[u8; 11], base_len: usize, n: u32) -> [u8; 11] {
    let mut digits = [0u8; 7];
    let mut len = 0;
    let mut v = n;
    while v > 0 && len < digits.len() {
        digits[len] = b'0' + (v % 10) as u8;
        v /= 10;
        len += 1;
    }
    let mut out = *basis;
    // "~" + digits has to fit in the 8-byte base.
    let keep = base_len.min(8 - (len + 1));
    out[keep] = b'~';
    for i in 0..len {
        out[keep + 1 + i] = digits[len - 1 - i];
    }
    for slot in out.iter_mut().take(8).skip(keep + 1 + len) {
        *slot = b' ';
    }
    out
}

/// Walks the sectors a directory occupies, following the cluster chain
/// when it has one.
pub(crate) struct DirSectors {
    fixed: bool,
    /// Fixed root: the next sector, and how many are left.
    next_fixed: u32,
    fixed_left: u32,
    /// Chain: the cluster we are in and how far into it we have gone.
    cluster: u32,
    in_cluster: u32,
    done: bool,
}

impl DirSectors {
    pub(crate) fn new(geom: &Geometry, dir: &Dir) -> Self {
        Self {
            fixed: dir.fixed_root,
            next_fixed: geom.root_dir_first_sector(),
            fixed_left: geom.root_dir_sectors,
            cluster: dir.first_cluster,
            in_cluster: 0,
            done: dir.first_cluster == 0 && !dir.fixed_root,
        }
    }

    /// The next volume-relative sector, or `None` at the end.
    pub(crate) fn next<D: SectorDriver, const S: usize>(
        &mut self,
        vol: &mut Volume<D, S>,
    ) -> Result<Option<u32>, Error<D::Error>> {
        if self.done {
            return Ok(None);
        }
        if self.fixed {
            if self.fixed_left == 0 {
                self.done = true;
                return Ok(None);
            }
            let sector = self.next_fixed;
            self.next_fixed += 1;
            self.fixed_left -= 1;
            return Ok(Some(sector));
        }
        let spc = vol.geom.sectors_per_cluster;
        if self.in_cluster == spc {
            match vol.next_cluster(self.cluster)? {
                Some(next) => {
                    self.cluster = next;
                    self.in_cluster = 0;
                }
                None => {
                    self.done = true;
                    return Ok(None);
                }
            }
        }
        if !vol.geom.is_data_cluster(self.cluster) {
            return Err(Error::CorruptChain);
        }
        let sector = vol.geom.cluster_first_sector(self.cluster) + self.in_cluster;
        self.in_cluster += 1;
        Ok(Some(sector))
    }

    /// The cluster the walker is currently in (meaningless for a fixed
    /// root).
    fn current_cluster(&self) -> u32 {
        self.cluster
    }
}

/// Accumulated long-name state during a forward scan, plus the locations
/// of the entries it came from so a removal can mark them all.
struct LfnRun {
    /// Still a consistent run.
    valid: bool,
    checksum: u8,
    /// The ordinal we expect next, counting down.
    expect: u8,
    /// Units in the whole name, known from the last-entry flag.
    units: usize,
    /// Whether every chunk so far matched the name we are looking for.
    matches: bool,
    slots: [EntryLoc; MAX_SLOTS],
    slot_count: usize,
}

impl LfnRun {
    fn new() -> Self {
        Self {
            valid: false,
            checksum: 0,
            expect: 0,
            units: 0,
            matches: false,
            slots: [EntryLoc::NONE; MAX_SLOTS],
            slot_count: 0,
        }
    }

    fn reset(&mut self) {
        self.valid = false;
        self.matches = false;
        self.units = 0;
        self.slot_count = 0;
    }

    /// Feed one long-name entry. `target` is the name being looked for, or
    /// `None` when the caller only wants the run's extent.
    fn feed(&mut self, raw: &[u8; ENTRY], loc: EntryLoc, target: Option<&str>) {
        let ord = raw[0] & !LAST_LONG_ENTRY;
        let last = raw[0] & LAST_LONG_ENTRY != 0;
        if ord == 0 || ord as usize > MAX_SLOTS - 1 {
            self.reset();
            return;
        }
        if last {
            // A new run starts here.
            self.reset();
            self.valid = true;
            self.matches = target.is_some();
            self.checksum = raw[13];
            self.expect = ord;
            self.units = (ord as usize - 1) * LFN_CHUNK + chunk_len(&lfn_units(raw));
            if let Some(name) = target {
                // The total length has to agree before any chunk can.
                self.matches = name.encode_utf16().count() == self.units;
            }
        } else if !self.valid || self.expect != ord || self.checksum != raw[13] {
            self.reset();
            return;
        }

        if self.slot_count < MAX_SLOTS {
            self.slots[self.slot_count] = loc;
            self.slot_count += 1;
        } else {
            self.reset();
            return;
        }

        if let (true, Some(name)) = (self.matches, target) {
            let start = (ord as usize - 1) * LFN_CHUNK;
            let units = lfn_units(raw);
            let have = chunk_len(&units);
            let mut want = name.encode_utf16().skip(start);
            for &unit in units.iter().take(have) {
                match want.next() {
                    Some(u) => {
                        let a = char::from_u32(unit as u32).map(fold);
                        let b = char::from_u32(u as u32).map(fold);
                        // Surrogate halves compare as raw units.
                        let same = match (a, b) {
                            (Some(a), Some(b)) => a == b,
                            _ => unit == u,
                        };
                        if !same {
                            self.matches = false;
                            break;
                        }
                    }
                    None => {
                        self.matches = false;
                        break;
                    }
                }
            }
        }
        self.expect = ord.saturating_sub(1);
    }

    /// Whether a complete run for the target ends at this short entry.
    fn matched(&self, raw: &[u8; ENTRY]) -> bool {
        self.valid
            && self.matches
            && self.expect == 0
            && self.checksum
                == lfn_checksum(raw[..11].try_into().expect("11 bytes of a 32-byte entry"))
    }
}

/// What a scan found.
struct Found {
    meta: Metadata,
    /// The long-name entries preceding the short one, if any.
    slots: [EntryLoc; MAX_SLOTS],
    slot_count: usize,
}

impl<D: SectorDriver, const S: usize> Volume<D, S> {
    /// Read one 32-byte entry.
    fn entry_bytes(&mut self, loc: EntryLoc) -> Result<[u8; ENTRY], Error<D::Error>> {
        let at = loc.offset as usize;
        let sector = self.sector(loc.sector)?;
        let mut raw = [0u8; ENTRY];
        raw.copy_from_slice(&sector[at..at + ENTRY]);
        Ok(raw)
    }

    /// Overwrite one 32-byte entry.
    fn set_entry_bytes(&mut self, loc: EntryLoc, raw: &[u8; ENTRY]) -> Result<(), Error<D::Error>> {
        let at = loc.offset as usize;
        let sector = self.sector_mut(loc.sector)?;
        sector[at..at + ENTRY].copy_from_slice(raw);
        Ok(())
    }

    /// Find `name` in `dir`.
    fn scan(&mut self, dir: &Dir, name: &str) -> Result<Option<Found>, Error<D::Error>> {
        let mut sectors = DirSectors::new(&self.geom, dir);
        let mut run = LfnRun::new();
        let per_sector = self.bps() / ENTRY;

        while let Some(sector) = sectors.next(self)? {
            for i in 0..per_sector {
                let loc = EntryLoc {
                    sector,
                    offset: (i * ENTRY) as u16,
                };
                let raw = self.entry_bytes(loc)?;
                if raw[0] == END {
                    return Ok(None);
                }
                if raw[0] == DELETED {
                    run.reset();
                    continue;
                }
                if is_lfn(&raw) {
                    run.feed(&raw, loc, Some(name));
                    continue;
                }
                // A short entry: either the long run that just ended
                // names our target, or its own 8.3 name might.
                let hit = run.matched(&raw) || short_name_matches(&raw, name);
                if hit && !Attributes(raw[11]).is_volume_id() {
                    return Ok(Some(Found {
                        meta: decode_short(&raw, self.geom.kind, loc),
                        slots: run.slots,
                        slot_count: if run.matched(&raw) { run.slot_count } else { 0 },
                    }));
                }
                run.reset();
            }
        }
        Ok(None)
    }

    /// Whether any entry in `dir` already carries this exact short name.
    fn short_name_taken(&mut self, dir: &Dir, short: &[u8; 11]) -> Result<bool, Error<D::Error>> {
        let mut sectors = DirSectors::new(&self.geom, dir);
        let per_sector = self.bps() / ENTRY;
        while let Some(sector) = sectors.next(self)? {
            for i in 0..per_sector {
                let loc = EntryLoc {
                    sector,
                    offset: (i * ENTRY) as u16,
                };
                let raw = self.entry_bytes(loc)?;
                if raw[0] == END {
                    return Ok(false);
                }
                if raw[0] == DELETED || is_lfn(&raw) {
                    continue;
                }
                if raw[..11] == short[..] {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Resolve `path`'s parent directory, returning it and the final
    /// component. `path` may start with `/`; `.` and `..` are refused.
    fn split_path<'p>(&mut self, path: &'p str) -> Result<(Dir, &'p str), Error<D::Error>> {
        let trimmed = path.trim_start_matches('/');
        let trimmed = trimmed.trim_end_matches('/');
        if trimmed.is_empty() {
            return Err(Error::InvalidPath);
        }
        let (parent_path, leaf) = match trimmed.rsplit_once('/') {
            Some((p, l)) => (p, l),
            None => ("", trimmed),
        };
        if leaf.is_empty() {
            return Err(Error::InvalidPath);
        }
        let dir = self.open_dir(parent_path)?;
        Ok((dir, leaf))
    }

    /// Open a directory by path. `""` and `"/"` are the root.
    pub fn open_dir(&mut self, path: &str) -> Result<Dir, Error<D::Error>> {
        let mut dir = self.root();
        for component in path.split('/').filter(|c| !c.is_empty()) {
            if component == "." || component == ".." {
                return Err(Error::InvalidPath);
            }
            let found = self.scan(&dir, component)?.ok_or(Error::NotFound)?;
            if !found.meta.is_dir() {
                return Err(Error::NotADirectory);
            }
            dir = Dir {
                first_cluster: found.meta.first_cluster,
                fixed_root: false,
                loc: found.meta.loc,
            };
        }
        Ok(dir)
    }

    /// Metadata for `path`. `"/"` reports the root.
    pub fn metadata(&mut self, path: &str) -> Result<Metadata, Error<D::Error>> {
        if path.trim_matches('/').is_empty() {
            return Ok(Metadata {
                attrs: Attributes(Attributes::DIRECTORY),
                len: 0,
                created: Timestamp::default(),
                modified: Timestamp::default(),
                first_cluster: self.root().first_cluster,
                loc: EntryLoc::NONE,
            });
        }
        let (dir, leaf) = self.split_path(path)?;
        Ok(self.scan(&dir, leaf)?.ok_or(Error::NotFound)?.meta)
    }

    /// Whether `path` exists.
    pub fn exists(&mut self, path: &str) -> Result<bool, Error<D::Error>> {
        match self.metadata(path) {
            Ok(_) => Ok(true),
            Err(Error::NotFound) | Err(Error::NotADirectory) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Append one zeroed cluster to `dir`'s chain and return its first
    /// sector. Fails for a fixed root, which cannot grow.
    fn extend_dir(&mut self, dir: &Dir) -> Result<u32, Error<D::Error>> {
        if dir.fixed_root {
            return Err(Error::DirectoryFull);
        }
        // Walk to the end of the chain.
        let mut last = dir.first_cluster;
        if !self.geom.is_data_cluster(last) {
            return Err(Error::CorruptChain);
        }
        while let Some(next) = self.next_cluster(last)? {
            last = next;
        }
        let cluster = self.alloc_zeroed_cluster(Some(last))?;
        Ok(self.geom.cluster_first_sector(cluster))
    }

    /// Find `count` consecutive free entry slots in `dir`, extending it
    /// when there is no such run.
    ///
    /// A never-used slot (`0x00`) both marks a free entry *and* ends the
    /// directory: every reader stops there. So a run may only be placed
    /// over deleted entries, or from the first never-used slot onward —
    /// never straddling one, which would strand everything written after
    /// it behind a terminator.
    fn find_slots(
        &mut self,
        dir: &Dir,
        count: usize,
    ) -> Result<[EntryLoc; MAX_SLOTS], Error<D::Error>> {
        let mut out = [EntryLoc::NONE; MAX_SLOTS];
        let mut have = 0usize;
        let per_sector = self.bps() / ENTRY;
        let mut sectors = DirSectors::new(&self.geom, dir);
        let mut terminator: Option<(u32, usize)> = None;

        // A run of deleted entries is the cheapest place to put this.
        'scan: while let Some(sector) = sectors.next(self)? {
            for i in 0..per_sector {
                let loc = EntryLoc {
                    sector,
                    offset: (i * ENTRY) as u16,
                };
                let first = self.entry_bytes(loc)?[0];
                if first == END {
                    terminator = Some((sector, i));
                    break 'scan;
                }
                if first == DELETED {
                    out[have] = loc;
                    have += 1;
                    if have == count {
                        return Ok(out);
                    }
                } else {
                    have = 0;
                }
            }
        }

        // Otherwise start at the terminator: from there to the end of the
        // directory every slot is free, and the walk continues into the
        // clusters that follow.
        have = 0;
        if let Some((sector, slot)) = terminator {
            for i in slot..per_sector {
                out[have] = EntryLoc {
                    sector,
                    offset: (i * ENTRY) as u16,
                };
                have += 1;
                if have == count {
                    return Ok(out);
                }
            }
            while let Some(sector) = sectors.next(self)? {
                for i in 0..per_sector {
                    out[have] = EntryLoc {
                        sector,
                        offset: (i * ENTRY) as u16,
                    };
                    have += 1;
                    if have == count {
                        return Ok(out);
                    }
                }
            }
        }

        // The directory has run out: grow it. A fresh cluster is zeroed,
        // so its slots are free and follow the ones above in chain order.
        while have < count {
            let first = self.extend_dir(dir)?;
            for n in 0..self.geom.sectors_per_cluster {
                for i in 0..per_sector {
                    out[have] = EntryLoc {
                        sector: first + n,
                        offset: (i * ENTRY) as u16,
                    };
                    have += 1;
                    if have == count {
                        return Ok(out);
                    }
                }
            }
        }
        Ok(out)
    }

    /// Write a new entry for `name` into `dir`, with the long-name run it
    /// needs, and return where the short entry landed.
    fn add_entry(
        &mut self,
        dir: &Dir,
        name: &str,
        attrs: u8,
        first_cluster: u32,
        len: u32,
    ) -> Result<EntryLoc, Error<D::Error>> {
        let units = check_long_name(name).ok_or(Error::InvalidName)?;

        // A name that fits 8.3 needs no long-name entries at all.
        let (short, nt_flags, lfn_slots) = match try_short_name(name) {
            Some((short, flags)) => (short, flags, 0usize),
            None => {
                let (basis, base_len) = short_basis(name);
                let mut chosen = None;
                for n in 1..=999_999u32 {
                    let candidate = apply_tail(&basis, base_len, n);
                    if !self.short_name_taken(dir, &candidate)? {
                        chosen = Some(candidate);
                        break;
                    }
                }
                (
                    chosen.ok_or(Error::DirectoryFull)?,
                    0,
                    units.div_ceil(LFN_CHUNK),
                )
            }
        };

        let total = lfn_slots + 1;
        let slots = self.find_slots(dir, total)?;
        let checksum = lfn_checksum(&short);

        // Long-name entries come first, highest ordinal first.
        for (slot, &where_) in slots.iter().enumerate().take(lfn_slots) {
            let ord = (lfn_slots - slot) as u8;
            let start = (ord as usize - 1) * LFN_CHUNK;
            let mut units_buf = [0xFFFFu16; LFN_CHUNK];
            let mut it = name.encode_utf16().skip(start);
            let mut n = 0;
            while n < LFN_CHUNK {
                match it.next() {
                    Some(u) => units_buf[n] = u,
                    None => {
                        // NUL-terminate, then pad with 0xFFFF.
                        units_buf[n] = 0;
                        break;
                    }
                }
                n += 1;
            }
            let mut raw = [0u8; ENTRY];
            raw[0] = ord | if slot == 0 { LAST_LONG_ENTRY } else { 0 };
            raw[11] = Attributes::LONG_NAME;
            raw[13] = checksum;
            set_lfn_units(&mut raw, &units_buf);
            self.set_entry_bytes(where_, &raw)?;
        }

        let mut raw = [0u8; ENTRY];
        raw[..11].copy_from_slice(&short);
        raw[11] = attrs;
        raw[12] = nt_flags;
        raw[13] = self.now.tenths;
        raw[14..16].copy_from_slice(&self.now.time.to_le_bytes());
        raw[16..18].copy_from_slice(&self.now.date.to_le_bytes());
        raw[18..20].copy_from_slice(&self.now.date.to_le_bytes());
        raw[20..22].copy_from_slice(&((first_cluster >> 16) as u16).to_le_bytes());
        raw[22..24].copy_from_slice(&self.now.time.to_le_bytes());
        raw[24..26].copy_from_slice(&self.now.date.to_le_bytes());
        raw[26..28].copy_from_slice(&(first_cluster as u16).to_le_bytes());
        raw[28..32].copy_from_slice(&len.to_le_bytes());
        let loc = slots[lfn_slots];
        self.set_entry_bytes(loc, &raw)?;
        Ok(loc)
    }

    /// Mark an entry and its long-name run deleted.
    fn delete_entry(&mut self, found: &Found) -> Result<(), Error<D::Error>> {
        for i in 0..found.slot_count {
            let loc = found.slots[i];
            let mut raw = self.entry_bytes(loc)?;
            raw[0] = DELETED;
            self.set_entry_bytes(loc, &raw)?;
        }
        let mut raw = self.entry_bytes(found.meta.loc)?;
        raw[0] = DELETED;
        self.set_entry_bytes(found.meta.loc, &raw)
    }

    /// Create an empty file and return a handle to it.
    pub fn create_file(&mut self, path: &str) -> Result<super::File, Error<D::Error>> {
        let (dir, leaf) = self.split_path(path)?;
        if self.scan(&dir, leaf)?.is_some() {
            return Err(Error::AlreadyExists);
        }
        let loc = self.add_entry(&dir, leaf, Attributes::ARCHIVE, 0, 0)?;
        Ok(super::File::new(0, 0, loc))
    }

    /// Open an existing file for reading and writing.
    pub fn open_file(&mut self, path: &str) -> Result<super::File, Error<D::Error>> {
        let meta = self.metadata(path)?;
        if meta.is_dir() {
            return Err(Error::IsADirectory);
        }
        Ok(super::File::new(meta.first_cluster, meta.len, meta.loc))
    }

    /// Open `path`, creating it if it does not exist.
    pub fn open_or_create_file(&mut self, path: &str) -> Result<super::File, Error<D::Error>> {
        match self.open_file(path) {
            Err(Error::NotFound) => self.create_file(path),
            other => other,
        }
    }

    /// Create a directory, with the `.` and `..` entries FAT requires.
    pub fn create_dir(&mut self, path: &str) -> Result<Dir, Error<D::Error>> {
        let (parent, leaf) = self.split_path(path)?;
        if self.scan(&parent, leaf)?.is_some() {
            return Err(Error::AlreadyExists);
        }
        let cluster = self.alloc_zeroed_cluster(None)?;

        // `..` must hold 0 when the parent is the root, even on FAT32.
        let parent_cluster = if parent.fixed_root || (!parent.fixed_root && parent.loc.is_none()) {
            0
        } else {
            parent.first_cluster
        };
        let first_sector = self.geom.cluster_first_sector(cluster);
        let mut dot = [0u8; ENTRY];
        dot[..11].copy_from_slice(b".          ");
        dot[11] = Attributes::DIRECTORY;
        dot[14..16].copy_from_slice(&self.now.time.to_le_bytes());
        dot[16..18].copy_from_slice(&self.now.date.to_le_bytes());
        dot[22..24].copy_from_slice(&self.now.time.to_le_bytes());
        dot[24..26].copy_from_slice(&self.now.date.to_le_bytes());
        dot[20..22].copy_from_slice(&((cluster >> 16) as u16).to_le_bytes());
        dot[26..28].copy_from_slice(&(cluster as u16).to_le_bytes());
        let mut dotdot = dot;
        dotdot[..11].copy_from_slice(b"..         ");
        dotdot[20..22].copy_from_slice(&((parent_cluster >> 16) as u16).to_le_bytes());
        dotdot[26..28].copy_from_slice(&(parent_cluster as u16).to_le_bytes());
        {
            let sector = self.sector_mut(first_sector)?;
            sector[..ENTRY].copy_from_slice(&dot);
            sector[ENTRY..ENTRY * 2].copy_from_slice(&dotdot);
        }

        // Only now link it into the parent, so a failure above leaves no
        // entry pointing at a half-built directory.
        let loc = match self.add_entry(&parent, leaf, Attributes::DIRECTORY, cluster, 0) {
            Ok(loc) => loc,
            Err(e) => {
                self.free_chain(cluster)?;
                return Err(e);
            }
        };
        Ok(Dir {
            first_cluster: cluster,
            fixed_root: false,
            loc,
        })
    }

    /// Remove a file, freeing its clusters.
    pub fn remove_file(&mut self, path: &str) -> Result<(), Error<D::Error>> {
        let (dir, leaf) = self.split_path(path)?;
        let found = self.scan(&dir, leaf)?.ok_or(Error::NotFound)?;
        if found.meta.is_dir() {
            return Err(Error::IsADirectory);
        }
        if found.meta.first_cluster != 0 {
            self.free_chain(found.meta.first_cluster)?;
        }
        self.delete_entry(&found)
    }

    /// Remove an empty directory.
    pub fn remove_dir(&mut self, path: &str) -> Result<(), Error<D::Error>> {
        let (parent, leaf) = self.split_path(path)?;
        let found = self.scan(&parent, leaf)?.ok_or(Error::NotFound)?;
        if !found.meta.is_dir() {
            return Err(Error::NotADirectory);
        }
        let dir = Dir {
            first_cluster: found.meta.first_cluster,
            fixed_root: false,
            loc: found.meta.loc,
        };
        if !self.dir_is_empty(&dir)? {
            return Err(Error::DirectoryNotEmpty);
        }
        if found.meta.first_cluster != 0 {
            self.free_chain(found.meta.first_cluster)?;
        }
        self.delete_entry(&found)
    }

    /// Whether `dir` holds nothing but `.` and `..`.
    fn dir_is_empty(&mut self, dir: &Dir) -> Result<bool, Error<D::Error>> {
        let mut sectors = DirSectors::new(&self.geom, dir);
        let per_sector = self.bps() / ENTRY;
        while let Some(sector) = sectors.next(self)? {
            for i in 0..per_sector {
                let loc = EntryLoc {
                    sector,
                    offset: (i * ENTRY) as u16,
                };
                let raw = self.entry_bytes(loc)?;
                if raw[0] == END {
                    return Ok(true);
                }
                if raw[0] == DELETED {
                    continue;
                }
                if is_lfn(&raw) {
                    return Ok(false);
                }
                if &raw[..11] != b".          " && &raw[..11] != b"..         " {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    /// Iterate `dir`'s entries, long names included.
    ///
    /// The iterator owns the buffer each name is decoded into, so an entry
    /// borrows from it and this is a `while let`, not a `for`. `.` and
    /// `..` are reported like any other entry; [`DirEntry::is_dot`] picks
    /// them out.
    pub fn iter_dir(&mut self, dir: Dir) -> DirIter<'_, D, S> {
        let sectors = DirSectors::new(&self.geom, &dir);
        DirIter {
            vol: self,
            sectors,
            sector: None,
            index: 0,
            run: LfnRun::new(),
            units: [0u16; MAX_NAME_UNITS],
            name: [0u8; MAX_NAME_BYTES],
            name_len: 0,
        }
    }

    /// Write a file's size and first cluster back into its entry.
    pub(crate) fn update_entry(
        &mut self,
        loc: EntryLoc,
        first_cluster: u32,
        len: u32,
    ) -> Result<(), Error<D::Error>> {
        if loc.is_none() {
            return Ok(());
        }
        let mut raw = self.entry_bytes(loc)?;
        raw[20..22].copy_from_slice(&((first_cluster >> 16) as u16).to_le_bytes());
        raw[26..28].copy_from_slice(&(first_cluster as u16).to_le_bytes());
        raw[28..32].copy_from_slice(&len.to_le_bytes());
        raw[22..24].copy_from_slice(&self.now.time.to_le_bytes());
        raw[24..26].copy_from_slice(&self.now.date.to_le_bytes());
        raw[18..20].copy_from_slice(&self.now.date.to_le_bytes());
        // Modifying a file clears nothing else, but the archive bit is
        // what every other implementation sets here.
        raw[11] |= Attributes::ARCHIVE;
        self.set_entry_bytes(loc, &raw)
    }
}

/// Case-insensitive comparison of an entry's 8.3 name against `name`.
fn short_name_matches(raw: &[u8; ENTRY], name: &str) -> bool {
    let mut buf = [0u8; 13];
    let len = short_name(raw, &mut buf);
    let Ok(text) = core::str::from_utf8(&buf[..len]) else {
        return false;
    };
    let mut a = text.chars().map(fold);
    let mut b = name.chars().map(fold);
    loop {
        match (a.next(), b.next()) {
            (None, None) => return true,
            (x, y) if x != y => return false,
            _ => {}
        }
    }
}

/// One entry yielded by [`DirIter`]. The name borrows the iterator's
/// buffer.
#[derive(Debug)]
pub struct DirEntry<'a> {
    name: &'a str,
    meta: Metadata,
}

impl DirEntry<'_> {
    /// The entry's name: the long name when it has one, otherwise its 8.3
    /// name.
    pub fn name(&self) -> &str {
        self.name
    }

    /// Everything the directory entry records.
    pub fn metadata(&self) -> Metadata {
        self.meta
    }

    /// Whether this is a directory.
    pub fn is_dir(&self) -> bool {
        self.meta.is_dir()
    }

    /// Size in bytes (0 for a directory).
    pub fn len(&self) -> u32 {
        self.meta.len
    }

    /// Whether the file is empty.
    pub fn is_empty(&self) -> bool {
        self.meta.len == 0
    }

    /// Whether this is the `.` or `..` entry of a subdirectory.
    pub fn is_dot(&self) -> bool {
        self.name == "." || self.name == ".."
    }

    /// A handle for the file this entry names, so it can be opened without
    /// another path lookup.
    pub fn to_file(&self) -> super::File {
        super::File::new(self.meta.first_cluster, self.meta.len, self.meta.loc)
    }

    /// A handle for the directory this entry names.
    pub fn to_dir(&self) -> Option<Dir> {
        self.is_dir().then_some(Dir {
            first_cluster: self.meta.first_cluster,
            fixed_root: false,
            loc: self.meta.loc,
        })
    }
}

/// A lending iterator over a directory's entries.
///
/// Created by [`Volume::iter_dir`]. It borrows the volume for its lifetime
/// and owns the ~1 KiB of buffers a long name needs, so entries borrow
/// from it:
///
/// ```ignore
/// let mut it = vol.iter_dir(dir);
/// while let Some(entry) = it.next()? {
///     // …
/// }
/// ```
pub struct DirIter<'v, D: SectorDriver, const S: usize> {
    vol: &'v mut Volume<D, S>,
    sectors: DirSectors,
    sector: Option<u32>,
    index: usize,
    run: LfnRun,
    units: [u16; MAX_NAME_UNITS],
    name: [u8; MAX_NAME_BYTES],
    name_len: usize,
}

impl<D: SectorDriver, const S: usize> DirIter<'_, D, S> {
    /// The next entry, or `None` at the end of the directory.
    #[allow(clippy::should_implement_trait)] // lending: the item borrows self
    pub fn next(&mut self) -> Result<Option<DirEntry<'_>>, Error<D::Error>> {
        let per_sector = self.vol.bps() / ENTRY;
        loop {
            let sector = match self.sector {
                Some(s) if self.index < per_sector => s,
                _ => {
                    let Some(s) = self.sectors.next(self.vol)? else {
                        return Ok(None);
                    };
                    self.sector = Some(s);
                    self.index = 0;
                    s
                }
            };
            let loc = EntryLoc {
                sector,
                offset: (self.index * ENTRY) as u16,
            };
            self.index += 1;
            let raw = self.vol.entry_bytes(loc)?;

            if raw[0] == END {
                return Ok(None);
            }
            if raw[0] == DELETED {
                self.run.reset();
                continue;
            }
            if is_lfn(&raw) {
                // Keep the units, indexed by the ordinal, so the run can
                // arrive in any order the volume happens to store it.
                let ord = (raw[0] & !LAST_LONG_ENTRY) as usize;
                self.run.feed(&raw, loc, None);
                if self.run.valid && ord >= 1 && ord <= MAX_NAME_UNITS.div_ceil(LFN_CHUNK) {
                    let chunk = lfn_units(&raw);
                    let start = (ord - 1) * LFN_CHUNK;
                    for (i, &u) in chunk.iter().enumerate() {
                        if start + i < MAX_NAME_UNITS {
                            self.units[start + i] = u;
                        }
                    }
                }
                continue;
            }
            if Attributes(raw[11]).is_volume_id() {
                // The volume label is not a directory entry anyone wants.
                self.run.reset();
                continue;
            }

            let checksum = lfn_checksum(raw[..11].try_into().expect("11 of 32 bytes"));
            let have_long = self.run.valid && self.run.expect == 0 && self.run.checksum == checksum;
            self.name_len = if have_long {
                let units = &self.units[..self.run.units.min(MAX_NAME_UNITS)];
                let mut at = 0;
                for r in core::char::decode_utf16(units.iter().copied()) {
                    let c = r.unwrap_or(char::REPLACEMENT_CHARACTER);
                    let n = push_char(&mut self.name, at, c);
                    if n == 0 {
                        break;
                    }
                    at += n;
                }
                at
            } else {
                short_name(&raw, &mut self.name)
            };
            self.run.reset();

            let meta = decode_short(&raw, self.vol.geom.kind, loc);
            let name = core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("");
            return Ok(Some(DirEntry { name, meta }));
        }
    }

    /// The cluster the walk is currently reading, for diagnostics.
    pub fn current_cluster(&self) -> u32 {
        self.sectors.current_cluster()
    }
}
