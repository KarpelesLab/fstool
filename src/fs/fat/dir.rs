//! FAT directory entries — 32-byte 8.3 entries and VFAT long-name (LFN)
//! entries.
//!
//! A regular directory entry is 32 bytes:
//!
//! ```text
//!     0  11  short name (8.3, space-padded, upper-case)
//!    11   1  attributes
//!    12   1  reserved (NT case flags)
//!    13   1  creation time, tenths
//!    14   2  creation time
//!    16   2  creation date
//!    18   2  last-access date
//!    20   2  first cluster, high 16 bits
//!    22   2  write time
//!    24   2  write date
//!    26   2  first cluster, low 16 bits
//!    28   4  file size in bytes (0 for directories)
//! ```
//!
//! A long name is stored as a run of LFN entries (`attr = 0x0F`) placed
//! *immediately before* the 8.3 entry, in reverse order — each carries 13
//! UTF-16 code units and a checksum tying it to the 8.3 name.

/// Size of one directory entry.
pub const ENTRY_SIZE: usize = 32;

/// Attribute bits.
pub const ATTR_READ_ONLY: u8 = 0x01;
pub const ATTR_HIDDEN: u8 = 0x02;
pub const ATTR_SYSTEM: u8 = 0x04;
pub const ATTR_VOLUME_ID: u8 = 0x08;
pub const ATTR_DIRECTORY: u8 = 0x10;
pub const ATTR_ARCHIVE: u8 = 0x20;
/// The attribute byte that marks an entry as an LFN fragment.
pub const ATTR_LFN: u8 = ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID;

/// UTF-16 code units carried by one LFN entry.
pub const LFN_CHARS_PER_ENTRY: usize = 13;

/// DOS date for 1980-01-01 (the FAT epoch): year 0, month 1, day 1.
pub const DOS_DATE_EPOCH: u16 = (1 << 5) | 1;

/// 1980-01-01 00:00:00 UTC as Unix epoch seconds — the FAT/DOS epoch.
const FAT_EPOCH: u64 = 315_532_800;

fn is_leap_year(y: u32) -> bool {
    (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
}

/// Convert Unix epoch seconds into the FAT `(date, time)` word pair. Values
/// before 1980 (or past 2107) collapse to the reproducible epoch
/// `(DOS_DATE_EPOCH, 0)`. FAT time has 2-second resolution, so odd seconds
/// round down.
pub fn unix_to_dos_datetime(unix_secs: u32) -> (u16, u16) {
    if u64::from(unix_secs) < FAT_EPOCH {
        return (DOS_DATE_EPOCH, 0);
    }
    let secs = u64::from(unix_secs) - FAT_EPOCH;
    let day_secs = secs % 86_400;
    let (h, m, s) = (day_secs / 3600, (day_secs / 60) % 60, day_secs % 60);
    let mut days = secs / 86_400;
    let mut year: u32 = 1980;
    loop {
        let diy = if is_leap_year(year) { 366 } else { 365 };
        if days < diy {
            break;
        }
        days -= diy;
        year += 1;
        if year > 2107 {
            return (DOS_DATE_EPOCH, 0);
        }
    }
    const MONTH_DAYS: [u64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month: u32 = 1;
    for (i, md) in MONTH_DAYS.iter().enumerate() {
        let dim = if i == 1 && is_leap_year(year) {
            29
        } else {
            *md
        };
        if days < dim {
            break;
        }
        days -= dim;
        month += 1;
    }
    let day = days as u32 + 1;
    let date = (((year - 1980) << 9) | (month << 5) | day) as u16;
    let time = ((h << 11) | (m << 5) | (s / 2)) as u16;
    (date, time)
}

/// Inverse of [`unix_to_dos_datetime`]: decode a FAT `(date, time)` pair into
/// Unix epoch seconds. A zero `date` (an unset field) decodes to `0`.
pub fn dos_datetime_to_unix(date: u16, time: u16) -> u32 {
    // A zero field, or the reproducible epoch sentinel an mtime-less entry is
    // written with, both mean "no timestamp". (A real 1980-01-01 00:00:00
    // file is indistinguishable from the sentinel anyway — `unix_to_dos_*`
    // maps it to exactly this pair — so collapsing it to 0 is lossless.)
    if date == 0 || (date == DOS_DATE_EPOCH && time == 0) {
        return 0;
    }
    let s = u32::from(time & 0x1F) * 2;
    let m = u32::from((time >> 5) & 0x3F);
    let h = u32::from((time >> 11) & 0x1F);
    let day = u32::from(date & 0x1F);
    let month = u32::from((date >> 5) & 0x0F);
    let year = u32::from((date >> 9) & 0x7F) + 1980;
    if !(1..=12).contains(&month) || day < 1 {
        return 0;
    }
    let mut days: u64 = 0;
    for y in 1980..year {
        days += if is_leap_year(y) { 366 } else { 365 };
    }
    const MONTH_DAYS: [u64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for mo in 1..month {
        days += if mo == 2 && is_leap_year(year) {
            29
        } else {
            MONTH_DAYS[(mo - 1) as usize]
        };
    }
    days += u64::from(day - 1);
    let secs = FAT_EPOCH + days * 86_400 + u64::from(h) * 3600 + u64::from(m) * 60 + u64::from(s);
    secs.min(u64::from(u32::MAX)) as u32
}

/// A decoded 8.3 directory entry.
#[derive(Debug, Clone)]
pub struct DirEntry {
    /// Raw 11-byte 8.3 name (8 base + 3 extension, space-padded).
    pub name_83: [u8; 11],
    pub attr: u8,
    pub first_cluster: u32,
    pub file_size: u32,
    /// Modification time, Unix epoch seconds. `0` means "no timestamp" and
    /// encodes as the reproducible FAT epoch (1980-01-01). FAT has 2-second
    /// resolution, so odd seconds round down on encode.
    pub mtime: u32,
}

impl DirEntry {
    /// Encode this 8.3 entry into 32 bytes. When `mtime` is `0` the
    /// timestamps are fixed at the FAT epoch for reproducible output;
    /// otherwise the creation / access / write fields all carry `mtime`.
    pub fn encode(&self) -> [u8; ENTRY_SIZE] {
        let mut b = [0u8; ENTRY_SIZE];
        b[0..11].copy_from_slice(&self.name_83);
        b[11] = self.attr;
        let (date, time) = if self.mtime == 0 {
            (DOS_DATE_EPOCH, 0)
        } else {
            unix_to_dos_datetime(self.mtime)
        };
        // 13 creation time tenths = 0; 14..16 creation time; 16..18 creation date.
        b[14..16].copy_from_slice(&time.to_le_bytes());
        b[16..18].copy_from_slice(&date.to_le_bytes());
        // 18..20 last-access date (no time field in FAT).
        b[18..20].copy_from_slice(&date.to_le_bytes());
        b[20..22].copy_from_slice(&((self.first_cluster >> 16) as u16).to_le_bytes());
        // 22..24 write time; 24..26 write date.
        b[22..24].copy_from_slice(&time.to_le_bytes());
        b[24..26].copy_from_slice(&date.to_le_bytes());
        b[26..28].copy_from_slice(&(self.first_cluster as u16).to_le_bytes());
        b[28..32].copy_from_slice(&self.file_size.to_le_bytes());
        b
    }

    /// Decode an 8.3 entry from 32 bytes. Returns `None` for a free slot
    /// (first byte 0x00 or 0xE5) or an LFN fragment.
    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < ENTRY_SIZE || b[0] == 0x00 || b[0] == 0xE5 {
            return None;
        }
        let attr = b[11];
        if attr & ATTR_LFN == ATTR_LFN {
            return None; // LFN fragment, not an 8.3 entry
        }
        let mut name_83 = [0u8; 11];
        name_83.copy_from_slice(&b[0..11]);
        let hi = u16::from_le_bytes(b[20..22].try_into().unwrap()) as u32;
        let lo = u16::from_le_bytes(b[26..28].try_into().unwrap()) as u32;
        let write_time = u16::from_le_bytes(b[22..24].try_into().unwrap());
        let write_date = u16::from_le_bytes(b[24..26].try_into().unwrap());
        Some(Self {
            name_83,
            attr,
            first_cluster: (hi << 16) | lo,
            file_size: u32::from_le_bytes(b[28..32].try_into().unwrap()),
            mtime: dos_datetime_to_unix(write_date, write_time),
        })
    }

    /// The human-readable form of the 8.3 name (`BASE.EXT`, lower-cased).
    pub fn short_name_string(&self) -> String {
        let base = String::from_utf8_lossy(&self.name_83[0..8])
            .trim_end()
            .to_string();
        let ext = String::from_utf8_lossy(&self.name_83[8..11])
            .trim_end()
            .to_string();
        let name = if ext.is_empty() {
            base
        } else {
            format!("{base}.{ext}")
        };
        name.to_ascii_lowercase()
    }
}

/// The LFN checksum of an 8.3 name — ties LFN fragments to their 8.3 entry.
pub fn lfn_checksum(name_83: &[u8; 11]) -> u8 {
    let mut sum: u8 = 0;
    for &c in name_83 {
        sum = ((sum & 1) << 7).wrapping_add(sum >> 1).wrapping_add(c);
    }
    sum
}

/// Encode the LFN entry run for `name` (a long file name) that precedes an
/// 8.3 entry with checksum `csum`. Entries are returned in on-disk order:
/// highest sequence number first (carrying the 0x40 "last" bit), down to 1.
pub fn encode_lfn_run(name: &str, csum: u8) -> Vec<[u8; ENTRY_SIZE]> {
    // UTF-16 code units, then a 0x0000 terminator, then 0xFFFF padding to a
    // multiple of 13.
    let mut units: Vec<u16> = name.encode_utf16().collect();
    units.push(0x0000);
    while !units.len().is_multiple_of(LFN_CHARS_PER_ENTRY) {
        units.push(0xFFFF);
    }
    let n_entries = units.len() / LFN_CHARS_PER_ENTRY;

    let mut out = Vec::with_capacity(n_entries);
    // Build entries 1..=n, then reverse to on-disk order.
    for seq in 1..=n_entries {
        let chunk = &units[(seq - 1) * LFN_CHARS_PER_ENTRY..seq * LFN_CHARS_PER_ENTRY];
        let mut e = [0u8; ENTRY_SIZE];
        let mut order = seq as u8;
        if seq == n_entries {
            order |= 0x40; // last (logically) LFN entry
        }
        e[0] = order;
        e[11] = ATTR_LFN;
        e[13] = csum;
        // name1: chars 0..5 at bytes 1..11
        for (i, &u) in chunk[0..5].iter().enumerate() {
            e[1 + i * 2..3 + i * 2].copy_from_slice(&u.to_le_bytes());
        }
        // name2: chars 5..11 at bytes 14..26
        for (i, &u) in chunk[5..11].iter().enumerate() {
            e[14 + i * 2..16 + i * 2].copy_from_slice(&u.to_le_bytes());
        }
        // name3: chars 11..13 at bytes 28..32
        for (i, &u) in chunk[11..13].iter().enumerate() {
            e[28 + i * 2..30 + i * 2].copy_from_slice(&u.to_le_bytes());
        }
        out.push(e);
    }
    out.reverse(); // on disk: highest sequence first
    out
}

/// Whether `name` is already a valid uppercase 8.3 name that needs no LFN.
pub fn is_valid_83(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > 12 {
        return false;
    }
    let valid = |c: u8| {
        c.is_ascii_uppercase()
            || c.is_ascii_digit()
            || matches!(
                c,
                b'$' | b'%'
                    | b'\''
                    | b'-'
                    | b'_'
                    | b'@'
                    | b'~'
                    | b'`'
                    | b'!'
                    | b'('
                    | b')'
                    | b'{'
                    | b'}'
                    | b'^'
                    | b'#'
                    | b'&'
            )
    };
    let dots = bytes.iter().filter(|&&c| c == b'.').count();
    match dots {
        0 => bytes.len() <= 8 && bytes.iter().all(|&c| valid(c)),
        1 => {
            let dot = name.find('.').unwrap();
            let (base, ext) = (&bytes[..dot], &bytes[dot + 1..]);
            !base.is_empty()
                && base.len() <= 8
                && ext.len() <= 3
                && base.iter().all(|&c| valid(c))
                && ext.iter().all(|&c| valid(c))
        }
        _ => false,
    }
}

/// Pack a known-valid 8.3 `name` into the raw 11-byte field.
pub fn pack_83(name: &str) -> [u8; 11] {
    let mut out = [b' '; 11];
    match name.find('.') {
        Some(dot) => {
            let base = &name.as_bytes()[..dot];
            let ext = &name.as_bytes()[dot + 1..];
            out[0..base.len()].copy_from_slice(base);
            out[8..8 + ext.len()].copy_from_slice(ext);
        }
        None => {
            let b = name.as_bytes();
            out[0..b.len()].copy_from_slice(b);
        }
    }
    out
}

/// One slot in a raw directory stream — either an 8.3 entry, an LFN
/// fragment, a deleted slot, or an end-of-directory marker.
#[derive(Debug, Clone)]
pub enum RawSlot {
    /// First byte is 0x00 — by spec this terminates the directory; the
    /// walker stops here.
    End,
    /// Deleted entry (first byte 0xE5) — skip but keep walking.
    Deleted,
    /// A 32-byte LFN fragment.
    Lfn(LfnFragment),
    /// A regular 8.3 entry. The volume-label entry shows up here too — the
    /// caller decides whether to skip it (it has `attr & ATTR_VOLUME_ID`).
    ShortEntry(DirEntry),
}

/// A decoded LFN fragment. `order` carries the sequence number (1-based)
/// in its low 6 bits; bit 0x40 marks the (logically) last fragment, which
/// appears first on disk.
#[derive(Debug, Clone)]
pub struct LfnFragment {
    pub order: u8,
    pub checksum: u8,
    /// 13 UTF-16 code units; 0x0000 marks the end of the name within the
    /// fragment, 0xFFFF is padding past the end.
    pub chars: [u16; LFN_CHARS_PER_ENTRY],
}

impl LfnFragment {
    /// Decode an LFN fragment from a 32-byte entry. The caller must have
    /// already confirmed `attr == ATTR_LFN`.
    pub fn decode(b: &[u8; ENTRY_SIZE]) -> Self {
        let mut chars = [0u16; LFN_CHARS_PER_ENTRY];
        for (i, slot) in chars[0..5].iter_mut().enumerate() {
            *slot = u16::from_le_bytes(b[1 + i * 2..3 + i * 2].try_into().unwrap());
        }
        for (i, slot) in chars[5..11].iter_mut().enumerate() {
            *slot = u16::from_le_bytes(b[14 + i * 2..16 + i * 2].try_into().unwrap());
        }
        for (i, slot) in chars[11..13].iter_mut().enumerate() {
            *slot = u16::from_le_bytes(b[28 + i * 2..30 + i * 2].try_into().unwrap());
        }
        Self {
            order: b[0],
            checksum: b[13],
            chars,
        }
    }
}

/// Classify a raw 32-byte directory slot.
pub fn classify_slot(b: &[u8; ENTRY_SIZE]) -> RawSlot {
    if b[0] == 0x00 {
        return RawSlot::End;
    }
    if b[0] == 0xE5 {
        return RawSlot::Deleted;
    }
    if b[11] & ATTR_LFN == ATTR_LFN {
        return RawSlot::Lfn(LfnFragment::decode(b));
    }
    // ShortEntry decode rejects 0x00/0xE5/LFN, all already handled above —
    // unwrap is safe.
    RawSlot::ShortEntry(DirEntry::decode(b).expect("classified short entry decodes"))
}

/// Reassemble a long name from an accumulated LFN run that precedes a
/// short entry. `fragments` is in *on-disk* order (highest order first).
/// Returns `None` if the run doesn't pass the checksum tying it to
/// `short_name_83`, or if the sequence numbers are inconsistent — caller
/// then falls back to the short name.
pub fn assemble_lfn(fragments: &[LfnFragment], short_name_83: &[u8; 11]) -> Option<String> {
    if fragments.is_empty() {
        return None;
    }
    let expected_csum = lfn_checksum(short_name_83);
    // Sequence must descend from N..1, with the first carrying the 0x40 bit.
    let first = &fragments[0];
    let n = (first.order & 0x3F) as usize;
    if n != fragments.len() || first.order & 0x40 == 0 {
        return None;
    }
    for (i, f) in fragments.iter().enumerate() {
        let want_seq = (n - i) as u8;
        // The 0x40 bit is only on the first fragment.
        let mask = if i == 0 { 0x40 } else { 0x00 };
        if f.order != want_seq | mask {
            return None;
        }
        if f.checksum != expected_csum {
            return None;
        }
    }
    // Concatenate fragments in *logical* order (seq 1..N), trim at 0x0000.
    let mut units: Vec<u16> = Vec::with_capacity(n * LFN_CHARS_PER_ENTRY);
    for f in fragments.iter().rev() {
        units.extend_from_slice(&f.chars);
    }
    let end = units
        .iter()
        .position(|&u| u == 0x0000)
        .unwrap_or(units.len());
    String::from_utf16(&units[..end]).ok()
}

/// Generate a unique 8.3 short name for a long name that can't be used
/// directly. `seq` is a per-directory counter making the result unique.
/// Form: `FT` + 6 hex digits of `seq` as the base, plus the upper-cased
/// first three valid extension characters.
pub fn generate_83(long: &str, seq: u32) -> [u8; 11] {
    let mut out = [b' '; 11];
    let base = format!("FT{:06X}", seq & 0xFF_FFFF);
    out[0..8].copy_from_slice(&base.as_bytes()[..8]);
    if let Some(dot) = long.rfind('.') {
        let ext: Vec<u8> = long[dot + 1..]
            .bytes()
            .filter(|c| c.is_ascii_alphanumeric())
            .take(3)
            .map(|c| c.to_ascii_uppercase())
            .collect();
        out[8..8 + ext.len()].copy_from_slice(&ext);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_roundtrip() {
        let e = DirEntry {
            name_83: *b"HELLO   TXT",
            attr: ATTR_ARCHIVE,
            first_cluster: 0x0012_3456,
            file_size: 4096,
            mtime: 0,
        };
        let dec = DirEntry::decode(&e.encode()).unwrap();
        assert_eq!(dec.name_83, *b"HELLO   TXT");
        assert_eq!(dec.first_cluster, 0x0012_3456);
        assert_eq!(dec.file_size, 4096);
        assert_eq!(dec.short_name_string(), "hello.txt");
        assert_eq!(dec.mtime, 0); // epoch sentinel → "no timestamp"
    }

    #[test]
    fn dos_datetime_round_trips() {
        // Even-second Unix times survive encode→decode (FAT has 2-second
        // resolution).
        for &t in &[
            1_577_836_800u32, // 2020-01-01 00:00:00
            1_615_779_296,    // 2021-03-15 12:34:56
            1_234_567_890,    // 2009-02-13 23:31:30
        ] {
            let (date, time) = unix_to_dos_datetime(t);
            assert_eq!(dos_datetime_to_unix(date, time), t, "round-trip {t}");
        }
        // Pre-1980 and the epoch both collapse to "no timestamp".
        assert_eq!(unix_to_dos_datetime(0), (DOS_DATE_EPOCH, 0));
        assert_eq!(dos_datetime_to_unix(DOS_DATE_EPOCH, 0), 0);
        // Odd seconds round down through the 2-second field.
        let (d, t) = unix_to_dos_datetime(1_615_779_297);
        assert_eq!(dos_datetime_to_unix(d, t), 1_615_779_296);
    }

    #[test]
    fn free_and_lfn_slots_decode_to_none() {
        assert!(DirEntry::decode(&[0u8; ENTRY_SIZE]).is_none());
        let mut deleted = [0x41u8; ENTRY_SIZE];
        deleted[0] = 0xE5;
        assert!(DirEntry::decode(&deleted).is_none());
        let mut lfn = [0u8; ENTRY_SIZE];
        lfn[0] = 0x41;
        lfn[11] = ATTR_LFN;
        assert!(DirEntry::decode(&lfn).is_none());
    }

    #[test]
    fn lfn_checksum_known_value() {
        // Checksum of "HELLO   TXT" — recompute via the documented algorithm.
        let name = *b"HELLO   TXT";
        let mut sum: u8 = 0;
        for &c in &name {
            sum = ((sum & 1) << 7).wrapping_add(sum >> 1).wrapping_add(c);
        }
        assert_eq!(lfn_checksum(&name), sum);
    }

    #[test]
    fn lfn_run_length_and_order() {
        // 20-char name → ceil((20+1)/13) = 2 LFN entries.
        let run = encode_lfn_run("a-twenty-char-name!!", 0xAB);
        assert_eq!(run.len(), 2);
        // On disk the first entry carries the high sequence + 0x40 bit.
        assert_eq!(run[0][0], 0x40 | 2);
        assert_eq!(run[1][0], 1);
        // Every fragment carries the 8.3 checksum and the LFN attr.
        for e in &run {
            assert_eq!(e[11], ATTR_LFN);
            assert_eq!(e[13], 0xAB);
        }
    }

    #[test]
    fn valid_83_classification() {
        assert!(is_valid_83("README"));
        assert!(is_valid_83("KERNEL.IMG"));
        assert!(is_valid_83("A.B"));
        assert!(!is_valid_83("readme")); // lower-case
        assert!(!is_valid_83("toolongname.txt")); // base > 8
        assert!(!is_valid_83("a.b.c")); // two dots
        assert!(!is_valid_83("with space")); // space invalid
    }

    #[test]
    fn generate_83_is_8_3() {
        let s = generate_83("some long name.tar.gz", 1);
        assert_eq!(&s[0..2], b"FT");
        assert_eq!(&s[8..11], b"GZ "); // extension from ".gz"
        // distinct seq → distinct base.
        assert_ne!(generate_83("x", 1), generate_83("x", 2));
    }
}
