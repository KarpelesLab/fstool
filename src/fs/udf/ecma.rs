//! ECMA-167 / OSTA UDF primitives: descriptor tags and their CRC, OSTA
//! CS0 compressed Unicode, timestamps, entity identifiers and the
//! allocation-descriptor shapes.
//!
//! Everything here is a pure byte-level codec — no device access — so the
//! reader, the writer and the fuzz target share one implementation.

use crate::Result;

// ---------------------------------------------------------------------------
// Tag identifiers (ECMA-167 3/7.2.1 and 4/7.2.1).
// ---------------------------------------------------------------------------

/// Primary Volume Descriptor.
pub const TAG_PVD: u16 = 1;
/// Anchor Volume Descriptor Pointer.
pub const TAG_AVDP: u16 = 2;
/// Volume Descriptor Pointer.
pub const TAG_VDP: u16 = 3;
/// Implementation Use Volume Descriptor.
pub const TAG_IUVD: u16 = 4;
/// Partition Descriptor.
pub const TAG_PD: u16 = 5;
/// Logical Volume Descriptor.
pub const TAG_LVD: u16 = 6;
/// Unallocated Space Descriptor.
pub const TAG_USD: u16 = 7;
/// Terminating Descriptor.
pub const TAG_TD: u16 = 8;
/// Logical Volume Integrity Descriptor.
pub const TAG_LVID: u16 = 9;
/// File Set Descriptor.
pub const TAG_FSD: u16 = 256;
/// File Identifier Descriptor.
pub const TAG_FID: u16 = 257;
/// Allocation Extent Descriptor.
pub const TAG_AED: u16 = 258;
/// Indirect Entry.
pub const TAG_IE: u16 = 259;
/// File Entry.
pub const TAG_FE: u16 = 261;
/// Extended Attribute Header Descriptor.
pub const TAG_EAHD: u16 = 262;
/// Space Bitmap Descriptor.
pub const TAG_SBD: u16 = 264;
/// Extended File Entry.
pub const TAG_EFE: u16 = 266;

/// Largest extent length an allocation descriptor can carry: the length
/// field is 30 bits, and an extent must be a whole number of blocks except
/// the last one of a file, so the largest *block-aligned* length is
/// `2^30 - block_size`.
pub fn max_extent_len(block_size: u32) -> u32 {
    (1u32 << 30) - block_size
}

// ---------------------------------------------------------------------------
// CRC-ITU-T (ECMA-167 1/7.2.6): polynomial x^16 + x^12 + x^5 + 1, initial
// value 0, no reflection, no final XOR — the "XMODEM" CRC-16.
// ---------------------------------------------------------------------------

const fn crc_table() -> [u16; 256] {
    let mut table = [0u16; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = (i as u16) << 8;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

static CRC_TABLE: [u16; 256] = crc_table();

/// CRC-ITU-T of `data`, as stored in a descriptor tag.
pub fn crc_itu(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in data {
        crc = (crc << 8) ^ CRC_TABLE[usize::from(((crc >> 8) as u8) ^ b)];
    }
    crc
}

// ---------------------------------------------------------------------------
// Descriptor tag (ECMA-167 3/7.2).
// ---------------------------------------------------------------------------

/// A parsed 16-byte descriptor tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tag {
    /// Tag identifier (`TAG_*`).
    pub id: u16,
    /// Descriptor version: 2 for ECMA-167 2nd edition (`NSR02`), 3 for the
    /// 3rd edition (`NSR03`).
    pub version: u16,
    /// Tag serial number.
    pub serial: u16,
    /// Descriptor CRC.
    pub crc: u16,
    /// Number of bytes after the tag the CRC covers.
    pub crc_len: u16,
    /// Where the descriptor says it is recorded: a physical sector for
    /// volume structures, a logical block of its partition otherwise.
    pub location: u32,
}

/// The tag checksum: sum modulo 256 of bytes 0–3 and 5–15.
pub fn tag_checksum(t: &[u8]) -> u8 {
    let mut sum: u8 = 0;
    for (i, &b) in t[..16].iter().enumerate() {
        if i != 4 {
            sum = sum.wrapping_add(b);
        }
    }
    sum
}

impl Tag {
    /// Parse the tag at the start of `buf`. `None` when the buffer is too
    /// short, the tag is all zero, or its checksum does not match — the
    /// cheap check every probe starts with.
    pub fn parse(buf: &[u8]) -> Option<Tag> {
        if buf.len() < 16 {
            return None;
        }
        let id = u16le(buf, 0);
        if id == 0 && buf[..16].iter().all(|&b| b == 0) {
            return None;
        }
        if tag_checksum(buf) != buf[4] {
            return None;
        }
        Some(Tag {
            id,
            version: u16le(buf, 2),
            serial: u16le(buf, 6),
            crc: u16le(buf, 8),
            crc_len: u16le(buf, 10),
            location: u32le(buf, 12),
        })
    }

    /// Whether the descriptor CRC over `buf[16..16 + crc_len]` matches.
    /// A CRC length running past `buf` is a mismatch.
    pub fn crc_ok(&self, buf: &[u8]) -> bool {
        let end = 16 + usize::from(self.crc_len);
        if end > buf.len() {
            return false;
        }
        crc_itu(&buf[16..end]) == self.crc
    }
}

/// Fill in the tag of the descriptor in `buf` (its first 16 bytes): id,
/// version, serial and location as given, the CRC over the `crc_len`
/// bytes after the tag, and the checksum last.
pub fn finish_tag(
    buf: &mut [u8],
    id: u16,
    version: u16,
    serial: u16,
    location: u32,
    crc_len: usize,
) {
    let crc_len = crc_len
        .min(buf.len().saturating_sub(16))
        .min(u16::MAX as usize);
    put_u16(buf, 0, id);
    put_u16(buf, 2, version);
    buf[4] = 0;
    buf[5] = 0;
    put_u16(buf, 6, serial);
    let crc = crc_itu(&buf[16..16 + crc_len]);
    put_u16(buf, 8, crc);
    put_u16(buf, 10, crc_len as u16);
    put_u32(buf, 12, location);
    buf[4] = tag_checksum(buf);
}

// ---------------------------------------------------------------------------
// Little-endian helpers. Every call site has checked the length first; the
// helpers index directly so a logic error panics in tests rather than
// silently reading zeros.
// ---------------------------------------------------------------------------

pub fn u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
pub fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
pub fn u64le(b: &[u8], o: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(a)
}
pub fn put_u16(b: &mut [u8], o: usize, v: u16) {
    b[o..o + 2].copy_from_slice(&v.to_le_bytes());
}
pub fn put_u32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
pub fn put_u64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_le_bytes());
}

// ---------------------------------------------------------------------------
// OSTA Compressed Unicode (UDF 2.1.1) and d-strings (ECMA-167 1/7.2.12).
// ---------------------------------------------------------------------------

/// Decode an OSTA CS0 string: a compression-ID byte (8 = one byte per
/// character, 16 = big-endian UTF-16; 254 / 255 are the UDF 2.50 forms of
/// the same) followed by the characters. Undecodable UTF-16 becomes
/// U+FFFD. An unknown compression ID decodes the bytes as Latin-1 rather
/// than failing — a name is better shown mangled than not at all.
pub fn decode_cs0(b: &[u8]) -> String {
    let Some((&comp, rest)) = b.split_first() else {
        return String::new();
    };
    match comp {
        16 | 255 => {
            let units = rest
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_be_bytes(*c));
            char::decode_utf16(units)
                .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
                .collect()
        }
        _ => rest.iter().map(|&c| char::from(c)).collect(),
    }
}

/// Encode `s` as OSTA CS0: the 8-bit form when every character fits in one
/// byte (U+0000–U+00FF), the 16-bit form otherwise (UTF-16, so characters
/// beyond the BMP become surrogate pairs).
pub fn encode_cs0(s: &str) -> Vec<u8> {
    if s.chars().all(|c| (c as u32) < 0x100) {
        let mut v = Vec::with_capacity(s.len() + 1);
        v.push(8);
        v.extend(s.chars().map(|c| c as u32 as u8));
        v
    } else {
        let mut v = Vec::with_capacity(s.len() * 2 + 1);
        v.push(16);
        for u in s.encode_utf16() {
            v.extend_from_slice(&u.to_be_bytes());
        }
        v
    }
}

/// Decode a d-string field: CS0 bytes followed by zero padding, with the
/// count of used bytes in the field's last byte.
pub fn decode_dstring(field: &[u8]) -> String {
    let Some((&len, body)) = field.split_last() else {
        return String::new();
    };
    let len = usize::from(len).min(body.len());
    decode_cs0(&body[..len])
}

/// Encode `s` as a d-string of `field_len` bytes. Fails when the encoded
/// form (compression ID included) does not fit in `field_len - 1` bytes;
/// `what` names the field in the error.
pub fn encode_dstring(s: &str, field_len: usize, what: &str) -> Result<Vec<u8>> {
    let mut out = vec![0u8; field_len];
    if s.is_empty() {
        return Ok(out);
    }
    let enc = encode_cs0(s);
    if enc.len() > field_len - 1 {
        let max8 = field_len - 2;
        let max16 = (field_len - 2) / 2;
        return Err(crate::Error::InvalidArgument(format!(
            "udf: {what} {s:?} is too long: {} bytes encoded, the field holds {} \
             ({max8} Latin-1 or {max16} UTF-16 units)",
            enc.len(),
            field_len - 1
        )));
    }
    out[..enc.len()].copy_from_slice(&enc);
    out[field_len - 1] = enc.len() as u8;
    Ok(out)
}

/// The 64-byte charspec "OSTA Compressed Unicode" (CS0) every UDF
/// descriptor names.
pub fn osta_charspec() -> [u8; 64] {
    let mut c = [0u8; 64];
    c[0] = 0; // CS0
    let s = b"OSTA Compressed Unicode";
    c[1..1 + s.len()].copy_from_slice(s);
    c
}

// ---------------------------------------------------------------------------
// Timestamps (ECMA-167 1/7.3).
// ---------------------------------------------------------------------------

/// Days since 1970-01-01 for a civil date (proleptic Gregorian).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (i64::from(m) + 9) % 12;
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Civil date for days since 1970-01-01.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Encode Unix seconds as a UDF timestamp in UTC (type 1 "local time",
/// offset 0 minutes, which every reader handles).
pub fn encode_timestamp(unix: i64) -> [u8; 12] {
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let y = y.clamp(1, 9999) as i16;
    let mut t = [0u8; 12];
    put_u16(&mut t, 0, 0x1000); // type 1, timezone offset 0
    t[2..4].copy_from_slice(&y.to_le_bytes());
    t[4] = m as u8;
    t[5] = d as u8;
    t[6] = (secs / 3600) as u8;
    t[7] = ((secs / 60) % 60) as u8;
    t[8] = (secs % 60) as u8;
    t
}

/// Decode a UDF timestamp to Unix seconds, applying its timezone offset
/// when one is recorded (-2047 means "unspecified", read as UTC). Out-of-
/// range fields are clamped rather than refused.
pub fn decode_timestamp(t: &[u8]) -> i64 {
    if t.len() < 12 || t.iter().all(|&b| b == 0) {
        return 0;
    }
    let tz_raw = u16le(t, 0) & 0x0FFF;
    // Sign-extend the 12-bit offset.
    let tz = if tz_raw & 0x800 != 0 {
        i64::from(tz_raw) - 0x1000
    } else {
        i64::from(tz_raw)
    };
    let year = i64::from(i16::from_le_bytes([t[2], t[3]]));
    let month = u32::from(t[4]).clamp(1, 12);
    let day = u32::from(t[5]).clamp(1, 31);
    let hour = i64::from(t[6].min(23));
    let min = i64::from(t[7].min(59));
    let sec = i64::from(t[8].min(59));
    let mut unix = days_from_civil(year, month, day) * 86_400 + hour * 3600 + min * 60 + sec;
    if tz != -2047 && (-1440..=1440).contains(&tz) {
        unix -= tz * 60;
    }
    unix
}

// ---------------------------------------------------------------------------
// Entity identifiers (ECMA-167 1/7.4, UDF 2.1.5).
// ---------------------------------------------------------------------------

/// Build a 32-byte entity identifier: flags 0, `id` (≤ 23 bytes), and an
/// 8-byte suffix.
pub fn entity_id(id: &str, suffix: [u8; 8]) -> [u8; 32] {
    let mut e = [0u8; 32];
    let b = id.as_bytes();
    let n = b.len().min(23);
    e[1..1 + n].copy_from_slice(&b[..n]);
    e[24..32].copy_from_slice(&suffix);
    e
}

/// The identifier part of a 32-byte entity identifier, NULs trimmed.
pub fn entity_name(e: &[u8]) -> String {
    let id = &e[1..24];
    let end = id.iter().position(|&b| b == 0).unwrap_or(id.len());
    String::from_utf8_lossy(&id[..end]).into_owned()
}

/// Domain identifier suffix: UDF revision + domain flags.
pub fn domain_suffix(rev: u16) -> [u8; 8] {
    let mut s = [0u8; 8];
    s[0..2].copy_from_slice(&rev.to_le_bytes());
    s
}

/// UDF identifier suffix: UDF revision, OS class, OS identifier. fstool
/// records OS class 4 (UNIX), identifier 0 (generic) — the image is not
/// tied to the host it was built on.
pub fn udf_suffix(rev: u16) -> [u8; 8] {
    let mut s = [0u8; 8];
    s[0..2].copy_from_slice(&rev.to_le_bytes());
    s[2] = 4;
    s[3] = 0;
    s
}

/// Implementation identifier suffix: OS class + OS identifier.
pub fn impl_suffix() -> [u8; 8] {
    let mut s = [0u8; 8];
    s[0] = 4;
    s
}

/// The implementation identifier fstool stamps on what it writes.
pub fn fstool_impl_id() -> [u8; 32] {
    entity_id("*fstool", impl_suffix())
}

// ---------------------------------------------------------------------------
// Allocation descriptors (ECMA-167 4/14.14).
// ---------------------------------------------------------------------------

/// Extent type in the top two bits of an allocation descriptor length.
pub const EXT_RECORDED: u8 = 0;
/// Allocated but not recorded (reads as zeros).
pub const EXT_ALLOCATED: u8 = 1;
/// Neither allocated nor recorded — a hole.
pub const EXT_HOLE: u8 = 2;
/// The extent is the next extent of allocation descriptors.
pub const EXT_NEXT: u8 = 3;

/// ICB flag: allocation-descriptor type in bits 0–2.
pub const ICB_AD_SHORT: u16 = 0;
pub const ICB_AD_LONG: u16 = 1;
pub const ICB_AD_EXTENDED: u16 = 2;
pub const ICB_AD_INLINE: u16 = 3;

/// A logical block address: block number within a partition reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct LbAddr {
    pub lbn: u32,
    pub part: u16,
}

impl LbAddr {
    pub fn parse(b: &[u8]) -> Self {
        LbAddr {
            lbn: u32le(b, 0),
            part: u16le(b, 4),
        }
    }
    pub fn write(&self, b: &mut [u8]) {
        put_u32(b, 0, self.lbn);
        put_u16(b, 4, self.part);
    }
}

/// A long allocation descriptor (16 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LongAd {
    /// Length in bytes, without the type bits.
    pub len: u32,
    /// Extent type (`EXT_*`).
    pub kind: u8,
    pub loc: LbAddr,
    /// Implementation use: bytes 2..6 carry the UDF unique ID in FIDs.
    pub imp: [u8; 6],
}

impl LongAd {
    pub fn parse(b: &[u8]) -> Self {
        let raw = u32le(b, 0);
        let mut imp = [0u8; 6];
        imp.copy_from_slice(&b[10..16]);
        LongAd {
            len: raw & 0x3FFF_FFFF,
            kind: (raw >> 30) as u8,
            loc: LbAddr::parse(&b[4..10]),
            imp,
        }
    }
    pub fn write(&self, b: &mut [u8]) {
        put_u32(
            b,
            0,
            (self.len & 0x3FFF_FFFF) | (u32::from(self.kind) << 30),
        );
        self.loc.write(&mut b[4..10]);
        b[10..16].copy_from_slice(&self.imp);
    }
}

/// Round `n` up to a multiple of `to` (a power of two or not).
pub fn round_up(n: u64, to: u64) -> u64 {
    n.div_ceil(to) * to
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_matches_ecma_example() {
        // ECMA-167 1/7.2.6: CRC of bytes 70 6A 77 is 0x3299.
        assert_eq!(crc_itu(&[0x70, 0x6A, 0x77]), 0x3299);
    }

    #[test]
    fn tag_round_trip() {
        let mut buf = vec![0u8; 512];
        buf[100] = 7;
        finish_tag(&mut buf, TAG_AVDP, 2, 1, 256, 496);
        let t = Tag::parse(&buf).unwrap();
        assert_eq!(t.id, TAG_AVDP);
        assert_eq!(t.location, 256);
        assert!(t.crc_ok(&buf));
        buf[200] = 1;
        assert!(!t.crc_ok(&buf));
        buf[0] ^= 1;
        assert!(Tag::parse(&buf).is_none());
    }

    #[test]
    fn cs0_round_trip() {
        for s in ["hello", "café", "日本語", "emoji 🎉", ""] {
            assert_eq!(decode_cs0(&encode_cs0(s)), s);
        }
        assert_eq!(encode_cs0("café")[0], 8);
        assert_eq!(encode_cs0("日本")[0], 16);
    }

    #[test]
    fn dstring_limits() {
        let f = encode_dstring("Vol", 32, "id").unwrap();
        assert_eq!(f[31], 4);
        assert_eq!(decode_dstring(&f), "Vol");
        assert!(encode_dstring(&"x".repeat(31), 32, "id").is_err());
        assert!(encode_dstring(&"x".repeat(30), 32, "id").is_ok());
        assert!(encode_dstring(&"日".repeat(16), 32, "id").is_err());
        assert!(encode_dstring(&"日".repeat(15), 32, "id").is_ok());
    }

    #[test]
    fn timestamp_round_trip() {
        for t in [0i64, 1, 86_399, 951_782_400, 1_700_000_000, 4_102_444_800] {
            assert_eq!(decode_timestamp(&encode_timestamp(t)), t);
        }
        // +60 minutes offset: local 01:00 is 00:00 UTC.
        let mut ts = encode_timestamp(3600);
        put_u16(&mut ts, 0, 0x1000 | 60);
        assert_eq!(decode_timestamp(&ts), 0);
        // Negative offset (-120 minutes).
        let mut ts = encode_timestamp(0);
        put_u16(&mut ts, 0, 0x1000 | ((-120i16 as u16) & 0xFFF));
        assert_eq!(decode_timestamp(&ts), 7200);
    }
}
