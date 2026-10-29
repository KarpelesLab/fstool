//! ZIP reader: locate the End-Of-Central-Directory, follow ZIP64 when
//! present, and walk the central directory into an [`ArchiveIndex`].
//!
//! Split archives (`disk number start` ≠ 0) are read through a device
//! that exposes its volumes via [`BlockDevice::segments`]; every
//! disk-relative offset is translated to the concatenation.

use super::encoding;
use super::{
    METHOD_AES, METHOD_DEFLATE, METHOD_STORE, SIG_CENTRAL, SIG_EOCD, SIG_ZIP64_EOCD,
    SIG_ZIP64_LOCATOR,
};
use crate::block::BlockDevice;
use crate::fs::archive::{ArchiveEntry, ArchiveIndex, Crypto, DataLocator, EntryKind, Method};
use crate::{Error, Result};

const S_IFMT: u32 = 0o170000;
const S_IFLNK: u32 = 0o120000;

fn le16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn le64(b: &[u8], o: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(a)
}

/// Translate a (disk, disk-relative offset) pair to an offset in `dev`.
/// A single-volume device only knows disk 0; a reference to any other
/// disk means the caller opened one volume of a split set on its own.
fn resolve(segments: Option<&[u64]>, disk: u64, offset: u64) -> Result<u64> {
    match segments {
        None if disk == 0 => Ok(offset),
        None => Err(Error::InvalidImage(format!(
            "zip: split archive refers to disk {disk} — open the whole volume set \
             (the .z01… volumes next to the .zip)"
        ))),
        Some(segs) => {
            let start = segs.get(disk as usize).copied().ok_or_else(|| {
                Error::InvalidImage(format!(
                    "zip: entry on disk {disk} but the volume set has only {} volumes",
                    segs.len()
                ))
            })?;
            start
                .checked_add(offset)
                .ok_or_else(|| Error::InvalidImage("zip: offset overflow".into()))
        }
    }
}

/// Central-directory geometry resolved from the EOCD (+ ZIP64), with
/// every offset already translated to the device.
struct Eocd {
    cd_offset: u64,
    cd_size: u64,
    total_entries: u64,
    /// Bytes of non-zip data prepended to the archive, as implied by the
    /// gap between where the EOCD actually sits and where the declared
    /// central-directory geometry says it should end. Non-zero for a
    /// self-extracting archive, whose offsets are relative to the start
    /// of the zip data rather than the start of the file. Only a hint:
    /// [`scan`] applies it when the declared offset misses.
    prefix_delta: u64,
}

fn find_eocd(dev: &mut dyn BlockDevice) -> Result<Eocd> {
    let total = dev.total_size();
    // EOCD is 22 bytes + up to 65535 bytes of comment.
    let max_back = (22 + 0xffff).min(total);
    let start = total - max_back;
    let mut tail = vec![0u8; max_back as usize];
    dev.read_at(start, &mut tail)?;

    // Scan backward for the EOCD signature, validating the comment len.
    let mut eocd_pos = None;
    if tail.len() >= 22 {
        for i in (0..=tail.len() - 22).rev() {
            if le32(&tail, i) == SIG_EOCD {
                let comment_len = le16(&tail, i + 20) as usize;
                if i + 22 + comment_len == tail.len() {
                    eocd_pos = Some(i);
                    break;
                }
            }
        }
    }
    let i = eocd_pos
        .ok_or_else(|| Error::InvalidImage("zip: end-of-central-directory not found".into()))?;

    let eocd_abs = start + i as u64;
    let segments: Option<Vec<u64>> = dev.segments().map(|s| s.to_vec());
    let segments = segments.as_deref();
    let mut cd_disk = le16(&tail, i + 6) as u64;
    let mut cd_size = le32(&tail, i + 12) as u64;
    let mut cd_offset = le32(&tail, i + 16) as u64;
    let mut total_entries = le16(&tail, i + 10) as u64;
    let mut zip64 = false;

    // ZIP64: a locator sits 20 bytes before the EOCD.
    if i >= 20 && le32(&tail, i - 20) == SIG_ZIP64_LOCATOR {
        let z64_disk = le32(&tail, i - 20 + 4) as u64;
        let z64_eocd_off = resolve(segments, z64_disk, le64(&tail, i - 20 + 8))?;
        let mut rec = [0u8; 56];
        dev.read_at(z64_eocd_off, &mut rec)?;
        if le32(&rec, 0) != SIG_ZIP64_EOCD {
            return Err(Error::InvalidImage(
                "zip: ZIP64 locator points at a bad record".into(),
            ));
        }
        cd_disk = le32(&rec, 20) as u64;
        total_entries = le64(&rec, 32);
        cd_size = le64(&rec, 40);
        cd_offset = le64(&rec, 48);
        zip64 = true;
    }

    let cd_offset = resolve(segments, cd_disk, cd_offset)?;
    let cd_end = cd_offset
        .checked_add(cd_size)
        .ok_or_else(|| Error::InvalidImage("zip: central-directory size overflow".into()))?;
    if cd_end > total {
        return Err(Error::InvalidImage(
            "zip: central directory extends past end of archive".into(),
        ));
    }
    // The classic EOCD immediately follows the central directory, so any
    // gap is a prepended stub. With ZIP64 the two extra records sit in
    // between, and the locator's own offset would need the same
    // correction, so don't guess there — nor on a split set, whose
    // offsets are already volume-relative.
    let prefix_delta = if zip64 || segments.is_some() {
        0
    } else {
        eocd_abs.saturating_sub(cd_end)
    };
    Ok(Eocd {
        cd_offset,
        cd_size,
        total_entries,
        prefix_delta,
    })
}

/// Everything an entry's extra fields may carry that we care about.
#[derive(Default, Debug)]
struct Extras {
    mtime: Option<u64>,
    atime: Option<u64>,
    ctime: Option<u64>,
    uid: Option<u32>,
    gid: Option<u32>,
    /// Info-ZIP Unicode Path (0x7075), when its CRC matches the raw name.
    unicode_name: Option<String>,
    /// WinZip AES (0x9901): vendor version, strength byte, real method.
    aes: Option<(u16, u8, u16)>,
    /// ZIP64 disk number, present when the 16-bit field is 0xFFFF.
    zip64_disk: Option<u32>,
}

/// Windows FILETIME (100 ns ticks since 1601-01-01) → Unix seconds.
/// `None` for a zero FILETIME, which writers use for "not recorded"
/// (7-Zip fills only the mtime slot).
fn filetime_to_unix(ft: u64) -> Option<u64> {
    (ft != 0).then(|| (ft / 10_000_000).saturating_sub(11_644_473_600))
}

/// Walk an extra-field block. ZIP64 (0x0001) overrides `comp` /
/// `uncomp` / `offset` for the values that were `0xFFFFFFFF` (and the
/// disk when it was `0xFFFF`); the rest lands in [`Extras`]: Unix mtime /
/// atime / ctime from the `UT` extra (0x5455), uid / gid from Info-ZIP's
/// `ux` (0x7875) and legacy `UX` (0x5855), NTFS timestamps (0x000a) as a
/// fallback, the Unicode path (0x7075), and the AES parameters (0x9901).
fn parse_extras(
    extra: &[u8],
    raw_name: &[u8],
    comp: &mut u64,
    uncomp: &mut u64,
    offset: &mut u64,
    disk: &mut u64,
) -> Extras {
    let mut x = Extras::default();
    let mut ntfs: Option<(Option<u64>, Option<u64>, Option<u64>)> = None;
    let mut p = 0;
    while p + 4 <= extra.len() {
        let id = le16(extra, p);
        let len = le16(extra, p + 2) as usize;
        let body_start = p + 4;
        if body_start + len > extra.len() {
            break;
        }
        let body = &extra[body_start..body_start + len];
        match id {
            0x0001 => {
                // ZIP64: present fields, in order, for each 0xFFFFFFFF value.
                let mut q = 0;
                if *uncomp == 0xffff_ffff && q + 8 <= body.len() {
                    *uncomp = le64(body, q);
                    q += 8;
                }
                if *comp == 0xffff_ffff && q + 8 <= body.len() {
                    *comp = le64(body, q);
                    q += 8;
                }
                if *offset == 0xffff_ffff && q + 8 <= body.len() {
                    *offset = le64(body, q);
                    q += 8;
                }
                if *disk == 0xffff && q + 4 <= body.len() {
                    let d = le32(body, q);
                    *disk = d as u64;
                    x.zip64_disk = Some(d);
                }
            }
            0x5455 if !body.is_empty() => {
                // UT: flags byte, then mtime / atime / ctime for each set
                // bit — as many as actually fit (the central copy carries
                // mtime alone whatever the flags say).
                let flags = body[0];
                let mut q = 1;
                for (bit, slot) in [(1u8, &mut x.mtime), (2, &mut x.atime), (4, &mut x.ctime)] {
                    if flags & bit != 0 && q + 4 <= body.len() {
                        *slot = Some(le32(body, q) as u64);
                        q += 4;
                    }
                }
            }
            0x5855 => {
                // UX (legacy Info-ZIP): atime, mtime; in the local header
                // also 16-bit uid, gid.
                if body.len() >= 8 {
                    x.atime.get_or_insert(le32(body, 0) as u64);
                    x.mtime.get_or_insert(le32(body, 4) as u64);
                }
                if body.len() >= 12 {
                    x.uid.get_or_insert(le16(body, 8) as u32);
                    x.gid.get_or_insert(le16(body, 10) as u32);
                }
            }
            0x7875 if body.len() >= 2 && body[0] == 1 => {
                // ux: version 1, then size-prefixed little-endian uid and gid.
                let read = |q: &mut usize| -> Option<u32> {
                    let n = *body.get(*q)? as usize;
                    *q += 1;
                    let bytes = body.get(*q..*q + n)?;
                    *q += n;
                    let mut v = 0u64;
                    for (i, b) in bytes.iter().enumerate().take(8) {
                        v |= (*b as u64) << (8 * i);
                    }
                    u32::try_from(v).ok()
                };
                let mut q = 1;
                if let Some(uid) = read(&mut q) {
                    x.uid = Some(uid);
                    if let Some(gid) = read(&mut q) {
                        x.gid = Some(gid);
                    }
                }
            }
            0x000a if body.len() >= 4 => {
                // NTFS: reserved u32, then tagged attributes; tag 1 holds
                // three FILETIMEs (mtime, atime, ctime).
                let mut q = 4;
                while q + 4 <= body.len() {
                    let tag = le16(body, q);
                    let size = le16(body, q + 2) as usize;
                    q += 4;
                    if q + size > body.len() {
                        break;
                    }
                    if tag == 1 && size >= 24 {
                        ntfs = Some((
                            filetime_to_unix(le64(body, q)),
                            filetime_to_unix(le64(body, q + 8)),
                            filetime_to_unix(le64(body, q + 16)),
                        ));
                    }
                    q += size;
                }
            }
            0x7075 if body.len() >= 5 && body[0] == 1 => {
                if le32(body, 1) == crate::crc::crc32(raw_name)
                    && let Ok(name) = std::str::from_utf8(&body[5..])
                {
                    x.unicode_name = Some(name.to_string());
                }
            }
            0x9901 if body.len() >= 7 && &body[2..4] == b"AE" => {
                x.aes = Some((le16(body, 0), body[4], le16(body, 5)));
            }
            _ => {}
        }
        p = body_start + len;
    }
    if let Some((m, a, c)) = ntfs {
        x.mtime = x.mtime.or(m);
        x.atime = x.atime.or(a);
        x.ctime = x.ctime.or(c);
    }
    x
}

/// General-purpose bit 0: the body is encrypted (traditional PKWARE or,
/// together with method 99, WinZip AES).
const GP_ENCRYPTED: u16 = 0x0001;
/// General-purpose bit 3: sizes and CRC follow the body in a data
/// descriptor; the ZipCrypto check byte then comes from the DOS time.
const GP_DESCRIPTOR: u16 = 0x0008;

/// Map a ZIP compression-method id to our [`Method`]. Bits 1 and 2 of
/// the general-purpose flags are method-specific parameters: the LZMA
/// end-of-stream marker, and Implode's window size / literal tree.
fn method_for(id: u16, gp_flags: u16) -> Method {
    use super::{
        METHOD_BZIP2, METHOD_DEFLATE64, METHOD_IMPLODE, METHOD_LZMA, METHOD_PPMD, METHOD_SHRINK,
        METHOD_XZ, METHOD_ZSTD,
    };
    let bit1 = gp_flags & 0x0002 != 0;
    let bit2 = gp_flags & 0x0004 != 0;
    match id {
        METHOD_STORE => Method::Stored,
        METHOD_SHRINK => Method::ZipShrink,
        2..=5 => Method::ZipReduce((id - 1) as u8),
        METHOD_IMPLODE => Method::ZipImplode {
            large_window: bit1,
            lit_tree: bit2,
        },
        METHOD_DEFLATE => Method::Deflate,
        METHOD_DEFLATE64 => Method::Deflate64,
        METHOD_BZIP2 => Method::Codec(crate::compression::Algo::Bzip2),
        METHOD_LZMA => Method::ZipLzma { eos: bit1 },
        METHOD_ZSTD => Method::Codec(crate::compression::Algo::Zstd),
        METHOD_XZ => Method::Codec(crate::compression::Algo::Xz),
        METHOD_PPMD => Method::ZipPpmd,
        other => Method::Unsupported(other),
    }
}

/// Index the archive on `dev`. `password` is only used here to decode
/// encrypted symlink targets; the handle keeps its own copy for file
/// bodies.
pub fn scan(dev: &mut dyn BlockDevice, password: Option<&[u8]>) -> Result<ArchiveIndex> {
    let eocd = find_eocd(dev)?;
    let mut cd = vec![0u8; eocd.cd_size as usize];
    dev.read_at(eocd.cd_offset, &mut cd)?;
    let segments: Option<Vec<u64>> = dev.segments().map(|s| s.to_vec());
    let segments = segments.as_deref();

    // Self-extracting archives keep offsets relative to the start of the
    // zip data. When the declared offset doesn't land on a central
    // record, retry at the offset the EOCD's own position implies and
    // carry the same correction into every local-header offset.
    let mut base = 0u64;
    if cd.len() >= 4 && le32(&cd, 0) != SIG_CENTRAL && eocd.prefix_delta != 0 {
        let alt = eocd.cd_offset + eocd.prefix_delta;
        if alt + eocd.cd_size <= dev.total_size() {
            let mut retry = vec![0u8; eocd.cd_size as usize];
            dev.read_at(alt, &mut retry)?;
            if le32(&retry, 0) == SIG_CENTRAL {
                crate::fstool_log!(
                    debug,
                    "zip: central directory found {} bytes past the declared offset \
                     (self-extracting stub?)",
                    eocd.prefix_delta
                );
                cd = retry;
                base = eocd.prefix_delta;
            }
        }
    }

    let mut idx = ArchiveIndex::new("zip");
    let mut p = 0usize;
    let mut seen = 0u64;
    while p + 46 <= cd.len() {
        if le32(&cd, p) != SIG_CENTRAL {
            break;
        }
        let version_made_by = le16(&cd, p + 4);
        let gp_flags = le16(&cd, p + 8);
        let method_id = le16(&cd, p + 10);
        let dos_time = le16(&cd, p + 12);
        let dos_date = le16(&cd, p + 14);
        let crc = le32(&cd, p + 16);
        let name_len = le16(&cd, p + 28) as usize;
        let extra_len = le16(&cd, p + 30) as usize;
        let comment_len = le16(&cd, p + 32) as usize;
        let mut disk = le16(&cd, p + 34) as u64;
        let external_attr = le32(&cd, p + 38);
        let mut comp = le32(&cd, p + 20) as u64;
        let mut uncomp = le32(&cd, p + 24) as u64;
        let mut local_offset = le32(&cd, p + 42) as u64;

        let name_off = p + 46;
        let extra_off = name_off + name_len;
        let comment_off = extra_off + extra_len;
        if comment_off + comment_len > cd.len() {
            return Err(Error::InvalidImage(
                "zip: central-directory record overruns".into(),
            ));
        }
        let name_bytes = &cd[name_off..extra_off];
        let extra = &cd[extra_off..comment_off];

        let cx = parse_extras(
            extra,
            name_bytes,
            &mut comp,
            &mut uncomp,
            &mut local_offset,
            &mut disk,
        );

        let name = match &cx.unicode_name {
            Some(u) if gp_flags & 0x0800 == 0 => u.clone(),
            _ => encoding::decode_name(name_bytes, gp_flags & 0x0800 != 0),
        };

        // Resolve the data offset from the *local* header (its extra
        // field length may differ from the central one), and pick up
        // the timestamps / ids that only the local copy carries.
        let local_offset = resolve(segments, disk, local_offset)?
            .checked_add(base)
            .filter(|o| o.saturating_add(30) <= dev.total_size())
            .ok_or_else(|| {
                Error::InvalidImage("zip: local-header offset past end of archive".into())
            })?;
        let mut lh = [0u8; 30];
        dev.read_at(local_offset, &mut lh)?;
        let l_name = le16(&lh, 26) as u64;
        let l_extra = le16(&lh, 28) as usize;
        let data_off = local_offset + 30 + l_name + l_extra as u64;
        let lx = if l_extra > 0 && data_off <= dev.total_size() {
            let mut buf = vec![0u8; l_extra];
            dev.read_at(local_offset + 30 + l_name, &mut buf)?;
            let (mut d0, mut d1, mut d2, mut d3) = (0u64, 0u64, 0u64, 0u64);
            parse_extras(&buf, name_bytes, &mut d0, &mut d1, &mut d2, &mut d3)
        } else {
            Extras::default()
        };

        let mtime = cx
            .mtime
            .or(lx.mtime)
            .unwrap_or_else(|| super::dos_to_unix(dos_date, dos_time));
        let atime = cx.atime.or(lx.atime).unwrap_or(0);
        let ctime = cx.ctime.or(lx.ctime).unwrap_or(0);
        let uid = cx.uid.or(lx.uid).unwrap_or(0);
        let gid = cx.gid.or(lx.gid).unwrap_or(0);

        // Host-OS byte (high byte of version-made-by) 3 == Unix → the
        // external-attributes high word is a Unix st_mode.
        let host_os = (version_made_by >> 8) & 0xff;
        let unix_mode = if host_os == 3 { external_attr >> 16 } else { 0 };

        let is_dir = name.ends_with('/');
        let kind = if is_dir {
            EntryKind::Dir
        } else if unix_mode & S_IFMT == S_IFLNK {
            EntryKind::Symlink
        } else {
            EntryKind::Regular
        };
        let mode = if unix_mode & 0o7777 != 0 {
            (unix_mode & 0o7777) as u16
        } else if is_dir {
            0o755
        } else {
            0o644
        };

        // Encryption wraps the compressed body. Method 99 is WinZip AES,
        // whose real method and key size live in the 0x9901 extra; any
        // other encrypted member is traditional PKWARE.
        let aes = cx.aes.or(lx.aes);
        let (method, crypto) = if gp_flags & GP_ENCRYPTED != 0 {
            if method_id == METHOD_AES {
                match aes.and_then(|(ver, strength, m)| {
                    super::crypto::aes_key_bits(strength).map(|bits| (ver, bits, m))
                }) {
                    Some((vendor_version, key_bits, real)) => (
                        method_for(real, gp_flags),
                        Crypto::Aes {
                            key_bits,
                            vendor_version,
                        },
                    ),
                    None => (Method::Unsupported(METHOD_AES), Crypto::None),
                }
            } else {
                let check = if gp_flags & GP_DESCRIPTOR != 0 {
                    (dos_time >> 8) as u8
                } else {
                    (crc >> 24) as u8
                };
                (method_for(method_id, gp_flags), Crypto::ZipCrypto { check })
            }
        } else {
            (method_for(method_id, gp_flags), Crypto::None)
        };
        // AE-2 zeroes the CRC (its HMAC authenticates the body instead).
        let crc32 = match crypto {
            Crypto::Aes {
                vendor_version: 2, ..
            } => None,
            _ => Some(crc),
        };
        let loc = DataLocator {
            offset: data_off,
            compressed_len: comp,
            uncompressed_len: uncomp,
            method,
            crypto,
            crc32,
        };

        let mut entry = ArchiveEntry {
            path: name,
            kind,
            mode,
            uid,
            gid,
            mtime,
            atime,
            ctime,
            link_target: None,
            device_major: 0,
            device_minor: 0,
            data: None,
        };
        match kind {
            EntryKind::Regular => entry.data = Some(loc),
            EntryKind::Symlink => {
                // The body holds the link target; decode it now (targets
                // are tiny). Unsupported codecs leave it empty.
                if let Ok(mut r) =
                    crate::fs::archive::reader::open_with_password(dev, loc, password)
                {
                    let mut t = String::new();
                    use std::io::Read;
                    if r.read_to_string(&mut t).is_ok() {
                        entry.link_target = Some(t);
                    }
                }
            }
            _ => {}
        }
        idx.push(entry);

        p = comment_off + comment_len;
        seen += 1;
    }

    if seen == 0 && eocd.total_entries != 0 {
        return Err(Error::InvalidImage(format!(
            "zip: central directory declares {} entries but holds no readable record \
             at offset {}",
            eocd.total_entries, eocd.cd_offset
        )));
    }
    if eocd.total_entries != 0 && seen != eocd.total_entries {
        // Not fatal — some tools miscount — but worth surfacing in logs.
        crate::fstool_log!(
            debug,
            "zip: EOCD declared {} entries, walked {seen}",
            eocd.total_entries
        );
    }
    Ok(idx)
}

#[cfg(test)]
mod tests {
    use super::super::SIG_LOCAL;
    use super::*;
    use crate::block::MemoryBackend;

    fn u16le(v: &mut Vec<u8>, n: u16) {
        v.extend_from_slice(&n.to_le_bytes());
    }
    fn u32le(v: &mut Vec<u8>, n: u32) {
        v.extend_from_slice(&n.to_le_bytes());
    }

    /// A minimal single-entry stored ZIP: local header + body + central
    /// directory + EOCD. `gp` is the general-purpose flag word.
    fn one_entry_zip(name: &str, body: &[u8], gp: u16) -> Vec<u8> {
        let crc = crate::crc::crc32(body);
        let n = name.as_bytes();
        let mut z = Vec::new();
        u32le(&mut z, SIG_LOCAL);
        u16le(&mut z, 20);
        u16le(&mut z, gp);
        u16le(&mut z, METHOD_STORE);
        u16le(&mut z, 0);
        u16le(&mut z, 0);
        u32le(&mut z, crc);
        u32le(&mut z, body.len() as u32);
        u32le(&mut z, body.len() as u32);
        u16le(&mut z, n.len() as u16);
        u16le(&mut z, 0);
        z.extend_from_slice(n);
        z.extend_from_slice(body);

        let cd_offset = z.len() as u32;
        u32le(&mut z, SIG_CENTRAL);
        u16le(&mut z, 20);
        u16le(&mut z, 20);
        u16le(&mut z, gp);
        u16le(&mut z, METHOD_STORE);
        u16le(&mut z, 0);
        u16le(&mut z, 0);
        u32le(&mut z, crc);
        u32le(&mut z, body.len() as u32);
        u32le(&mut z, body.len() as u32);
        u16le(&mut z, n.len() as u16);
        u16le(&mut z, 0); // extra
        u16le(&mut z, 0); // comment
        u16le(&mut z, 0); // disk
        u16le(&mut z, 0); // internal attrs
        u32le(&mut z, 0); // external attrs
        u32le(&mut z, 0); // local header offset
        z.extend_from_slice(n);
        let cd_size = z.len() as u32 - cd_offset;

        u32le(&mut z, SIG_EOCD);
        u16le(&mut z, 0);
        u16le(&mut z, 0);
        u16le(&mut z, 1);
        u16le(&mut z, 1);
        u32le(&mut z, cd_size);
        u32le(&mut z, cd_offset);
        u16le(&mut z, 0);
        z
    }

    fn dev_from(bytes: &[u8]) -> MemoryBackend {
        let mut dev = MemoryBackend::new(bytes.len().max(1) as u64);
        dev.write_at(0, bytes).unwrap();
        dev
    }

    /// A self-extracting archive keeps the central-directory and local
    /// offsets relative to the start of the zip data. The scan used to
    /// read whatever sat at the declared (too small) offset, find no
    /// signature, and hand back an empty archive.
    #[test]
    fn sfx_prefix_is_corrected() {
        let zip = one_entry_zip("a.txt", b"hi", 0);
        let mut sfx = vec![0x7fu8; 4096]; // stand-in for the stub
        sfx.extend_from_slice(&zip);
        let mut dev = dev_from(&sfx);
        let idx = scan(&mut dev, None).unwrap();
        let e = idx
            .entries()
            .iter()
            .find(|e| e.path == "/a.txt")
            .expect("entry");
        let loc = e.data.as_ref().unwrap();
        // Local header is at 4096; body follows 30 bytes + the name.
        assert_eq!(loc.offset, 4096 + 30 + 5);
        assert_eq!(loc.uncompressed_len, 2);
    }

    /// Without a plausible prefix to blame, a central directory that
    /// holds no record while the EOCD counts entries is a broken image,
    /// not an empty archive.
    #[test]
    fn unreadable_central_directory_is_an_error() {
        let mut zip = one_entry_zip("a.txt", b"hi", 0);
        // The central record starts right after the 30+5+2 byte member.
        let cd = 30 + 5 + 2;
        zip[cd] ^= 0xff;
        let mut dev = dev_from(&zip);
        let err = match scan(&mut dev, None) {
            Ok(_) => panic!("scan accepted an unreadable central directory"),
            Err(e) => e,
        };
        assert!(
            matches!(err, Error::InvalidImage(_)),
            "expected InvalidImage, got {err:?}"
        );
    }

    /// General-purpose bit 0 means the body is ciphertext; without a
    /// passphrase it must not be fed to the method's decoder.
    #[test]
    fn encrypted_entry_is_flagged() {
        let zip = one_entry_zip("secret.txt", b"hi", 0x0001);
        let mut dev = dev_from(&zip);
        let idx = scan(&mut dev, None).unwrap();
        let e = idx
            .entries()
            .iter()
            .find(|e| e.path == "/secret.txt")
            .expect("entry");
        let loc = e.data.clone().unwrap();
        assert_eq!(loc.method, Method::Stored);
        let check = (crate::crc::crc32(b"hi") >> 24) as u8;
        assert_eq!(loc.crypto, Crypto::ZipCrypto { check });
        let err = match crate::fs::archive::reader::open(&mut dev, loc) {
            Ok(_) => panic!("reader opened an encrypted body"),
            Err(e) => e,
        };
        assert!(
            matches!(&err, crate::Error::InvalidArgument(m) if m.contains("passphrase")),
            "expected a passphrase request, got {err:?}"
        );
    }

    // ─── real archives, one per compression method ───────────────────
    //
    // `zip_{deflate64,ppmd,bzip2,lzma,xz}.zip` were written by 7-Zip
    // (`7zz a -tzip -mm=<Method>`; PPMd there is variant I, which we
    // only recognise), `zip_lzma_py.zip` by Python's
    // `zipfile` (a different LZMA version header), all holding the same
    // 1360-byte `a.txt`. The PKZIP 1.x members wrap compcol's own test
    // vectors: `zip_shrink.zip` (method 1) and `zip_reduce4.zip`
    // (method 5, factor 4) are payloads a reference encoder produced and
    // Info-ZIP verified; `zip_implode.zip` (method 6, 8 KiB window +
    // literal tree) was emitted by compcol's Implode fixture builder.

    fn read_member(arc: &[u8], path: &str) -> crate::Result<Vec<u8>> {
        use crate::fs::Filesystem;
        let mut dev = dev_from(arc);
        let mut fs = super::super::ZipFs::open(&mut dev)?;
        let mut r = fs.read_file(&mut dev, std::path::Path::new(path))?;
        let mut out = Vec::new();
        std::io::Read::read_to_end(&mut r, &mut out)?;
        Ok(out)
    }

    fn method_of(arc: &[u8], path: &str) -> Method {
        let mut dev = dev_from(arc);
        let idx = scan(&mut dev, None).unwrap();
        idx.lookup(path).unwrap().data.as_ref().unwrap().method
    }

    #[cfg(any(
        feature = "deflate64",
        feature = "bzip2",
        feature = "lzma",
        feature = "xz"
    ))]
    fn a_txt() -> Vec<u8> {
        b"hello hello hello hello zip world\n".repeat(40)
    }

    /// Every method id indexes, whatever this build can decode.
    #[test]
    fn every_method_is_recognised() {
        use crate::compression::Algo;
        let cases: [(&[u8], &str, Method); 8] = [
            (
                include_bytes!("../testdata/zip_deflate64.zip"),
                "/a.txt",
                Method::Deflate64,
            ),
            (
                include_bytes!("../testdata/zip_ppmd.zip"),
                "/a.txt",
                Method::ZipPpmd,
            ),
            (
                include_bytes!("../testdata/zip_bzip2.zip"),
                "/a.txt",
                Method::Codec(Algo::Bzip2),
            ),
            (
                include_bytes!("../testdata/zip_lzma.zip"),
                "/a.txt",
                Method::ZipLzma { eos: true },
            ),
            (
                include_bytes!("../testdata/zip_xz.zip"),
                "/a.txt",
                Method::Codec(Algo::Xz),
            ),
            (
                include_bytes!("../testdata/zip_shrink.zip"),
                "/lorem.txt",
                Method::ZipShrink,
            ),
            (
                include_bytes!("../testdata/zip_reduce4.zip"),
                "/hello.txt",
                Method::ZipReduce(4),
            ),
            (
                include_bytes!("../testdata/zip_implode.zip"),
                "/fox.txt",
                Method::ZipImplode {
                    large_window: true,
                    lit_tree: true,
                },
            ),
        ];
        for (arc, path, want) in cases {
            assert_eq!(method_of(arc, path), want);
        }
    }

    /// PPMd lists but reads `Unsupported` in every build: zip's variant I
    /// has no decoder in compcol (its `ppmd` is variant H).
    #[test]
    fn ppmd_lists_but_reads_unsupported() {
        let err = read_member(include_bytes!("../testdata/zip_ppmd.zip"), "/a.txt").unwrap_err();
        assert!(
            matches!(&err, Error::Unsupported(m) if m.contains("PPMd")),
            "expected Unsupported, got {err:?}"
        );
    }

    /// A method whose codec is compiled out reads `Unsupported` naming
    /// the feature, never garbage.
    #[cfg(not(feature = "zip-legacy"))]
    #[test]
    fn compiled_out_method_reads_unsupported() {
        let err =
            read_member(include_bytes!("../testdata/zip_shrink.zip"), "/lorem.txt").unwrap_err();
        assert!(
            matches!(&err, Error::Unsupported(m) if m.contains("zip-legacy")),
            "expected Unsupported naming the feature, got {err:?}"
        );
    }

    #[cfg(feature = "deflate64")]
    #[test]
    fn reads_deflate64() {
        let out = read_member(include_bytes!("../testdata/zip_deflate64.zip"), "/a.txt").unwrap();
        assert_eq!(out, a_txt());
    }

    #[cfg(feature = "bzip2")]
    #[test]
    fn reads_bzip2() {
        let out = read_member(include_bytes!("../testdata/zip_bzip2.zip"), "/a.txt").unwrap();
        assert_eq!(out, a_txt());
    }

    /// Both LZMA writers in the wild: 7-Zip and Python's zipfile set
    /// the end-of-stream bit and differ only in the version header.
    #[cfg(feature = "lzma")]
    #[test]
    fn reads_lzma() {
        for arc in [
            &include_bytes!("../testdata/zip_lzma.zip")[..],
            &include_bytes!("../testdata/zip_lzma_py.zip")[..],
        ] {
            assert_eq!(read_member(arc, "/a.txt").unwrap(), a_txt());
        }
    }

    #[cfg(feature = "xz")]
    #[test]
    fn reads_xz() {
        let out = read_member(include_bytes!("../testdata/zip_xz.zip"), "/a.txt").unwrap();
        assert_eq!(out, a_txt());
    }

    #[cfg(feature = "zip-legacy")]
    #[test]
    fn reads_pkzip_1x_methods() {
        assert_eq!(
            read_member(include_bytes!("../testdata/zip_shrink.zip"), "/lorem.txt").unwrap(),
            b"lorem ipsum dolor sit amet ".repeat(4)
        );
        assert_eq!(
            read_member(include_bytes!("../testdata/zip_reduce4.zip"), "/hello.txt").unwrap(),
            b"hello world"
        );
        assert_eq!(
            read_member(include_bytes!("../testdata/zip_implode.zip"), "/fox.txt").unwrap(),
            b"The quick brown fox jumps over the lazy dog. ".repeat(5)
        );
    }

    // ─── encryption, extras, split sets ──────────────────────────────
    //
    // `zip_crypt_infozip.zip` is `zip -P secret` (ZipCrypto with data
    // descriptors, `UT` + `ux` extras); `zip_crypt_7z.zip`, `zip_aes256.zip`
    // and `zip_aes128.zip` are 7-Zip's `-mem=ZipCrypto` / `AES256` /
    // `AES128` with the same passphrase (NTFS timestamps, AE-2);
    // `zip_split.z01` + `zip_split.zip` is `zip -s 64k` and
    // `zip_sevz.zip.001` + `.002` is `7zz -v64k`, both holding
    // `zip_split_noise.bin` and `a.txt`.

    fn read_member_pw(arc: &[u8], path: &str, pw: Option<&str>) -> crate::Result<Vec<u8>> {
        use crate::fs::Filesystem;
        let mut dev = dev_from(arc);
        let mut fs = super::super::ZipFs::open_with_password(&mut dev, pw)?;
        let mut r = fs.read_file(&mut dev, std::path::Path::new(path))?;
        let mut out = Vec::new();
        std::io::Read::read_to_end(&mut r, &mut out)?;
        Ok(out)
    }

    fn entry_of(arc: &[u8], path: &str) -> ArchiveEntry {
        let mut dev = dev_from(arc);
        let idx = scan(&mut dev, None).unwrap();
        idx.lookup(path).unwrap().clone()
    }

    const PLAIN: &[u8] = b"hello hello hello hello zip world\n";

    #[test]
    fn reads_zipcrypto_members() {
        let want = PLAIN.repeat(40);
        for arc in [
            &include_bytes!("../testdata/zip_crypt_infozip.zip")[..],
            &include_bytes!("../testdata/zip_crypt_7z.zip")[..],
        ] {
            let e = entry_of(arc, "/a.txt");
            assert!(matches!(
                e.data.as_ref().unwrap().crypto,
                Crypto::ZipCrypto { .. }
            ));
            if cfg!(feature = "gzip") {
                assert_eq!(read_member_pw(arc, "/a.txt", Some("secret")).unwrap(), want);
            }
            let err = read_member_pw(arc, "/a.txt", Some("wrong")).unwrap_err();
            assert!(
                matches!(&err, Error::InvalidArgument(m) if m.contains("wrong passphrase")),
                "{err:?}"
            );
            let err = read_member_pw(arc, "/a.txt", None).unwrap_err();
            assert!(
                matches!(&err, Error::InvalidArgument(m) if m.contains("passphrase")),
                "{err:?}"
            );
        }
        // A Stored encrypted member with a data descriptor (check byte
        // from the DOS time).
        assert_eq!(
            read_member_pw(
                include_bytes!("../testdata/zip_crypt_infozip.zip"),
                "/sub/deep.txt",
                Some("secret")
            )
            .unwrap(),
            b"nested file contents\n"
        );
    }

    #[test]
    fn aes_members_are_recognised() {
        for (arc, bits) in [
            (&include_bytes!("../testdata/zip_aes256.zip")[..], 256u16),
            (&include_bytes!("../testdata/zip_aes128.zip")[..], 128),
        ] {
            let e = entry_of(arc, "/a.txt");
            let loc = e.data.as_ref().unwrap();
            assert_eq!(loc.method, Method::Deflate, "{bits}");
            assert_eq!(
                loc.crypto,
                Crypto::Aes {
                    key_bits: bits,
                    vendor_version: 2
                }
            );
        }
    }

    #[cfg(all(feature = "zip-aes", feature = "gzip"))]
    #[test]
    fn reads_aes_members() {
        let want = PLAIN.repeat(40);
        for arc in [
            &include_bytes!("../testdata/zip_aes256.zip")[..],
            &include_bytes!("../testdata/zip_aes128.zip")[..],
        ] {
            assert_eq!(read_member_pw(arc, "/a.txt", Some("secret")).unwrap(), want);
            let err = read_member_pw(arc, "/a.txt", Some("wrong")).unwrap_err();
            assert!(
                matches!(&err, Error::InvalidArgument(m) if m.contains("wrong passphrase")),
                "{err:?}"
            );
        }
    }

    #[cfg(not(feature = "zip-aes"))]
    #[test]
    fn aes_without_feature_names_it() {
        let err = read_member_pw(
            include_bytes!("../testdata/zip_aes256.zip"),
            "/a.txt",
            Some("secret"),
        )
        .unwrap_err();
        assert!(
            matches!(&err, Error::Unsupported(m) if m.contains("zip-aes")),
            "{err:?}"
        );
    }

    /// Info-ZIP's `UT` (mtime in the central copy, atime in the local
    /// one) and `ux` (32-bit uid / gid) extras.
    #[test]
    fn reads_unix_extras() {
        let e = entry_of(
            include_bytes!("../testdata/zip_crypt_infozip.zip"),
            "/a.txt",
        );
        assert_eq!(e.uid, 501);
        assert_eq!(e.gid, 0);
        assert_eq!(e.mtime, 1_792_209_851);
        assert_eq!(e.atime, 1_792_209_851);
        assert_eq!(e.ctime, 0);
    }

    /// 7-Zip writes NTFS (0x000a) FILETIMEs instead; the mtime it holds
    /// is the same second the `UT` extra carries for the same file, and
    /// the atime / ctime slots it leaves zero read as "not recorded".
    #[test]
    fn reads_ntfs_timestamps() {
        let e = entry_of(include_bytes!("../testdata/zip_crypt_7z.zip"), "/a.txt");
        assert_eq!(e.mtime, 1_792_209_851);
        assert_eq!(e.atime, 0);
        assert_eq!(e.ctime, 0);
        assert_eq!(filetime_to_unix(0x01dd_5dec_90a4_9861), Some(1_792_209_851));
        assert_eq!(filetime_to_unix(0), None);
    }

    fn split_dev(parts: &[&[u8]]) -> crate::block::SplitBackend {
        let devs: Vec<Box<dyn BlockDevice>> = parts
            .iter()
            .map(|p| Box::new(dev_from(p)) as Box<dyn BlockDevice>)
            .collect();
        crate::block::SplitBackend::new(devs).unwrap()
    }

    fn read_split(parts: &[&[u8]], path: &str) -> crate::Result<Vec<u8>> {
        use crate::fs::Filesystem;
        let mut dev = split_dev(parts);
        let mut fs = super::super::ZipFs::open(&mut dev)?;
        let mut r = fs.read_file(&mut dev, std::path::Path::new(path))?;
        let mut out = Vec::new();
        std::io::Read::read_to_end(&mut r, &mut out)?;
        Ok(out)
    }

    /// An Info-ZIP `.z01` + `.zip` set: the first volume opens with the
    /// split signature, every offset is volume-relative, and the noise
    /// member straddles the two volumes.
    #[test]
    fn reads_infozip_split_set() {
        let z01 = &include_bytes!("../testdata/zip_split.z01")[..];
        let zip = &include_bytes!("../testdata/zip_split.zip")[..];
        assert_eq!(&z01[..4], &super::super::SIG_SPLIT.to_le_bytes());
        let noise = &include_bytes!("../testdata/zip_split_noise.bin")[..];
        // Info-ZIP deflated both members (the noise shrank by a byte or
        // two), so the bodies need the codec; the geometry does not.
        let mut set = split_dev(&[z01, zip]);
        let idx = scan(&mut set, None).unwrap();
        let loc = idx.lookup("/noise.bin").unwrap().data.clone().unwrap();
        assert_eq!(loc.uncompressed_len, noise.len() as u64);
        assert!(loc.offset > 4 && loc.offset + loc.compressed_len > z01.len() as u64);
        if cfg!(feature = "gzip") {
            assert_eq!(read_split(&[z01, zip], "/noise.bin").unwrap(), noise);
            assert_eq!(read_split(&[z01, zip], "/a.txt").unwrap(), PLAIN.repeat(40));
        }
        // The final volume alone cannot be read: its central directory
        // points at disk 0 and the error says so.
        let err = read_split(&[zip], "/noise.bin").unwrap_err();
        assert!(
            matches!(&err, Error::InvalidImage(m) if m.contains("volume set")),
            "{err:?}"
        );
    }

    /// 7-Zip's `-v` output is a plain byte split (`.001`, `.002`): disk
    /// numbers stay 0 and the concatenation is the archive.
    #[test]
    fn reads_byte_split_set() {
        let p1 = &include_bytes!("../testdata/zip_sevz.zip.001")[..];
        let p2 = &include_bytes!("../testdata/zip_sevz.zip.002")[..];
        let noise = &include_bytes!("../testdata/zip_split_noise.bin")[..];
        assert_eq!(read_split(&[p1, p2], "/noise.bin").unwrap(), noise);
    }
}
