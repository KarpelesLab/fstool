//! ZIP reader: locate the End-Of-Central-Directory, follow ZIP64 when
//! present, and walk the central directory into an [`ArchiveIndex`].

use super::encoding;
use super::{
    METHOD_DEFLATE, METHOD_STORE, SIG_CENTRAL, SIG_EOCD, SIG_ZIP64_EOCD, SIG_ZIP64_LOCATOR,
};
use crate::block::BlockDevice;
use crate::fs::archive::{ArchiveEntry, ArchiveIndex, DataLocator, EntryKind, Method};
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

/// Central-directory geometry resolved from the EOCD (+ ZIP64).
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
    let mut cd_size = le32(&tail, i + 12) as u64;
    let mut cd_offset = le32(&tail, i + 16) as u64;
    let mut total_entries = le16(&tail, i + 10) as u64;
    let mut zip64 = false;

    // ZIP64: a locator sits 20 bytes before the EOCD.
    if i >= 20 && le32(&tail, i - 20) == SIG_ZIP64_LOCATOR {
        let z64_eocd_off = le64(&tail, i - 20 + 8);
        let mut rec = [0u8; 56];
        dev.read_at(z64_eocd_off, &mut rec)?;
        if le32(&rec, 0) != SIG_ZIP64_EOCD {
            return Err(Error::InvalidImage(
                "zip: ZIP64 locator points at a bad record".into(),
            ));
        }
        total_entries = le64(&rec, 32);
        cd_size = le64(&rec, 40);
        cd_offset = le64(&rec, 48);
        zip64 = true;
    }

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
    // correction, so don't guess there.
    let prefix_delta = if zip64 {
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

/// Walk a per-entry extra field, applying ZIP64 overrides and reading a
/// Unix mtime from the `UT` (0x5455) extra. `comp`/`uncomp`/`offset`
/// are overridden from the ZIP64 (0x0001) field only for the values
/// that were `0xFFFFFFFF`.
fn apply_extras(extra: &[u8], comp: &mut u64, uncomp: &mut u64, offset: &mut u64, mtime: &mut u64) {
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
                }
            }
            0x5455
                // UT: flags byte, then mtime if bit 0 set.
                if !body.is_empty() && (body[0] & 1) != 0 && body.len() >= 5 => {
                    *mtime = le32(body, 1) as u64;
                }
            _ => {}
        }
        p = body_start + len;
    }
}

/// General-purpose bit 0: the body is encrypted (traditional PKWARE or,
/// together with bit 6 / method 99, one of the strong variants).
const GP_ENCRYPTED: u16 = 0x0001;

/// Map a ZIP compression-method id to our [`Method`].
fn method_for(id: u16) -> Method {
    match id {
        METHOD_STORE => Method::Stored,
        METHOD_DEFLATE => Method::Deflate,
        93 => Method::Codec(crate::compression::Algo::Zstd),
        other => Method::Unsupported(other),
    }
}

pub fn scan(dev: &mut dyn BlockDevice) -> Result<ArchiveIndex> {
    let eocd = find_eocd(dev)?;
    let mut cd = vec![0u8; eocd.cd_size as usize];
    dev.read_at(eocd.cd_offset, &mut cd)?;

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
        let name_len = le16(&cd, p + 28) as usize;
        let extra_len = le16(&cd, p + 30) as usize;
        let comment_len = le16(&cd, p + 32) as usize;
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

        let mut mtime = super::dos_to_unix(dos_date, dos_time);
        apply_extras(extra, &mut comp, &mut uncomp, &mut local_offset, &mut mtime);

        let name = encoding::decode_name(name_bytes, gp_flags & 0x0800 != 0);

        // Resolve the data offset from the *local* header (its extra
        // field length may differ from the central one).
        let local_offset = local_offset
            .checked_add(base)
            .filter(|o| o.saturating_add(30) <= dev.total_size())
            .ok_or_else(|| {
                Error::InvalidImage("zip: local-header offset past end of archive".into())
            })?;
        let mut lh = [0u8; 30];
        dev.read_at(local_offset, &mut lh)?;
        let l_name = le16(&lh, 26) as u64;
        let l_extra = le16(&lh, 28) as u64;
        let data_off = local_offset + 30 + l_name + l_extra;

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

        // An encrypted body is ciphertext whatever the method id says;
        // index it but refuse to hand it to a decompressor.
        let method = if gp_flags & GP_ENCRYPTED != 0 {
            Method::Encrypted
        } else {
            method_for(method_id)
        };
        let loc = DataLocator {
            offset: data_off,
            compressed_len: comp,
            uncompressed_len: uncomp,
            method,
        };

        let mut entry = ArchiveEntry {
            path: name,
            kind,
            mode,
            uid: 0,
            gid: 0,
            mtime,
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
                if let Ok(mut r) = crate::fs::archive::reader::open(dev, loc) {
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
        let idx = scan(&mut dev).unwrap();
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
        let err = match scan(&mut dev) {
            Ok(_) => panic!("scan accepted an unreadable central directory"),
            Err(e) => e,
        };
        assert!(
            matches!(err, Error::InvalidImage(_)),
            "expected InvalidImage, got {err:?}"
        );
    }

    /// General-purpose bit 0 means the body is ciphertext; it must not be
    /// fed to the method's decoder.
    #[test]
    fn encrypted_entry_is_flagged() {
        let zip = one_entry_zip("secret.txt", b"hi", 0x0001);
        let mut dev = dev_from(&zip);
        let idx = scan(&mut dev).unwrap();
        let e = idx
            .entries()
            .iter()
            .find(|e| e.path == "/secret.txt")
            .expect("entry");
        assert_eq!(e.data.as_ref().unwrap().method, Method::Encrypted);
        let loc = e.data.clone().unwrap();
        let err = match crate::fs::archive::reader::open(&mut dev, loc) {
            Ok(_) => panic!("reader opened an encrypted body"),
            Err(e) => e,
        };
        assert!(
            matches!(err, crate::Error::Unsupported(_)),
            "expected Unsupported, got {err:?}"
        );
    }
}
