//! `ar` writer: members stored uncompressed, streamed straight to the
//! device as they arrive.
//!
//! Names that fit the 16-byte header field (and carry no space) sit
//! there directly, space-padded — the traditional/BSD layout, not GNU's
//! trailing-`/` form, so BSD `ar` extracts them by name. Longer names
//! (or any with a space) use the BSD `#1/<len>` convention — the name
//! bytes are prepended to the body — rather than GNU's leading `//`
//! string table. Neither form needs a forward reference, so each
//! member's header + name + body flush to the device the moment
//! [`add_file`](ArWriter::add_file) is called and no body is ever
//! retained in memory. Our own reader ([`super::scan`]) decodes both
//! forms, and GNU `ar` reads BSD `#1/` names too.

use crate::block::BlockDevice;
use crate::fs::archive::ArchiveBuilder;
use crate::fs::archive::tree;
use crate::fs::archive::writer::Cursor;
use crate::fs::{DeviceKind, FileMeta};
use crate::{Error, Result};

pub struct ArWriter {
    cursor: Cursor,
    /// Set once the 8-byte global header has been emitted.
    began: bool,
}

impl ArWriter {
    pub fn new(dev: &dyn BlockDevice) -> Self {
        Self {
            cursor: Cursor::new(dev),
            began: false,
        }
    }

    /// Emit the `!<arch>\n` global header before the first member (or on
    /// `finish` for an empty archive).
    fn ensure_magic(&mut self, dev: &mut dyn BlockDevice) -> Result<()> {
        if !self.began {
            self.cursor.write(dev, super::MAGIC)?;
            self.began = true;
        }
        Ok(())
    }
}

/// `ar` is flat: reject a path that names a subdirectory.
fn flat_name(path: &str) -> Result<String> {
    let norm = tree::normalise_path(path);
    let leaf = norm.trim_start_matches('/');
    if leaf.contains('/') {
        return Err(Error::Unsupported(format!(
            "ar: {path:?} is inside a subdirectory — `ar` is a flat archive; \
             use tar/zip/cpio for directory trees"
        )));
    }
    Ok(leaf.to_string())
}

/// Left-justify `s` into `field`, space-padding the remainder.
fn put(field: &mut [u8], s: &str) {
    let b = s.as_bytes();
    let n = b.len().min(field.len());
    field[..n].copy_from_slice(&b[..n]);
}

/// Build a 60-byte member header. `member_len` is the on-disk body
/// length (for a BSD `#1/` member that includes the prepended name).
fn member_header(
    name_field: &str,
    mtime: u64,
    uid: u32,
    gid: u32,
    mode: u16,
    member_len: u64,
) -> [u8; 60] {
    let mut hdr = [b' '; 60];
    put(&mut hdr[0..16], name_field);
    put(&mut hdr[16..28], &mtime.to_string());
    put(&mut hdr[28..34], &uid.to_string());
    put(&mut hdr[34..40], &gid.to_string());
    // Full st_mode in octal (regular file | perm bits), e.g. "100644".
    put(
        &mut hdr[40..48],
        &format!("{:o}", 0o100000u32 | u32::from(mode)),
    );
    put(&mut hdr[48..58], &member_len.to_string());
    hdr[58] = b'`';
    hdr[59] = b'\n';
    hdr
}

impl ArchiveBuilder for ArWriter {
    fn add_file_streaming(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &str,
        body: &mut dyn std::io::Read,
        len: u64,
        meta: FileMeta,
    ) -> Result<()> {
        let name = flat_name(path)?;

        // A name that fits the 16-byte field (and has no space, which
        // trailing padding would swallow) sits there directly; anything
        // longer uses the BSD `#1/<len>` inline form so nothing has to be
        // buffered for a leading string table.
        let bsd = name.len() > 16 || name.contains(' ');
        let (name_field, member_len) = if bsd {
            (format!("#1/{}", name.len()), name.len() as u64 + len)
        } else {
            (name.clone(), len)
        };

        self.ensure_magic(dev)?;
        let hdr = member_header(
            &name_field,
            u64::from(meta.mtime),
            meta.uid,
            meta.gid,
            meta.mode,
            member_len,
        );
        self.cursor.write(dev, &hdr)?;
        if bsd {
            self.cursor.write(dev, name.as_bytes())?;
        }

        // Stream the body straight through (reader derefs to dyn Read).
        let mut remaining = len;
        let mut buf = [0u8; 64 * 1024];
        while remaining > 0 {
            let want = remaining.min(buf.len() as u64) as usize;
            body.read_exact(&mut buf[..want]).map_err(Error::from)?;
            self.cursor.write(dev, &buf[..want])?;
            remaining -= want as u64;
        }
        // Members are padded to an even offset with a newline.
        if member_len % 2 == 1 {
            self.cursor.write(dev, b"\n")?;
        }
        Ok(())
    }

    fn add_dir(&mut self, _dev: &mut dyn BlockDevice, _path: &str, _meta: FileMeta) -> Result<()> {
        // `ar` has no directories; silently drop (files carry no path).
        Ok(())
    }

    fn add_symlink(
        &mut self,
        _dev: &mut dyn BlockDevice,
        path: &str,
        _target: &str,
        _meta: FileMeta,
    ) -> Result<()> {
        Err(Error::Unsupported(format!(
            "ar: cannot store symlink {path:?} — `ar` has no symlink records"
        )))
    }

    fn add_device(
        &mut self,
        _dev: &mut dyn BlockDevice,
        path: &str,
        _kind: DeviceKind,
        _major: u32,
        _minor: u32,
        _meta: FileMeta,
    ) -> Result<()> {
        Err(Error::Unsupported(format!(
            "ar: cannot store device/special node {path:?}"
        )))
    }

    fn finish(&mut self, dev: &mut dyn BlockDevice) -> Result<()> {
        // Members are already on the device; just make sure an empty
        // archive still carries the global header, then sync.
        self.ensure_magic(dev)?;
        dev.sync()?;
        Ok(())
    }

    fn position(&self) -> u64 {
        self.cursor.position()
    }
}
