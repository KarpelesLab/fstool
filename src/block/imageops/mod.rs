//! Container-level image operations: conversion, checksums and
//! container-only resizing, all streamed through [`BlockDevice`] without
//! looking at (or rebuilding) the filesystem inside.
//!
//! | Operation | Function | Needs |
//! |---|---|---|
//! | Checksum, stored bytes or logical sectors | [`image_checksum`] | `std` (UDIF: `dmg`) |
//! | Convert between raw, UDIF and sparse images | [`convert_image`] | `std` (UDIF source: `dmg`, target: `dmg-write`; sparse: `sparse-image`) |
//! | Grow / shrink the *container* | [`resize_container`] | `std` (sparse: `sparse-image`, UDIF: `dmg-write`) |
//!
//! UDIF-specific editing — verifying embedded checksums, segmenting and
//! joining, resource import/export, removing a code signature — lives in
//! [`crate::block::dmg`].
//!
//! ## Common rules
//!
//! - **Logical sectors are preserved.** A conversion reproduces every
//!   sector of the source, in order, and nothing else; a converted image
//!   reads back byte-identical.
//! - **Bounded memory.** Everything streams in chunk-sized pieces (1 MiB,
//!   or the UDIF chunk size).
//! - **Failures preserve existing outputs.** A destination path is only
//!   ever replaced by a complete result: output is written to a hidden
//!   sibling and renamed over the destination on success, and removed on
//!   failure. In-place resizes check everything before changing anything.
//! - **Choices are explicit inputs.** Credentials (a passphrase for an
//!   encrypted source), data loss (discarding sectors on a shrink,
//!   dropping a code signature or a legacy resource fork) and checksum
//!   algorithms are options; an algorithm fstool cannot compute is
//!   [`crate::Error::Unsupported`], never silently replaced.

mod checksum;
mod convert;
mod resize;
#[cfg(all(test, feature = "dmg-write"))]
mod tests;

pub use checksum::{
    ChecksumAlgorithm, ChecksumHasher, ChecksumOptions, ChecksumScope, ImageChecksum,
    image_checksum,
};
pub use convert::{ConvertOptions, ConvertReport, ImageKind, ResourcePolicy, convert_image};
pub use resize::{ContainerResizeOptions, ContainerResizeReport, ShrinkData, resize_container};

use std::path::{Path, PathBuf};

use crate::Result;
use crate::block::BlockDevice;

/// Lower-case hex of `bytes`.
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Copy buffer size for the streaming loops.
pub(crate) const COPY_CHUNK: usize = 1 << 20;

/// Open `path` read-only as the logical sectors it holds, with an explicit
/// passphrase for encrypted containers.
///
/// Beyond [`crate::block::open_image_read_only_with_password`], this
/// opens a passphrase-protected `.dmg` (`encrcdsa`): with no passphrase it
/// is refused rather than read as ciphertext, and its plaintext — a UDIF
/// image, or bare sectors — is decoded.
pub(crate) fn open_source(path: &Path, password: Option<&str>) -> Result<Box<dyn BlockDevice>> {
    #[cfg(feature = "dmg")]
    if crate::block::dmg::probe_encrypted(path)? {
        let Some(pw) = password else {
            return Err(crate::Error::InvalidArgument(format!(
                "{} is a passphrase-protected disk image; supply the passphrase",
                path.display()
            )));
        };
        #[cfg(feature = "dmg-encrypted")]
        {
            use std::io::{Read, Seek, SeekFrom};
            let mut enc = crate::block::dmg::EncryptedDmgBackend::open_with_password(path, pw)?;
            let len = enc.total_size();
            let mut magic = [0u8; 4];
            if len >= crate::block::dmg::KOLY_SIZE {
                enc.seek(SeekFrom::Start(len - crate::block::dmg::KOLY_SIZE))?;
                enc.read_exact(&mut magic)?;
            }
            enc.seek(SeekFrom::Start(0))?;
            if u32::from_be_bytes(magic) == crate::block::dmg::KOLY_MAGIC {
                return Ok(Box::new(crate::block::dmg::DmgBackend::from_reader(
                    enc, len,
                )?));
            }
            return Ok(Box::new(enc));
        }
        #[cfg(not(feature = "dmg-encrypted"))]
        {
            let _ = pw;
            return Err(crate::Error::Unsupported(
                "encrypted disk images need the `dmg-encrypted` feature".into(),
            ));
        }
    }
    crate::block::open_image_read_only_with_password(path, password)
}

/// Whether `path` holds a UDIF image (a koly trailer).
pub(crate) fn is_udif(path: &Path) -> Result<bool> {
    #[cfg(feature = "dmg")]
    {
        if path.is_file() {
            return crate::block::dmg::probe(path);
        }
        Ok(false)
    }
    #[cfg(not(feature = "dmg"))]
    {
        let _ = path;
        Ok(false)
    }
}

/// A hidden sibling of `dst` to build output in:
/// `.<name>.<pid>.<tag>.partial.<ext>` — keeping the extension, which
/// [`crate::block::create_image`] picks the container by.
pub(crate) fn temp_sibling(dst: &Path, tag: &str) -> Result<PathBuf> {
    let name = dst.file_name().ok_or_else(|| {
        crate::Error::InvalidArgument(format!("{} has no file name", dst.display()))
    })?;
    let mut tmp = std::ffi::OsString::from(".");
    tmp.push(name);
    tmp.push(format!(".{}.{tag}.partial", std::process::id()));
    if let Some(ext) = dst.extension() {
        tmp.push(".");
        tmp.push(ext);
    }
    Ok(dst.with_file_name(tmp))
}

/// Remove a file or directory tree, ignoring "not found".
pub(crate) fn remove_any(p: &Path) -> std::io::Result<()> {
    let r = if p.is_dir() {
        std::fs::remove_dir_all(p)
    } else {
        std::fs::remove_file(p)
    };
    match r {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// Move a finished `tmp` over `dst`. A file replaces a file atomically; a
/// directory (sparsebundle) is swapped in via a second sibling so the old
/// one survives until the new one is in place.
pub(crate) fn publish(tmp: &Path, dst: &Path) -> Result<()> {
    if tmp.is_dir() && dst.exists() {
        let old = temp_sibling(dst, "old")?;
        std::fs::rename(dst, &old)?;
        if let Err(e) = std::fs::rename(tmp, dst) {
            let _ = std::fs::rename(&old, dst);
            return Err(e.into());
        }
        remove_any(&old)?;
        return Ok(());
    }
    std::fs::rename(tmp, dst)?;
    Ok(())
}

/// Run `build` against a temp sibling of `dst`, then publish it; on any
/// error the temp is removed and `dst` is untouched.
pub(crate) fn write_beside<T>(dst: &Path, build: impl FnOnce(&Path) -> Result<T>) -> Result<T> {
    let tmp = temp_sibling(dst, "new")?;
    let _ = remove_any(&tmp);
    let r = build(&tmp).and_then(|v| {
        publish(&tmp, dst)?;
        Ok(v)
    });
    if r.is_err() {
        let _ = remove_any(&tmp);
    }
    r
}

/// Whether `a` and `b` name the same existing file.
pub(crate) fn same_file(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}
