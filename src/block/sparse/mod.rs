//! Apple sparse disk images: `.sparseimage` and `.sparsebundle`.
//!
//! Both are what `hdiutil create -type SPARSE` / `-type SPARSEBUNDLE`
//! produce: a large virtual disk whose storage is carved into fixed-size
//! **bands**, only the bands that were ever written taking space on the
//! host. A band that was never written reads as zeros; the first write
//! that lands in one allocates it.
//!
//! - [`SparseImageBackend`] — a single file: a 4 KiB `sprs` header whose
//!   band table maps file slots to virtual bands in allocation order,
//!   continued by extension headers chained through the file once the
//!   first header's 1,008 entries are used up.
//! - [`SparseBundleBackend`] — a directory: `Info.plist` (band size and
//!   virtual size), `token`, and `bands/<hex>`, one host file per band,
//!   where a missing file is a hole and a short one is zero-padded.
//!
//! ## Space management
//!
//! Three explicit operations sit beside the I/O:
//!
//! - [`resize`](SparseImageBackend::resize) changes the virtual size.
//!   Shrinking refuses to drop nonzero bytes unless the [`ShrinkPolicy`]
//!   says so.
//! - [`compact`](SparseImageBackend::compact) returns the space of bands
//!   that are entirely zero. It knows nothing of filesystems — and a
//!   deleted file leaves its bytes behind, so after deletions it finds
//!   little to do.
//! - [`reclaim`] is the filesystem-aware one: it reads each volume's
//!   allocation bitmap ([`crate::fs::free_space`]: HFS+, HFS, FAT, exFAT,
//!   ext2/3/4), through the partition table, and releases the bands that
//!   hold only free space, discarding the stale bytes of deleted files.
//!   It runs only on cleanly unmounted volumes; zeroing the free part of
//!   bands that also hold live data is a separate opt-in
//!   ([`PartialBandPolicy::ZeroFree`]). The backends'
//!   [`reclaim`](SparseImageBackend::reclaim) methods take the free ranges
//!   from the caller instead.
//!
//! All three leave a sparseimage untouched when they fail (see below); a
//! bundle is changed one atomic file operation at a time.
//!
//! ## Concurrency
//!
//! A writer takes an exclusive lock and a reader a shared one, through
//! [`std::fs::File::try_lock`], and a lock held elsewhere fails the open
//! instead of waiting. On Unix this is `flock(2)` — the same lock hdiutil
//! and `diskimages-helper` take on a `.sparseimage` and on a bundle's
//! `token` and `lock` files, so fstool and an attached image keep each
//! other out. On Windows it is `LockFileEx` over the whole file, which is
//! mandatory: while a writer holds a `.sparseimage` other processes cannot
//! read it either. Where the host filesystem has no locking (some network
//! mounts) the open goes ahead unlocked.
//!
//! ## Crash safety
//!
//! Both backends behave like a disk with a volatile write cache, with
//! [`sync`](super::BlockDevice::sync) as the cache flush: everything
//! written before a `sync` returns survives a crash; a write after it
//! may be lost — the band reads its previous contents, or zeros if it was
//! a hole — but a crash never makes a band read bytes that were not
//! written to it. That is the contract journaling filesystems already
//! rely on, so no journal of its own is needed. In detail:
//!
//! - **sparseimage.** A band's slot is zeroed and its data written
//!   first; the band-table entry that maps it is written only at `sync`
//!   (or drop) after a flush of that data, and flushed in turn before an
//!   extension header holding new entries is linked from the header
//!   before it. A crash in between leaves the entry missing — the band is
//!   a hole again — and the next writer zeroes the unreachable slot before
//!   reusing it, so its stale bytes can never be mapped. Overwrites of
//!   mapped bands are in place, like sector writes. The header fields
//!   (size, flags) and any table entry each lie within one 512-byte
//!   sector, so a grow is a single-sector update; a torn table write
//!   leaves a prefix of the new entries. Shrink, compact and reclaim
//!   write a complete new image beside the old one, flush it and rename
//!   it into place: a crash leaves the old image or the new one. These
//!   orderings are checked by replaying recorded writes in every order
//!   the disk could persist them between flushes.
//! - **sparsebundle.** There is no mapping table: a band exists when its
//!   file does, and a missing or short file reads as zeros. Band files
//!   are flushed at `sync` along with the `bands/` directory. A shrink
//!   deletes and truncates band files before `Info.plist` (replaced by
//!   write-flush-rename) records the new size; compaction and reclamation
//!   delete band files one at a time, each deletion atomic and each
//!   dropping only bytes that were zero or free.

mod bundle;
mod image;
pub(crate) mod plist;
mod reclaim;

pub use bundle::SparseBundleBackend;
pub use image::SparseImageBackend;
pub use reclaim::{
    MappedVolume, PartialBandPolicy, ReclaimOpts, ReclaimReport, ReclaimStats, SkippedVolume,
    SparseBackend, reclaim,
};

use std::fs::{File, Metadata};
use std::io;
use std::path::Path;

/// What [`SparseImageBackend::resize`] / [`SparseBundleBackend::resize`]
/// may do with data past a shrunken end.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum ShrinkPolicy {
    /// Refuse — leaving the image unchanged — if any byte past the new
    /// end is nonzero.
    #[default]
    RequireZero,
    /// Drop whatever lies past the new end.
    Discard,
}

/// Default sparseimage band: 2,048 sectors (1 MiB), as `hdiutil` makes.
pub const DEFAULT_IMAGE_BAND_SIZE: u64 = 1 << 20;
/// Default sparsebundle band: 8 MiB, as `hdiutil` makes.
pub const DEFAULT_BUNDLE_BAND_SIZE: u64 = 8 << 20;
/// Largest band either backend accepts, from a header or a caller.
pub const MAX_BAND_SIZE: u64 = 1 << 32;

/// True when `path`'s extension is `.sparseimage`.
pub fn is_sparseimage_path(path: &Path) -> bool {
    ext_is(path, "sparseimage")
}

/// True when `path`'s extension is `.sparsebundle`.
pub fn is_sparsebundle_path(path: &Path) -> bool {
    ext_is(path, "sparsebundle")
}

fn ext_is(path: &Path, want: &str) -> bool {
    path.extension()
        .and_then(|s| s.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case(want))
}

/// Open `path` as whichever sparse format it is, or `None` when it is
/// neither (by content, not extension).
pub(crate) fn open_auto(
    path: &Path,
    read_only: bool,
) -> crate::Result<Option<alloc::boxed::Box<dyn super::BlockDevice>>> {
    if SparseBundleBackend::probe(path)? {
        let b = if read_only {
            SparseBundleBackend::open_read_only(path)?
        } else {
            SparseBundleBackend::open(path)?
        };
        return Ok(Some(alloc::boxed::Box::new(b)));
    }
    refuse_encrypted_image(path)?;
    if SparseImageBackend::probe(path)? {
        let b = if read_only {
            SparseImageBackend::open_read_only(path)?
        } else {
            SparseImageBackend::open(path)?
        };
        return Ok(Some(alloc::boxed::Box::new(b)));
    }
    Ok(None)
}

/// An encrypted `.sparseimage` is an `encrcdsa` container around the
/// `sprs` file. Decrypting it is not supported: say so, rather than let it
/// be read as a raw disk full of ciphertext.
fn refuse_encrypted_image(path: &Path) -> crate::Result<()> {
    if !is_sparseimage_path(path) || !path.is_file() {
        return Ok(());
    }
    let mut head = [0u8; 8];
    let mut f = File::open(path)?;
    read_full_at(&mut f, 0, &mut head)?;
    if &head == b"encrcdsa" {
        return Err(crate::Error::Unsupported(format!(
            "{}: encrypted sparseimages are not supported",
            path.display()
        )));
    }
    Ok(())
}

/// Validate a caller-supplied band size: a nonzero multiple of 512, at
/// most [`MAX_BAND_SIZE`].
fn check_band_size(band_size: u64) -> crate::Result<()> {
    if band_size == 0 || !band_size.is_multiple_of(512) || band_size > MAX_BAND_SIZE {
        return Err(crate::Error::InvalidArgument(format!(
            "sparse image: band size {band_size} must be a nonzero multiple of 512 \
             no larger than {MAX_BAND_SIZE}"
        )));
    }
    Ok(())
}

/// How long [`lock`] retries a contended lock.
const LOCK_GRACE: std::time::Duration = std::time::Duration::from_millis(500);

/// Take the advisory lock: exclusive for a writer, shared for a reader.
///
/// Contention is retried for up to [`LOCK_GRACE`] before giving up. A
/// child process spawned by another thread shares our open files until
/// its `exec` closes them, so an image this process just closed can look
/// locked for a few milliseconds; an image attached in hdiutil or held by
/// another fstool stays locked and still fails.
fn lock(file: &File, exclusive: bool, what: &Path) -> crate::Result<()> {
    let deadline = std::time::Instant::now() + LOCK_GRACE;
    let r = loop {
        let r = if exclusive {
            file.try_lock()
        } else {
            file.try_lock_shared()
        };
        match r {
            Err(std::fs::TryLockError::WouldBlock) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            r => break r,
        }
    };
    match r {
        Ok(()) => Ok(()),
        Err(std::fs::TryLockError::WouldBlock) => Err(crate::Error::Io(io::Error::new(
            io::ErrorKind::ResourceBusy,
            format!(
                "{}: in use by another process (attached, or open in another fstool)",
                what.display()
            ),
        ))),
        // No locking on this filesystem: carry on unlocked.
        Err(std::fs::TryLockError::Error(e)) if e.kind() == io::ErrorKind::Unsupported => Ok(()),
        Err(std::fs::TryLockError::Error(e)) => Err(e.into()),
    }
}

/// True for a symlink, or on Windows any reparse point (junctions,
/// mount points and the like as well as symlinks).
fn is_link(meta: &Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }
    false
}

/// Refuse anything that is not a plain regular file (symlinks and
/// reparse points first of all) before it is opened.
fn require_regular(path: &Path) -> crate::Result<Metadata> {
    let meta = std::fs::symlink_metadata(path)?;
    if is_link(&meta) {
        return Err(crate::Error::InvalidImage(format!(
            "{}: is a symlink or reparse point — refusing to follow it out of the image",
            path.display()
        )));
    }
    if !meta.is_file() {
        return Err(crate::Error::InvalidImage(format!(
            "{}: not a regular file",
            path.display()
        )));
    }
    Ok(meta)
}

/// After opening a path checked with [`require_regular`], make sure the
/// handle is that same file — closing the window in which it could have
/// been swapped for a link.
fn same_file(opened: &File, checked: &Metadata, path: &Path) -> crate::Result<()> {
    let now = opened.metadata()?;
    let same = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            now.dev() == checked.dev() && now.ino() == checked.ino()
        }
        #[cfg(not(unix))]
        {
            now.is_file() && now.len() == checked.len()
        }
    };
    if !same || !now.is_file() {
        return Err(crate::Error::InvalidImage(format!(
            "{}: changed while being opened",
            path.display()
        )));
    }
    Ok(())
}

/// Open a regular file that must not be a link, verifying the handle.
///
/// On Windows the open itself refuses to traverse a reparse point
/// (`FILE_FLAG_OPEN_REPARSE_POINT` opens the link, not its target, and the
/// handle's attributes are then checked).
fn open_regular(path: &Path, opts: &std::fs::OpenOptions) -> crate::Result<File> {
    let meta = require_regular(path)?;
    #[cfg(windows)]
    let f = {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        let mut o = opts.clone();
        o.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        let f = o.open(path)?;
        if is_link(&f.metadata()?) {
            return Err(crate::Error::InvalidImage(format!(
                "{}: is a reparse point — refusing to follow it out of the image",
                path.display()
            )));
        }
        f
    };
    #[cfg(not(windows))]
    let f = opts.open(path)?;
    same_file(&f, &meta, path)?;
    Ok(f)
}

/// Read up to `buf.len()` bytes at `off`, zero-filling past EOF.
fn read_full_at(file: &mut File, off: u64, buf: &mut [u8]) -> io::Result<()> {
    use std::io::{Read, Seek, SeekFrom};
    file.seek(SeekFrom::Start(off))?;
    let mut done = 0;
    while done < buf.len() {
        match file.read(&mut buf[done..]) {
            Ok(0) => break,
            Ok(n) => done += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    buf[done..].fill(0);
    Ok(())
}

fn write_all_at(file: &mut File, off: u64, buf: &[u8]) -> io::Result<()> {
    use std::io::{Seek, SeekFrom, Write};
    file.seek(SeekFrom::Start(off))?;
    file.write_all(buf)
}

/// Write `len` zero bytes at `off`.
fn write_zeros_at(file: &mut File, mut off: u64, mut len: u64) -> io::Result<()> {
    let zero = [0u8; 64 * 1024];
    while len > 0 {
        let n = len.min(zero.len() as u64) as usize;
        write_all_at(file, off, &zero[..n])?;
        off += n as u64;
        len -= n as u64;
    }
    Ok(())
}

/// True when `len` bytes of `file` from `off` are all zero (bytes past
/// EOF count as zero).
fn range_is_zero(file: &mut File, mut off: u64, mut len: u64) -> io::Result<bool> {
    let mut buf = alloc::vec![0u8; 64 * 1024];
    while len > 0 {
        let n = len.min(buf.len() as u64) as usize;
        read_full_at(file, off, &mut buf[..n])?;
        if buf[..n].iter().any(|&b| b != 0) {
            return Ok(false);
        }
        off += n as u64;
        len -= n as u64;
    }
    Ok(true)
}

/// Flush a directory's entries (new / renamed / removed files) to disk.
/// A no-op where directories can't be opened for that (Windows).
fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

/// Split `[off, off+len)` at band boundaries: yields
/// `(band, offset_in_band, buf_start, piece_len)`.
fn band_pieces(
    off: u64,
    len: usize,
    band_size: u64,
) -> impl Iterator<Item = (u64, u64, usize, usize)> {
    let mut done = 0usize;
    core::iter::from_fn(move || {
        if done >= len {
            return None;
        }
        let pos = off + done as u64;
        let band = pos / band_size;
        let inner = pos % band_size;
        let n = ((band_size - inner).min((len - done) as u64)) as usize;
        let item = (band, inner, done, n);
        done += n;
        Some(item)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn band_pieces_split_at_boundaries() {
        let v: alloc::vec::Vec<_> = band_pieces(1000, 3000, 1024).collect();
        assert_eq!(
            v,
            [
                (0, 1000, 0, 24),
                (1, 0, 24, 1024),
                (2, 0, 1048, 1024),
                (3, 0, 2072, 928)
            ]
        );
        assert_eq!(band_pieces(0, 0, 512).count(), 0);
        let v: alloc::vec::Vec<_> = band_pieces(2048, 1024, 1024).collect();
        assert_eq!(v, [(2, 0, 0, 1024)]);
    }

    #[test]
    fn encrypted_sparseimage_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("e.sparseimage");
        let mut raw = b"encrcdsa".to_vec();
        raw.resize(8192, 0);
        std::fs::write(&p, raw).unwrap();
        assert!(matches!(
            open_auto(&p, true),
            Err(crate::Error::Unsupported(_))
        ));
        assert!(matches!(
            SparseBackend::open(&p),
            Err(crate::Error::Unsupported(_))
        ));
    }

    #[test]
    fn path_helpers() {
        assert!(is_sparseimage_path(Path::new("a/b.SparseImage")));
        assert!(is_sparsebundle_path(Path::new("x.sparsebundle")));
        assert!(!is_sparsebundle_path(Path::new("x.sparseimage")));
        assert!(check_band_size(0).is_err());
        assert!(check_band_size(1000).is_err());
        assert!(check_band_size(MAX_BAND_SIZE * 2).is_err());
        assert!(check_band_size(4096).is_ok());
    }
}
