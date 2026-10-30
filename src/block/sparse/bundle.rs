//! `.sparsebundle` — Apple's directory-based sparse disk image.
//!
//! ```text
//! name.sparsebundle/
//!   Info.plist   band-size, size, diskimage-bundle-type, bundle-backingstore-version
//!   Info.bckup   a copy of Info.plist
//!   token        empty unless the bundle is encrypted
//!   lock         empty; hdiutil holds a lock on it (and on token) while attached
//!   bands/0, bands/1, … bands/1a, …
//! ```
//!
//! Band `n` lives in `bands/<n in lowercase hex, unpadded>` and covers
//! virtual bytes `[n × band-size, (n+1) × band-size)`. A missing band file
//! reads as zeros and a short one is zero past its end — hdiutil leaves
//! most band files short.
//!
//! ## Validation
//!
//! The bundle's own path may be a symlink (it is what the caller asked
//! for), but nothing inside it may be: `bands/`, `Info.plist`, `token`,
//! `lock` and every band file must be a plain directory or file, so a
//! crafted bundle cannot read or write outside itself. Band files are
//! re-checked when opened. A band name that is hex but not in canonical
//! form (`00a`, `A`) would alias another band and is refused, as is one
//! past the last band or longer than a band; other names (`.DS_Store`) are
//! ignored.
//!
//! Encrypted bundles (a non-empty `token`) are refused with
//! [`Error::Unsupported`](crate::Error::Unsupported).

use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};

use super::plist;
use super::reclaim::{
    PartialBandPolicy, ReclaimOpts, ReclaimStats, check_ranges, complement, free_within,
};
use super::{
    ShrinkPolicy, band_pieces, check_band_size, is_link, lock, open_regular, range_is_zero,
    read_full_at, require_regular, sync_dir, write_all_at, write_zeros_at,
};
use crate::Result;
use crate::block::BlockDevice;

const BUNDLE_TYPE: &str = "com.apple.diskimage.sparsebundle";
/// Open band files kept around between calls.
const HANDLE_CACHE: usize = 16;
/// Largest virtual size accepted (2^55 bytes, as for sparseimage).
const MAX_SIZE: u64 = 1 << 55;

fn bad(msg: impl core::fmt::Display) -> crate::Error {
    crate::Error::InvalidImage(format!("sparsebundle: {msg}"))
}

fn info_plist(size: u64, band_size: u64) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleInfoDictionaryVersion</key>
	<string>6.0</string>
	<key>band-size</key>
	<integer>{band_size}</integer>
	<key>bundle-backingstore-version</key>
	<integer>1</integer>
	<key>diskimage-bundle-type</key>
	<string>{BUNDLE_TYPE}</string>
	<key>size</key>
	<integer>{size}</integer>
</dict>
</plist>
"#
    )
}

/// The canonical file name of band `n`.
fn band_name(n: u64) -> String {
    format!("{n:x}")
}

/// Parse a band file name: `Ok(None)` for a name that is not a band at
/// all, an error for a hex name that is not canonical.
fn parse_band_name(name: &str) -> Result<Option<u64>> {
    if name.is_empty() || !name.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Ok(None);
    }
    let canonical = name.len() <= 16
        && name.bytes().all(|c| !c.is_ascii_uppercase())
        && (name == "0" || !name.starts_with('0'));
    if !canonical {
        return Err(bad(format_args!(
            "band file name {name:?} is not canonical"
        )));
    }
    Ok(Some(u64::from_str_radix(name, 16).expect("validated hex")))
}

struct Info {
    raw: String,
    band_size: u64,
    size: u64,
}

fn parse_info(raw: Vec<u8>) -> Result<Info> {
    let entries = plist::parse_dict(&raw)?;
    match plist::get_str(&entries, "diskimage-bundle-type")? {
        Some(BUNDLE_TYPE) => {}
        Some(other) => {
            return Err(crate::Error::Unsupported(format!(
                "sparsebundle: bundle type {other:?}"
            )));
        }
        None => return Err(bad("Info.plist has no diskimage-bundle-type")),
    }
    match plist::get_u64(&entries, "bundle-backingstore-version")? {
        Some(1) => {}
        Some(v) => {
            return Err(crate::Error::Unsupported(format!(
                "sparsebundle: backing-store version {v} (only 1 is supported)"
            )));
        }
        None => return Err(bad("Info.plist has no bundle-backingstore-version")),
    }
    let band_size =
        plist::get_u64(&entries, "band-size")?.ok_or_else(|| bad("Info.plist has no band-size"))?;
    if band_size == 0 || band_size > super::MAX_BAND_SIZE {
        return Err(bad(format_args!("band size {band_size}")));
    }
    let size = plist::get_u64(&entries, "size")?.ok_or_else(|| bad("Info.plist has no size"))?;
    if size > MAX_SIZE {
        return Err(bad(format_args!("size {size}")));
    }
    let raw = String::from_utf8(raw).map_err(|_| bad("Info.plist is not UTF-8"))?;
    Ok(Info {
        raw,
        band_size,
        size,
    })
}

/// A [`BlockDevice`] over a `.sparsebundle` directory. See the
/// [module docs](super) for locking and crash-safety guarantees.
pub struct SparseBundleBackend {
    root: PathBuf,
    bands_dir: PathBuf,
    read_only: bool,
    band_size: u64,
    size: u64,
    /// The `Info.plist` text, rewritten in place on resize.
    info_raw: String,
    /// Band files that exist, with their current lengths.
    present: HashMap<u64, u64>,
    /// Open band files, most recently used last.
    cache: Vec<(u64, File)>,
    /// Bands written since the last sync.
    dirty: HashSet<u64>,
    /// Band files created or removed since the last directory sync.
    names_dirty: bool,
    _token: Option<File>,
    _lock: Option<File>,
    cursor: u64,
}

impl std::fmt::Debug for SparseBundleBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SparseBundleBackend")
            .field("root", &self.root)
            .field("size", &self.size)
            .field("band_size", &self.band_size)
            .field("bands", &self.present.len())
            .field("read_only", &self.read_only)
            .finish()
    }
}

impl SparseBundleBackend {
    /// True when `path` is a directory holding an `Info.plist` (or its
    /// `Info.bckup` copy).
    pub fn probe(path: &Path) -> Result<bool> {
        if !path.is_dir() {
            return Ok(false);
        }
        Ok(std::fs::symlink_metadata(path.join("Info.plist")).is_ok()
            || std::fs::symlink_metadata(path.join("Info.bckup")).is_ok())
    }

    /// Open an existing bundle for reading and writing, taking exclusive
    /// locks on its `token` and `lock` files.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::open_inner(path.as_ref(), false)
    }

    /// Open an existing bundle read-only, under shared locks. Writes fail
    /// with `PermissionDenied`.
    pub fn open_read_only<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::open_inner(path.as_ref(), true)
    }

    fn open_inner(root: &Path, read_only: bool) -> Result<Self> {
        if !std::fs::metadata(root)?.is_dir() {
            return Err(bad(format_args!("{} is not a directory", root.display())));
        }
        // Locks first, so nothing changes under the scan below.
        let token = Self::lock_file(root, "token", read_only)?;
        if let Some(t) = &token
            && t.metadata()?.len() != 0
        {
            return Err(crate::Error::Unsupported(
                "sparsebundle: encrypted bundles (non-empty token) are not supported".into(),
            ));
        }
        let lockf = Self::lock_file(root, "lock", read_only)?;

        let info = Self::read_info(root)?;
        let bands_dir = root.join("bands");
        let present = match std::fs::symlink_metadata(&bands_dir) {
            Ok(m) => {
                if is_link(&m) || !m.is_dir() {
                    return Err(bad("bands is a symlink or not a directory"));
                }
                Self::scan(&bands_dir, info.size, info.band_size)?
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                if !read_only {
                    std::fs::create_dir(&bands_dir)?;
                }
                HashMap::new()
            }
            Err(e) => return Err(e.into()),
        };
        Ok(Self {
            root: root.to_path_buf(),
            bands_dir,
            read_only,
            band_size: info.band_size,
            size: info.size,
            info_raw: info.raw,
            present,
            cache: Vec::new(),
            dirty: HashSet::new(),
            names_dirty: false,
            _token: token,
            _lock: lockf,
            cursor: 0,
        })
    }

    /// Open and lock `root/name`; a writer creates it when missing.
    fn lock_file(root: &Path, name: &str, read_only: bool) -> Result<Option<File>> {
        let p = root.join(name);
        let f = match std::fs::symlink_metadata(&p) {
            Ok(_) => open_regular(&p, OpenOptions::new().read(true).write(!read_only))?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                if read_only {
                    return Ok(None);
                }
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .open(&p)?
            }
            Err(e) => return Err(e.into()),
        };
        lock(&f, !read_only, &p)?;
        Ok(Some(f))
    }

    fn read_info(root: &Path) -> Result<Info> {
        let mut p = root.join("Info.plist");
        if std::fs::symlink_metadata(&p).is_err() {
            // hdiutil keeps a backup copy; fall back to it.
            p = root.join("Info.bckup");
        }
        let meta = require_regular(&p)?;
        if meta.len() > plist::MAX_PLIST_BYTES {
            return Err(bad("Info.plist is larger than 64 KiB"));
        }
        let mut f = open_regular(&p, OpenOptions::new().read(true))?;
        let mut raw = Vec::new();
        (&mut f)
            .take(plist::MAX_PLIST_BYTES + 1)
            .read_to_end(&mut raw)?;
        parse_info(raw)
    }

    /// List `bands/`, validating every band file.
    fn scan(dir: &Path, size: u64, band_size: u64) -> Result<HashMap<u64, u64>> {
        let band_count = size.div_ceil(band_size);
        let mut present = HashMap::new();
        for ent in std::fs::read_dir(dir)? {
            let ent = ent?;
            let name = ent.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(n) = parse_band_name(name)? else {
                continue;
            };
            if n >= band_count {
                return Err(bad(format_args!(
                    "band {name} lies past the end of the image ({band_count} bands)"
                )));
            }
            let meta = std::fs::symlink_metadata(ent.path())?;
            if is_link(&meta) {
                return Err(bad(format_args!(
                    "band {name} is a symlink or reparse point"
                )));
            }
            if !meta.is_file() {
                return Err(bad(format_args!("band {name} is not a regular file")));
            }
            if meta.len() > band_size {
                return Err(bad(format_args!(
                    "band {name} is {} bytes, longer than a band ({band_size})",
                    meta.len()
                )));
            }
            present.insert(n, meta.len());
        }
        Ok(present)
    }

    /// Create a new, empty bundle at `path` of `size` bytes (rounded up
    /// to a whole sector) in bands of `band_size` bytes (a multiple of 512;
    /// `hdiutil` uses
    /// [`DEFAULT_BUNDLE_BAND_SIZE`](super::DEFAULT_BUNDLE_BAND_SIZE)).
    ///
    /// An existing sparsebundle at `path` is emptied and reused — once its
    /// locks are ours; any other existing path is an error.
    pub fn create<P: AsRef<Path>>(path: P, size: u64, band_size: u64) -> Result<Self> {
        let root = path.as_ref();
        check_band_size(band_size)?;
        let size = size
            .checked_next_multiple_of(512)
            .filter(|&s| s > 0 && s <= MAX_SIZE)
            .ok_or_else(|| {
                crate::Error::InvalidArgument(format!("sparsebundle: unusable size {size}"))
            })?;
        if std::fs::symlink_metadata(root).is_ok() {
            if !Self::probe(root)? {
                return Err(crate::Error::Io(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("{}: exists and is not a sparsebundle", root.display()),
                )));
            }
            let mut b = Self::open(root)?;
            b.reset(size, band_size)?;
            return Ok(b);
        }
        std::fs::create_dir(root)?;
        std::fs::create_dir(root.join("bands"))?;
        File::create(root.join("token"))?;
        File::create(root.join("lock"))?;
        let info = info_plist(size, band_size);
        for name in ["Info.plist", "Info.bckup"] {
            let mut f = File::create(root.join(name))?;
            f.write_all(info.as_bytes())?;
            f.sync_all()?;
        }
        sync_dir(root)?;
        if let Some(parent) = root.parent()
            && !parent.as_os_str().is_empty()
        {
            let _ = sync_dir(parent);
        }
        Self::open(root)
    }

    /// Empty this bundle and give it a new geometry.
    fn reset(&mut self, size: u64, band_size: u64) -> Result<()> {
        self.cache.clear();
        self.dirty.clear();
        let mut bands: Vec<u64> = self.present.keys().copied().collect();
        bands.sort_unstable();
        for b in bands {
            std::fs::remove_file(self.bands_dir.join(band_name(b)))?;
            self.present.remove(&b);
        }
        sync_dir(&self.bands_dir)?;
        self.write_info(info_plist(size, band_size))?;
        self.size = size;
        self.band_size = band_size;
        self.cursor = 0;
        Ok(())
    }

    /// Replace `Info.plist` (and `Info.bckup`) atomically: write a
    /// temporary file, flush it, rename it over the original.
    fn write_info(&mut self, text: String) -> Result<()> {
        for name in ["Info.plist", "Info.bckup"] {
            let dst = self.root.join(name);
            if let Ok(m) = std::fs::symlink_metadata(&dst)
                && (is_link(&m) || !m.is_file())
            {
                return Err(bad(format_args!("{name} is a symlink or not a file")));
            }
            let tmp = self.root.join(format!("{name}.fstool-tmp"));
            let r = (|| -> io::Result<()> {
                let mut f = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(&tmp)?;
                f.write_all(text.as_bytes())?;
                f.sync_all()?;
                drop(f);
                std::fs::rename(&tmp, &dst)
            })();
            if let Err(e) = r {
                let _ = std::fs::remove_file(&tmp);
                return Err(e.into());
            }
        }
        sync_dir(&self.root)?;
        self.info_raw = text;
        Ok(())
    }

    /// The current `Info.plist` with `size` replaced.
    fn info_with_size(&self, size: u64) -> Result<String> {
        let entries = plist::parse_dict(self.info_raw.as_bytes())?;
        let span = plist::get(&entries, "size")
            .ok_or_else(|| bad("Info.plist has no size"))?
            .text_span
            .clone();
        let mut s = String::with_capacity(self.info_raw.len() + 8);
        s.push_str(&self.info_raw[..span.start]);
        s.push_str(&size.to_string());
        s.push_str(&self.info_raw[span.end..]);
        Ok(s)
    }

    /// Band size in bytes.
    pub fn band_size(&self) -> u64 {
        self.band_size
    }

    /// How many band files exist.
    pub fn allocated_bands(&self) -> u64 {
        self.present.len() as u64
    }

    fn check_writable(&self) -> Result<()> {
        if self.read_only {
            return Err(crate::Error::Io(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "sparsebundle: opened read-only",
            )));
        }
        Ok(())
    }

    fn check_range(&self, off: u64, len: usize) -> Result<()> {
        if off.checked_add(len as u64).is_none_or(|e| e > self.size) {
            return Err(crate::Error::OutOfBounds {
                offset: off,
                len: len as u64,
                size: self.size,
            });
        }
        Ok(())
    }

    /// The open handle for band `b` (which must exist), from the cache or
    /// freshly opened and checked.
    fn handle(&mut self, b: u64) -> Result<&mut File> {
        if let Some(i) = self.cache.iter().position(|(n, _)| *n == b) {
            let e = self.cache.remove(i);
            self.cache.push(e);
        } else {
            if self.cache.len() >= HANDLE_CACHE {
                self.evict(0)?;
            }
            let p = self.bands_dir.join(band_name(b));
            let f = open_regular(&p, OpenOptions::new().read(true).write(!self.read_only))?;
            self.cache.push((b, f));
        }
        Ok(&mut self.cache.last_mut().unwrap().1)
    }

    /// Close cache entry `i`, flushing it first if it was written.
    fn evict(&mut self, i: usize) -> Result<()> {
        let (b, f) = self.cache.remove(i);
        if self.dirty.remove(&b) {
            f.sync_data()?;
        }
        Ok(())
    }

    /// Close band `b`'s cached handle, if any.
    fn close(&mut self, b: u64) -> Result<()> {
        if let Some(i) = self.cache.iter().position(|(n, _)| *n == b) {
            self.evict(i)?;
        }
        Ok(())
    }

    fn read_virtual(&mut self, off: u64, buf: &mut [u8]) -> Result<()> {
        self.check_range(off, buf.len())?;
        for (b, inner, s, n) in band_pieces(off, buf.len(), self.band_size) {
            let piece = &mut buf[s..s + n];
            let len = self.present.get(&b).copied().unwrap_or(0);
            if inner >= len {
                piece.fill(0);
                continue;
            }
            let have = ((len - inner) as usize).min(n);
            let f = self.handle(b)?;
            read_full_at(f, inner, &mut piece[..have])?;
            piece[have..].fill(0);
        }
        Ok(())
    }

    fn write_virtual(&mut self, off: u64, buf: &[u8]) -> Result<()> {
        self.check_writable()?;
        self.check_range(off, buf.len())?;
        for (b, inner, s, n) in band_pieces(off, buf.len(), self.band_size) {
            let piece = &buf[s..s + n];
            let len = match self.present.get(&b) {
                Some(&l) => l,
                None if piece.iter().all(|&x| x == 0) => continue,
                None => {
                    if self.cache.len() >= HANDLE_CACHE {
                        self.evict(0)?;
                    }
                    let p = self.bands_dir.join(band_name(b));
                    // create_new: never follows or reuses whatever is there.
                    let f = OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create_new(true)
                        .open(&p)?;
                    self.cache.push((b, f));
                    self.present.insert(b, 0);
                    self.names_dirty = true;
                    0
                }
            };
            // Writing zeros past a band file's end changes nothing.
            if inner >= len && piece.iter().all(|&x| x == 0) {
                continue;
            }
            let f = self.handle(b)?;
            write_all_at(f, inner, piece)?;
            self.dirty.insert(b);
            self.present.insert(b, len.max(inner + n as u64));
        }
        Ok(())
    }

    /// Change the virtual size to `new_size` bytes (a multiple of 512).
    ///
    /// Shrinking checks the bytes past the new end first: under
    /// [`ShrinkPolicy::RequireZero`] any nonzero byte fails the call with
    /// the bundle unchanged. Band files wholly past the new end are then
    /// deleted and a straddling one truncated *before* `Info.plist` records
    /// the new size, so a crash part-way leaves the old size with the
    /// dropped bands reading as zeros.
    pub fn resize(&mut self, new_size: u64, policy: ShrinkPolicy) -> Result<()> {
        self.check_writable()?;
        if new_size == 0 || !new_size.is_multiple_of(512) || new_size > MAX_SIZE {
            return Err(crate::Error::InvalidArgument(format!(
                "sparsebundle: new size {new_size} must be a nonzero multiple of 512"
            )));
        }
        self.sync()?;
        let band_size = self.band_size;
        // Bands whose file reaches past the new end (on grow: past the old
        // end, which can only be leftovers).
        let end = new_size.min(self.size);
        let mut affected: Vec<(u64, u64)> = self
            .present
            .iter()
            .filter(|&(&b, &len)| b * band_size + len > end)
            .map(|(&b, &len)| (b, len))
            .collect();
        affected.sort_unstable();
        if new_size < self.size && policy == ShrinkPolicy::RequireZero {
            for &(b, len) in &affected {
                let from = new_size.saturating_sub(b * band_size);
                let f = self.handle(b)?;
                if !range_is_zero(f, from, len - from)? {
                    return Err(crate::Error::InvalidArgument(format!(
                        "sparsebundle: shrinking to {new_size} bytes would discard nonzero \
                         data in band {} — pass ShrinkPolicy::Discard to drop it",
                        band_name(b)
                    )));
                }
            }
        }
        for &(b, _) in &affected {
            self.close(b)?;
            let p = self.bands_dir.join(band_name(b));
            let keep = end.saturating_sub(b * band_size);
            if keep == 0 {
                std::fs::remove_file(&p)?;
                self.present.remove(&b);
            } else {
                let f = open_regular(&p, OpenOptions::new().write(true))?;
                f.set_len(keep)?;
                f.sync_all()?;
                self.present.insert(b, keep);
            }
        }
        sync_dir(&self.bands_dir)?;
        let text = self.info_with_size(new_size)?;
        self.write_info(text)?;
        self.size = new_size;
        self.cursor = self.cursor.min(new_size);
        Ok(())
    }

    /// Delete every band file whose contents are entirely zero, returning
    /// how many went. Each deletion is atomic and a deleted band reads as
    /// zeros, so an interrupted compaction leaves a consistent bundle.
    ///
    /// This is not filesystem-aware: space a filesystem has freed but not
    /// zeroed stays allocated.
    pub fn compact(&mut self) -> Result<u64> {
        self.check_writable()?;
        self.sync()?;
        let mut bands: Vec<(u64, u64)> = self.present.iter().map(|(&b, &l)| (b, l)).collect();
        bands.sort_unstable();
        let mut dropped = 0;
        for (b, len) in bands {
            let zero = {
                let f = self.handle(b)?;
                range_is_zero(f, 0, len)?
            };
            if zero {
                self.close(b)?;
                std::fs::remove_file(self.bands_dir.join(band_name(b)))?;
                self.present.remove(&b);
                self.names_dirty = true;
                dropped += 1;
            }
        }
        self.sync()?;
        Ok(dropped)
    }

    /// Delete every band file whose bytes are all either in `free` or
    /// zero, and — under [`PartialBandPolicy::ZeroFree`] — zero the `free`
    /// bytes of the band files that stay (truncating a free tail). Band
    /// files with no free byte are left alone.
    ///
    /// `free` holds virtual byte ranges, sorted and non-overlapping, that
    /// the caller guarantees nothing needs: normally a filesystem's free
    /// space from [`crate::fs::free_space`], as [`reclaim`](super::reclaim)
    /// gathers it. Their contents are discarded, nonzero or not.
    ///
    /// Each band is handled on its own: a deletion is atomic and zeroing
    /// only touches bytes in `free`, so an interrupted run leaves the
    /// bundle consistent with everything outside `free` intact.
    /// `opts.partition` is ignored here.
    pub fn reclaim(&mut self, free: &[Range<u64>], opts: &ReclaimOpts) -> Result<ReclaimStats> {
        if !opts.dry_run {
            self.check_writable()?;
            self.sync()?;
        }
        check_ranges(free, self.size)?;
        let mut stats = ReclaimStats {
            bands_before: self.present.len() as u64,
            ..Default::default()
        };
        let mut bands: Vec<(u64, u64)> = self.present.iter().map(|(&b, &l)| (b, l)).collect();
        bands.sort_unstable();
        for (b, len) in bands {
            let start = b * self.band_size;
            let holes = free_within(free, start, start + len);
            if holes.is_empty() {
                continue;
            }
            let mut rest_zero = true;
            for r in complement(&holes, len) {
                let f = self.handle(b)?;
                if !range_is_zero(f, r.start, r.end - r.start)? {
                    rest_zero = false;
                    break;
                }
            }
            if rest_zero {
                stats.bands_released += 1;
                if !opts.dry_run {
                    self.close(b)?;
                    std::fs::remove_file(self.bands_dir.join(band_name(b)))?;
                    self.present.remove(&b);
                    self.names_dirty = true;
                }
                continue;
            }
            if opts.partial != PartialBandPolicy::ZeroFree {
                continue;
            }
            stats.bands_zeroed += 1;
            stats.bytes_zeroed += holes.iter().map(|r| r.end - r.start).sum::<u64>();
            if opts.dry_run {
                continue;
            }
            // A free tail is cut off rather than written.
            let new_len = match holes.last() {
                Some(last) if last.end == len => last.start,
                _ => len,
            };
            let f = self.handle(b)?;
            for r in &holes {
                let hi = r.end.min(new_len);
                if r.start < hi {
                    write_zeros_at(f, r.start, hi - r.start)?;
                }
            }
            if new_len < len {
                f.set_len(new_len)?;
            }
            f.sync_all()?;
            self.present.insert(b, new_len);
        }
        if !opts.dry_run {
            self.sync()?;
        }
        Ok(stats)
    }
}

impl Read for SparseBundleBackend {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = (buf.len() as u64).min(self.size.saturating_sub(self.cursor)) as usize;
        if n == 0 {
            return Ok(0);
        }
        self.read_virtual(self.cursor, &mut buf[..n])
            .map_err(io::Error::other)?;
        self.cursor += n as u64;
        Ok(n)
    }
}

impl Write for SparseBundleBackend {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = (buf.len() as u64).min(self.size.saturating_sub(self.cursor)) as usize;
        if n == 0 {
            return Ok(0);
        }
        self.write_virtual(self.cursor, &buf[..n])
            .map_err(io::Error::other)?;
        self.cursor += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.sync().map_err(io::Error::other)
    }
}

impl Seek for SparseBundleBackend {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(n) => Some(n),
            SeekFrom::End(n) => self.size.checked_add_signed(n),
            SeekFrom::Current(n) => self.cursor.checked_add_signed(n),
        };
        self.cursor = new.ok_or_else(|| io::Error::other("sparsebundle: seek out of range"))?;
        Ok(self.cursor)
    }
}

impl BlockDevice for SparseBundleBackend {
    fn block_size(&self) -> u32 {
        512
    }

    fn total_size(&self) -> u64 {
        self.size
    }

    fn sync(&mut self) -> Result<()> {
        if self.read_only {
            return Ok(());
        }
        for (b, f) in &self.cache {
            if self.dirty.contains(b) {
                f.sync_data()?;
            }
        }
        self.dirty.clear();
        if self.names_dirty {
            sync_dir(&self.bands_dir)?;
            self.names_dirty = false;
        }
        Ok(())
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.read_virtual(offset, buf)
    }

    fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        self.write_virtual(offset, buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn band_names() {
        assert_eq!(band_name(0), "0");
        assert_eq!(band_name(26), "1a");
        assert_eq!(parse_band_name("1a").unwrap(), Some(26));
        assert_eq!(parse_band_name("0").unwrap(), Some(0));
        assert_eq!(parse_band_name(".DS_Store").unwrap(), None);
        assert_eq!(parse_band_name("Info").unwrap(), None);
        assert!(parse_band_name("01").is_err());
        assert!(parse_band_name("1A").is_err());
        assert!(parse_band_name("11111111111111111").is_err());
    }

    #[test]
    fn create_write_read_reopen() {
        let d = tmpdir();
        let p = d.path().join("a.sparsebundle");
        let mut b = SparseBundleBackend::create(&p, 10 * 4096 + 100, 4096).unwrap();
        assert_eq!(b.total_size(), 10 * 4096 + 512);
        let mut buf = vec![1u8; 4096];
        b.read_at(4096, &mut buf).unwrap();
        assert!(buf.iter().all(|&x| x == 0));
        b.write_at(0, &[0u8; 9000]).unwrap();
        assert_eq!(b.allocated_bands(), 0);
        b.write_at(3 * 4096 - 2, b"abcd").unwrap();
        b.write_at(10 * 4096 + 10, b"end").unwrap();
        b.sync().unwrap();
        drop(b);
        let names: HashSet<String> = std::fs::read_dir(p.join("bands"))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names, HashSet::from(["2".into(), "3".into(), "a".into()]));
        assert_eq!(std::fs::metadata(p.join("bands/2")).unwrap().len(), 4096);
        // Short band files: only up to the last byte written.
        assert_eq!(std::fs::metadata(p.join("bands/3")).unwrap().len(), 2);
        assert_eq!(std::fs::metadata(p.join("bands/a")).unwrap().len(), 13);

        let mut b = SparseBundleBackend::open_read_only(&p).unwrap();
        let mut all = vec![0u8; b.total_size() as usize];
        b.read_at(0, &mut all).unwrap();
        let mut want = vec![0u8; all.len()];
        want[3 * 4096 - 2..3 * 4096 + 2].copy_from_slice(b"abcd");
        want[10 * 4096 + 10..10 * 4096 + 13].copy_from_slice(b"end");
        assert_eq!(all, want);
        assert!(b.write_at(0, b"x").is_err());
    }

    #[test]
    fn locks_are_exclusive_for_writers() {
        let d = tmpdir();
        let p = d.path().join("l.sparsebundle");
        let b = SparseBundleBackend::create(&p, 8192, 4096).unwrap();
        assert!(SparseBundleBackend::open(&p).is_err());
        assert!(SparseBundleBackend::open_read_only(&p).is_err());
        drop(b);
        let _r1 = SparseBundleBackend::open_read_only(&p).unwrap();
        let _r2 = SparseBundleBackend::open_read_only(&p).unwrap();
        assert!(SparseBundleBackend::open(&p).is_err());
    }

    #[test]
    fn resize_and_compact() {
        let d = tmpdir();
        let p = d.path().join("r.sparsebundle");
        let mut b = SparseBundleBackend::create(&p, 8 * 4096, 4096).unwrap();
        b.write_at(4096 + 10, b"keep").unwrap();
        b.write_at(6 * 4096, b"far").unwrap();
        let info_before = std::fs::read(p.join("Info.plist")).unwrap();
        assert!(b.resize(4 * 4096, ShrinkPolicy::RequireZero).is_err());
        assert_eq!(std::fs::read(p.join("Info.plist")).unwrap(), info_before);
        assert!(p.join("bands/6").exists());
        b.resize(4096 + 12, ShrinkPolicy::Discard).unwrap_err(); // not a sector multiple
        b.resize(4096 + 512, ShrinkPolicy::Discard).unwrap();
        assert!(!p.join("bands/6").exists());
        assert_eq!(b.total_size(), 4096 + 512);
        b.resize(16 * 4096, ShrinkPolicy::RequireZero).unwrap();
        drop(b);
        let mut b = SparseBundleBackend::open(&p).unwrap();
        assert_eq!(b.total_size(), 16 * 4096);
        let mut x = [0u8; 4];
        b.read_at(4096 + 10, &mut x).unwrap();
        assert_eq!(&x, b"keep");
        b.read_at(6 * 4096, &mut x).unwrap();
        assert_eq!(x, [0; 4]);
        let bckup = std::fs::read_to_string(p.join("Info.bckup")).unwrap();
        assert!(bckup.contains(&format!("<integer>{}</integer>", 16 * 4096)));

        // Shrinking past a band whose tail beyond the cut is zero.
        b.write_at(9 * 4096, &[5u8; 100]).unwrap();
        b.resize(9 * 4096 + 512, ShrinkPolicy::RequireZero).unwrap();
        b.write_at(9 * 4096, &[0u8; 100]).unwrap();
        assert_eq!(b.compact().unwrap(), 1);
        assert_eq!(b.allocated_bands(), 1);
        assert!(!p.join("bands/9").exists());
        b.read_at(4096 + 10, &mut x).unwrap();
        assert_eq!(&x, b"keep");
    }

    #[test]
    fn reclaim_deletes_free_bands_and_trims_free_tails() {
        let d = tmpdir();
        let p = d.path().join("rc.sparsebundle");
        let bs = 4096u64;
        let mut b = SparseBundleBackend::create(&p, 8 * bs, bs).unwrap();
        b.write_at(0, &[0xAB; 4096]).unwrap(); // band 0: all free
        b.write_at(bs, &[0x11; 1024]).unwrap(); // band 1: used, free middle,
        b.write_at(bs + 1024, &[0xCD; 1024]).unwrap();
        b.write_at(bs + 2048, &[0x22; 1024]).unwrap(); // used, free tail
        b.write_at(bs + 3072, &[0xCD; 1024]).unwrap();
        b.write_at(2 * bs + 2048, &[0xEF; 512]).unwrap(); // band 2: zero + free
        b.write_at(4 * bs, &[0x44; 100]).unwrap(); // band 4: no free byte
        b.sync().unwrap();
        let free = [0..bs, bs + 1024..bs + 2048, bs + 3072..3 * bs];

        let mut opts = ReclaimOpts {
            dry_run: true,
            ..Default::default()
        };
        let st = b.reclaim(&free, &opts).unwrap();
        assert_eq!((st.bands_before, st.bands_released), (4, 2));
        assert!(p.join("bands/0").exists() && p.join("bands/2").exists());

        opts.dry_run = false;
        let st = b.reclaim(&free, &opts).unwrap();
        assert_eq!((st.bands_released, st.bands_zeroed), (2, 0));
        assert!(!p.join("bands/0").exists() && !p.join("bands/2").exists());
        assert_eq!(std::fs::metadata(p.join("bands/1")).unwrap().len(), bs);

        opts.partial = PartialBandPolicy::ZeroFree;
        let st = b.reclaim(&free, &opts).unwrap();
        assert_eq!((st.bands_zeroed, st.bytes_zeroed), (1, 2048));
        // The free tail is cut off, the free middle zeroed.
        assert_eq!(std::fs::metadata(p.join("bands/1")).unwrap().len(), 3072);
        drop(b);
        let mut b = SparseBundleBackend::open(&p).unwrap();
        let mut got = vec![0u8; 5 * bs as usize];
        b.read_at(0, &mut got).unwrap();
        let mut want = vec![0u8; 5 * bs as usize];
        want[4096..5120].fill(0x11);
        want[6144..7168].fill(0x22);
        want[4 * 4096..4 * 4096 + 100].fill(0x44);
        assert_eq!(got, want);
        assert_eq!(b.allocated_bands(), 2);
    }

    #[test]
    fn rejects_bad_bundles() {
        let d = tmpdir();
        let mk = |name: &str| {
            let p = d.path().join(name);
            drop(SparseBundleBackend::create(&p, 8 * 4096, 4096).unwrap());
            p
        };
        // Out-of-range band.
        let p = mk("oob.sparsebundle");
        std::fs::write(p.join("bands/8"), b"x").unwrap();
        assert!(SparseBundleBackend::open_read_only(&p).is_err());
        // Non-canonical alias.
        let p = mk("alias.sparsebundle");
        std::fs::write(p.join("bands/01"), b"x").unwrap();
        assert!(SparseBundleBackend::open_read_only(&p).is_err());
        // Oversized band.
        let p = mk("big.sparsebundle");
        std::fs::write(p.join("bands/1"), vec![1u8; 4097]).unwrap();
        assert!(SparseBundleBackend::open_read_only(&p).is_err());
        // A directory where a band should be.
        let p = mk("dir.sparsebundle");
        std::fs::create_dir(p.join("bands/2")).unwrap();
        assert!(SparseBundleBackend::open_read_only(&p).is_err());
        // Encrypted.
        let p = mk("enc.sparsebundle");
        std::fs::write(p.join("token"), b"encrcdsa").unwrap();
        assert!(matches!(
            SparseBundleBackend::open_read_only(&p),
            Err(crate::Error::Unsupported(_))
        ));
        // Bad plists.
        for (i, text) in [
            info_plist(8 * 4096, 0),
            info_plist(8 * 4096, 4096).replace(BUNDLE_TYPE, "com.example.other"),
            info_plist(8 * 4096, 4096).replace("<integer>1</integer>", "<integer>9</integer>"),
            info_plist(u64::MAX, 4096),
            "garbage".into(),
        ]
        .into_iter()
        .enumerate()
        {
            let p = mk(&format!("plist{i}.sparsebundle"));
            std::fs::write(p.join("Info.plist"), text).unwrap();
            assert!(
                SparseBundleBackend::open_read_only(&p).is_err(),
                "plist {i}"
            );
        }
        // Stray non-band files are ignored.
        let p = mk("stray.sparsebundle");
        std::fs::write(p.join("bands/.DS_Store"), b"x").unwrap();
        assert!(SparseBundleBackend::open_read_only(&p).is_ok());
        // Creating over something that is not a bundle.
        let f = d.path().join("plain.sparsebundle");
        std::fs::write(&f, b"x").unwrap();
        assert!(SparseBundleBackend::create(&f, 4096, 4096).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_escapes() {
        use std::os::unix::fs::symlink;
        let d = tmpdir();
        let outside = d.path().join("outside");
        std::fs::write(&outside, vec![9u8; 100]).unwrap();
        let mk = |name: &str| {
            let p = d.path().join(name);
            drop(SparseBundleBackend::create(&p, 8 * 4096, 4096).unwrap());
            p
        };
        // A band that is a symlink.
        let p = mk("band.sparsebundle");
        symlink(&outside, p.join("bands/0")).unwrap();
        assert!(SparseBundleBackend::open_read_only(&p).is_err());
        // bands/ itself a symlink.
        let p = mk("dir.sparsebundle");
        let elsewhere = d.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::fs::remove_dir(p.join("bands")).unwrap();
        symlink(&elsewhere, p.join("bands")).unwrap();
        assert!(SparseBundleBackend::open_read_only(&p).is_err());
        // Info.plist / token as symlinks.
        let p = mk("plist.sparsebundle");
        std::fs::remove_file(p.join("Info.plist")).unwrap();
        symlink(&outside, p.join("Info.plist")).unwrap();
        assert!(SparseBundleBackend::open_read_only(&p).is_err());
        let p = mk("token.sparsebundle");
        std::fs::remove_file(p.join("token")).unwrap();
        symlink(&outside, p.join("token")).unwrap();
        assert!(SparseBundleBackend::open_read_only(&p).is_err());
        // A band swapped for a symlink after open is refused on use.
        let p = mk("late.sparsebundle");
        std::fs::write(p.join("bands/1"), b"x").unwrap();
        let mut b = SparseBundleBackend::open(&p).unwrap();
        std::fs::remove_file(p.join("bands/1")).unwrap();
        symlink(&outside, p.join("bands/1")).unwrap();
        assert!(b.write_at(4096, b"y").is_err());
        assert_eq!(std::fs::read(&outside).unwrap(), vec![9u8; 100]);
    }
}
