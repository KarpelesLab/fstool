//! Block-device abstraction — the bottom layer of the fstool stack.
//!
//! A [`BlockDevice`] is a seekable byte-addressable store. Every higher layer
//! (partition table, filesystem) reads and writes through this trait, which
//! makes it trivial to substitute an on-disk file with an in-memory buffer in
//! tests or with a sub-range view when carving partitions.
//!
//! ## Invariants
//!
//! - `total_size()` is the logical capacity in bytes; reads and writes outside
//!   `[0, total_size())` MUST be rejected (the trait returns a short read /
//!   short write at the boundary via the standard `Read`/`Write` contract, and
//!   fstool's explicit positional helpers return [`crate::Error::OutOfBounds`]).
//! - Implementations are free to back themselves with sparse storage. Bytes
//!   that have never been written MUST read as zero.
//! - `block_size()` reports the *logical* sector size — usually 512 — and is
//!   purely advisory; it does not constrain the alignment of reads or writes.
//!
//! ## Streaming guarantee
//!
//! File-backed backends MUST NOT pull the full device into memory; that is
//! what lets fstool handle multi-gigabyte images. [`MemoryBackend`] is the
//! deliberate exception — a first-class in-RAM backend used wherever there is
//! no host filesystem (most importantly the WebAssembly build, where an
//! uploaded file is inspected and converted entirely in memory; see
//! [`crate::memconv`]). Its footprint is bounded by the caller's input size,
//! so use it where that is acceptable and a file backend elsewhere.

use std::io::{Read, Seek, Write};

use crate::Result;

pub mod crash_inject;
pub mod diskcopy;
pub mod dmg;
pub mod file;
#[cfg(feature = "luks")]
pub mod luks;
pub mod memory;
pub mod qcow2;
pub mod sliced;

pub use crash_inject::{CrashInject, FailAfter};
pub use diskcopy::DiskCopy42Backend;
pub use dmg::DmgBackend;
pub use file::FileBackend;
#[cfg(feature = "luks")]
pub use luks::LuksBackend;
pub use memory::MemoryBackend;
pub use qcow2::Qcow2Backend;
pub use sliced::SlicedBackend;

use std::path::{Path, PathBuf};

/// Open `path` as a [`BlockDevice`], picking the backend automatically.
///
/// Detection order:
///
/// - qcow2 magic `"QFI\xfb"` at offset 0   → [`Qcow2Backend`]
/// - UDIF `koly` trailer at `file_size-512` → [`DmgBackend`] (scaffold:
///   parses the trailer; reads return `Unsupported` until the chunk
///   decoder lands)
/// - LUKS magic at offset 0                 → [`luks::LuksBackend`]
/// - everything else (regular file, block device, raw image) →
///   [`FileBackend`]
///
/// Encrypted content — a LUKS volume, or a qcow2 with `crypt_method` set
/// — is *refused* here rather than handed back as ciphertext, which a
/// filesystem probe would then misreport as an unknown format. Use
/// [`open_image_with_password`] to actually open it.
///
/// This does **not** handle compressed inputs like `.tar.gz`. Use
/// [`open_image_maybe_compressed`] when the path might carry a codec.
pub fn open_image(path: &Path) -> crate::Result<Box<dyn BlockDevice>> {
    open_image_with_password(path, None)
}

/// [`open_image`], with a passphrase for encrypted containers.
///
/// The passphrase is used for whichever encrypted form `path` turns out
/// to be: a LUKS1/LUKS2 volume, or a qcow2 image encrypted with either
/// `crypt_method`. It is ignored for anything unencrypted, so a caller
/// that always has one on hand can pass it unconditionally.
pub fn open_image_with_password(
    path: &Path,
    password: Option<&str>,
) -> crate::Result<Box<dyn BlockDevice>> {
    if Qcow2Backend::probe(path)? {
        return open_qcow2(path, password, false);
    }
    if dmg::probe(path)? {
        return Ok(Box::new(DmgBackend::open(path)?));
    }
    if diskcopy::probe(path)? {
        // DiskCopy 4.2 wraps a raw volume; expose its data fork so detection
        // sees the inner filesystem (classic HFS / MFS) transparently.
        return Ok(Box::new(DiskCopy42Backend::new(Box::new(
            FileBackend::open(path)?,
        ))?));
    }
    let file = FileBackend::open(path)?;
    open_maybe_luks(file, path, password, false)
}

/// Open a qcow2 image, with or without a passphrase.
fn open_qcow2(
    path: &Path,
    password: Option<&str>,
    read_only: bool,
) -> crate::Result<Box<dyn BlockDevice>> {
    #[cfg(feature = "qcow2-crypto")]
    if let Some(password) = password {
        return Ok(if read_only {
            Box::new(Qcow2Backend::open_encrypted_read_only(path, password)?)
        } else {
            Box::new(Qcow2Backend::open_encrypted(path, password)?)
        });
    }
    let _ = password;
    Ok(if read_only {
        Box::new(Qcow2Backend::open_read_only(path)?)
    } else {
        Box::new(Qcow2Backend::open(path)?)
    })
}

/// If `file` turns out to be a LUKS container, unlock it; otherwise hand
/// it back unchanged.
#[cfg(feature = "luks")]
fn open_maybe_luks(
    mut file: FileBackend,
    path: &Path,
    password: Option<&str>,
    read_only: bool,
) -> crate::Result<Box<dyn BlockDevice>> {
    let Some(version) = luks::probe(&mut file) else {
        return Ok(Box::new(file));
    };
    let Some(password) = password else {
        return Err(crate::Error::InvalidArgument(format!(
            "{}: this is a {version} volume — open it with a passphrase",
            path.display()
        )));
    };
    Ok(if read_only {
        Box::new(LuksBackend::open_read_only(file, password)?)
    } else {
        Box::new(LuksBackend::open(file, password)?)
    })
}

#[cfg(not(feature = "luks"))]
fn open_maybe_luks(
    file: FileBackend,
    _path: &Path,
    _password: Option<&str>,
    _read_only: bool,
) -> crate::Result<Box<dyn BlockDevice>> {
    Ok(Box::new(file))
}

/// Like [`open_image`], but transparently decompresses `.gz` / `.zst` /
/// `.xz` / etc. into an in-memory [`MemoryBackend`] before returning it,
/// giving random access to a compressed *image* without a host temp file
/// (so it works in wasm too). The whole image is held in RAM — for a
/// compressed *archive* (tar/…) prefer the streaming readers instead.
///
/// For uncompressed paths the behaviour matches [`open_image`] exactly.
pub fn open_image_maybe_compressed(path: &Path) -> crate::Result<Box<dyn BlockDevice>> {
    open_image_maybe_compressed_with_password(path, None)
}

/// [`open_image_maybe_compressed`], with a passphrase for encrypted
/// containers. A compressed *encrypted* image is decompressed into RAM
/// first and then unlocked from there.
pub fn open_image_maybe_compressed_with_password(
    path: &Path,
    password: Option<&str>,
) -> crate::Result<Box<dyn BlockDevice>> {
    match crate::compression::detect_path(path)? {
        Some(algo) => {
            let bytes = crate::compression::decompress_to_memory(path, algo)?;
            open_memory_maybe_luks(MemoryBackend::from_bytes(bytes), path, password)
        }
        None => open_image_with_password(path, password),
    }
}

/// The [`MemoryBackend`] counterpart of `open_maybe_luks`, for the
/// decompress-into-RAM paths.
#[cfg(feature = "luks")]
fn open_memory_maybe_luks(
    mut mem: MemoryBackend,
    path: &Path,
    password: Option<&str>,
) -> crate::Result<Box<dyn BlockDevice>> {
    let Some(version) = luks::probe(&mut mem) else {
        return Ok(Box::new(mem));
    };
    let Some(password) = password else {
        return Err(crate::Error::InvalidArgument(format!(
            "{}: this is a {version} volume — open it with a passphrase",
            path.display()
        )));
    };
    Ok(Box::new(LuksBackend::open(mem, password)?))
}

#[cfg(not(feature = "luks"))]
fn open_memory_maybe_luks(
    mem: MemoryBackend,
    _path: &Path,
    _password: Option<&str>,
) -> crate::Result<Box<dyn BlockDevice>> {
    Ok(Box::new(mem))
}

/// Read-only counterpart of [`open_image`]. Picks the same backend
/// (qcow2 / dmg / raw) but opens the underlying file `O_RDONLY` so
/// writes through any layer fail with `PermissionDenied`. Use for
/// strictly read-only callers (`fstool shell --ro`, etc.).
pub fn open_image_read_only(path: &Path) -> crate::Result<Box<dyn BlockDevice>> {
    open_image_read_only_with_password(path, None)
}

/// [`open_image_read_only`], with a passphrase for encrypted containers.
pub fn open_image_read_only_with_password(
    path: &Path,
    password: Option<&str>,
) -> crate::Result<Box<dyn BlockDevice>> {
    if Qcow2Backend::probe(path)? {
        return open_qcow2(path, password, true);
    }
    if dmg::probe(path)? {
        // DmgBackend has no write surface to gate — it's already
        // read-only by construction.
        return Ok(Box::new(DmgBackend::open(path)?));
    }
    if diskcopy::probe(path)? {
        // Read-only container by construction (writes are rejected).
        return Ok(Box::new(DiskCopy42Backend::new(Box::new(
            FileBackend::open_read_only(path)?,
        ))?));
    }
    let file = FileBackend::open_read_only(path)?;
    open_maybe_luks(file, path, password, true)
}

/// Read-only counterpart of [`open_image_maybe_compressed`]. For a
/// compressed source the decompressed bytes live in a throwaway
/// [`MemoryBackend`], so any mutation lands on that copy and is discarded —
/// same effect the read-only wrapper gave before. Uncompressed sources go
/// through [`open_image_read_only`], which opens the file `O_RDONLY`.
pub fn open_image_maybe_compressed_read_only(path: &Path) -> crate::Result<Box<dyn BlockDevice>> {
    open_image_maybe_compressed_read_only_with_password(path, None)
}

/// [`open_image_maybe_compressed_read_only`], with a passphrase for
/// encrypted containers.
pub fn open_image_maybe_compressed_read_only_with_password(
    path: &Path,
    password: Option<&str>,
) -> crate::Result<Box<dyn BlockDevice>> {
    match crate::compression::detect_path(path)? {
        Some(algo) => {
            let bytes = crate::compression::decompress_to_memory(path, algo)?;
            // The decompressed copy is a throwaway, so an unlock over it
            // is read-only in effect whatever we ask for.
            open_memory_maybe_luks(MemoryBackend::from_bytes(bytes), path, password)
        }
        None => open_image_read_only_with_password(path, password),
    }
}

/// Options for [`create_image`].
#[derive(Debug, Clone)]
pub struct CreateOpts {
    /// qcow2 cluster size in bytes (power of two, ≥ 512). Default 64 KiB,
    /// matching qemu-img. Ignored when creating a raw image.
    pub cluster_size: u32,
    /// Encrypt the new image, protecting it with this passphrase.
    ///
    /// A qcow2 destination gets `crypt_method = 2` — a LUKS header
    /// embedded in the image. Anything else becomes a LUKS container with
    /// the requested capacity as its payload, so the file on disk is a
    /// little larger than `virtual_size`.
    pub encrypt: Option<EncryptOpts>,
    /// Make the new qcow2 an overlay over this image: `(path, format)`,
    /// where `path` is recorded in the header (relative paths resolve
    /// against the new image's directory) and `format` is the backing
    /// file's format name (`"qcow2"`, `"raw"`, …) or `None` to have it
    /// probed. Ignored for a raw destination, which has nowhere to
    /// record it.
    pub backing: Option<(PathBuf, Option<String>)>,
}

/// How [`create_image`] should encrypt a new image.
#[derive(Debug, Clone)]
pub struct EncryptOpts {
    /// Passphrase protecting the new volume's keyslot.
    pub password: String,
    /// Cipher, key length, KDF cost and the rest. Note that a qcow2
    /// destination requires `version: Version::V1` — that is the header
    /// qemu embeds and reads.
    #[cfg(feature = "luks")]
    pub luks: luks::FormatOpts,
}

impl Default for CreateOpts {
    fn default() -> Self {
        Self {
            cluster_size: 65_536,
            encrypt: None,
            backing: None,
        }
    }
}

impl CreateOpts {
    /// Defaults with an explicit cluster size.
    pub fn with_cluster_size(cluster_size: u32) -> Self {
        Self {
            cluster_size,
            ..Self::default()
        }
    }
}

/// Create a new image at `path` of capacity `virtual_size` bytes. The
/// backend is chosen by the path's extension: `.qcow2` (or `.qcow` /
/// `.q2`) → [`Qcow2Backend`], everything else → [`FileBackend`] (sparse
/// raw file or block device).
///
/// With [`CreateOpts::encrypt`] set, the returned device is the
/// *plaintext* view: writes to it land encrypted, and offset 0 is the
/// first usable byte. With [`CreateOpts::backing`] set on a qcow2
/// destination, the new image reads through to that base for anything it
/// does not hold.
pub fn create_image(
    path: &Path,
    virtual_size: u64,
    opts: &CreateOpts,
) -> crate::Result<Box<dyn BlockDevice>> {
    let cluster_size = if opts.cluster_size == 0 {
        65_536
    } else {
        opts.cluster_size
    };
    if is_qcow2_path(path) {
        let backing = opts
            .backing
            .as_ref()
            .map(|(p, f)| (p.as_path(), f.as_deref()));
        #[cfg(feature = "qcow2-crypto")]
        if let Some(enc) = &opts.encrypt {
            if backing.is_some() {
                return Err(crate::Error::Unsupported(
                    "qcow2: an encrypted image cannot also have a backing file — \
                     the base's clusters are not encrypted under this image's key"
                        .into(),
                ));
            }
            return Ok(Box::new(Qcow2Backend::create_encrypted(
                path,
                virtual_size,
                cluster_size,
                &enc.password,
                &enc.luks,
            )?));
        }
        if opts.encrypt.is_some() {
            return Err(crate::Error::Unsupported(
                "qcow2: encryption needs the `qcow2-crypto` feature".into(),
            ));
        }
        return Ok(Box::new(Qcow2Backend::create_with_backing(
            path,
            virtual_size,
            cluster_size,
            backing,
        )?));
    }
    if opts.backing.is_some() {
        return Err(crate::Error::Unsupported(
            "a raw image has no header to record a backing file in — \
             use a .qcow2 destination"
                .into(),
        ));
    }
    #[cfg(feature = "luks")]
    if let Some(enc) = &opts.encrypt {
        // The container has to hold the header *and* the requested
        // capacity, so the file is larger than the payload.
        let payload_offset = enc.luks.payload_offset();
        let total = payload_offset.checked_add(virtual_size).ok_or_else(|| {
            crate::Error::InvalidArgument("luks: container size overflows u64".into())
        })?;
        let file = FileBackend::create(path, total)?;
        return Ok(Box::new(luks::format(file, &enc.password, &enc.luks)?));
    }
    if opts.encrypt.is_some() {
        return Err(crate::Error::Unsupported(
            "encryption needs the `luks` feature".into(),
        ));
    }
    Ok(Box::new(FileBackend::create(path, virtual_size)?))
}

/// True when `path`'s extension marks it as a qcow2 image (`.qcow2` /
/// `.qcow` / `.q2`). Used by the create/finalize paths to decide the backend.
pub fn is_qcow2_path(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|s| s.to_str()) else {
        return false;
    };
    matches!(ext.to_ascii_lowercase().as_str(), "qcow2" | "qcow" | "q2")
}

/// A seekable byte-addressable store of fixed capacity.
///
/// Implementors compose `Read + Write + Seek` so the standard library's
/// streaming APIs work directly. The extra trait methods expose information
/// that higher layers need (advisory sector size, total capacity, sparse-zero
/// hint, durability flush).
pub trait BlockDevice: Read + Write + Seek + Send {
    /// Advisory logical sector size, in bytes. Usually 512. Higher layers may
    /// use this for alignment hints; it does not constrain valid I/O offsets.
    fn block_size(&self) -> u32;

    /// Total capacity of the device in bytes.
    fn total_size(&self) -> u64;

    /// Hint that the range `[offset, offset+len)` should read as zero. The
    /// default implementation actually writes zero bytes; backends with sparse
    /// support (file with `set_len`, memory) may override to do nothing when
    /// the underlying storage is already zero-initialised.
    fn zero_range(&mut self, offset: u64, len: u64) -> Result<()> {
        let size = self.total_size();
        if offset.checked_add(len).is_none_or(|end| end > size) {
            return Err(crate::Error::OutOfBounds { offset, len, size });
        }
        if len == 0 {
            return Ok(());
        }
        self.seek(std::io::SeekFrom::Start(offset))?;
        let zero = [0u8; 4096];
        let mut remaining = len;
        while remaining > 0 {
            let n = remaining.min(zero.len() as u64) as usize;
            self.write_all(&zero[..n])?;
            remaining -= n as u64;
        }
        Ok(())
    }

    /// Persist outstanding writes. For [`FileBackend`] this is `fsync`; for
    /// [`MemoryBackend`] it is a no-op.
    fn sync(&mut self) -> Result<()>;

    /// Positional read — fills `buf` from `offset` without moving the
    /// implicit stream cursor across calls (the cursor IS seeked, but callers
    /// should not rely on its position after this method returns).
    ///
    /// Returns [`crate::Error::OutOfBounds`] if `offset + buf.len()` exceeds
    /// [`total_size`](Self::total_size). Implementations that can do a true
    /// `pread` (positional read without modifying the cursor) are encouraged
    /// to override this.
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let size = self.total_size();
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or(crate::Error::OutOfBounds {
                offset,
                len: buf.len() as u64,
                size,
            })?;
        if end > size {
            return Err(crate::Error::OutOfBounds {
                offset,
                len: buf.len() as u64,
                size,
            });
        }
        self.seek(std::io::SeekFrom::Start(offset))?;
        self.read_exact(buf)?;
        Ok(())
    }

    /// Positional write — writes `buf` at `offset`. Mirrors
    /// [`read_at`](Self::read_at)'s semantics.
    fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        let size = self.total_size();
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or(crate::Error::OutOfBounds {
                offset,
                len: buf.len() as u64,
                size,
            })?;
        if end > size {
            return Err(crate::Error::OutOfBounds {
                offset,
                len: buf.len() as u64,
                size,
            });
        }
        self.seek(std::io::SeekFrom::Start(offset))?;
        self.write_all(buf)?;
        Ok(())
    }
}

/// Forward every method to the boxed device.
///
/// `Read`/`Write`/`Seek` already forward through `Box` via the standard
/// library's blanket impls, but `BlockDevice` is ours, so it needs this
/// one. It is what lets a wrapper that takes ownership of its parent —
/// [`luks::LuksBackend`], a qcow2 backing chain — be built over the
/// `Box<dyn BlockDevice>` that [`open_image`] hands back.
impl<B: BlockDevice + ?Sized> BlockDevice for Box<B> {
    fn block_size(&self) -> u32 {
        (**self).block_size()
    }

    fn total_size(&self) -> u64 {
        (**self).total_size()
    }

    fn zero_range(&mut self, offset: u64, len: u64) -> Result<()> {
        (**self).zero_range(offset, len)
    }

    fn sync(&mut self) -> Result<()> {
        (**self).sync()
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        (**self).read_at(offset, buf)
    }

    fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        (**self).write_at(offset, buf)
    }
}
