//! One interface over every allocator-free filesystem driver, and a mount
//! that works out which one a medium holds.
//!
//! Each driver — [`fat`](crate::fs::fat), [`exfat`](crate::fs::exfat),
//! [`littlefs`](crate::fs::littlefs) — has its own `Volume`, `File` and
//! `DirIter`, shaped the same way but typed apart: sizes are `u32` on FAT
//! and littlefs and `u64` on exFAT, names are `&str` on the FAT family and
//! bytes on littlefs, and each has its own error enum. Code that only wants
//! "a filesystem" is written against the traits here instead, and runs on
//! any of them — including [`AnyVolume`], which is whichever one
//! [`mount`] found:
//!
//! ```no_run
//! # use fstool::device::SectorDriver;
//! use fstool::fs::volume::{self, Volume, VolumeDirIter, VolumeFile};
//!
//! /// Append a line to a log, on whatever filesystem the card holds.
//! fn log_boot<V: Volume>(vol: &mut V) -> Result<(), V::Error> {
//!     let mut log = vol.open_or_create_file("/boot.log")?;
//!     log.seek_to_end(vol)?;
//!     log.write_all(vol, b"booted\n")?;
//!     log.flush(vol)?;
//!
//!     let root = vol.root();
//!     let mut it = vol.iter_dir(root);
//!     while let Some(entry) = it.next()? {
//!         let _ = (entry.name_str(), entry.len(), entry.is_dir());
//!     }
//!     Ok(())
//! }
//!
//! # fn demo<D: SectorDriver>(card: D) -> Result<(), volume::AnyError<D::Error>> {
//! let mut vol = volume::mount::<_, 512, 4096>(card)?;
//! log_boot(&mut vol)?;
//! let _card = vol.unmount()?;
//! # Ok(())
//! # }
//! ```
//!
//! The drivers' own APIs are unchanged and stay the richer surface — FAT
//! attributes and timestamps, exFAT's `NoFatChain` runs, littlefs user
//! attributes. The traits are the common ground, and cost nothing to use:
//! they are generic, not `dyn`, so a call through them compiles to the same
//! code as the driver's own method.
//!
//! # Shape
//!
//! It is the drivers' shape, because it has to be: no heap means the volume
//! owns the device, handles are plain values that borrow nothing, and every
//! operation on a handle takes the volume back.
//!
//! * [`Volume`] — paths, directories, opening files, space, unmounting.
//! * [`VolumeFile`] — reading, writing, seeking and resizing an open file.
//! * [`VolumeDirIter`] — a lending iterator: an [`Entry`]'s name borrows the
//!   iterator, so a listing is `while let`, not `for`.
//! * [`VolumeError`] — every driver's error answers [`ErrorKind`], so generic
//!   code can tell "not found" from "card failed" without knowing whose
//!   error it holds.
//!
//! # Mounting whatever is there
//!
//! [`probe`] looks at a [`SectorDriver`](crate::device::SectorDriver) —
//! the whole medium first, then each GPT or MBR partition — and reports the
//! first volume it recognises. [`mount`] mounts it as an [`AnyVolume`], and
//! [`format`](fn@format) lays a fresh one of any of them down (see
//! [`FormatAs`]), with [`device::mbr`](crate::device::mbr) and
//! [`device::gpt`](crate::device::gpt) there to partition the card first. Raw
//! flash needs no probing, since littlefs is the one filesystem this crate
//! drives there: [`littlefs::Volume`](crate::fs::littlefs::Volume)
//! implements [`Volume`] directly.

mod any;
#[cfg(feature = "exfat")]
mod exfat;
#[cfg(feature = "fat")]
mod fat;
#[cfg(feature = "littlefs")]
mod littlefs;
#[cfg(test)]
mod tests;

pub use any::{
    AnyDir, AnyDirIter, AnyError, AnyFile, AnyVolume, FormatAs, Found, format, mount, mount_found,
    probe,
};
#[cfg(feature = "exfat")]
pub use exfat::ExfatDirIter;
#[cfg(feature = "fat")]
pub use fat::FatDirIter;
#[cfg(feature = "littlefs")]
pub use littlefs::LittleFsDirIter;

/// Which filesystem a volume is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FsType {
    /// FAT12, FAT16 or FAT32.
    Fat,
    /// exFAT.
    Exfat,
    /// littlefs.
    LittleFs,
}

impl FsType {
    /// A short lower-case name: `"fat"`, `"exfat"`, `"littlefs"`.
    pub fn as_str(self) -> &'static str {
        match self {
            FsType::Fat => "fat",
            FsType::Exfat => "exfat",
            FsType::LittleFs => "littlefs",
        }
    }
}

/// What a directory entry names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Kind {
    /// A regular file.
    File,
    /// A directory.
    Dir,
}

/// What every filesystem can say about a file or directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Metadata {
    kind: Kind,
    len: u64,
}

impl Metadata {
    /// Metadata for an entry of `kind` holding `len` bytes.
    pub fn new(kind: Kind, len: u64) -> Self {
        Self { kind, len }
    }

    /// What the entry is.
    pub fn kind(&self) -> Kind {
        self.kind
    }

    /// Whether this is a directory.
    pub fn is_dir(&self) -> bool {
        self.kind == Kind::Dir
    }

    /// Whether this is a regular file.
    pub fn is_file(&self) -> bool {
        self.kind == Kind::File
    }

    /// Size in bytes. What a directory reports is the filesystem's business:
    /// 0 on FAT and littlefs, the length of its cluster chain on exFAT.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether the entry holds no bytes.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// One entry of a directory listing. The name borrows the iterator that
/// produced it.
///
/// `.` and `..` are never reported: FAT is the only filesystem here that
/// stores them, and a listing should not depend on which one it came from.
#[derive(Debug, Clone, Copy)]
pub struct Entry<'a> {
    name: &'a [u8],
    meta: Metadata,
}

impl<'a> Entry<'a> {
    /// An entry named `name`.
    pub fn new(name: &'a [u8], meta: Metadata) -> Self {
        Self { name, meta }
    }

    /// The name as stored. Always UTF-8 on FAT and exFAT, which decode
    /// UTF-16 into it; littlefs names are bytes the program chose.
    pub fn name(&self) -> &'a [u8] {
        self.name
    }

    /// The name as UTF-8, or `None` when it is not.
    pub fn name_str(&self) -> Option<&'a str> {
        core::str::from_utf8(self.name).ok()
    }

    /// The entry's metadata.
    pub fn metadata(&self) -> Metadata {
        self.meta
    }

    /// Whether this is a directory.
    pub fn is_dir(&self) -> bool {
        self.meta.is_dir()
    }

    /// Size in bytes.
    pub fn len(&self) -> u64 {
        self.meta.len
    }

    /// Whether the entry holds no bytes.
    pub fn is_empty(&self) -> bool {
        self.meta.len == 0
    }
}

/// The category of a filesystem error, for code that handles errors from
/// more than one driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The device driver failed.
    Io,
    /// No filesystem this build can mount was found.
    NotRecognised,
    /// The medium, the volume and the buffers the volume was instantiated
    /// with do not fit together: a sector or block size mismatch, a scratch
    /// buffer too small, a volume that runs past the device, a missing
    /// partition.
    Geometry,
    /// The volume's on-disk structures failed validation.
    Corrupt,
    /// Recognised, but uses something the driver does not implement.
    Unsupported,
    /// The volume cannot be written.
    ReadOnly,
    /// A path component does not exist.
    NotFound,
    /// A path component that must be a directory is not one.
    NotADirectory,
    /// The operation needs a file and was given a directory.
    IsADirectory,
    /// The name is already taken.
    AlreadyExists,
    /// The directory still has entries.
    DirectoryNotEmpty,
    /// The name is empty, too long, or uses a reserved character.
    InvalidName,
    /// The path is malformed.
    InvalidPath,
    /// The directory cannot hold another entry.
    DirectoryFull,
    /// No free space left.
    NoSpace,
    /// The file would outgrow what the filesystem can store.
    FileTooLarge,
    /// A seek or read outside what the file or filesystem can address.
    InvalidOffset,
    /// A handle was used with a volume it did not come from.
    WrongVolume,
}

/// An error that can say which [`ErrorKind`] it is.
pub trait VolumeError {
    /// The error's category.
    fn kind(&self) -> ErrorKind;

    /// True for [`ErrorKind::NotFound`] — the check callers write most.
    fn is_not_found(&self) -> bool {
        self.kind() == ErrorKind::NotFound
    }
}

/// A mounted filesystem.
///
/// Paths are absolute, `/`-separated and case-handled however the
/// filesystem handles them (case-insensitively on FAT and exFAT).
pub trait Volume: Sized {
    /// What the volume's operations fail with.
    type Error: VolumeError;
    /// What [`unmount`](Self::unmount) hands back.
    type Device;
    /// An open file. A plain value: it borrows nothing, and each operation
    /// takes the volume back.
    type File: VolumeFile<Self> + core::fmt::Debug;
    /// A directory handle, from [`root`](Self::root),
    /// [`open_dir`](Self::open_dir) or [`create_dir`](Self::create_dir).
    type Dir: Copy + core::fmt::Debug;
    /// A listing in progress.
    type DirIter<'a>: VolumeDirIter<Error = Self::Error>
    where
        Self: 'a;

    /// Which filesystem this is.
    fn fs_type(&self) -> FsType;

    /// The root directory.
    fn root(&self) -> Self::Dir;

    /// Open the directory at `path`.
    fn open_dir(&mut self, path: &str) -> Result<Self::Dir, Self::Error>;

    /// List `dir`.
    fn iter_dir(&mut self, dir: Self::Dir) -> Self::DirIter<'_>;

    /// What `path` names.
    fn metadata(&mut self, path: &str) -> Result<Metadata, Self::Error>;

    /// Whether `path` names anything.
    fn exists(&mut self, path: &str) -> Result<bool, Self::Error> {
        match self.metadata(path) {
            Ok(_) => Ok(true),
            Err(e) if e.is_not_found() => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Create an empty directory at `path`. Its parent must exist.
    fn create_dir(&mut self, path: &str) -> Result<Self::Dir, Self::Error>;

    /// Remove the empty directory at `path`.
    fn remove_dir(&mut self, path: &str) -> Result<(), Self::Error>;

    /// Remove the file at `path`.
    fn remove_file(&mut self, path: &str) -> Result<(), Self::Error>;

    /// Open the existing file at `path`, positioned at its start.
    fn open_file(&mut self, path: &str) -> Result<Self::File, Self::Error>;

    /// Create a file at `path`, truncating it if it exists.
    fn create_file(&mut self, path: &str) -> Result<Self::File, Self::Error>;

    /// Open the file at `path`, creating it empty if it does not exist.
    fn open_or_create_file(&mut self, path: &str) -> Result<Self::File, Self::Error>;

    /// Push everything the volume holds back to the device.
    fn flush(&mut self) -> Result<(), Self::Error>;

    /// Bytes of file data the volume can hold in all.
    fn total_bytes(&self) -> u64;

    /// Bytes of file data still free. May walk the volume's allocation
    /// structures to find out.
    fn free_bytes(&mut self) -> Result<u64, Self::Error>;

    /// Capacity figures in `statfs` shape — the allocation unit, how many
    /// there are and how many are free, the longest name — the same struct
    /// the hosted [`Filesystem::statfs`](crate::fs::Filesystem) answers
    /// with. Costs what [`free_bytes`](Self::free_bytes) costs.
    ///
    /// The FAT, exFAT and littlefs drivers answer in their own allocation
    /// units. The default, for an implementation that predates this method,
    /// derives the figures from [`total_bytes`](Self::total_bytes) and
    /// [`free_bytes`](Self::free_bytes) in 512-byte units with a 255-byte
    /// `name_max`.
    fn statfs(&mut self) -> Result<crate::fs::StatFs, Self::Error> {
        const UNIT: u64 = 512;
        let blocks = self.total_bytes() / UNIT;
        let free = self.free_bytes()? / UNIT;
        Ok(crate::fs::StatFs {
            block_size: UNIT as u32,
            blocks,
            blocks_free: free,
            blocks_avail: free,
            inodes: 0,
            inodes_free: 0,
            name_max: 255,
        })
    }

    /// Flush and hand the device back.
    fn unmount(self) -> Result<Self::Device, Self::Error>;
}

/// An open file on a `V`.
///
/// Changes to a file's length reach its directory entry on
/// [`flush`](Self::flush); flush a file you have written before dropping
/// its handle.
pub trait VolumeFile<V: Volume> {
    /// Length in bytes.
    fn len(&self) -> u64;

    /// Whether the file is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The position the next read or write starts at.
    fn pos(&self) -> u64;

    /// Move to byte `pos`. Past the end is allowed; a write there extends
    /// the file.
    fn seek(&mut self, vol: &mut V, pos: u64) -> Result<(), V::Error>;

    /// Move to the end, so the next write appends.
    fn seek_to_end(&mut self, vol: &mut V) -> Result<(), V::Error> {
        let len = self.len();
        self.seek(vol, len)
    }

    /// Read into `buf` from the current position; 0 at end of file.
    fn read(&mut self, vol: &mut V, buf: &mut [u8]) -> Result<usize, V::Error>;

    /// Fill `buf` exactly, or fail.
    fn read_exact(&mut self, vol: &mut V, buf: &mut [u8]) -> Result<(), V::Error>;

    /// Write from `buf` at the current position, extending the file as
    /// needed; returns how much was written.
    fn write(&mut self, vol: &mut V, buf: &[u8]) -> Result<usize, V::Error>;

    /// Write all of `buf`, or fail.
    fn write_all(&mut self, vol: &mut V, buf: &[u8]) -> Result<(), V::Error>;

    /// Truncate or extend to `len` bytes. Extension reads back as zeros.
    fn set_len(&mut self, vol: &mut V, len: u64) -> Result<(), V::Error>;

    /// Record the file's state in its directory entry and push it to the
    /// device.
    fn flush(&mut self, vol: &mut V) -> Result<(), V::Error>;
}

/// A directory listing in progress: a lending iterator, because an entry's
/// name borrows the buffer it was decoded into.
pub trait VolumeDirIter {
    /// What the walk fails with.
    type Error: VolumeError;

    /// The next entry, or `None` at the end of the directory.
    fn next(&mut self) -> Result<Option<Entry<'_>>, Self::Error>;
}
