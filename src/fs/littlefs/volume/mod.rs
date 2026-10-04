//! littlefs with no allocator.
//!
//! This is a second, independent littlefs driver. [`super::hosted`] is the
//! hosted one: it replays metadata pairs into `Vec<Entry>` views, holds an
//! exact in-use bitmap for the whole volume, hands back `String` names, and
//! speaks the crate's [`Filesystem`](crate::fs::Filesystem) trait. That
//! design is right for building images on a machine with a heap and wrong
//! for a microcontroller, so none of it is reused here. Instead:
//!
//! * **No allocation, anywhere.** Every buffer is a fixed-size array or
//!   comes from the caller. With `default-features = false, features =
//!   ["littlefs"]` the crate compiles and links on a target with no global
//!   allocator at all; the hosted driver appears only when `alloc` is also
//!   on.
//! * **One block of scratch.** A metadata pair is read into it and answered
//!   from there by walking the tag log (see [`mdir`]); a commit streams out
//!   through a staging buffer the size of one program page. Nothing else is
//!   held.
//! * **Allocation through a lookahead window.** littlefs keeps no free list
//!   on disk — a block is in use exactly when something reachable from the
//!   superblock points at it — so the driver rediscovers that by traversing
//!   the filesystem into a fixed [`LOOKAHEAD_BLOCKS`]-block bitmap, exactly
//!   as the C implementation does. With `alloc` the traversal happens once
//!   and the whole volume's bitmap is kept instead.
//! * **A flash driver, not a block device.** [`FlashDriver`](crate::device::FlashDriver) — from
//!   [`crate::device`], the layer below the filesystems — is what you
//!   implement over your NOR/NAND peripheral. It mirrors littlefs's own
//!   `lfs_config` (read, program, erase, sync) and carries an associated
//!   error type, unlike [`crate::block::BlockDevice`], whose signatures
//!   return a `crate::Error` that owns a `String`.
//!
//! Reads and writes are both supported: mount, format, open, read, seek,
//! append, extend, truncate, create and remove files, create and remove
//! directories, list directories, and read and write littlefs user
//! attributes.
//!
//! # Shape of the API
//!
//! There is no interior mutability and no heap, so the volume owns the
//! driver and every handle is a plain `Copy` value that borrows nothing.
//! Operations on a handle therefore take the volume back:
//!
//! ```
//! # use fstool::device::FlashDriver;
//! # use fstool::fs::littlefs::{Error, Volume};
//! # struct Nor([u8; 0]);
//! # impl FlashDriver for Nor {
//! #     type Error = core::convert::Infallible;
//! #     fn block_size(&self) -> u32 { 4096 }
//! #     fn block_count(&self) -> u32 { 0 }
//! #     fn read(&mut self, _: u32, _: u32, _: &mut [u8]) -> Result<(), Self::Error> { Ok(()) }
//! #     fn prog(&mut self, _: u32, _: u32, _: &[u8]) -> Result<(), Self::Error> { Ok(()) }
//! #     fn erase(&mut self, _: u32) -> Result<(), Self::Error> { Ok(()) }
//! # }
//! # fn demo(flash: Nor) -> Result<(), Error<core::convert::Infallible>> {
//! let mut vol = Volume::<_, 4096>::mount(flash)?;
//!
//! // Read a config file into a fixed buffer.
//! let mut file = vol.open_file("/config/wifi.txt")?;
//! let mut buf = [0u8; 256];
//! let n = file.read(&mut vol, &mut buf)?;
//!
//! // Append a line to a log, creating it if needed.
//! let mut log = vol.open_or_create_file("/log.txt")?;
//! log.seek_to_end(&mut vol);
//! log.write_all(&mut vol, b"booted\n")?;
//!
//! // List a directory. Entries borrow the volume's scratch, so this is a
//! // `while let`, not a `for`.
//! let dir = vol.open_dir("/")?;
//! let mut it = vol.iter_dir(dir);
//! while let Some(entry) = it.next()? {
//!     let _ = (entry.name(), entry.len(), entry.is_dir());
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Limits
//!
//! * `BLOCK`, the first const parameter, is the scratch buffer's size and
//!   must be at least the volume's block size; `PROG`, the second, is the
//!   staging buffer's and must be at least the driver's program size. Use
//!   `Volume::<_, 4096>` unless your flash says otherwise.
//! * Every metadata change is written as a full compaction — one erase and
//!   one block programmed — rather than appended to the live block the way
//!   littlefs can when the rest of it is known to be erased. The result is
//!   always a volume a stock littlefs mounts and keeps appending to; the
//!   cost is flash wear on metadata-heavy workloads. The hosted half makes
//!   the same trade.
//! * A file write is applied immediately: there is no dirty region to
//!   buffer it in. Writing a file in small pieces therefore rewrites its
//!   last block once per call, so prefer writing in block-sized chunks.
//! * A handle caches where its directory entry lives, so removing or
//!   re-creating a path while a handle to it is open is a bug the driver
//!   cannot detect.
//! * A metadata pair holding more than 255 entries can be read but not
//!   written to ([`Error::Unsupported`]): the sizing a commit does lives in
//!   a fixed array, and littlefs's own writer splits a pair well before it
//!   gets there.
//! * An image a stock littlefs left mid-*move* (its global state naming an
//!   entry in limbo) is read with that entry still present, as the hosted
//!   half reads it.

mod dir;
mod file;
mod mdir;
#[cfg(test)]
mod tests;

pub use dir::{Dir, DirEntry, DirIter, Metadata};
pub use file::File;

use super::index;
use super::tag;
use super::{DISK_VERSION_2_0, DISK_VERSION_2_1, FILE_MAX, MAGIC, SUPERBLOCK_PAIR};
use mdir::{Commit, Data, Mdir, Struct, StructOut};

/// Blocks one refill of the allocator's lookahead window covers.
///
/// The window is a bitmap of this many blocks (so, this many bits — 32
/// bytes) built by traversing the filesystem. littlefs's own default covers
/// 128 blocks; a larger window means fewer traversals and the same
/// allocations. With `alloc` on, the whole volume is covered at once and the
/// window is not used.
pub const LOOKAHEAD_BLOCKS: u32 = 256;

/// Words of the lookahead bitmap.
#[cfg(not(feature = "alloc"))]
const LOOKAHEAD_WORDS: usize = (LOOKAHEAD_BLOCKS as usize).div_ceil(32);

/// Smallest block size littlefs can work with: below this a CTZ block
/// cannot hold its skip pointers.
pub const MIN_BLOCK_SIZE: u32 = 128;

// The storage the driver is written against lives one layer down in
// `crate::device` — the module a consumer implements against, and the only
// canonical path for it. A block size below `MIN_BLOCK_SIZE` is refused at
// mount: under it a CTZ block cannot hold its own skip pointers.
use crate::device::FlashDriver;

/// Everything that can go wrong, parameterised by the driver's own error.
///
/// No variant owns a heap allocation; the ones that carry detail carry it
/// as numbers or a `&'static str`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error<E> {
    /// The driver failed.
    Io(E),
    /// No littlefs volume here: the magic is missing from block 0.
    NotLittleFs,
    /// The volume's on-disk version is not one this driver reads.
    UnsupportedVersion {
        /// Major version from the superblock.
        major: u16,
        /// Minor version from the superblock.
        minor: u16,
    },
    /// The volume was formatted for a different block size than the driver
    /// reports, or claims more blocks than the driver has.
    GeometryMismatch {
        /// What the superblock says.
        volume: u32,
        /// What the driver reports.
        driver: u32,
    },
    /// The driver describes a geometry littlefs cannot use: a block size
    /// that is not a power of two or is too small, a program size larger
    /// than a block, or fewer than four blocks.
    BadGeometry,
    /// A scratch buffer is too small: `BLOCK` below the volume's block
    /// size, or `PROG` below the driver's program size.
    ScratchTooSmall {
        /// What is needed.
        needed: usize,
        /// The const parameter the volume was instantiated with.
        got: usize,
    },
    /// On-disk structure failed validation; the volume needs `fsck`.
    Corrupt(&'static str),
    /// A path component does not exist.
    NotFound,
    /// A path component that must be a directory is not one.
    NotADirectory,
    /// The target is a directory and the operation needs a file.
    IsADirectory,
    /// Creating something whose name is already taken.
    AlreadyExists,
    /// `remove_dir` on a directory that still has entries.
    DirectoryNotEmpty,
    /// The name is empty, longer than the volume's `name_max`, or contains
    /// a `/`.
    InvalidName,
    /// A path is malformed: not absolute, or a component is `.` or `..`.
    InvalidPath,
    /// The volume has no free block left.
    NoSpace,
    /// One entry is too large for a metadata block to hold on its own —
    /// a name plus an inline file that no split can separate.
    CommitTooLarge,
    /// The operation would take the file past the volume's `file_max`.
    FileTooLarge,
    /// A seek or write past the end of what littlefs can address.
    InvalidOffset,
    /// The attribute value is longer than the volume's `attr_max`.
    AttrTooLarge,
    /// Recognised on-disk structure this driver does not implement.
    Unsupported(&'static str),
}

impl<E> Error<E> {
    /// True for [`Error::NotFound`] — the check callers write most.
    pub fn is_not_found(&self) -> bool {
        matches!(self, Error::NotFound)
    }
}

impl<E: core::fmt::Display> core::fmt::Display for Error<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "device error: {e}"),
            Error::NotLittleFs => f.write_str("not a littlefs volume"),
            Error::UnsupportedVersion { major, minor } => {
                write!(f, "unsupported littlefs disk version {major}.{minor}")
            }
            Error::GeometryMismatch { volume, driver } => {
                write!(
                    f,
                    "volume is formatted for {volume}, driver reports {driver}"
                )
            }
            Error::BadGeometry => f.write_str("geometry littlefs cannot use"),
            Error::ScratchTooSmall { needed, got } => {
                write!(f, "scratch buffer is {got} bytes, need {needed}")
            }
            Error::Corrupt(what) => write!(f, "corrupt volume: {what}"),
            Error::NotFound => f.write_str("no such file or directory"),
            Error::NotADirectory => f.write_str("not a directory"),
            Error::IsADirectory => f.write_str("is a directory"),
            Error::AlreadyExists => f.write_str("already exists"),
            Error::DirectoryNotEmpty => f.write_str("directory not empty"),
            Error::InvalidName => f.write_str("invalid name"),
            Error::InvalidPath => f.write_str("invalid path"),
            Error::NoSpace => f.write_str("no space left on volume"),
            Error::CommitTooLarge => f.write_str("entry too large for a metadata block"),
            Error::FileTooLarge => f.write_str("file would exceed the volume's limit"),
            Error::InvalidOffset => f.write_str("offset out of range"),
            Error::AttrTooLarge => f.write_str("attribute value too large"),
            Error::Unsupported(what) => write!(f, "unsupported: {what}"),
        }
    }
}

#[cfg(feature = "std")]
impl<E: core::fmt::Debug + core::fmt::Display> std::error::Error for Error<E> {}

/// Format-time options for [`Volume::format_with`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormatOpts {
    /// Blocks to use. `None` takes every block the driver reports. The
    /// block size and program size come from the driver, not from here.
    pub block_count: Option<u32>,
    /// On-disk version to write: [`DISK_VERSION_2_1`](super::DISK_VERSION_2_1)
    /// (default) or [`DISK_VERSION_2_0`](super::DISK_VERSION_2_0) for
    /// targets running a pre-2.1 littlefs.
    pub disk_version: u32,
    /// Longest name the volume accepts.
    pub name_max: u32,
    /// Largest file kept inline in its directory's metadata instead of
    /// being written out as a CTZ skip-list. `None` picks littlefs's own
    /// default of an eighth of a block.
    pub inline_max: Option<u32>,
}

impl Default for FormatOpts {
    fn default() -> Self {
        Self {
            block_count: None,
            disk_version: DISK_VERSION_2_1,
            name_max: 255,
            inline_max: None,
        }
    }
}

/// A volume's validated geometry and limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Geometry {
    /// Logical block (erase unit) size.
    pub block_size: u32,
    /// Blocks the filesystem spans.
    pub block_count: u32,
    /// Program alignment commits are padded to.
    pub prog_size: u32,
    /// On-disk version, as stored in the superblock.
    pub version: u32,
    /// Longest name the volume accepts.
    pub name_max: u32,
    /// Largest file the volume accepts.
    pub file_max: u32,
    /// Largest user attribute the volume accepts.
    pub attr_max: u32,
    /// Largest file kept inline in metadata.
    pub inline_max: u32,
}

impl Geometry {
    /// Whether commits carry lfs2.1 forward-CRC tags. Off for images pinned
    /// to disk version 2.0, whose readers mistake an FCRC for a commit CRC.
    fn fcrc(&self) -> bool {
        self.version >= DISK_VERSION_2_1
    }

    /// On-disk version as `(major, minor)`.
    pub fn version_parts(&self) -> (u16, u16) {
        ((self.version >> 16) as u16, (self.version & 0xffff) as u16)
    }

    /// Largest total size of a pair's *entries* that a metadata block can
    /// still hold once everything a commit appends to them is accounted
    /// for: the tail (4+8), a global-state delta (4+12), the forward-CRC
    /// (4+8) and the commit CRC (4+4).
    fn commit_limit(&self) -> usize {
        self.block_size as usize - 48
    }

    /// Size past which a metadata pair is split in two. littlefs caps a
    /// compaction at half a block so a pair that is repeatedly appended to
    /// doesn't degenerate into one that must compact on every commit.
    fn split_limit(&self) -> usize {
        let half = (self.block_size as usize / 2).next_multiple_of(self.prog_size.max(1) as usize);
        half.min(self.commit_limit())
    }

    /// littlefs's own default: a file is inlined while it fits in an eighth
    /// of a metadata block, bounded by what a single tag can carry.
    fn default_inline_max(&self) -> u32 {
        let ceiling = (tag::MAX_SIZE as u32).min(self.split_limit() as u32 / 2);
        (self.block_size / 8).min(ceiling)
    }
}

/// Which entry of a pair a commit is about, and where it ended up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Placed {
    pair: [u32; 2],
    id: u16,
}

/// The change a commit applies to the pair it rewrites.
#[derive(Debug, Clone, Copy)]
enum Edit<'a> {
    /// Rewrite the pair as it stands — used when only its tail or its
    /// global-state delta changed.
    Nothing,
    /// Add an entry at `at`, shifting the ids after it up.
    Insert {
        at: u16,
        kind: u8,
        name: &'a [u8],
        data: StructOut<'a>,
    },
    /// Point an existing id at different data.
    SetStruct { id: u16, data: StructOut<'a> },
    /// Drop an id, shifting the ids after it down.
    Delete { id: u16 },
    /// Set (or, with `None`, remove) one user attribute.
    SetAttr {
        id: u16,
        key: u8,
        value: Option<&'a [u8]>,
    },
}

impl<'a> Edit<'a> {
    /// How the pair's id count changes.
    fn count_delta(&self) -> i32 {
        match self {
            Edit::Insert { .. } => 1,
            Edit::Delete { .. } => -1,
            _ => 0,
        }
    }

    /// The logical id this edit is about, if any.
    fn focus(&self) -> Option<u16> {
        match self {
            Edit::Insert { at, .. } => Some(*at),
            Edit::SetStruct { id, .. } | Edit::SetAttr { id, .. } => Some(*id),
            Edit::Nothing | Edit::Delete { .. } => None,
        }
    }

    /// What logical entry `i` of the rewritten pair is.
    fn item(&self, i: u16) -> Item<'a> {
        match self {
            Edit::Nothing => Item::Copy(i),
            Edit::Insert {
                at,
                kind,
                name,
                data,
            } => {
                if i < *at {
                    Item::Copy(i)
                } else if i == *at {
                    Item::New {
                        kind: *kind,
                        name,
                        data: *data,
                    }
                } else {
                    Item::Copy(i - 1)
                }
            }
            Edit::SetStruct { id, data } => {
                if i == *id {
                    Item::CopyWithData(i, *data)
                } else {
                    Item::Copy(i)
                }
            }
            Edit::Delete { id } => {
                if i < *id {
                    Item::Copy(i)
                } else {
                    Item::Copy(i + 1)
                }
            }
            Edit::SetAttr { id, key, value } => {
                if i == *id {
                    Item::CopyWithAttr(i, *key, *value)
                } else {
                    Item::Copy(i)
                }
            }
        }
    }
}

/// One entry a commit is going to write.
#[derive(Debug, Clone, Copy)]
enum Item<'a> {
    /// Source id, copied through unchanged.
    Copy(u16),
    /// Source id, with its struct replaced.
    CopyWithData(u16, StructOut<'a>),
    /// Source id, with one attribute set or removed.
    CopyWithAttr(u16, u8, Option<&'a [u8]>),
    /// A brand-new entry.
    New {
        kind: u8,
        name: &'a [u8],
        data: StructOut<'a>,
    },
}

/// A mounted littlefs volume that owns its flash.
///
/// `BLOCK` is the size of the single block of scratch RAM the volume keeps;
/// it must be at least the volume's block size. `PROG` is the staging
/// buffer a commit is programmed through; it must be at least the driver's
/// program size, and a larger one means fewer, bigger `prog` calls.
#[derive(Debug)]
pub struct Volume<D: FlashDriver, const BLOCK: usize = 4096, const PROG: usize = 256> {
    dev: D,
    geom: Geometry,
    /// One block of scratch: the live half of whichever metadata pair was
    /// last fetched, or a data block being assembled.
    buf: [u8; BLOCK],
    /// Staging buffer for the commit being written.
    stage: [u8; PROG],
    /// The pair `buf` holds the live block of, and its parse.
    cached: Option<Mdir>,
    /// The metadata pair the root directory's entries start at. Usually the
    /// superblock pair, but littlefs moves the root along its own chain as
    /// it is rewritten, to spread erase cycles.
    root: [u32; 2],
    /// First block the lookahead window covers. The window itself, the
    /// candidate within it, and whether a traversal has filled it —
    /// allocation's whole state when there is no heap to hold a bitmap of
    /// the entire volume in.
    #[cfg(not(feature = "alloc"))]
    look_start: u32,
    #[cfg(not(feature = "alloc"))]
    look: [u32; LOOKAHEAD_WORDS],
    #[cfg(not(feature = "alloc"))]
    look_next: u32,
    #[cfg(not(feature = "alloc"))]
    look_valid: bool,
    /// A metadata pair claimed by an operation in progress and not yet
    /// linked into the filesystem, and the skip-list of a file being
    /// written. A lookahead refill has to count these as taken, or it would
    /// hand the same block out twice.
    pending_pair: Option<[u32; 2]>,
    pending_ctz: Option<(u32, u32)>,
    /// Where the next search for a free block starts, with the whole
    /// volume's bitmap to search.
    #[cfg(feature = "alloc")]
    cursor: u32,
    /// The whole volume's in-use bitmap, held when there is a heap to hold
    /// it in. Pure optimisation: the same calls give the same answers
    /// without it, just one traversal per window refill instead of none.
    #[cfg(feature = "alloc")]
    used: Option<::alloc::vec::Vec<u32>>,
}

impl<D: FlashDriver, const BLOCK: usize, const PROG: usize> Volume<D, BLOCK, PROG> {
    // -- mounting ---------------------------------------------------------

    /// Mount the volume on `dev`.
    ///
    /// The driver's own geometry is what the filesystem is read with, and
    /// the superblock is checked against it — which is both what littlefs
    /// itself does and what lets a mount survive a corrupt block 0, since
    /// the superblock entry is read through its metadata *pair* rather than
    /// from a fixed offset.
    pub fn mount(dev: D) -> Result<Self, Error<D::Error>> {
        Self::check_scratch(&dev)?;
        // Provisional limits, wide enough to read the superblock with; the
        // real ones come out of it below.
        let provisional = Geometry {
            block_size: dev.block_size(),
            block_count: dev.block_count(),
            prog_size: dev.prog_size().max(1),
            version: DISK_VERSION_2_1,
            name_max: tag::MAX_SIZE as u32,
            file_max: FILE_MAX,
            attr_max: tag::MAX_SIZE as u32,
            inline_max: 0,
        };
        Self::check_geometry(&provisional)?;
        let mut vol = Self::new(dev, provisional);

        let m = match vol.fetch(SUPERBLOCK_PAIR) {
            Ok(m) => m,
            // Neither half holds a valid commit: there is no filesystem
            // here, which is a different thing from a device that failed.
            Err(Error::Corrupt(_)) => return Err(Error::NotLittleFs),
            Err(e) => return Err(e),
        };
        let bs = vol.bs();
        let Some((kind, name_off, name_len)) = mdir::name_of(&vol.buf[..bs], &m, 0) else {
            return Err(Error::NotLittleFs);
        };
        if kind != tag::TYPE_SUPERBLOCK as u8
            || name_len as usize != MAGIC.len()
            || &vol.buf[name_off as usize..name_off as usize + MAGIC.len()] != MAGIC
        {
            return Err(Error::NotLittleFs);
        }
        let Some(Struct::Inline { off, len }) = mdir::struct_of(&vol.buf[..bs], &m, 0) else {
            return Err(Error::NotLittleFs);
        };
        if len < 24 {
            return Err(Error::NotLittleFs);
        }
        let cfg = &vol.buf[off as usize..off as usize + 24];
        let version = tag::le32(&cfg[0..4]);
        let block_size = tag::le32(&cfg[4..8]);
        let block_count = tag::le32(&cfg[8..12]);
        let mut geom = Geometry {
            version,
            name_max: tag::le32(&cfg[12..16]),
            file_max: tag::le32(&cfg[16..20]),
            attr_max: tag::le32(&cfg[20..24]),
            ..vol.geom
        };

        if version >> 16 != 2 || version & 0xffff > (DISK_VERSION_2_1 & 0xffff) {
            return Err(Error::UnsupportedVersion {
                major: (version >> 16) as u16,
                minor: (version & 0xffff) as u16,
            });
        }
        if block_size != vol.dev.block_size() {
            return Err(Error::GeometryMismatch {
                volume: block_size,
                driver: vol.dev.block_size(),
            });
        }
        if block_count == 0 || block_count > vol.dev.block_count() {
            return Err(Error::GeometryMismatch {
                volume: block_count,
                driver: vol.dev.block_count(),
            });
        }
        geom.block_count = block_count;
        // A zero — or implausible — limit means "unset"; littlefs falls back
        // to its own defaults for those.
        if geom.name_max == 0 || geom.name_max > tag::MAX_SIZE as u32 {
            geom.name_max = 255;
        }
        if geom.file_max == 0 || geom.file_max > FILE_MAX {
            geom.file_max = FILE_MAX;
        }
        if geom.attr_max == 0 || geom.attr_max > tag::MAX_SIZE as u32 {
            geom.attr_max = tag::MAX_SIZE as u32;
        }
        geom.inline_max = geom.default_inline_max();
        Self::check_geometry(&geom)?;
        vol.geom = geom;

        // Walk the superblock chain: the last pair still carrying a
        // superblock entry is the root directory. littlefs grows this chain
        // as the root is rewritten, to spread erase cycles.
        vol.root = SUPERBLOCK_PAIR;
        let mut pair = Some(SUPERBLOCK_PAIR);
        let mut hops = 0u32;
        while let Some(p) = pair {
            let m = vol.fetch(p)?;
            if vol.is_superblock_pair(&m) {
                vol.root = m.pair;
            }
            pair = m.tail;
            hops += 1;
            if hops > block_count {
                return Err(Error::Corrupt("cycle in the metadata-pair list"));
            }
        }
        Ok(vol)
    }

    /// Format a fresh volume on `dev` with the default options, then mount
    /// it.
    pub fn format(dev: D) -> Result<Self, Error<D::Error>> {
        Self::format_with(dev, &FormatOpts::default())
    }

    /// Format a fresh volume on `dev`, then mount it.
    ///
    /// This is `lfs_format`: the superblock pair is laid down twice, so that
    /// *both* halves are valid littlefs commits and nothing of an older
    /// filesystem is left for a fetch to trip over.
    pub fn format_with(dev: D, opts: &FormatOpts) -> Result<Self, Error<D::Error>> {
        Self::check_scratch(&dev)?;
        if opts.disk_version != DISK_VERSION_2_0 && opts.disk_version != DISK_VERSION_2_1 {
            return Err(Error::UnsupportedVersion {
                major: (opts.disk_version >> 16) as u16,
                minor: (opts.disk_version & 0xffff) as u16,
            });
        }
        let avail = dev.block_count();
        let block_count = opts.block_count.unwrap_or(avail);
        if block_count > avail {
            return Err(Error::GeometryMismatch {
                volume: block_count,
                driver: avail,
            });
        }
        if opts.name_max == 0 || opts.name_max > tag::MAX_SIZE as u32 {
            return Err(Error::BadGeometry);
        }

        let mut geom = Geometry {
            block_size: dev.block_size(),
            block_count,
            prog_size: dev.prog_size().max(1),
            version: opts.disk_version,
            name_max: opts.name_max,
            file_max: FILE_MAX,
            attr_max: tag::MAX_SIZE as u32,
            inline_max: 0,
        };
        geom.inline_max = match opts.inline_max {
            Some(v) => {
                let ceiling = (tag::MAX_SIZE as u32).min(geom.split_limit() as u32 / 2);
                if v > ceiling {
                    return Err(Error::BadGeometry);
                }
                v
            }
            None => geom.default_inline_max(),
        };
        Self::check_geometry(&geom)?;

        let mut vol = Self::new(dev, geom);
        vol.root = SUPERBLOCK_PAIR;
        // The superblock entry: a name tag carrying the magic, and an
        // inline struct carrying the configuration. Both halves of the pair
        // are written, so neither is left holding an older filesystem's
        // commit for a fetch to trip over — and the second, with the higher
        // revision count, is the live one.
        let sb = vol.superblock_bytes();
        for (i, block) in [SUPERBLOCK_PAIR[0], SUPERBLOCK_PAIR[1]]
            .into_iter()
            .enumerate()
        {
            let empty = Mdir::empty([block, block]);
            vol.write_range(
                &empty,
                Edit::Insert {
                    at: 0,
                    kind: tag::TYPE_SUPERBLOCK as u8,
                    name: MAGIC,
                    data: StructOut::Inline(Data::Bytes(&sb)),
                },
                0,
                1,
                block,
                i as u32 + 1,
                None,
                false,
                None,
            )?;
        }
        vol.cached = None;
        // Claim the superblock pair so nothing else can hand it out.
        vol.mark_used(SUPERBLOCK_PAIR[0]);
        vol.mark_used(SUPERBLOCK_PAIR[1]);
        Ok(vol)
    }

    fn new(dev: D, geom: Geometry) -> Self {
        Self {
            dev,
            geom,
            buf: [0u8; BLOCK],
            stage: [0u8; PROG],
            cached: None,
            root: SUPERBLOCK_PAIR,
            #[cfg(not(feature = "alloc"))]
            look_start: 0,
            #[cfg(not(feature = "alloc"))]
            look: [0u32; LOOKAHEAD_WORDS],
            #[cfg(not(feature = "alloc"))]
            look_next: 0,
            #[cfg(not(feature = "alloc"))]
            look_valid: false,
            pending_pair: None,
            pending_ctz: None,
            #[cfg(feature = "alloc")]
            cursor: 0,
            #[cfg(feature = "alloc")]
            used: None,
        }
    }

    fn check_scratch(dev: &D) -> Result<(), Error<D::Error>> {
        let bs = dev.block_size() as usize;
        if BLOCK < bs {
            return Err(Error::ScratchTooSmall {
                needed: bs,
                got: BLOCK,
            });
        }
        let prog = dev.prog_size().max(1) as usize;
        if PROG < prog {
            return Err(Error::ScratchTooSmall {
                needed: prog,
                got: PROG,
            });
        }
        Ok(())
    }

    fn check_geometry(geom: &Geometry) -> Result<(), Error<D::Error>> {
        if geom.block_size < MIN_BLOCK_SIZE
            || !geom.block_size.is_power_of_two()
            || !geom.prog_size.is_power_of_two()
            || geom.prog_size > geom.block_size
            // The superblock pair plus room for a directory pair and data.
            || geom.block_count < 4
        {
            return Err(Error::BadGeometry);
        }
        Ok(())
    }

    /// The 24-byte superblock configuration record.
    fn superblock_bytes(&self) -> [u8; 24] {
        let mut b = [0u8; 24];
        for (i, v) in [
            self.geom.version,
            self.geom.block_size,
            self.geom.block_count,
            self.geom.name_max,
            self.geom.file_max,
            self.geom.attr_max,
        ]
        .iter()
        .enumerate()
        {
            b[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
        }
        b
    }

    // -- accessors --------------------------------------------------------

    /// The volume's geometry and limits.
    pub fn geometry(&self) -> &Geometry {
        &self.geom
    }

    /// Borrow the driver.
    pub fn driver(&self) -> &D {
        &self.dev
    }

    /// Mutably borrow the driver.
    pub fn driver_mut(&mut self) -> &mut D {
        &mut self.dev
    }

    /// Flush the driver's own cache. Filesystem state is written through as
    /// it changes, so there is nothing of the volume's to flush.
    pub fn sync(&mut self) -> Result<(), Error<D::Error>> {
        self.dev.sync().map_err(Error::Io)
    }

    /// Give the driver back.
    ///
    /// Filesystem state is written through as it changes, so this only
    /// syncs the driver; a volume that is simply dropped has nothing
    /// outstanding either.
    pub fn unmount(mut self) -> Result<D, Error<D::Error>> {
        self.sync()?;
        // The volume has no destructor of its own, so the driver moves out
        // by destructuring — which drops what is left, allocation bitmap
        // included, rather than leaking it.
        let Self { dev, .. } = self;
        Ok(dev)
    }

    /// Bytes of allocation bitmap currently held in memory.
    ///
    /// Always `0` in a build without `alloc`, where allocation traverses
    /// the filesystem into a [`LOOKAHEAD_BLOCKS`]-block window whenever
    /// that window runs dry. With a heap the whole volume is covered once
    /// and kept, which is the only difference the feature makes to this
    /// driver: the same calls give the same answers, with far fewer reads.
    /// (*Which* free block a write lands in can differ — a window only
    /// rediscovers freed blocks when it comes round to them again — but
    /// nothing a caller can observe through this API does.)
    pub fn alloc_cache_bytes(&self) -> usize {
        #[cfg(feature = "alloc")]
        {
            self.used.as_ref().map_or(0, |v| v.len() * 4)
        }
        #[cfg(not(feature = "alloc"))]
        {
            0
        }
    }
}

// ---------------------------------------------------------------------
// The scratch buffer, metadata pairs, and commits
// ---------------------------------------------------------------------

impl<D: FlashDriver, const BLOCK: usize, const PROG: usize> Volume<D, BLOCK, PROG> {
    /// The volume's block size, as a `usize` for slicing the scratch.
    fn bs(&self) -> usize {
        self.geom.block_size as usize
    }

    /// Read `block` into the scratch buffer.
    fn read_block(&mut self, block: u32) -> Result<(), Error<D::Error>> {
        if block >= self.geom.block_count {
            return Err(Error::Corrupt("block beyond the end of the volume"));
        }
        let bs = self.bs();
        self.cached = None;
        self.dev
            .read(block, 0, &mut self.buf[..bs])
            .map_err(Error::Io)
    }

    /// Read just the revision count of a block.
    fn read_rev(&mut self, block: u32) -> Result<u32, Error<D::Error>> {
        let mut b = [0u8; 4];
        self.dev.read(block, 0, &mut b).map_err(Error::Io)?;
        Ok(u32::from_le_bytes(b))
    }

    /// Fetch a metadata pair: whichever half holds the newer valid commit,
    /// parsed, with its bytes left in the scratch buffer.
    fn fetch(&mut self, pair: [u32; 2]) -> Result<Mdir, Error<D::Error>> {
        for b in pair {
            if b >= self.geom.block_count {
                return Err(Error::Corrupt("metadata pair beyond the end of the volume"));
            }
        }
        // A pair addresses the same metadata whichever way round it is
        // written, and a commit swaps the two halves.
        if let Some(m) = self.cached
            && ((m.pair[0] == pair[0] && m.pair[1] == pair[1])
                || (m.pair[0] == pair[1] && m.pair[1] == pair[0]))
        {
            return Ok(m);
        }

        // Try the block with the newer revision count first; fall back to
        // its partner when it holds no valid commit (a power cut
        // mid-compaction).
        let mut order = pair;
        let a = self.read_rev(pair[0])?;
        let b = self.read_rev(pair[1])?;
        if tag::rev_newer(b, a) {
            order.swap(0, 1);
        }
        for i in 0..2 {
            let block = order[i];
            self.read_block(block)?;
            let bs = self.bs();
            if let Some(m) = mdir::parse(&self.buf[..bs], [block, order[1 - i]]) {
                self.cached = Some(m);
                return Ok(m);
            }
        }
        Err(Error::Corrupt("metadata pair holds no valid commit"))
    }

    /// Make sure the scratch buffer holds `m`'s live block.
    fn load(&mut self, m: &Mdir) -> Result<(), Error<D::Error>> {
        if self.cached.is_some_and(|c| c.pair[0] == m.pair[0]) {
            return Ok(());
        }
        self.read_block(m.pair[0])?;
        let bs = self.bs();
        // Re-parsing gives the same answer the caller already has; keeping
        // it is what makes the next fetch of this pair free.
        self.cached = mdir::parse(&self.buf[..bs], m.pair);
        Ok(())
    }

    /// Whether this pair carries the superblock entry — which is how the
    /// root directory is recognised.
    fn is_superblock_pair(&self, m: &Mdir) -> bool {
        let bs = self.bs();
        matches!(
            mdir::name_of(&self.buf[..bs], m, 0),
            Some((kind, _, _)) if kind == tag::TYPE_SUPERBLOCK as u8
        )
    }

    /// Rewrite `m` with `edit` applied, splitting it across further pairs
    /// first if the result no longer fits one metadata block.
    ///
    /// Returns the pair the head half ended up as, and where the entry the
    /// edit was about landed.
    fn commit(&mut self, m: &Mdir, edit: Edit<'_>) -> Result<CommitOut, Error<D::Error>> {
        // The marker is restored rather than cleared: this commit may be
        // one step of an operation that has claimed a pair of its own, and
        // it has to be put back whether or not the commit gets there.
        let outer_pending = self.pending_pair;
        let out = self.commit_inner(m, edit);
        self.pending_pair = outer_pending;
        out
    }

    fn commit_inner(&mut self, m: &Mdir, edit: Edit<'_>) -> Result<CommitOut, Error<D::Error>> {
        self.load(m)?;
        let total = (m.count as i32 + edit.count_delta()).max(0);
        if total > MAX_IDS as i32 + 1 {
            return Err(Error::Unsupported(
                "more than 255 entries in a metadata pair",
            ));
        }
        let total = total as u16;

        // Entry sizes, measured once. A commit needs them to decide
        // whether the pair still fits, and a split needs them repeatedly.
        // One slot more than a pair may hold: an insert into a full pair is
        // measured first and split afterwards.
        let mut sizes = [0u16; MAX_IDS + 1];
        {
            let bs = self.bs();
            let src = &self.buf[..bs];
            let keys = mdir::attr_keys(src, m);
            for i in 0..total {
                sizes[i as usize] = item_size(src, m, &keys, &edit.item(i)) as u16;
            }
        }
        let span = |lo: u16, hi: u16| -> usize {
            sizes[lo as usize..hi as usize]
                .iter()
                .map(|n| *n as usize)
                .sum()
        };

        let mut focus = edit.focus().map(|id| Placed { pair: m.pair, id });
        let mut placed = None;
        let mut end = total;
        let mut tail = m.tail;
        let mut hard = m.hard;
        let limit = self.geom.split_limit();

        // Peel entries off the end into fresh pairs until what is left
        // fits, exactly as littlefs's compaction does.
        while span(0, end) > limit || end as usize >= MAX_IDS {
            let at = split_point(&sizes, end, limit);
            if at == 0 {
                return Err(Error::CommitTooLarge);
            }
            let fresh = self.alloc_pair()?;
            let rev = self.read_rev(fresh[0])?.wrapping_add(1);
            // Every pair peeled so far hangs off this one's tail, so
            // naming the newest keeps all of them reachable for the
            // allocator until the head commit links them in for real.
            self.pending_pair = Some(fresh);
            self.write_range(m, edit, at, end, fresh[1], rev, tail, hard, None)?;
            let fresh = [fresh[1], fresh[0]];
            if let Some(f) = focus
                && f.id >= at
                && f.id < end
            {
                placed = Some(Placed {
                    pair: fresh,
                    id: f.id - at,
                });
                focus = None;
            }
            // The overflow pair becomes the continuation of this directory,
            // which also keeps it threaded on the filesystem-wide list.
            tail = Some(fresh);
            hard = true;
            end = at;
        }

        let rev = m.rev.wrapping_add(1);
        self.write_range(m, edit, 0, end, m.target(), rev, tail, hard, m.gdelta)?;
        // The block just written is now the live half of the pair.
        let head = [m.pair[1], m.pair[0]];
        if let Some(f) = focus
            && f.id < end
        {
            placed = Some(Placed {
                pair: head,
                id: f.id,
            });
        }
        // The scratch holds the block this commit superseded.
        self.cached = None;
        Ok(CommitOut { pair: head, placed })
    }

    /// Write one compaction: logical entries `lo..hi` of `m` with `edit`
    /// applied, into `block`, which is erased first.
    ///
    /// The entries are copied out of the scratch buffer, which this loads
    /// `m` into — allocating a pair to split into traverses the filesystem
    /// through that same buffer, so it cannot be assumed to still be there.
    #[allow(clippy::too_many_arguments)]
    fn write_range(
        &mut self,
        m: &Mdir,
        edit: Edit<'_>,
        lo: u16,
        hi: u16,
        block: u32,
        rev: u32,
        tail: Option<[u32; 2]>,
        hard: bool,
        gdelta: Option<[u8; 12]>,
    ) -> Result<(), Error<D::Error>> {
        if block >= self.geom.block_count {
            return Err(Error::Corrupt("commit target beyond the end of the volume"));
        }
        self.load(m)?;
        self.dev.erase(block).map_err(Error::Io)?;

        // The source block and the staging buffer are different fields, so
        // the commit can read one while programming out of the other.
        let bs = self.geom.block_size as usize;
        let Self {
            dev,
            stage,
            buf,
            geom,
            ..
        } = self;
        let src = &buf[..bs];
        let keys = mdir::attr_keys(src, m);
        let mut c = Commit::new(dev, stage, geom, block, rev)?;
        for i in lo..hi {
            emit_item(&mut c, src, m, &keys, &edit.item(i), i - lo)?;
        }
        if let Some(t) = tail {
            let ty = if hard {
                tag::TYPE_HARDTAIL
            } else {
                tag::TYPE_SOFTTAIL
            };
            c.push_pair(tag::Tag::new(ty, tag::ID_NONE, 8), t)?;
        }
        if let Some(g) = gdelta {
            c.push(
                tag::Tag::new(tag::TYPE_MOVESTATE, tag::ID_NONE, 12),
                &Data::Bytes(&g),
                src,
            )?;
        }
        c.finish(geom.fcrc())?;
        Ok(())
    }
}

/// Largest number of entries this driver writes into one metadata pair.
/// littlefs's own writer caps a pair at `0xff` ids, and the sizing arrays a
/// commit needs are that long.
const MAX_IDS: usize = 0xff;

/// What a commit did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CommitOut {
    /// The pair the head half ended up as, live block first.
    pair: [u32; 2],
    /// Where the entry the edit was about landed.
    placed: Option<Placed>,
}

/// How many leading entries stay in the pair when splitting, mirroring
/// littlefs's "halve until it fits" search. Returns `0` when even a single
/// entry is too large for a block — the caller turns that into an error.
fn split_point(sizes: &[u16; MAX_IDS + 1], end: u16, limit: usize) -> u16 {
    let mut split = 0u16;
    while end - split > 1 {
        let size: usize = sizes[split as usize..end as usize]
            .iter()
            .map(|n| *n as usize)
            .sum();
        if ((end - split) as usize) < MAX_IDS && size <= limit {
            break;
        }
        split += (end - split) / 2;
    }
    split
}

/// Bytes one entry of a commit will take.
///
/// Measured the same way [`emit_item`] writes it — the two have to agree or
/// a commit sized against this would overflow its block.
fn item_size(src: &[u8], m: &Mdir, keys: &[u32; 8], item: &Item<'_>) -> usize {
    let (name_len, data_size, sid) = match item {
        Item::Copy(sid) | Item::CopyWithAttr(sid, _, _) => (
            mdir::name_of(src, m, *sid).map_or(0, |(_, _, len)| len),
            mdir::struct_of(src, m, *sid).map_or(0, |s| mdir::struct_size(&s)),
            Some(*sid),
        ),
        Item::CopyWithData(sid, data) => (
            mdir::name_of(src, m, *sid).map_or(0, |(_, _, len)| len),
            mdir::struct_out_size(data),
            Some(*sid),
        ),
        Item::New { name, data, .. } => (name.len() as u32, mdir::struct_out_size(data), None),
    };
    let mut n = 4 + name_len as usize + data_size;
    if let Some(sid) = sid {
        let edit = match item {
            Item::CopyWithAttr(_, key, value) => Some((*key, *value)),
            _ => None,
        };
        if !mdir::no_attrs(keys) || edit.is_some() {
            for key in 0..=u8::MAX {
                if let Some((k, value)) = edit
                    && k == key
                {
                    if let Some(v) = value {
                        n += 4 + v.len();
                    }
                    continue;
                }
                if mdir::has_key(keys, key)
                    && let Some((_, len)) = mdir::attr_of(src, m, sid, key)
                {
                    n += 4 + len as usize;
                }
            }
        }
    }
    n
}

/// Write one entry into a commit: its name tag, its struct tag, and its
/// user attributes in ascending key order.
fn emit_item<D: FlashDriver>(
    c: &mut Commit<'_, D>,
    src: &[u8],
    m: &Mdir,
    keys: &[u32; 8],
    item: &Item<'_>,
    id: u16,
) -> Result<(), Error<D::Error>> {
    let sid = match item {
        Item::Copy(sid) | Item::CopyWithData(sid, _) | Item::CopyWithAttr(sid, _, _) => {
            let (kind, off, len) = mdir::name_of(src, m, *sid).unwrap_or((0, 0, 0));
            c.push(
                tag::Tag::new(tag::TYPE_NAME | kind as u16, id, len as u16),
                &Data::Run { off, len },
                src,
            )?;
            match item {
                Item::CopyWithData(_, data) => emit_struct(c, src, id, data)?,
                _ => {
                    if let Some(s) = mdir::struct_of(src, m, *sid) {
                        emit_source_struct(c, src, id, &s)?;
                    }
                }
            }
            Some(*sid)
        }
        Item::New { kind, name, data } => {
            c.push(
                tag::Tag::new(tag::TYPE_NAME | *kind as u16, id, name.len() as u16),
                &Data::Bytes(name),
                src,
            )?;
            emit_struct(c, src, id, data)?;
            None
        }
    };

    let Some(sid) = sid else { return Ok(()) };
    let edit = match item {
        Item::CopyWithAttr(_, key, value) => Some((*key, *value)),
        _ => None,
    };
    if mdir::no_attrs(keys) && edit.is_none() {
        return Ok(());
    }
    for key in 0..=u8::MAX {
        if let Some((k, value)) = edit
            && k == key
        {
            if let Some(v) = value {
                c.push(
                    tag::Tag::new(tag::TYPE_USERATTR | key as u16, id, v.len() as u16),
                    &Data::Bytes(v),
                    src,
                )?;
            }
            continue;
        }
        if mdir::has_key(keys, key)
            && let Some((off, len)) = mdir::attr_of(src, m, sid, key)
        {
            c.push(
                tag::Tag::new(tag::TYPE_USERATTR | key as u16, id, len as u16),
                &Data::Run { off, len },
                src,
            )?;
        }
    }
    Ok(())
}

/// Write the struct tag a caller asked for.
fn emit_struct<D: FlashDriver>(
    c: &mut Commit<'_, D>,
    src: &[u8],
    id: u16,
    data: &StructOut<'_>,
) -> Result<(), Error<D::Error>> {
    match data {
        StructOut::Dir(p) => c.push_pair(tag::Tag::new(tag::TYPE_DIRSTRUCT, id, 8), *p),
        StructOut::Ctz { head, size } => {
            c.push_pair(tag::Tag::new(tag::TYPE_CTZSTRUCT, id, 8), [*head, *size])
        }
        StructOut::Inline(d) => c.push(
            tag::Tag::new(tag::TYPE_INLINESTRUCT, id, d.len() as u16),
            d,
            src,
        ),
    }
}

/// Copy a struct tag forward from the source block.
fn emit_source_struct<D: FlashDriver>(
    c: &mut Commit<'_, D>,
    src: &[u8],
    id: u16,
    s: &Struct,
) -> Result<(), Error<D::Error>> {
    match s {
        Struct::Dir(p) => c.push_pair(tag::Tag::new(tag::TYPE_DIRSTRUCT, id, 8), *p),
        Struct::Ctz { head, size } => {
            c.push_pair(tag::Tag::new(tag::TYPE_CTZSTRUCT, id, 8), [*head, *size])
        }
        Struct::Inline { off, len } => c.push(
            tag::Tag::new(tag::TYPE_INLINESTRUCT, id, *len as u16),
            &Data::Run {
                off: *off,
                len: *len,
            },
            src,
        ),
    }
}

// ---------------------------------------------------------------------
// Block allocation
// ---------------------------------------------------------------------

impl<D: FlashDriver, const BLOCK: usize, const PROG: usize> Volume<D, BLOCK, PROG> {
    /// Claim a free block.
    ///
    /// Allocation reads through the scratch buffer — it traverses the
    /// filesystem to find out what is in use — so a caller holding a
    /// metadata pair there must re-[`load`](Self::load) it afterwards.
    #[cfg(feature = "alloc")]
    fn alloc_block(&mut self) -> Result<u32, Error<D::Error>> {
        if self.used.is_none() {
            self.build_used()?;
        }
        let count = self.geom.block_count;
        let start = self.cursor.min(count.saturating_sub(1));
        let used = self.used.as_mut().expect("just built");
        for i in 0..count {
            let b = (start + i) % count;
            let w = &mut used[b as usize / 32];
            let bit = 1u32 << (b % 32);
            if *w & bit == 0 {
                *w |= bit;
                self.cursor = (b + 1) % count;
                return Ok(b);
            }
        }
        Err(Error::NoSpace)
    }

    /// Claim a free block, out of the lookahead window and refilling it by
    /// traversing the filesystem whenever it runs dry — the allocator
    /// littlefs itself uses.
    #[cfg(not(feature = "alloc"))]
    fn alloc_block(&mut self) -> Result<u32, Error<D::Error>> {
        let count = self.geom.block_count;
        let windows = count.div_ceil(LOOKAHEAD_BLOCKS);
        let mut visited = 0u32;
        loop {
            if !self.look_valid {
                self.refill_lookahead()?;
            }
            while self.look_next < LOOKAHEAD_BLOCKS && self.look_start + self.look_next < count {
                let i = self.look_next as usize;
                let taken = self.look[i / 32] & (1 << (i % 32)) != 0;
                let block = self.look_start + self.look_next;
                self.look_next += 1;
                if !taken {
                    self.look[i / 32] |= 1 << (i % 32);
                    return Ok(block);
                }
            }
            // The window is exhausted; move it along and look again.
            self.look_start += LOOKAHEAD_BLOCKS;
            if self.look_start >= count {
                self.look_start = 0;
            }
            self.look_next = 0;
            self.look_valid = false;
            visited += 1;
            if visited > windows {
                return Err(Error::NoSpace);
            }
        }
    }

    /// Claim a metadata pair — two distinct blocks.
    fn alloc_pair(&mut self) -> Result<[u32; 2], Error<D::Error>> {
        let a = self.alloc_block()?;
        match self.alloc_block() {
            Ok(b) => Ok([a, b]),
            Err(e) => {
                self.free_block(a);
                Err(e)
            }
        }
    }

    /// Note that `block` is in use.
    fn mark_used(&mut self, block: u32) {
        #[cfg(feature = "alloc")]
        if let Some(used) = &mut self.used
            && (block as usize / 32) < used.len()
        {
            used[block as usize / 32] |= 1 << (block % 32);
        }
        #[cfg(not(feature = "alloc"))]
        if block >= self.look_start && block - self.look_start < LOOKAHEAD_BLOCKS {
            let i = (block - self.look_start) as usize;
            self.look[i / 32] |= 1 << (i % 32);
        }
    }

    /// Give `block` back.
    ///
    /// Without a heap this does nothing and needs to do nothing: a block is
    /// free exactly when nothing reachable from the superblock points at
    /// it, which is what the next lookahead refill discovers. With the
    /// whole-volume bitmap held in memory, that bitmap has to be told.
    fn free_block(&mut self, block: u32) {
        #[cfg(feature = "alloc")]
        if let Some(used) = &mut self.used
            && (block as usize / 32) < used.len()
        {
            used[block as usize / 32] &= !(1 << (block % 32));
            self.cursor = self.cursor.min(block);
        }
        #[cfg(not(feature = "alloc"))]
        let _ = block;
    }

    /// Rebuild the lookahead window by traversing the filesystem.
    #[cfg(not(feature = "alloc"))]
    fn refill_lookahead(&mut self) -> Result<(), Error<D::Error>> {
        let start = self.look_start;
        let mut bits = [0u32; LOOKAHEAD_WORDS];
        self.traverse(&mut |b| {
            if b >= start && b - start < LOOKAHEAD_BLOCKS {
                let i = (b - start) as usize;
                bits[i / 32] |= 1 << (i % 32);
            }
        })?;
        self.look = bits;
        self.look_next = 0;
        self.look_valid = true;
        Ok(())
    }

    /// Build the whole volume's in-use bitmap.
    #[cfg(feature = "alloc")]
    fn build_used(&mut self) -> Result<(), Error<D::Error>> {
        let words = (self.geom.block_count as usize).div_ceil(32);
        let mut bits = ::alloc::vec::Vec::new();
        if bits.try_reserve_exact(words).is_err() {
            return Err(Error::NoSpace);
        }
        bits.resize(words, 0u32);
        self.traverse(&mut |b| {
            if (b as usize / 32) < bits.len() {
                bits[b as usize / 32] |= 1 << (b % 32);
            }
        })?;
        self.used = Some(bits);
        Ok(())
    }

    /// Call `mark` for every block the filesystem currently occupies: both
    /// halves of every metadata pair on the threaded list, every block of
    /// every file's skip-list, and whatever an operation in flight has
    /// claimed but not yet linked in.
    fn traverse(&mut self, mark: &mut dyn FnMut(u32)) -> Result<(), Error<D::Error>> {
        if let Some((head, size)) = self.pending_ctz {
            self.ctz_traverse(head, size, mark)?;
        }
        // A pair claimed by an operation in flight is not on the threaded
        // list yet, and the pairs an earlier step of that same operation
        // claimed hang off *its* tail, so walking from it reaches all of
        // them. The walk runs into the live list and stops when the hop
        // budget does; marking a block twice costs nothing.
        if let Some(p) = self.pending_pair {
            self.walk_pairs(p, mark)?;
        }
        self.walk_pairs(SUPERBLOCK_PAIR, mark)
    }

    /// Mark every block the metadata pairs from `start` onwards occupy,
    /// following tail pointers, plus the skip-lists their entries name.
    fn walk_pairs(
        &mut self,
        start: [u32; 2],
        mark: &mut dyn FnMut(u32),
    ) -> Result<(), Error<D::Error>> {
        let mut next = Some(start);
        let mut hops = 0u32;
        while let Some(pair) = next {
            let m = self.fetch(pair)?;
            mark(m.pair[0]);
            mark(m.pair[1]);
            for id in 0..m.count {
                let bs = self.bs();
                // A skip-list walk reads blocks of its own, but through the
                // driver rather than the scratch, so the pair is still
                // there for the next id.
                let data = mdir::struct_of(&self.buf[..bs], &m, id);
                if let Some(Struct::Ctz { head, size }) = data {
                    self.ctz_traverse(head, size, mark)?;
                }
            }
            next = m.tail;
            hops += 1;
            if hops > self.geom.block_count {
                return Err(Error::Corrupt("cycle in the metadata-pair list"));
            }
        }
        Ok(())
    }

    /// Blocks the filesystem currently occupies.
    ///
    /// Counted the way littlefs counts them: by traversing every metadata
    /// pair and every file's skip-list. A block reached twice is counted
    /// once, which is why the count goes through a bitmap.
    pub fn used_blocks(&mut self) -> Result<u32, Error<D::Error>> {
        let count = self.geom.block_count;
        Ok(self.count_used()?.min(count))
    }

    #[cfg(feature = "alloc")]
    fn count_used(&mut self) -> Result<u32, Error<D::Error>> {
        if self.used.is_none() {
            self.build_used()?;
        }
        let used = self.used.as_ref().expect("just built");
        Ok(used.iter().map(|w| w.count_ones()).sum())
    }

    /// One window at a time, since there is nowhere to hold a bitmap of the
    /// whole volume.
    #[cfg(not(feature = "alloc"))]
    fn count_used(&mut self) -> Result<u32, Error<D::Error>> {
        let count = self.geom.block_count;
        let mut total = 0u32;
        let mut start = 0u32;
        while start < count {
            let mut bits = [0u32; LOOKAHEAD_WORDS];
            self.traverse(&mut |b| {
                if b >= start && b - start < LOOKAHEAD_BLOCKS {
                    let i = (b - start) as usize;
                    bits[i / 32] |= 1 << (i % 32);
                }
            })?;
            total += bits.iter().map(|w| w.count_ones()).sum::<u32>();
            start += LOOKAHEAD_BLOCKS;
        }
        Ok(total)
    }

    /// Capacity figures in `statfs` shape: erase blocks as the allocation
    /// unit, free blocks from [`Self::free_blocks`] (so a traversal, or the
    /// in-use bitmap with `alloc`), no inodes, and the superblock's
    /// `name_max`.
    pub fn statfs(&mut self) -> Result<crate::fs::StatFs, Error<D::Error>> {
        let free = self.free_blocks()? as u64;
        Ok(crate::fs::StatFs {
            block_size: self.geom.block_size,
            blocks: self.geom.block_count as u64,
            blocks_free: free,
            blocks_avail: free,
            inodes: 0,
            inodes_free: 0,
            name_max: self.geom.name_max,
        })
    }

    /// Blocks the filesystem has left.
    pub fn free_blocks(&mut self) -> Result<u32, Error<D::Error>> {
        let used = self.used_blocks()?;
        Ok(self.geom.block_count.saturating_sub(used))
    }
}

// ---------------------------------------------------------------------
// CTZ skip-lists
// ---------------------------------------------------------------------

/// Where a file's committed bytes live.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Contents {
    /// Nothing yet.
    Empty,
    /// Inline in a metadata block, at `off` for `len` bytes. Only valid
    /// until that pair is committed again.
    Inline { block: u32, off: u32, len: u32 },
    /// A CTZ skip-list.
    Ctz { head: u32, size: u32 },
}

impl Contents {
    fn len(&self) -> u32 {
        match self {
            Contents::Empty => 0,
            Contents::Inline { len, .. } => *len,
            Contents::Ctz { size, .. } => *size,
        }
    }
}

/// What the bytes of a file being written are made of: the caller's new
/// bytes where they land, the old contents elsewhere, and zeroes for any
/// gap a write past the end left behind.
pub(super) struct Fill<'a> {
    pub old: Contents,
    pub at: u32,
    pub new: &'a [u8],
}

impl<D: FlashDriver, const BLOCK: usize, const PROG: usize> Volume<D, BLOCK, PROG> {
    /// Read one skip pointer out of a block.
    fn read_pointer(&mut self, block: u32, slot: u32) -> Result<u32, Error<D::Error>> {
        if block >= self.geom.block_count {
            return Err(Error::Corrupt("file block beyond the end of the volume"));
        }
        let mut b = [0u8; 4];
        self.dev.read(block, 4 * slot, &mut b).map_err(Error::Io)?;
        Ok(u32::from_le_bytes(b))
    }

    /// Walk the skip-list to the block holding file offset `pos`, returning
    /// it and the byte offset to read from inside it.
    fn ctz_find(&mut self, head: u32, size: u32, pos: u32) -> Result<(u32, u32), Error<D::Error>> {
        if size == 0 {
            return Err(Error::InvalidOffset);
        }
        let bs = self.geom.block_size;
        let (mut current, _) = index::index_of(bs, size - 1);
        let (target, off) = index::index_of(bs, pos);
        let mut head = head;
        // `current` strictly decreases, so a corrupt pointer cannot spin
        // here.
        while current > target {
            let (slot, step) = index::hop(current, target);
            head = self.read_pointer(head, slot)?;
            current -= step;
        }
        Ok((head, off))
    }

    /// Call `mark` once for every block of a file, from the head backwards.
    fn ctz_traverse(
        &mut self,
        head: u32,
        size: u32,
        mark: &mut dyn FnMut(u32),
    ) -> Result<(), Error<D::Error>> {
        if size == 0 {
            return Ok(());
        }
        let (mut index, _) = index::index_of(self.geom.block_size, size - 1);
        let mut head = head;
        loop {
            mark(head);
            if index == 0 {
                return Ok(());
            }
            // An odd index has its predecessor as its only "new" pointer; an
            // even one lets us pick up two blocks per read.
            let count = 2 - (index & 1);
            let mut heads = [0u32; 2];
            for (i, h) in heads.iter_mut().enumerate().take(count as usize) {
                *h = self.read_pointer(head, i as u32)?;
            }
            for h in heads.iter().take(count as usize - 1) {
                mark(*h);
            }
            head = heads[count as usize - 1];
            // `count` is 1 for an odd index and 2 for an even one, so it
            // never exceeds `index` and the walk always terminates at 0.
            index -= count;
        }
    }

    /// Read up to `buf.len()` bytes of `src` at file offset `pos`.
    ///
    /// Returns 0 at end of file; a short read means the next call continues
    /// from the next block.
    fn read_contents(
        &mut self,
        src: &Contents,
        pos: u32,
        buf: &mut [u8],
    ) -> Result<usize, Error<D::Error>> {
        if pos >= src.len() || buf.is_empty() {
            return Ok(0);
        }
        match src {
            Contents::Empty => Ok(0),
            Contents::Inline { block, off, len } => {
                let n = buf.len().min((len - pos) as usize);
                self.dev
                    .read(*block, off + pos, &mut buf[..n])
                    .map_err(Error::Io)?;
                Ok(n)
            }
            Contents::Ctz { head, size } => {
                let (block, off) = self.ctz_find(*head, *size, pos)?;
                // A read stops at the end of the block it started in — the
                // next call resumes in the next one.
                let in_block = (self.geom.block_size - off) as usize;
                let n = buf.len().min(in_block).min((size - pos) as usize);
                if block >= self.geom.block_count {
                    return Err(Error::Corrupt("file block beyond the end of the volume"));
                }
                self.dev
                    .read(block, off, &mut buf[..n])
                    .map_err(Error::Io)?;
                Ok(n)
            }
        }
    }

    /// Fill `out` with what the file looks like from offset `off` on.
    fn fill_from(
        &mut self,
        fill: &Fill<'_>,
        off: u32,
        out: &mut [u8],
    ) -> Result<(), Error<D::Error>> {
        let new_end = fill.at + fill.new.len() as u32;
        let old_size = fill.old.len();
        let mut done = 0usize;
        while done < out.len() {
            let o = off + done as u32;
            let want = out.len() - done;
            if o >= fill.at && o < new_end {
                // The caller's own bytes.
                let s = (o - fill.at) as usize;
                let n = want.min(fill.new.len() - s);
                out[done..done + n].copy_from_slice(&fill.new[s..s + n]);
                done += n;
            } else if o < old_size && (o >= new_end || o < fill.at) {
                // Old contents, bounded so the read never runs into the
                // region the new bytes cover.
                let limit = if o < fill.at {
                    fill.at.min(old_size) - o
                } else {
                    old_size - o
                };
                let cap = want.min(limit as usize);
                let n = self.read_contents(&fill.old, o, &mut out[done..done + cap])?;
                if n == 0 {
                    return Err(Error::Corrupt("short read while rewriting a file"));
                }
                done += n;
            } else {
                // A gap left by a write past the end of the file.
                let limit = if o < fill.at {
                    (fill.at - o) as usize
                } else {
                    want
                };
                let n = want.min(limit);
                out[done..done + n].fill(0);
                done += n;
            }
        }
        Ok(())
    }

    /// Write file data as CTZ blocks.
    ///
    /// Blocks are emitted starting at `index`, whose predecessor block is
    /// `prev` (`None` only when `index` is 0) and whose first byte is at file
    /// offset `file_off`. Returns the new head — the last block written — or
    /// `prev` when there is nothing to write.
    ///
    /// Each block is assembled in the scratch buffer, so whatever metadata
    /// pair was there is gone by the time this returns.
    fn write_ctz(
        &mut self,
        index: u32,
        prev: Option<u32>,
        file_off: u32,
        fill: &Fill<'_>,
        len: u32,
    ) -> Result<Option<u32>, Error<D::Error>> {
        // Blocks written here are not reachable from the superblock until
        // the metadata commit that names the head, so the allocator is told
        // to count them as taken meanwhile — and told again on the way out,
        // whether or not the write got there.
        let saved = self.pending_ctz;
        let out = self.write_ctz_blocks(index, prev, file_off, fill, len);
        self.pending_ctz = saved;
        out
    }

    fn write_ctz_blocks(
        &mut self,
        mut index: u32,
        mut prev: Option<u32>,
        mut file_off: u32,
        fill: &Fill<'_>,
        len: u32,
    ) -> Result<Option<u32>, Error<D::Error>> {
        let bs = self.geom.block_size;
        let mut remaining = len;
        while remaining > 0 {
            // Allocated before the image is assembled: allocation may read
            // through the very buffer the image goes in.
            let block = self.alloc_block()?;
            let skips = index::pointers(index);
            let cap = index::payload(bs, index);
            let n = cap.min(remaining);
            let start = 4 * skips;

            // The skip pointers: the first is our predecessor, and each
            // subsequent one is found by following the previous pointer's
            // own skip list.
            let mut pointers = [0u32; 32];
            if skips > 0 {
                let mut p = prev.ok_or(Error::Corrupt("skip-list continuation without a head"))?;
                for j in 0..skips {
                    pointers[j as usize] = p;
                    if j + 1 < skips {
                        p = self.read_pointer(p, j)?;
                    }
                }
            }

            self.cached = None;
            {
                let image = &mut self.buf[..bs as usize];
                image.fill(0xff);
                for (j, p) in pointers.iter().take(skips as usize).enumerate() {
                    image[j * 4..j * 4 + 4].copy_from_slice(&p.to_le_bytes());
                }
            }
            self.fill_into_scratch(fill, file_off, start, n)?;

            self.dev.erase(block).map_err(Error::Io)?;
            // Only the bytes the block actually holds are programmed; the
            // rest stays erased.
            let prog = self.geom.prog_size.max(1);
            let end = (start + n).next_multiple_of(prog).min(bs) as usize;
            self.dev
                .prog(block, 0, &self.buf[..end])
                .map_err(Error::Io)?;

            prev = Some(block);
            self.pending_ctz = Some((block, file_off + n));
            index += 1;
            file_off += n;
            remaining -= n;
        }
        Ok(prev)
    }

    /// `fill_from` into the scratch buffer — split out so the borrow of the
    /// buffer does not overlap the driver's.
    fn fill_into_scratch(
        &mut self,
        fill: &Fill<'_>,
        off: u32,
        at: u32,
        len: u32,
    ) -> Result<(), Error<D::Error>> {
        let mut done = 0u32;
        // Copied a chunk at a time: `fill_from` needs the driver, which is
        // the same `&mut self` the buffer hangs off.
        let mut tmp = [0u8; 128];
        while done < len {
            let n = (len - done).min(tmp.len() as u32) as usize;
            self.fill_from(fill, off + done, &mut tmp[..n])?;
            let dst = (at + done) as usize;
            self.buf[dst..dst + n].copy_from_slice(&tmp[..n]);
            done += n as u32;
        }
        Ok(())
    }

    /// Give back the blocks of a file's skip-list from index `from` on.
    fn release_ctz(&mut self, head: u32, size: u32, from: u32) -> Result<(), Error<D::Error>> {
        #[cfg(feature = "alloc")]
        {
            if self.used.is_none() {
                // Nothing is being tracked, so nothing needs releasing: the
                // next traversal will see the truth.
                return Ok(());
            }
            if size == 0 {
                return Ok(());
            }
            let (mut index, _) = index::index_of(self.geom.block_size, size - 1);
            // `ctz_traverse` walks the list head-first, i.e. from the
            // highest index down, one index per callback.
            let mut doomed = ::alloc::vec::Vec::new();
            self.ctz_traverse(head, size, &mut |b| {
                if index >= from {
                    doomed.push(b);
                }
                index = index.saturating_sub(1);
            })?;
            for b in doomed {
                self.free_block(b);
            }
        }
        #[cfg(not(feature = "alloc"))]
        let _ = (head, size, from);
        Ok(())
    }
}
