//! littlefs — the little fail-safe filesystem used on microcontroller
//! flash (`lfs2`, disk versions 2.0 and 2.1).
//!
//! ## On-disk format (little-endian, except tags)
//!
//! littlefs has no fixed superblock region, no allocation table and no inode
//! table. Everything is built from two structures:
//!
//! * **Metadata pairs** — two blocks holding a revision count and an
//!   append-only log of commits; the block with the newer revision count that
//!   ends in a valid CRC is the live one. Each commit is a run of 32-bit
//!   *tags* (the `tag` submodule) and their data. A directory is a linked
//!   list of metadata pairs; the pair at blocks `{0, 1}` holds the superblock
//!   entry (the magic `"littlefs"` at offset 8) and doubles as the root
//!   directory. Every pair in the volume is also threaded onto one list
//!   through *tail* pointers, which is what makes a full traversal — and
//!   therefore block allocation — possible without an on-disk free map.
//! * **CTZ skip-lists** — file data too large to inline in a metadata block
//!   (the `index` submodule is their arithmetic). Files smaller than
//!   `inline_max` live directly in their directory's metadata instead.
//!
//! ## One backend, two halves
//!
//! The feature that separates them only ever *adds*:
//!
//! * **The driver** — [`Volume`], [`File`], [`Dir`] and the
//!   [`FlashDriver`](crate::device::FlashDriver) you implement over your
//!   flash. It allocates nothing: one block of
//!   scratch RAM, one staging buffer the size of a program page, a fixed
//!   lookahead window for allocation, and no other state. `default-features
//!   = false, features = ["littlefs"]` compiles the crate down to this, and
//!   it links on a target with no `#[global_allocator]`.
//! * **The hosted surface** — [`LittleFs`] and friends, compiled when
//!   `alloc` is on (so, in every `std` build). It implements the crate's
//!   [`Filesystem`](crate::fs::Filesystem) trait, formats volumes and builds
//!   images, which is what `inspect`, `repack`, the spec engine and the CLI
//!   dispatch through.
//!
//! `alloc` also makes the driver *faster* without changing a line of its
//! API: the block allocator keeps an exact in-use bitmap for the whole
//! volume instead of re-traversing the filesystem every time its lookahead
//! window runs dry (see [`Volume::alloc_cache_bytes`]). The same calls, the
//! same results — just far fewer reads.
//!
//! See the [`Volume`] docs for the driver's API and its limits, and
//! [`LittleFs`] for the hosted one's.

/// Disk version 2.0 — understood by every littlefs v2 release. Images
/// pinned to it carry no forward-CRC tags, which releases older than
/// lfs2.1 would mistake for a commit CRC.
pub const DISK_VERSION_2_0: u32 = 0x0002_0000;
/// Disk version 2.1 — the current on-disk version, with forward-CRC tags.
pub const DISK_VERSION_2_1: u32 = 0x0002_0001;

/// The metadata pair every littlefs volume is rooted at.
pub(crate) const SUPERBLOCK_PAIR: [u32; 2] = [0, 1];
/// Magic string carried by the superblock's name tag.
pub(crate) const MAGIC: &[u8; 8] = b"littlefs";
/// Largest value littlefs allows for `file_max`.
pub(crate) const FILE_MAX: u32 = 0x7fff_ffff;

// The two pieces of the format both halves speak. Neither allocates, so
// both are compiled in every configuration.
pub(crate) mod index;
pub(crate) mod tag;

mod volume;

pub use volume::{
    Dir, DirEntry, DirIter, Error, File, FormatOpts, Geometry, LOOKAHEAD_BLOCKS, MIN_BLOCK_SIZE,
    Metadata, Volume,
};

// ---------------------------------------------------------------------
// The hosted half. Everything below needs a heap.
// ---------------------------------------------------------------------

#[cfg(feature = "alloc")]
mod hosted;

#[cfg(feature = "alloc")]
pub use hosted::*;
