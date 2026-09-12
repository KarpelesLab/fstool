//! FAT12 / FAT16 / FAT32.
//!
//! One backend, two halves, and the feature that separates them only ever
//! adds:
//!
//! * **The driver** — [`Volume`], [`File`], [`Dir`] and the
//!   [`SectorDriver`] you implement over your storage. It allocates
//!   nothing: every buffer is a fixed array or comes from the caller, and
//!   the allocation table is read a sector at a time from the device.
//!   `default-features = false, features = ["fat"]` compiles the crate
//!   down to this, and it links on a target with no `#[global_allocator]`.
//! * **The hosted surface** — [`Fat32`] and friends, compiled when `alloc`
//!   is on (so, in every `std` build). It implements the crate's
//!   [`Filesystem`](crate::fs::Filesystem) trait, formats volumes and
//!   builds images, which is what `inspect`, `repack`, the spec engine and
//!   the CLI dispatch through.
//!
//! `alloc` also makes the driver *faster* without changing a line of its
//! API: [`Volume`] keeps the allocation table in memory instead of
//! re-reading a sector per lookup (see [`Volume::fat_cache_bytes`]). The
//! same calls, the same types, the same results — just fewer transfers.
//!
//! See the [`Volume`] docs for the driver's API and its limits.

mod volume;

// `Error` here is the driver's own — generic over your `SectorDriver`'s
// failure, and allocating nothing. The hosted half returns the crate's
// `Error` instead, and exports no type of that name, so there is no
// ambiguity inside this module.
pub use volume::{
    Attributes, Dir, DirEntry, DirIter, Error, FatKind, File, Geometry, MAX_FILE_LEN,
    MAX_SECTOR_SIZE, MIN_SECTOR_SIZE, MbrPartition, Metadata, SectorDriver, Timestamp, Volume,
};

// ---------------------------------------------------------------------
// The hosted half. Everything below needs a heap.
// ---------------------------------------------------------------------

#[cfg(feature = "alloc")]
mod hosted;

// `hosted` carries the submodules with it, so the paths callers have
// always used — `fs::fat::table`, `fs::fat::dir`, … — still resolve.
#[cfg(feature = "alloc")]
pub use hosted::size_plan::FatSizePlan;
#[cfg(feature = "alloc")]
pub use hosted::*;
