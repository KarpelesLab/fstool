//! exFAT — Microsoft's flash-friendly FAT successor, and what SDXC cards
//! ship formatted with.
//!
//! ## High-level layout
//!
//! ```text
//!   sector 0          Main Boot Sector (this is what `probe` looks at)
//!   sector 1..=8      Extended Boot Sectors
//!   sector 9          OEM Parameters
//!   sector 10         Reserved
//!   sector 11         Main Boot Checksum
//!   sector 12..=23    Backup of sectors 0..=11
//!   FatOffset         First FAT — 32-bit entries, one per cluster
//!   ClusterHeapOffset First data cluster (cluster 2)
//! ```
//!
//! Three things make exFAT its own filesystem rather than FAT32 with wider
//! entries, and all three shape the code below:
//!
//! * **The allocation bitmap is the authority on free space**, not the FAT.
//!   A file may be marked `NoFatChain`, meaning its clusters are contiguous
//!   and its FAT entries are never written — so a FAT-only scan would hand
//!   live data out again.
//! * **Names are UTF-16 and compared case-insensitively through the
//!   volume's own up-case table**, which is stored on disk as a
//!   (usually run-length compressed) array of code units.
//! * **A directory entry is a *set*** — a file entry, a stream extension,
//!   and one name entry per 15 code units — protected by a checksum over
//!   the whole set, so changing any field means recomputing it.
//!
//! ## One backend, two halves
//!
//! The feature that separates them only ever *adds*:
//!
//! * **The driver** — [`Volume`], [`File`], [`Dir`] and the
//!   [`SectorDriver`](crate::device::SectorDriver) you implement over your
//!   card. It allocates nothing:
//!   one sector of scratch RAM, the FAT and the allocation bitmap read a
//!   sector at a time from the card, and the up-case table consulted on
//!   disk rather than held in memory. `default-features = false, features =
//!   ["exfat"]` compiles the crate down to this, and it links on a target
//!   with no `#[global_allocator]`. It is the same trait
//!   [`fat`](crate::fs::fat) uses, so one implementation over your SD
//!   driver serves both filesystems.
//! * **The hosted surface** — [`Exfat`] and friends, compiled when `alloc`
//!   is on (so, in every `std` build). It implements the crate's
//!   [`Filesystem`](crate::fs::Filesystem) trait, formats volumes and
//!   builds images, which is what `inspect`, `repack`, the spec engine and
//!   the CLI dispatch through.
//!
//! `alloc` also makes the driver *faster* without changing a line of its
//! API: the up-case table is decoded into memory on first use instead of
//! being walked on disk for every non-ASCII comparison (see
//! [`Volume::upcase_cache_bytes`]). The same calls, the same answers — just
//! far fewer reads.
//!
//! See the [`Volume`] docs for the driver's API and its limits, and
//! [`Exfat`] for the hosted one's.

// The on-disk vocabulary both halves speak: the boot sector's fields, the
// directory-entry types, the checksums and the FAT sentinels. It allocates
// nothing, so it is compiled in every configuration.
pub(crate) mod layout;

mod volume;

pub use volume::{
    Dir, DirEntry, DirIter, Error, File, Geometry, MAX_NAME_LEN, Metadata, Timestamp, Volume,
};

// ---------------------------------------------------------------------
// The hosted half. Everything below needs a heap.
// ---------------------------------------------------------------------

#[cfg(feature = "alloc")]
mod hosted;

#[cfg(feature = "alloc")]
pub use hosted::*;
