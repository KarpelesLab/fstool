//! Filesystem layer.
//!
//! Two things live here. The [`Filesystem`] trait and the backends that
//! implement it are the hosted surface: they hand back owned collections
//! and so need `alloc`, which every build that has `std` does.
//!
//! [`fat`] is the exception, and the shape the rest is headed for: its
//! driver needs no allocator at all, and `alloc` only *adds* to it —
//! the hosted [`Filesystem`] implementation, and an in-memory allocation
//! table that makes the same API faster. Enabling a feature never changes
//! the shape of what you call.

// The hosted trait surface: `Filesystem`, `FileMeta`, `DirEntry`, … .
#[cfg(feature = "alloc")]
mod api;
#[cfg(feature = "alloc")]
pub use api::*;

#[cfg(all(feature = "alloc", feature = "affs"))]
pub mod affs;
#[cfg(all(feature = "alloc", feature = "apfs"))]
pub mod apfs;
#[cfg(all(feature = "alloc", feature = "archive"))]
pub mod archive;
#[cfg(feature = "alloc")]
pub mod devnum;
#[cfg(feature = "alloc")]
pub(crate) mod dir_batch;
// Another backend that works with or without a heap.
#[cfg(feature = "exfat")]
pub mod exfat;
#[cfg(all(feature = "alloc", feature = "ext"))]
pub mod ext;
#[cfg(all(feature = "alloc", feature = "f2fs"))]
pub mod f2fs;
// One of the two backends that work with or without a heap.
#[cfg(feature = "fat")]
pub mod fat;
#[cfg(all(feature = "alloc", feature = "grf"))]
pub mod grf;
#[cfg(all(feature = "alloc", feature = "hfs"))]
pub mod hfs;
#[cfg(all(feature = "alloc", feature = "hfs-plus"))]
pub mod hfs_plus;
#[cfg(all(feature = "alloc", feature = "iso9660"))]
pub mod iso9660;
// The other backend that works with or without a heap.
#[cfg(feature = "littlefs")]
pub mod littlefs;
#[cfg(all(feature = "alloc", feature = "ntfs"))]
pub mod ntfs;
#[cfg(all(feature = "alloc", feature = "ramfs"))]
pub mod ramfs;
#[cfg(all(feature = "alloc", feature = "std"))]
pub mod rootdevs;
#[cfg(all(feature = "alloc", feature = "squashfs"))]
pub mod squashfs;
#[cfg(all(feature = "alloc", feature = "tar"))]
pub mod tar;
#[cfg(feature = "alloc")]
pub mod xattr;
#[cfg(all(feature = "alloc", feature = "xfs"))]
pub mod xfs;
