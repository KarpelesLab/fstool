//! fstool — build disk images and filesystems from a directory tree and TOML spec.
//!
//! The crate is organised as a stack of three trait-based layers:
//!
//! - [`block`] — `BlockDevice`: raw seekable byte storage. Backends include
//!   on-disk files, in-memory buffers (for tests), sub-range slices used to
//!   give each partition an isolated view, and the disk-image *containers*:
//!   qcow2 (with backing files and encryption), LUKS1/LUKS2 volumes, and
//!   read-only DMG.
//! - [`part`] — `PartitionTable`: MBR, GPT and APM.
//! - [`fs`] — `Filesystem`: one trait over every backend — ext2/3/4,
//!   FAT12/16/32, exFAT, XFS, HFS+, HFS, AFFS, APFS, NTFS, F2FS, littlefs,
//!   SquashFS, ISO 9660, GRF, tar and the archive formats.
//!
//! High-level entry points: [`spec::build`] builds an image from a TOML
//! spec, [`inspect`] opens and walks an existing one, [`repack`] converts
//! between formats, and [`memconv`] / [`memedit`] do both in memory.
//!
//! Beside that stack sits [`noalloc`], for targets with no heap: drivers
//! that allocate nothing and depend on none of the layers above. Today
//! that is [`noalloc::fat`], a second FAT12/16/32 implementation that
//! reads and writes a card through one sector of scratch RAM.

#![cfg_attr(not(feature = "std"), no_std)]

// The `alloc` crate is the floor for the hosted API: every layer hands
// back `Vec`s and `String`s, so a consumer of it brings a global
// allocator (as it already does for `alloc` itself). With `std` on, this
// is just `std`'s own `alloc` under another name.
//
// With the `alloc` feature off, none of that is compiled and the crate
// links on a target with no global allocator; what remains is
// [`noalloc`]. Host unit tests always have `alloc` available, so test
// code can still build fixtures with a `Vec` while the code under test
// cannot.
#[cfg(any(feature = "alloc", test))]
extern crate alloc;

// The unit tests run on a host, and reach for `std` (temp files,
// `println!`) even when the crate under test is the `no_std` core.
#[cfg(test)]
#[macro_use]
extern crate std;

// An empty crate is never what the caller meant.
#[cfg(not(any(feature = "alloc", feature = "fat-noalloc")))]
compile_error!(
    "fstool: enable at least one feature — `std` (or `default-features = false` \
     with a backend such as `fat`) for the library, or `fat-noalloc` for the \
     allocator-free FAT driver"
);

#[cfg(all(
    feature = "std",
    not(any(
        feature = "affs",
        feature = "apfs",
        feature = "archive",
        feature = "exfat",
        feature = "ext",
        feature = "f2fs",
        feature = "fat",
        feature = "grf",
        feature = "hfs",
        feature = "hfs-plus",
        feature = "iso9660",
        feature = "littlefs",
        feature = "ntfs",
        feature = "ramfs",
        feature = "squashfs",
        feature = "tar",
        feature = "xfs",
    ))
))]
compile_error!(
    "fstool: the `std` build needs at least one filesystem feature \
     (`fat`, `ext`, … or `filesystems`); `inspect` has nothing to dispatch to otherwise"
);

#[cfg(feature = "std")]
pub mod analyze;
#[cfg(feature = "std")]
pub mod base64;
#[cfg(feature = "alloc")]
pub mod block;
#[cfg(feature = "std")]
pub mod compression;
#[cfg(feature = "ext")]
pub mod concurrent;
pub mod crc;
#[cfg(feature = "alloc")]
pub mod error;
#[cfg(feature = "alloc")]
pub mod format_opts;
#[cfg(feature = "alloc")]
pub mod fs;
#[cfg(feature = "fuse")]
pub mod fuse_adapter;
#[cfg(feature = "std")]
pub mod inspect;
#[cfg(feature = "alloc")]
pub mod io;
#[cfg(feature = "std")]
pub mod macroman;
#[cfg(feature = "std")]
pub mod memconv;
#[cfg(feature = "std")]
pub mod memedit;
#[cfg(feature = "std")]
pub mod merge;
#[cfg(feature = "alloc")]
pub mod part;
#[cfg(feature = "alloc")]
pub mod path;
#[cfg(feature = "std")]
pub mod path_style;
#[cfg(feature = "std")]
pub mod repack;
#[cfg(feature = "std")]
pub mod resfork;
#[cfg(feature = "std")]
pub mod spec;
/// WebAssembly bindings (browser UI). Only compiled for `wasm32` with the
/// `wasm` feature; see `src/wasm.rs`.
#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
pub mod wasm;

/// `log::warn!` / `log::debug!` when the `log` feature is on, and
/// nothing at all when it is off.
///
/// Every call site reports something the code *recovered* from — a
/// dropped handle, an odd field — never a failure, so compiling them
/// away costs no diagnosis of anything fatal. The arguments are still
/// type-checked in both configurations: the no-op arm feeds them to
/// `format_args!` and discards it, so a stale `{}` placeholder is a
/// compile error either way rather than only in the logging build.
#[macro_export]
#[doc(hidden)]
macro_rules! fstool_log {
    ($level:ident, $($arg:tt)*) => {{
        #[cfg(feature = "log")]
        ::log::$level!($($arg)*);
        #[cfg(not(feature = "log"))]
        {
            let _ = ::core::format_args!($($arg)*);
        }
    }};
}

/// Allocator-free backends: everything here works with no heap at all,
/// on a target with no global allocator. See [`noalloc::fat`].
#[cfg(feature = "fat-noalloc")]
pub mod noalloc;

#[cfg(feature = "alloc")]
pub use error::{Error, Result};
