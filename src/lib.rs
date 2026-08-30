//! fstool — build disk images and filesystems from a directory tree and TOML spec.
//!
//! The crate is organised as a stack of three trait-based layers:
//!
//! - [`block`] — `BlockDevice`: raw seekable byte storage. Backends include
//!   on-disk files, in-memory buffers (for tests), and sub-range slices used to
//!   give each partition an isolated view.
//! - [`part`] — `PartitionTable`: MBR, GPT and APM.
//! - [`fs`] — `Filesystem`: one trait over every backend — ext2/3/4,
//!   FAT12/16/32, exFAT, XFS, HFS+, HFS, AFFS, APFS, NTFS, F2FS, littlefs,
//!   SquashFS, ISO 9660, GRF, tar and the archive formats.
//!
//! High-level entry points: [`spec::build`] builds an image from a TOML
//! spec, [`inspect`] opens and walks an existing one, [`repack`] converts
//! between formats, and [`memconv`] / [`memedit`] do both in memory.

pub mod analyze;
pub mod base64;
pub mod block;
pub mod compression;
pub mod concurrent;
pub mod error;
pub mod format_opts;
pub mod fs;
#[cfg(feature = "fuse")]
pub mod fuse_adapter;
pub mod inspect;
pub mod macroman;
pub mod memconv;
pub mod memedit;
pub mod merge;
pub mod part;
pub mod path_style;
pub mod repack;
pub mod resfork;
pub mod spec;
/// WebAssembly bindings (browser UI). Only compiled for `wasm32` with the
/// `wasm` feature; see `src/wasm.rs`.
#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
pub mod wasm;

pub use error::{Error, Result};
