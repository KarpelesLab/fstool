//! Backends that need no allocator.
//!
//! Everything under this module is written to run on a target with no heap
//! and no `#[global_allocator]`: no `Vec`, no `String`, no `Box`, and no
//! dependency on the crate's hosted layers (which hand back owned
//! collections throughout and so require `alloc`).
//!
//! Build it with
//!
//! ```toml
//! fstool = { version = "0.4", default-features = false, features = ["fat-noalloc"] }
//! ```
//!
//! which compiles the crate as `#![no_std]` with nothing that can
//! allocate. The same code is also compiled into hosted builds, where it
//! sits beside the allocator-backed drivers.
//!
//! Today this is [`crate::noalloc::fat`] — FAT12/FAT16/FAT32, read and
//! write.

#[cfg(feature = "fat-noalloc")]
pub mod fat;
