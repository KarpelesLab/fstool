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
//! fstool = { version = "0.4", default-features = false, features = ["fat"] }
//! ```
//!
//! which compiles the crate as `#![no_std]` with nothing that can
//! allocate. `alloc` is additive from there: a build that has it keeps
//! everything here and gains the hosted drivers beside it, so the same
//! code is compiled into every configuration.
//!
//! Today this is [`crate::noalloc::fat`] — FAT12/FAT16/FAT32, read and
//! write.

#[cfg(feature = "fat")]
pub mod fat;
