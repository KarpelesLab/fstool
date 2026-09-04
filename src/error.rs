//! Error type and `Result` alias for the crate.
//!
//! All public APIs return `fstool::Result<T>` = `Result<T, fstool::Error>`. The
//! variants are intentionally small at this stage; further variants will be
//! added as later layers (partition tables, filesystems, spec parsing) come
//! online.

use std::io;

/// Crate-wide error type.
///
/// The `Display` and `Error` impls below are written out rather than
/// derived: the enum is small and stable, and hand-writing them is what
/// lets the crate carry no proc-macro dependency of its own. Keep a new
/// variant's arm in `Display` — the match is exhaustive, so the compiler
/// will say so if you forget.
#[derive(Debug)]
pub enum Error {
    /// Underlying I/O failure (file backend, host file source, etc.).
    Io(io::Error),

    /// A block-device operation referenced a byte range that lies (partly or
    /// wholly) outside the device's logical extent. Includes slice violations.
    OutOfBounds { offset: u64, len: u64, size: u64 },

    /// On-disk structure failed validation (bad magic, bad checksum, etc.).
    InvalidImage(String),

    /// The requested feature exists in the format but is not implemented in
    /// this build of fstool. Used for clean "FAT32 not in v1" type messages.
    Unsupported(String),

    /// A user-supplied value was malformed or contradictory (bad spec, etc.).
    InvalidArgument(String),

    /// The operation tried to modify a **streaming** filesystem — one
    /// whose writer can't seek backward once bytes have been emitted.
    /// Tar today; any future stream-of-records format that lands in
    /// fstool. Distinct from [`Error::Immutable`] so callers can tell
    /// "the writer fundamentally can't go back" apart from "the
    /// on-disk layout was never designed for in-place edits."
    Streaming {
        /// The filesystem kind that refused (today: `"tar"`).
        kind: &'static str,
        /// Short verb describing the attempted op (`"add"`, `"rm"`, …).
        /// Free-form; not a stable enum.
        op: &'static str,
    },

    /// The operation tried to modify a **write-once** filesystem whose
    /// on-disk layout has no in-place mutation hooks (no free-block
    /// tracking, no journal). ISO 9660 and SquashFS today. The
    /// writer can seek, but re-opening the image as writable isn't
    /// part of the format's design — modifications go through
    /// `fstool repack` to rebuild the image from scratch.
    Immutable {
        /// The filesystem kind that refused (today: `"iso9660"`,
        /// `"squashfs"`).
        kind: &'static str,
        /// Short verb describing the attempted op.
        op: &'static str,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io: {e}"),
            Error::OutOfBounds { offset, len, size } => write!(
                f,
                "out of bounds: offset {offset} len {len} exceeds device size {size}"
            ),
            Error::InvalidImage(m) => write!(f, "invalid image: {m}"),
            Error::Unsupported(m) => write!(f, "unsupported feature: {m}"),
            Error::InvalidArgument(m) => write!(f, "invalid argument: {m}"),
            Error::Streaming { kind, op } => write!(
                f,
                "{op}: {kind} is a streaming format — use `fstool repack` to produce a new one"
            ),
            Error::Immutable { kind, op } => write!(
                f,
                "{op}: {kind} is a write-once format — use `fstool repack` to rebuild it"
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

/// `?` on an `io::Error` yields [`Error::Io`] — the conversion the rest
/// of the crate leans on constantly.
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;
