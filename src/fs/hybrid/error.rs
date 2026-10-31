//! Typed errors of the hybrid planner and writer.

use std::fmt;

use super::view::ViewId;

/// What went wrong planning, writing or verifying a hybrid image.
///
/// Layout problems — overlapping regions, regions past the end of the
/// image, a view that asks for a sector another view owns — each have a
/// variant of their own, so a caller can tell a bad request from an I/O
/// failure. Every variant converts into [`crate::Error`].
#[derive(Debug)]
#[non_exhaustive]
pub enum HybridError {
    /// No view is enabled: there is nothing to advertise.
    NoViews,
    /// An option is malformed or contradictory.
    InvalidOption(String),
    /// A path named in the options (blessed folder, boot image, Finder
    /// info target, …) is not in the source tree, or not visible in the
    /// view that needs it.
    UnknownPath {
        /// The option naming it.
        option: &'static str,
        /// The path as given.
        path: String,
    },
    /// The source tree itself is malformed (a duplicate name, a parent
    /// that is not a directory, a hard link to a non-file, …).
    InvalidTree(String),
    /// Two regions of the plan claim the same sectors (or, in the system
    /// area, the same bytes).
    Overlap {
        /// The first region.
        first: String,
        /// Its sectors (bytes for system-area claims), `start..end`.
        first_range: (u64, u64),
        /// The region it collides with.
        second: String,
        /// Its range.
        second_range: (u64, u64),
    },
    /// A region lies (partly) outside the space it must live in: past
    /// the end of the image, below LBA 16 for a volume descriptor, or
    /// outside the 32 KiB system area for a system-area claim.
    OutOfBounds {
        /// The region.
        region: String,
        /// Its range, `start..end`.
        range: (u64, u64),
        /// The bound it crosses.
        limit: u64,
    },
    /// More than one view wants to enclose the shared payloads (only one
    /// partition can wrap them).
    MultipleWrappers(Vec<ViewId>),
    /// Something does not fit the on-disk format: more than 2^32
    /// sectors, a volume larger than HFS+ can address, a boot image
    /// larger than El Torito can load, ….
    TooLarge {
        /// What is too large.
        what: String,
        /// The size requested.
        size: u64,
        /// The format's limit.
        limit: u64,
    },
    /// A payload source produced a different number of bytes than the
    /// tree declared for it (the file changed between planning and
    /// writing).
    PayloadLength {
        /// The tree path of the (first) file using the payload.
        path: String,
        /// Bytes declared in the plan.
        expected: u64,
        /// Bytes the source produced (at least this many, when longer).
        actual: u64,
    },
    /// The destination device is smaller than the planned image.
    DeviceTooSmall {
        /// Bytes needed.
        needed: u64,
        /// Bytes available.
        available: u64,
    },
    /// Verification read back something other than the plan: a view's
    /// descriptors fail their checksum or signature, or an independent
    /// reader of a view sees a different tree or different payload
    /// extents than were planned.
    Verify {
        /// The view whose read-back failed.
        view: ViewId,
        /// What differs.
        detail: String,
    },
    /// An error from a filesystem, block device or source reader.
    Fs(crate::Error),
}

impl fmt::Display for HybridError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoViews => write!(f, "hybrid: no filesystem view is enabled"),
            Self::InvalidOption(m) => write!(f, "hybrid: {m}"),
            Self::UnknownPath { option, path } => {
                write!(f, "hybrid: {option}: no such entry {path:?}")
            }
            Self::InvalidTree(m) => write!(f, "hybrid: source tree: {m}"),
            Self::Overlap {
                first,
                first_range,
                second,
                second_range,
            } => write!(
                f,
                "hybrid: {first} ({}..{}) overlaps {second} ({}..{})",
                first_range.0, first_range.1, second_range.0, second_range.1
            ),
            Self::OutOfBounds {
                region,
                range,
                limit,
            } => write!(
                f,
                "hybrid: {region} ({}..{}) crosses its bound {limit}",
                range.0, range.1
            ),
            Self::MultipleWrappers(v) => write!(
                f,
                "hybrid: views {v:?} each want to enclose the shared payloads; only one can"
            ),
            Self::TooLarge { what, size, limit } => {
                write!(f, "hybrid: {what} is {size}, the limit is {limit}")
            }
            Self::PayloadLength {
                path,
                expected,
                actual,
            } => write!(
                f,
                "hybrid: {path:?}: planned {expected} bytes, source produced {actual}"
            ),
            Self::DeviceTooSmall { needed, available } => write!(
                f,
                "hybrid: device holds {available} bytes, the image needs {needed}"
            ),
            Self::Verify { view, detail } => {
                write!(
                    f,
                    "hybrid: verification of the {view} view failed: {detail}"
                )
            }
            Self::Fs(e) => write!(f, "hybrid: {e}"),
        }
    }
}

impl std::error::Error for HybridError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Fs(e) => Some(e),
            _ => None,
        }
    }
}

impl From<crate::Error> for HybridError {
    fn from(e: crate::Error) -> Self {
        Self::Fs(e)
    }
}

impl From<std::io::Error> for HybridError {
    fn from(e: std::io::Error) -> Self {
        Self::Fs(crate::Error::Io(e))
    }
}

impl From<HybridError> for crate::Error {
    fn from(e: HybridError) -> Self {
        match e {
            HybridError::Fs(e) => e,
            HybridError::Verify { .. } => crate::Error::InvalidImage(e.to_string()),
            HybridError::PayloadLength { .. } => crate::Error::InvalidArgument(e.to_string()),
            HybridError::TooLarge { .. } => crate::Error::Unsupported(e.to_string()),
            other => crate::Error::InvalidArgument(other.to_string()),
        }
    }
}

/// `Result` of the hybrid API.
pub type Result<T> = std::result::Result<T, HybridError>;
