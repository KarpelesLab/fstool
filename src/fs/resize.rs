//! Filesystem resize plans: decide first, change second.
//!
//! Resizing is split into two calls so a caller learns whether a
//! volume *can* change size — and why not — before anything is
//! written:
//!
//! 1. `plan_resize(dev, new_size, &opts)` is read-only. It verifies the
//!    volume, works out exactly what would change, and returns a plan.
//!    A plan that cannot be carried out still comes back `Ok`, with its
//!    [`ResizeRefusal`]s listed; `Err` is kept for "this is not a volume
//!    of that kind" and I/O failures.
//! 2. `apply_resize(dev, &plan)` carries a feasible plan out. The plan
//!    remembers a fingerprint of what it was computed from (the volume
//!    header bytes, the device size, a checksum of the allocation map),
//!    and apply refuses with [`crate::Error::InvalidArgument`] if the
//!    device in front of it is not that volume in that state any more —
//!    a stale plan, or the wrong device.
//!
//! This is a *filesystem* resize: it changes how much of its device a
//! volume uses. Resizing the device itself — the image file, the
//! partition — is a separate step that comes before a grow and after a
//! shrink (see [`crate::part::resize`] for partitions, and
//! `fstool resize` / the container APIs for image files).
//!
//! Implemented for HFS+ / HFSX: [`crate::fs::hfs_plus::resize`].

use std::fmt;

/// Which way a plan changes the volume.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResizeDirection {
    /// The volume gets bigger.
    Grow,
    /// The volume gets smaller.
    Shrink,
    /// The requested size is the current size.
    Unchanged,
}

impl fmt::Display for ResizeDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ResizeDirection::Grow => "grow",
            ResizeDirection::Shrink => "shrink",
            ResizeDirection::Unchanged => "unchanged",
        })
    }
}

/// Why a resize plan cannot be carried out.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResizeRefusal {
    /// The new size is not a multiple of the volume's allocation unit.
    NotAligned {
        /// Requested size, bytes.
        size: u64,
        /// Allocation block / cluster size, bytes.
        unit: u64,
    },
    /// The new size is below what the volume's own metadata needs, or
    /// below the smallest size its live data allows without moving it.
    BelowMinimum {
        /// The smallest size reachable without moving data, bytes.
        min_size: u64,
    },
    /// The new size exceeds what the format can address (or what can be
    /// reached without relocating metadata).
    AboveMaximum {
        /// Largest reachable size, bytes.
        max_size: u64,
    },
    /// Allocated blocks lie at or past the new end. Shrinking past them
    /// would mean moving data, which is not supported.
    AllocatedBeyondEnd {
        /// First allocated block in the region that would be cut off.
        first_block: u64,
        /// Allocated blocks in that region.
        blocks: u64,
    },
    /// The allocation bitmap itself lies past the new end and would have
    /// to be moved.
    BitmapRelocationRequired,
    /// The allocation bitmap would have to grow, and cannot: it already
    /// uses all of its inline extents, continues in the extents
    /// overflow file, or there is no room for it in the added space.
    BitmapExtensionUnsupported {
        /// Why.
        reason: String,
    },
    /// The volume is journaled and its journal holds transactions not
    /// yet replayed (mount it once, or replay it, first).
    JournalNotEmpty,
    /// The journal lives on another device, or its info block is not
    /// understood.
    JournalUnsupported {
        /// Why.
        reason: String,
    },
    /// The volume is not marked cleanly unmounted (it may be mounted
    /// right now).
    VolumeDirty,
    /// The volume is flagged inconsistent by the kernel.
    VolumeInconsistent,
    /// Verification found errors; resizing a damaged volume is refused.
    VerificationFailed {
        /// Errors found.
        errors: u64,
        /// The first few, rendered.
        first: Vec<String>,
    },
    /// Verification could not complete within its bounds.
    VerificationIncomplete,
    /// Something this resizer does not handle.
    Unsupported {
        /// What.
        reason: String,
    },
}

impl fmt::Display for ResizeRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResizeRefusal::NotAligned { size, unit } => {
                write!(
                    f,
                    "size {size} is not a multiple of the {unit}-byte allocation block"
                )
            }
            ResizeRefusal::BelowMinimum { min_size } => {
                write!(
                    f,
                    "below the minimum size reachable without moving data ({min_size} bytes)"
                )
            }
            ResizeRefusal::AboveMaximum { max_size } => {
                write!(f, "above the maximum reachable size ({max_size} bytes)")
            }
            ResizeRefusal::AllocatedBeyondEnd {
                first_block,
                blocks,
            } => write!(
                f,
                "{blocks} allocated block(s) from block {first_block} lie past the new end \
                 (moving data is not supported)"
            ),
            ResizeRefusal::BitmapRelocationRequired => {
                f.write_str("the allocation bitmap lies past the new end and would have to move")
            }
            ResizeRefusal::BitmapExtensionUnsupported { reason } => {
                write!(f, "the allocation bitmap cannot be extended: {reason}")
            }
            ResizeRefusal::JournalNotEmpty => {
                f.write_str("the journal holds unreplayed transactions")
            }
            ResizeRefusal::JournalUnsupported { reason } => {
                write!(f, "unsupported journal: {reason}")
            }
            ResizeRefusal::VolumeDirty => f.write_str("the volume is not cleanly unmounted"),
            ResizeRefusal::VolumeInconsistent => f.write_str("the volume is flagged inconsistent"),
            ResizeRefusal::VerificationFailed { errors, first } => {
                write!(f, "verification found {errors} error(s)")?;
                if let Some(e) = first.first() {
                    write!(f, ", first: {e}")?;
                }
                Ok(())
            }
            ResizeRefusal::VerificationIncomplete => {
                f.write_str("verification hit its bounds before completing")
            }
            ResizeRefusal::Unsupported { reason } => write!(f, "unsupported: {reason}"),
        }
    }
}

#[cfg(feature = "hfs-plus")]
/// Render a refusal list as one error, for `apply_resize` on an
/// infeasible plan.
pub(crate) fn refusal_error(what: &str, refusals: &[ResizeRefusal]) -> crate::Error {
    let list: Vec<String> = refusals.iter().map(|r| r.to_string()).collect();
    crate::Error::InvalidArgument(format!("{what}: resize refused: {}", list.join("; ")))
}
