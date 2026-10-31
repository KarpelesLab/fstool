//! Verifying a UDIF image's embedded checksums, as `hdiutil verify` does.
//!
//! A UDIF image records three kinds of checksum (each a type code plus a
//! value; fstool computes CRC-32 and MD5):
//!
//! - a **partition checksum** in each `blkx` entry's mish header, over
//!   the entry's decoded sectors in table order, *excluding* sectors
//!   carried by "ignore" (free-space) chunks;
//! - a **data-fork checksum** in each segment's trailer, over that
//!   segment's data-fork bytes as stored;
//! - the **master checksum** in the trailer, over the partition
//!   checksums' values concatenated in `blkx` order.
//!
//! [`verify_udif`] recomputes each one that is recorded and reports them
//! all in a [`UdifVerifyReport`]. A checksum of a type fstool cannot
//! compute is reported [`ChecksumStatus::Unsupported`] — and makes the
//! report not valid — rather than skipped.

use std::path::Path;

use super::DmgBackend;
use super::container::StoredChecksum;
use super::mish::ChunkType;
use crate::Result;
use crate::block::imageops::{ChecksumHasher, to_hex};

/// `hdiutil verify` hashes a zero-fill chunk under MD5 as `count × 512`
/// zero bytes *plus three*; fstool's writer never records such a
/// checksum (it uses "ignore" chunks under MD5), but a checksum computed
/// the way Apple's engine does verifies the same way here.
const MD5_ZERO_FILL_EXTRA: u64 = 3;

/// The outcome of one checksum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChecksumStatus {
    /// Recomputed and equal to the recorded value.
    Valid,
    /// Recomputed and different.
    Mismatch,
    /// None recorded (type 0); nothing to check.
    Absent,
    /// Recorded with a type fstool cannot compute.
    Unsupported,
}

/// One checked checksum.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ChecksumCheck {
    /// What it covers: the `blkx` entry's name, the segment's file, or
    /// `"master"`.
    pub label: String,
    /// The recorded checksum.
    pub stored: StoredChecksum,
    /// The recomputed value, when one was computed.
    pub computed: Option<Vec<u8>>,
    /// The outcome.
    pub status: ChecksumStatus,
}

impl ChecksumCheck {
    /// Lower-case hex of the recomputed value (empty when none).
    pub fn computed_hex(&self) -> String {
        self.computed.as_deref().map(to_hex).unwrap_or_default()
    }
}

/// Everything [`verify_udif`] checked.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct UdifVerifyReport {
    /// One per `blkx` entry, in plist order.
    pub partitions: Vec<ChecksumCheck>,
    /// One per segment (one for an ordinary image).
    pub data_forks: Vec<ChecksumCheck>,
    /// The master checksum.
    pub master: ChecksumCheck,
}

impl UdifVerifyReport {
    /// Every check, partitions first.
    pub fn checks(&self) -> impl Iterator<Item = &ChecksumCheck> {
        self.partitions
            .iter()
            .chain(&self.data_forks)
            .chain(core::iter::once(&self.master))
    }

    /// True when nothing mismatched and nothing was of an uncomputable
    /// type. (An image with no checksums at all is valid but has
    /// [`Self::checked_any`] false.)
    pub fn is_valid(&self) -> bool {
        self.checks()
            .all(|c| matches!(c.status, ChecksumStatus::Valid | ChecksumStatus::Absent))
    }

    /// Whether at least one checksum was actually recomputed and matched.
    pub fn checked_any(&self) -> bool {
        self.checks().any(|c| c.status == ChecksumStatus::Valid)
    }

    /// The checks that failed (mismatched or uncomputable).
    pub fn failures(&self) -> impl Iterator<Item = &ChecksumCheck> {
        self.checks().filter(|c| {
            matches!(
                c.status,
                ChecksumStatus::Mismatch | ChecksumStatus::Unsupported
            )
        })
    }
}

fn judge(label: String, stored: StoredChecksum, computed: Option<Vec<u8>>) -> ChecksumCheck {
    let status = if stored.is_none() {
        ChecksumStatus::Absent
    } else {
        match &computed {
            None => ChecksumStatus::Unsupported,
            Some(v) if v.as_slice() == stored.value() => ChecksumStatus::Valid,
            Some(_) => ChecksumStatus::Mismatch,
        }
    };
    ChecksumCheck {
        label,
        stored,
        computed,
        status,
    }
}

/// Verify every checksum the UDIF image at `path` (its first segment, for
/// a segmented image) records. Decodes every data chunk once and reads
/// the data fork once; memory stays bounded by one chunk.
///
/// Errors are for images that cannot be read at all (a chunk that fails
/// to decode is an error too — its data is not there to checksum); a
/// checksum that does not match is a [`ChecksumStatus::Mismatch`] in the
/// report.
pub fn verify_udif(path: &Path) -> Result<UdifVerifyReport> {
    let mut dev = DmgBackend::open(path)?;
    verify_backend(&mut dev)
}

pub(crate) fn verify_backend(dev: &mut DmgBackend) -> Result<UdifVerifyReport> {
    let blkx = dev.info().blkx.clone();
    let mut partitions = Vec::with_capacity(blkx.len());
    for (i, b) in blkx.iter().enumerate() {
        let label = if b.name.is_empty() {
            format!("blkx {i} (ID {})", b.id)
        } else {
            b.name.clone()
        };
        let computed = match b.checksum.algorithm() {
            Some(alg) if !b.checksum.is_none() => {
                let md5 = alg == crate::block::imageops::ChecksumAlgorithm::Md5;
                let mut h = ChecksumHasher::new(alg);
                for c in &b.chunks {
                    match c.kind {
                        ChunkType::Ignored | ChunkType::Comment | ChunkType::Terminator => {}
                        ChunkType::Zero => {
                            let extra = if md5 && c.sector_count > 0 {
                                MD5_ZERO_FILL_EXTRA
                            } else {
                                0
                            };
                            h.update_zeros(c.sector_count * 512 + extra);
                        }
                        _ => {
                            let plain = dev.decode_chunk(c)?;
                            h.update(&plain);
                        }
                    }
                }
                Some(h.finish())
            }
            _ => None,
        };
        partitions.push(judge(label, b.checksum, computed));
    }

    let segments = dev.info().segments.clone();
    let mut data_forks = Vec::with_capacity(segments.len());
    let mut buf = vec![0u8; crate::block::imageops::COPY_CHUNK];
    for s in &segments {
        let label = s
            .path
            .as_ref()
            .map_or_else(|| "data fork".to_string(), |p| p.display().to_string());
        let stored = s.data_checksum();
        let computed = match stored.algorithm() {
            Some(alg) if !stored.is_none() => {
                let mut h = ChecksumHasher::new(alg);
                let (start, len) = (s.fork_start(), s.trailer.data_fork_length);
                let mut done = 0u64;
                while done < len {
                    let n = (len - done).min(buf.len() as u64) as usize;
                    dev.read_fork(start + done, &mut buf[..n])?;
                    h.update(&buf[..n]);
                    done += n as u64;
                }
                Some(h.finish())
            }
            _ => None,
        };
        data_forks.push(judge(label, stored, computed));
    }

    let stored = dev.info().master_checksum;
    let computed = match stored.algorithm() {
        Some(alg) if !stored.is_none() => {
            let mut h = ChecksumHasher::new(alg);
            for b in &blkx {
                if !b.checksum.is_none() {
                    h.update(b.checksum.value());
                }
            }
            Some(h.finish())
        }
        _ => None,
    };
    let master = judge("master".to_string(), stored, computed);
    Ok(UdifVerifyReport {
        partitions,
        data_forks,
        master,
    })
}
