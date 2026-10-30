//! Filesystem-aware free-space reclamation, and [`SparseBackend`], the
//! either-format handle it (and the CLI) works through.
//!
//! [`compact`](SparseImageBackend::compact) drops bands that are all zero;
//! it cannot help after a file is deleted, because the filesystem only
//! marks the file's blocks free and leaves its bytes in place. Reclamation
//! asks the filesystem instead: [`reclaim`] reads each volume's allocation
//! bitmap ([`crate::fs::free_space`]) and releases every band that holds
//! nothing the filesystem uses.
//!
//! A band is released when each of its bytes is either free (by the
//! filesystem's own map) or zero. Bands that hold live data as well as free
//! space are kept untouched unless [`PartialBandPolicy::ZeroFree`] asks for
//! their free parts to be zeroed — useful before compressing or shipping
//! the image, and the only case in which bytes of a *kept* band change.
//! Either way only bytes the filesystem has declared free are discarded,
//! and only from a volume that is consistent and cleanly unmounted (the
//! free-space map refuses anything else); the exclusive image lock keeps
//! hdiutil (an attached image) and other fstool processes out meanwhile.
//!
//! Partition tables are honoured: every volume is mapped through its own
//! partition slice, so nothing outside a partition — the table itself,
//! gaps, partitions holding filesystems that cannot be mapped — is ever
//! counted as free. A table with overlapping partitions is refused.
//!
//! Failure leaves the image as it was for a `.sparseimage` (the new image
//! is written beside it and renamed into place). A `.sparsebundle` is
//! changed band by band — deleting a band file is atomic and zeroing only
//! touches free bytes — so an interrupted run leaves every file's contents
//! intact, with part of the free space reclaimed.

use std::ops::Range;
use std::path::Path;

use super::{ShrinkPolicy, SparseBundleBackend, SparseImageBackend};
use crate::Result;
use crate::block::BlockDevice;

/// What to do with free space inside a band that also holds live data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum PartialBandPolicy {
    /// Leave such bands exactly as they are.
    #[default]
    Keep,
    /// Overwrite their free bytes with zeros (on a sparsebundle, a free
    /// tail is truncated away instead). The live data is not touched.
    ZeroFree,
}

/// Options for [`reclaim`] and the backends' `reclaim` methods.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReclaimOpts {
    /// Treatment of free space in bands that are kept.
    pub partial: PartialBandPolicy,
    /// Work out what would be released and zeroed, but change nothing.
    pub dry_run: bool,
    /// Only reclaim inside this partition (0-based). `None` maps every
    /// partition holding a supported filesystem — or the whole image when
    /// it has no partition table.
    pub partition: Option<usize>,
}

/// Band counts from one reclamation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReclaimStats {
    /// Allocated bands before.
    pub bands_before: u64,
    /// Bands released (or, on a dry run, that would be).
    pub bands_released: u64,
    /// Kept bands whose free bytes were zeroed (or would be).
    pub bands_zeroed: u64,
    /// Free bytes zeroed in kept bands (or that would be).
    pub bytes_zeroed: u64,
}

impl ReclaimStats {
    /// Allocated bands after.
    pub fn bands_after(&self) -> u64 {
        self.bands_before - self.bands_released
    }
}

/// One volume whose free space was mapped.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MappedVolume {
    /// Partition index (0-based), `None` for an unpartitioned image.
    pub partition: Option<usize>,
    /// Byte offset of the volume in the image.
    pub offset: u64,
    /// Filesystem, as [`crate::fs::free_space::FreeSpace::fs`] names it.
    pub fs: &'static str,
    /// Free bytes the filesystem reports.
    pub free_bytes: u64,
}

/// A partition that was left alone, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SkippedVolume {
    /// Partition index (0-based).
    pub partition: usize,
    /// Why its free space was not mapped (an unsupported filesystem, or
    /// none at all).
    pub reason: String,
}

/// What [`reclaim`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReclaimReport {
    /// Band counts.
    pub stats: ReclaimStats,
    /// Volumes whose free space was used.
    pub volumes: Vec<MappedVolume>,
    /// Partitions skipped because their filesystem can't be mapped.
    pub skipped: Vec<SkippedVolume>,
}

/// Give back the space of every band of the sparse image or bundle at
/// `path` that holds only free space (or zeros), as its filesystems report
/// it — the filesystem-aware counterpart of `compact`, which only drops
/// all-zero bands and so cannot see a deleted file's leftover bytes.
///
/// Each volume's allocation bitmap is read through
/// [`crate::fs::free_space`] — through the partition table, so nothing
/// outside a mapped partition (the table itself, gaps, partitions with
/// filesystems that can't be mapped) ever counts as free. A band is
/// released when every byte of it is free or zero; a band that also holds
/// live data is kept as it is unless [`PartialBandPolicy::ZeroFree`] asks
/// for its free bytes to be zeroed. Only bytes the filesystem declares free
/// are ever discarded.
///
/// Fails without changing anything when the image is in use (hdiutil or
/// another process holds its lock), when a volume is dirty, mounted,
/// inconsistent or has an unreplayed journal, when the partition table has
/// overlapping entries, or when no volume could be mapped. A failure part
/// way leaves a `.sparseimage` exactly as it was (the new image is written
/// beside it and renamed into place); a `.sparsebundle` is changed one
/// atomic band-file deletion (or free-bytes-only zeroing) at a time, so
/// it stays consistent with every live byte intact.
pub fn reclaim(path: &Path, opts: &ReclaimOpts) -> Result<ReclaimReport> {
    let mut dev = if opts.dry_run {
        SparseBackend::open_read_only(path)?
    } else {
        SparseBackend::open(path)?
    };
    let (free, volumes, skipped) = map_free_space(dev.as_block_device(), opts.partition)?;
    if volumes.is_empty() {
        let why: Vec<String> = skipped
            .iter()
            .map(|s| format!("partition {}: {}", s.partition + 1, s.reason))
            .collect();
        return Err(crate::Error::Unsupported(format!(
            "{}: no volume whose free space can be mapped ({})",
            path.display(),
            why.join("; ")
        )));
    }
    let stats = dev.reclaim(&free, opts)?;
    if !opts.dry_run {
        dev.as_block_device().sync()?;
    }
    Ok(ReclaimReport {
        stats,
        volumes,
        skipped,
    })
}

type Mapped = (Vec<Range<u64>>, Vec<MappedVolume>, Vec<SkippedVolume>);

/// Free byte ranges of `dev`, in its own coordinates, across the volumes
/// [`ReclaimOpts::partition`] selects.
pub(crate) fn map_free_space(
    dev: &mut dyn BlockDevice,
    partition: Option<usize>,
) -> Result<Mapped> {
    use crate::fs::free_space::free_space;
    let Some(table) = crate::inspect::detect_partition_table(dev)? else {
        if let Some(i) = partition {
            return Err(crate::Error::InvalidArgument(format!(
                "no partition table, so no partition {}",
                i + 1
            )));
        }
        let fs = free_space(dev)?;
        let vol = MappedVolume {
            partition: None,
            offset: 0,
            fs: fs.fs,
            free_bytes: fs.free_bytes(),
        };
        return Ok((fs.ranges, vec![vol], Vec::new()));
    };
    let parts = table.partitions();
    check_disjoint(parts, u64::from(dev.block_size()))?;
    let wanted: Vec<usize> = match partition {
        Some(i) if i >= parts.len() => {
            return Err(crate::Error::InvalidArgument(format!(
                "partition {} out of range (have {})",
                i + 1,
                parts.len()
            )));
        }
        Some(i) => vec![i],
        None => (0..parts.len()).collect(),
    };
    let mut free = Vec::new();
    let mut volumes = Vec::new();
    let mut skipped = Vec::new();
    for i in wanted {
        let mut slice = crate::part::slice_partition(table.as_table(), dev, i)?;
        let off = slice.parent_offset();
        let len = slice.total_size();
        match free_space(&mut slice) {
            Ok(fs) => {
                volumes.push(MappedVolume {
                    partition: Some(i),
                    offset: off,
                    fs: fs.fs,
                    free_bytes: fs.free_bytes(),
                });
                free.extend(
                    fs.ranges
                        .iter()
                        .filter(|r| r.end <= len)
                        .map(|r| r.start + off..r.end + off),
                );
            }
            // A partition with nothing mappable on it is skipped when
            // sweeping the whole table, but an explicit request must work.
            Err(crate::Error::Unsupported(why)) if partition.is_none() => {
                skipped.push(SkippedVolume {
                    partition: i,
                    reason: why,
                });
            }
            Err(e) => return Err(e),
        }
    }
    free.sort_unstable_by_key(|r| r.start);
    Ok((free, volumes, skipped))
}

/// Refuse a table whose partitions overlap: one volume's free space could
/// be another's data.
fn check_disjoint(parts: &[crate::part::Partition], bs: u64) -> Result<()> {
    let mut spans: Vec<(u64, u64)> = parts
        .iter()
        .map(|p| {
            let s = p.start_lba.saturating_mul(bs);
            (s, s.saturating_add(p.size_lba.saturating_mul(bs)))
        })
        .collect();
    spans.sort_unstable();
    if spans.windows(2).any(|w| w[1].0 < w[0].1) {
        return Err(crate::Error::InvalidImage(
            "partition table has overlapping partitions — refusing to reclaim".into(),
        ));
    }
    Ok(())
}

/// Check that `free` is sorted and non-overlapping.
pub(super) fn check_ranges(free: &[Range<u64>], size: u64) -> Result<()> {
    let mut prev = 0u64;
    for r in free {
        if r.start < prev || r.start > r.end || r.end > size {
            return Err(crate::Error::InvalidArgument(
                "free ranges must be sorted, non-overlapping and inside the image".into(),
            ));
        }
        prev = r.end;
    }
    Ok(())
}

/// The free parts of `[start, end)`, relative to `start`.
pub(super) fn free_within(free: &[Range<u64>], start: u64, end: u64) -> Vec<Range<u64>> {
    let i = free.partition_point(|r| r.end <= start);
    free[i..]
        .iter()
        .take_while(|r| r.start < end)
        .map(|r| r.start.max(start) - start..r.end.min(end) - start)
        .filter(|r| r.start < r.end)
        .collect()
}

/// The parts of `[0, len)` not in `holes` (sorted, disjoint).
pub(super) fn complement(holes: &[Range<u64>], len: u64) -> Vec<Range<u64>> {
    let mut out = Vec::new();
    let mut at = 0;
    for h in holes {
        if h.start > at {
            out.push(at..h.start);
        }
        at = at.max(h.end);
    }
    if at < len {
        out.push(at..len);
    }
    out
}

/// A `.sparseimage` or a `.sparsebundle`, whichever is on disk.
#[derive(Debug)]
#[non_exhaustive]
pub enum SparseBackend {
    /// A single-file `.sparseimage`.
    Image(SparseImageBackend),
    /// A `.sparsebundle` directory.
    Bundle(SparseBundleBackend),
}

impl SparseBackend {
    /// Open `path` for writing, under an exclusive lock, as whichever
    /// format it is (by content). Anything else is
    /// [`Error::InvalidArgument`](crate::Error::InvalidArgument).
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_inner(path, false)
    }

    /// Open `path` read-only, under a shared lock.
    pub fn open_read_only(path: &Path) -> Result<Self> {
        Self::open_inner(path, true)
    }

    fn open_inner(path: &Path, ro: bool) -> Result<Self> {
        if SparseBundleBackend::probe(path)? {
            return Ok(Self::Bundle(if ro {
                SparseBundleBackend::open_read_only(path)?
            } else {
                SparseBundleBackend::open(path)?
            }));
        }
        super::refuse_encrypted_image(path)?;
        if SparseImageBackend::probe(path)? {
            return Ok(Self::Image(if ro {
                SparseImageBackend::open_read_only(path)?
            } else {
                SparseImageBackend::open(path)?
            }));
        }
        Err(crate::Error::InvalidArgument(format!(
            "{}: not a .sparseimage or .sparsebundle",
            path.display()
        )))
    }

    /// The image as a [`BlockDevice`].
    pub fn as_block_device(&mut self) -> &mut dyn BlockDevice {
        match self {
            Self::Image(b) => b,
            Self::Bundle(b) => b,
        }
    }

    /// `"sparseimage"` or `"sparsebundle"`.
    pub fn format_name(&self) -> &'static str {
        match self {
            Self::Image(_) => "sparseimage",
            Self::Bundle(_) => "sparsebundle",
        }
    }

    /// Band size in bytes.
    pub fn band_size(&self) -> u64 {
        match self {
            Self::Image(b) => b.band_size(),
            Self::Bundle(b) => b.band_size(),
        }
    }

    /// Bands holding data.
    pub fn allocated_bands(&self) -> u64 {
        match self {
            Self::Image(b) => b.allocated_bands(),
            Self::Bundle(b) => b.allocated_bands(),
        }
    }

    /// See [`SparseImageBackend::compact`] / [`SparseBundleBackend::compact`].
    pub fn compact(&mut self) -> Result<u64> {
        match self {
            Self::Image(b) => b.compact(),
            Self::Bundle(b) => b.compact(),
        }
    }

    /// See [`SparseImageBackend::resize`] / [`SparseBundleBackend::resize`].
    pub fn resize(&mut self, new_size: u64, policy: ShrinkPolicy) -> Result<()> {
        match self {
            Self::Image(b) => b.resize(new_size, policy),
            Self::Bundle(b) => b.resize(new_size, policy),
        }
    }

    /// See [`SparseImageBackend::reclaim`] / [`SparseBundleBackend::reclaim`].
    pub fn reclaim(&mut self, free: &[Range<u64>], opts: &ReclaimOpts) -> Result<ReclaimStats> {
        match self {
            Self::Image(b) => b.reclaim(free, opts),
            Self::Bundle(b) => b.reclaim(free, opts),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_helpers() {
        let free = [10..20, 30..40, 50..60];
        assert_eq!(free_within(&free, 15, 35), vec![0..5, 15..20]);
        assert_eq!(free_within(&free, 20, 30), Vec::<Range<u64>>::new());
        assert_eq!(free_within(&free, 0, 100).len(), 3);
        assert_eq!(complement(&[0..5, 15..20], 20), vec![5..15]);
        assert_eq!(complement(&[], 7), vec![0..7]);
        assert!(check_ranges(&free, 60).is_ok());
        assert!(check_ranges(&free, 59).is_err());
        assert!(check_ranges(&[10..20, 15..30], 100).is_err());
    }

    /// HFS+ in partition 1 of a GPT disk, raw data in partition 2: the
    /// deleted file's bands go, nothing outside partition 1 is touched.
    #[cfg(feature = "hfs-plus")]
    #[test]
    fn reclaim_inside_a_gpt_partition() {
        use crate::inspect::AnyFs;
        use crate::part::{Gpt, Partition, PartitionKind, PartitionTable, slice_partition};
        let d = tempfile::tempdir().unwrap();
        let img = d.path().join("g.sparseimage");
        let mib = 1u64 << 20;
        let keep = d.path().join("keep");
        let gone = d.path().join("gone");
        std::fs::write(&keep, vec![0x5Au8; 2 << 20]).unwrap();
        std::fs::write(&gone, vec![0xC3u8; 8 << 20]).unwrap();
        {
            let mut dev = SparseImageBackend::create(&img, 48 * mib, mib).unwrap();
            let gpt = Gpt::build(vec![
                Partition::new(2048, 40960, PartitionKind::LinuxFilesystem),
                Partition::new(43008, 20480, PartitionKind::LinuxFilesystem),
            ])
            .unwrap();
            gpt.write(&mut dev).unwrap();
            {
                let mut p1 = slice_partition(&gpt, &mut dev, 0).unwrap();
                let opts = crate::fs::hfs_plus::FormatOpts::default();
                let mut fs = crate::fs::hfs_plus::HfsPlus::format(&mut p1, &opts).unwrap();
                crate::fs::Filesystem::flush(&mut fs, &mut p1).unwrap();
                drop(fs);
                let mut fs = AnyFs::open_writable(&mut p1).unwrap();
                fs.add_file(&mut p1, "/keep", &keep).unwrap();
                fs.add_file(&mut p1, "/gone", &gone).unwrap();
                fs.remove(&mut p1, "/gone").unwrap();
                fs.flush(&mut p1).unwrap();
            }
            // Partition 2: no filesystem, nonzero bytes.
            dev.write_at(43008 * 512, &vec![0x77u8; 10 << 20]).unwrap();
            dev.sync().unwrap();
        }
        let before = SparseBackend::open_read_only(&img)
            .unwrap()
            .allocated_bands();
        let rep = reclaim(&img, &ReclaimOpts::default()).unwrap();
        assert_eq!(rep.volumes.len(), 1);
        assert_eq!(rep.volumes[0].partition, Some(0));
        assert_eq!(rep.volumes[0].offset, mib);
        assert_eq!(rep.skipped.len(), 1);
        assert_eq!(rep.skipped[0].partition, 1);
        assert_eq!(rep.stats.bands_before, before);
        assert!(rep.stats.bands_released >= 7, "{:?}", rep.stats);

        let mut dev = SparseImageBackend::open(&img).unwrap();
        assert_eq!(dev.allocated_bands(), before - rep.stats.bands_released);
        let mut p2 = vec![0u8; 10 << 20];
        dev.read_at(43008 * 512, &mut p2).unwrap();
        assert!(p2.iter().all(|&b| b == 0x77), "partition 2 changed");
        let gpt = match crate::inspect::detect_partition_table(&mut dev).unwrap() {
            Some(crate::inspect::DetectedTable::Gpt(g)) => g,
            _ => panic!("GPT gone"),
        };
        let mut p1 = slice_partition(gpt.as_ref(), &mut dev, 0).unwrap();
        let mut fs = AnyFs::open(&mut p1).unwrap();
        let mut out = Vec::new();
        fs.copy_file_to(&mut p1, "/keep", &mut out).unwrap();
        assert!(out == vec![0x5Au8; 2 << 20]);
        drop(fs);

        // Partition 2 explicitly: nothing mappable there is an error.
        drop(dev);
        let mut opts = ReclaimOpts {
            partition: Some(1),
            ..Default::default()
        };
        assert!(reclaim(&img, &opts).is_err());
        opts.partition = Some(5);
        assert!(reclaim(&img, &opts).is_err());

        // Overlapping partitions (which the table builders refuse to
        // write) are refused outright.
        assert!(check_disjoint(&[Partition::new(10, 10, PartitionKind::Empty)], 512).is_ok());
        let p = [
            Partition::new(100, 50, PartitionKind::LinuxFilesystem),
            Partition::new(10, 10, PartitionKind::LinuxFilesystem),
            Partition::new(140, 5, PartitionKind::LinuxFilesystem),
        ];
        assert!(matches!(
            check_disjoint(&p, 512),
            Err(crate::Error::InvalidImage(_))
        ));
        assert!(check_disjoint(&p[..2], 512).is_ok());
    }
}
