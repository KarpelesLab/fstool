//! Typed HFS+ / HFSX resize plans and their application.
//!
//! [`plan_resize`] is read-only: it verifies the volume
//! ([`super::verify::verify`]), checks the requested size against what
//! the volume can reach without moving data, and returns an
//! [`HfsPlusResizePlan`] — feasible, or carrying the
//! [`ResizeRefusal`]s that say why not. [`apply_resize`] carries a
//! feasible plan out, after checking that the device in front of it is
//! still the volume the plan was made from.
//!
//! The device is resized separately: grow the device (image file,
//! partition) first and apply the plan to the larger device; apply a
//! shrink plan first and cut the device afterwards. See
//! [`crate::part::resize`] for doing both inside a partition table.
//!
//! ## What is supported
//!
//! * **Grow** within the allocation bitmap's existing capacity (its
//!   allocation file is usually rounded up to a clump, so it covers more
//!   blocks than the volume has), and beyond it: the allocation file is
//!   extended by one new extent placed at the start of the added space,
//!   as long as it still has a free inline extent slot.
//! * **Shrink** as long as every allocated block (the special files
//!   included) lies before the new end. The allocation file keeps its
//!   size, so a later grow back is cheap.
//! * Plain HFS+ and HFSX alike; journaled volumes as long as the
//!   journal is in the volume and **empty** (`start == end`) — the
//!   volume was cleanly unmounted or its journal replayed. The journal's
//!   contents do not depend on the volume size, so it is left alone.
//!
//! ## What is refused, and why
//!
//! * Allocated blocks past the new end
//!   ([`ResizeRefusal::AllocatedBeyondEnd`]): moving file extents would
//!   mean rewriting catalog and extents-overflow records under a crash
//!   boundary, which this resizer does not do. [`HfsPlusResizePlan::min_size`]
//!   says how far a shrink can go.
//! * The allocation file itself past the new end
//!   ([`ResizeRefusal::BitmapRelocationRequired`]).
//! * A bitmap that would have to grow but has no free inline extent
//!   slot, continues in the extents-overflow file, or has no room in the
//!   added space ([`ResizeRefusal::BitmapExtensionUnsupported`]).
//! * Sizes not a multiple of the allocation block, past 2³² blocks, or
//!   below the minimum.
//! * Dirty, inconsistent or damaged volumes, and journals with pending
//!   transactions or on another device.
//!
//! ## Transaction boundary
//!
//! The commit point is the single 512-byte write of the primary volume
//! header (sector-atomic on every device fstool targets). Writes are
//! ordered so that each state a crash can leave behind is either the
//! old volume or the new one, never a mix, and in no state is a block
//! that holds live data marked free:
//!
//! **Grow.** (1) Bitmap blocks are written with every change that is
//! invisible to the old volume — bits past its last block, and new
//! bitmap blocks placed in the added space. (2) The new alternate header
//! is written at the new end. (3) **Commit**: the primary header with the
//! new block count, the extended allocation fork, and a free count that
//! still counts the old alternate-header block(s) as used. (4) Those
//! blocks are cleared in the bitmap, the stale alternate header is
//! zeroed, and the primary is rewritten with the final free count.
//! A crash before (3) leaves the old volume, untouched where it can see;
//! between (3) and (4) the new volume with one or two allocated-but-
//! unowned blocks, which `fsck_hfs` reclaims as a minor repair.
//!
//! **Shrink.** (1) The block(s) that will hold the new alternate header
//! are marked used, and the primary header's free count lowered to
//! match — still the old volume, with one or two unowned blocks. (2) The
//! new alternate header is written into them. (3) **Commit**: the primary
//! header with the new block count and free count. (4) Bits past the new
//! end are cleared and the old alternate header zeroed — both past the
//! new end, invisible to the new volume. The device can then be cut.
//!
//! Plans are single-use: the first header write changes the bytes the
//! plan's fingerprint covers, so re-running an interrupted apply is
//! refused as stale; plan again from the state the crash left.

use crate::Result;
use crate::block::BlockDevice;
use crate::fs::resize::{ResizeDirection, ResizeRefusal, refusal_error};
use crate::fs::verify::{VerifyOpts, VerifyReport};

use super::volume_header::{ExtentDescriptor, FORK_DATA_SIZE, ForkData, SIG_HFS_PLUS, SIG_HFSX};

const ATTR_UNMOUNTED: u32 = 1 << 8;
const ATTR_INCONSISTENT: u32 = 1 << 11;
const ATTR_JOURNALED: u32 = 1 << 13;
const FORK_ALLOCATION: usize = 0x70;

/// Knobs for [`plan_resize`].
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct ResizeOpts {
    /// Run [`super::verify::verify`] first and refuse a volume with
    /// errors (default `true`). Turning it off skips the cross-checks the
    /// resize relies on (the bitmap matching what files own); do so only
    /// for a volume you have just verified yourself.
    pub verify: bool,
    /// Bounds for that verification.
    pub verify_opts: VerifyOpts,
    /// Allow a grow past the bitmap's capacity by extending the
    /// allocation file (default `true`). Off, such a grow is refused
    /// with [`ResizeRefusal::BitmapExtensionUnsupported`].
    pub allow_bitmap_extension: bool,
}

impl Default for ResizeOpts {
    fn default() -> Self {
        Self {
            verify: true,
            verify_opts: VerifyOpts::default(),
            allow_bitmap_extension: true,
        }
    }
}

/// What a plan was computed from; apply refuses anything else.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Fingerprint {
    device_size: u64,
    header: [u8; 512],
    bitmap_crc: u32,
}

/// A resize plan for one HFS+ / HFSX volume. Produced by
/// [`plan_resize`], consumed by [`apply_resize`].
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct HfsPlusResizePlan {
    /// Grow, shrink or nothing.
    pub direction: ResizeDirection,
    /// The device size the plan was computed on, bytes.
    pub device_size: u64,
    /// The volume's current size (`totalBlocks × blockSize`), bytes.
    pub old_size: u64,
    /// The requested size, bytes.
    pub new_size: u64,
    /// Allocation block size, bytes.
    pub block_size: u32,
    /// Current `totalBlocks`.
    pub old_total_blocks: u32,
    /// `totalBlocks` after the resize.
    pub new_total_blocks: u32,
    /// Current `freeBlocks`.
    pub old_free_blocks: u32,
    /// `freeBlocks` after the resize.
    pub new_free_blocks: u32,
    /// The extent added to the allocation file when the bitmap has to
    /// grow, `None` when it already covers the new size.
    pub bitmap_extension: Option<ExtentDescriptor>,
    /// Allocation-file blocks a shrink releases: trailing extents of the
    /// bitmap (an earlier grow's extension, typically) that lie past the
    /// new end and that the smaller volume does not need.
    pub bitmap_blocks_released: u32,
    /// Smallest size reachable without moving data, bytes.
    pub min_size: u64,
    /// Largest size reachable with the bitmap as it is, bytes.
    pub max_size_in_place: u64,
    /// Largest size reachable at all (with a bitmap extension, if one is
    /// possible), bytes.
    pub max_size: u64,
    /// The volume is HFSX.
    pub hfsx: bool,
    /// The volume is journaled (with an empty journal, or the plan is
    /// refused).
    pub journaled: bool,
    /// Why the plan cannot be applied. Empty means feasible.
    pub refusals: Vec<ResizeRefusal>,
    /// The verification run the plan was based on, if any.
    pub verification: Option<VerifyReport>,
    fingerprint: Fingerprint,
    alloc_fork: ForkData,
    drop_extents: usize,
}

impl HfsPlusResizePlan {
    /// True when [`apply_resize`] would carry the plan out.
    pub fn is_feasible(&self) -> bool {
        self.refusals.is_empty()
    }
}

fn be32(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes(b[o..o + 4].try_into().unwrap())
}
fn be64(b: &[u8], o: usize) -> u64 {
    u64::from_be_bytes(b[o..o + 8].try_into().unwrap())
}

fn alloc_fork(vh: &[u8; 512]) -> ForkData {
    let mut tmp = [0u8; FORK_DATA_SIZE];
    tmp.copy_from_slice(&vh[FORK_ALLOCATION..FORK_ALLOCATION + FORK_DATA_SIZE]);
    ForkData::decode(&tmp)
}

/// Blocks the alternate header (and the reserved last sector) occupy.
fn tail_blocks(bs: u64) -> u64 {
    1024u64.div_ceil(bs)
}

fn read_header(dev: &mut dyn BlockDevice) -> Result<[u8; 512]> {
    if dev.total_size() < 1536 {
        return Err(crate::Error::InvalidImage(
            "hfs+ resize: device too small for a volume header".into(),
        ));
    }
    let mut vh = [0u8; 512];
    dev.read_at(1024, &mut vh)?;
    if vh[0..2] != SIG_HFS_PLUS && vh[0..2] != SIG_HFSX {
        return Err(crate::Error::InvalidImage(
            "hfs+ resize: no HFS+ / HFSX volume header at byte 1024".into(),
        ));
    }
    let bs = be32(&vh, 40);
    if bs < 512 || !bs.is_power_of_two() || be32(&vh, 44) == 0 {
        return Err(crate::Error::InvalidImage(
            "hfs+ resize: implausible block size or block count".into(),
        ));
    }
    Ok(vh)
}

/// The bitmap as a list of device byte ranges, from the allocation
/// fork's inline extents.
fn bitmap_extents(fork: &ForkData) -> Vec<ExtentDescriptor> {
    fork.extents
        .iter()
        .copied()
        .take_while(|e| e.block_count != 0)
        .collect()
}

/// What one pass over the on-disk bitmap tells the planner.
struct Scan {
    crc: u32,
    /// Free blocks in `[0, a)` and `[0, b)`.
    free_below_a: u64,
    free_below_b: u64,
    /// Highest allocated block below `limit` (the old tail), if any.
    last_used: Option<u64>,
    /// Allocated blocks in `[lo, hi)`, and the first of them.
    used_in_range: u64,
    first_used_in_range: Option<u64>,
}

#[allow(clippy::too_many_arguments)]
fn scan_bitmap(
    dev: &mut dyn BlockDevice,
    fork: &ForkData,
    bs: u64,
    total: u64,
    a: u64,
    b: u64,
    range: (u64, u64),
    ignore: &[(u64, u64)],
) -> Result<Scan> {
    let need = total.div_ceil(8);
    let reader = super::btree::ForkReader {
        base_offset: 0,
        block_size: bs as u32,
        extents: bitmap_extents(fork),
        logical_size: fork.logical_size,
    };
    let limit = total - tail_blocks(bs).min(total);
    let mut s = Scan {
        crc: 0,
        free_below_a: 0,
        free_below_b: 0,
        last_used: None,
        used_in_range: 0,
        first_used_in_range: None,
    };
    const CHUNK: u64 = 1 << 20;
    let mut buf = vec![0u8; CHUNK as usize];
    let mut pos = 0u64;
    while pos < need {
        let n = (need - pos).min(CHUNK) as usize;
        reader.read(dev, pos, &mut buf[..n])?;
        s.crc = crate::crc::crc32_append(s.crc, &buf[..n]);
        for (i, &byte) in buf[..n].iter().enumerate() {
            let base = (pos + i as u64) * 8;
            if byte == 0 && base + 8 <= a && base + 8 <= b {
                s.free_below_a += 8;
                s.free_below_b += 8;
                continue;
            }
            for bit in 0..8u64 {
                let blk = base + bit;
                if blk >= total {
                    break;
                }
                let used = byte & (0x80 >> bit) != 0;
                if !used {
                    if blk < a {
                        s.free_below_a += 1;
                    }
                    if blk < b {
                        s.free_below_b += 1;
                    }
                    continue;
                }
                if ignore.iter().any(|&(lo, hi)| blk >= lo && blk < hi) {
                    continue;
                }
                if blk < limit {
                    s.last_used = Some(blk);
                }
                if blk >= range.0 && blk < range.1 {
                    s.used_in_range += 1;
                    s.first_used_in_range.get_or_insert(blk);
                }
            }
        }
        pos += n as u64;
    }
    Ok(s)
}

/// How many trailing allocation-file extents a volume of `need_bits`
/// blocks can release: each lies at or past block `limit`, and the
/// extents before them still hold `need_bits` bits. The first extent is
/// always kept.
fn droppable(inline: &[ExtentDescriptor], bs: u64, limit: u64, need_bits: u64) -> usize {
    let mut cap: u64 = inline.iter().map(|e| u64::from(e.block_count)).sum::<u64>() * bs * 8;
    let mut n = 0;
    for e in inline.iter().rev() {
        if inline.len() - n <= 1 {
            break;
        }
        let c = u64::from(e.block_count) * bs * 8;
        if u64::from(e.start_block) < limit || cap - c < need_bits {
            break;
        }
        cap -= c;
        n += 1;
    }
    n
}

/// Block ranges of the last `n` extents.
fn tail_ranges(inline: &[ExtentDescriptor], n: usize) -> Vec<(u64, u64)> {
    inline[inline.len() - n..]
        .iter()
        .map(|e| {
            (
                u64::from(e.start_block),
                u64::from(e.start_block) + u64::from(e.block_count),
            )
        })
        .collect()
}

/// Is the journal empty and in the volume? `Ok(None)` when it is,
/// otherwise the refusal.
fn journal_state(
    dev: &mut dyn BlockDevice,
    vh: &[u8; 512],
    bs: u64,
) -> Result<Option<ResizeRefusal>> {
    let jib_block = u64::from(be32(vh, 12));
    let total = u64::from(be32(vh, 44));
    if jib_block == 0 || jib_block >= total {
        return Ok(Some(ResizeRefusal::JournalUnsupported {
            reason: format!("journal info block {jib_block} is outside the volume"),
        }));
    }
    let mut jib = [0u8; 52];
    dev.read_at(jib_block * bs, &mut jib)?;
    let flags = be32(&jib, 0);
    if flags & 2 != 0 {
        return Ok(Some(ResizeRefusal::JournalUnsupported {
            reason: "the journal lives on another device".into(),
        }));
    }
    if flags & 1 == 0 {
        return Ok(Some(ResizeRefusal::JournalUnsupported {
            reason: "the journal info block does not place the journal in the volume".into(),
        }));
    }
    let off = be64(&jib, 36);
    if off.saturating_add(32) > total * bs {
        return Ok(Some(ResizeRefusal::JournalUnsupported {
            reason: "the journal lies outside the volume".into(),
        }));
    }
    let mut jh = [0u8; 32];
    dev.read_at(off, &mut jh)?;
    let (start, end) = if be32(&jh, 0) == 0x4A4E_4C78 && be32(&jh, 4) == 0x1234_5678 {
        (be64(&jh, 8), be64(&jh, 16))
    } else if jh[0..4] == 0x4A4E_4C78u32.to_le_bytes() && jh[4..8] == 0x1234_5678u32.to_le_bytes() {
        (
            u64::from_le_bytes(jh[8..16].try_into().unwrap()),
            u64::from_le_bytes(jh[16..24].try_into().unwrap()),
        )
    } else {
        return Ok(Some(ResizeRefusal::JournalUnsupported {
            reason: "the journal header has no JNLx magic".into(),
        }));
    };
    Ok(if start != end {
        Some(ResizeRefusal::JournalNotEmpty)
    } else {
        None
    })
}

/// Plan resizing the HFS+ / HFSX volume on `dev` to `new_size` bytes.
/// Read-only.
///
/// `dev` must start at the volume (slice a partition first). For a grow
/// it may already be the larger device or still the old one; for a
/// shrink it is the current device, cut after [`apply_resize`].
///
/// Returns `Err` only when `dev` holds no HFS+ / HFSX volume header or
/// cannot be read; everything that makes the resize impossible is in
/// [`HfsPlusResizePlan::refusals`].
pub fn plan_resize(
    dev: &mut dyn BlockDevice,
    new_size: u64,
    opts: &ResizeOpts,
) -> Result<HfsPlusResizePlan> {
    let vh = read_header(dev)?;
    let device_size = dev.total_size();
    let bs = u64::from(be32(&vh, 40));
    let total = u64::from(be32(&vh, 44));
    let old_free = be32(&vh, 48);
    let attrs = be32(&vh, 4);
    let journaled = attrs & ATTR_JOURNALED != 0;
    let k = tail_blocks(bs);
    let mut refusals = Vec::new();

    if total * bs > device_size {
        return Err(crate::Error::InvalidImage(format!(
            "hfs+ resize: volume of {} bytes is larger than its {device_size}-byte device",
            total * bs
        )));
    }
    if attrs & ATTR_INCONSISTENT != 0 {
        refusals.push(ResizeRefusal::VolumeInconsistent);
    }
    if attrs & ATTR_UNMOUNTED == 0 {
        refusals.push(ResizeRefusal::VolumeDirty);
    }
    if journaled && let Some(r) = journal_state(dev, &vh, bs)? {
        refusals.push(r);
    }
    let verification = if opts.verify {
        let rep = super::verify::verify(dev, &opts.verify_opts)?;
        if rep.error_count > 0 {
            refusals.push(ResizeRefusal::VerificationFailed {
                errors: rep.error_count,
                first: rep.errors().take(3).map(|d| d.to_string()).collect(),
            });
        } else if !rep.is_complete() {
            refusals.push(ResizeRefusal::VerificationIncomplete);
        }
        Some(rep)
    } else {
        None
    };

    let fork = alloc_fork(&vh);
    let inline = bitmap_extents(&fork);
    let inline_blocks: u64 = inline.iter().map(|e| u64::from(e.block_count)).sum();
    let alloc_overflows = inline_blocks < u64::from(fork.total_blocks);
    let capacity_bits = (inline_blocks * bs).saturating_mul(8);
    let max_blocks = u64::from(u32::MAX);
    let max_size_in_place = capacity_bits.min(max_blocks) * bs;

    let new_total = new_size / bs;
    if !new_size.is_multiple_of(bs) {
        refusals.push(ResizeRefusal::NotAligned {
            size: new_size,
            unit: bs,
        });
    }
    if new_total > max_blocks {
        refusals.push(ResizeRefusal::AboveMaximum {
            max_size: max_blocks * bs,
        });
    }
    let new_total = new_total.min(max_blocks);
    let direction = match new_total.cmp(&total) {
        std::cmp::Ordering::Greater => ResizeDirection::Grow,
        std::cmp::Ordering::Less => ResizeDirection::Shrink,
        std::cmp::Ordering::Equal => ResizeDirection::Unchanged,
    };

    if alloc_overflows {
        refusals.push(ResizeRefusal::Unsupported {
            reason: "the allocation file continues in the extents-overflow file".into(),
        });
        return Ok(HfsPlusResizePlan {
            direction,
            device_size,
            old_size: total * bs,
            new_size,
            block_size: bs as u32,
            old_total_blocks: total as u32,
            new_total_blocks: new_total as u32,
            old_free_blocks: old_free,
            new_free_blocks: old_free,
            bitmap_extension: None,
            bitmap_blocks_released: 0,
            min_size: total * bs,
            max_size_in_place: total * bs,
            max_size: total * bs,
            hfsx: vh[0..2] == SIG_HFSX,
            journaled,
            refusals,
            verification,
            fingerprint: Fingerprint {
                device_size,
                header: vh,
                bitmap_crc: 0,
            },
            alloc_fork: fork,
            drop_extents: 0,
        });
    }

    // The shrink precondition range: everything from the new tail up to
    // the old tail must be free.
    let new_tail_start = new_total.saturating_sub(k);
    let old_tail_start = total - k.min(total);
    let range = (new_tail_start, old_tail_start);
    // A shrink may release trailing allocation-file extents (typically
    // one an earlier grow added at the old end) that the smaller volume's
    // bitmap does not need.
    let drop_extents = if new_total < total {
        droppable(&inline, bs, new_tail_start, new_total)
    } else {
        0
    };
    let scan = scan_bitmap(
        dev,
        &fork,
        bs,
        total,
        old_tail_start,
        new_tail_start.min(total),
        range,
        &tail_ranges(&inline, drop_extents),
    )?;

    // The smallest size: try releasing 0, 1, … trailing bitmap extents.
    let mut min_blocks = scan.last_used.map_or(1, |b| b + 1) + k;
    if drop_extents == 0 {
        let base = scan_bitmap(dev, &fork, bs, total, 0, 0, (0, 0), &[])?;
        min_blocks = base.last_used.map_or(1, |b| b + 1) + k;
    }
    for d in 1..inline.len() {
        let ign = tail_ranges(&inline, d);
        let alt = scan_bitmap(dev, &fork, bs, total, 0, 0, (0, 0), &ign)?;
        let m = alt.last_used.map_or(1, |b| b + 1) + k;
        let cap: u64 = inline[..inline.len() - d]
            .iter()
            .map(|e| u64::from(e.block_count))
            .sum::<u64>()
            * bs
            * 8;
        let first_dropped = ign.iter().map(|r| r.0).min().unwrap_or(0);
        if m <= cap && first_dropped + k >= m && m < min_blocks {
            min_blocks = m;
        }
    }
    let min_size = min_blocks.max(1536u64.div_ceil(bs) + k) * bs;
    // A bitmap extension could reach this far: the remaining inline
    // slots each add one extent, but one is all we place.
    let can_extend = opts.allow_bitmap_extension && inline.len() < 8;
    let max_size = if can_extend {
        max_blocks * bs
    } else {
        max_size_in_place
    };

    let mut bitmap_extension = None;
    let mut new_free = u64::from(old_free);
    match direction {
        ResizeDirection::Unchanged => {}
        ResizeDirection::Shrink => {
            if new_total < min_blocks {
                if let Some(first) = scan.first_used_in_range {
                    refusals.push(ResizeRefusal::AllocatedBeyondEnd {
                        first_block: first,
                        blocks: scan.used_in_range,
                    });
                } else {
                    refusals.push(ResizeRefusal::BelowMinimum { min_size });
                }
                let bitmap_end = inline[..inline.len() - drop_extents]
                    .iter()
                    .map(|e| u64::from(e.start_block) + u64::from(e.block_count))
                    .max()
                    .unwrap_or(0);
                if bitmap_end > new_tail_start {
                    refusals.push(ResizeRefusal::BitmapRelocationRequired);
                }
            }
            new_free = scan.free_below_b;
        }
        ResizeDirection::Grow => {
            if new_total > capacity_bits {
                let need_bytes = new_total.div_ceil(8);
                let need_blocks = need_bytes.div_ceil(bs);
                let extra = need_blocks - inline_blocks;
                // Past the old device's end, so a partition-relative
                // alternate header beyond the old volume is not inside it.
                let start = if device_size < new_size {
                    total.max(device_size.div_ceil(bs))
                } else {
                    total
                };
                // Round up to the allocation file's clump, like the kernel,
                // so the next grow is likely to fit without another extent.
                let clump = (u64::from(fork.clump_size) / bs).max(1);
                let rounded = extra.div_ceil(clump) * clump;
                let extra = if start + rounded + k <= new_total {
                    rounded
                } else {
                    extra
                };
                if !opts.allow_bitmap_extension {
                    refusals.push(ResizeRefusal::BitmapExtensionUnsupported {
                        reason: "bitmap extension is disabled".into(),
                    });
                } else if inline.len() >= 8 {
                    refusals.push(ResizeRefusal::BitmapExtensionUnsupported {
                        reason: "the allocation file already uses all eight inline extents".into(),
                    });
                } else if start + extra + k > new_total || extra > u64::from(u32::MAX) {
                    refusals.push(ResizeRefusal::BitmapExtensionUnsupported {
                        reason: format!(
                            "the {extra} new bitmap block(s) do not fit in the added space"
                        ),
                    });
                } else {
                    bitmap_extension = Some(ExtentDescriptor {
                        start_block: start as u32,
                        block_count: extra as u32,
                    });
                }
            }
            // Final free count: unchanged below the old tail; the old
            // tail and the added space are free except the new tail (which
            // lies inside `[old_tail_start, new_total)` on a grow) and the
            // bitmap extension (placed before the new tail).
            let extra = bitmap_extension.map_or(0, |e| u64::from(e.block_count));
            new_free = (scan.free_below_a + (new_total - old_tail_start)).saturating_sub(k + extra);
        }
    }

    Ok(HfsPlusResizePlan {
        direction,
        device_size,
        old_size: total * bs,
        new_size,
        block_size: bs as u32,
        old_total_blocks: total as u32,
        new_total_blocks: new_total as u32,
        old_free_blocks: old_free,
        new_free_blocks: new_free.min(u64::from(u32::MAX)) as u32,
        bitmap_extension,
        bitmap_blocks_released: if direction == ResizeDirection::Shrink {
            inline[inline.len() - drop_extents..]
                .iter()
                .map(|e| e.block_count)
                .sum()
        } else {
            0
        },
        min_size,
        max_size_in_place,
        max_size,
        hfsx: vh[0..2] == SIG_HFSX,
        journaled,
        refusals,
        verification,
        fingerprint: Fingerprint {
            device_size,
            header: vh,
            bitmap_crc: scan.crc,
        },
        alloc_fork: fork,
        drop_extents: if direction == ResizeDirection::Shrink {
            drop_extents
        } else {
            0
        },
    })
}

/// Copy-on-write view of the allocation bitmap, block by block. Fork
/// blocks below `existing` are read from disk on first touch; later ones
/// (a fresh extension) start zeroed.
struct BitmapEdit {
    bs: u64,
    extents: Vec<ExtentDescriptor>,
    existing: u64,
    cache: std::collections::BTreeMap<u64, Vec<u8>>,
}

impl BitmapEdit {
    fn new(bs: u64, extents: Vec<ExtentDescriptor>, existing: u64) -> Self {
        Self {
            bs,
            extents,
            existing,
            cache: std::collections::BTreeMap::new(),
        }
    }

    /// Device byte offset of fork block `fb`.
    fn dev_offset(&self, fb: u64) -> Result<u64> {
        let mut walked = 0u64;
        for e in &self.extents {
            let n = u64::from(e.block_count);
            if fb < walked + n {
                return Ok((u64::from(e.start_block) + fb - walked) * self.bs);
            }
            walked += n;
        }
        Err(crate::Error::InvalidImage(format!(
            "hfs+ resize: bitmap block {fb} is past the allocation file"
        )))
    }

    fn block(&mut self, dev: &mut dyn BlockDevice, fb: u64) -> Result<&mut Vec<u8>> {
        if !self.cache.contains_key(&fb) {
            let mut buf = vec![0u8; self.bs as usize];
            if fb < self.existing {
                let off = self.dev_offset(fb)?;
                dev.read_at(off, &mut buf)?;
            }
            self.cache.insert(fb, buf);
        }
        Ok(self.cache.get_mut(&fb).unwrap())
    }

    /// Set (`val`) or clear the bits of blocks `[start, end)`; returns how
    /// many bits changed.
    fn fill(&mut self, dev: &mut dyn BlockDevice, start: u64, end: u64, val: bool) -> Result<u64> {
        let bits_per_block = self.bs * 8;
        let mut changed = 0u64;
        let mut b = start;
        while b < end {
            let fb = b / bits_per_block;
            let blk_end = ((fb + 1) * bits_per_block).min(end);
            let base = fb * bits_per_block;
            let buf = self.block(dev, fb)?;
            while b < blk_end {
                let i = ((b - base) / 8) as usize;
                if (b - base).is_multiple_of(8) && b + 8 <= blk_end {
                    let want = if val { 0xFF } else { 0x00 };
                    changed += u64::from((buf[i] ^ want).count_ones());
                    buf[i] = want;
                    b += 8;
                    continue;
                }
                let m = 0x80u8 >> ((b - base) % 8);
                if (buf[i] & m != 0) != val {
                    changed += 1;
                }
                if val {
                    buf[i] |= m;
                } else {
                    buf[i] &= !m;
                }
                b += 1;
            }
        }
        Ok(changed)
    }

    fn get(&mut self, dev: &mut dyn BlockDevice, blk: u64) -> Result<bool> {
        let bits_per_block = self.bs * 8;
        let fb = blk / bits_per_block;
        let r = blk - fb * bits_per_block;
        let buf = self.block(dev, fb)?;
        Ok(buf[(r / 8) as usize] & (0x80 >> (r % 8)) != 0)
    }

    /// Write every touched block out, new (extension) blocks first.
    fn write(&mut self, dev: &mut dyn BlockDevice) -> Result<()> {
        let blocks: Vec<u64> = self.cache.keys().copied().collect();
        for pass_new in [true, false] {
            for &fb in &blocks {
                if (fb >= self.existing) == pass_new {
                    let off = self.dev_offset(fb)?;
                    dev.write_at(off, &self.cache[&fb])?;
                }
            }
        }
        self.cache.clear();
        Ok(())
    }
}

fn put32(vh: &mut [u8; 512], off: usize, v: u32) {
    vh[off..off + 4].copy_from_slice(&v.to_be_bytes());
}

/// Check, without writing, that `plan` is feasible and still describes
/// `dev`: the same volume header bytes, the same allocation bitmap, and
/// a device of the planned size (or, for a grow, at least the new size).
pub fn check_resize_plan(dev: &mut dyn BlockDevice, plan: &HfsPlusResizePlan) -> Result<()> {
    if !plan.is_feasible() {
        return Err(refusal_error("hfs+", &plan.refusals));
    }
    let vh = read_header(dev)?;
    if vh != plan.fingerprint.header {
        return Err(crate::Error::InvalidArgument(
            "hfs+ resize: the volume header differs from the one the plan was made from \
             (stale plan, or the wrong device) — plan again"
                .into(),
        ));
    }
    let cur = dev.total_size();
    let grow_dir = plan.direction == ResizeDirection::Grow;
    if cur != plan.device_size && !(grow_dir && cur >= plan.new_size) {
        return Err(crate::Error::InvalidArgument(format!(
            "hfs+ resize: device is {cur} bytes; the plan was made on a {}-byte device{}",
            plan.device_size,
            if grow_dir {
                format!(
                    " (a grow also accepts a device of at least {} bytes)",
                    plan.new_size
                )
            } else {
                String::new()
            }
        )));
    }
    let bs = u64::from(plan.block_size);
    let total = u64::from(plan.old_total_blocks);
    let crc = scan_bitmap(dev, &plan.alloc_fork, bs, total, 0, 0, (0, 0), &[])?.crc;
    if crc != plan.fingerprint.bitmap_crc {
        return Err(crate::Error::InvalidArgument(
            "hfs+ resize: the allocation bitmap changed since the plan was made — plan again"
                .into(),
        ));
    }
    Ok(())
}

/// Carry out a feasible plan from [`plan_resize`] on `dev`.
///
/// `dev` must hold exactly the volume the plan was computed on (see
/// [`check_resize_plan`]). For a grow it must already be at least
/// [`HfsPlusResizePlan::new_size`] bytes — grow the device first, then
/// apply. A shrink leaves the device's size alone; cut it to
/// [`HfsPlusResizePlan::new_size`] afterwards.
///
/// See the [module docs](self) for the write order and why every crash
/// point leaves a usable volume.
pub fn apply_resize(dev: &mut dyn BlockDevice, plan: &HfsPlusResizePlan) -> Result<()> {
    check_resize_plan(dev, plan)?;
    let cur = dev.total_size();
    let grow_dir = plan.direction == ResizeDirection::Grow;
    if grow_dir && cur < plan.new_size {
        return Err(crate::Error::InvalidArgument(format!(
            "hfs+ resize: grow the device to at least {} bytes before applying (it is {cur})",
            plan.new_size
        )));
    }
    let vh = plan.fingerprint.header;
    let bs = u64::from(plan.block_size);
    let geo = Geometry {
        bs,
        total: u64::from(plan.old_total_blocks),
        new_total: u64::from(plan.new_total_blocks),
        k: tail_blocks(bs),
    };
    match plan.direction {
        ResizeDirection::Grow => grow(dev, plan, vh, cur, geo),
        ResizeDirection::Shrink => shrink(dev, plan, vh, geo),
        _ => Ok(()),
    }
}

/// A filesystem resize together with the resize of the partition that
/// holds it. Produced by [`plan_resize_in_partition`].
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct HfsPlusPartitionResizePlan {
    /// The partition-table change.
    pub partition: crate::part::resize::PartitionResizePlan,
    /// The filesystem change, planned on the partition as it is now.
    pub filesystem: HfsPlusResizePlan,
}

impl HfsPlusPartitionResizePlan {
    /// True when both halves are feasible.
    pub fn is_feasible(&self) -> bool {
        self.partition.is_feasible() && self.filesystem.is_feasible()
    }
}

/// Plan resizing the HFS+ / HFSX volume in partition `index` (0-based;
/// `disk.img:N` is `N - 1`) of the GPT / APM / MBR disk `disk`, together
/// with its partition, to `new_size` bytes. `new_disk_size` also moves
/// the end of the disk (see
/// [`crate::part::resize::plan_partition_resize`]). Read-only.
pub fn plan_resize_in_partition(
    disk: &mut dyn BlockDevice,
    index: usize,
    new_size: u64,
    new_disk_size: Option<u64>,
    opts: &ResizeOpts,
) -> Result<HfsPlusPartitionResizePlan> {
    use crate::part::resize::{PartitionRefusal, plan_partition_resize};
    let mut partition = plan_partition_resize(disk, index, new_size / 512, new_disk_size)?;
    if !new_size.is_multiple_of(512) {
        partition.refusals.push(PartitionRefusal::InvalidSize {
            reason: format!("{new_size} is not a multiple of 512"),
        });
    }
    let off = partition.offset();
    let len = partition.old_size_lba * 512;
    let mut slice = crate::block::SlicedBackend::new(disk, off, len)?;
    let filesystem = plan_resize(&mut slice, new_size, opts)?;
    Ok(HfsPlusPartitionResizePlan {
        partition,
        filesystem,
    })
}

/// Carry out a plan from [`plan_resize_in_partition`]. Both halves are
/// checked against the disk before anything is written. A grow resizes
/// the partition (moving the GPT backup if the disk grew — grow the disk
/// image to [`crate::part::resize::PartitionResizePlan::new_disk_size`]
/// first) and then the filesystem; a shrink does the filesystem first,
/// then the partition — cut the disk image afterwards when it shrinks.
/// Each half has its own commit point (see the module docs here and in
/// [`crate::part::resize`]); between them the volume is valid and simply
/// smaller than its partition.
pub fn apply_resize_in_partition(
    disk: &mut dyn BlockDevice,
    plan: &HfsPlusPartitionResizePlan,
) -> Result<()> {
    use crate::part::resize::{apply_partition_resize, check_partition_plan};
    check_partition_plan(disk, &plan.partition)?;
    let off = plan.partition.offset();
    let old_len = plan.partition.old_size_lba * 512;
    let new_len = plan.partition.new_size_lba * 512;
    {
        let mut slice = crate::block::SlicedBackend::new(disk, off, old_len)?;
        check_resize_plan(&mut slice, &plan.filesystem)?;
    }
    if new_len >= old_len {
        apply_partition_resize(disk, &plan.partition)?;
        let mut slice = crate::block::SlicedBackend::new(disk, off, new_len)?;
        apply_resize(&mut slice, &plan.filesystem)
    } else {
        {
            let mut slice = crate::block::SlicedBackend::new(disk, off, old_len)?;
            apply_resize(&mut slice, &plan.filesystem)?;
        }
        apply_partition_resize(disk, &plan.partition)
    }
}

#[derive(Clone, Copy)]
struct Geometry {
    bs: u64,
    total: u64,
    new_total: u64,
    k: u64,
}

fn encode_fork(f: &ForkData) -> [u8; FORK_DATA_SIZE] {
    let mut b = [0u8; FORK_DATA_SIZE];
    b[0..8].copy_from_slice(&f.logical_size.to_be_bytes());
    b[8..12].copy_from_slice(&f.clump_size.to_be_bytes());
    b[12..16].copy_from_slice(&f.total_blocks.to_be_bytes());
    for (i, e) in f.extents.iter().enumerate() {
        b[16 + i * 8..20 + i * 8].copy_from_slice(&e.start_block.to_be_bytes());
        b[20 + i * 8..24 + i * 8].copy_from_slice(&e.block_count.to_be_bytes());
    }
    b
}

fn grow(
    dev: &mut dyn BlockDevice,
    plan: &HfsPlusResizePlan,
    vh: [u8; 512],
    cur: u64,
    g: Geometry,
) -> Result<()> {
    let Geometry {
        bs,
        total,
        new_total,
        k,
    } = g;
    let fork = plan.alloc_fork;
    let mut extents = bitmap_extents(&fork);
    let existing: u64 = extents.iter().map(|e| u64::from(e.block_count)).sum();
    let mut new_fork = fork;
    if let Some(ext) = plan.bitmap_extension {
        extents.push(ext);
        new_fork.extents[extents.len() - 1] = ext;
        new_fork.total_blocks += ext.block_count;
        new_fork.logical_size = u64::from(new_fork.total_blocks) * bs;
    } else if new_fork.logical_size < new_total.div_ceil(8) {
        new_fork.logical_size = u64::from(new_fork.total_blocks) * bs;
    }
    let old_tail = (total - k.min(total), total);
    let new_tail = (new_total - k, new_total);
    let ext_range = plan.bitmap_extension.map(|e| {
        (
            u64::from(e.start_block),
            u64::from(e.start_block) + u64::from(e.block_count),
        )
    });

    // Phase A: bits the old volume cannot see.
    let mut ed = BitmapEdit::new(bs, extents.clone(), existing);
    let cap_old = existing * bs * 8;
    ed.fill(dev, total, new_total.min(cap_old), false)?;
    if let Some((s, e)) = ext_range {
        ed.fill(dev, s, e, true)?;
    }
    ed.fill(dev, new_tail.0, new_tail.1, true)?;
    ed.write(dev)?;
    dev.sync()?;

    // The final header.
    let mut h2 = vh;
    put32(&mut h2, 44, new_total as u32);
    put32(&mut h2, 48, plan.new_free_blocks);
    put32(&mut h2, 0x44, be32(&vh, 0x44).wrapping_add(1));
    h2[FORK_ALLOCATION..FORK_ALLOCATION + FORK_DATA_SIZE].copy_from_slice(&encode_fork(&new_fork));

    // Alternate header(s): volume-relative, and device-relative when the
    // device is larger than the volume.
    let fs_avh = new_total * bs - 1024;
    let dev_avh = cur - 1024;
    dev.write_at(fs_avh, &h2)?;
    if dev_avh != fs_avh {
        dev.write_at(dev_avh, &h2)?;
    }
    dev.sync()?;

    // Commit, with the old tail still counted as used.
    let still_used = (old_tail.0..old_tail.1).filter(|&b| b < new_tail.0).count() as u32;
    let mut h1 = h2;
    put32(&mut h1, 48, plan.new_free_blocks.saturating_sub(still_used));
    dev.write_at(1024, &h1)?;
    dev.sync()?;

    // Phase B: release the old tail, wipe the stale alternate header(s).
    let mut ed = BitmapEdit::new(bs, extents, u64::from(new_fork.total_blocks));
    ed.fill(dev, old_tail.0, old_tail.1.min(new_tail.0), false)?;
    let mut stale = vec![total * bs - 1024];
    if plan.device_size - 1024 != total * bs - 1024 {
        stale.push(plan.device_size - 1024);
    }
    let mut wipe = Vec::new();
    for off in stale {
        if off == fs_avh || off == dev_avh || off + 512 > new_total * bs {
            continue;
        }
        let blk = off / bs;
        if blk >= new_tail.0 || ext_range.is_some_and(|(s, e)| blk >= s && blk < e) {
            continue;
        }
        if !ed.get(dev, blk)? {
            wipe.push(off);
        }
    }
    ed.write(dev)?;
    for off in wipe {
        dev.write_at(off, &[0u8; 512])?;
    }
    dev.write_at(1024, &h2)?;
    dev.sync()?;
    Ok(())
}

fn shrink(
    dev: &mut dyn BlockDevice,
    plan: &HfsPlusResizePlan,
    vh: [u8; 512],
    g: Geometry,
) -> Result<()> {
    let Geometry {
        bs,
        total,
        new_total,
        k,
    } = g;
    let extents = bitmap_extents(&plan.alloc_fork);
    let existing: u64 = extents.iter().map(|e| u64::from(e.block_count)).sum();
    let new_tail = (new_total - k, new_total);
    // The allocation fork after releasing trailing extents.
    let mut new_fork = plan.alloc_fork;
    let keep = extents.len() - plan.drop_extents;
    for e in new_fork.extents.iter_mut().skip(keep) {
        *e = ExtentDescriptor::default();
    }
    new_fork.total_blocks = extents[..keep].iter().map(|e| e.block_count).sum();
    new_fork.logical_size = new_fork
        .logical_size
        .min(u64::from(new_fork.total_blocks) * bs);
    let kept_bits = u64::from(new_fork.total_blocks) * bs * 8;

    // Phase A: reserve the new tail inside the old volume.
    let mut ed = BitmapEdit::new(bs, extents.clone(), existing);
    let newly = ed.fill(dev, new_tail.0, new_tail.1, true)?;
    ed.write(dev)?;
    dev.sync()?;
    let mut h0 = vh;
    put32(&mut h0, 48, be32(&vh, 48).saturating_sub(newly as u32));
    dev.write_at(1024, &h0)?;
    dev.sync()?;

    // The new alternate header.
    let mut h2 = vh;
    put32(&mut h2, 44, new_total as u32);
    put32(&mut h2, 48, plan.new_free_blocks);
    put32(&mut h2, 0x44, be32(&vh, 0x44).wrapping_add(1));
    if u64::from(be32(&vh, 0x34)) >= new_total {
        put32(&mut h2, 0x34, 0);
    }
    if plan.drop_extents > 0 {
        h2[FORK_ALLOCATION..FORK_ALLOCATION + FORK_DATA_SIZE]
            .copy_from_slice(&encode_fork(&new_fork));
    }
    dev.write_at(new_total * bs - 1024, &h2)?;
    dev.sync()?;

    // Commit.
    dev.write_at(1024, &h2)?;
    dev.sync()?;

    // Phase B: tidy what now lies past the end.
    let mut ed = BitmapEdit::new(bs, extents, existing);
    ed.fill(dev, new_total, total.min(kept_bits), false)?;
    ed.write(dev)?;
    let mut stale = vec![total * bs - 1024];
    if plan.device_size - 1024 != total * bs - 1024 {
        stale.push(plan.device_size - 1024);
    }
    for off in stale {
        if off >= new_total * bs {
            dev.write_at(off, &[0u8; 512])?;
        }
    }
    dev.sync()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{CrashInject, FailAfter, MemoryBackend};
    use crate::fs::hfs_plus::HfsPlus;
    use crate::fs::hfs_plus::verify::tests::sample;
    use crate::fs::hfs_plus::verify::verify;
    use crate::fs::verify::DiagCode;

    const MIB: u64 = 1024 * 1024;

    fn resized(dev: MemoryBackend, size: u64) -> MemoryBackend {
        let mut bytes = dev.into_bytes();
        bytes.resize(size as usize, 0);
        MemoryBackend::from_bytes(bytes)
    }

    fn assert_clean(dev: &mut MemoryBackend) {
        let r = verify(dev, &VerifyOpts::default()).unwrap();
        assert!(r.is_clean(), "{:#?}", r.diagnostics);
    }

    fn assert_payload(dev: &mut MemoryBackend) {
        let fs = HfsPlus::open(dev).unwrap();
        for i in [0usize, 7, 39] {
            let mut r = fs.open_file_reader(dev, &format!("/d/file{i}")).unwrap();
            let mut got = Vec::new();
            std::io::Read::read_to_end(&mut r, &mut got).unwrap();
            assert_eq!(got, vec![i as u8; 1000 + i * 300]);
        }
    }

    fn grow_to(dev: MemoryBackend, size: u64) -> MemoryBackend {
        let mut dev = resized(dev, size);
        let plan = plan_resize(&mut dev, size, &ResizeOpts::default()).unwrap();
        assert!(plan.is_feasible(), "{:?}", plan.refusals);
        apply_resize(&mut dev, &plan).unwrap();
        dev
    }

    #[test]
    fn grow_within_bitmap_capacity() {
        for cs in [false, true] {
            let dev = sample(cs);
            let mut dev = grow_to(dev, 64 * MIB);
            assert_clean(&mut dev);
            assert_payload(&mut dev);
            let fs = HfsPlus::open(&mut dev).unwrap();
            assert_eq!(fs.total_bytes(), 64 * MIB);
        }
    }

    #[test]
    fn grow_extends_the_bitmap() {
        let mut dev = sample(false);
        let plan = plan_resize(&mut dev, 600 * MIB, &ResizeOpts::default()).unwrap();
        assert!(plan.is_feasible(), "{:?}", plan.refusals);
        let ext = plan.bitmap_extension.expect("needs a bitmap extension");
        assert_eq!(u64::from(ext.start_block), 8 * MIB / 4096);
        // Planned on the old device, applied on the grown one.
        let mut dev = resized(dev, 600 * MIB);
        apply_resize(&mut dev, &plan).unwrap();
        assert_clean(&mut dev);
        assert_payload(&mut dev);
        // And the volume is writable afterwards.
        let mut fs = HfsPlus::open(&mut dev).unwrap();
        let big = vec![9u8; 300 * MIB as usize];
        fs.create_file(
            &mut dev,
            "/big",
            &mut std::io::Cursor::new(&big),
            big.len() as u64,
            0o644,
            0,
            0,
            0,
        )
        .unwrap();
        fs.flush(&mut dev).unwrap();
        assert_clean(&mut dev);
        fs.remove(&mut dev, "/big").unwrap();
        fs.flush(&mut dev).unwrap();
        drop(fs);

        // Shrinking back below the old size releases the extension.
        let plan = plan_resize(&mut dev, 6 * MIB, &ResizeOpts::default()).unwrap();
        assert!(plan.is_feasible(), "{:?}", plan.refusals);
        assert_eq!(plan.bitmap_blocks_released, ext.block_count);
        assert!(plan.min_size < 6 * MIB, "min {}", plan.min_size);
        // Crash at every point of that shrink, too.
        for n in 0..40u64 {
            let copy = MemoryBackend::from_bytes(dev.as_slice().to_vec());
            let mut ci = CrashInject::new(copy, FailAfter::Writes(n));
            apply_resize(&mut ci, &plan).unwrap();
            let crashed = ci.crashed();
            let mut copy = ci.into_inner();
            assert_crash_state_safe(&mut copy, n);
            if !crashed {
                break;
            }
        }
        apply_resize(&mut dev, &plan).unwrap();
        let mut dev = resized(dev, 6 * MIB);
        assert_clean(&mut dev);
        assert_payload(&mut dev);
    }

    #[test]
    fn grow_refused_without_extension() {
        let mut dev = sample(false);
        let opts = ResizeOpts {
            allow_bitmap_extension: false,
            ..ResizeOpts::default()
        };
        let plan = plan_resize(&mut dev, 600 * MIB, &opts).unwrap();
        assert!(matches!(
            plan.refusals[..],
            [ResizeRefusal::BitmapExtensionUnsupported { .. }]
        ));
        assert!(apply_resize(&mut dev, &plan).is_err());
        assert_eq!(plan.max_size_in_place, 128 * MIB);
    }

    #[test]
    fn shrink_then_cut() {
        for cs in [false, true] {
            let dev = sample(cs);
            let mut dev = grow_to(dev, 64 * MIB);
            let plan = plan_resize(&mut dev, 4 * MIB, &ResizeOpts::default()).unwrap();
            assert!(plan.is_feasible(), "{:?}", plan.refusals);
            assert_eq!(plan.direction, ResizeDirection::Shrink);
            apply_resize(&mut dev, &plan).unwrap();
            let mut dev = resized(dev, 4 * MIB);
            assert_clean(&mut dev);
            assert_payload(&mut dev);
        }
    }

    #[test]
    fn shrink_past_data_is_refused_with_minimum() {
        let mut dev = sample(false);
        let plan = plan_resize(&mut dev, 64 * 1024, &ResizeOpts::default()).unwrap();
        assert!(
            plan.refusals
                .iter()
                .any(|r| matches!(r, ResizeRefusal::AllocatedBeyondEnd { .. })),
            "{:?}",
            plan.refusals
        );
        assert!(plan.min_size > 64 * 1024 && plan.min_size < 8 * MIB);
        // The reported minimum itself is feasible.
        let plan = plan_resize(&mut dev, plan.min_size, &ResizeOpts::default()).unwrap();
        assert!(plan.is_feasible(), "{:?}", plan.refusals);
        apply_resize(&mut dev, &plan).unwrap();
        let mut dev = resized(dev, plan.new_size);
        assert_clean(&mut dev);
        assert_payload(&mut dev);
    }

    #[test]
    fn unaligned_and_damaged_are_refused() {
        let mut dev = sample(false);
        let plan = plan_resize(&mut dev, 8 * MIB + 512, &ResizeOpts::default()).unwrap();
        assert!(matches!(
            plan.refusals[..],
            [ResizeRefusal::NotAligned { .. }]
        ));
        // Damage the free count: verification refuses.
        let mut b = [0u8; 4];
        dev.read_at(1024 + 48, &mut b).unwrap();
        let free = u32::from_be_bytes(b) - 1;
        dev.write_at(1024 + 48, &free.to_be_bytes()).unwrap();
        let plan = plan_resize(&mut dev, 16 * MIB, &ResizeOpts::default()).unwrap();
        assert!(matches!(
            plan.refusals[..],
            [ResizeRefusal::VerificationFailed { .. }]
        ));
        // Dirty flag.
        let mut dev = sample(false);
        dev.read_at(1024 + 4, &mut b).unwrap();
        let attrs = u32::from_be_bytes(b) & !ATTR_UNMOUNTED;
        dev.write_at(1024 + 4, &attrs.to_be_bytes()).unwrap();
        let plan = plan_resize(&mut dev, 16 * MIB, &ResizeOpts::default()).unwrap();
        assert!(plan.refusals.contains(&ResizeRefusal::VolumeDirty));
    }

    #[test]
    fn stale_and_wrong_device_plans_are_rejected() {
        let mut a = sample(false);
        let plan = plan_resize(&mut a, 6 * MIB, &ResizeOpts::default()).unwrap();
        assert!(plan.is_feasible());
        // A different volume of the same shape.
        let mut b = sample(true);
        assert!(apply_resize(&mut b, &plan).is_err());
        // The same volume after a change.
        let mut fs = HfsPlus::open(&mut a).unwrap();
        fs.create_dir(&mut a, "/later", 0o755, 0, 0, 0).unwrap();
        fs.flush(&mut a).unwrap();
        assert!(apply_resize(&mut a, &plan).is_err());
        // A shrink plan on a device of another size.
        let mut a = sample(false);
        let plan = plan_resize(&mut a, 6 * MIB, &ResizeOpts::default()).unwrap();
        let mut bigger = resized(a, 16 * MIB);
        assert!(apply_resize(&mut bigger, &plan).is_err());
        // Applied once, the plan is spent.
        let mut a = sample(false);
        let plan = plan_resize(&mut a, 6 * MIB, &ResizeOpts::default()).unwrap();
        apply_resize(&mut a, &plan).unwrap();
        assert!(apply_resize(&mut a, &plan).is_err());
    }

    #[test]
    fn journaled_volume_with_empty_journal_resizes() {
        let mut dev = MemoryBackend::new(16 * MIB);
        let opts = crate::fs::hfs_plus::FormatOpts {
            journaled: true,
            ..Default::default()
        };
        let mut fs = HfsPlus::format(&mut dev, &opts).unwrap();
        fs.create_dir(&mut dev, "/x", 0o755, 0, 0, 0).unwrap();
        fs.flush(&mut dev).unwrap();
        drop(fs);
        let mut dev = resized(dev, 48 * MIB);
        let plan = plan_resize(&mut dev, 48 * MIB, &ResizeOpts::default()).unwrap();
        assert!(plan.journaled);
        assert!(plan.is_feasible(), "{:?}", plan.refusals);
        apply_resize(&mut dev, &plan).unwrap();
        assert_clean(&mut dev);
        HfsPlus::open(&mut dev).unwrap();
    }

    /// Classify a post-crash state: it must be the old or the new volume,
    /// possibly with leaked blocks / a stale free count / a stale
    /// alternate header — never a block in use but marked free.
    fn assert_crash_state_safe(dev: &mut MemoryBackend, n: u64) {
        let r = verify(dev, &VerifyOpts::default()).unwrap();
        for d in r.errors() {
            assert!(
                matches!(
                    d.code,
                    DiagCode::BitmapLeakedBlocks
                        | DiagCode::FreeCountMismatch
                        | DiagCode::AlternateHeaderMismatch
                        | DiagCode::AlternateHeaderMissing
                ),
                "after {n} writes: unsafe state {d}"
            );
        }
        assert_payload(dev);
    }

    #[test]
    fn every_crash_point_leaves_a_usable_volume() {
        for (grow_size, ext) in [(64 * MIB, false), (600 * MIB, true)] {
            let base = resized(sample(false), grow_size);
            let mut probe = MemoryBackend::from_bytes(base.as_slice().to_vec());
            let plan = plan_resize(&mut probe, grow_size, &ResizeOpts::default()).unwrap();
            assert_eq!(plan.bitmap_extension.is_some(), ext);
            for n in 0..40u64 {
                let dev = MemoryBackend::from_bytes(base.as_slice().to_vec());
                let mut ci = CrashInject::new(dev, FailAfter::Writes(n));
                apply_resize(&mut ci, &plan).unwrap();
                let crashed = ci.crashed();
                let mut dev = ci.into_inner();
                assert_crash_state_safe(&mut dev, n);
                if !crashed {
                    assert_clean(&mut dev);
                    break;
                }
            }
        }
        // Shrink.
        let base = grow_to(sample(false), 64 * MIB);
        let mut probe = MemoryBackend::from_bytes(base.as_slice().to_vec());
        let plan = plan_resize(&mut probe, 6 * MIB, &ResizeOpts::default()).unwrap();
        for n in 0..40u64 {
            let dev = MemoryBackend::from_bytes(base.as_slice().to_vec());
            let mut ci = CrashInject::new(dev, FailAfter::Writes(n));
            apply_resize(&mut ci, &plan).unwrap();
            let crashed = ci.crashed();
            let mut dev = ci.into_inner();
            assert_crash_state_safe(&mut dev, n);
            if !crashed {
                let mut dev = resized(dev, 6 * MIB);
                assert_clean(&mut dev);
                break;
            }
        }
    }

    #[test]
    fn grow_and_shrink_inside_gpt() {
        use crate::part::{Gpt, Partition, PartitionKind, PartitionTable};
        let mut disk = MemoryBackend::new(32 * MIB);
        let hfs_type = uuid::Uuid::parse_str("48465300-0000-11AA-AA11-00306543ECAC").unwrap();
        let g = Gpt::build_with_guids(
            vec![
                Partition::new(2048, 2048, PartitionKind::EfiSystem),
                Partition::new(4096, 16384, PartitionKind::Gpt(hfs_type)),
            ],
            uuid::Uuid::from_u128(0xd15c),
            {
                let mut n = 0u128;
                move || {
                    n += 1;
                    uuid::Uuid::from_u128(n)
                }
            },
        )
        .unwrap();
        g.write(&mut disk).unwrap();
        disk.write_at(2048 * 512, &[0xA5; 4096]).unwrap();
        // Put the sample volume into partition 2.
        let vol = sample(false);
        disk.write_at(4096 * 512, vol.as_slice()).unwrap();
        let before = Gpt::read(&mut disk).unwrap();

        // Grow to fill the disk, which itself grows to 64 MiB.
        let new = 64 * MIB - 4096 * 512 - 34 * 512;
        let new = new / 4096 * 4096;
        let plan =
            plan_resize_in_partition(&mut disk, 1, new, Some(64 * MIB), &ResizeOpts::default())
                .unwrap();
        assert!(
            plan.is_feasible(),
            "{:?} {:?}",
            plan.partition.refusals,
            plan.filesystem.refusals
        );
        assert!(
            apply_resize_in_partition(&mut disk, &plan).is_err(),
            "disk not grown yet"
        );
        let mut disk = resized(disk, 64 * MIB);
        apply_resize_in_partition(&mut disk, &plan).unwrap();
        let after = Gpt::read(&mut disk).unwrap();
        assert_eq!(after.disk_guid, before.disk_guid);
        assert_eq!(after.partitions[0], before.partitions[0]);
        assert_eq!(after.partitions[1].uuid, before.partitions[1].uuid);
        assert_eq!(after.partitions[1].size_lba * 512, new);
        let mut b = [0u8; 4096];
        disk.read_at(2048 * 512, &mut b).unwrap();
        assert_eq!(b, [0xA5; 4096]);
        {
            let mut part = MemoryBackend::from_bytes(
                disk.as_slice()[4096 * 512..4096 * 512 + new as usize].to_vec(),
            );
            assert_clean(&mut part);
            assert_payload(&mut part);
        }

        // Shrink back, and the disk with it.
        let plan = plan_resize_in_partition(
            &mut disk,
            1,
            6 * MIB,
            Some((4096 + 12288 + 34) * 512),
            &ResizeOpts::default(),
        )
        .unwrap();
        assert!(
            plan.is_feasible(),
            "{:?} {:?}",
            plan.partition.refusals,
            plan.filesystem.refusals
        );
        apply_resize_in_partition(&mut disk, &plan).unwrap();
        let mut disk = resized(disk, (4096 + 12288 + 34) * 512);
        let after = Gpt::read(&mut disk).unwrap();
        assert_eq!(after.partitions[1].size_lba, 12288);
        let mut part =
            MemoryBackend::from_bytes(disk.as_slice()[4096 * 512..(4096 + 12288) * 512].to_vec());
        assert_clean(&mut part);
        assert_payload(&mut part);
    }

    #[test]
    fn small_blocks_tiny_steps() {
        // 512-byte blocks: the alternate header spans two blocks, so a
        // one-block grow / shrink overlaps old and new tails.
        let mut dev = MemoryBackend::new(4 * MIB);
        let opts = crate::fs::hfs_plus::FormatOpts {
            block_size: 512,
            ..Default::default()
        };
        let mut fs = HfsPlus::format(&mut dev, &opts).unwrap();
        fs.create_dir(&mut dev, "/x", 0o755, 0, 0, 0).unwrap();
        fs.flush(&mut dev).unwrap();
        drop(fs);
        let mut size = 4 * MIB;
        for step in [-1024i64, -512, 512, 1024, -2048, 1536] {
            let new = (size as i64 + step) as u64;
            if step > 0 {
                dev = resized(dev, new);
            }
            let plan = plan_resize(&mut dev, new, &ResizeOpts::default()).unwrap();
            assert!(plan.is_feasible(), "step {step}: {:?}", plan.refusals);
            apply_resize(&mut dev, &plan).unwrap();
            if step < 0 {
                dev = resized(dev, new);
            }
            size = new;
            assert_clean(&mut dev);
        }
    }
}
