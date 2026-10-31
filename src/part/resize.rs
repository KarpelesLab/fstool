//! Partition resize plans: grow a partition into the free space after
//! it, shrink it, and move a GPT's backup structures when the disk
//! itself changes size.
//!
//! Like the filesystem resizers ([`crate::fs::resize`]) this is two
//! calls: [`plan_partition_resize`] (read-only, typed
//! [`PartitionRefusal`]s) and [`apply_partition_resize`], which refuses a
//! plan made from another table or disk size.
//!
//! The tables are edited **in place**: only the fields that change are
//! rewritten — the partition's ending LBA (GPT) or sector count (MBR,
//! APM), the GPT headers' backup location and last usable LBA, the
//! entry-array CRCs, the protective MBR's size, the APM driver
//! descriptor's block count and the `Apple_Free` entries around the
//! partition. Every other byte — the disk GUID, partition GUIDs, type
//! GUIDs, names, attribute bits, entry slots, boot code, the other
//! partitions — is preserved.
//!
//! Partitions keep their start; nothing is moved. A grow needs free
//! space directly after the partition (or the end of a disk being
//! enlarged); a shrink leaves the freed space unpartitioned (GPT, MBR)
//! or as an `Apple_Free` entry (APM).
//!
//! ## Order of writes
//!
//! **GPT.** The backup entry array and backup header are written first
//! (at the new end of the disk), then the primary entry array, then the
//! primary header — the commit point, one sector. A crash before it
//! leaves the old primary table, which is what every reader trusts
//! first. After it, the stale backup at the old end (when the disk grew)
//! is zeroed and the protective MBR's size updated.
//!
//! **MBR, APM.** A single sector write when the entry count does not
//! change (MBR always; APM when an existing `Apple_Free` entry is
//! resized). An APM edit that adds or removes an `Apple_Free` entry
//! rewrites the map blocks after the partition in one write.
//!
//! The disk is resized by the caller: grow the image before applying a
//! plan whose [`PartitionResizePlan::new_disk_size`] is larger, cut it
//! after applying one whose new size is smaller.

use std::string::{String, ToString};
use std::vec::Vec;

use crate::Result;
use crate::block::BlockDevice;

/// Which partition-table format a plan edits.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TableKind {
    /// GUID Partition Table.
    Gpt,
    /// Master Boot Record (primary partitions).
    Mbr,
    /// Apple Partition Map.
    Apm,
}

/// Why a partition resize cannot be carried out.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PartitionRefusal {
    /// The requested size runs into the next partition or past the end
    /// of the (new) disk.
    NoRoom {
        /// The largest size the partition can have, in 512-byte sectors.
        max_size_lba: u64,
    },
    /// A size of zero, or a disk size that is not a multiple of 512.
    InvalidSize {
        /// Why.
        reason: String,
    },
    /// Shrinking the disk would cut off (part of) another partition.
    DiskTooSmall {
        /// The smallest disk size that keeps every partition, bytes.
        min_disk_size: u64,
    },
    /// The partition is an MBR extended-partition container, or past the
    /// 2³²-sector MBR limit.
    MbrLimit {
        /// Why.
        reason: String,
    },
    /// The APM map has no room for the `Apple_Free` entry a shrink needs.
    ApmMapFull,
    /// The partition kind or table layout is not supported.
    Unsupported {
        /// Why.
        reason: String,
    },
}

impl core::fmt::Display for PartitionRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PartitionRefusal::NoRoom { max_size_lba } => write!(
                f,
                "not enough free space after the partition (at most {max_size_lba} sectors, {} bytes)",
                max_size_lba * 512
            ),
            PartitionRefusal::InvalidSize { reason } => write!(f, "invalid size: {reason}"),
            PartitionRefusal::DiskTooSmall { min_disk_size } => write!(
                f,
                "the disk cannot shrink below {min_disk_size} bytes without cutting a partition"
            ),
            PartitionRefusal::MbrLimit { reason } => write!(f, "MBR: {reason}"),
            PartitionRefusal::ApmMapFull => {
                f.write_str("the Apple Partition Map has no room for another entry")
            }
            PartitionRefusal::Unsupported { reason } => write!(f, "unsupported: {reason}"),
        }
    }
}

/// A plan to resize one partition (and possibly move the end of the
/// disk). Produced by [`plan_partition_resize`].
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct PartitionResizePlan {
    /// The table format.
    pub table: TableKind,
    /// The partition, as fstool numbers them (0-based; `disk.img:N` is
    /// index `N - 1`).
    pub index: usize,
    /// First sector of the partition (unchanged).
    pub start_lba: u64,
    /// Current length, 512-byte sectors.
    pub old_size_lba: u64,
    /// Length after the resize, 512-byte sectors.
    pub new_size_lba: u64,
    /// Disk size the plan was computed on, bytes.
    pub old_disk_size: u64,
    /// Disk size after the resize, bytes. Grow the disk to this before
    /// applying when it is larger; cut it after applying when smaller.
    pub new_disk_size: u64,
    /// Largest the partition could be on the new disk, sectors.
    pub max_size_lba: u64,
    /// Why the plan cannot be applied. Empty means feasible.
    pub refusals: Vec<PartitionRefusal>,
    /// The disk GUID (GPT), kept as is.
    pub disk_guid: Option<uuid::Uuid>,
    /// The partition's unique GUID (GPT), kept as is.
    pub partition_guid: Option<uuid::Uuid>,
    slot: usize,
    fingerprint: u32,
}

impl PartitionResizePlan {
    /// True when [`apply_partition_resize`] would carry the plan out.
    pub fn is_feasible(&self) -> bool {
        self.refusals.is_empty()
    }

    /// Byte offset of the partition on the disk.
    pub fn offset(&self) -> u64 {
        self.start_lba * 512
    }
}

const SECTOR: u64 = 512;

fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn le64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}
fn be32(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes(b[o..o + 4].try_into().unwrap())
}

/// Detect the table on `disk`.
fn detect(disk: &mut dyn BlockDevice) -> Result<TableKind> {
    if disk.total_size() < 1024 {
        return Err(crate::Error::InvalidImage(
            "partition resize: disk too small for a partition table".into(),
        ));
    }
    let mut s1 = [0u8; 8];
    disk.read_at(512, &mut s1)?;
    if &s1 == b"EFI PART" {
        return Ok(TableKind::Gpt);
    }
    if super::Apm::probe(disk) {
        return Ok(TableKind::Apm);
    }
    let mut s0 = [0u8; 512];
    disk.read_at(0, &mut s0)?;
    if s0[510..512] == [0x55, 0xAA] {
        return Ok(TableKind::Mbr);
    }
    Err(crate::Error::InvalidImage(
        "partition resize: no GPT, APM or MBR partition table found".into(),
    ))
}

// ---------------------------------------------------------------------
// GPT
// ---------------------------------------------------------------------

struct GptRaw {
    header: [u8; 512],
    entries: Vec<u8>,
    entries_lbas: u64,
    entry_size: usize,
    num_entries: usize,
    first_usable: u64,
    last_usable: u64,
}

fn read_gpt(disk: &mut dyn BlockDevice) -> Result<GptRaw> {
    // Full validation (CRCs, geometry caps) first.
    super::Gpt::read(disk)?;
    let mut header = [0u8; 512];
    disk.read_at(512, &mut header)?;
    let entries_lba = le64(&header, 72);
    let num_entries = le32(&header, 80) as usize;
    let entry_size = le32(&header, 84) as usize;
    let bytes = num_entries * entry_size;
    let mut entries = vec![0u8; bytes];
    disk.read_at(entries_lba * SECTOR, &mut entries)?;
    Ok(GptRaw {
        header,
        entries_lbas: (bytes as u64).div_ceil(SECTOR),
        entry_size,
        num_entries,
        first_usable: le64(&header, 40),
        last_usable: le64(&header, 48),
        entries,
    })
}

fn gpt_slot_range(raw: &GptRaw, slot: usize) -> (u64, u64) {
    let e = &raw.entries[slot * raw.entry_size..slot * raw.entry_size + 128];
    (le64(e, 32), le64(e, 40))
}

fn gpt_slot_used(raw: &GptRaw, slot: usize) -> bool {
    let e = &raw.entries[slot * raw.entry_size..slot * raw.entry_size + 16];
    e.iter().any(|&b| b != 0)
}

fn gpt_header_crc(h: &mut [u8; 512]) {
    let size = (le32(h, 12) as usize).clamp(92, 512);
    h[16..20].fill(0);
    let crc = crate::crc::crc32(&h[..size]);
    h[16..20].copy_from_slice(&crc.to_le_bytes());
}

/// Plan resizing partition `index` (0-based, as fstool lists them) to
/// `new_size_lba` 512-byte sectors. `new_disk_size` moves the end of the
/// disk too (`None` keeps it): pass the larger size to grow a partition
/// at the end of a disk into space that is about to be added, or a
/// smaller one to give the space back after a shrink. Read-only.
pub fn plan_partition_resize(
    disk: &mut dyn BlockDevice,
    index: usize,
    new_size_lba: u64,
    new_disk_size: Option<u64>,
) -> Result<PartitionResizePlan> {
    let kind = detect(disk)?;
    let old_disk_size = disk.total_size();
    let new_disk_size = new_disk_size.unwrap_or(old_disk_size);
    let mut refusals = Vec::new();
    if new_size_lba == 0 {
        refusals.push(PartitionRefusal::InvalidSize {
            reason: "a partition cannot be zero sectors".into(),
        });
    }
    if !new_disk_size.is_multiple_of(SECTOR) {
        refusals.push(PartitionRefusal::InvalidSize {
            reason: format!("disk size {new_disk_size} is not a multiple of 512"),
        });
    }
    let new_lbas = new_disk_size / SECTOR;
    let fp = fingerprint_at_size(disk, kind, old_disk_size)?;
    let mut plan = PartitionResizePlan {
        table: kind,
        index,
        start_lba: 0,
        old_size_lba: 0,
        new_size_lba,
        old_disk_size,
        new_disk_size,
        max_size_lba: 0,
        refusals: Vec::new(),
        disk_guid: None,
        partition_guid: None,
        slot: 0,
        fingerprint: fp,
    };
    match kind {
        TableKind::Gpt => {
            let raw = read_gpt(disk)?;
            let slot = (0..raw.num_entries)
                .filter(|&s| gpt_slot_used(&raw, s))
                .nth(index)
                .ok_or_else(|| {
                    crate::Error::InvalidArgument(format!("GPT has no partition {}", index + 1))
                })?;
            let (start, end) = gpt_slot_range(&raw, slot);
            plan.slot = slot;
            plan.start_lba = start;
            plan.old_size_lba = end + 1 - start;
            plan.disk_guid = Some(super::uuid_from_gpt_bytes(
                raw.header[56..72].try_into().unwrap(),
            ));
            let e = &raw.entries[slot * raw.entry_size..];
            plan.partition_guid = Some(super::uuid_from_gpt_bytes(e[16..32].try_into().unwrap()));
            // New last usable LBA: the standard layout relative to the new
            // end when the disk changes size, the current one otherwise.
            let last_usable = if new_disk_size == old_disk_size {
                raw.last_usable
            } else {
                new_lbas.saturating_sub(2 + raw.entries_lbas)
            };
            let mut limit = last_usable;
            let mut others_end = raw.first_usable;
            for s in 0..raw.num_entries {
                if s == slot || !gpt_slot_used(&raw, s) {
                    continue;
                }
                let (ps, pe) = gpt_slot_range(&raw, s);
                if ps > start {
                    limit = limit.min(ps - 1);
                }
                others_end = others_end.max(pe);
            }
            plan.max_size_lba = (limit + 1).saturating_sub(start);
            if others_end > last_usable {
                refusals.push(PartitionRefusal::DiskTooSmall {
                    min_disk_size: (others_end + 2 + raw.entries_lbas) * SECTOR,
                });
            }
        }
        TableKind::Mbr => {
            let mut s0 = [0u8; 512];
            disk.read_at(0, &mut s0)?;
            if index >= 4 {
                return Err(crate::Error::InvalidArgument(format!(
                    "MBR partition {} is not a primary partition",
                    index + 1
                )));
            }
            let ent = |i: usize| &s0[446 + i * 16..446 + i * 16 + 16];
            let e = ent(index);
            let ty = e[4];
            let start = u64::from(le32(e, 8));
            let size = u64::from(le32(e, 12));
            if ty == 0 || size == 0 {
                return Err(crate::Error::InvalidArgument(format!(
                    "MBR partition {} is empty",
                    index + 1
                )));
            }
            if matches!(ty, 0x05 | 0x0F | 0x85) {
                refusals.push(PartitionRefusal::MbrLimit {
                    reason: "an extended-partition container cannot be resized".into(),
                });
            }
            if ty == 0xEE {
                refusals.push(PartitionRefusal::Unsupported {
                    reason: "this is a GPT protective entry".into(),
                });
            }
            plan.slot = index;
            plan.start_lba = start;
            plan.old_size_lba = size;
            let mut limit = new_lbas.saturating_sub(1);
            let mut others_end = 0u64;
            for i in 0..4 {
                let o = ent(i);
                let (os, on) = (u64::from(le32(o, 8)), u64::from(le32(o, 12)));
                if i == index || o[4] == 0 || on == 0 {
                    continue;
                }
                if os > start {
                    limit = limit.min(os - 1);
                }
                others_end = others_end.max(os + on);
            }
            limit = limit.min(u64::from(u32::MAX) + start - 1);
            plan.max_size_lba = (limit + 1).saturating_sub(start);
            if others_end * SECTOR > new_disk_size {
                refusals.push(PartitionRefusal::DiskTooSmall {
                    min_disk_size: others_end * SECTOR,
                });
            }
            if new_size_lba > u64::from(u32::MAX) {
                refusals.push(PartitionRefusal::MbrLimit {
                    reason: "MBR sizes are limited to 2^32 sectors".into(),
                });
            }
        }
        TableKind::Apm => {
            let map = read_apm(disk)?;
            let e = map.get(index).ok_or_else(|| {
                crate::Error::InvalidArgument(format!("APM has no partition {}", index + 1))
            })?;
            let ty = apm_type(e);
            if ty == "Apple_partition_map" || ty == "Apple_Free" {
                refusals.push(PartitionRefusal::Unsupported {
                    reason: format!("an {ty} entry cannot be resized"),
                });
            }
            let start = u64::from(be32(e, 8));
            plan.slot = index;
            plan.start_lba = start;
            plan.old_size_lba = u64::from(be32(e, 12));
            let mut limit = new_lbas.saturating_sub(1);
            let mut others_end = 0u64;
            for (i, o) in map.iter().enumerate() {
                if i == index || apm_type(o) == "Apple_Free" {
                    continue;
                }
                let (os, on) = (u64::from(be32(o, 8)), u64::from(be32(o, 12)));
                if os > start {
                    limit = limit.min(os - 1);
                }
                others_end = others_end.max(os + on);
            }
            limit = limit.min(u64::from(u32::MAX) + start - 1);
            plan.max_size_lba = (limit + 1).saturating_sub(start);
            if others_end * SECTOR > new_disk_size {
                refusals.push(PartitionRefusal::DiskTooSmall {
                    min_disk_size: others_end * SECTOR,
                });
            }
            // A shrink (or a grow that leaves a gap) needs an Apple_Free
            // entry after the partition; check there is room for one.
            let end_new = start + new_size_lba;
            let next_start = start + plan.max_size_lba;
            let gap_after = next_start > end_new;
            let free_after = map
                .get(index + 1)
                .is_some_and(|n| apm_type(n) == "Apple_Free");
            let capacity = map
                .iter()
                .find(|m| apm_type(m) == "Apple_partition_map")
                .map_or(map.len() as u64, |m| u64::from(be32(m, 12)));
            let free_entries_in_gap = apm_free_entries_after(&map, index, next_start);
            let count_after = map.len() - free_entries_in_gap + usize::from(gap_after);
            if gap_after && !free_after && count_after as u64 > capacity {
                refusals.push(PartitionRefusal::ApmMapFull);
            }
        }
    }
    if new_size_lba > plan.max_size_lba {
        refusals.push(PartitionRefusal::NoRoom {
            max_size_lba: plan.max_size_lba,
        });
    }
    plan.refusals = refusals;
    Ok(plan)
}

/// Carry out a feasible plan on `disk`, whose size must be
/// [`PartitionResizePlan::new_disk_size`] when that is larger than the
/// planned disk, and the planned size otherwise.
pub fn apply_partition_resize(
    disk: &mut dyn BlockDevice,
    plan: &PartitionResizePlan,
) -> Result<()> {
    check_partition_plan(disk, plan)?;
    match plan.table {
        TableKind::Gpt => apply_gpt(disk, plan),
        TableKind::Mbr => apply_mbr(disk, plan),
        TableKind::Apm => apply_apm(disk, plan),
    }
}

/// Validate that `plan` still describes `disk` (same table bytes, the
/// expected disk size) without changing anything.
pub fn check_partition_plan(disk: &mut dyn BlockDevice, plan: &PartitionResizePlan) -> Result<()> {
    if !plan.is_feasible() {
        let list: Vec<String> = plan.refusals.iter().map(|r| r.to_string()).collect();
        return Err(crate::Error::InvalidArgument(format!(
            "partition resize refused: {}",
            list.join("; ")
        )));
    }
    let want_size = plan.new_disk_size.max(plan.old_disk_size);
    let cur = disk.total_size();
    if cur != want_size && cur != plan.old_disk_size {
        return Err(crate::Error::InvalidArgument(format!(
            "partition resize: disk is {cur} bytes, the plan expects {want_size}"
        )));
    }
    if plan.new_disk_size > plan.old_disk_size && cur < plan.new_disk_size {
        return Err(crate::Error::InvalidArgument(format!(
            "partition resize: grow the disk to {} bytes before applying",
            plan.new_disk_size
        )));
    }
    // The fingerprint covers the disk size; recompute it as of planning.
    let kind = detect(disk)?;
    if kind != plan.table {
        return Err(crate::Error::InvalidArgument(
            "partition resize: the partition table changed kind since the plan was made".into(),
        ));
    }
    let fp = fingerprint_at_size(disk, kind, plan.old_disk_size)?;
    if fp != plan.fingerprint {
        return Err(crate::Error::InvalidArgument(
            "partition resize: the partition table differs from the one the plan was made \
             from (stale plan, or the wrong disk) — plan again"
                .into(),
        ));
    }
    Ok(())
}

/// A checksum of the table's bytes and of the disk size the plan saw
/// (the disk may have been grown since).
fn fingerprint_at_size(disk: &mut dyn BlockDevice, kind: TableKind, size: u64) -> Result<u32> {
    let mut crc = crate::crc::crc32(&size.to_le_bytes());
    let len = match kind {
        TableKind::Gpt => {
            let raw = read_gpt_unchecked(disk)?;
            crc = crate::crc::crc32_append(crc, &raw.entries);
            1024
        }
        TableKind::Mbr => 512,
        TableKind::Apm => {
            let mut b = [0u8; 512];
            disk.read_at(512, &mut b)?;
            ((u64::from(be32(&b, 4)).min(256) + 1) * SECTOR).min(disk.total_size())
        }
    };
    let mut buf = vec![0u8; len as usize];
    disk.read_at(0, &mut buf)?;
    Ok(crate::crc::crc32_append(crc, &buf))
}

/// The primary GPT without [`super::Gpt::read`]'s size checks (which
/// look at the backup's position relative to a disk that may have just
/// grown).
fn read_gpt_unchecked(disk: &mut dyn BlockDevice) -> Result<GptRaw> {
    let mut header = [0u8; 512];
    disk.read_at(512, &mut header)?;
    if &header[0..8] != b"EFI PART" {
        return Err(crate::Error::InvalidImage("GPT header vanished".into()));
    }
    let entries_lba = le64(&header, 72);
    let num_entries = (le32(&header, 80) as usize).min(4096);
    let entry_size = (le32(&header, 84) as usize).clamp(128, 4096);
    let bytes = num_entries * entry_size;
    let mut entries = vec![0u8; bytes];
    disk.read_at(entries_lba.saturating_mul(SECTOR), &mut entries)?;
    Ok(GptRaw {
        header,
        entries_lbas: (bytes as u64).div_ceil(SECTOR),
        entry_size,
        num_entries,
        first_usable: le64(&header, 40),
        last_usable: le64(&header, 48),
        entries,
    })
}

fn apply_gpt(disk: &mut dyn BlockDevice, plan: &PartitionResizePlan) -> Result<()> {
    let mut raw = read_gpt_unchecked(disk)?;
    let new_lbas = plan.new_disk_size / SECTOR;
    let resized_disk = plan.new_disk_size != plan.old_disk_size;
    // The entry.
    let off = plan.slot * raw.entry_size;
    let end = plan.start_lba + plan.new_size_lba - 1;
    raw.entries[off + 40..off + 48].copy_from_slice(&end.to_le_bytes());
    let entries_crc = crate::crc::crc32(&raw.entries);
    let last_usable = if resized_disk {
        new_lbas - 2 - raw.entries_lbas
    } else {
        raw.last_usable
    };
    let backup_lba = new_lbas - 1;
    let backup_entries_lba = if resized_disk {
        backup_lba - raw.entries_lbas
    } else {
        // Keep the backup array where it is.
        let mut b = [0u8; 512];
        disk.read_at(le64(&raw.header, 32) * SECTOR, &mut b)?;
        if &b[0..8] == b"EFI PART" {
            le64(&b, 72)
        } else {
            backup_lba - raw.entries_lbas
        }
    };
    let old_backup_lba = le64(&raw.header, 32);

    // Backup first.
    let mut backup = raw.header;
    backup[24..32].copy_from_slice(&backup_lba.to_le_bytes());
    backup[32..40].copy_from_slice(&1u64.to_le_bytes());
    backup[48..56].copy_from_slice(&last_usable.to_le_bytes());
    backup[72..80].copy_from_slice(&backup_entries_lba.to_le_bytes());
    backup[88..92].copy_from_slice(&entries_crc.to_le_bytes());
    gpt_header_crc(&mut backup);
    disk.write_at(backup_entries_lba * SECTOR, &raw.entries)?;
    disk.write_at(backup_lba * SECTOR, &backup)?;
    disk.sync()?;

    // Primary entries, then the primary header (commit).
    let entries_lba = le64(&raw.header, 72);
    disk.write_at(entries_lba * SECTOR, &raw.entries)?;
    let mut primary = raw.header;
    primary[32..40].copy_from_slice(&backup_lba.to_le_bytes());
    primary[48..56].copy_from_slice(&last_usable.to_le_bytes());
    primary[88..92].copy_from_slice(&entries_crc.to_le_bytes());
    gpt_header_crc(&mut primary);
    disk.sync()?;
    disk.write_at(SECTOR, &primary)?;
    disk.sync()?;

    if resized_disk {
        // The stale backup header, when it still lies on the disk.
        if old_backup_lba != backup_lba && (old_backup_lba + 1) * SECTOR <= disk.total_size() {
            disk.write_at(old_backup_lba * SECTOR, &[0u8; 512])?;
        }
        // Protective MBR size.
        let mut s0 = [0u8; 512];
        disk.read_at(0, &mut s0)?;
        let mut changed = false;
        for i in 0..4 {
            let o = 446 + i * 16;
            if s0[o + 4] == 0xEE && le32(&s0, o + 8) == 1 {
                let v = (new_lbas - 1).min(u64::from(u32::MAX)) as u32;
                s0[o + 12..o + 16].copy_from_slice(&v.to_le_bytes());
                changed = true;
            }
        }
        if changed {
            disk.write_at(0, &s0)?;
        }
        disk.sync()?;
    }
    Ok(())
}

/// Encode an LBA as an MBR CHS triple (255 heads, 63 sectors), or the
/// LBA-only placeholder past cylinder 1023.
fn chs(lba: u64) -> [u8; 3] {
    let (h_per_c, s_per_t) = (255u64, 63u64);
    let c = lba / (h_per_c * s_per_t);
    if c > 1023 {
        return [0xFE, 0xFF, 0xFF];
    }
    let h = (lba / s_per_t) % h_per_c;
    let s = lba % s_per_t + 1;
    [
        h as u8,
        (s as u8) | (((c >> 2) & 0xC0) as u8),
        (c & 0xFF) as u8,
    ]
}

fn apply_mbr(disk: &mut dyn BlockDevice, plan: &PartitionResizePlan) -> Result<()> {
    let mut s0 = [0u8; 512];
    disk.read_at(0, &mut s0)?;
    let o = 446 + plan.slot * 16;
    s0[o + 12..o + 16].copy_from_slice(&(plan.new_size_lba as u32).to_le_bytes());
    // Keep the CHS convention the entry already used.
    if s0[o + 5..o + 8] != [0xFE, 0xFF, 0xFF] && s0[o + 5..o + 8] != [0xFF, 0xFF, 0xFF] {
        let c = chs(plan.start_lba + plan.new_size_lba - 1);
        s0[o + 5..o + 8].copy_from_slice(&c);
    }
    disk.write_at(0, &s0)?;
    disk.sync()
}

// ---------------------------------------------------------------------
// APM
// ---------------------------------------------------------------------

fn read_apm(disk: &mut dyn BlockDevice) -> Result<Vec<[u8; 512]>> {
    let mut first = [0u8; 512];
    disk.read_at(SECTOR, &mut first)?;
    if &first[0..2] != b"PM" {
        return Err(crate::Error::InvalidImage("APM: no map at block 1".into()));
    }
    let n = be32(&first, 4).min(256);
    let mut out = Vec::new();
    for i in 0..n {
        let mut e = [0u8; 512];
        let off = (u64::from(i) + 1) * SECTOR;
        if off + SECTOR > disk.total_size() {
            break;
        }
        disk.read_at(off, &mut e)?;
        if &e[0..2] != b"PM" {
            break;
        }
        out.push(e);
    }
    Ok(out)
}

fn apm_type(e: &[u8; 512]) -> String {
    let t = &e[48..80];
    let n = t.iter().position(|&b| b == 0).unwrap_or(t.len());
    String::from_utf8_lossy(&t[..n]).to_string()
}

/// Number of Apple_Free entries lying in `(partition end, next_start)`,
/// i.e. inside the region a resize may reshape.
fn apm_free_entries_after(map: &[[u8; 512]], index: usize, next_start: u64) -> usize {
    let start = u64::from(be32(&map[index], 8));
    map.iter()
        .enumerate()
        .filter(|(i, e)| {
            *i != index
                && apm_type(e) == "Apple_Free"
                && u64::from(be32(&e[..], 8)) > start
                && u64::from(be32(&e[..], 8)) < next_start
        })
        .count()
}

fn apply_apm(disk: &mut dyn BlockDevice, plan: &PartitionResizePlan) -> Result<()> {
    let mut map = read_apm(disk)?;
    let orig = map.clone();
    let index = plan.slot;
    let start = plan.start_lba;
    let new_end = start + plan.new_size_lba; // exclusive
    let region_end = start + plan.max_size_lba; // exclusive: next partition or disk end
    let template = map.iter().find(|e| apm_type(e) == "Apple_Free").copied();
    // Resize the entry itself.
    let e = &mut map[index];
    let old_size = be32(e, 12);
    e[12..16].copy_from_slice(&(plan.new_size_lba as u32).to_be_bytes());
    let data_cnt = be32(e, 84);
    if data_cnt == old_size || u64::from(data_cnt) > plan.new_size_lba {
        e[84..88].copy_from_slice(&(plan.new_size_lba as u32).to_be_bytes());
    }
    // Reshape the free space between the partition and the next one:
    // drop the Apple_Free entries there, and put one back covering what
    // is left, right after the partition's entry.
    let in_region = |i: usize, e: &[u8; 512]| {
        i != index
            && apm_type(e) == "Apple_Free"
            && u64::from(be32(e, 8)) > start
            && u64::from(be32(e, 8)) < region_end
    };
    let region_free = map
        .iter()
        .enumerate()
        .find(|(i, e)| in_region(*i, e))
        .map(|(_, e)| *e);
    let mut kept: Vec<[u8; 512]> = Vec::with_capacity(map.len() + 1);
    for (i, e) in map.iter().enumerate() {
        if in_region(i, e) {
            continue;
        }
        kept.push(*e);
        if i == index && new_end < region_end {
            let mut f = region_free.or(template).unwrap_or_else(|| {
                let mut f = [0u8; 512];
                f[0..2].copy_from_slice(b"PM");
                f[48..58].copy_from_slice(b"Apple_Free");
                f
            });
            let count = (region_end - new_end) as u32;
            f[8..12].copy_from_slice(&(new_end as u32).to_be_bytes());
            f[12..16].copy_from_slice(&count.to_be_bytes());
            f[80..84].copy_from_slice(&0u32.to_be_bytes());
            f[84..88].copy_from_slice(&count.to_be_bytes());
            kept.push(f);
        }
    }
    let n = kept.len() as u32;
    for e in kept.iter_mut() {
        e[4..8].copy_from_slice(&n.to_be_bytes());
    }
    let old_n = map.len();
    // DDM block count when the disk changes size.
    if plan.new_disk_size != plan.old_disk_size {
        let mut ddm = [0u8; 512];
        disk.read_at(0, &mut ddm)?;
        if &ddm[0..2] == b"ER" {
            let bsz = u64::from(u16::from_be_bytes([ddm[2], ddm[3]])).max(512);
            let cnt = (plan.new_disk_size / bsz).min(u64::from(u32::MAX)) as u32;
            ddm[4..8].copy_from_slice(&cnt.to_be_bytes());
            disk.write_at(0, &ddm)?;
        }
    }
    if kept.len() == old_n {
        // Same entry count: rewrite only what changed, ordered so a crash
        // leaves a gap rather than an Apple_Free entry over live data —
        // the partition first on a shrink, last on a grow.
        let shrinking = plan.new_size_lba < plan.old_size_lba;
        let mut order: Vec<usize> = (0..kept.len()).filter(|&i| i != index).collect();
        if shrinking {
            order.insert(0, index);
        } else {
            order.push(index);
        }
        for i in order {
            if kept[i] != orig[i] {
                disk.write_at((i as u64 + 1) * SECTOR, &kept[i])?;
                disk.sync()?;
            }
        }
    } else {
        let mut buf = Vec::with_capacity(kept.len().max(old_n) * 512);
        for e in &kept {
            buf.extend_from_slice(e);
        }
        for _ in kept.len()..old_n {
            buf.extend_from_slice(&[0u8; 512]);
        }
        disk.write_at(SECTOR, &buf)?;
    }
    disk.sync()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::MemoryBackend;
    use crate::part::{Gpt, Partition, PartitionKind, PartitionTable};
    use uuid::Uuid;

    const MIB: u64 = 1024 * 1024;

    fn gpt_disk(size: u64) -> MemoryBackend {
        let mut d = MemoryBackend::new(size);
        let mut n = 0x100u128;
        let parts = vec![
            Partition {
                name: Some("first".into()),
                attributes: 1 << 60,
                ..Partition::new(2048, 2048, PartitionKind::EfiSystem)
            },
            Partition::new(4096, 8192, PartitionKind::LinuxFilesystem),
        ];
        let g = Gpt::build_with_guids(parts, Uuid::from_u128(0xd15c), move || {
            n += 1;
            Uuid::from_u128(n)
        })
        .unwrap();
        g.write(&mut d).unwrap();
        d
    }

    fn resized(d: MemoryBackend, size: u64) -> MemoryBackend {
        let mut b = d.into_bytes();
        b.resize(size as usize, 0);
        MemoryBackend::from_bytes(b)
    }

    #[test]
    fn gpt_grow_into_free_space_preserves_identity() {
        let mut d = gpt_disk(16 * MIB);
        let before = Gpt::read(&mut d).unwrap();
        let plan = plan_partition_resize(&mut d, 1, 16384, None).unwrap();
        assert!(plan.is_feasible(), "{:?}", plan.refusals);
        apply_partition_resize(&mut d, &plan).unwrap();
        let after = Gpt::read(&mut d).unwrap();
        assert_eq!(after.disk_guid, before.disk_guid);
        assert_eq!(after.partitions[0], before.partitions[0]);
        assert_eq!(after.partitions[1].size_lba, 16384);
        assert_eq!(after.partitions[1].uuid, before.partitions[1].uuid);
        // Too big.
        let plan = plan_partition_resize(&mut d, 1, 1 << 20, None).unwrap();
        assert!(matches!(
            plan.refusals[..],
            [PartitionRefusal::NoRoom { .. }]
        ));
        // Neighbour blocks a grow of the first partition.
        let plan = plan_partition_resize(&mut d, 0, 2049, None).unwrap();
        assert!(matches!(
            plan.refusals[..],
            [PartitionRefusal::NoRoom { max_size_lba: 2048 }]
        ));
    }

    #[test]
    fn gpt_disk_grow_and_shrink_move_the_backup() {
        let d = gpt_disk(8 * MIB);
        let mut d0 = MemoryBackend::from_bytes(d.as_slice().to_vec());
        let plan = plan_partition_resize(&mut d0, 1, 30000, Some(32 * MIB)).unwrap();
        assert!(plan.is_feasible(), "{:?}", plan.refusals);
        // Not grown yet: refused.
        assert!(apply_partition_resize(&mut d0, &plan).is_err());
        let mut d = resized(d, 32 * MIB);
        apply_partition_resize(&mut d, &plan).unwrap();
        let g = Gpt::read(&mut d).unwrap();
        assert_eq!(g.disk_guid, Uuid::from_u128(0xd15c));
        assert_eq!(g.partitions[1].size_lba, 30000);
        let mut b = [0u8; 512];
        d.read_at(32 * MIB - 512, &mut b).unwrap();
        assert_eq!(&b[0..8], b"EFI PART");
        d.read_at(8 * MIB - 512, &mut b).unwrap();
        assert_ne!(&b[0..8], b"EFI PART", "stale backup header wiped");
        // Shrink partition and disk back.
        let plan = plan_partition_resize(&mut d, 1, 4000, Some(6 * MIB)).unwrap();
        assert!(plan.is_feasible(), "{:?}", plan.refusals);
        apply_partition_resize(&mut d, &plan).unwrap();
        let mut d = resized(d, 6 * MIB);
        let g = Gpt::read(&mut d).unwrap();
        assert_eq!(g.partitions[1].size_lba, 4000);
        assert_eq!(g.partitions.len(), 2);
        // Cutting into a partition is refused.
        let plan = plan_partition_resize(&mut d, 0, 2048, Some(2 * MIB)).unwrap();
        assert!(
            plan.refusals
                .iter()
                .any(|r| matches!(r, PartitionRefusal::DiskTooSmall { .. }))
        );
    }

    #[test]
    fn stale_partition_plan_is_rejected() {
        let mut d = gpt_disk(16 * MIB);
        let plan = plan_partition_resize(&mut d, 1, 10000, None).unwrap();
        let mut other = gpt_disk(16 * MIB);
        // Same layout, but change a name: different bytes.
        let mut g = Gpt::read(&mut other).unwrap();
        g.partitions[1].name = Some("x".into());
        g.write(&mut other).unwrap();
        assert!(apply_partition_resize(&mut other, &plan).is_err());
        apply_partition_resize(&mut d, &plan).unwrap();
        assert!(apply_partition_resize(&mut d, &plan).is_err());
    }

    #[test]
    fn mbr_resize_in_place() {
        let mut d = MemoryBackend::new(16 * MIB);
        let m = crate::part::Mbr::new(vec![
            Partition::new(2048, 4096, PartitionKind::Fat32),
            Partition::new(8192, 4096, PartitionKind::LinuxFilesystem),
        ])
        .unwrap();
        m.write(&mut d).unwrap();
        d.write_at(0, b"bootcode").unwrap();
        let plan = plan_partition_resize(&mut d, 0, 6144, None).unwrap();
        assert!(plan.is_feasible());
        apply_partition_resize(&mut d, &plan).unwrap();
        let m2 = crate::part::Mbr::read(&mut d).unwrap();
        assert_eq!(m2.partitions()[0].size_lba, 6144);
        assert_eq!(m2.partitions()[1], m.partitions()[1]);
        let mut b = [0u8; 8];
        d.read_at(0, &mut b).unwrap();
        assert_eq!(&b, b"bootcode");
        let plan = plan_partition_resize(&mut d, 0, 6145, None).unwrap();
        assert!(!plan.is_feasible());
    }

    fn apm_entry(start: u32, count: u32, name: &str, ty: &str, n: u32) -> [u8; 512] {
        let mut e = [0u8; 512];
        e[0..2].copy_from_slice(b"PM");
        e[4..8].copy_from_slice(&n.to_be_bytes());
        e[8..12].copy_from_slice(&start.to_be_bytes());
        e[12..16].copy_from_slice(&count.to_be_bytes());
        e[16..16 + name.len()].copy_from_slice(name.as_bytes());
        e[48..48 + ty.len()].copy_from_slice(ty.as_bytes());
        e[84..88].copy_from_slice(&count.to_be_bytes());
        e
    }

    fn apm_disk() -> MemoryBackend {
        let mut d = MemoryBackend::new(8 * MIB);
        let blocks = (8 * MIB / 512) as u32;
        let mut ddm = [0u8; 512];
        ddm[0..2].copy_from_slice(b"ER");
        ddm[2..4].copy_from_slice(&512u16.to_be_bytes());
        ddm[4..8].copy_from_slice(&blocks.to_be_bytes());
        d.write_at(0, &ddm).unwrap();
        let ents = [
            apm_entry(1, 63, "Apple", "Apple_partition_map", 3),
            apm_entry(64, 4000, "disk image", "Apple_HFS", 3),
            apm_entry(4064, blocks - 4064, "", "Apple_Free", 3),
        ];
        for (i, e) in ents.iter().enumerate() {
            d.write_at((i as u64 + 1) * 512, e).unwrap();
        }
        d
    }

    #[test]
    fn apm_grow_consumes_free_and_shrink_recreates_it() {
        let mut d = apm_disk();
        let blocks = 8 * MIB / 512;
        // Grow to fill the disk: the Apple_Free entry disappears.
        let plan = plan_partition_resize(&mut d, 1, blocks - 64, None).unwrap();
        assert!(plan.is_feasible(), "{:?}", plan.refusals);
        apply_partition_resize(&mut d, &plan).unwrap();
        let a = crate::part::Apm::read(&mut d).unwrap();
        assert_eq!(a.partitions().len(), 2);
        assert_eq!(a.partitions()[1].size_lba, blocks - 64);
        assert_eq!(a.partitions()[1].name.as_deref(), Some("disk image"));
        // Shrink: an Apple_Free entry comes back after it.
        let plan = plan_partition_resize(&mut d, 1, 3000, None).unwrap();
        assert!(plan.is_feasible(), "{:?}", plan.refusals);
        apply_partition_resize(&mut d, &plan).unwrap();
        let a = crate::part::Apm::read(&mut d).unwrap();
        assert_eq!(a.partitions().len(), 3);
        assert_eq!(a.partitions()[2].start_lba, 64 + 3000);
        assert_eq!(a.partitions()[2].size_lba, blocks - 64 - 3000);
        assert_eq!(
            a.partitions()[2].kind,
            PartitionKind::Apm("Apple_Free".into())
        );
        // Partial grow: the free entry shrinks.
        let plan = plan_partition_resize(&mut d, 1, 5000, None).unwrap();
        apply_partition_resize(&mut d, &plan).unwrap();
        let a = crate::part::Apm::read(&mut d).unwrap();
        assert_eq!(a.partitions().len(), 3);
        assert_eq!(a.partitions()[2].start_lba, 64 + 5000);
        assert_eq!(a.partitions()[1].size_lba, 5000);
    }
}
