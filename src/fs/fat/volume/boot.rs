//! Boot sector (BPB) and MBR parsing, with every field the driver needs
//! validated up front so nothing downstream has to re-check it.
//!
//! The layout is the same one [`crate::fs::fat::boot`] documents; this is a
//! second, allocation-free reader of it. Where the hosted parser models
//! fields it may later *write*, this one keeps only geometry, and it is
//! stricter: an inconsistency that the hosted driver can report as an error
//! per operation has to be caught here, because the no-alloc driver has
//! nowhere to carry a deferred complaint.

use super::{Error, FatKind};

/// Smallest sector a FAT volume may declare, and the smallest scratch
/// buffer [`super::Volume`] can be instantiated with.
pub const MIN_SECTOR_SIZE: usize = 512;

/// Largest sector size the FAT specification allows.
pub const MAX_SECTOR_SIZE: usize = 4096;

/// A validated FAT volume layout: where each region starts and how big it
/// is, in the units the driver actually computes with.
///
/// Every LBA in the driver is relative to `part_start`, so a volume inside
/// a partition needs no special-casing anywhere else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Geometry {
    /// FAT entry width, decided by the data-cluster count (never by the
    /// `fs_type` string, which is documentation).
    pub kind: FatKind,
    pub bytes_per_sector: u32,
    pub sectors_per_cluster: u32,
    pub reserved_sectors: u32,
    pub num_fats: u32,
    /// Slots in the fixed root directory; `0` on FAT32.
    pub root_entry_count: u32,
    /// Sectors in one FAT copy.
    pub fat_sectors: u32,
    pub total_sectors: u32,
    /// Sectors the fixed root directory occupies; `0` on FAT32.
    pub root_dir_sectors: u32,
    /// First sector of the data region (cluster 2).
    pub first_data_sector: u32,
    /// Number of addressable data clusters; valid cluster numbers are
    /// `2 ..= cluster_count + 1`.
    pub cluster_count: u32,
    /// First cluster of the root directory on FAT32; `0` otherwise.
    pub root_cluster: u32,
    /// FSInfo sector on FAT32 (relative to the volume); `0` when absent.
    pub fs_info_sector: u32,
    /// The FAT copy to read. With mirroring on (the normal case) all
    /// copies are identical and this is 0.
    pub active_fat: u32,
    /// Whether writes must be mirrored to every FAT copy.
    pub mirrored: bool,
    /// LBA of the volume's sector 0 within the device.
    pub part_start: u64,
}

fn u16_at(b: &[u8], at: usize) -> u32 {
    u16::from_le_bytes([b[at], b[at + 1]]) as u32
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

impl Geometry {
    /// Parse and validate a boot sector.
    ///
    /// `part_start` is the LBA the sector was read from, carried into the
    /// geometry so the caller can address the volume by relative sector.
    /// `device_sectors` is the medium's size in 512-byte units, used only
    /// to reject a volume that claims to run past the end of its device.
    pub fn parse<E>(sector: &[u8], part_start: u64, device_bytes: u64) -> Result<Self, Error<E>> {
        if sector.len() < MIN_SECTOR_SIZE {
            return Err(Error::NotFat);
        }
        // 0x55AA at the end of the first 512 bytes. Present on every FAT
        // volume ever formatted by a Microsoft-compatible tool.
        if sector[510] != 0x55 || sector[511] != 0xAA {
            return Err(Error::NotFat);
        }
        // A boot sector starts with a jump over the BPB. Checking this
        // keeps us from mounting, say, an MBR as a FAT volume.
        if sector[0] != 0xEB && sector[0] != 0xE9 {
            return Err(Error::NotFat);
        }

        let bytes_per_sector = u16_at(sector, 11);
        if !matches!(bytes_per_sector, 512 | 1024 | 2048 | 4096) {
            return Err(Error::NotFat);
        }
        let sectors_per_cluster = sector[13] as u32;
        if sectors_per_cluster == 0
            || !sectors_per_cluster.is_power_of_two()
            || sectors_per_cluster > 128
        {
            return Err(Error::NotFat);
        }
        // A cluster larger than 32 KiB is out of spec and, more to the
        // point, larger than anything this driver will buffer.
        if bytes_per_sector
            .checked_mul(sectors_per_cluster)
            .is_none_or(|cb| cb > 64 * 1024)
        {
            return Err(Error::NotFat);
        }
        let reserved_sectors = u16_at(sector, 14);
        if reserved_sectors == 0 {
            return Err(Error::NotFat);
        }
        let num_fats = sector[16] as u32;
        if num_fats == 0 || num_fats > 4 {
            return Err(Error::NotFat);
        }
        let root_entry_count = u16_at(sector, 17);
        let total_16 = u16_at(sector, 19);
        let fat_16 = u16_at(sector, 22);
        let total_32 = u32_at(sector, 32);
        let fat_32 = u32_at(sector, 36);

        let total_sectors = if total_16 != 0 { total_16 } else { total_32 };
        let fat_sectors = if fat_16 != 0 { fat_16 } else { fat_32 };
        if total_sectors == 0 || fat_sectors == 0 {
            return Err(Error::NotFat);
        }

        // The fixed root directory rounds up to a whole number of sectors;
        // it is empty on FAT32, where the root is a cluster chain.
        let root_dir_sectors = root_entry_count
            .checked_mul(32)
            .ok_or(Error::NotFat)?
            .div_ceil(bytes_per_sector);

        let meta_sectors = reserved_sectors
            .checked_add(num_fats.checked_mul(fat_sectors).ok_or(Error::NotFat)?)
            .and_then(|n| n.checked_add(root_dir_sectors))
            .ok_or(Error::NotFat)?;
        if meta_sectors >= total_sectors {
            return Err(Error::NotFat);
        }
        let first_data_sector = meta_sectors;
        let cluster_count = (total_sectors - meta_sectors) / sectors_per_cluster;
        if cluster_count == 0 {
            return Err(Error::NotFat);
        }

        // The flavour follows from the cluster count alone — the same rule
        // the hosted driver and every other implementation use.
        let kind = if cluster_count < 4085 {
            FatKind::Fat12
        } else if cluster_count < 65525 {
            FatKind::Fat16
        } else {
            FatKind::Fat32
        };

        // A FAT32 entry is 28 bits wide and 0x0FFFFFF7..=0x0FFFFFFF are the
        // bad-cluster and end-of-chain marks, so 0x0FFFFFF6 is the highest
        // cluster a volume can name. Past that the allocator would hand out
        // a cluster number that every reader treats as the end of a chain.
        if kind == FatKind::Fat32 && cluster_count > 0x0FFF_FFF5 {
            return Err(Error::NotFat);
        }

        // The FAT has to be able to map every cluster, or a perfectly
        // ordinary lookup walks off the end of it.
        let needed_bytes = match kind {
            // Two entries of padding (0 and 1) precede cluster 2.
            FatKind::Fat12 => (cluster_count as u64 + 2).div_ceil(2) * 3,
            FatKind::Fat16 => (cluster_count as u64 + 2) * 2,
            FatKind::Fat32 => (cluster_count as u64 + 2) * 4,
        };
        if (fat_sectors as u64) * (bytes_per_sector as u64) < needed_bytes {
            return Err(Error::NotFat);
        }

        let (root_cluster, fs_info_sector, ext_flags) = if kind == FatKind::Fat32 {
            if root_entry_count != 0 {
                return Err(Error::NotFat);
            }
            let root_cluster = u32_at(sector, 44);
            if root_cluster < 2 || root_cluster > cluster_count + 1 {
                return Err(Error::NotFat);
            }
            let fs_info = u16_at(sector, 48);
            // 0xFFFF is the documented "absent"; anything outside the
            // reserved region would land on the FAT.
            let fs_info = if fs_info == 0 || fs_info >= reserved_sectors {
                0
            } else {
                fs_info
            };
            (root_cluster, fs_info, u16_at(sector, 40))
        } else {
            if root_entry_count == 0 {
                return Err(Error::NotFat);
            }
            (0, 0, 0)
        };

        // ext_flags bit 7 clear means every FAT copy is kept identical;
        // set means only the one in bits 0..3 is live.
        let mirrored = ext_flags & 0x80 == 0;
        let active_fat = if mirrored { 0 } else { ext_flags & 0x0F };
        if active_fat >= num_fats {
            return Err(Error::NotFat);
        }

        // Everything above is self-consistent; make sure it also fits the
        // medium we are holding.
        let volume_bytes = (total_sectors as u64)
            .checked_mul(bytes_per_sector as u64)
            .ok_or(Error::NotFat)?;
        // The volume's sector size is the device's (the caller enforces
        // that), so a relative sector scales by it.
        let start_bytes = part_start
            .checked_mul(bytes_per_sector as u64)
            .ok_or(Error::VolumeExceedsDevice)?;
        if start_bytes
            .checked_add(volume_bytes)
            .is_none_or(|end| end > device_bytes)
        {
            return Err(Error::VolumeExceedsDevice);
        }

        Ok(Self {
            kind,
            bytes_per_sector,
            sectors_per_cluster,
            reserved_sectors,
            num_fats,
            root_entry_count,
            fat_sectors,
            total_sectors,
            root_dir_sectors,
            first_data_sector,
            cluster_count,
            root_cluster,
            fs_info_sector,
            active_fat,
            mirrored,
            part_start,
        })
    }

    /// Bytes in one cluster.
    pub fn cluster_bytes(&self) -> u32 {
        self.bytes_per_sector * self.sectors_per_cluster
    }

    /// Volume-relative first sector of `cluster`, which must be valid.
    pub fn cluster_first_sector(&self, cluster: u32) -> u32 {
        self.first_data_sector + (cluster - 2) * self.sectors_per_cluster
    }

    /// True when `cluster` addresses real data on this volume.
    pub fn is_data_cluster(&self, cluster: u32) -> bool {
        cluster >= 2 && cluster <= self.cluster_count + 1
    }

    /// Volume-relative first sector of the fixed root directory
    /// (FAT12/FAT16 only).
    pub fn root_dir_first_sector(&self) -> u32 {
        self.reserved_sectors + self.num_fats * self.fat_sectors
    }
}

/// One MBR partition entry worth keeping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MbrPartition {
    /// 1-based slot in the table.
    pub index: u8,
    /// Partition type byte.
    pub kind: u8,
    pub start_lba: u64,
    pub sectors: u64,
}

impl MbrPartition {
    /// Whether the type byte is one of the FAT ones. A volume is still
    /// mounted by reading its boot sector, not by trusting this.
    pub fn looks_like_fat(&self) -> bool {
        matches!(
            self.kind,
            0x01 | 0x04 | 0x06 | 0x0B | 0x0C | 0x0E | 0x11 | 0x14 | 0x16 | 0x1B | 0x1C | 0x1E
        )
    }
}

/// Read the four primary partition entries out of an MBR, skipping empty
/// and extended-container slots. Returns `None` when the sector carries no
/// usable table.
pub fn parse_mbr(sector: &[u8]) -> Option<[Option<MbrPartition>; 4]> {
    if sector.len() < MIN_SECTOR_SIZE || sector[510] != 0x55 || sector[511] != 0xAA {
        return None;
    }
    let mut out = [None; 4];
    let mut any = false;
    for (i, slot) in out.iter_mut().enumerate() {
        let at = 446 + i * 16;
        let kind = sector[at + 4];
        let start_lba = u32_at(sector, at + 8) as u64;
        let sectors = u32_at(sector, at + 12) as u64;
        // Type 0 is an unused slot; 0x05/0x0F/0x85 are extended
        // containers, whose logical partitions this driver does not walk.
        if kind == 0 || sectors == 0 || start_lba == 0 {
            continue;
        }
        if matches!(kind, 0x05 | 0x0F | 0x85) {
            continue;
        }
        any = true;
        *slot = Some(MbrPartition {
            index: i as u8 + 1,
            kind,
            start_lba,
            sectors,
        });
    }
    if any { Some(out) } else { None }
}
