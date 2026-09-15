//! Laying a fresh exFAT volume down, with no allocator.
//!
//! ```text
//!   0..=11      main boot region: boot sector, 8 extended boot sectors,
//!               OEM parameters, reserved, boot checksum
//!   12..=23     backup boot region, identical
//!   FatOffset   the FAT: clusters 0 and 1 reserved, then the chains of the
//!               three metadata streams below
//!   heap        cluster 2..  allocation bitmap
//!               then         up-case table
//!               then         root directory: label, bitmap and up-case entries
//! ```
//!
//! Every sector is produced into one sector of stack and written through the
//! caller's [`SectorDriver`]; the data clusters after the root are free the
//! moment the bitmap says so, and their old contents are never touched. The
//! boot regions go last — backup, then main — so a format torn part-way does
//! not leave a boot sector describing structures that were never written.
//!
//! The up-case table is the one the exFAT specification recommends, the same
//! 5836 bytes `mkfs.exfat` and Windows write, so names on a card formatted
//! here compare case-insensitively across all of Unicode's simple mappings,
//! exactly as they would on a card formatted anywhere else.

use super::super::layout::{self, ENTRY_SIZE};
use super::{Error, SectorDriver, Volume};

/// The specification's recommended up-case table, compressed.
const UPCASE: &[u8] = include_bytes!("../upcase_table.bin");

/// Its checksum, as the up-case directory entry records it.
const UPCASE_CHECKSUM: u32 = 0xE619_D30D;

/// How [`Volume::format`] lays a volume out. The default picks the cluster
/// size from the volume's size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VolumeFormatOpts<'a> {
    /// Cluster size in bytes: a power of two from one sector to 32 MiB.
    /// `None` takes Microsoft's defaults — 4 KiB up to 256 MiB, 32 KiB up to
    /// 32 GiB, 128 KiB above.
    pub cluster_size: Option<u32>,
    /// The volume serial number. A real one should differ between cards.
    pub volume_serial: u32,
    /// The volume label: up to 11 UTF-16 code units, or empty for none.
    pub label: &'a str,
}

impl Default for VolumeFormatOpts<'_> {
    fn default() -> Self {
        Self {
            cluster_size: None,
            volume_serial: 0x1234_5678,
            label: "",
        }
    }
}

/// Sectors in one boot region.
const BOOT_REGION: u32 = 12;

/// A planned layout, before a byte is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Plan {
    pub(crate) ss: u32,
    pub(crate) spc: u32,
    pub(crate) volume_sectors: u64,
    pub(crate) fat_offset: u32,
    pub(crate) fat_length: u32,
    pub(crate) heap_offset: u32,
    pub(crate) clusters: u32,
    pub(crate) bitmap_clusters: u32,
    pub(crate) upcase_clusters: u32,
}

impl Plan {
    fn bitmap_bytes(&self) -> u64 {
        (self.clusters as u64).div_ceil(8)
    }
    fn upcase_cluster(&self) -> u32 {
        2 + self.bitmap_clusters
    }
    pub(crate) fn root_cluster(&self) -> u32 {
        self.upcase_cluster() + self.upcase_clusters
    }
    /// Clusters the three metadata streams take.
    #[cfg(test)]
    pub(crate) fn used_for_tests(&self) -> u32 {
        self.used()
    }

    /// Clusters the three metadata streams take.
    fn used(&self) -> u32 {
        self.bitmap_clusters + self.upcase_clusters + 1
    }
    fn cluster_sector(&self, cluster: u32) -> u64 {
        self.heap_offset as u64 + (cluster as u64 - 2) * self.spc as u64
    }
}

/// Work out a layout for `sectors` sectors of `ss` bytes.
pub(crate) fn plan(sectors: u64, ss: u32, cluster_size: Option<u32>) -> Result<Plan, &'static str> {
    let bytes = sectors.saturating_mul(ss as u64);
    if bytes < 1 << 20 {
        return Err("exFAT volumes start at 1 MiB");
    }
    let cb = match cluster_size {
        Some(cb) if cb.is_power_of_two() && cb >= ss && cb <= 32 << 20 => cb,
        Some(_) => return Err("cluster size must be a power of two from a sector to 32 MiB"),
        None if bytes <= 256 << 20 => 4096,
        None if bytes <= 32 << 30 => 32 << 10,
        None => 128 << 10,
    }
    .max(ss);
    let spc = cb / ss;
    // A little past the two boot regions, as mkfs tools leave.
    let fat_offset = 2 * BOOT_REGION + 8;

    let mut clusters = (sectors / spc as u64).min(layout::MAX_CLUSTER_COUNT as u64);
    for _ in 0..16 {
        let fat_length = ((clusters + 2) * 4).div_ceil(ss as u64);
        let heap = (fat_offset as u64 + fat_length).div_ceil(spc as u64) * spc as u64;
        if heap >= sectors {
            return Err("volume too small for exFAT's metadata");
        }
        let fit = ((sectors - heap) / spc as u64).min(layout::MAX_CLUSTER_COUNT as u64);
        if fit == clusters {
            let p = Plan {
                ss,
                spc,
                volume_sectors: sectors,
                fat_offset,
                fat_length: u32::try_from(fat_length).map_err(|_| "FAT too large")?,
                heap_offset: u32::try_from(heap).map_err(|_| "cluster heap offset too large")?,
                clusters: clusters as u32,
                bitmap_clusters: (clusters.div_ceil(8)).div_ceil(cb as u64).max(1) as u32,
                upcase_clusters: (UPCASE.len() as u64).div_ceil(cb as u64) as u32,
            };
            if p.clusters < p.used() + 1 {
                return Err("volume too small for exFAT's metadata");
            }
            return Ok(p);
        }
        clusters = fit;
    }
    Err("exFAT layout did not settle")
}

impl<'a> VolumeFormatOpts<'a> {
    /// The label's UTF-16 units, validated.
    fn label_units(&self) -> Result<([u16; 11], usize), &'static str> {
        let mut units = [0u16; 11];
        let mut n = 0;
        for u in self.label.encode_utf16() {
            if n == units.len() {
                return Err("exFAT labels are at most 11 UTF-16 units");
            }
            units[n] = u;
            n += 1;
        }
        Ok((units, n))
    }
}

impl<D: SectorDriver, const SECTOR: usize> Volume<D, SECTOR> {
    /// Format the whole card as an exFAT volume, then mount it.
    ///
    /// See [`format_at`](Self::format_at).
    pub fn format(dev: D, opts: &VolumeFormatOpts<'_>) -> Result<Self, Error<D::Error>> {
        let sectors = dev.sector_count();
        Self::format_at(dev, 0, sectors, opts)
    }

    /// Format `sectors` sectors starting at `start_lba` as an exFAT volume —
    /// a partition's extent, typically — then mount it.
    ///
    /// Written: both boot regions, the FAT, the allocation bitmap, the
    /// up-case table and the root directory's first cluster. The FAT is the
    /// bulk of it — about 3 800 sectors on a 64 GB card with the default
    /// 128 KiB clusters — and the data region is never read or cleared.
    /// Refused with [`Error::Unsupported`] for a size or option exFAT cannot
    /// represent, and with [`Error::VolumeExceedsDevice`] when the extent
    /// runs off the card.
    pub fn format_at(
        mut dev: D,
        start_lba: u64,
        sectors: u64,
        opts: &VolumeFormatOpts<'_>,
    ) -> Result<Self, Error<D::Error>> {
        Self::check_scratch(&dev)?;
        let ss = dev.sector_size();
        if start_lba
            .checked_add(sectors)
            .is_none_or(|end| end > dev.sector_count())
        {
            return Err(Error::VolumeExceedsDevice);
        }
        let p = plan(sectors, ss, opts.cluster_size).map_err(Error::Unsupported)?;
        let (label, label_len) = opts.label_units().map_err(Error::Unsupported)?;

        let mut scratch = [0u8; SECTOR];
        let buf = &mut scratch[..ss as usize];
        let put = |dev: &mut D, rel: u64, buf: &[u8]| {
            dev.write_sectors(start_lba + rel, buf).map_err(Error::Io)
        };

        // Between the backup boot region and the FAT: nothing.
        buf.fill(0);
        for rel in 2 * BOOT_REGION..p.fat_offset {
            put(&mut dev, rel as u64, buf)?;
        }
        // The FAT, then whatever pads it out to the cluster heap.
        for k in 0..p.fat_length {
            fat_sector(buf, &p, k);
            put(&mut dev, (p.fat_offset + k) as u64, buf)?;
        }
        buf.fill(0);
        for rel in (p.fat_offset + p.fat_length)..p.heap_offset {
            put(&mut dev, rel as u64, buf)?;
        }
        // The allocation bitmap: the metadata clusters in use, nothing else.
        let first = p.cluster_sector(2);
        for k in 0..p.bitmap_clusters as u64 * p.spc as u64 {
            bitmap_sector(buf, &p, k);
            put(&mut dev, first + k, buf)?;
        }
        // The up-case table.
        let first = p.cluster_sector(p.upcase_cluster());
        for k in 0..p.upcase_clusters as u64 * p.spc as u64 {
            buf.fill(0);
            let at = (k * ss as u64) as usize;
            if at < UPCASE.len() {
                let n = (UPCASE.len() - at).min(ss as usize);
                buf[..n].copy_from_slice(&UPCASE[at..at + n]);
            }
            put(&mut dev, first + k, buf)?;
        }
        // The root directory.
        let first = p.cluster_sector(p.root_cluster());
        for k in 0..p.spc as u64 {
            buf.fill(0);
            if k == 0 {
                root_entries(buf, &p, &label[..label_len]);
            }
            put(&mut dev, first + k, buf)?;
        }

        // The boot regions last: backup, then main.
        let mut checksum = 0u32;
        for i in 0..BOOT_REGION - 1 {
            boot_region_sector(buf, &p, start_lba, opts.volume_serial, i);
            for (at, &b) in buf.iter().enumerate() {
                // VolumeFlags and PercentInUse change at run time, so the
                // checksum leaves them out.
                if i == 0 && matches!(at, 106 | 107 | 112) {
                    continue;
                }
                checksum = checksum.rotate_right(1).wrapping_add(b as u32);
            }
        }
        for base in [BOOT_REGION, 0] {
            for i in 0..BOOT_REGION {
                if i == BOOT_REGION - 1 {
                    for chunk in buf.as_chunks_mut::<4>().0 {
                        chunk.copy_from_slice(&checksum.to_le_bytes());
                    }
                } else {
                    boot_region_sector(buf, &p, start_lba, opts.volume_serial, i);
                }
                put(&mut dev, (base + i) as u64, buf)?;
            }
        }
        dev.flush().map_err(Error::Io)?;
        Self::mount_at(dev, start_lba)
    }
}

/// Sector `i` (0..=10) of a boot region.
fn boot_region_sector(b: &mut [u8], p: &Plan, start_lba: u64, serial: u32, i: u32) {
    b.fill(0);
    let n = b.len();
    match i {
        0 => {
            b[0..3].copy_from_slice(&[0xEB, 0x76, 0x90]);
            b[3..11].copy_from_slice(b"EXFAT   ");
            b[64..72].copy_from_slice(&start_lba.to_le_bytes());
            b[72..80].copy_from_slice(&p.volume_sectors.to_le_bytes());
            b[80..84].copy_from_slice(&p.fat_offset.to_le_bytes());
            b[84..88].copy_from_slice(&p.fat_length.to_le_bytes());
            b[88..92].copy_from_slice(&p.heap_offset.to_le_bytes());
            b[92..96].copy_from_slice(&p.clusters.to_le_bytes());
            b[96..100].copy_from_slice(&p.root_cluster().to_le_bytes());
            b[100..104].copy_from_slice(&serial.to_le_bytes());
            b[104..106].copy_from_slice(&0x0100u16.to_le_bytes()); // revision 1.00
            b[108] = p.ss.trailing_zeros() as u8;
            b[109] = p.spc.trailing_zeros() as u8;
            b[110] = 1; // one FAT
            b[111] = 0x80; // drive select
            let used = p.used() as u64 * 100 / p.clusters as u64;
            b[112] = used as u8; // percent in use
            b[510] = 0x55;
            b[511] = 0xAA;
        }
        // Extended boot sectors carry only their signature.
        1..=8 => b[n - 4..].copy_from_slice(&0xAA55_0000u32.to_le_bytes()),
        // OEM parameters and the reserved sector are empty.
        _ => {}
    }
}

/// FAT sector `k`: entries 0 and 1 reserved, then a chain per metadata
/// stream.
fn fat_sector(b: &mut [u8], p: &Plan, k: u32) {
    b.fill(0);
    let per = b.len() as u32 / 4;
    let first = k as u64 * per as u64;
    let end = 2 + p.used() as u64;
    if first >= end {
        return;
    }
    let chains = [
        (2, p.bitmap_clusters),
        (p.upcase_cluster(), p.upcase_clusters),
        (p.root_cluster(), 1),
    ];
    for (i, slot) in b.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        let c = first + i as u64;
        let value = match c {
            0 => 0xFFFF_FFF8,
            1 => layout::FAT_EOC,
            _ => chains
                .iter()
                .find(|&&(start, len)| c >= start as u64 && c < start as u64 + len as u64)
                .map_or(layout::FAT_FREE, |&(start, len)| {
                    if c + 1 == start as u64 + len as u64 {
                        layout::FAT_EOC
                    } else {
                        c as u32 + 1
                    }
                }),
        };
        slot.copy_from_slice(&value.to_le_bytes());
    }
}

/// Allocation-bitmap sector `k`: the first `used` clusters marked.
fn bitmap_sector(b: &mut [u8], p: &Plan, k: u64) {
    let used = p.used() as u64;
    let len = p.bitmap_bytes();
    for (i, byte) in b.iter_mut().enumerate() {
        let at = k * p.ss as u64 + i as u64;
        let bit = at * 8;
        *byte = if at >= len || bit >= used {
            0
        } else if bit + 8 <= used {
            0xFF
        } else {
            (1u8 << (used - bit)) - 1
        };
    }
}

/// The root directory's first sector: the label, the bitmap and the up-case
/// table.
fn root_entries(b: &mut [u8], p: &Plan, label: &[u16]) {
    let mut at = 0;
    if !label.is_empty() {
        let e = &mut b[at..at + ENTRY_SIZE];
        e[0] = layout::ENTRY_VOLUME_LABEL;
        e[1] = label.len() as u8;
        for (i, u) in label.iter().enumerate() {
            e[2 + i * 2..4 + i * 2].copy_from_slice(&u.to_le_bytes());
        }
        at += ENTRY_SIZE;
    }
    let e = &mut b[at..at + ENTRY_SIZE];
    e[0] = layout::ENTRY_ALLOCATION_BITMAP;
    e[20..24].copy_from_slice(&2u32.to_le_bytes());
    e[24..32].copy_from_slice(&p.bitmap_bytes().to_le_bytes());
    at += ENTRY_SIZE;
    let e = &mut b[at..at + ENTRY_SIZE];
    e[0] = layout::ENTRY_UPCASE_TABLE;
    e[4..8].copy_from_slice(&UPCASE_CHECKSUM.to_le_bytes());
    e[20..24].copy_from_slice(&p.upcase_cluster().to_le_bytes());
    e[24..32].copy_from_slice(&(UPCASE.len() as u64).to_le_bytes());
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_embedded_up_case_table_is_the_recommended_one() {
        assert_eq!(super::UPCASE.len(), 5836);
        assert_eq!(
            super::super::super::layout::table_checksum(super::UPCASE),
            super::UPCASE_CHECKSUM
        );
    }
}
