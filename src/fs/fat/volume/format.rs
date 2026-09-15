//! Laying a fresh FAT volume down, with no allocator.
//!
//! A format is a handful of sectors of structure and a lot of zeros: the boot
//! sector (and, on FAT32, its FSInfo and their backups), two FAT copies whose
//! first sector reserves clusters 0 and 1, the root directory, and nothing
//! else — every cluster of the data region is free the moment the FATs say
//! so, so its old contents are never touched. Everything here is produced a
//! sector at a time into one sector of stack and written through the
//! caller's [`SectorDriver`].
//!
//! The geometry follows what `mkfs.fat` and Windows pick for a volume of the
//! same size, so a card formatted here looks like one formatted anywhere
//! else: FAT32 from 512 MiB up with Microsoft's cluster-size table, FAT16
//! below that and FAT12 for the smallest, and on FAT32 a data region that
//! starts on a cluster boundary.

use super::{Error, FatKind, SectorDriver, Timestamp, Volume};

/// How [`Volume::format`] lays a volume out. The default picks everything
/// from the volume's size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormatOpts {
    /// FAT12, FAT16 or FAT32; `None` chooses by size.
    pub kind: Option<FatKind>,
    /// Cluster size in bytes — a power of two from one sector to 32 KiB;
    /// `None` chooses by size.
    pub cluster_size: Option<u32>,
    /// The volume serial number. A real one should differ between cards;
    /// a driver with a clock or a random source can derive one.
    pub volume_id: u32,
    /// The volume label: 11 bytes, space-padded. `NO NAME    ` means none.
    pub label: [u8; 11],
    /// Fixed root-directory slots on FAT12/16: a multiple of the entries a
    /// sector holds. Ignored on FAT32, whose root is an ordinary directory.
    pub root_entries: u16,
    /// Stamped on the label's directory entry.
    pub time: Timestamp,
}

impl Default for FormatOpts {
    fn default() -> Self {
        Self {
            kind: None,
            cluster_size: None,
            volume_id: 0x1234_5678,
            label: *b"NO NAME    ",
            root_entries: 512,
            time: Timestamp::EPOCH,
        }
    }
}

/// The sectors [`Volume::format_at`] reserves before the FATs on FAT32:
/// room for the boot sector, FSInfo and their backups at 6 and 7.
const FAT32_RESERVED: u32 = 32;

/// A planned layout, before a byte is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Plan {
    pub(crate) kind: FatKind,
    pub(crate) spc: u32,
    pub(crate) reserved: u32,
    pub(crate) fat_sectors: u32,
    pub(crate) root_entries: u32,
    pub(crate) root_sectors: u32,
    pub(crate) clusters: u32,
}

impl Plan {
    fn data_start(&self) -> u32 {
        self.reserved + 2 * self.fat_sectors + self.root_sectors
    }
}

/// Work out a layout for `total` sectors of `ss` bytes.
pub(crate) fn plan(total: u32, ss: u32, opts: &FormatOpts) -> Result<Plan, &'static str> {
    if let Some(cb) = opts.cluster_size
        && (!cb.is_power_of_two() || cb < ss || cb > 32 * 1024)
    {
        return Err("cluster size must be a power of two from a sector to 32 KiB");
    }
    let bytes = total as u64 * ss as u64;
    let preferred = match opts.kind {
        Some(kind) => return plan_kind(kind, total, ss, opts),
        None if bytes >= 512 << 20 => [FatKind::Fat32, FatKind::Fat16, FatKind::Fat12],
        None if bytes >= 16 << 20 => [FatKind::Fat16, FatKind::Fat32, FatKind::Fat12],
        None => [FatKind::Fat12, FatKind::Fat16, FatKind::Fat32],
    };
    let mut last = "volume too small for FAT";
    for kind in preferred {
        match plan_kind(kind, total, ss, opts) {
            Ok(p) => return Ok(p),
            Err(e) => last = e,
        }
    }
    Err(last)
}

fn plan_kind(kind: FatKind, total: u32, ss: u32, opts: &FormatOpts) -> Result<Plan, &'static str> {
    let bytes = total as u64 * ss as u64;
    let per_sector = ss / 32;
    let (reserved, root_entries) = match kind {
        FatKind::Fat32 => (FAT32_RESERVED, 0),
        _ => {
            let n = opts.root_entries as u32;
            if n == 0 || !n.is_multiple_of(per_sector) {
                return Err("root_entries must be a non-zero multiple of the entries in a sector");
            }
            (1, n)
        }
    };
    let root_sectors = root_entries * 32 / ss;
    let spc_of = |cb: u32| (cb / ss).max(1);

    // Candidate cluster sizes, in the order to try them.
    let max_spc = spc_of(32 * 1024);
    let first = match (opts.cluster_size, kind) {
        (Some(cb), _) => spc_of(cb),
        // Microsoft's table for FAT32 by volume size.
        (None, FatKind::Fat32) => spc_of(match bytes {
            b if b <= 260 << 20 => 512,
            b if b <= 8 << 30 => 4096,
            b if b <= 16 << 30 => 8192,
            b if b <= 32 << 30 => 16384,
            _ => 32768,
        }),
        // FAT12/16 take the smallest cluster that keeps the count in range.
        (None, _) => 1,
    };
    let mut spc = first;
    loop {
        let (mut reserved, fat_sectors, mut clusters) =
            converge(kind, total, ss, spc, reserved, root_sectors)?;
        if kind == FatKind::Fat32 {
            // Start the data region on a cluster boundary, the way mkfs.fat
            // does, by growing the reserved region. The FAT only shrinks in
            // what it has to map, so it stays big enough.
            let meta = reserved + 2 * fat_sectors;
            let pad = (spc - meta % spc) % spc;
            if reserved + pad <= u16::MAX as u32 && meta + pad < total {
                reserved += pad;
                clusters = (total - reserved - 2 * fat_sectors) / spc;
            }
        }
        let fits = clusters >= kind.min_clusters() && clusters <= kind.max_clusters();
        if fits {
            return Ok(Plan {
                kind,
                spc,
                reserved,
                fat_sectors,
                root_entries,
                root_sectors,
                clusters,
            });
        }
        let explicit = opts.cluster_size.is_some();
        // Too many clusters wants bigger ones; too few wants smaller.
        if clusters > kind.max_clusters() && !explicit && spc < max_spc {
            spc *= 2;
        } else if clusters < kind.min_clusters() && !explicit && spc > 1 && spc <= first {
            spc /= 2;
        } else {
            return Err(match kind {
                FatKind::Fat12 => "volume does not fit FAT12's cluster range",
                FatKind::Fat16 => "volume does not fit FAT16's cluster range",
                FatKind::Fat32 => "volume does not fit FAT32's cluster range (at least ~33 MiB)",
            });
        }
    }
}

/// Grow the FAT until it maps every cluster it leaves room for.
fn converge(
    kind: FatKind,
    total: u32,
    ss: u32,
    spc: u32,
    reserved: u32,
    root_sectors: u32,
) -> Result<(u32, u32, u32), &'static str> {
    let mut fat_sectors = 1u32;
    loop {
        let meta = reserved as u64 + 2 * fat_sectors as u64 + root_sectors as u64;
        if meta >= total as u64 {
            return Err("volume too small for the FAT metadata");
        }
        let clusters = (total - meta as u32) / spc;
        let need = kind.fat_bytes(clusters as u64 + 2).div_ceil(ss as u64);
        if need <= fat_sectors as u64 {
            return Ok((reserved, fat_sectors, clusters));
        }
        fat_sectors = u32::try_from(need).map_err(|_| "FAT too large")?;
    }
}

impl<D: SectorDriver, const SECTOR: usize> Volume<D, SECTOR> {
    /// Format the whole medium as a FAT volume, then mount it.
    ///
    /// See [`format_at`](Self::format_at).
    pub fn format(dev: D, opts: &FormatOpts) -> Result<Self, Error<D::Error>> {
        let sectors = dev.sector_count();
        Self::format_at(dev, 0, sectors, opts)
    }

    /// Format `sectors` sectors starting at `start_lba` as a FAT volume —
    /// a partition's extent, typically — then mount it.
    ///
    /// Only the volume's metadata is written: the reserved region, both
    /// FATs, and the root directory. That is one write per sector of it, a
    /// few thousand on a large card, and the old contents of the data region
    /// are never read or cleared. Refused with [`Error::Unsupported`] when no
    /// FAT flavour (or not the one asked for) fits the size, and with
    /// [`Error::VolumeExceedsDevice`] when the extent runs off the medium.
    pub fn format_at(
        mut dev: D,
        start_lba: u64,
        sectors: u64,
        opts: &FormatOpts,
    ) -> Result<Self, Error<D::Error>> {
        Self::check_scratch(&dev)?;
        let ss = dev.sector_size();
        if start_lba
            .checked_add(sectors)
            .is_none_or(|end| end > dev.sector_count())
        {
            return Err(Error::VolumeExceedsDevice);
        }
        let total = u32::try_from(sectors)
            .map_err(|_| Error::Unsupported("FAT volumes stop at 2^32 sectors"))?;
        let p = plan(total, ss, opts).map_err(Error::Unsupported)?;

        let mut buf = [0u8; SECTOR];
        let buf = &mut buf[..ss as usize];
        let fat32 = p.kind == FatKind::Fat32;
        let data_start = p.data_start();
        // FAT32's root is cluster 2, which has to read as an empty directory.
        let end = if fat32 {
            data_start + p.spc
        } else {
            data_start
        };
        let root_first = if fat32 {
            data_start
        } else {
            p.reserved + 2 * p.fat_sectors
        };

        // Everything but the boot sector and its FAT32 backup, which go last
        // so a format torn part-way does not leave a boot sector describing
        // FATs that were never written.
        for rel in 1..end {
            if fat32 && rel == 6 {
                continue;
            }
            buf.fill(0);
            match rel {
                1 | 7 if fat32 => fs_info(buf, p.clusters - 1),
                r if r == p.reserved || r == p.reserved + p.fat_sectors => {
                    first_fat_sector(buf, p.kind)
                }
                r if r == root_first && opts.label != *b"NO NAME    " => {
                    buf[0..11].copy_from_slice(&opts.label);
                    buf[11] = 0x08; // volume label
                    buf[22..24].copy_from_slice(&opts.time.time.to_le_bytes());
                    buf[24..26].copy_from_slice(&opts.time.date.to_le_bytes());
                }
                _ => {}
            }
            dev.write_sectors(start_lba + rel as u64, buf)
                .map_err(Error::Io)?;
        }
        buf.fill(0);
        boot_sector(buf, &p, total, start_lba, opts);
        if fat32 {
            dev.write_sectors(start_lba + 6, buf).map_err(Error::Io)?;
        }
        dev.write_sectors(start_lba, buf).map_err(Error::Io)?;
        dev.flush().map_err(Error::Io)?;
        Self::mount_at(dev, start_lba)
    }
}

/// The boot sector (and FAT32's backup of it).
fn boot_sector(b: &mut [u8], p: &Plan, total: u32, start_lba: u64, opts: &FormatOpts) {
    let fat32 = p.kind == FatKind::Fat32;
    let ss = b.len() as u32;
    b[0..3].copy_from_slice(&[0xEB, if fat32 { 0x58 } else { 0x3C }, 0x90]);
    b[3..11].copy_from_slice(b"MSWIN4.1");
    b[11..13].copy_from_slice(&(ss as u16).to_le_bytes());
    b[13] = p.spc as u8;
    b[14..16].copy_from_slice(&(p.reserved as u16).to_le_bytes());
    b[16] = 2;
    b[17..19].copy_from_slice(&(p.root_entries as u16).to_le_bytes());
    if !fat32 && total < 0x1_0000 {
        b[19..21].copy_from_slice(&(total as u16).to_le_bytes());
    } else {
        b[32..36].copy_from_slice(&total.to_le_bytes());
    }
    b[21] = 0xF8;
    b[24..26].copy_from_slice(&63u16.to_le_bytes());
    b[26..28].copy_from_slice(&255u16.to_le_bytes());
    b[28..32].copy_from_slice(&(start_lba.min(u32::MAX as u64) as u32).to_le_bytes());
    let ext = if fat32 {
        b[36..40].copy_from_slice(&p.fat_sectors.to_le_bytes());
        b[44..48].copy_from_slice(&2u32.to_le_bytes()); // root cluster
        b[48..50].copy_from_slice(&1u16.to_le_bytes()); // FSInfo
        b[50..52].copy_from_slice(&6u16.to_le_bytes()); // backup boot sector
        64
    } else {
        b[22..24].copy_from_slice(&(p.fat_sectors as u16).to_le_bytes());
        36
    };
    b[ext] = 0x80; // drive number
    b[ext + 2] = 0x29; // extended boot signature
    b[ext + 3..ext + 7].copy_from_slice(&opts.volume_id.to_le_bytes());
    b[ext + 7..ext + 18].copy_from_slice(&opts.label);
    b[ext + 18..ext + 26].copy_from_slice(p.kind.fs_type_label());
    b[510] = 0x55;
    b[511] = 0xAA;
}

/// FAT32's FSInfo sector (and its backup).
fn fs_info(b: &mut [u8], free: u32) {
    b[0..4].copy_from_slice(&0x4161_5252u32.to_le_bytes());
    b[484..488].copy_from_slice(&0x6141_7272u32.to_le_bytes());
    b[488..492].copy_from_slice(&free.to_le_bytes());
    // Cluster 2 is the root directory; 3 is the first free one.
    b[492..496].copy_from_slice(&3u32.to_le_bytes());
    b[508..512].copy_from_slice(&0xAA55_0000u32.to_le_bytes());
}

/// The first sector of a FAT: entries 0 and 1 reserved (the media byte and
/// an end-of-chain), and on FAT32 cluster 2 ending the root directory.
fn first_fat_sector(b: &mut [u8], kind: FatKind) {
    match kind {
        FatKind::Fat12 => b[0..3].copy_from_slice(&[0xF8, 0xFF, 0xFF]),
        FatKind::Fat16 => b[0..4].copy_from_slice(&[0xF8, 0xFF, 0xFF, 0xFF]),
        FatKind::Fat32 => {
            b[0..4].copy_from_slice(&0x0FFF_FFF8u32.to_le_bytes());
            b[4..8].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes());
            b[8..12].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes());
        }
    }
}
