//! Read-only FAT12 / FAT16 / FAT32 verification — a bounded
//! `fsck.fat -n` / `fsck_msdos -n`.
//!
//! [`verify`] checks, without writing:
//!
//! * the boot sector (BPB geometry, signature) and, on FAT32, the backup
//!   boot sector and the FSInfo sector (signatures, cached free count);
//! * the FAT copies against each other, the media byte in entry 0 and
//!   the clean-shutdown bit in entry 1;
//! * the directory tree from the root: every entry's cluster chain —
//!   clusters in range, no free or bad cluster mid-chain, no loops, no
//!   cluster shared by two chains (cross-links) — and its length
//!   against the file size; `.` / `..` in every subdirectory;
//! * clusters the FAT marks in use that no chain reaches (lost chains).
//!
//! Bounded by [`VerifyOpts`] like every verifier.

use crate::Result;
use crate::block::BlockDevice;
use crate::fs::verify::{Collector, DiagCode, Location, Truncation, VerifyOpts, VerifyReport};

use super::boot::{BOOT_SECTOR_SIZE, BootSector, probe};
use crate::fs::fat::FatKind;

/// Verify the FAT volume on `dev` (starting at its boot sector).
///
/// Returns `Err` only on I/O failure; a boot sector that does not decode
/// is reported as [`DiagCode::HeaderUnreadable`].
pub fn verify(dev: &mut dyn BlockDevice, opts: &VerifyOpts) -> Result<VerifyReport> {
    let mut c = Collector::new("fat", opts);
    let mut b0 = [0u8; BOOT_SECTOR_SIZE];
    if dev.total_size() < 512 {
        c.error(
            DiagCode::HeaderUnreadable,
            Location::structure("boot-sector"),
            "device too small for a FAT boot sector",
        );
        return Ok(c.finish());
    }
    dev.read_at(0, &mut b0)?;
    let bs = match BootSector::decode(&b0) {
        Ok(b) => b,
        Err(e) => {
            c.error(
                DiagCode::HeaderUnreadable,
                Location::structure("boot-sector"),
                e.to_string(),
            );
            return Ok(c.finish());
        }
    };
    c.report.fs = match bs.kind {
        FatKind::Fat12 => "fat12",
        FatKind::Fat16 => "fat16",
        FatKind::Fat32 => "fat32",
    };
    let mut v = FatVerifier::new(dev, c, bs, b0);
    v.run()?;
    Ok(v.c.finish())
}

/// [`verify`] when `dev` carries a FAT boot sector, `None` otherwise.
pub fn probe_and_verify(
    dev: &mut dyn BlockDevice,
    opts: &VerifyOpts,
) -> Result<Option<VerifyReport>> {
    if dev.total_size() < 512 {
        return Ok(None);
    }
    let mut b0 = [0u8; BOOT_SECTOR_SIZE];
    dev.read_at(0, &mut b0)?;
    if probe(&b0).is_none() {
        return Ok(None);
    }
    verify(dev, opts).map(Some)
}

struct FatVerifier<'d> {
    c: Collector,
    dev: &'d mut dyn BlockDevice,
    bs: BootSector,
    b0: [u8; 512],
    sector: u64,
    cluster_bytes: u64,
    clusters: u32,
    fat: Vec<u32>,
    claimed: Vec<u8>,
    files: u64,
    dirs: u64,
}

impl<'d> FatVerifier<'d> {
    fn new(dev: &'d mut dyn BlockDevice, c: Collector, bs: BootSector, b0: [u8; 512]) -> Self {
        let sector = u64::from(bs.bytes_per_sector);
        let cluster_bytes = sector * u64::from(bs.sectors_per_cluster);
        let clusters = bs.cluster_count();
        Self {
            c,
            dev,
            sector,
            cluster_bytes,
            clusters,
            bs,
            b0,
            fat: Vec::new(),
            claimed: Vec::new(),
            files: 0,
            dirs: 0,
        }
    }

    fn eoc(&self) -> u32 {
        match self.bs.kind {
            FatKind::Fat12 => 0xFF8,
            FatKind::Fat16 => 0xFFF8,
            FatKind::Fat32 => 0x0FFF_FFF8,
        }
    }

    fn bad(&self) -> u32 {
        self.eoc() - 1
    }

    fn run(&mut self) -> Result<()> {
        let vol = u64::from(self.bs.total_sectors) * self.sector;
        if vol > self.dev.total_size() {
            self.c.error(
                DiagCode::VolumeLargerThanDevice,
                Location::structure("boot-sector"),
                format!(
                    "volume of {vol} bytes exceeds its {}-byte device",
                    self.dev.total_size()
                ),
            );
            return Ok(());
        }
        if self.bs.kind == FatKind::Fat32 {
            self.check_fat32_extras()?;
        }
        if !self.load_fats()? {
            return Ok(());
        }
        let need = (u64::from(self.clusters) + 2).div_ceil(8);
        self.claimed = vec![0u8; need as usize];
        self.walk_tree()?;
        self.check_lost();
        self.c.report.stats.files = self.files;
        self.c.report.stats.folders = self.dirs;
        self.c.report.stats.total_blocks = u64::from(self.clusters);
        Ok(())
    }

    fn check_fat32_extras(&mut self) -> Result<()> {
        let bk = u64::from(self.bs.backup_boot_sector);
        if bk != 0 && bk < u64::from(self.bs.reserved_sector_count) {
            let mut b = [0u8; 512];
            self.dev.read_at(bk * self.sector, &mut b)?;
            // The BPB proper; OEM name and boot code may legitimately differ.
            if b[11..90] != self.b0[11..90] || b[510..512] != self.b0[510..512] {
                self.c.warn(
                    DiagCode::AlternateHeaderMismatch,
                    Location::structure("backup-boot-sector").at_byte(bk * self.sector),
                    "the backup boot sector differs from the primary",
                );
            }
        }
        Ok(())
    }

    /// Load the first FAT, compare the other copies, check entries 0/1.
    fn load_fats(&mut self) -> Result<bool> {
        let fat_bytes = u64::from(self.bs.fat_size) * self.sector;
        let entries = u64::from(self.clusters) + 2;
        let width_bits: u64 = match self.bs.kind {
            FatKind::Fat12 => 12,
            FatKind::Fat16 => 16,
            FatKind::Fat32 => 32,
        };
        if (entries * width_bits).div_ceil(8) > fat_bytes {
            self.c.error(
                DiagCode::BitmapInvalid,
                Location::structure("fat"),
                format!(
                    "a {fat_bytes}-byte FAT cannot hold {entries} entries of {width_bits} bits"
                ),
            );
            return Ok(false);
        }
        if entries * 4 > self.c.opts.max_bitmap_bytes {
            self.c.report.truncate(Truncation::Memory);
            self.c.info(
                DiagCode::Unsupported,
                Location::structure("fat"),
                format!(
                    "chain checks skipped: {entries} FAT entries exceed max_bitmap_bytes {}",
                    self.c.opts.max_bitmap_bytes
                ),
            );
            return Ok(false);
        }
        let base = u64::from(self.bs.reserved_sector_count) * self.sector;
        let used = (entries * width_bits).div_ceil(8) as usize;
        let mut first = vec![0u8; used];
        self.dev.read_at(base, &mut first)?;
        for i in 1..u64::from(self.bs.num_fats) {
            let mut other = vec![0u8; used];
            self.dev.read_at(base + i * fat_bytes, &mut other)?;
            if other != first {
                let at = other
                    .iter()
                    .zip(&first)
                    .position(|(a, b)| a != b)
                    .unwrap_or(0);
                // A warning, not an error: every driver (and macOS's
                // fsck_msdos) works from the first copy; fsck.fat and
                // chkdsk resync the others.
                self.c.warn(
                    DiagCode::TableCopiesDiffer,
                    Location::structure("fat").at_byte(base + i * fat_bytes + at as u64),
                    format!("FAT copy {} differs from the first at byte {at}", i + 1),
                );
            }
        }
        let mut fat = Vec::with_capacity(entries as usize);
        for n in 0..entries as usize {
            let v = match self.bs.kind {
                FatKind::Fat12 => {
                    let o = n * 3 / 2;
                    let w = u16::from_le_bytes([first[o], first[o + 1]]);
                    u32::from(if n % 2 == 0 { w & 0xFFF } else { w >> 4 })
                }
                FatKind::Fat16 => u32::from(u16::from_le_bytes([first[n * 2], first[n * 2 + 1]])),
                FatKind::Fat32 => {
                    u32::from_le_bytes(first[n * 4..n * 4 + 4].try_into().unwrap()) & 0x0FFF_FFFF
                }
            };
            fat.push(v);
        }
        // Entry 0 carries the media byte; entry 1 the clean-shutdown bit.
        if fat[0] & 0xFF != u32::from(self.bs.media) {
            self.c.warn(
                DiagCode::HeaderFieldInvalid,
                Location::structure("fat"),
                format!(
                    "FAT entry 0 ({:#x}) does not carry the media byte {:#x}",
                    fat[0], self.bs.media
                ),
            );
        }
        let clean_bit = match self.bs.kind {
            FatKind::Fat12 => None,
            FatKind::Fat16 => Some(0x8000),
            FatKind::Fat32 => Some(0x0800_0000),
        };
        if let Some(bit) = clean_bit
            && fat[1] & bit == 0
        {
            self.c.warn(
                DiagCode::VolumeDirty,
                Location::structure("fat"),
                "the clean-shutdown bit in FAT entry 1 is clear",
            );
        }
        self.fat = fat;
        Ok(true)
    }

    fn cluster_offset(&self, cl: u32) -> u64 {
        (u64::from(self.bs.data_start_sector())
            + u64::from(cl - 2) * u64::from(self.bs.sectors_per_cluster))
            * self.sector
    }

    fn in_range(&self, cl: u32) -> bool {
        cl >= 2 && cl < self.clusters + 2
    }

    /// Follow and claim the chain from `first`. Returns the clusters, or
    /// `None` if the chain is broken (already reported).
    fn chain(&mut self, first: u32, owner: &str) -> Option<Vec<u32>> {
        let mut out = Vec::new();
        let mut cl = first;
        loop {
            if !self.in_range(cl) {
                self.c.error(
                    DiagCode::ChainInvalid,
                    Location::structure("fat").object(u64::from(first)),
                    format!(
                        "{owner}: chain reaches cluster {cl}, outside 2..{}",
                        self.clusters + 2
                    ),
                );
                return None;
            }
            if !self.c.take_extent() {
                return None;
            }
            let byte = (cl / 8) as usize;
            let m = 0x80u8 >> (cl % 8);
            if self.claimed[byte] & m != 0 {
                self.c.error(
                    DiagCode::ExtentOverlap,
                    Location::structure("fat").blocks(u64::from(cl), 1).object(u64::from(first)),
                    format!("{owner}: cluster {cl} is already used by another chain (cross-link or loop)"),
                );
                return None;
            }
            self.claimed[byte] |= m;
            out.push(cl);
            let next = self.fat[cl as usize];
            if next >= self.eoc() {
                return Some(out);
            }
            if next == 0 || next == self.bad() {
                self.c.error(
                    DiagCode::ChainInvalid,
                    Location::structure("fat")
                        .blocks(u64::from(cl), 1)
                        .object(u64::from(first)),
                    format!(
                        "{owner}: chain runs into a {} cluster after {cl}",
                        if next == 0 { "free" } else { "bad" }
                    ),
                );
                return Some(out);
            }
            cl = next;
        }
    }

    fn walk_tree(&mut self) -> Result<()> {
        // (directory data, its first cluster (0 = fixed root), parent cluster, path)
        let root_fixed = self.bs.kind != FatKind::Fat32;
        let mut queue: Vec<(u32, u32, String)> = Vec::new();
        let root_data = if root_fixed {
            let off = u64::from(self.bs.root_dir_start_sector()) * self.sector;
            let mut b = vec![0u8; usize::from(self.bs.root_entry_count) * 32];
            self.dev.read_at(off, &mut b)?;
            Some(b)
        } else {
            None
        };
        self.dirs += 1;
        if let Some(data) = root_data {
            self.scan_dir(&data, 0, 0, "/", true, &mut queue);
        } else {
            let rc = self.bs.root_cluster;
            match self.chain(rc, "root directory") {
                Some(list) => {
                    let data = self.read_clusters(&list)?;
                    self.scan_dir(&data, rc, 0, "/", true, &mut queue);
                }
                None => {
                    self.c.error(
                        DiagCode::RootMissing,
                        Location::structure("root").object(u64::from(rc)),
                        "the root directory chain is unusable",
                    );
                    return Ok(());
                }
            }
        }
        while let Some((cl, parent, path)) = queue.pop() {
            if !self.c.take_node() {
                return Ok(());
            }
            let Some(list) = self.chain(cl, &path) else {
                continue;
            };
            let data = self.read_clusters(&list)?;
            self.scan_dir(&data, cl, parent, &path, false, &mut queue);
        }
        Ok(())
    }

    fn read_clusters(&mut self, list: &[u32]) -> Result<Vec<u8>> {
        let mut out = vec![0u8; list.len() * self.cluster_bytes as usize];
        for (i, &cl) in list.iter().enumerate() {
            let off = self.cluster_offset(cl);
            let n = self.cluster_bytes as usize;
            self.dev.read_at(off, &mut out[i * n..(i + 1) * n])?;
        }
        Ok(out)
    }

    fn scan_dir(
        &mut self,
        data: &[u8],
        me: u32,
        parent: u32,
        path: &str,
        is_root: bool,
        queue: &mut Vec<(u32, u32, String)>,
    ) {
        let loc = || Location::structure("directory").object(u64::from(me));
        let mut idx = 0usize;
        for ent in data.as_chunks::<32>().0 {
            idx += 1;
            if ent[0] == 0 {
                break;
            }
            if ent[0] == 0xE5 || ent[11] & 0x0F == 0x0F {
                continue;
            }
            if !self.c.take_record() {
                return;
            }
            let attr = ent[11];
            let hi = u32::from(u16::from_le_bytes([ent[20], ent[21]]));
            let lo = u32::from(u16::from_le_bytes([ent[26], ent[27]]));
            let first = if self.bs.kind == FatKind::Fat32 {
                (hi << 16) | lo
            } else {
                lo
            };
            let size = u64::from(u32::from_le_bytes(ent[28..32].try_into().unwrap()));
            let name = &ent[0..11];
            let display = String::from_utf8_lossy(name).trim_end().to_string();
            if attr & 0x08 != 0 {
                continue; // volume label
            }
            if name == b".          " || name == b"..         " {
                if is_root {
                    self.c.error(
                        DiagCode::RecordInvalid,
                        loc(),
                        "the root directory holds a '.' or '..' entry",
                    );
                    continue;
                }
                let want = if name[1] == b'.' {
                    if parent == self.bs.root_cluster && self.bs.kind == FatKind::Fat32 {
                        // FAT32 subdirectories of the root point '..' at 0.
                        0
                    } else {
                        parent
                    }
                } else {
                    me
                };
                if first != want && !(name[1] == b'.' && first == parent) {
                    self.c.error(
                        DiagCode::RecordInvalid,
                        loc(),
                        format!(
                            "{path}: '{}' points at cluster {first}, expected {want}",
                            display
                        ),
                    );
                }
                if (idx == 1 && name[1] == b'.') || (idx == 2 && name[1] != b'.') {
                    self.c.warn(
                        DiagCode::RecordInvalid,
                        loc(),
                        format!("{path}: '.' / '..' are not the first two entries"),
                    );
                }
                continue;
            }
            let child = format!("{}{}", path, display);
            if attr & 0x10 != 0 {
                self.dirs += 1;
                if first == 0 {
                    self.c.error(
                        DiagCode::ChainInvalid,
                        loc(),
                        format!("{child}: directory has no cluster"),
                    );
                    continue;
                }
                queue.push((first, me, format!("{child}/")));
                continue;
            }
            self.files += 1;
            if first == 0 {
                if size != 0 {
                    self.c.error(
                        DiagCode::ForkSizeMismatch,
                        loc(),
                        format!("{child}: {size} bytes but no clusters"),
                    );
                }
                continue;
            }
            if let Some(list) = self.chain(first, &child) {
                let want = size.div_ceil(self.cluster_bytes);
                if list.len() as u64 != want {
                    self.c.error(
                        DiagCode::ForkSizeMismatch,
                        Location::structure("directory").object(u64::from(first)),
                        format!(
                            "{child}: file size is {size} bytes, cluster chain length is {} \
                             ({} expected)",
                            list.len(),
                            want
                        ),
                    );
                }
            }
        }
    }

    fn check_lost(&mut self) {
        if !self.c.report.truncated.is_empty() {
            return;
        }
        let mut lost: Vec<u64> = Vec::new();
        let mut free = 0u64;
        for cl in 2..self.clusters + 2 {
            let v = self.fat[cl as usize];
            if v == 0 {
                free += 1;
                continue;
            }
            if v == self.bad() {
                continue;
            }
            if self.claimed[(cl / 8) as usize] & (0x80 >> (cl % 8)) == 0 {
                lost.push(u64::from(cl));
            }
        }
        self.c.report.stats.free_blocks = free;
        for (s, n) in crate::fs::verify::runs_of(lost.into_iter()) {
            self.c.error(
                DiagCode::BitmapLeakedBlocks,
                Location::structure("fat").blocks(s, n),
                format!("clusters {s}+{n} are in use but no file or directory reaches them"),
            );
        }
        if self.bs.kind == FatKind::Fat32 {
            let fsi = u64::from(self.bs.fs_info_sector);
            let mut b = [0u8; 512];
            if fsi != 0
                && self.dev.read_at(fsi * self.sector, &mut b).is_ok()
                && let Ok(info) = super::fsinfo::FsInfo::decode(&b)
            {
                if info.free_count != u32::MAX && u64::from(info.free_count) != free {
                    self.c.warn(
                        DiagCode::FreeCountMismatch,
                        Location::structure("fsinfo").at_byte(fsi * self.sector),
                        format!(
                            "FSInfo free count {} but the FAT has {free} free cluster(s)",
                            info.free_count
                        ),
                    );
                }
            } else if fsi != 0 {
                self.c.warn(
                    DiagCode::HeaderFieldInvalid,
                    Location::structure("fsinfo"),
                    "the FSInfo sector is missing or has bad signatures",
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::MemoryBackend;
    use crate::fs::fat::{Fat32, FatFormatOpts};

    fn sample() -> MemoryBackend {
        let mut dev = MemoryBackend::new(64 * 1024 * 1024);
        let opts = FatFormatOpts {
            total_sectors: 64 * 1024 * 1024 / 512,
            volume_id: 0x1234_5678,
            volume_label: *b"VERIFYTEST ",
            ..Default::default()
        };
        let mut fs = Fat32::format(&mut dev, &opts).unwrap();
        use crate::fs::Filesystem;
        let meta = crate::fs::FileMeta::default();
        fs.create_dir(&mut dev, std::path::Path::new("/sub"), meta)
            .unwrap();
        for i in 0..20usize {
            let body = vec![i as u8; 1000 + i * 3000];
            fs.create_file(
                &mut dev,
                std::path::Path::new(&format!("/sub/f{i}.bin")),
                crate::fs::FileSource::Reader {
                    reader: Box::new(std::io::Cursor::new(body.clone())),
                    len: body.len() as u64,
                },
                meta,
            )
            .unwrap();
        }
        fs.flush(&mut dev).unwrap();
        dev
    }

    #[test]
    fn fresh_fat32_verifies_clean_and_damage_is_found() {
        let mut dev = sample();
        let r = verify(&mut dev, &VerifyOpts::default()).unwrap();
        assert!(r.is_clean(), "{:#?}", r.diagnostics);
        assert_eq!(r.fs, "fat32");
        assert_eq!(r.stats.files, 20);
        // Leak a cluster in both FATs.
        let mut b0 = [0u8; 512];
        dev.read_at(0, &mut b0).unwrap();
        let bs = BootSector::decode(&b0).unwrap();
        let base = u64::from(bs.reserved_sector_count) * 512;
        let cl = bs.cluster_count() as u64 - 5;
        for i in 0..u64::from(bs.num_fats) {
            let off = base + i * u64::from(bs.fat_size) * 512 + cl * 4;
            dev.write_at(off, &0x0FFF_FFFFu32.to_le_bytes()).unwrap();
        }
        let r = verify(&mut dev, &VerifyOpts::default()).unwrap();
        assert!(r.has(DiagCode::BitmapLeakedBlocks), "{:#?}", r.diagnostics);
        // FAT copies that disagree.
        let off = base + u64::from(bs.fat_size) * 512 + cl * 4;
        dev.write_at(off, &0u32.to_le_bytes()).unwrap();
        let r = verify(&mut dev, &VerifyOpts::default()).unwrap();
        assert!(r.has(DiagCode::TableCopiesDiffer));
    }
}
