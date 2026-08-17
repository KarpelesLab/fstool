//! FAT boot sector + BIOS Parameter Block (BPB).
//!
//! The boot sector is sector 0 (512 bytes). FAT32 also keeps a backup copy
//! at sector 6; FAT12/FAT16 have no backup. Layout (offsets in bytes, all
//! multi-byte fields little-endian) per the public Microsoft FAT
//! specification.
//!
//! The first 36 bytes — the BPB proper — are common to all three flavours:
//!
//! ```text
//!     0   3   jump instruction (EB 58 90 on FAT32, EB 3C 90 otherwise)
//!     3   8   OEM name
//!    11   2   bytes_per_sector
//!    13   1   sectors_per_cluster
//!    14   2   reserved_sector_count   (32 for FAT32, 1 for FAT12/16)
//!    16   1   num_fats                (2)
//!    17   2   root_entry_count        (0 for FAT32)
//!    19   2   total_sectors_16        (0 when the count needs 32 bits)
//!    21   1   media                   (0xF8)
//!    22   2   fat_size_16             (0 for FAT32 — see fat_size_32)
//!    24   2   sectors_per_track
//!    26   2   num_heads
//!    28   4   hidden_sectors
//!    32   4   total_sectors_32
//! ```
//!
//! From byte 36 the two dialects diverge. FAT32 (the "FAT32 EBPB"):
//!
//! ```text
//!    36   4   fat_size_32             (sectors per FAT)
//!    40   2   ext_flags
//!    42   2   fs_version              (0)
//!    44   4   root_cluster            (usually 2)
//!    48   2   fs_info_sector          (1)
//!    50   2   backup_boot_sector      (6)
//!    52  12   reserved
//!    64   1   drive_number
//!    65   1   reserved1
//!    66   1   boot_signature          (0x29)
//!    67   4   volume_id
//!    71  11   volume_label
//!    82   8   fs_type                 ("FAT32   ")
//!   510   2   0x55 0xAA
//! ```
//!
//! FAT12/FAT16 (the DOS 4.0 EBPB) instead:
//!
//! ```text
//!    36   1   drive_number
//!    37   1   reserved1
//!    38   1   boot_signature          (0x29)
//!    39   4   volume_id
//!    43  11   volume_label
//!    54   8   fs_type                 ("FAT12   " / "FAT16   ")
//!   510   2   0x55 0xAA
//! ```
//!
//! Note that `fs_type` is documentation, never a signature: a volume's
//! flavour is decided solely by its data-cluster count (see
//! [`FatKind::from_cluster_count`]). [`BootSector::decode`] follows that
//! rule, so it reads FAT12/16 media that name themselves `"FAT     "` — or
//! nothing at all — just as happily.

use super::table::FatKind;

/// Bytes in a boot sector.
pub const BOOT_SECTOR_SIZE: usize = 512;

/// Extended-BPB signature marking `volume_id` / `volume_label` / `fs_type`
/// as present.
const EXT_BOOT_SIGNATURE: u8 = 0x29;

/// Fields of a FAT boot sector. Only the values fstool needs to set or
/// read are modelled; boot code is left zero (we produce data images, not
/// bootable media).
#[derive(Debug, Clone)]
pub struct BootSector {
    /// Entry width, derived from the data-cluster count.
    pub kind: FatKind,
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub reserved_sector_count: u16,
    pub num_fats: u8,
    /// Slots in the fixed root directory. `0` on FAT32, where the root is
    /// an ordinary cluster chain instead.
    pub root_entry_count: u16,
    pub media: u8,
    pub sectors_per_track: u16,
    pub num_heads: u16,
    pub hidden_sectors: u32,
    pub total_sectors: u32,
    pub fat_size: u32,
    /// First cluster of the root directory. `0` on FAT12/FAT16, whose root
    /// lives in a fixed region rather than a chain — the same `0` those
    /// volumes already use in a `..` entry pointing at the root.
    pub root_cluster: u32,
    pub fs_info_sector: u16,
    pub backup_boot_sector: u16,
    pub drive_number: u8,
    pub volume_id: u32,
    pub volume_label: [u8; 11],
}

impl BootSector {
    /// A BootSector with `kind`-conventional fixed fields and the rest
    /// zero. Caller fills `sectors_per_cluster`, `total_sectors`,
    /// `fat_size`, and (for FAT12/16) `root_entry_count`.
    pub fn defaults_for(kind: FatKind) -> Self {
        let fat32 = kind == FatKind::Fat32;
        Self {
            kind,
            bytes_per_sector: 512,
            sectors_per_cluster: 1,
            reserved_sector_count: if fat32 { 32 } else { 1 },
            num_fats: 2,
            root_entry_count: if fat32 { 0 } else { 512 },
            media: 0xF8,
            sectors_per_track: 32,
            num_heads: 8,
            hidden_sectors: 0,
            total_sectors: 0,
            fat_size: 0,
            root_cluster: if fat32 { 2 } else { 0 },
            fs_info_sector: if fat32 { 1 } else { 0 },
            backup_boot_sector: if fat32 { 6 } else { 0 },
            drive_number: 0x80,
            volume_id: 0,
            volume_label: *b"NO NAME    ",
        }
    }

    /// Sectors occupied by the FAT12/FAT16 fixed root directory. Zero on
    /// FAT32.
    pub fn root_dir_sectors(&self) -> u32 {
        let bytes = u32::from(self.root_entry_count) * 32;
        bytes.div_ceil(u32::from(self.bytes_per_sector))
    }

    /// First sector of the FAT12/FAT16 fixed root directory — immediately
    /// after the last FAT copy. Meaningless on FAT32.
    pub fn root_dir_start_sector(&self) -> u32 {
        self.reserved_sector_count as u32 + self.num_fats as u32 * self.fat_size
    }

    /// First data sector — where cluster 2 begins. Clusters are numbered
    /// from 2, so cluster `n` starts at `data_start + (n-2)*spc`.
    pub fn data_start_sector(&self) -> u32 {
        self.root_dir_start_sector() + self.root_dir_sectors()
    }

    /// Total number of data clusters in the volume.
    pub fn cluster_count(&self) -> u32 {
        let data_sectors = self.total_sectors.saturating_sub(self.data_start_sector());
        data_sectors / self.sectors_per_cluster as u32
    }

    /// Encode into the 512-byte on-disk boot sector.
    pub fn encode(&self) -> [u8; BOOT_SECTOR_SIZE] {
        let fat32 = self.kind == FatKind::Fat32;
        let mut b = [0u8; BOOT_SECTOR_SIZE];
        // Jump instruction + OEM name. The jump target differs because the
        // two EBPBs put boot code at different offsets.
        b[0..3].copy_from_slice(&[0xEB, if fat32 { 0x58 } else { 0x3C }, 0x90]);
        b[3..11].copy_from_slice(b"fstool  ");
        b[11..13].copy_from_slice(&self.bytes_per_sector.to_le_bytes());
        b[13] = self.sectors_per_cluster;
        b[14..16].copy_from_slice(&self.reserved_sector_count.to_le_bytes());
        b[16] = self.num_fats;
        b[17..19].copy_from_slice(&self.root_entry_count.to_le_bytes());
        // A sector count that fits in 16 bits goes in the 16-bit field and
        // leaves the 32-bit one zero — FAT32 always uses the 32-bit field.
        let use_16 = !fat32 && self.total_sectors < 0x1_0000;
        if use_16 {
            b[19..21].copy_from_slice(&(self.total_sectors as u16).to_le_bytes());
        } else {
            b[32..36].copy_from_slice(&self.total_sectors.to_le_bytes());
        }
        b[21] = self.media;
        if !fat32 {
            b[22..24].copy_from_slice(&(self.fat_size as u16).to_le_bytes());
        }
        b[24..26].copy_from_slice(&self.sectors_per_track.to_le_bytes());
        b[26..28].copy_from_slice(&self.num_heads.to_le_bytes());
        b[28..32].copy_from_slice(&self.hidden_sectors.to_le_bytes());
        if fat32 {
            b[36..40].copy_from_slice(&self.fat_size.to_le_bytes());
            // 40..42 ext_flags = 0; 42..44 fs_version = 0.
            b[44..48].copy_from_slice(&self.root_cluster.to_le_bytes());
            b[48..50].copy_from_slice(&self.fs_info_sector.to_le_bytes());
            b[50..52].copy_from_slice(&self.backup_boot_sector.to_le_bytes());
            b[64] = self.drive_number;
            b[66] = EXT_BOOT_SIGNATURE;
            b[67..71].copy_from_slice(&self.volume_id.to_le_bytes());
            b[71..82].copy_from_slice(&self.volume_label);
            b[82..90].copy_from_slice(self.kind.fs_type_label());
        } else {
            b[36] = self.drive_number;
            b[38] = EXT_BOOT_SIGNATURE;
            b[39..43].copy_from_slice(&self.volume_id.to_le_bytes());
            b[43..54].copy_from_slice(&self.volume_label);
            b[54..62].copy_from_slice(self.kind.fs_type_label());
        }
        b[510] = 0x55;
        b[511] = 0xAA;
        b
    }

    /// Decode a 512-byte boot sector, deriving the FAT flavour from the
    /// geometry it declares.
    ///
    /// Validates the 0x55AA signature and every BPB field the cluster-count
    /// arithmetic depends on, so a non-FAT sector that happens to end in
    /// 0x55AA (an MBR, say) is rejected here rather than producing a
    /// nonsense geometry downstream.
    pub fn decode(b: &[u8; BOOT_SECTOR_SIZE]) -> crate::Result<Self> {
        if b[510] != 0x55 || b[511] != 0xAA {
            return Err(crate::Error::InvalidImage(
                "fat: missing 0x55AA boot-sector signature".into(),
            ));
        }
        let bytes_per_sector = u16::from_le_bytes(b[11..13].try_into().unwrap());
        if !(512..=4096).contains(&bytes_per_sector) || !bytes_per_sector.is_power_of_two() {
            return Err(crate::Error::InvalidImage(format!(
                "fat: bytes_per_sector must be a power of two in 512..=4096 (got \
                 {bytes_per_sector})"
            )));
        }
        let sectors_per_cluster = b[13];
        if sectors_per_cluster == 0
            || !sectors_per_cluster.is_power_of_two()
            || sectors_per_cluster > 128
        {
            return Err(crate::Error::InvalidImage(format!(
                "fat: sectors_per_cluster must be a power of two in 1..=128 (got \
                 {sectors_per_cluster})"
            )));
        }
        let reserved_sector_count = u16::from_le_bytes(b[14..16].try_into().unwrap());
        if reserved_sector_count == 0 {
            return Err(crate::Error::InvalidImage(
                "fat: reserved_sector_count must be at least 1".into(),
            ));
        }
        let num_fats = b[16];
        if num_fats == 0 || num_fats > 4 {
            return Err(crate::Error::InvalidImage(format!(
                "fat: num_fats must be in 1..=4 (got {num_fats})"
            )));
        }
        let root_entry_count = u16::from_le_bytes(b[17..19].try_into().unwrap());
        let total_16 = u16::from_le_bytes(b[19..21].try_into().unwrap());
        let fat_size_16 = u16::from_le_bytes(b[22..24].try_into().unwrap());
        let total_32 = u32::from_le_bytes(b[32..36].try_into().unwrap());
        let fat_size_32 = u32::from_le_bytes(b[36..40].try_into().unwrap());
        // Either field may carry the value; the 16-bit one wins when set,
        // exactly as the spec prescribes.
        let total_sectors = if total_16 != 0 {
            u32::from(total_16)
        } else {
            total_32
        };
        let fat_size = if fat_size_16 != 0 {
            u32::from(fat_size_16)
        } else {
            fat_size_32
        };
        if fat_size == 0 || total_sectors == 0 {
            return Err(crate::Error::InvalidImage(
                "fat: boot sector declares a zero FAT size or volume size".into(),
            ));
        }
        // Derive the cluster count in u64 so a hostile FAT size can't wrap
        // the metadata sum before the bounds check below catches it.
        let root_sectors = (u32::from(root_entry_count) * 32).div_ceil(u32::from(bytes_per_sector));
        let data_start = u64::from(reserved_sector_count)
            + u64::from(num_fats) * u64::from(fat_size)
            + u64::from(root_sectors);
        if data_start >= u64::from(total_sectors) {
            return Err(crate::Error::InvalidImage(format!(
                "fat: metadata ({data_start} sectors) overruns the volume of \
                 {total_sectors} sectors"
            )));
        }
        let clusters =
            ((u64::from(total_sectors) - data_start) / u64::from(sectors_per_cluster)) as u32;
        let kind = FatKind::from_cluster_count(clusters);
        // A FAT32 volume keeps the root as a chain and must not declare a
        // fixed root region; FAT12/16 must declare one.
        if kind == FatKind::Fat32 && root_entry_count != 0 {
            return Err(crate::Error::InvalidImage(
                "fat32: root_entry_count must be 0 on a FAT32 volume".into(),
            ));
        }
        if kind != FatKind::Fat32 && root_entry_count == 0 {
            return Err(crate::Error::InvalidImage(format!(
                "{}: root_entry_count must be non-zero",
                kind.as_str()
            )));
        }
        let mut volume_label = *b"NO NAME    ";
        let mut volume_id = 0u32;
        let (root_cluster, fs_info_sector, backup_boot_sector, drive_number) =
            if kind == FatKind::Fat32 {
                if b[66] == EXT_BOOT_SIGNATURE {
                    volume_id = u32::from_le_bytes(b[67..71].try_into().unwrap());
                    volume_label.copy_from_slice(&b[71..82]);
                }
                (
                    u32::from_le_bytes(b[44..48].try_into().unwrap()),
                    u16::from_le_bytes(b[48..50].try_into().unwrap()),
                    u16::from_le_bytes(b[50..52].try_into().unwrap()),
                    b[64],
                )
            } else {
                if b[38] == EXT_BOOT_SIGNATURE {
                    volume_id = u32::from_le_bytes(b[39..43].try_into().unwrap());
                    volume_label.copy_from_slice(&b[43..54]);
                }
                (0, 0, 0, b[36])
            };
        Ok(Self {
            kind,
            bytes_per_sector,
            sectors_per_cluster,
            reserved_sector_count,
            num_fats,
            root_entry_count,
            media: b[21],
            sectors_per_track: u16::from_le_bytes(b[24..26].try_into().unwrap()),
            num_heads: u16::from_le_bytes(b[26..28].try_into().unwrap()),
            hidden_sectors: u32::from_le_bytes(b[28..32].try_into().unwrap()),
            total_sectors,
            fat_size,
            root_cluster,
            fs_info_sector,
            backup_boot_sector,
            drive_number,
            volume_id,
            volume_label,
        })
    }
}

/// Cheap, conservative probe: does this 512-byte sector look like a FAT
/// boot sector, and if so which flavour?
///
/// [`BootSector::decode`] already rejects a nonsense BPB, but a decodable
/// BPB is not by itself proof — so this also demands the x86 jump
/// instruction and a legal media descriptor that every real FAT volume
/// carries. Used by `detect_fs`, which cannot rely on a magic string:
/// FAT12/FAT16 have none.
pub fn probe(b: &[u8; BOOT_SECTOR_SIZE]) -> Option<FatKind> {
    // Boot sectors start with a short or near jump over the BPB.
    if b[0] != 0xEB && b[0] != 0xE9 {
        return None;
    }
    // Media descriptors run 0xF0 and 0xF8..=0xFF; anything else is noise.
    if b[21] < 0xF0 || (b[21] > 0xF0 && b[21] < 0xF8) {
        return None;
    }
    BootSector::decode(b).ok().map(|bs| bs.kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fat32_roundtrip() {
        let mut bs = BootSector::defaults_for(FatKind::Fat32);
        bs.total_sectors = 131072;
        bs.fat_size = 1009;
        bs.volume_id = 0x1234_5678;
        bs.volume_label = *b"REFVOL     ";
        let enc = bs.encode();
        assert_eq!(&enc[82..87], b"FAT32");
        let dec = BootSector::decode(&enc).unwrap();
        assert_eq!(dec.kind, FatKind::Fat32);
        assert_eq!(dec.total_sectors, 131072);
        assert_eq!(dec.fat_size, 1009);
        assert_eq!(dec.root_cluster, 2);
        assert_eq!(dec.reserved_sector_count, 32);
        assert_eq!(dec.num_fats, 2);
        assert_eq!(dec.volume_id, 0x1234_5678);
        assert_eq!(&dec.volume_label, b"REFVOL     ");
    }

    /// A 16 MiB FAT16: 32768 sectors, spc 1, 512 root slots. The label and
    /// volume id live at the DOS-4.0 offsets, not the FAT32 ones.
    #[test]
    fn fat16_roundtrip() {
        let mut bs = BootSector::defaults_for(FatKind::Fat16);
        bs.total_sectors = 32768;
        bs.fat_size = 128;
        bs.volume_id = 0xDEAD_BEEF;
        bs.volume_label = *b"SIXTEEN    ";
        let enc = bs.encode();
        assert_eq!(&enc[54..59], b"FAT16");
        // The 16-bit sector count is used; the 32-bit field stays zero.
        assert_eq!(u16::from_le_bytes(enc[19..21].try_into().unwrap()), 32768);
        assert_eq!(u32::from_le_bytes(enc[32..36].try_into().unwrap()), 0);
        let dec = BootSector::decode(&enc).unwrap();
        assert_eq!(dec.kind, FatKind::Fat16);
        assert_eq!(dec.root_cluster, 0);
        assert_eq!(dec.root_entry_count, 512);
        assert_eq!(dec.total_sectors, 32768);
        assert_eq!(dec.fat_size, 128);
        assert_eq!(dec.volume_id, 0xDEAD_BEEF);
        assert_eq!(&dec.volume_label, b"SIXTEEN    ");
        // 1 reserved + 2*128 FAT + 32 root sectors.
        assert_eq!(dec.root_dir_sectors(), 32);
        assert_eq!(dec.data_start_sector(), 1 + 256 + 32);
    }

    /// A 1.44 MB floppy: 2880 sectors, spc 1, 224 root slots → FAT12.
    #[test]
    fn fat12_floppy_roundtrip() {
        let mut bs = BootSector::defaults_for(FatKind::Fat12);
        bs.total_sectors = 2880;
        bs.fat_size = 9;
        bs.root_entry_count = 224;
        bs.volume_label = *b"FLOPPY     ";
        let enc = bs.encode();
        assert_eq!(&enc[54..59], b"FAT12");
        let dec = BootSector::decode(&enc).unwrap();
        assert_eq!(dec.kind, FatKind::Fat12);
        assert_eq!(dec.root_entry_count, 224);
        assert_eq!(dec.root_dir_sectors(), 14);
        assert_eq!(dec.data_start_sector(), 1 + 18 + 14);
        assert_eq!(dec.cluster_count(), 2880 - 33);
        assert!(dec.cluster_count() < FatKind::Fat16.min_clusters());
    }

    /// The flavour comes from the cluster count, never from `fs_type` — a
    /// FAT16 volume mislabelled "FAT12   " still decodes as FAT16.
    #[test]
    fn fs_type_string_does_not_decide_the_flavour() {
        let mut bs = BootSector::defaults_for(FatKind::Fat16);
        bs.total_sectors = 32768;
        bs.fat_size = 128;
        let mut enc = bs.encode();
        enc[54..62].copy_from_slice(b"FAT12   ");
        assert_eq!(BootSector::decode(&enc).unwrap().kind, FatKind::Fat16);
    }

    #[test]
    fn data_start_and_cluster_count() {
        let mut bs = BootSector::defaults_for(FatKind::Fat32);
        bs.total_sectors = 131072;
        bs.fat_size = 1009;
        // 32 reserved + 2 * 1009 = 2050.
        assert_eq!(bs.data_start_sector(), 2050);
        // (131072 - 2050) / 1 = 129022 clusters.
        assert_eq!(bs.cluster_count(), 129022);
    }

    #[test]
    fn bad_signature_rejected() {
        let buf = [0u8; BOOT_SECTOR_SIZE];
        assert!(BootSector::decode(&buf).is_err());
    }

    #[test]
    fn probe_identifies_each_flavour_and_rejects_noise() {
        for (kind, total, fat_size, root) in [
            (FatKind::Fat12, 2880u32, 9u32, 224u16),
            (FatKind::Fat16, 32768, 128, 512),
            (FatKind::Fat32, 131072, 1009, 0),
        ] {
            let mut bs = BootSector::defaults_for(kind);
            bs.total_sectors = total;
            bs.fat_size = fat_size;
            bs.root_entry_count = root;
            assert_eq!(probe(&bs.encode()), Some(kind));
        }
        // An MBR-ish sector: right trailing signature, no jump, no BPB.
        let mut mbr = [0u8; BOOT_SECTOR_SIZE];
        mbr[510] = 0x55;
        mbr[511] = 0xAA;
        assert_eq!(probe(&mbr), None);
        // A valid BPB with an impossible media byte is not FAT.
        let mut bs = BootSector::defaults_for(FatKind::Fat16);
        bs.total_sectors = 32768;
        bs.fat_size = 128;
        bs.media = 0x00;
        assert_eq!(probe(&bs.encode()), None);
    }

    /// 0x55AA alone must not be enough: a sector whose BPB is nonsense is
    /// not a FAT volume.
    #[test]
    fn signature_without_a_sane_bpb_is_rejected() {
        let mut buf = [0u8; BOOT_SECTOR_SIZE];
        buf[510] = 0x55;
        buf[511] = 0xAA;
        assert!(BootSector::decode(&buf).is_err(), "zero BPB");
        // Plausible sector size, but sectors_per_cluster is not a power of 2.
        buf[11..13].copy_from_slice(&512u16.to_le_bytes());
        buf[13] = 3;
        assert!(BootSector::decode(&buf).is_err(), "spc = 3");
    }
}
