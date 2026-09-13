//! The exFAT on-disk vocabulary both halves of the backend speak.
//!
//! Nothing here allocates or touches a device: it is the boot sector's
//! fields, the 32-byte directory-entry types and their checksums, and the
//! FAT's sentinel values — the facts about the format itself, in one place
//! so the hosted implementation and the allocator-free driver cannot drift
//! apart on them.
//!
//! Field layouts are documented where they are decoded: the boot sector in
//! [`Boot`], the directory entries in [`super::dir`] (hosted) and mirrored
//! by the driver's own reader.

// Each half of the backend speaks a subset of this vocabulary — the driver
// accumulates checksums an entry at a time, the hosted implementation takes
// them over a buffer it already holds — so some of it is unused in any one
// configuration. It is the format's vocabulary, not dead code.
#![allow(dead_code)]

/// Bytes per on-disk directory entry.
pub const ENTRY_SIZE: usize = 32;

// Entry-type bytes.
/// Allocation bitmap (a primary critical entry in the root).
pub const ENTRY_ALLOCATION_BITMAP: u8 = 0x81;
/// Up-case table (a primary critical entry in the root).
pub const ENTRY_UPCASE_TABLE: u8 = 0x82;
/// Volume label (a primary critical entry in the root).
pub const ENTRY_VOLUME_LABEL: u8 = 0x83;
/// File / directory — the primary entry of a file set.
pub const ENTRY_FILE: u8 = 0x85;
/// Stream extension — the first secondary entry of a file set.
pub const ENTRY_STREAM_EXTENSION: u8 = 0xC0;
/// File name — the remaining secondary entries of a file set.
pub const ENTRY_FILE_NAME: u8 = 0xC1;

/// Mask: an entry is "in use" when its high bit is set. A type byte of
/// `0x00` ends the directory; any other value with this bit clear is a
/// deleted slot.
pub const ENTRY_INUSE: u8 = 0x80;

// FileAttributes bits (from the file entry).
pub const ATTR_READ_ONLY: u16 = 0x0001;
pub const ATTR_HIDDEN: u16 = 0x0002;
pub const ATTR_SYSTEM: u16 = 0x0004;
pub const ATTR_DIRECTORY: u16 = 0x0010;
pub const ATTR_ARCHIVE: u16 = 0x0020;

// GeneralSecondaryFlags bits (stream extension).
/// The stream may own clusters.
pub const SECFLAG_ALLOC_POSSIBLE: u8 = 0x01;
/// The stream's clusters are contiguous and its FAT entries are not valid.
pub const SECFLAG_NO_FAT_CHAIN: u8 = 0x02;

/// UTF-16 code units a name can hold — `NameLength` is one byte, and 17
/// name entries of 15 units each is what a set can carry.
pub const MAX_NAME_UNITS: usize = 255;

/// UTF-16 code units one FileName entry carries.
pub const NAME_UNITS_PER_ENTRY: usize = 15;

/// Largest legal `ClusterCount` (2^32 - 11), per the specification.
///
/// The eleven excluded values leave room for the two reserved FAT entries
/// and the end-of-chain / bad-cluster markers, and guarantee that
/// `cluster_count + 2` — the exclusive end of the data-cluster range —
/// fits in a `u32`.
pub const MAX_CLUSTER_COUNT: u32 = u32::MAX - 10;

// FAT entry values.
/// Free cluster.
pub const FAT_FREE: u32 = 0x0000_0000;
/// Bad-cluster marker.
pub const FAT_BAD: u32 = 0xFFFF_FFF7;
/// End-of-chain marker.
pub const FAT_EOC: u32 = 0xFFFF_FFFF;

/// Classification of one FAT entry's value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FatEntry {
    Free,
    Bad,
    Eoc,
    /// The next cluster in this chain.
    Next(u32),
}

/// Classify a raw 32-bit FAT entry value.
///
/// Per the specification only `0xFFFFFFFF` ends a chain; the reserved
/// `0xFFFFFFF8..=0xFFFFFFFE` values are returned as `Next` so a broken
/// image surfaces rather than being silently followed.
pub fn classify(value: u32) -> FatEntry {
    match value {
        FAT_FREE => FatEntry::Free,
        FAT_BAD => FatEntry::Bad,
        FAT_EOC => FatEntry::Eoc,
        n => FatEntry::Next(n),
    }
}

/// The 16-bit checksum over the bytes of a whole file entry set, primary
/// first. Bytes 2 and 3 of the primary — where the checksum itself lives —
/// are skipped.
pub fn set_checksum(set: &[u8]) -> u16 {
    let mut sum: u16 = 0;
    for (i, &b) in set.iter().enumerate() {
        if i == 2 || i == 3 {
            continue;
        }
        sum = sum.rotate_right(1).wrapping_add(b as u16);
    }
    sum
}

/// Feed one entry of a set into a running [`set_checksum`].
///
/// `index` is the entry's position in the set, so that the primary's
/// checksum field is skipped. Lets a checksum be accumulated an entry at a
/// time, which is what a driver with nowhere to hold the whole set does.
pub fn set_checksum_step(sum: u16, index: usize, entry: &[u8; ENTRY_SIZE]) -> u16 {
    let mut sum = sum;
    for (i, &b) in entry.iter().enumerate() {
        if index == 0 && (i == 2 || i == 3) {
            continue;
        }
        sum = sum.rotate_right(1).wrapping_add(b as u16);
    }
    sum
}

/// The 16-bit NameHash over an up-cased name, as a little-endian u16
/// stream. exFAT stores it so a lookup can reject most names without
/// comparing them.
pub fn name_hash(upcased_le_bytes: &[u8]) -> u16 {
    let mut hash: u16 = 0;
    for &b in upcased_le_bytes {
        hash = hash.rotate_right(1).wrapping_add(b as u16);
    }
    hash
}

/// Feed one up-cased code unit into a running [`name_hash`].
pub fn name_hash_step(hash: u16, unit: u16) -> u16 {
    let mut hash = hash;
    for b in unit.to_le_bytes() {
        hash = hash.rotate_right(1).wrapping_add(b as u16);
    }
    hash
}

/// Rolling 32-bit checksum used for the up-case table. Each byte rotates
/// the accumulator right by one bit and adds the byte.
pub fn table_checksum(bytes: &[u8]) -> u32 {
    table_checksum_step(0, bytes)
}

/// Continue a [`table_checksum`] over another run of bytes.
pub fn table_checksum_step(sum: u32, bytes: &[u8]) -> u32 {
    let mut sum = sum;
    for &b in bytes {
        sum = sum.rotate_right(1).wrapping_add(b as u32);
    }
    sum
}

/// The fields of the main boot sector, decoded and range-checked.
///
/// ```text
///   off  size  name
///     0     3  JumpBoot                  (EB 76 90)
///     3     8  FileSystemName            ("EXFAT   ")
///    11    53  MustBeZero
///    64     8  PartitionOffset           (sectors; advisory)
///    72     8  VolumeLength              (in sectors)
///    80     4  FatOffset                 (sectors from volume start)
///    84     4  FatLength                 (sectors per FAT)
///    88     4  ClusterHeapOffset         (sectors from volume start)
///    92     4  ClusterCount
///    96     4  FirstClusterOfRootDirectory
///   100     4  VolumeSerialNumber
///   104     2  FileSystemRevision        (high = major, low = minor)
///   106     2  VolumeFlags
///   108     1  BytesPerSectorShift       (power of 2: 9..=12 → 512..4096)
///   109     1  SectorsPerClusterShift    (power of 2: 0..=25-BPSshift)
///   110     1  NumberOfFats              (1 or 2; TexFAT uses 2)
///   111     1  DriveSelect
///   112     1  PercentInUse
///   113     7  Reserved
///   120   390  BootCode
///   510     2  BootSignature             (0x55 0xAA)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Boot {
    pub partition_offset: u64,
    pub volume_length: u64,
    pub fat_offset: u32,
    pub fat_length: u32,
    pub cluster_heap_offset: u32,
    pub cluster_count: u32,
    pub first_cluster_of_root_directory: u32,
    pub volume_serial_number: u32,
    pub fs_revision_major: u8,
    pub fs_revision_minor: u8,
    pub volume_flags: u16,
    pub bytes_per_sector_shift: u8,
    pub sectors_per_cluster_shift: u8,
    pub number_of_fats: u8,
    pub drive_select: u8,
    pub percent_in_use: u8,
}

impl Boot {
    /// Bytes per sector — 2^BytesPerSectorShift.
    pub fn bytes_per_sector(&self) -> u32 {
        1u32 << self.bytes_per_sector_shift
    }

    /// Sectors per cluster — 2^SectorsPerClusterShift.
    pub fn sectors_per_cluster(&self) -> u32 {
        1u32 << self.sectors_per_cluster_shift
    }

    /// Bytes per cluster.
    pub fn bytes_per_cluster(&self) -> u32 {
        self.bytes_per_sector() << self.sectors_per_cluster_shift
    }

    /// Decode the first 512 bytes of the volume's first sector.
    ///
    /// The error is a `&'static str` so that a caller with no allocator can
    /// use it; the hosted half wraps it in its own error type.
    pub fn decode(b: &[u8]) -> Result<Self, &'static str> {
        if b.len() < 512 {
            return Err("boot sector is shorter than 512 bytes");
        }
        if &b[3..11] != b"EXFAT   " {
            return Err("missing \"EXFAT   \" signature at offset 3");
        }
        // MustBeZero (offset 11..64) must be all zeros.
        if b[11..64].iter().any(|&x| x != 0) {
            return Err("MustBeZero region is non-zero");
        }
        if b[510] != 0x55 || b[511] != 0xAA {
            return Err("missing 0x55AA boot-sector signature");
        }
        let bytes_per_sector_shift = b[108];
        let sectors_per_cluster_shift = b[109];
        if !(9..=12).contains(&bytes_per_sector_shift) {
            return Err("invalid BytesPerSectorShift (must be 9..=12)");
        }
        if bytes_per_sector_shift as u32 + sectors_per_cluster_shift as u32 > 25 {
            return Err("BytesPerSectorShift + SectorsPerClusterShift exceeds 25");
        }
        let number_of_fats = b[110];
        if number_of_fats != 1 && number_of_fats != 2 {
            return Err("NumberOfFats must be 1 or 2");
        }
        // ClusterCount is capped at 2^32 - 11 by the spec. Enforcing it
        // here means `cluster_count + 2` — the exclusive end of the data
        // range, computed all over both halves — can never overflow.
        let cluster_count = le32(b, 92);
        if cluster_count > MAX_CLUSTER_COUNT {
            return Err("ClusterCount exceeds the specification maximum");
        }
        let fs_revision = le16(b, 104);
        Ok(Self {
            partition_offset: le64(b, 64),
            volume_length: le64(b, 72),
            fat_offset: le32(b, 80),
            fat_length: le32(b, 84),
            cluster_heap_offset: le32(b, 88),
            cluster_count,
            first_cluster_of_root_directory: le32(b, 96),
            volume_serial_number: le32(b, 100),
            fs_revision_major: (fs_revision >> 8) as u8,
            fs_revision_minor: (fs_revision & 0xff) as u8,
            volume_flags: le16(b, 106),
            bytes_per_sector_shift,
            sectors_per_cluster_shift,
            number_of_fats,
            drive_select: b[111],
            percent_in_use: b[112],
        })
    }
}

/// Read a little-endian `u16` at `off`.
pub fn le16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

/// Read a little-endian `u32` at `off`.
pub fn le32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// Read a little-endian `u64` at `off`.
pub fn le64(b: &[u8], off: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[off..off + 8]);
    u64::from_le_bytes(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksums_match_their_streaming_form() {
        // A three-entry set: the streaming accumulator has to agree with
        // the one-shot version, including skipping the primary's own
        // checksum field.
        let mut set = [0u8; 3 * ENTRY_SIZE];
        for (i, b) in set.iter_mut().enumerate() {
            *b = (i * 7 + 1) as u8;
        }
        let one_shot = set_checksum(&set);
        let mut streamed = 0u16;
        for i in 0..3 {
            let entry: &[u8; ENTRY_SIZE] = (&set[i * ENTRY_SIZE..(i + 1) * ENTRY_SIZE])
                .try_into()
                .unwrap();
            streamed = set_checksum_step(streamed, i, entry);
        }
        assert_eq!(one_shot, streamed);

        // And the name hash, unit by unit.
        let units = [0x0041u16, 0x1234, 0xFF21];
        let mut bytes = [0u8; 6];
        for (i, u) in units.iter().enumerate() {
            bytes[i * 2..i * 2 + 2].copy_from_slice(&u.to_le_bytes());
        }
        let one_shot = name_hash(&bytes);
        let streamed = units.iter().fold(0u16, |h, u| name_hash_step(h, *u));
        assert_eq!(one_shot, streamed);
    }

    #[test]
    fn table_checksum_known_values() {
        assert_eq!(table_checksum(&[]), 0);
        assert_eq!(table_checksum(&[0x01]), 1);
        assert_eq!(table_checksum(&[0x01, 0x02]), 0x8000_0002);
        // Split runs accumulate the same way.
        assert_eq!(
            table_checksum_step(table_checksum(&[0x01]), &[0x02]),
            table_checksum(&[0x01, 0x02])
        );
    }

    #[test]
    fn fat_sentinels_classify() {
        assert_eq!(classify(0), FatEntry::Free);
        assert_eq!(classify(FAT_BAD), FatEntry::Bad);
        assert_eq!(classify(FAT_EOC), FatEntry::Eoc);
        assert_eq!(classify(7), FatEntry::Next(7));
        // Reserved values are not silently treated as end-of-chain.
        assert_eq!(classify(0xFFFF_FFFE), FatEntry::Next(0xFFFF_FFFE));
    }
}
