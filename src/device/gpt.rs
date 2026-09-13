//! The EFI GUID Partition Table, read without an allocator.
//!
//! GPT is what anything above 2 TB uses, what every UEFI machine boots from,
//! and increasingly what removable media arrives with — so a driver that
//! mounts "the volume on this medium" has to read one. This is the smallest
//! thing that answers where a volume starts:
//!
//! ```text
//!   LBA 0       protective MBR — one 0xEE entry covering the disk
//!   LBA 1       primary header ("EFI PART", CRC-protected)
//!   LBA 2..     primary entry array, 128 bytes per entry by default
//!   …
//!   last-1..    backup entry array
//!   last LBA    backup header
//! ```
//!
//! [`Table::read`] takes the header from LBA 1, falling back to the backup at
//! the last sector when the primary's CRC does not check out — which is the
//! whole point of there being two — and [`Table::entry`] decodes one slot at
//! a time through a sector of scratch the caller already has. Nothing here
//! allocates, and the caller's [`SectorDriver`] is the only way it touches
//! the medium.
//!
//! [`part::Gpt`](crate::part::Gpt) is the hosted counterpart: it owns a
//! table, builds and writes one, and speaks
//! [`BlockDevice`](crate::block::BlockDevice). Unlike that one, the reader
//! here does not insist on 512-byte sectors — the header says where the entry
//! array is, so a 4 KiB-sector medium works the same way.

use super::SectorDriver;

/// Signature at the start of a GPT header.
pub const SIGNATURE: &[u8; 8] = b"EFI PART";

/// The revision this reader understands (1.0).
pub const REVISION: u32 = 0x0001_0000;

/// Smallest legal header size, and the part of it the CRC covers.
pub const MIN_HEADER_SIZE: u32 = 92;

/// Smallest legal partition entry.
pub const MIN_ENTRY_SIZE: u32 = 128;

/// Entries this reader will walk. The specification requires a table to
/// reserve at least 16 KiB for the array — 128 entries of 128 bytes — and
/// nothing in the wild exceeds it; a header claiming more is read up to here.
pub const MAX_ENTRIES: u32 = 128;

/// A GPT type or instance GUID, as the sixteen bytes on disk.
///
/// GPT stores the first three fields little-endian and the last two big-
/// endian, which is why this is kept as bytes: comparing and copying them
/// needs no interpretation, and a consumer that wants to print one can format
/// it however it likes. [`Guid::from_fields`] builds one from the usual
/// hex-grouped spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Guid(pub [u8; 16]);

impl Guid {
    /// The all-zero GUID, which marks an unused entry.
    pub const NIL: Guid = Guid([0u8; 16]);

    /// Build a GUID from the five groups of its canonical spelling —
    /// `Guid::from_fields(0xC12A7328, 0xF81F, 0x11D2, 0xBA4B, 0x00A0C93EC93B)`
    /// is the EFI system partition — applying GPT's mixed endianness.
    pub const fn from_fields(a: u32, b: u16, c: u16, d: u16, e: u64) -> Guid {
        let a = a.to_le_bytes();
        let b = b.to_le_bytes();
        let c = c.to_le_bytes();
        let d = d.to_be_bytes();
        let e = e.to_be_bytes();
        Guid([
            a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], d[0], d[1], e[2], e[3], e[4], e[5],
            e[6], e[7],
        ])
    }

    /// Whether this is the all-zero GUID.
    pub fn is_nil(&self) -> bool {
        self.0 == [0u8; 16]
    }
}

/// Microsoft basic data — what FAT, exFAT and NTFS volumes are labelled
/// with, and what a removable medium's data partition almost always is.
pub const BASIC_DATA: Guid =
    Guid::from_fields(0xEBD0_A0A2, 0xB9E5, 0x4433, 0x87C0, 0x68B6_B726_99C7);
/// The EFI system partition, which is always FAT.
pub const EFI_SYSTEM: Guid =
    Guid::from_fields(0xC12A_7328, 0xF81F, 0x11D2, 0xBA4B, 0x00A0_C93E_C93B);
/// Linux filesystem data.
pub const LINUX_FS: Guid = Guid::from_fields(0x0FC6_3DAF, 0x8483, 0x4772, 0x8E79, 0x3D69_D847_7DE4);
/// Apple HFS / HFS+.
pub const APPLE_HFS: Guid = Guid::from_fields(0x48465300, 0x0000, 0x11AA, 0xAA11, 0x0030_6543_ECAC);

/// A GPT header, decoded and CRC-checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// The LBA this header was read from, as the header itself records it.
    pub my_lba: u64,
    /// Where the other copy of the header lives.
    pub alternate_lba: u64,
    /// First and last sector a partition may occupy.
    pub first_usable_lba: u64,
    pub last_usable_lba: u64,
    /// The disk's own GUID.
    pub disk_guid: Guid,
    /// First sector of the partition entry array.
    pub entries_lba: u64,
    /// Entries the array holds, and the size of each.
    pub entry_count: u32,
    pub entry_size: u32,
    /// CRC-32 the header records for the entry array. A caller that wants to
    /// verify the array itself can compute it with
    /// [`crate::crc::crc32_small`] over every entry in order — this reader
    /// does not, since that means reading the whole array twice.
    pub entries_crc32: u32,
}

impl Header {
    /// Decode a header out of the sector it lives in, verifying its CRC.
    ///
    /// `None` when this is not a GPT header, is a revision this reader does
    /// not understand, fails its checksum, or describes an array it could not
    /// walk.
    pub fn decode(sector: &[u8]) -> Option<Header> {
        if sector.len() < MIN_HEADER_SIZE as usize || &sector[0..8] != SIGNATURE {
            return None;
        }
        if le32(sector, 8) != REVISION {
            return None;
        }
        let header_size = le32(sector, 12);
        if header_size < MIN_HEADER_SIZE || header_size as usize > sector.len() {
            return None;
        }
        // The CRC covers `header_size` bytes with its own field zeroed. It is
        // computed a piece at a time so that no copy of the sector is needed.
        let stored = le32(sector, 16);
        // `crc32_small`, not `crc32`: the table-driven one would pull 8 KiB
        // of lookup tables into a firmware image to checksum 92 bytes.
        let crc = crate::crc::crc32_small_append(
            crate::crc::crc32_small_append(
                crate::crc::crc32_small_append(0, &sector[..16]),
                &[0, 0, 0, 0],
            ),
            &sector[20..header_size as usize],
        );
        if stored != crc {
            return None;
        }
        let entry_size = le32(sector, 84);
        if entry_size < MIN_ENTRY_SIZE {
            return None;
        }
        let mut guid = [0u8; 16];
        guid.copy_from_slice(&sector[56..72]);
        Some(Header {
            my_lba: le64(sector, 24),
            alternate_lba: le64(sector, 32),
            first_usable_lba: le64(sector, 40),
            last_usable_lba: le64(sector, 48),
            disk_guid: Guid(guid),
            entries_lba: le64(sector, 72),
            entry_count: le32(sector, 80),
            entry_size,
            entries_crc32: le32(sector, 88),
        })
    }

    /// Entries this reader will walk: what the header claims, bounded by
    /// [`MAX_ENTRIES`].
    pub fn entries(&self) -> u32 {
        self.entry_count.min(MAX_ENTRIES)
    }

    /// Where entry `index` lives: its sector, and its offset within it.
    ///
    /// `None` when the entry would fall outside the array or the arithmetic
    /// would overflow — which a header from an untrusted medium can ask for.
    pub fn entry_position(&self, index: u32, sector_size: u32) -> Option<(u64, usize)> {
        if index >= self.entries() || sector_size == 0 {
            return None;
        }
        let off = (index as u64).checked_mul(self.entry_size as u64)?;
        let lba = self.entries_lba.checked_add(off / sector_size as u64)?;
        let at = (off % sector_size as u64) as usize;
        // An entry never straddles two sectors: the entry size is a power of
        // two of at least 128 and sectors are at least 512.
        if at + MIN_ENTRY_SIZE as usize > sector_size as usize {
            return None;
        }
        Some((lba, at))
    }
}

/// One partition the table describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Partition {
    /// 0-based slot in the entry array.
    pub index: u32,
    /// What the partition holds, as a type GUID.
    pub type_guid: Guid,
    /// The partition's own GUID.
    pub guid: Guid,
    /// First and last sector it occupies, both inclusive.
    pub start_lba: u64,
    pub end_lba: u64,
    /// Attribute flags — bit 0 is "required", bit 60 read-only.
    pub attributes: u64,
}

impl Partition {
    /// Decode one entry of the array. `None` for an unused slot — a nil type
    /// GUID — or one whose extent makes no sense.
    pub fn decode(entry: &[u8], index: u32) -> Option<Partition> {
        if entry.len() < MIN_ENTRY_SIZE as usize {
            return None;
        }
        let mut type_guid = [0u8; 16];
        type_guid.copy_from_slice(&entry[0..16]);
        let type_guid = Guid(type_guid);
        if type_guid.is_nil() {
            return None;
        }
        let mut guid = [0u8; 16];
        guid.copy_from_slice(&entry[16..32]);
        let start_lba = le64(entry, 32);
        let end_lba = le64(entry, 40);
        if end_lba < start_lba {
            return None;
        }
        Some(Partition {
            index,
            type_guid,
            guid: Guid(guid),
            start_lba,
            end_lba,
            attributes: le64(entry, 48),
        })
    }

    /// Sectors the partition spans.
    ///
    /// Both bounds are inclusive, so this is one more than their difference —
    /// saturating, because an entry off untrusted media can name the whole
    /// 64-bit range and the count would then not fit in it.
    pub fn sectors(&self) -> u64 {
        (self.end_lba - self.start_lba).saturating_add(1)
    }

    /// Whether the type GUID is the one FAT, exFAT and NTFS volumes carry.
    pub fn is_basic_data(&self) -> bool {
        self.type_guid == BASIC_DATA
    }

    /// Whether the type GUID is the EFI system partition's, which is FAT.
    pub fn is_efi_system(&self) -> bool {
        self.type_guid == EFI_SYSTEM
    }

    /// Whether the type GUID is one a FAT or exFAT volume is normally found
    /// under. A volume is still mounted by reading its boot sector, never by
    /// trusting this.
    pub fn looks_like_fat_family(&self) -> bool {
        self.is_basic_data() || self.is_efi_system()
    }

    /// Whether the read-only attribute (bit 60) is set.
    pub fn is_read_only(&self) -> bool {
        self.attributes & (1 << 60) != 0
    }

    /// The partition's name, as UTF-16 code units, into `out`. Returns how
    /// many were written; names are at most 36 units and usually empty.
    pub fn name_from(entry: &[u8], out: &mut [u16]) -> usize {
        let mut n = 0;
        for i in 0..36 {
            let at = 56 + i * 2;
            if at + 2 > entry.len() || n >= out.len() {
                break;
            }
            let unit = le16(entry, at);
            if unit == 0 {
                break;
            }
            out[n] = unit;
            n += 1;
        }
        n
    }
}

/// A GPT on a medium, ready to have its entries read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Table {
    /// The header this table was read from.
    pub header: Header,
    /// Whether it came from the backup at the end of the medium rather than
    /// the primary at LBA 1.
    pub from_backup: bool,
}

impl Table {
    /// Read the table's header from `dev`, primary first and then the backup.
    ///
    /// `scratch` must be at least one sector long; the sector it holds
    /// afterwards is not defined. Returns `Ok(None)` when the medium carries
    /// no readable GPT — which is not an error, just an answer.
    pub fn read<D: SectorDriver>(
        dev: &mut D,
        scratch: &mut [u8],
    ) -> Result<Option<Table>, D::Error> {
        let ss = dev.sector_size() as usize;
        if scratch.len() < ss || ss == 0 || dev.sector_count() < 2 {
            return Ok(None);
        }
        let buf = &mut scratch[..ss];
        // The primary header sits at LBA 1, immediately after the protective
        // MBR.
        dev.read_sectors(1, buf)?;
        if let Some(header) = Header::decode(buf) {
            return Ok(Some(Table {
                header,
                from_backup: false,
            }));
        }
        // The backup lives in the last sector. Two copies is the format's
        // answer to a torn write, so a reader that never looks at the second
        // one has thrown that away.
        let last = dev.sector_count() - 1;
        dev.read_sectors(last, buf)?;
        match Header::decode(buf) {
            Some(header) => Ok(Some(Table {
                header,
                from_backup: true,
            })),
            None => Ok(None),
        }
    }

    /// Entries this table holds.
    pub fn entries(&self) -> u32 {
        self.header.entries()
    }

    /// Read entry `index`. `Ok(None)` for an unused slot, or an index past
    /// the end of the array.
    ///
    /// `scratch` must be at least one sector long and is used for the read.
    pub fn entry<D: SectorDriver>(
        &self,
        dev: &mut D,
        scratch: &mut [u8],
        index: u32,
    ) -> Result<Option<Partition>, D::Error> {
        let ss = dev.sector_size();
        let Some((lba, at)) = self.header.entry_position(index, ss) else {
            return Ok(None);
        };
        if scratch.len() < ss as usize || lba >= dev.sector_count() {
            return Ok(None);
        }
        let buf = &mut scratch[..ss as usize];
        dev.read_sectors(lba, buf)?;
        Ok(Partition::decode(&buf[at..], index))
    }
}

fn le16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

fn le32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn le64(b: &[u8], off: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[off..off + 8]);
    u64::from_le_bytes(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A medium with a GPT: protective MBR, primary header and array, and the
    /// backup pair at the end.
    struct Disk(alloc::vec::Vec<u8>);

    impl SectorDriver for Disk {
        type Error = core::convert::Infallible;
        fn sector_size(&self) -> u32 {
            512
        }
        fn sector_count(&self) -> u64 {
            self.0.len() as u64 / 512
        }
        fn read_sectors(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), Self::Error> {
            let at = lba as usize * 512;
            buf.copy_from_slice(&self.0[at..at + buf.len()]);
            Ok(())
        }
        fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> Result<(), Self::Error> {
            let at = lba as usize * 512;
            self.0[at..at + buf.len()].copy_from_slice(buf);
            Ok(())
        }
    }

    /// Build the 128-byte entry for one partition.
    fn entry(type_guid: Guid, start: u64, end: u64, name: &str) -> [u8; 128] {
        let mut e = [0u8; 128];
        e[0..16].copy_from_slice(&type_guid.0);
        e[16..32].copy_from_slice(&[0x11u8; 16]);
        e[32..40].copy_from_slice(&start.to_le_bytes());
        e[40..48].copy_from_slice(&end.to_le_bytes());
        for (i, u) in name.encode_utf16().take(36).enumerate() {
            e[56 + i * 2..58 + i * 2].copy_from_slice(&u.to_le_bytes());
        }
        e
    }

    /// Lay down a GPT describing `parts`, with correct CRCs in both headers.
    fn disk(parts: &[[u8; 128]], sectors: u64) -> Disk {
        let mut data = alloc::vec![0u8; sectors as usize * 512];
        // Protective MBR: one 0xEE partition covering the disk.
        data[446 + 4] = 0xEE;
        data[446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes());
        data[446 + 12..446 + 16].copy_from_slice(&((sectors - 1) as u32).to_le_bytes());
        data[510] = 0x55;
        data[511] = 0xAA;

        // The entry array: 128 entries of 128 bytes = 32 sectors.
        let mut array = alloc::vec![0u8; 128 * 128];
        for (i, p) in parts.iter().enumerate() {
            array[i * 128..(i + 1) * 128].copy_from_slice(p);
        }
        let array_crc = crate::crc::crc32(&array);
        let primary_array_lba = 2u64;
        let backup_array_lba = sectors - 1 - 32;
        data[primary_array_lba as usize * 512..][..array.len()].copy_from_slice(&array);
        data[backup_array_lba as usize * 512..][..array.len()].copy_from_slice(&array);

        let header = |my: u64, alt: u64, entries: u64| -> [u8; 512] {
            let mut h = [0u8; 512];
            h[0..8].copy_from_slice(SIGNATURE);
            h[8..12].copy_from_slice(&REVISION.to_le_bytes());
            h[12..16].copy_from_slice(&92u32.to_le_bytes());
            h[24..32].copy_from_slice(&my.to_le_bytes());
            h[32..40].copy_from_slice(&alt.to_le_bytes());
            h[40..48].copy_from_slice(&34u64.to_le_bytes());
            h[48..56].copy_from_slice(&(sectors - 34).to_le_bytes());
            h[56..72].copy_from_slice(&[0x22u8; 16]);
            h[72..80].copy_from_slice(&entries.to_le_bytes());
            h[80..84].copy_from_slice(&128u32.to_le_bytes());
            h[84..88].copy_from_slice(&128u32.to_le_bytes());
            h[88..92].copy_from_slice(&array_crc.to_le_bytes());
            let crc = crate::crc::crc32(&h[..92]);
            h[16..20].copy_from_slice(&crc.to_le_bytes());
            h
        };
        data[512..1024].copy_from_slice(&header(1, sectors - 1, primary_array_lba));
        data[(sectors - 1) as usize * 512..][..512].copy_from_slice(&header(
            sectors - 1,
            1,
            backup_array_lba,
        ));
        Disk(data)
    }

    #[test]
    fn reads_the_primary_table_and_its_entries() {
        let parts = [
            entry(EFI_SYSTEM, 2048, 133_119, "EFI"),
            entry(BASIC_DATA, 133_120, 999_999, "DATA"),
        ];
        let mut dev = disk(&parts, 1_000_000);
        let mut buf = [0u8; 512];
        let table = Table::read(&mut dev, &mut buf).unwrap().expect("a GPT");
        assert!(!table.from_backup);
        assert_eq!(table.header.entry_count, 128);
        assert_eq!(table.entries(), 128);

        let first = table.entry(&mut dev, &mut buf, 0).unwrap().expect("slot 0");
        assert!(first.is_efi_system() && first.looks_like_fat_family());
        assert_eq!(first.start_lba, 2048);
        assert_eq!(first.sectors(), 131_072);
        let second = table.entry(&mut dev, &mut buf, 1).unwrap().expect("slot 1");
        assert!(second.is_basic_data());
        assert_eq!(second.start_lba, 133_120);
        // Unused slots report nothing, and so does an index past the array.
        assert!(table.entry(&mut dev, &mut buf, 2).unwrap().is_none());
        assert!(table.entry(&mut dev, &mut buf, 999).unwrap().is_none());
    }

    #[test]
    fn falls_back_to_the_backup_header() {
        let parts = [entry(BASIC_DATA, 2048, 99_999, "DATA")];
        let mut dev = disk(&parts, 100_000);
        // Scribble the primary header: the backup is what the format keeps a
        // second copy for.
        dev.0[512..604].fill(0x5A);
        let mut buf = [0u8; 512];
        let table = Table::read(&mut dev, &mut buf).unwrap().expect("a GPT");
        assert!(table.from_backup, "the backup header was not used");
        let p = table.entry(&mut dev, &mut buf, 0).unwrap().expect("slot 0");
        assert_eq!(p.start_lba, 2048);
    }

    #[test]
    fn refuses_a_header_that_does_not_check_out() {
        let parts = [entry(BASIC_DATA, 2048, 99_999, "DATA")];
        // Both copies corrupt: no table at all.
        let mut dev = disk(&parts, 100_000);
        dev.0[512..604].fill(0x5A);
        let last = dev.0.len() - 512;
        dev.0[last..last + 92].fill(0x5A);
        let mut buf = [0u8; 512];
        assert!(Table::read(&mut dev, &mut buf).unwrap().is_none());

        // A one-bit change in the header is a CRC failure, not a silent read.
        let mut dev = disk(&parts, 100_000);
        dev.0[24] ^= 0; // the MBR, untouched
        dev.0[512 + 40] ^= 1; // first_usable_lba in the primary header
        let mut buf = [0u8; 512];
        let table = Table::read(&mut dev, &mut buf).unwrap().expect("backup");
        assert!(table.from_backup);
    }

    #[test]
    fn a_header_with_an_impossible_array_is_refused() {
        let mut h = [0u8; 512];
        h[0..8].copy_from_slice(SIGNATURE);
        h[8..12].copy_from_slice(&REVISION.to_le_bytes());
        h[12..16].copy_from_slice(&92u32.to_le_bytes());
        // An entry size below the specification's minimum.
        h[84..88].copy_from_slice(&64u32.to_le_bytes());
        let crc = crate::crc::crc32(&h[..92]);
        h[16..20].copy_from_slice(&crc.to_le_bytes());
        assert!(Header::decode(&h).is_none());

        // An entry offset that would overflow.
        let mut h2 = [0u8; 512];
        h2[0..8].copy_from_slice(SIGNATURE);
        h2[8..12].copy_from_slice(&REVISION.to_le_bytes());
        h2[12..16].copy_from_slice(&92u32.to_le_bytes());
        h2[72..80].copy_from_slice(&u64::MAX.to_le_bytes());
        h2[80..84].copy_from_slice(&128u32.to_le_bytes());
        h2[84..88].copy_from_slice(&128u32.to_le_bytes());
        let crc = crate::crc::crc32(&h2[..92]);
        h2[16..20].copy_from_slice(&crc.to_le_bytes());
        let header = Header::decode(&h2).expect("the header itself is well formed");
        // An index whose offset reaches into the next sector overflows the
        // array's start, and is refused rather than wrapped.
        assert!(header.entry_position(5, 512).is_none());
        // One that does not overflow still names a sector past the end of
        // any medium, which is where `Table::entry` stops it.
        assert!(header.entry_position(1, 512).is_some());
        let mut dev = disk(&[entry(BASIC_DATA, 2048, 4095, "x")], 1024);
        let table = Table {
            header,
            from_backup: false,
        };
        let mut buf = [0u8; 512];
        assert!(table.entry(&mut dev, &mut buf, 1).unwrap().is_none());
    }

    #[test]
    fn an_absurd_extent_is_counted_without_overflowing() {
        // A GPT off untrusted media can name the whole 64-bit range. The
        // extent is legal — end is not before start — so it decodes, and the
        // count it implies has to saturate rather than wrap.
        let e = entry(BASIC_DATA, 0, u64::MAX, "huge");
        let p = Partition::decode(&e, 0).expect("a legal, if absurd, extent");
        assert_eq!(p.sectors(), u64::MAX);
        // And the ordinary case is still exact.
        let e = entry(BASIC_DATA, 2048, 4095, "normal");
        assert_eq!(Partition::decode(&e, 0).unwrap().sectors(), 2048);
        // End before start is not an extent at all.
        let e = entry(BASIC_DATA, 4096, 2048, "backwards");
        assert!(Partition::decode(&e, 0).is_none());
    }

    #[test]
    fn guids_are_built_the_way_the_table_stores_them() {
        // The EFI system partition GUID, byte for byte as a GPT holds it.
        assert_eq!(
            EFI_SYSTEM.0,
            [
                0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E,
                0xC9, 0x3B
            ]
        );
        assert_eq!(
            BASIC_DATA.0,
            [
                0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44, 0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26,
                0x99, 0xC7
            ]
        );
        assert!(Guid::NIL.is_nil() && !BASIC_DATA.is_nil());
    }

    #[test]
    fn a_partitions_name_is_read_into_the_callers_buffer() {
        let e = entry(BASIC_DATA, 2048, 4095, "Untitled");
        let mut units = [0u16; 36];
        let n = Partition::name_from(&e, &mut units);
        let name: alloc::string::String = char::decode_utf16(units[..n].iter().copied())
            .map(|c| c.unwrap_or('?'))
            .collect();
        assert_eq!(name, "Untitled");
        // An empty name reads as nothing rather than 36 zeros.
        let e = entry(BASIC_DATA, 2048, 4095, "");
        assert_eq!(Partition::name_from(&e, &mut units), 0);
    }
}
