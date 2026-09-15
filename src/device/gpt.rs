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
//! Writing is the same shape. [`write`](fn@write) lays down a whole table — protective
//! MBR, both headers, both entry arrays — from a list of [`NewPartition`]s;
//! [`set_entry`] adds, changes or removes one entry of the table already
//! there, rewriting both copies so a damaged one is repaired on the way;
//! [`erase`] removes a GPT so the medium can take an MBR. A sector of scratch
//! is all any of them uses: the entry array is written, and its CRC-32
//! computed, one sector at a time. The format wants GUIDs, and a random
//! source is the one thing a driver cannot assume, so they are the caller's
//! — [`Guid::random_v4`] turns sixteen random bytes into a well-formed one.
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

    /// A version-4 (random) GUID made from `bytes`, which should come from
    /// whatever random source the platform has: the version and variant
    /// bits are set, everything else is taken as given.
    pub const fn random_v4(mut bytes: [u8; 16]) -> Guid {
        // Byte 7 holds the version nibble (the third group is stored
        // little-endian), byte 8 the variant bits.
        bytes[7] = (bytes[7] & 0x0F) | 0x40;
        bytes[8] = (bytes[8] & 0x3F) | 0x80;
        Guid(bytes)
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

/// Entries [`write`](fn@write) puts in the array: the specification's minimum
/// reservation, and what every partitioning tool uses.
pub const ENTRY_COUNT: u32 = 128;

/// Size of each entry [`write`](fn@write) lays down.
pub const ENTRY_SIZE: u32 = 128;

/// Longest partition name, in UTF-16 code units.
pub const MAX_NAME_UNITS: usize = 36;

/// A partition to write into a table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NewPartition<'a> {
    /// What it holds — [`BASIC_DATA`] for FAT and exFAT, [`LINUX_FS`], ….
    pub type_guid: Guid,
    /// The partition's own GUID. Must not be nil.
    pub guid: Guid,
    /// First sector.
    pub start_lba: u64,
    /// Last sector, inclusive.
    pub end_lba: u64,
    /// Attribute flags — bit 0 "required", bit 60 read-only, ….
    pub attributes: u64,
    /// Name, up to [`MAX_NAME_UNITS`] UTF-16 code units.
    pub name: &'a str,
}

impl<'a> NewPartition<'a> {
    /// A partition of `type_guid` covering `sectors` sectors from
    /// `start_lba`, unnamed and with no attributes.
    pub fn new(type_guid: Guid, guid: Guid, start_lba: u64, sectors: u64) -> Self {
        Self {
            type_guid,
            guid,
            start_lba,
            end_lba: start_lba.saturating_add(sectors).saturating_sub(1),
            attributes: 0,
            name: "",
        }
    }

    /// The 128-byte entry for this partition, validated.
    fn encode(&self, out: &mut [u8]) -> Result<(), Invalid> {
        if self.type_guid.is_nil() || self.guid.is_nil() || self.end_lba < self.start_lba {
            return Err(Invalid::Entry);
        }
        out[..ENTRY_SIZE as usize].fill(0);
        out[0..16].copy_from_slice(&self.type_guid.0);
        out[16..32].copy_from_slice(&self.guid.0);
        out[32..40].copy_from_slice(&self.start_lba.to_le_bytes());
        out[40..48].copy_from_slice(&self.end_lba.to_le_bytes());
        out[48..56].copy_from_slice(&self.attributes.to_le_bytes());
        for (n, unit) in self.name.encode_utf16().enumerate() {
            if n == MAX_NAME_UNITS {
                return Err(Invalid::Name);
            }
            out[56 + n * 2..58 + n * 2].copy_from_slice(&unit.to_le_bytes());
        }
        Ok(())
    }
}

/// Where a table on a medium of a given size puts things.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    /// Sectors each copy of the entry array takes.
    pub array_sectors: u64,
    /// First sector a partition may use: after the protective MBR, the
    /// primary header and its array.
    pub first_usable_lba: u64,
    /// Last sector a partition may use: before the backup array and header.
    pub last_usable_lba: u64,
    /// First sector of the backup array.
    pub backup_array_lba: u64,
    /// The backup header: the medium's last sector.
    pub backup_lba: u64,
}

impl Layout {
    /// The layout of a [`ENTRY_COUNT`]-entry table on `sector_count` sectors
    /// of `sector_size` bytes, or `None` when that leaves no room for a
    /// partition.
    pub fn new(sector_count: u64, sector_size: u32) -> Option<Layout> {
        if sector_size < 512 {
            return None;
        }
        let array_sectors = ((ENTRY_COUNT * ENTRY_SIZE) as u64).div_ceil(sector_size as u64);
        let first_usable_lba = 2 + array_sectors;
        let backup_lba = sector_count.checked_sub(1)?;
        let backup_array_lba = backup_lba.checked_sub(array_sectors)?;
        let last_usable_lba = backup_array_lba.checked_sub(1)?;
        (last_usable_lba >= first_usable_lba).then_some(Layout {
            array_sectors,
            first_usable_lba,
            last_usable_lba,
            backup_array_lba,
            backup_lba,
        })
    }

    /// The first usable sector on a 1 MiB boundary — where partitioning
    /// tools start the first partition, aligned with flash erase blocks and
    /// Advanced Format sectors alike.
    pub fn first_aligned_lba(&self, sector_size: u32) -> u64 {
        let align = ((1u64 << 20) / sector_size.max(1) as u64).max(1);
        self.first_usable_lba.div_ceil(align) * align
    }
}

/// Why a table could not be written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteError<E> {
    /// The device failed.
    Io(E),
    /// The scratch buffer is shorter than a sector, or sectors are smaller
    /// than 512 bytes.
    ScratchTooSmall,
    /// The medium is too small for a table and a partition.
    MediumTooSmall,
    /// More partitions than the array holds, or an index past it.
    NoSuchSlot,
    /// The entry at this index has a nil type or partition GUID, or ends
    /// before it starts.
    InvalidEntry(u32),
    /// The entry at this index has a name longer than [`MAX_NAME_UNITS`].
    NameTooLong(u32),
    /// The entry at this index lies outside the usable sectors.
    OutsideUsable(u32),
    /// The entries at these indices share sectors.
    Overlap(u32, u32),
    /// [`set_entry`] found no valid table to change.
    NoTable,
    /// [`set_entry`] found a table laid out in a way it does not rewrite:
    /// more than [`MAX_ENTRIES`] entries, entries that are not a whole
    /// fraction of a sector, or an array overlapping the usable sectors.
    UnsupportedLayout,
}

impl<E: core::fmt::Display> core::fmt::Display for WriteError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WriteError::Io(e) => write!(f, "device error: {e}"),
            WriteError::ScratchTooSmall => f.write_str("scratch buffer smaller than a sector"),
            WriteError::MediumTooSmall => f.write_str("medium too small for a GPT"),
            WriteError::NoSuchSlot => f.write_str("no such GPT entry"),
            WriteError::InvalidEntry(i) => write!(f, "GPT entry {i} is invalid"),
            WriteError::NameTooLong(i) => write!(f, "GPT entry {i} has a name over 36 units"),
            WriteError::OutsideUsable(i) => {
                write!(f, "GPT entry {i} lies outside the usable sectors")
            }
            WriteError::Overlap(a, b) => write!(f, "GPT entries {a} and {b} overlap"),
            WriteError::NoTable => f.write_str("no GPT to change"),
            WriteError::UnsupportedLayout => f.write_str("GPT layout not supported for rewriting"),
        }
    }
}

#[cfg(feature = "std")]
impl<E: core::fmt::Debug + core::fmt::Display> std::error::Error for WriteError<E> {}

/// What was wrong with a [`NewPartition`], before its index is known.
enum Invalid {
    Entry,
    Name,
}

impl Invalid {
    fn at<E>(self, index: u32) -> WriteError<E> {
        match self {
            Invalid::Entry => WriteError::InvalidEntry(index),
            Invalid::Name => WriteError::NameTooLong(index),
        }
    }
}

/// Everything a header records that is not derived from the layout.
struct Shape {
    disk_guid: Guid,
    first_usable_lba: u64,
    last_usable_lba: u64,
    primary_array_lba: u64,
    backup_array_lba: u64,
    backup_lba: u64,
    entry_count: u32,
    entry_size: u32,
}

/// Write a GPT holding `parts` — entry `i` of the array is `parts[i]` —
/// over whatever the medium had: a protective MBR, both headers and both
/// arrays.
///
/// The partitions are checked first (inside the usable sectors, no overlaps,
/// GUIDs set, names short enough) and nothing is written unless all of them
/// pass. The backup copy is written before the primary, so a write torn
/// part-way leaves one complete table or the old one.
pub fn write<D: SectorDriver>(
    dev: &mut D,
    scratch: &mut [u8],
    disk_guid: Guid,
    parts: &[NewPartition<'_>],
) -> Result<(), WriteError<D::Error>> {
    let ss = check_scratch(dev, scratch)?;
    let layout = Layout::new(dev.sector_count(), ss).ok_or(WriteError::MediumTooSmall)?;
    if parts.len() > ENTRY_COUNT as usize {
        return Err(WriteError::NoSuchSlot);
    }
    let mut entry = [0u8; ENTRY_SIZE as usize];
    for (i, p) in parts.iter().enumerate() {
        let i = i as u32;
        p.encode(&mut entry).map_err(|e| e.at(i))?;
        if p.start_lba < layout.first_usable_lba || p.end_lba > layout.last_usable_lba {
            return Err(WriteError::OutsideUsable(i));
        }
        for (j, q) in parts.iter().enumerate().skip(i as usize + 1) {
            if p.start_lba <= q.end_lba && q.start_lba <= p.end_lba {
                return Err(WriteError::Overlap(i, j as u32));
            }
        }
    }
    let shape = Shape {
        disk_guid,
        first_usable_lba: layout.first_usable_lba,
        last_usable_lba: layout.last_usable_lba,
        primary_array_lba: 2,
        backup_array_lba: layout.backup_array_lba,
        backup_lba: layout.backup_lba,
        entry_count: ENTRY_COUNT,
        entry_size: ENTRY_SIZE,
    };
    commit(dev, scratch, &shape, |_, first, sector| {
        for (k, out) in sector
            .as_chunks_mut::<{ ENTRY_SIZE as usize }>()
            .0
            .iter_mut()
            .enumerate()
        {
            match parts.get(first as usize + k) {
                // Already validated above.
                Some(p) => {
                    let _ = p.encode(out);
                }
                None => out.fill(0),
            }
        }
        Ok(())
    })?;
    protective_mbr(dev, scratch, ss)
}

/// Add, change or remove (with `None`) entry `index` of the GPT already on
/// `dev`, and rewrite both copies of the table.
///
/// The table is read from the primary header, or the backup when the
/// primary is damaged; either way both are written back whole, so this also
/// repairs a table with one bad copy. The new entry is checked against the
/// usable sectors and against every other entry before anything is written.
pub fn set_entry<D: SectorDriver>(
    dev: &mut D,
    scratch: &mut [u8],
    index: u32,
    part: Option<NewPartition<'_>>,
) -> Result<(), WriteError<D::Error>> {
    let ss = check_scratch(dev, scratch)?;
    let table = Table::read(dev, scratch)
        .map_err(WriteError::Io)?
        .ok_or(WriteError::NoTable)?;
    let h = table.header;
    let count = dev.sector_count();
    if h.entry_count > MAX_ENTRIES
        || !h.entry_size.is_power_of_two()
        || h.entry_size > ss
        || count < 2
    {
        return Err(WriteError::UnsupportedLayout);
    }
    if index >= h.entry_count {
        return Err(WriteError::NoSuchSlot);
    }
    let array_sectors = (h.entry_count as u64 * h.entry_size as u64).div_ceil(ss as u64);
    let backup_lba = count - 1;
    let backup_array_lba = backup_lba
        .checked_sub(array_sectors)
        .ok_or(WriteError::UnsupportedLayout)?;
    if h.first_usable_lba < 2 + array_sectors || h.last_usable_lba >= backup_array_lba {
        return Err(WriteError::UnsupportedLayout);
    }

    // Validate against every other live entry before touching the medium.
    let mut entry = [0u8; ENTRY_SIZE as usize];
    if let Some(p) = &part {
        p.encode(&mut entry).map_err(|e| e.at(index))?;
        if p.start_lba < h.first_usable_lba || p.end_lba > h.last_usable_lba {
            return Err(WriteError::OutsideUsable(index));
        }
        for j in 0..h.entry_count {
            if j == index {
                continue;
            }
            if let Some(q) = table.entry(dev, scratch, j).map_err(WriteError::Io)?
                && p.start_lba <= q.end_lba
                && q.start_lba <= p.end_lba
            {
                return Err(WriteError::Overlap(index, j));
            }
        }
    }

    let source = h.entries_lba;
    // The array the header points at has to be on the medium to be read
    // back — a header off untrusted media can point anywhere.
    if source
        .checked_add(array_sectors)
        .is_none_or(|end| end > count)
    {
        return Err(WriteError::UnsupportedLayout);
    }
    // Regenerating a copy over itself is safe sector by sector; over a range
    // that only partly overlaps its source (a backup array on a medium that
    // has since grown by less than the array) it is not.
    let partly_overlaps = |dest: u64| {
        dest != source && dest < source + array_sectors && source < dest + array_sectors
    };
    if partly_overlaps(2) || partly_overlaps(backup_array_lba) {
        return Err(WriteError::UnsupportedLayout);
    }
    let per_sector = ss / h.entry_size;
    let entry_size = h.entry_size as usize;
    let shape = Shape {
        disk_guid: h.disk_guid,
        first_usable_lba: h.first_usable_lba,
        last_usable_lba: h.last_usable_lba,
        primary_array_lba: 2,
        backup_array_lba,
        backup_lba,
        entry_count: h.entry_count,
        entry_size: h.entry_size,
    };
    // The array is regenerated from the copy the header was read from, a
    // sector at a time, with the one entry patched in on the way. Each
    // source sector is read before its destination is written, so
    // rewriting a copy over itself is safe, and patching a sector that
    // already carries the change is harmless.
    commit(dev, scratch, &shape, |dev, first, sector| {
        let lba = source + (first / per_sector) as u64;
        if lba < count {
            dev.read_sectors(lba, sector)?;
        } else {
            sector.fill(0);
        }
        if (first..first + per_sector).contains(&index) {
            let at = (index - first) as usize * entry_size;
            let slot = &mut sector[at..at + entry_size];
            match &part {
                // Already validated above.
                Some(p) => {
                    let _ = p.encode(slot);
                }
                None => slot.fill(0),
            }
        }
        Ok(())
    })?;
    // A table whose protective MBR is already there (or is a hybrid one a
    // tool put there on purpose) keeps it.
    Ok(())
}

/// Remove the GPT from `dev` by zeroing both headers, so the medium can be
/// given an MBR (or nothing) without a GPT reader finding the old table's
/// backup. Partition data is not touched.
pub fn erase<D: SectorDriver>(dev: &mut D, scratch: &mut [u8]) -> Result<(), WriteError<D::Error>> {
    let ss = check_scratch(dev, scratch)? as usize;
    let count = dev.sector_count();
    if count < 2 {
        return Ok(());
    }
    let buf = &mut scratch[..ss];
    buf.fill(0);
    dev.write_sectors(1, buf).map_err(WriteError::Io)?;
    dev.write_sectors(count - 1, buf).map_err(WriteError::Io)?;
    dev.flush().map_err(WriteError::Io)
}

/// The sector size, once the scratch is known to hold a sector.
fn check_scratch<D: SectorDriver>(dev: &D, scratch: &[u8]) -> Result<u32, WriteError<D::Error>> {
    let ss = dev.sector_size();
    if ss < 512 || !ss.is_power_of_two() || scratch.len() < ss as usize {
        return Err(WriteError::ScratchTooSmall);
    }
    Ok(ss)
}

/// Write both copies of the table: the backup array, the backup header, the
/// primary array, the primary header — in that order, so a write torn at
/// any point leaves at least one copy whose header and array agree.
///
/// `fill(dev, first, sector)` produces the array sector whose first entry is
/// index `first`. It is called once per sector per copy, and must produce
/// the same bytes both times.
fn commit<D: SectorDriver>(
    dev: &mut D,
    scratch: &mut [u8],
    shape: &Shape,
    mut fill: impl FnMut(&mut D, u32, &mut [u8]) -> Result<(), D::Error>,
) -> Result<(), WriteError<D::Error>> {
    let ss = dev.sector_size() as usize;
    let buf = &mut scratch[..ss];
    let per_sector = ss as u32 / shape.entry_size;
    let array_bytes = shape.entry_count as u64 * shape.entry_size as u64;
    let sectors = array_bytes.div_ceil(ss as u64);

    let mut crc = 0;
    for (copy, (array_lba, my_lba, alternate_lba)) in [
        (shape.backup_array_lba, shape.backup_lba, 1),
        (shape.primary_array_lba, 1, shape.backup_lba),
    ]
    .into_iter()
    .enumerate()
    {
        let mut running = 0;
        for k in 0..sectors {
            fill(dev, k as u32 * per_sector, buf).map_err(WriteError::Io)?;
            // Past the last entry the sector is padding, and not part of the
            // array the CRC covers.
            let used = (array_bytes - k * ss as u64).min(ss as u64) as usize;
            buf[used..].fill(0);
            running = crate::crc::crc32_small_append(running, &buf[..used]);
            dev.write_sectors(array_lba + k, buf)
                .map_err(WriteError::Io)?;
        }
        if copy == 0 {
            crc = running;
        }
        header(buf, shape, my_lba, alternate_lba, array_lba, crc);
        dev.write_sectors(my_lba, buf).map_err(WriteError::Io)?;
    }
    dev.flush().map_err(WriteError::Io)
}

/// Encode a header into `sector`.
fn header(sector: &mut [u8], shape: &Shape, my: u64, alternate: u64, array: u64, crc: u32) {
    sector.fill(0);
    sector[0..8].copy_from_slice(SIGNATURE);
    sector[8..12].copy_from_slice(&REVISION.to_le_bytes());
    sector[12..16].copy_from_slice(&MIN_HEADER_SIZE.to_le_bytes());
    sector[24..32].copy_from_slice(&my.to_le_bytes());
    sector[32..40].copy_from_slice(&alternate.to_le_bytes());
    sector[40..48].copy_from_slice(&shape.first_usable_lba.to_le_bytes());
    sector[48..56].copy_from_slice(&shape.last_usable_lba.to_le_bytes());
    sector[56..72].copy_from_slice(&shape.disk_guid.0);
    sector[72..80].copy_from_slice(&array.to_le_bytes());
    sector[80..84].copy_from_slice(&shape.entry_count.to_le_bytes());
    sector[84..88].copy_from_slice(&shape.entry_size.to_le_bytes());
    sector[88..92].copy_from_slice(&crc.to_le_bytes());
    let own = crate::crc::crc32_small(&sector[..MIN_HEADER_SIZE as usize]);
    sector[16..20].copy_from_slice(&own.to_le_bytes());
}

/// Write the protective MBR a GPT medium carries in sector 0: one partition
/// of type `0xEE` covering the medium (capped at what 32 bits can say),
/// keeping any boot code already there.
fn protective_mbr<D: SectorDriver>(
    dev: &mut D,
    scratch: &mut [u8],
    ss: u32,
) -> Result<(), WriteError<D::Error>> {
    let buf = &mut scratch[..ss as usize];
    dev.read_sectors(0, buf).map_err(WriteError::Io)?;
    buf[440..].fill(0);
    let sectors = (dev.sector_count() - 1).min(u32::MAX as u64) as u32;
    let slot = &mut buf[446..462];
    slot[1..4].copy_from_slice(&[0x00, 0x02, 0x00]); // CHS of LBA 1
    slot[4] = super::mbr::GPT_PROTECTIVE;
    slot[5..8].copy_from_slice(&[0xFF, 0xFF, 0xFF]);
    slot[8..12].copy_from_slice(&1u32.to_le_bytes());
    slot[12..16].copy_from_slice(&sectors.to_le_bytes());
    buf[510] = 0x55;
    buf[511] = 0xAA;
    dev.write_sectors(0, buf).map_err(WriteError::Io)?;
    dev.flush().map_err(WriteError::Io)
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

    /// A blank medium of `sectors` sectors of `ss` bytes.
    struct Blank {
        data: alloc::vec::Vec<u8>,
        ss: u32,
    }

    impl SectorDriver for Blank {
        type Error = core::convert::Infallible;
        fn sector_size(&self) -> u32 {
            self.ss
        }
        fn sector_count(&self) -> u64 {
            self.data.len() as u64 / self.ss as u64
        }
        fn read_sectors(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), Self::Error> {
            assert_eq!(buf.len() % self.ss as usize, 0);
            let at = lba as usize * self.ss as usize;
            buf.copy_from_slice(&self.data[at..at + buf.len()]);
            Ok(())
        }
        fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> Result<(), Self::Error> {
            assert_eq!(buf.len() % self.ss as usize, 0);
            let at = lba as usize * self.ss as usize;
            self.data[at..at + buf.len()].copy_from_slice(buf);
            Ok(())
        }
    }

    fn blank(sectors: usize, ss: u32) -> Blank {
        Blank {
            data: alloc::vec![0u8; sectors * ss as usize],
            ss,
        }
    }

    fn guid(n: u8) -> Guid {
        Guid::random_v4([n; 16])
    }

    /// Verify the array CRC a header records against the array itself.
    fn array_crc_matches(dev: &mut Blank, h: &Header) -> bool {
        let ss = dev.ss as usize;
        let bytes = (h.entry_count * h.entry_size) as usize;
        let at = h.entries_lba as usize * ss;
        crate::crc::crc32(&dev.data[at..at + bytes]) == h.entries_crc32
    }

    #[test]
    fn a_written_table_reads_back_from_either_copy() {
        for ss in [512u32, 4096] {
            let sectors = (64 * 1024 * 1024 / ss) as usize;
            let mut dev = blank(sectors, ss);
            let layout = Layout::new(sectors as u64, ss).unwrap();
            let start = layout.first_aligned_lba(ss);
            assert_eq!(start * ss as u64, 1 << 20);
            let parts = [
                NewPartition {
                    name: "EFI system",
                    ..NewPartition::new(EFI_SYSTEM, guid(1), start, 8192 * 512 / ss as u64)
                },
                NewPartition {
                    attributes: 1 << 60,
                    ..NewPartition::new(BASIC_DATA, guid(2), start + 8192 * 512 / ss as u64, 1000)
                },
            ];
            let mut scratch = [0u8; 4096];
            write(&mut dev, &mut scratch, guid(9), &parts).unwrap();

            // Protective MBR.
            let mbr = super::super::mbr::parse(&dev.data[..512]);
            assert!(
                mbr.is_none(),
                "the protective entry is not offered as a partition"
            );
            assert_eq!(dev.data[446 + 4], 0xEE);

            for damage_primary in [false, true] {
                if damage_primary {
                    let at = ss as usize;
                    dev.data[at..at + 92].fill(0x5A);
                }
                let table = Table::read(&mut dev, &mut scratch).unwrap().expect("table");
                assert_eq!(table.from_backup, damage_primary);
                assert_eq!(table.header.disk_guid, guid(9));
                assert_eq!(table.header.first_usable_lba, layout.first_usable_lba);
                assert_eq!(table.header.last_usable_lba, layout.last_usable_lba);
                assert!(
                    array_crc_matches(&mut dev, &table.header),
                    "array CRC at {ss}"
                );
                let a = table.entry(&mut dev, &mut scratch, 0).unwrap().unwrap();
                assert!(a.is_efi_system());
                assert_eq!((a.start_lba, a.guid), (start, guid(1)));
                let (lba, at) = table.header.entry_position(0, ss).unwrap();
                let sector = &dev.data[lba as usize * ss as usize..][..ss as usize];
                let mut name = [0u16; MAX_NAME_UNITS];
                let n = Partition::name_from(&sector[at..], &mut name);
                assert!(name[..n].iter().copied().eq("EFI system".encode_utf16()));
                let b = table.entry(&mut dev, &mut scratch, 1).unwrap().unwrap();
                assert!(b.is_read_only() && b.is_basic_data());
                assert!(table.entry(&mut dev, &mut scratch, 2).unwrap().is_none());
            }
        }
    }

    #[test]
    fn an_invalid_table_writes_nothing() {
        let mut dev = blank(100_000, 512);
        let mut scratch = [0u8; 512];
        let l = Layout::new(100_000, 512).unwrap();
        let p = |start, n| NewPartition::new(BASIC_DATA, guid(1), start, n);
        let cases: [(&[NewPartition<'_>], WriteError<core::convert::Infallible>); 5] = [
            (&[p(2048, 100), p(2100, 10)], WriteError::Overlap(0, 1)),
            (&[p(10, 100)], WriteError::OutsideUsable(0)),
            (&[p(2048, l.last_usable_lba)], WriteError::OutsideUsable(0)),
            (
                &[NewPartition {
                    guid: Guid::NIL,
                    ..p(2048, 10)
                }],
                WriteError::InvalidEntry(0),
            ),
            (
                &[
                    p(2048, 10),
                    NewPartition {
                        name: "a name that is far too long to fit in GPT",
                        ..p(4096, 10)
                    },
                ],
                WriteError::NameTooLong(1),
            ),
        ];
        for (parts, want) in cases {
            assert_eq!(write(&mut dev, &mut scratch, guid(9), parts), Err(want));
        }
        assert!(dev.data.iter().all(|&b| b == 0), "nothing was written");
        assert_eq!(
            write(&mut blank(60, 512), &mut scratch, guid(9), &[]),
            Err(WriteError::MediumTooSmall)
        );
    }

    #[test]
    fn entries_change_one_at_a_time_and_a_damaged_copy_is_repaired() {
        let mut dev = blank(200_000, 512);
        let mut scratch = [0u8; 512];
        write(
            &mut dev,
            &mut scratch,
            guid(9),
            &[NewPartition::new(BASIC_DATA, guid(1), 2048, 4096)],
        )
        .unwrap();

        // Add a second partition in slot 5, leaving a gap.
        set_entry(
            &mut dev,
            &mut scratch,
            5,
            Some(NewPartition::new(LINUX_FS, guid(2), 8192, 4096)),
        )
        .unwrap();
        // One that overlaps the first is refused.
        assert_eq!(
            set_entry(
                &mut dev,
                &mut scratch,
                6,
                Some(NewPartition::new(LINUX_FS, guid(3), 3000, 10))
            ),
            Err(WriteError::Overlap(6, 0))
        );
        assert_eq!(
            set_entry(&mut dev, &mut scratch, 128, None),
            Err(WriteError::NoSuchSlot)
        );
        // Resizing an entry in place is not an overlap with itself.
        set_entry(
            &mut dev,
            &mut scratch,
            0,
            Some(NewPartition::new(BASIC_DATA, guid(1), 2048, 6000)),
        )
        .unwrap();

        // Damage the primary; the next change reads the backup and rewrites
        // both.
        dev.data[512..604].fill(0x5A);
        set_entry(&mut dev, &mut scratch, 0, None).unwrap();
        let table = Table::read(&mut dev, &mut scratch).unwrap().unwrap();
        assert!(!table.from_backup, "the primary was repaired");
        assert!(array_crc_matches(&mut dev, &table.header));
        assert!(table.entry(&mut dev, &mut scratch, 0).unwrap().is_none());
        let p = table.entry(&mut dev, &mut scratch, 5).unwrap().unwrap();
        assert_eq!((p.start_lba, p.guid), (8192, guid(2)));
        // And the backup agrees.
        let last = dev.data.len() - 512;
        let backup = Header::decode(&dev.data[last..]).unwrap();
        assert_eq!(backup.entries_crc32, table.header.entries_crc32);
        assert!(array_crc_matches(&mut dev, &backup));

        // A medium with no GPT has nothing to change.
        assert_eq!(
            set_entry(&mut blank(200_000, 512), &mut scratch, 0, None),
            Err(WriteError::NoTable)
        );
    }

    #[test]
    fn an_erased_table_is_gone_from_both_ends() {
        let mut dev = blank(100_000, 512);
        let mut scratch = [0u8; 512];
        write(
            &mut dev,
            &mut scratch,
            guid(9),
            &[NewPartition::new(BASIC_DATA, guid(1), 2048, 4096)],
        )
        .unwrap();
        erase(&mut dev, &mut scratch).unwrap();
        assert!(Table::read(&mut dev, &mut scratch).unwrap().is_none());
    }

    #[test]
    fn a_random_guid_carries_version_4_and_the_rfc_variant() {
        let g = Guid::random_v4([0xFF; 16]);
        assert_eq!(g.0[7] >> 4, 4);
        assert_eq!(g.0[8] >> 6, 0b10);
        assert_eq!(Guid::random_v4([0; 16]).0[7], 0x40);
    }

    #[test]
    fn a_header_pointing_its_array_off_the_medium_is_not_rewritten() {
        let mut dev = blank(100_000, 512);
        let mut scratch = [0u8; 512];
        write(
            &mut dev,
            &mut scratch,
            guid(9),
            &[NewPartition::new(BASIC_DATA, guid(1), 2048, 4096)],
        )
        .unwrap();
        // Re-sign the primary header with its array at the top of the
        // address space.
        let h = &mut dev.data[512..1024];
        h[72..80].copy_from_slice(&u64::MAX.to_le_bytes());
        h[16..20].fill(0);
        let crc = crate::crc::crc32(&h[..92]);
        h[16..20].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(
            set_entry(&mut dev, &mut scratch, 1, None),
            Err(WriteError::UnsupportedLayout)
        );
    }
}
