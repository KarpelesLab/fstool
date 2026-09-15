//! The master boot record's primary partition table, decoded.
//!
//! A card is usually partitioned — SDXC cards from the SD Association's own
//! formatter are, and so are most cameras' — so a driver that mounts "the
//! volume on this card" has to read the table first. This is the smallest
//! thing that answers where a volume starts: four numbers per slot, no
//! allocator, no device trait of its own (the caller reads sector 0 and
//! passes the bytes in).
//!
//! It writes one too: [`write`](fn@write) lays a fresh table down over up to four
//! [`Entry`]s, and [`set_entry`] changes one slot of an existing table — both
//! through the caller's [`SectorDriver`] and one sector of scratch, both
//! checking the layout (inside the medium, no overlaps, within MBR's 32-bit
//! reach) before a byte is written. The boot code in the first 440 bytes is
//! kept, so a bootloader survives a repartition.
//!
//! [`part::Mbr`](crate::part::Mbr) is the hosted counterpart: it owns a
//! table and speaks [`BlockDevice`](crate::block::BlockDevice).
//!
//! ```text
//!   off  size  field                       (per slot, four slots)
//!   446    16  slot 0
//!     +0   1   boot flag
//!     +4   1   partition type
//!     +8   4   first sector (LBA)
//!    +12   4   sectors
//!   510     2  0x55 0xAA signature
//! ```

use super::SectorDriver;

/// Type byte for FAT12.
pub const FAT12: u8 = 0x01;
/// Type byte for FAT16 addressed by LBA — what a FAT16 volume should carry.
pub const FAT16_LBA: u8 = 0x0E;
/// Type byte for FAT32 addressed by LBA — what a FAT32 volume should carry.
pub const FAT32_LBA: u8 = 0x0C;
/// Type byte exFAT and NTFS share.
pub const EXFAT: u8 = 0x07;
/// Type byte for a Linux filesystem — the usual label for littlefs on a card.
pub const LINUX: u8 = 0x83;
/// Type byte for an EFI system partition.
pub const EFI_SYSTEM: u8 = 0xEF;
/// Type byte of the one entry a GPT's protective MBR carries.
pub const GPT_PROTECTIVE: u8 = 0xEE;

/// Where partitions conventionally start: 1 MiB into a 512-byte-sector
/// medium, which aligns them with the erase blocks of every SD card and the
/// physical sectors of every Advanced Format disk.
pub const FIRST_LBA: u32 = 2048;

/// One entry of the table: where a partition starts, how long it is, and
/// what its type byte claims it holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Partition {
    /// 1-based slot in the table.
    pub index: u8,
    /// Partition type byte.
    pub kind: u8,
    /// First sector of the partition.
    pub start_lba: u64,
    /// Sectors it spans.
    pub sectors: u64,
}

impl Partition {
    /// Whether the type byte is one of the FAT ones. A volume is still
    /// mounted by reading its boot sector, not by trusting this.
    pub fn looks_like_fat(&self) -> bool {
        matches!(
            self.kind,
            0x01 | 0x04 | 0x06 | 0x0B | 0x0C | 0x0E | 0x11 | 0x14 | 0x16 | 0x1B | 0x1C | 0x1E
        )
    }

    /// Whether the type byte is the one exFAT and NTFS share (`0x07`).
    pub fn looks_like_exfat(&self) -> bool {
        self.kind == 0x07
    }

    /// Whether the type byte marks a GPT protective partition — a table
    /// [`parse`] skips, because the real one is [`super::gpt`]'s.
    pub fn is_protective(&self) -> bool {
        self.kind == 0xEE
    }
}

/// Read the four primary partition entries out of `sector` — the medium's
/// first sector — skipping empty and extended-container slots. Returns
/// `None` when the sector carries no usable table.
pub fn parse(sector: &[u8]) -> Option<[Option<Partition>; 4]> {
    if sector.len() < 512 || sector[510] != 0x55 || sector[511] != 0xAA {
        return None;
    }
    let mut out = [None; 4];
    let mut any = false;
    for (i, slot) in out.iter_mut().enumerate() {
        let at = 446 + i * 16;
        let kind = sector[at + 4];
        let start_lba = u32::from_le_bytes([
            sector[at + 8],
            sector[at + 9],
            sector[at + 10],
            sector[at + 11],
        ]) as u64;
        let sectors = u32::from_le_bytes([
            sector[at + 12],
            sector[at + 13],
            sector[at + 14],
            sector[at + 15],
        ]) as u64;
        // Type 0 is an unused slot; 0x05/0x0F/0x85 are extended containers,
        // whose logical partitions these drivers do not walk; 0xEE is the
        // protective entry a GPT disk puts here, and the real table is
        // [`super::gpt`]'s.
        if kind == 0 || sectors == 0 || start_lba == 0 || matches!(kind, 0x05 | 0x0F | 0x85 | 0xEE)
        {
            continue;
        }
        any = true;
        *slot = Some(Partition {
            index: i as u8 + 1,
            kind,
            start_lba,
            sectors,
        });
    }
    if any { Some(out) } else { None }
}

/// A partition to write into a table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    /// Partition type byte — [`FAT32_LBA`], [`EXFAT`], [`LINUX`], ….
    pub kind: u8,
    /// Whether the active (boot) flag is set.
    pub bootable: bool,
    /// First sector.
    pub start_lba: u32,
    /// Sectors it spans.
    pub sectors: u32,
}

impl Entry {
    /// A partition of `kind` covering `sectors` sectors from `start_lba`.
    pub fn new(kind: u8, start_lba: u32, sectors: u32) -> Self {
        Self {
            kind,
            bootable: false,
            start_lba,
            sectors,
        }
    }

    /// The sector after the partition's last.
    fn end(&self) -> u64 {
        self.start_lba as u64 + self.sectors as u64
    }
}

/// Why a table could not be written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteError<E> {
    /// The device failed.
    Io(E),
    /// The scratch buffer is shorter than a sector, or the medium's sectors
    /// are smaller than 512 bytes.
    ScratchTooSmall,
    /// Slot numbers are 1 to 4.
    NoSuchSlot,
    /// An entry has type 0 (which marks an unused slot), no sectors, or
    /// starts at sector 0, where the table itself lives.
    InvalidEntry,
    /// An entry runs past the end of the medium.
    PastEnd,
    /// Two entries share sectors: the 1-based slots named.
    Overlap(u8, u8),
}

impl<E: core::fmt::Display> core::fmt::Display for WriteError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WriteError::Io(e) => write!(f, "device error: {e}"),
            WriteError::ScratchTooSmall => f.write_str("scratch buffer smaller than a sector"),
            WriteError::NoSuchSlot => f.write_str("MBR slots are numbered 1 to 4"),
            WriteError::InvalidEntry => {
                f.write_str("entry has type 0, no sectors, or starts at sector 0")
            }
            WriteError::PastEnd => f.write_str("entry runs past the end of the medium"),
            WriteError::Overlap(a, b) => write!(f, "slots {a} and {b} overlap"),
        }
    }
}

#[cfg(feature = "std")]
impl<E: core::fmt::Debug + core::fmt::Display> std::error::Error for WriteError<E> {}

/// Write a partition table holding `entries` — slot 1 first, `None` for an
/// unused slot — over whatever table the medium had.
///
/// The first 440 bytes of sector 0 (boot code) are kept; the disk signature
/// is set to `disk_id` unless it is 0, in which case the existing one is
/// kept. Nothing is written unless every entry is valid.
///
/// A medium that carried a GPT still has its headers afterwards, and a GPT
/// reader that finds the backup at the end will prefer it; call
/// [`gpt::erase`](super::gpt::erase) first when replacing one.
pub fn write<D: SectorDriver>(
    dev: &mut D,
    scratch: &mut [u8],
    entries: &[Option<Entry>; 4],
    disk_id: u32,
) -> Result<(), WriteError<D::Error>> {
    validate(dev.sector_count(), entries)?;
    let sector = sector_zero(dev, scratch)?;
    for (i, e) in entries.iter().enumerate() {
        encode(&mut sector[446 + i * 16..462 + i * 16], e.as_ref());
    }
    if disk_id != 0 {
        sector[440..444].copy_from_slice(&disk_id.to_le_bytes());
        sector[444..446].fill(0);
    }
    sector[510] = 0x55;
    sector[511] = 0xAA;
    dev.write_sectors(0, sector).map_err(WriteError::Io)?;
    dev.flush().map_err(WriteError::Io)
}

/// Change one slot (1 to 4) of the table on `dev` — add a partition, resize
/// one, or remove it with `None` — leaving the other three as they are.
///
/// A medium with no table gets one. The result is checked as a whole, so a
/// change that would overlap a partition already there is refused.
pub fn set_entry<D: SectorDriver>(
    dev: &mut D,
    scratch: &mut [u8],
    slot: u8,
    entry: Option<Entry>,
) -> Result<(), WriteError<D::Error>> {
    if !(1..=4).contains(&slot) {
        return Err(WriteError::NoSuchSlot);
    }
    let count = dev.sector_count();
    let sector = sector_zero(dev, scratch)?;
    let mut entries = [None; 4];
    if sector[510] == 0x55 && sector[511] == 0xAA {
        for (i, e) in entries.iter_mut().enumerate() {
            *e = decode(&sector[446 + i * 16..462 + i * 16]);
        }
    } else {
        // No table: whatever is in sector 0 is not a partition list, so do
        // not read one out of it.
        sector[446..].fill(0);
    }
    entries[slot as usize - 1] = entry;
    validate(count, &entries)?;
    let at = 446 + (slot as usize - 1) * 16;
    encode(&mut sector[at..at + 16], entry.as_ref());
    sector[510] = 0x55;
    sector[511] = 0xAA;
    dev.write_sectors(0, sector).map_err(WriteError::Io)?;
    dev.flush().map_err(WriteError::Io)
}

/// Read sector 0 into the scratch, checking the scratch can hold it.
fn sector_zero<'a, D: SectorDriver>(
    dev: &mut D,
    scratch: &'a mut [u8],
) -> Result<&'a mut [u8], WriteError<D::Error>> {
    let ss = dev.sector_size() as usize;
    if ss < 512 || scratch.len() < ss || dev.sector_count() == 0 {
        return Err(WriteError::ScratchTooSmall);
    }
    let sector = &mut scratch[..ss];
    dev.read_sectors(0, sector).map_err(WriteError::Io)?;
    Ok(sector)
}

/// Check a whole table against a medium of `sectors` sectors.
fn validate<E>(sectors: u64, entries: &[Option<Entry>; 4]) -> Result<(), WriteError<E>> {
    for (i, e) in entries.iter().enumerate() {
        let Some(e) = e else { continue };
        if e.kind == 0 || e.sectors == 0 || e.start_lba == 0 {
            return Err(WriteError::InvalidEntry);
        }
        if e.end() > sectors {
            return Err(WriteError::PastEnd);
        }
        for (j, other) in entries.iter().enumerate().skip(i + 1) {
            if let Some(o) = other
                && (e.start_lba as u64) < o.end()
                && (o.start_lba as u64) < e.end()
            {
                return Err(WriteError::Overlap(i as u8 + 1, j as u8 + 1));
            }
        }
    }
    Ok(())
}

/// A slot's 16 bytes.
fn encode(slot: &mut [u8], entry: Option<&Entry>) {
    slot.fill(0);
    let Some(e) = entry else { return };
    slot[0] = if e.bootable { 0x80 } else { 0 };
    slot[1..4].copy_from_slice(&chs(e.start_lba as u64));
    slot[4] = e.kind;
    slot[5..8].copy_from_slice(&chs(e.end() - 1));
    slot[8..12].copy_from_slice(&e.start_lba.to_le_bytes());
    slot[12..16].copy_from_slice(&e.sectors.to_le_bytes());
}

/// A slot's entry, or `None` for an unused one.
fn decode(slot: &[u8]) -> Option<Entry> {
    let kind = slot[4];
    let start_lba = u32::from_le_bytes([slot[8], slot[9], slot[10], slot[11]]);
    let sectors = u32::from_le_bytes([slot[12], slot[13], slot[14], slot[15]]);
    (kind != 0 && sectors != 0).then_some(Entry {
        kind,
        bootable: slot[0] & 0x80 != 0,
        start_lba,
        sectors,
    })
}

/// The cylinder/head/sector address of `lba` in the 255-head, 63-sector
/// geometry every partitioning tool assumes, or the "use the LBA" marker
/// past what CHS can express. Nothing modern reads these; old BIOSes and
/// some tools still compare them.
fn chs(lba: u64) -> [u8; 3] {
    const HEADS: u64 = 255;
    const SECTORS: u64 = 63;
    let cylinder = lba / (HEADS * SECTORS);
    if cylinder > 1023 {
        return [0xFE, 0xFF, 0xFF];
    }
    let head = (lba / SECTORS) % HEADS;
    let sector = lba % SECTORS + 1;
    [
        head as u8,
        (sector as u8) | ((cylinder >> 2) as u8 & 0xC0),
        cylinder as u8,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A table with one FAT32 partition, one exFAT/NTFS one, an extended
    /// container and an empty slot.
    fn mbr() -> [u8; 512] {
        let mut s = [0u8; 512];
        let mut put = |slot: usize, kind: u8, start: u32, sectors: u32| {
            let at = 446 + slot * 16;
            s[at + 4] = kind;
            s[at + 8..at + 12].copy_from_slice(&start.to_le_bytes());
            s[at + 12..at + 16].copy_from_slice(&sectors.to_le_bytes());
        };
        put(0, 0x0C, 2048, 100_000);
        put(1, 0x07, 200_000, 300_000);
        put(2, 0x05, 600_000, 100_000);
        s[510] = 0x55;
        s[511] = 0xAA;
        s
    }

    #[test]
    fn reads_the_primary_slots_and_skips_the_rest() {
        let table = parse(&mbr()).expect("a usable table");
        let first = table[0].expect("slot 1");
        assert_eq!((first.index, first.kind, first.start_lba), (1, 0x0C, 2048));
        assert!(first.looks_like_fat() && !first.looks_like_exfat());
        let second = table[1].expect("slot 2");
        assert_eq!(second.start_lba, 200_000);
        assert!(second.looks_like_exfat() && !second.looks_like_fat());
        // The extended container and the unused slot are not offered.
        assert!(table[2].is_none() && table[3].is_none());
    }

    #[test]
    fn refuses_a_sector_that_is_not_a_table() {
        let mut s = mbr();
        s[510] = 0;
        assert!(parse(&s).is_none());
        // A signature with no usable slot is not a table either.
        let mut empty = [0u8; 512];
        empty[510] = 0x55;
        empty[511] = 0xAA;
        assert!(parse(&empty).is_none());
        // Too short to hold one.
        assert!(parse(&[0u8; 64]).is_none());
    }

    /// A 64 MiB medium of 512-byte sectors.
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

    fn disk() -> Disk {
        Disk(alloc::vec![0u8; 64 * 1024 * 1024])
    }

    #[test]
    fn a_written_table_reads_back_and_keeps_the_boot_code() {
        let mut d = disk();
        d.0[..440].fill(0x90);
        let mut scratch = [0u8; 512];
        let entries = [
            Some(Entry {
                bootable: true,
                ..Entry::new(FAT32_LBA, FIRST_LBA, 65_536)
            }),
            None,
            Some(Entry::new(LINUX, 100_000, 20_000)),
            None,
        ];
        write(&mut d, &mut scratch, &entries, 0x1234_5678).unwrap();
        assert!(d.0[..440].iter().all(|&b| b == 0x90), "boot code kept");
        assert_eq!(&d.0[440..444], &0x1234_5678u32.to_le_bytes());

        let table = parse(&d.0[..512]).unwrap();
        let p = table[0].unwrap();
        assert_eq!(
            (p.index, p.kind, p.start_lba, p.sectors),
            (1, FAT32_LBA, 2048, 65_536)
        );
        assert!(table[1].is_none());
        assert_eq!(table[2].unwrap().start_lba, 100_000);
        assert_eq!(d.0[446], 0x80, "active flag");
        // CHS of LBA 2048 in 255/63 geometry is cylinder 0, head 32, sector 33.
        assert_eq!(&d.0[447..450], &[32, 33, 0]);
    }

    #[test]
    fn a_bad_layout_writes_nothing() {
        let mut d = disk();
        let mut scratch = [0u8; 512];
        let total = d.sector_count() as u32;
        let e = |start, n| Some(Entry::new(FAT32_LBA, start, n));
        assert_eq!(
            write(
                &mut d,
                &mut scratch,
                &[e(2048, 1000), e(2500, 10), None, None],
                0
            ),
            Err(WriteError::Overlap(1, 2))
        );
        assert_eq!(
            write(&mut d, &mut scratch, &[e(2048, total), None, None, None], 0),
            Err(WriteError::PastEnd)
        );
        assert_eq!(
            write(&mut d, &mut scratch, &[e(0, 10), None, None, None], 0),
            Err(WriteError::InvalidEntry)
        );
        assert!(d.0[..512].iter().all(|&b| b == 0), "nothing was written");
        assert_eq!(
            write(&mut d, &mut [0u8; 100], &[None; 4], 0),
            Err(WriteError::ScratchTooSmall)
        );
    }

    #[test]
    fn one_slot_changes_and_the_others_stay() {
        let mut d = disk();
        let mut scratch = [0u8; 512];
        // No table yet: setting a slot creates one.
        set_entry(&mut d, &mut scratch, 2, Some(Entry::new(EXFAT, 2048, 4096))).unwrap();
        set_entry(&mut d, &mut scratch, 1, Some(Entry::new(LINUX, 8192, 4096))).unwrap();
        // Overlapping what slot 2 holds is refused.
        assert_eq!(
            set_entry(&mut d, &mut scratch, 3, Some(Entry::new(LINUX, 6000, 10))),
            Err(WriteError::Overlap(2, 3))
        );
        assert_eq!(
            set_entry(&mut d, &mut scratch, 5, None),
            Err(WriteError::NoSuchSlot)
        );
        let table = parse(&d.0[..512]).unwrap();
        assert_eq!(table[0].unwrap().kind, LINUX);
        assert_eq!(table[1].unwrap().kind, EXFAT);
        // Removing one leaves the other.
        set_entry(&mut d, &mut scratch, 1, None).unwrap();
        let table = parse(&d.0[..512]).unwrap();
        assert!(table[0].is_none() && table[1].is_some());
    }
}
