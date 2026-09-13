//! The master boot record's primary partition table, decoded.
//!
//! A card is usually partitioned — SDXC cards from the SD Association's own
//! formatter are, and so are most cameras' — so a driver that mounts "the
//! volume on this card" has to read the table first. This is the smallest
//! thing that answers where a volume starts: four numbers per slot, no
//! allocator, no device trait of its own (the caller reads sector 0 and
//! passes the bytes in).
//!
//! [`part::Mbr`](crate::part::Mbr) is the hosted counterpart: it owns a
//! table, writes one, and speaks [`BlockDevice`](crate::block::BlockDevice).
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
}
