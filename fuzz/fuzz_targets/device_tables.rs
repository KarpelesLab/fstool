//! Feed arbitrary bytes into the allocator-free partition-table readers.
//!
//! Both of them decode a table straight off untrusted media for drivers that
//! run with no allocator and often no watchdog to spare: `mbr::parse` reads
//! four slots out of a sector, and `gpt::Table` walks a header whose own
//! fields say where its entry array lives and how big each entry is. A
//! malformed one must come back as `None` — never a panic, never a read
//! outside the medium, never an endless walk.
//!
//! Run with:
//!   cargo +nightly fuzz run device_tables

#![no_main]

use fstool::device::{SectorDriver, gpt, mbr};
use libfuzzer_sys::fuzz_target;

/// A RAM-backed medium, bounds-checked so a read outside it is a finding
/// rather than silent luck.
struct Disk(Vec<u8>);

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
        assert!(
            at + buf.len() <= self.0.len(),
            "read of {} bytes at LBA {lba} runs past the medium",
            buf.len()
        );
        buf.copy_from_slice(&self.0[at..at + buf.len()]);
        Ok(())
    }

    fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> Result<(), Self::Error> {
        let at = lba as usize * 512;
        assert!(at + buf.len() <= self.0.len(), "write past the medium");
        self.0[at..at + buf.len()].copy_from_slice(buf);
        Ok(())
    }
}

/// 128 sectors: enough for a header, an entry array and a backup pair.
const SECTORS: usize = 128;

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }

    // The MBR reader takes a sector's worth of bytes and nothing else.
    let mut sector = [0u8; 512];
    let n = data.len().min(512);
    sector[..n].copy_from_slice(&data[..n]);
    if let Some(table) = mbr::parse(&sector) {
        for slot in table.iter().flatten() {
            // Every accessor, on every slot the parser was willing to hand
            // back.
            let _ = (
                slot.index,
                slot.kind,
                slot.start_lba,
                slot.sectors,
                slot.looks_like_fat(),
                slot.looks_like_exfat(),
                slot.is_protective(),
            );
        }
    }
    // A short sector is not a table, and must not be read as one.
    let _ = mbr::parse(&sector[..n.min(64)]);

    // The GPT reader gets a whole medium: the fuzzer's bytes tile it, so a
    // header it accepts may point its entry array anywhere at all.
    let mut image = vec![0u8; SECTORS * 512];
    for chunk in image.chunks_mut(data.len()) {
        let n = chunk.len().min(data.len());
        chunk[..n].copy_from_slice(&data[..n]);
    }
    // Give the fuzzer a head start on reaching the parser at all.
    if data[0] & 1 == 0 {
        image[512..520].copy_from_slice(gpt::SIGNATURE);
        image[520..524].copy_from_slice(&gpt::REVISION.to_le_bytes());
        image[524..528].copy_from_slice(&92u32.to_le_bytes());
        let crc = fstool::crc::crc32(&{
            let mut h = [0u8; 92];
            h.copy_from_slice(&image[512..604]);
            h[16..20].fill(0);
            h
        });
        image[528..532].copy_from_slice(&crc.to_le_bytes());
    }

    let mut dev = Disk(image);
    let mut scratch = [0u8; 512];

    // The writers that start from what is on the medium parse it first, and
    // must refuse — never panic, never write outside it — whatever it says.
    // They run on a copy, so the reader below still sees the fuzzer's bytes.
    {
        let mut copy = Disk(dev.0.clone());
        let n = data[1] as u32;
        let part = gpt::NewPartition::new(
            gpt::BASIC_DATA,
            gpt::Guid::random_v4([data[2]; 16]),
            u32::from_le_bytes([data[3], data[4], data[5], 0]) as u64,
            (data[6] as u64) << (data[7] % 40),
        );
        let _ = gpt::set_entry(&mut copy, &mut scratch, n, Some(part));
        let _ = gpt::set_entry(&mut copy, &mut scratch, n, None);
        let entry = mbr::Entry::new(data[2], u32::from_le_bytes([data[3], data[4], 0, 0]), data[6] as u32);
        let _ = mbr::set_entry(&mut copy, &mut scratch, data[1] % 6, Some(entry));
        // Anything they did write must still be a table the readers take.
        let _ = gpt::Table::read(&mut copy, &mut scratch);
        let _ = mbr::parse(&copy.0[..512]);
    }

    let Ok(Some(table)) = gpt::Table::read(&mut dev, &mut scratch) else {
        return;
    };
    let _ = (
        table.from_backup,
        table.header.disk_guid,
        table.header.entries_crc32,
        table.header.first_usable_lba,
        table.header.last_usable_lba,
        table.header.alternate_lba,
        table.header.my_lba,
    );
    // Walk every entry the header claims, bounded by what the reader will
    // offer.
    for i in 0..table.entries() {
        let Ok(Some(part)) = table.entry(&mut dev, &mut scratch, i) else {
            continue;
        };
        let _ = (
            part.index,
            part.start_lba,
            part.end_lba,
            part.sectors(),
            part.attributes,
            part.is_read_only(),
            part.looks_like_fat_family(),
            part.is_basic_data(),
            part.is_efi_system(),
            part.guid.is_nil(),
        );
        // And the name, out of the entry's own bytes.
        if let Some((lba, at)) = table.header.entry_position(i, 512)
            && lba < dev.sector_count()
        {
            let mut buf = [0u8; 512];
            if dev.read_sectors(lba, &mut buf).is_ok() {
                let mut units = [0u16; 36];
                let _ = gpt::Partition::name_from(&buf[at..], &mut units);
            }
        }
    }
});
