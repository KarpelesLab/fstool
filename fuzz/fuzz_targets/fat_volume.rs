//! Build a small valid FAT volume, splatter the fuzzer's bytes into it,
//! then mount and walk it with the allocation-free driver.
//!
//! Everything must terminate with entries or an `Err` — never a panic,
//! never a read past the medium, and never an endless walk. That last one
//! matters more here than in the hosted driver: a cyclic cluster chain on
//! a microcontroller is a watchdog reset, so every chain walk is bounded
//! and this target is what keeps it that way.

#![no_main]

use fstool::block::{BlockDevice, MemoryBackend};
use fstool::fs::Filesystem;
use fstool::fs::fat::{Fat32, FatFormatOpts, FatKind, SectorDriver, Volume};
use libfuzzer_sys::fuzz_target;

/// The volume under test, in RAM.
struct Card(Vec<u8>);

impl SectorDriver for Card {
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

/// 2 MiB is enough for a FAT16 volume with room to grow a directory.
const SECTORS: u32 = 4096;

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }

    // A valid volume to start from, with a file and a directory in it so
    // the walk has something to find.
    let mut dev = MemoryBackend::new(SECTORS as u64 * 512);
    let opts = FatFormatOpts {
        kind: FatKind::Fat16,
        total_sectors: SECTORS,
        ..Default::default()
    };
    let Ok(mut fs) = Fat32::format(&mut dev, &opts) else {
        return;
    };
    let _ = fs.create_dir(
        &mut dev,
        std::path::Path::new("/sub"),
        fstool::fs::FileMeta::default(),
    );
    let _ = fs.create_file(
        &mut dev,
        std::path::Path::new("/sub/a long name.txt"),
        fstool::fs::FileSource::Reader {
            reader: Box::new(std::io::Cursor::new(vec![0xA5u8; 5000])),
            len: 5000,
        },
        fstool::fs::FileMeta::default(),
    );
    if fs.flush(&mut dev).is_err() {
        return;
    }
    let mut image = dev.into_bytes();

    // Splatter: the first four bytes choose where, the rest is the damage.
    let off = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize % image.len();
    let payload = &data[4..];
    let n = payload.len().min(image.len() - off);
    image[off..off + n].copy_from_slice(&payload[..n]);

    // Now put the no-alloc driver through it. Any outcome but a panic or
    // a hang is fine.
    let Ok(mut vol) = Volume::<_, 512>::mount_auto(Card(image)) else {
        return;
    };
    let _ = vol.free_clusters();

    // Walk the root, bounded so a broken volume cannot keep us here.
    let root = vol.root();
    let mut seen = 0u32;
    let mut sub = None;
    {
        let mut it = vol.iter_dir(root);
        while let Ok(Some(entry)) = it.next() {
            if entry.is_dir() && !entry.is_dot() {
                sub = entry.to_dir();
            }
            seen += 1;
            if seen > 100_000 {
                break;
            }
        }
    }
    if let Some(dir) = sub {
        let mut it = vol.iter_dir(dir);
        let mut n = 0u32;
        while let Ok(Some(_)) = it.next() {
            n += 1;
            if n > 100_000 {
                break;
            }
        }
    }

    // Lookups and a read of whatever survived.
    let _ = vol.metadata("/sub");
    let _ = vol.exists("/sub/a long name.txt");
    if let Ok(mut f) = vol.open_file("/sub/a long name.txt") {
        let mut buf = [0u8; 1024];
        let _ = f.read(&mut vol, &mut buf);
        let _ = f.seek(&mut vol, 4000);
        let _ = f.read(&mut vol, &mut buf);
    }

    // And a mutation, which exercises allocation against a corrupt FAT.
    if let Ok(mut f) = vol.open_or_create_file("/fuzz.bin") {
        let _ = f.write(&mut vol, &[1u8; 2048]);
        let _ = f.flush(&mut vol);
    }
    let _ = vol.create_dir("/fuzzdir");
    let _ = vol.remove_file("/sub/a long name.txt");
    let _ = vol.flush();
});
