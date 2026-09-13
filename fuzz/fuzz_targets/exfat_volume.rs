//! Build a small valid exFAT volume, splatter the fuzzer's bytes into it,
//! then mount and walk it with the allocation-free driver.
//!
//! Everything must terminate with entries or an `Err` — never a panic,
//! never a read past the medium, and never an endless walk. exFAT derives
//! all of its structure from the card: the cluster heap's geometry comes out
//! of the boot sector, directories and files are cluster chains followed
//! through the FAT, the allocation bitmap and the up-case table are
//! themselves streams named by directory entries, and a name is compared by
//! walking that table. All of it is attacker-controlled in an untrusted
//! card, and a cycle in any chain on a microcontroller is a watchdog reset.
//!
//! Run with:
//!   cargo +nightly fuzz run exfat_volume

#![no_main]

use fstool::block::MemoryBackend;
use fstool::fs::exfat::format::FormatOpts;
use fstool::device::SectorDriver;
use fstool::fs::exfat::{Exfat, Volume};
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

/// 16 MiB, which the hosted formatter turns into a 4 KiB-cluster volume.
const BYTES: u64 = 16 * 1024 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }

    // A valid volume to start from, with a directory, a small file and a
    // multi-cluster one, so the walk has something to find.
    let mut dev = MemoryBackend::new(BYTES);
    let Ok(mut fs) = Exfat::format(&mut dev, &FormatOpts::default()) else {
        return;
    };
    let _ = fs.create_dir(&mut dev, "/sub", 0);
    let body = vec![0xa5u8; 30_000];
    let mut reader: &[u8] = &body;
    let _ = fs.create_file(
        &mut dev,
        "/sub/payload.bin",
        &mut reader,
        body.len() as u64,
        0,
    );
    let mut small: &[u8] = b"small";
    let _ = fs.create_file(&mut dev, "/sub/Mixed Case.txt", &mut small, 5, 0);
    if fs.flush(&mut dev).is_err() {
        return;
    }
    let mut image = dev.into_bytes();

    // Splatter: the first four bytes choose where, the rest is the damage.
    let off = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize % image.len();
    let payload = &data[4..];
    let n = payload.len().min(image.len() - off);
    image[off..off + n].copy_from_slice(&payload[..n]);

    // Now put the driver through it. Any outcome but a panic or a hang is
    // fine.
    let Ok(mut vol) = Volume::<_, 512>::mount(Card(image)) else {
        return;
    };
    let _ = vol.used_clusters();
    let _ = vol.free_bytes();

    // Walk the tree the card claims to hold, bounded so a corrupt directory
    // graph cannot keep us here.
    let mut dirs: Vec<String> = vec![String::from("/")];
    let mut budget = 48u32;
    while let Some(path) = dirs.pop() {
        budget -= 1;
        if budget == 0 {
            break;
        }
        let Ok(handle) = vol.open_dir(&path) else {
            continue;
        };
        let mut kids: Vec<(String, bool)> = Vec::new();
        let mut seen = 0u32;
        let mut it = vol.iter_dir(handle);
        while let Ok(Some(entry)) = it.next() {
            kids.push((entry.name().to_string(), entry.is_dir()));
            seen += 1;
            if seen > 4_000 {
                break;
            }
        }
        for (name, is_dir) in kids {
            let child = join(&path, &name);
            let _ = vol.metadata(&child);
            if is_dir {
                dirs.push(child);
                continue;
            }
            if let Ok(mut f) = vol.open_file(&child) {
                // Bound the read: a corrupt DataLength can claim terabytes.
                let mut buf = [0u8; 1024];
                let mut left = 64u32;
                while let Ok(got) = f.read(&mut vol, &mut buf) {
                    left -= 1;
                    if got == 0 || left == 0 {
                        break;
                    }
                }
            }
        }
    }

    // Lookups at the paths the volume was built with, including a
    // case-insensitive one — which walks the up-case table the image may no
    // longer have.
    let _ = vol.metadata("/sub");
    let _ = vol.exists("/sub/mixed case.txt");
    if let Ok(mut f) = vol.open_file("/sub/payload.bin") {
        let mut buf = [0u8; 1024];
        let _ = f.read(&mut vol, &mut buf);
        f.seek(20_000);
        let _ = f.read(&mut vol, &mut buf);
    }

    // And mutations, which exercise allocation and the entry-set writer
    // against a corrupt volume.
    if let Ok(mut f) = vol.open_or_create_file("/fuzz.bin") {
        let _ = f.write(&mut vol, &[1u8; 9_000]);
        let _ = f.set_len(&mut vol, 100);
        let _ = f.flush(&mut vol);
    }
    let _ = vol.create_dir("/fuzzdir");
    let _ = vol.remove_file("/sub/Mixed Case.txt");
    let _ = vol.remove_dir("/fuzzdir");
    let _ = vol.flush();
});

/// Join a directory and a name. The driver skips repeated separators, so the
/// root's trailing one needs no special case.
fn join(dir: &str, name: &str) -> String {
    let mut out = String::with_capacity(dir.len() + name.len() + 1);
    out.push_str(dir);
    out.push('/');
    out.push_str(name);
    out
}
