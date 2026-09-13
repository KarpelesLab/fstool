//! Build a small valid littlefs volume, splatter the fuzzer's bytes into
//! it, then mount and walk it with the allocation-free driver.
//!
//! Everything must terminate with entries or an `Err` — never a panic,
//! never a read outside a block, and never an endless walk. That last one
//! matters more here than in the hosted driver: littlefs follows pointers
//! stored in the blocks themselves — metadata-pair tails, directory chains,
//! CTZ skip-list back-pointers — and a cycle in any of them on a
//! microcontroller is a watchdog reset, so every walk is bounded and this
//! target is what keeps it that way.
//!
//! Run with:
//!   cargo +nightly fuzz run littlefs_volume

#![no_main]

use fstool::device::FlashDriver;
use fstool::fs::littlefs::Volume;
use libfuzzer_sys::fuzz_target;

/// 512 KiB of "flash": 128 blocks of 4 KiB.
const BLOCK_SIZE: u32 = 4096;
const BLOCKS: u32 = 128;

/// The volume under test, in RAM, with flash semantics: a program can only
/// clear bits, and an erase puts them all back.
struct Flash(Vec<u8>);

impl FlashDriver for Flash {
    type Error = core::convert::Infallible;

    fn block_size(&self) -> u32 {
        BLOCK_SIZE
    }

    fn block_count(&self) -> u32 {
        self.0.len() as u32 / BLOCK_SIZE
    }

    fn prog_size(&self) -> u32 {
        256
    }

    fn read(&mut self, block: u32, off: u32, buf: &mut [u8]) -> Result<(), Self::Error> {
        let at = block as usize * BLOCK_SIZE as usize + off as usize;
        buf.copy_from_slice(&self.0[at..at + buf.len()]);
        Ok(())
    }

    fn prog(&mut self, block: u32, off: u32, data: &[u8]) -> Result<(), Self::Error> {
        let at = block as usize * BLOCK_SIZE as usize + off as usize;
        for (slot, byte) in self.0[at..at + data.len()].iter_mut().zip(data) {
            *slot &= *byte;
        }
        Ok(())
    }

    fn erase(&mut self, block: u32) -> Result<(), Self::Error> {
        let at = block as usize * BLOCK_SIZE as usize;
        self.0[at..at + BLOCK_SIZE as usize].fill(0xff);
        Ok(())
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }

    // A valid volume to start from, with a directory, an inline file and a
    // multi-block one, so the walk has something to find.
    let flash = Flash(vec![0xff; (BLOCKS * BLOCK_SIZE) as usize]);
    let Ok(mut vol) = Volume::<_, 4096, 256>::format(flash) else {
        return;
    };
    let _ = vol.create_dir("/sub");
    if let Ok(mut f) = vol.create_file("/sub/payload.bin") {
        let _ = f.write(&mut vol, &[0xa5u8; 20_000]);
    }
    if let Ok(mut f) = vol.create_file("/sub/inline.txt") {
        let _ = f.write(&mut vol, b"small");
    }
    let _ = vol.set_attr("/sub/inline.txt", 3, b"attr");
    let Ok(flash) = vol.unmount() else {
        return;
    };
    let mut image = flash.0;

    // Splatter: the first four bytes choose where, the rest is the damage.
    let off = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize % image.len();
    let payload = &data[4..];
    let n = payload.len().min(image.len() - off);
    image[off..off + n].copy_from_slice(&payload[..n]);

    // Now put the driver through it. Any outcome but a panic or a hang is
    // fine.
    let Ok(mut vol) = Volume::<_, 4096, 256>::mount(Flash(image)) else {
        return;
    };
    let _ = vol.used_blocks();

    // Walk the tree the image claims to hold, bounded so a corrupt
    // directory graph cannot keep us here.
    let mut dirs: Vec<String> = vec![String::from("/")];
    let mut budget = 64u32;
    while let Some(path) = dirs.pop() {
        budget -= 1;
        if budget == 0 {
            break;
        }
        let Ok(dir) = vol.open_dir(&path) else {
            continue;
        };
        let mut kids: Vec<(String, bool)> = Vec::new();
        let mut seen = 0u32;
        let mut it = vol.iter_dir(dir);
        while let Ok(Some(entry)) = it.next() {
            if let Some(name) = entry.name_str() {
                kids.push((name.to_string(), entry.is_dir()));
            }
            seen += 1;
            if seen > 10_000 {
                break;
            }
        }
        for (name, is_dir) in kids {
            let child = join(&path, &name);
            let _ = vol.metadata(&child);
            let mut attr = [0u8; 64];
            let _ = vol.attr(&child, 3, &mut attr);
            if is_dir {
                dirs.push(child);
                continue;
            }
            if let Ok(mut f) = vol.open_file(&child) {
                // Bound the read: a corrupt size field can claim 2 GiB.
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

    // Lookups and reads at the paths the volume was built with.
    let _ = vol.metadata("/sub");
    let _ = vol.exists("/sub/payload.bin");
    if let Ok(mut f) = vol.open_file("/sub/payload.bin") {
        let mut buf = [0u8; 1024];
        let _ = f.read(&mut vol, &mut buf);
        f.seek(15_000);
        let _ = f.read(&mut vol, &mut buf);
    }

    // And mutations, which exercise allocation and commits against a
    // corrupt volume.
    if let Ok(mut f) = vol.open_or_create_file("/fuzz.bin") {
        let _ = f.write(&mut vol, &[1u8; 9_000]);
        let _ = f.set_len(&mut vol, 100);
    }
    let _ = vol.create_dir("/fuzzdir");
    let _ = vol.set_attr("/fuzz.bin", 9, &[7u8; 32]);
    let _ = vol.remove_file("/sub/inline.txt");
    let _ = vol.remove_dir("/fuzzdir");
    let _ = vol.sync();
});

/// Join a directory and a name. The driver skips repeated separators, so
/// the root's trailing one needs no special case.
fn join(dir: &str, name: &str) -> String {
    let mut out = String::with_capacity(dir.len() + name.len() + 1);
    out.push_str(dir);
    out.push('/');
    out.push_str(name);
    out
}
