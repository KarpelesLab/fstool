//! Feed arbitrary bytes into `LittleFs::open` and walk whatever comes
//! back: no panics, no unwraps, no infinite loops — every malformed
//! image either parses into a usable handle or returns a structured
//! `crate::Error`.
//!
//! littlefs derives everything from data in the image: the block size and
//! count come out of the superblock, directory chains and the volume-wide
//! metadata list are followed through pointers stored in the blocks
//! themselves, and file lengths drive the CTZ skip-list walk. All of that
//! is attacker-controlled in an untrusted image, which is what this
//! target exercises.
//!
//! Run with:
//!   cargo +nightly fuzz run littlefs_open

#![no_main]

use fstool::block::{BlockDevice, MemoryBackend};
use fstool::fs::Filesystem;
use fstool::fs::littlefs::LittleFs;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The superblock's magic + geometry live in the first 44 bytes.
    if data.len() < 64 {
        return;
    }
    let mut dev = MemoryBackend::new(data.len() as u64);
    let _ = dev.write_at(0, data);

    let Ok(mut fs) = LittleFs::open(&mut dev) else {
        return;
    };

    // Walk the tree the image claims to hold, bounded so that a corrupt
    // directory graph can't keep us here forever.
    let mut stack = vec![std::path::PathBuf::from("/")];
    let mut budget = 64;
    while let Some(dir) = stack.pop() {
        budget -= 1;
        if budget == 0 {
            break;
        }
        let Ok(entries) = fs.list(&mut dev, &dir) else {
            continue;
        };
        for e in entries {
            let child = dir.join(&e.name);
            let _ = fs.getattr(&mut dev, &child);
            let _ = fs.list_xattrs(&mut dev, &child);
            if matches!(e.kind, fstool::fs::EntryKind::Dir) {
                stack.push(child);
            } else if let Ok(mut r) = fs.read_file(&mut dev, &child) {
                // Bound the read: a corrupt size field can claim 2 GiB.
                let mut sink = Vec::new();
                let _ = std::io::Read::read_to_end(&mut std::io::Read::take(&mut r, 1 << 20), &mut sink);
            }
        }
    }
    let _ = fs.statfs(&mut dev);
});
