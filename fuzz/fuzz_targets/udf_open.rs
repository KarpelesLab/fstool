//! Feed arbitrary bytes to the UDF reader and walk whatever opens: list
//! directories, stat entries, read files and symlink targets. Asserts no
//! panics, no unbounded allocations and no infinite loops — every damaged
//! input either works or returns a structured `fstool::Error`.
//!
//! The input is the image itself, zero-extended to at least 300 blocks
//! (the anchor lives at block 256). Seed the corpus with small images
//! from `fstool create -t udf` (every revision) so the fuzzer starts
//! inside the descriptor parsers rather than at the probe.
//!
//! Run with:
//!   cargo +nightly fuzz run udf_open

#![no_main]

use std::io::Read;
use std::path::{Path, PathBuf};

use fstool::block::{BlockDevice, MemoryBackend};
use fstool::fs::Filesystem;
use fstool::fs::udf::Udf;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 64 {
        return;
    }
    // Small devices: 2048-byte blocks, at least 300 of them.
    let size = (data.len() as u64).max(300 * 2048).min(8 << 20);
    let mut dev = MemoryBackend::new(size);
    let _ = dev.write_at(0, &data[..data.len().min(size as usize)]);
    let Ok(mut fs) = Udf::open(&mut dev) else {
        return;
    };
    let _ = fs.info();
    // Bounded breadth-first walk.
    let mut queue: Vec<PathBuf> = vec![PathBuf::from("/")];
    let mut visited = 0usize;
    while let Some(dir) = queue.pop() {
        visited += 1;
        if visited > 64 {
            break;
        }
        let Ok(entries) = fs.list(&mut dev, &dir) else {
            continue;
        };
        for e in entries.into_iter().take(64) {
            let p = dir.join(&e.name);
            let _ = fs.getattr(&mut dev, &p);
            let _ = fs.list_xattrs(&mut dev, &p);
            match e.kind {
                fstool::fs::EntryKind::Dir => queue.push(p),
                fstool::fs::EntryKind::Symlink => {
                    let _ = fs.read_symlink(&mut dev, &p);
                }
                _ => {
                    if let Ok(mut r) = fs.read_file(&mut dev, Path::new(&p)) {
                        let mut buf = [0u8; 4096];
                        let _ = r.read(&mut buf);
                    }
                }
            }
        }
    }
});
