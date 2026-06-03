//! Unit tests for the AFFS reader, built around hand-assembled volumes.
//!
//! The reader scans all hash-table slots (it does not depend on the name
//! hash to *find* entries), so these fixtures place header pointers in
//! arbitrary slots; only the root-block checksum must be correct.

use super::*;
use crate::block::{BlockDevice, MemoryBackend};

fn put_u32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_be_bytes());
}

fn put_name(b: &mut [u8], name: &str) {
    b[OFF_NAME_LEN] = name.len() as u8;
    b[OFF_NAME_LEN + 1..OFF_NAME_LEN + 1 + name.len()].copy_from_slice(name.as_bytes());
}

/// Zero the checksum word, then store `0 - sum(words)` so the block sums to 0.
fn fix_checksum(block: &mut [u8]) {
    put_u32(block, 0x14, 0);
    let mut sum = 0u32;
    let mut i = 0;
    while i < BSIZE {
        sum = sum.wrapping_add(be_u32(block, i));
        i += 4;
    }
    put_u32(block, 0x14, 0u32.wrapping_sub(sum));
}

/// Build a tiny single-file volume. `ffs` selects raw vs OFS data blocks.
/// Layout: boot@0-1, root@8 (16-block volume), file header@9, data@10.
fn build_volume(ffs: bool, content: &[u8]) -> (MemoryBackend, u32) {
    const NBLK: u32 = 16;
    const ROOT: u32 = 8;
    const FHDR: u32 = 9;
    const DATA0: u32 = 10;
    let mut dev = MemoryBackend::new((NBLK as u64) * BSIZE as u64);

    // Boot block.
    let mut boot = vec![0u8; 2 * BSIZE];
    boot[0..3].copy_from_slice(b"DOS");
    boot[3] = if ffs { 1 } else { 0 };
    put_u32(&mut boot, 8, ROOT); // root pointer
    dev.write_at(0, &boot).unwrap();

    // Root block.
    let mut root = vec![0u8; BSIZE];
    put_u32(&mut root, OFF_TYPE, T_HEADER as u32);
    put_u32(&mut root, 0x0c, HT_SIZE as u32); // hashTableSize
    put_u32(&mut root, OFF_HASHTABLE, FHDR); // one entry in slot 0
    put_name(&mut root, "TestDisk");
    put_u32(&mut root, OFF_SEC_TYPE, ST_ROOT as u32);
    fix_checksum(&mut root);
    dev.write_at(ROOT as u64 * BSIZE as u64, &root).unwrap();

    // File header.
    let payload = if ffs { BSIZE } else { BSIZE - 24 };
    let nblocks = content.len().div_ceil(payload).max(1) as u32;
    assert!(nblocks <= MAX_DATABLK as u32);
    let mut fh = vec![0u8; BSIZE];
    put_u32(&mut fh, OFF_TYPE, T_HEADER as u32);
    put_u32(&mut fh, 0x04, FHDR); // headerKey
    put_u32(&mut fh, OFF_HIGH_SEQ, nblocks);
    put_u32(&mut fh, 0x10, DATA0); // firstData
    // Data pointers fill downward from slot MAX_DATABLK-1.
    for i in 0..nblocks {
        let slot = MAX_DATABLK - 1 - i as usize;
        put_u32(&mut fh, OFF_HASHTABLE + slot * 4, DATA0 + i);
    }
    put_u32(&mut fh, OFF_BYTE_SIZE, content.len() as u32);
    // mtime: 1 day after the Amiga epoch.
    put_u32(&mut fh, OFF_DAYS, 1);
    put_name(&mut fh, "hello.txt");
    put_u32(&mut fh, OFF_NEXT_SAME_HASH, 0);
    put_u32(&mut fh, 0x1f4, ROOT); // parent
    put_u32(&mut fh, OFF_SEC_TYPE, ST_FILE as u32);
    fix_checksum(&mut fh);
    dev.write_at(FHDR as u64 * BSIZE as u64, &fh).unwrap();

    // Data blocks.
    for i in 0..nblocks {
        let mut blk = vec![0u8; BSIZE];
        let start = i as usize * payload;
        let end = (start + payload).min(content.len());
        let chunk = &content[start..end];
        if ffs {
            blk[..chunk.len()].copy_from_slice(chunk);
        } else {
            put_u32(&mut blk, OFF_TYPE, T_DATA as u32);
            put_u32(&mut blk, 0x04, FHDR); // headerKey
            put_u32(&mut blk, 0x08, i + 1); // seqNum (1-based)
            put_u32(&mut blk, 0x0c, chunk.len() as u32); // dataSize
            let next = if (i + 1) < nblocks { DATA0 + i + 1 } else { 0 };
            put_u32(&mut blk, 0x10, next); // nextData
            blk[24..24 + chunk.len()].copy_from_slice(chunk);
            fix_checksum(&mut blk);
        }
        dev.write_at((DATA0 + i) as u64 * BSIZE as u64, &blk)
            .unwrap();
    }

    (dev, NBLK)
}

#[test]
fn opens_ffs_and_lists_root() {
    let (mut dev, _) = build_volume(true, b"hello amiga\n");
    let affs = Affs::open(&mut dev).unwrap();
    assert_eq!(affs.volume_name, "TestDisk");
    assert!(affs.variant().ffs);
    let entries = affs.list_path("/").unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "hello.txt");
    assert_eq!(entries[0].kind, EntryKind::Regular);
    assert_eq!(entries[0].size, 12);
}

#[test]
fn reads_ffs_file_contents() {
    let content = b"The quick brown fox jumps over the lazy dog.\n";
    let (mut dev, _) = build_volume(true, content);
    let affs = Affs::open(&mut dev).unwrap();
    let mut r = affs.open_file_reader(&mut dev, "hello.txt").unwrap();
    let mut got = Vec::new();
    r.read_to_end(&mut got).unwrap();
    assert_eq!(got, content);
}

#[test]
fn reads_ofs_file_contents_spanning_blocks() {
    // > 488 bytes forces two OFS data blocks.
    let content: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
    let (mut dev, _) = build_volume(false, &content);
    let affs = Affs::open(&mut dev).unwrap();
    assert!(!affs.variant().ffs);
    let mut r = affs.open_file_reader(&mut dev, "/hello.txt").unwrap();
    let mut got = Vec::new();
    r.read_to_end(&mut got).unwrap();
    assert_eq!(got, content);
}

#[test]
fn file_reader_seek_works() {
    let content = b"0123456789ABCDEF";
    let (mut dev, _) = build_volume(true, content);
    let affs = Affs::open(&mut dev).unwrap();
    let mut r = affs.open_file_reader(&mut dev, "hello.txt").unwrap();
    r.seek(SeekFrom::Start(10)).unwrap();
    let mut got = Vec::new();
    r.read_to_end(&mut got).unwrap();
    assert_eq!(got, b"ABCDEF");
}

#[test]
fn rejects_non_dos_image() {
    let mut dev = MemoryBackend::new(4096);
    assert!(Affs::open(&mut dev).is_err());
}

#[test]
fn variant_flags_decode() {
    assert_eq!(
        Variant::from_flag(3),
        Variant {
            ffs: true,
            intl: true,
            dircache: false
        }
    );
    assert_eq!(Variant::from_flag(0).dos_label(), "DOS\\0");
    assert_eq!(Variant::from_flag(7).dos_label(), "DOS\\7");
}

#[test]
fn amiga_epoch_is_1978() {
    // 1978-01-01T00:00:00Z = 252460800 unix seconds.
    assert_eq!(super::AMIGA_EPOCH, 252_460_800);
    assert_eq!(amiga_date_to_unix(0, 0, 0), 252_460_800);
    assert_eq!(amiga_date_to_unix(1, 0, 0), 252_460_800 + 86_400);
}

fn roundtrip_variant(ffs: bool) {
    use crate::fs::{FileMeta, FileSource, Filesystem};
    use std::path::Path;
    let mut dev = MemoryBackend::new(880 * 1024); // standard DD floppy
    let opts = super::AffsFormatOpts {
        volume_name: "MyVol".into(),
        ffs,
        intl: true,
    };
    let big: Vec<u8> = (0..5000u32).map(|i| (i * 7 % 256) as u8).collect();
    {
        let mut fs = Affs::format(&mut dev, &opts).unwrap();
        fs.create_dir(&mut dev, Path::new("/docs"), FileMeta::default())
            .unwrap();
        fs.create_file(
            &mut dev,
            Path::new("/docs/readme.txt"),
            FileSource::Reader {
                reader: Box::new(std::io::Cursor::new(b"hello from amiga\n".to_vec())),
                len: 17,
            },
            FileMeta::default(),
        )
        .unwrap();
        // A multi-block file (spans data blocks + exercises OFS headers).
        fs.create_file(
            &mut dev,
            Path::new("/big.bin"),
            FileSource::Reader {
                reader: Box::new(std::io::Cursor::new(big.clone())),
                len: big.len() as u64,
            },
            FileMeta::default(),
        )
        .unwrap();
        fs.flush(&mut dev).unwrap();
    }

    // Reopen read-only via the on-disk reader and verify.
    let affs = Affs::open(&mut dev).unwrap();
    assert_eq!(affs.volume_name, "MyVol");
    assert_eq!(affs.variant().ffs, ffs);
    let root: Vec<_> = affs
        .list_path("/")
        .unwrap()
        .into_iter()
        .map(|e| (e.name, e.kind))
        .collect();
    assert!(root.contains(&("docs".into(), EntryKind::Dir)));
    assert!(root.contains(&("big.bin".into(), EntryKind::Regular)));
    let docs = affs.list_path("/docs").unwrap();
    assert_eq!(docs.len(), 1);
    assert_eq!(docs[0].name, "readme.txt");

    let mut r = affs.open_file_reader(&mut dev, "/docs/readme.txt").unwrap();
    let mut got = Vec::new();
    r.read_to_end(&mut got).unwrap();
    assert_eq!(got, b"hello from amiga\n");

    let mut r = affs.open_file_reader(&mut dev, "/big.bin").unwrap();
    let mut got = Vec::new();
    r.read_to_end(&mut got).unwrap();
    assert_eq!(got, big);
}

#[test]
fn writer_round_trip_ffs() {
    roundtrip_variant(true);
}

#[test]
fn writer_round_trip_ofs() {
    roundtrip_variant(false);
}

/// Independently re-validate a written volume the way the Linux kernel
/// `affs` driver does: every block checksum, every directory entry living in
/// the hash slot its name hashes to, and a bitmap that exactly matches the
/// set of allocated blocks. This catches the writer bugs the lenient reader
/// (which scans all slots) cannot — and runs on every CI platform with no
/// external tools.
fn assert_conformant(dev: &mut MemoryBackend) {
    let n = (dev.total_size() / BSIZE as u64) as usize;
    let read = |dev: &mut MemoryBackend, b: usize| {
        let mut buf = vec![0u8; BSIZE];
        dev.read_at(b as u64 * BSIZE as u64, &mut buf).unwrap();
        buf
    };
    let boot = read(dev, 0);
    let ffs = boot[3] & 1 != 0;
    let intl = boot[3] & 2 != 0;
    let csum_ok = |blk: &[u8]| {
        let mut s = 0u32;
        let mut i = 0;
        while i < BSIZE {
            s = s.wrapping_add(be_u32(blk, i));
            i += 4;
        }
        s == 0
    };
    let root = n / 2;
    let rb = read(dev, root);
    assert!(csum_ok(&rb), "root checksum");
    assert_eq!(be_i32(&rb, 0x1fc), super::ST_ROOT, "root sectype");
    assert_eq!(be_u32(&rb, 0x0c), HT_SIZE as u32, "root htSize");
    assert_eq!(be_i32(&rb, 0x138), -1, "bmFlag valid");

    let bm0 = be_u32(&rb, 0x13c) as usize;
    assert!(csum_ok(&read(dev, bm0)), "bitmap checksum");

    let mut used = std::collections::BTreeSet::from([0, 1, root, bm0]);
    // Recursive walk of all hash buckets.
    let mut stack = vec![root];
    while let Some(dirblk) = stack.pop() {
        let db = read(dev, dirblk);
        for slot in 0..HT_SIZE {
            let mut e = be_u32(&db, 0x18 + slot * 4) as usize;
            while e != 0 {
                used.insert(e);
                let eb = read(dev, e);
                assert!(csum_ok(&eb), "header {e} checksum");
                let name = read_name(&eb);
                let h = super::writer::hash_name_for_test(&name, intl);
                assert_eq!(h, slot, "entry {name:?} in slot {slot} but hashes to {h}");
                match be_i32(&eb, 0x1fc) {
                    s if s == super::ST_USERDIR => stack.push(e),
                    s if s == super::ST_FILE => {
                        // Collect data + extension blocks.
                        let mut cur = e;
                        while cur != 0 {
                            let cb = read(dev, cur);
                            let hq = be_i32(&cb, 0x08).clamp(0, MAX_DATABLK as i32) as usize;
                            for i in 0..hq {
                                let dptr = be_u32(&cb, 0x18 + (MAX_DATABLK - 1 - i) * 4) as usize;
                                used.insert(dptr);
                                if !ffs {
                                    // OFS data blocks carry their own checksum.
                                    assert!(csum_ok(&read(dev, dptr)), "OFS data {dptr} checksum");
                                }
                            }
                            let ext = be_u32(&cb, 0x1f8) as usize;
                            if ext != 0 {
                                used.insert(ext);
                            }
                            cur = ext;
                        }
                    }
                    _ => {}
                }
                e = be_u32(&eb, 0x1f0) as usize;
            }
        }
    }

    // Bitmap bit set == free; verify it matches the used set exactly.
    let bm = read(dev, bm0);
    for b in 2..n {
        let word = be_u32(&bm, 4 + ((b - 2) / 32) * 4);
        let free = (word >> ((b - 2) % 32)) & 1 == 1;
        assert_eq!(free, !used.contains(&b), "bitmap disagrees on block {b}");
    }
}

#[test]
fn written_ffs_volume_is_kernel_conformant() {
    use crate::fs::{FileMeta, FileSource, Filesystem};
    use std::path::Path;
    let mut dev = MemoryBackend::new(880 * 1024);
    let mut fs = Affs::format(
        &mut dev,
        &super::AffsFormatOpts {
            volume_name: "Conf".into(),
            ffs: true,
            intl: true,
        },
    )
    .unwrap();
    fs.create_dir(&mut dev, Path::new("/System"), FileMeta::default())
        .unwrap();
    for name in ["readme", "AExplorer", "Disk.info", "café"] {
        fs.create_file(
            &mut dev,
            &Path::new("/System").join(name),
            FileSource::Reader {
                reader: Box::new(std::io::Cursor::new(vec![0xABu8; 1500])),
                len: 1500,
            },
            FileMeta::default(),
        )
        .unwrap();
    }
    fs.flush(&mut dev).unwrap();
    assert_conformant(&mut dev);
}

#[test]
fn written_ofs_volume_is_kernel_conformant() {
    use crate::fs::{FileMeta, FileSource, Filesystem};
    use std::path::Path;
    let mut dev = MemoryBackend::new(880 * 1024);
    let mut fs = Affs::format(
        &mut dev,
        &super::AffsFormatOpts {
            volume_name: "ConfOfs".into(),
            ffs: false,
            intl: false,
        },
    )
    .unwrap();
    for name in ["one", "two", "three", "SYSTEM"] {
        fs.create_file(
            &mut dev,
            &Path::new("/").join(name),
            FileSource::Reader {
                reader: Box::new(std::io::Cursor::new(vec![0x5Au8; 2000])),
                len: 2000,
            },
            FileMeta::default(),
        )
        .unwrap();
    }
    fs.flush(&mut dev).unwrap();
    assert_conformant(&mut dev);
}

#[test]
fn in_place_add_and_remove_round_trip() {
    use crate::fs::{FileMeta, FileSource, Filesystem};
    use std::path::Path;
    let mut dev = MemoryBackend::new(880 * 1024);
    let original: Vec<u8> = (0..3333u32).map(|i| (i % 200) as u8).collect();
    // Build an initial volume with a couple of entries.
    {
        let mut fs = Affs::format(&mut dev, &super::AffsFormatOpts::default()).unwrap();
        fs.create_dir(&mut dev, Path::new("/keep"), FileMeta::default())
            .unwrap();
        fs.create_file(
            &mut dev,
            Path::new("/keep/orig.bin"),
            FileSource::Reader {
                reader: Box::new(std::io::Cursor::new(original.clone())),
                len: original.len() as u64,
            },
            FileMeta::default(),
        )
        .unwrap();
        fs.create_file(
            &mut dev,
            Path::new("/old.txt"),
            FileSource::Reader {
                reader: Box::new(std::io::Cursor::new(b"delete me\n".to_vec())),
                len: 10,
            },
            FileMeta::default(),
        )
        .unwrap();
        fs.flush(&mut dev).unwrap();
    }

    // Re-open the existing image, mutate in place, flush.
    {
        let mut fs = Affs::open_writable(&mut dev).unwrap();
        fs.remove(&mut dev, Path::new("/old.txt")).unwrap();
        fs.create_dir(&mut dev, Path::new("/added"), FileMeta::default())
            .unwrap();
        fs.create_file(
            &mut dev,
            Path::new("/added/new.txt"),
            FileSource::Reader {
                reader: Box::new(std::io::Cursor::new(b"freshly added\n".to_vec())),
                len: 14,
            },
            FileMeta::default(),
        )
        .unwrap();
        fs.flush(&mut dev).unwrap();
    }

    // Re-open read-only and confirm the original survived and the edits stuck.
    let affs = Affs::open(&mut dev).unwrap();
    let root: Vec<_> = affs
        .list_path("/")
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert!(root.contains(&"keep".to_string()));
    assert!(root.contains(&"added".to_string()));
    assert!(
        !root.contains(&"old.txt".to_string()),
        "removed file should be gone"
    );

    // Original file content preserved byte-exact across the in-place rewrite.
    let mut r = affs.open_file_reader(&mut dev, "/keep/orig.bin").unwrap();
    let mut got = Vec::new();
    r.read_to_end(&mut got).unwrap();
    assert_eq!(got, original);

    let mut r = affs.open_file_reader(&mut dev, "/added/new.txt").unwrap();
    let mut got = Vec::new();
    r.read_to_end(&mut got).unwrap();
    assert_eq!(got, b"freshly added\n");

    // And the rewritten volume is still kernel-conformant.
    assert_conformant(&mut dev);
}

#[test]
fn writer_remove_and_reject_duplicate() {
    use crate::fs::{FileMeta, FileSource, Filesystem};
    use std::path::Path;
    let mut dev = MemoryBackend::new(880 * 1024);
    let mut fs = Affs::format(&mut dev, &super::AffsFormatOpts::default()).unwrap();
    fs.create_file(
        &mut dev,
        Path::new("/a.txt"),
        FileSource::Reader {
            reader: Box::new(std::io::Cursor::new(b"x".to_vec())),
            len: 1,
        },
        FileMeta::default(),
    )
    .unwrap();
    // Duplicate name rejected.
    assert!(
        fs.create_dir(&mut dev, Path::new("/a.txt"), FileMeta::default())
            .is_err()
    );
    fs.remove(&mut dev, Path::new("/a.txt")).unwrap();
    fs.flush(&mut dev).unwrap();
    let affs = Affs::open(&mut dev).unwrap();
    assert!(affs.list_path("/").unwrap().is_empty());
}

#[test]
fn latin1_names_decode() {
    let mut block = vec![0u8; BSIZE];
    // "café" in Latin-1: c a f é(0xE9)
    block[OFF_NAME_LEN] = 4;
    block[OFF_NAME_LEN + 1..OFF_NAME_LEN + 5].copy_from_slice(&[b'c', b'a', b'f', 0xE9]);
    assert_eq!(read_name(&block), "café");
}
