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
    // Only DOS\0 / DOS\1 fold with the classic table.
    assert!(!Variant::from_flag(0).intl);
    assert!(!Variant::from_flag(1).intl);
    for flag in 2..=5u8 {
        assert!(
            Variant::from_flag(flag).intl,
            "DOS\\{flag} must be international"
        );
    }
    // Directory cache implies international (issue #42): there is no
    // non-intl dircache flavour, so DOS\4 / DOS\5 must hash with the
    // international table even though bit 1 is clear.
    assert_eq!(
        Variant::from_flag(5),
        Variant {
            ffs: true,
            intl: true,
            dircache: true
        }
    );
    assert!(!Variant::from_flag(4).ffs);
    // The label round-trips for every supported flag.
    for flag in 0..=5u8 {
        assert_eq!(Variant::from_flag(flag).dos_label(), format!("DOS\\{flag}"));
    }
}

#[test]
fn open_refuses_long_filename_variants() {
    for flag in [6u8, 7] {
        let mut dev = MemoryBackend::new(880 * 1024);
        Affs::format(&mut dev, &super::AffsFormatOpts::default())
            .unwrap()
            .flush(&mut dev)
            .unwrap();
        dev.write_at(3, &[flag]).unwrap();
        let err = match Affs::open(&mut dev) {
            Ok(_) => panic!("DOS\\{flag}: open must be refused"),
            Err(e) => e,
        };
        assert!(
            matches!(err, crate::Error::Unsupported(ref m) if m.contains("long-filename")),
            "DOS\\{flag}: expected an Unsupported error, got {err:?}"
        );
    }
}

#[test]
fn amiga_epoch_is_1978() {
    // 1978-01-01T00:00:00Z = 252460800 unix seconds.
    assert_eq!(super::AMIGA_EPOCH, 252_460_800);
    assert_eq!(amiga_date_to_unix(0, 0, 0), 252_460_800);
    assert_eq!(amiga_date_to_unix(1, 0, 0), 252_460_800 + 86_400);
}

/// Collect a file's on-disk block set (header + extension + data) by walking
/// its header from `dev`, using only the raw block layout.
fn file_block_set(dev: &mut MemoryBackend, header: u32) -> Vec<u32> {
    let mut blocks = vec![header];
    let mut cur = header;
    loop {
        let mut buf = vec![0u8; BSIZE];
        dev.read_at(cur as u64 * BSIZE as u64, &mut buf).unwrap();
        let hq = be_i32(&buf, OFF_HIGH_SEQ).clamp(0, MAX_DATABLK as i32) as usize;
        for i in 0..hq {
            let p = be_u32(&buf, OFF_HASHTABLE + (MAX_DATABLK - 1 - i) * 4);
            if p != 0 {
                blocks.push(p);
            }
        }
        let ext = be_u32(&buf, OFF_EXTENSION);
        if ext == 0 {
            break;
        }
        blocks.push(ext);
        cur = ext;
    }
    blocks
}

fn snapshot_blocks(dev: &mut MemoryBackend, blocks: &[u32]) -> Vec<(u32, Vec<u8>)> {
    blocks
        .iter()
        .map(|&b| {
            let mut buf = vec![0u8; BSIZE];
            dev.read_at(b as u64 * BSIZE as u64, &mut buf).unwrap();
            (b, buf)
        })
        .collect()
}

/// The whole point of the in-place editor: adding a file must NOT rewrite or
/// relocate the blocks of files it didn't touch.
#[test]
fn in_place_edit_leaves_existing_blocks_untouched() {
    use crate::fs::{FileMeta, FileSource, Filesystem};
    use std::path::Path;
    let keep: Vec<u8> = (0..9000u32).map(|i| (i % 256) as u8).collect();
    let mut dev = MemoryBackend::new(880 * 1024);
    {
        let mut fs = Affs::format(&mut dev, &super::AffsFormatOpts::default()).unwrap();
        fs.create_file(
            &mut dev,
            Path::new("/keep.bin"),
            FileSource::Reader {
                reader: Box::new(std::io::Cursor::new(keep.clone())),
                len: keep.len() as u64,
            },
            FileMeta::default(),
        )
        .unwrap();
        fs.flush(&mut dev).unwrap();
    }

    // Record keep.bin's exact on-disk blocks + their bytes.
    let header = {
        let affs = Affs::open(&mut dev).unwrap();
        affs.list_path("/")
            .unwrap()
            .into_iter()
            .find(|e| e.name == "keep.bin")
            .unwrap()
            .inode
    };
    let kept_blocks = file_block_set(&mut dev, header);
    let before = snapshot_blocks(&mut dev, &kept_blocks);

    // In-place add of an unrelated file.
    {
        let mut fs = Affs::open_writable(&mut dev).unwrap();
        fs.create_file(
            &mut dev,
            Path::new("/added.bin"),
            FileSource::Reader {
                reader: Box::new(std::io::Cursor::new(vec![0xEEu8; 4000])),
                len: 4000,
            },
            FileMeta::default(),
        )
        .unwrap();
        fs.flush(&mut dev).unwrap();
    }

    // keep.bin's blocks must be byte-for-byte identical (not re-laid-out).
    let after = snapshot_blocks(&mut dev, &kept_blocks);
    assert_eq!(
        before, after,
        "in-place edit relocated/rewrote untouched blocks"
    );

    // …and both files read back correctly, volume still conformant.
    let affs = Affs::open(&mut dev).unwrap();
    let mut r = affs.open_file_reader(&mut dev, "/keep.bin").unwrap();
    let mut got = Vec::new();
    r.read_to_end(&mut got).unwrap();
    assert_eq!(got, keep);
    assert_conformant(&mut dev);
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
    // DOS\2..DOS\5 are international; dircache (bit 2) implies it.
    let intl = boot[3] >= 2;
    let dircache = boot[3] & 4 != 0;
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
        // (entry block, name, size, secondary type) per hash-chain entry,
        // to compare against the directory cache below.
        let mut chain_entries: Vec<(u32, String, u32, i32)> = Vec::new();
        for slot in 0..HT_SIZE {
            let mut e = be_u32(&db, 0x18 + slot * 4) as usize;
            while e != 0 {
                used.insert(e);
                let eb = read(dev, e);
                assert!(csum_ok(&eb), "header {e} checksum");
                let name = read_name(&eb);
                let h = super::writer::hash_name_for_test(&name, intl);
                assert_eq!(h, slot, "entry {name:?} in slot {slot} but hashes to {h}");
                let st = be_i32(&eb, 0x1fc);
                let size = if st == super::ST_FILE {
                    be_u32(&eb, 0x144)
                } else {
                    0
                };
                chain_entries.push((e as u32, name.clone(), size, st));
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
        if dircache {
            // The directory cache must exist, be structurally sound, and
            // describe exactly the entries the hash chains hold
            // (issue #43: AmigaDOS lists directories from the cache).
            let mut cached: Vec<(u32, String, u32, i32)> = Vec::new();
            let mut dc = be_u32(&db, 0x1f8) as usize;
            assert_ne!(dc, 0, "directory {dirblk} has no dircache chain");
            let mut guard = 0;
            while dc != 0 {
                assert!(used.insert(dc), "dircache block {dc} reachable twice");
                let cb = read(dev, dc);
                assert!(csum_ok(&cb), "dircache {dc} checksum");
                assert_eq!(be_i32(&cb, 0x00), super::T_DIRCACHE, "dircache {dc} type");
                assert_eq!(be_u32(&cb, 0x04) as usize, dc, "dircache {dc} own key");
                assert_eq!(be_u32(&cb, 0x08) as usize, dirblk, "dircache {dc} parent");
                let count = be_u32(&cb, 0x0c) as usize;
                let mut off = 0x18;
                for _ in 0..count {
                    let name_len = cb[off + 23] as usize;
                    let name: String = cb[off + 24..off + 24 + name_len]
                        .iter()
                        .map(|&b| b as char)
                        .collect();
                    let comment_len = cb[off + 24 + name_len] as usize;
                    cached.push((
                        be_u32(&cb, off),
                        name,
                        be_u32(&cb, off + 4),
                        cb[off + 22] as i8 as i32,
                    ));
                    let raw = 25 + name_len + comment_len;
                    off += raw + (raw & 1);
                    assert!(off <= BSIZE, "dircache {dc} record overruns the block");
                }
                dc = be_u32(&cb, 0x10) as usize;
                guard += 1;
                assert!(guard < 64, "dircache chain loop at {dc}");
            }
            let mut want = chain_entries.clone();
            want.sort();
            cached.sort();
            assert_eq!(
                cached, want,
                "dircache of directory {dirblk} disagrees with its hash chains"
            );
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

/// Turn a freshly formatted DOS\3 volume into DOS\5 by flipping the boot
/// flag. The root has no cache yet (pointer 0), which is exactly the state
/// a stale-cache-unaware tool leaves behind; the editor rebuilds it on the
/// first mutation.
fn format_dos5(dev: &mut MemoryBackend) {
    let mut fs = Affs::format(
        dev,
        &super::AffsFormatOpts {
            volume_name: "DcVol".into(),
            ffs: true,
            intl: true,
        },
    )
    .unwrap();
    fs.flush(dev).unwrap();
    dev.write_at(3, &[5]).unwrap();
}

/// Issues #42 + #43: on a DOS\5 volume, an in-place write must hash
/// accented names with the international table *and* keep every touched
/// directory's cache chain in step with its hash chains — through adds,
/// mkdirs, removals, and a root listing big enough to span several cache
/// blocks.
#[test]
fn in_place_edits_maintain_dircache_on_dos5() {
    use crate::fs::{FileMeta, FileSource, Filesystem};
    use std::path::Path;
    let mut dev = MemoryBackend::new(880 * 1024);
    format_dos5(&mut dev);

    let mut fs = Affs::open_writable(&mut dev).unwrap();
    assert!(fs.variant().dircache && fs.variant().intl);
    let put = |fs: &mut Affs, dev: &mut MemoryBackend, path: &str, len: usize| {
        fs.create_file(
            dev,
            Path::new(path),
            FileSource::Reader {
                reader: Box::new(std::io::Cursor::new(vec![0x42u8; len])),
                len: len as u64,
            },
            FileMeta::default(),
        )
        .unwrap();
    };
    // The reporter's reproduction: an accented name on a DOS\5 volume.
    put(&mut fs, &mut dev, "/éclair", 1);
    // Enough root entries that the cache needs more than one block
    // (≈ 45 bytes per record, 488 bytes per block).
    for i in 0..40 {
        put(&mut fs, &mut dev, &format!("/file_number_{i}"), 700);
    }
    fs.create_dir(&mut dev, Path::new("/Docs"), FileMeta::default())
        .unwrap();
    fs.create_dir(&mut dev, Path::new("/Docs/Empty"), FileMeta::default())
        .unwrap();
    put(&mut fs, &mut dev, "/Docs/Zwölf", 3000);
    put(&mut fs, &mut dev, "/Docs/tiny", 1);
    fs.remove(&mut dev, Path::new("/file_number_7")).unwrap();
    fs.remove(&mut dev, Path::new("/Docs/tiny")).unwrap();
    fs.remove(&mut dev, Path::new("/Docs/Empty")).unwrap();
    fs.flush(&mut dev).unwrap();

    // `éclair` must sit where the international fold puts it (slot 18),
    // not where the classic table would (slot 10).
    assert_eq!(super::writer::hash_name_for_test("éclair", true), 18);
    assert_eq!(super::writer::hash_name_for_test("éclair", false), 10);
    let root = 880 * 1024 / BSIZE / 2;
    let mut rb = vec![0u8; BSIZE];
    dev.read_at(root as u64 * BSIZE as u64, &mut rb).unwrap();
    let head = be_u32(&rb, 0x18 + 18 * 4);
    assert_ne!(head, 0, "éclair must be reachable from hash slot 18");

    // Root cache spans several blocks; each block's record count is what
    // its records occupy.
    let mut dc = be_u32(&rb, 0x1f8);
    let mut chain = 0;
    while dc != 0 {
        let mut cb = vec![0u8; BSIZE];
        dev.read_at(dc as u64 * BSIZE as u64, &mut cb).unwrap();
        chain += 1;
        dc = be_u32(&cb, 0x10);
    }
    assert!(
        chain >= 3,
        "expected a multi-block root cache, got {chain} block(s)"
    );

    // Structural + cache-vs-chain + bitmap conformance, every directory.
    assert_conformant(&mut dev);

    // And the reader still sees everything.
    let affs = Affs::open(&mut dev).unwrap();
    let names: std::collections::BTreeSet<String> = affs
        .list_path("/")
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert!(names.contains("éclair"));
    assert!(names.contains("Docs"));
    assert!(!names.contains("file_number_7"));
    let docs: Vec<String> = affs
        .list_path("/Docs")
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert_eq!(docs, ["Zwölf"]);
}

/// A directory that ends up empty again keeps a single zero-record cache
/// block, and removing a directory releases its cache block.
#[test]
fn dos5_empty_directory_keeps_an_empty_cache_block() {
    use crate::fs::{FileMeta, Filesystem};
    use std::path::Path;
    let mut dev = MemoryBackend::new(880 * 1024);
    format_dos5(&mut dev);
    let mut fs = Affs::open_writable(&mut dev).unwrap();
    fs.create_dir(&mut dev, Path::new("/A"), FileMeta::default())
        .unwrap();
    fs.create_dir(&mut dev, Path::new("/A/B"), FileMeta::default())
        .unwrap();
    fs.remove(&mut dev, Path::new("/A/B")).unwrap();
    fs.flush(&mut dev).unwrap();
    assert_conformant(&mut dev);

    let affs = Affs::open(&mut dev).unwrap();
    let Some(super::Resolved::Dir(a)) = affs.resolve("A") else {
        panic!("expected /A to be a directory");
    };
    let mut ab = vec![0u8; BSIZE];
    dev.read_at(a as u64 * BSIZE as u64, &mut ab).unwrap();
    let dc = be_u32(&ab, 0x1f8);
    assert_ne!(dc, 0, "empty dir must still own a cache block");
    let mut cb = vec![0u8; BSIZE];
    dev.read_at(dc as u64 * BSIZE as u64, &mut cb).unwrap();
    assert_eq!(be_i32(&cb, 0), super::T_DIRCACHE);
    assert_eq!(be_u32(&cb, 0x0c), 0, "record count of an empty dir's cache");
    assert_eq!(be_u32(&cb, 0x10), 0, "an empty cache is a single block");
}

/// Only 25 bitmap-page pointers fit in the root block, so a volume
/// bigger than 25 × 4064 blocks (~49.6 MiB at 512-byte blocks) needs a
/// bitmap-extension chain hanging off `bmExt` (root offset 0x1a0). The
/// writer used to emit the first 25 pages and stop, leaving the tail of
/// the volume undescribed — and, because the extension blocks weren't
/// reserved either, whatever landed on those blocks was corrupted by
/// the next allocation.
#[test]
fn writer_emits_bitmap_extension_blocks_on_a_large_volume() {
    use crate::fs::{FileMeta, FileSource, Filesystem};
    use std::path::Path;

    const BLOCKS: u64 = 140_000; // ~68 MiB → 35 bitmap pages
    let mut dev = MemoryBackend::new(BLOCKS * BSIZE as u64);
    let mut fs = Affs::format(
        &mut dev,
        &super::AffsFormatOpts {
            volume_name: "BigVol".into(),
            ffs: true,
            intl: true,
        },
    )
    .unwrap();
    fs.create_file(
        &mut dev,
        Path::new("/payload"),
        FileSource::Reader {
            reader: Box::new(std::io::Cursor::new(vec![0x5Au8; 4096])),
            len: 4096,
        },
        FileMeta::default(),
    )
    .unwrap();
    fs.flush(&mut dev).unwrap();

    let read = |dev: &mut MemoryBackend, b: u64| {
        let mut buf = vec![0u8; BSIZE];
        dev.read_at(b * BSIZE as u64, &mut buf).unwrap();
        buf
    };
    let root_block = BLOCKS / 2;
    let root = read(&mut dev, root_block);

    // Collect every bitmap page: the 25 inline pointers plus the chain.
    let words_per_ext = BSIZE / 4 - 1;
    let mut pages: Vec<u32> = Vec::new();
    for i in 0..25 {
        let p = be_u32(&root, 0x13c + i * 4);
        if p != 0 {
            pages.push(p);
        }
    }
    let mut ext = be_u32(&root, 0x1a0);
    assert_ne!(ext, 0, "bmExt must be set on a >25-page volume");
    let mut guard = 0;
    while ext != 0 {
        guard += 1;
        assert!(guard < 64, "bmExt chain runs away");
        let blk = read(&mut dev, ext as u64);
        for w in 0..words_per_ext {
            let p = be_u32(&blk, w * 4);
            if p != 0 {
                pages.push(p);
            }
        }
        ext = be_u32(&blk, words_per_ext * 4);
    }
    let want_pages = (BLOCKS - 2).div_ceil(u64::from(super::writer::BM_BITS_PER_BLOCK)) as usize;
    assert_eq!(
        pages.len(),
        want_pages,
        "bitmap must describe the whole volume"
    );

    // Every page must be inside the volume, distinct, and checksum-valid.
    let mut seen = std::collections::BTreeSet::new();
    for &p in &pages {
        assert!((p as u64) < BLOCKS, "bitmap page {p} out of range");
        assert!(seen.insert(p), "bitmap page {p} listed twice");
        let blk = read(&mut dev, p as u64);
        let mut sum = 0u32;
        let mut i = 0;
        while i < BSIZE {
            sum = sum.wrapping_add(be_u32(&blk, i));
            i += 4;
        }
        assert_eq!(sum, 0, "bitmap page {p} checksum");
    }

    // The last block of the volume is described, and reported free.
    let last = BLOCKS - 1;
    let bit = last - 2;
    let page_idx = (bit / u64::from(super::writer::BM_BITS_PER_BLOCK)) as usize;
    let within = bit % u64::from(super::writer::BM_BITS_PER_BLOCK);
    let blk = read(&mut dev, pages[page_idx] as u64);
    let word = be_u32(&blk, 4 + (within / 32) as usize * 4);
    assert_ne!(
        word & (1 << (within % 32)),
        0,
        "last block of the volume must be marked free in the bitmap"
    );

    // And the file still reads back.
    let fs = Affs::open(&mut dev).unwrap();
    let mut got = Vec::new();
    std::io::Read::read_to_end(
        &mut fs.open_file_reader(&mut dev, "/payload").unwrap(),
        &mut got,
    )
    .unwrap();
    assert_eq!(got, vec![0x5Au8; 4096]);
}

/// An AFFS hard link (`ST_LINKFILE` / `ST_LINKDIR`) is a header with no
/// content of its own — zero `byteSize`, empty data-block table, empty
/// hash table — and `realEntry` at 0x1d4 names the header that holds
/// everything. Reading the link header directly therefore reports an
/// empty file and an empty directory; the reader has to follow the
/// pointer.
#[test]
fn hard_links_resolve_to_their_target() {
    use crate::fs::{FileMeta, FileSource, Filesystem};
    use std::path::Path;

    const BLOCKS: u64 = 1760;
    let payload = vec![0xC3u8; 2000];
    let mut dev = MemoryBackend::new(BLOCKS * BSIZE as u64);
    {
        let mut fs = Affs::format(
            &mut dev,
            &super::AffsFormatOpts {
                volume_name: "Links".into(),
                ffs: true,
                intl: true,
            },
        )
        .unwrap();
        fs.create_dir(&mut dev, Path::new("/realdir"), FileMeta::default())
            .unwrap();
        fs.create_file(
            &mut dev,
            Path::new("/realdir/inner.txt"),
            FileSource::Reader {
                reader: Box::new(std::io::Cursor::new(b"inner\n".to_vec())),
                len: 6,
            },
            FileMeta::default(),
        )
        .unwrap();
        fs.create_file(
            &mut dev,
            Path::new("/real.txt"),
            FileSource::Reader {
                reader: Box::new(std::io::Cursor::new(payload.clone())),
                len: payload.len() as u64,
            },
            FileMeta::default(),
        )
        .unwrap();
        fs.flush(&mut dev).unwrap();
    }

    let root_block = BLOCKS / 2;
    let read = |dev: &mut MemoryBackend, b: u64| {
        let mut buf = vec![0u8; BSIZE];
        dev.read_at(b * BSIZE as u64, &mut buf).unwrap();
        buf
    };
    // Locate the two real headers by walking the root's hash table.
    let root = read(&mut dev, root_block);
    let mut real_file = 0u32;
    let mut real_dir = 0u32;
    for slot in 0..HT_SIZE {
        let mut e = be_u32(&root, 0x18 + slot * 4);
        while e != 0 {
            let hb = read(&mut dev, e as u64);
            match read_name(&hb).as_str() {
                "real.txt" => real_file = e,
                "realdir" => real_dir = e,
                _ => {}
            }
            e = be_u32(&hb, 0x1f0);
        }
    }
    assert!(real_file != 0 && real_dir != 0);

    // Hand-craft two link headers on otherwise-unused blocks and splice
    // them into the root's hash chains. (Our writer can't create hard
    // links; a real Amiga volume would.)
    let mut root = root;
    for (block, name, target, sec_type) in [
        (BLOCKS as u32 - 3, "hardfile", real_file, super::ST_LINKFILE),
        (BLOCKS as u32 - 4, "harddir", real_dir, super::ST_LINKDIR),
    ] {
        let slot = super::writer::hash_name_for_test(name, true);
        let mut hb = vec![0u8; BSIZE];
        super::writer::put_u32(&mut hb, 0x00, super::T_HEADER as u32);
        super::writer::put_u32(&mut hb, 0x04, block);
        let nb = name.as_bytes();
        hb[0x1b0] = nb.len() as u8;
        hb[0x1b1..0x1b1 + nb.len()].copy_from_slice(nb);
        super::writer::put_u32(&mut hb, 0x1d4, target); // realEntry
        super::writer::put_u32(&mut hb, 0x1f0, be_u32(&root, 0x18 + slot * 4));
        super::writer::put_u32(&mut hb, 0x1f4, root_block as u32);
        super::writer::put_u32(&mut hb, 0x1fc, sec_type as u32);
        let mut sum = 0u32;
        let mut i = 0;
        while i < BSIZE {
            if i != 0x14 {
                sum = sum.wrapping_add(be_u32(&hb, i));
            }
            i += 4;
        }
        super::writer::put_u32(&mut hb, 0x14, (!sum).wrapping_add(1));
        dev.write_at(block as u64 * BSIZE as u64, &hb).unwrap();
        super::writer::put_u32(&mut root, 0x18 + slot * 4, block);
    }
    // Re-checksum the root and write it back.
    let mut sum = 0u32;
    let mut i = 0;
    while i < BSIZE {
        if i != 0x14 {
            sum = sum.wrapping_add(be_u32(&root, i));
        }
        i += 4;
    }
    super::writer::put_u32(&mut root, 0x14, (!sum).wrapping_add(1));
    dev.write_at(root_block * BSIZE as u64, &root).unwrap();

    let fs = Affs::open(&mut dev).unwrap();
    let names: std::collections::BTreeSet<String> = fs
        .list_path("/")
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert!(names.contains("hardfile"), "{names:?}");
    assert!(names.contains("harddir"), "{names:?}");

    // The linked file has the target's size and contents.
    let hardfile = fs
        .list_path("/")
        .unwrap()
        .into_iter()
        .find(|e| e.name == "hardfile")
        .unwrap();
    assert_eq!(hardfile.size, payload.len() as u64, "link reports no size");
    let mut got = Vec::new();
    std::io::Read::read_to_end(
        &mut fs.open_file_reader(&mut dev, "/hardfile").unwrap(),
        &mut got,
    )
    .unwrap();
    assert_eq!(got, payload);

    // The linked directory lists the target's children.
    let inner: Vec<String> = fs
        .list_path("/harddir")
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert_eq!(inner, vec!["inner.txt".to_string()]);
}
