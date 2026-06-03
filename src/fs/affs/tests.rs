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

#[test]
fn latin1_names_decode() {
    let mut block = vec![0u8; BSIZE];
    // "café" in Latin-1: c a f é(0xE9)
    block[OFF_NAME_LEN] = 4;
    block[OFF_NAME_LEN + 1..OFF_NAME_LEN + 5].copy_from_slice(&[b'c', b'a', b'f', 0xE9]);
    assert_eq!(read_name(&block), "café");
}
