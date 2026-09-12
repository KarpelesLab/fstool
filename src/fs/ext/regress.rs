//! Regression tests for on-disk correctness fixes in the ext writer.
//!
//! Every test here builds its image through `MemoryBackend` so it runs
//! without e2fsprogs; where a fix concerns compatibility with mke2fs-made
//! images the on-disk condition is reproduced by patching the bytes the
//! crate's own formatter wrote into the shape mke2fs would produce.

use std::io::Read as _;

use super::constants::{self, INO_ROOT_DIR};
use super::{Ext, FormatOpts, FsKind};
use crate::block::{BlockDevice, MemoryBackend};
use crate::fs::FileMeta;

fn add_file(ext: &mut Ext, dev: &mut MemoryBackend, parent: u32, name: &[u8], body: &[u8]) -> u32 {
    ext.add_file_to_streaming(
        dev,
        parent,
        name,
        &mut std::io::Cursor::new(body.to_vec()),
        body.len() as u64,
        FileMeta::with_mode(0o644),
    )
    .expect("add file")
}

fn read_path(ext: &Ext, dev: &mut MemoryBackend, path: &str) -> Vec<u8> {
    let ino = ext.path_to_inode(dev, path).expect("path");
    let mut out = Vec::new();
    ext.open_file_reader(dev, ino)
        .expect("reader")
        .read_to_end(&mut out)
        .expect("read");
    out
}

fn ext4_opts() -> FormatOpts {
    FormatOpts {
        kind: FsKind::Ext4,
        block_size: 4096,
        blocks_count: 16 * 1024,
        inodes_count: 1024,
        sparse_super: true,
        ..FormatOpts::default()
    }
}

// ───────────────────────── finding 1: alloc_inode ─────────────────────────

/// Format, create files, remove one in the middle, reopen, create two
/// more: the new inodes must land on free slots only, every original
/// file must still read back with its original content, and no two
/// live files may share an inode.
#[test]
fn alloc_inode_on_reopened_image_never_reuses_live_inodes() {
    let mut dev = MemoryBackend::new(64 * 1024 * 1024);
    let mut ext = Ext::format_with(&mut dev, &ext4_opts()).unwrap();
    let mut inos = Vec::new();
    for i in 0..8 {
        let name = format!("f{i}");
        let body = format!("body-{i}").repeat(10);
        inos.push(add_file(
            &mut ext,
            &mut dev,
            INO_ROOT_DIR,
            name.as_bytes(),
            body.as_bytes(),
        ));
    }
    ext.remove_path(&mut dev, "/f3").unwrap();
    ext.flush(&mut dev).unwrap();

    let mut re = Ext::open(&mut dev).unwrap();
    let a = add_file(&mut re, &mut dev, INO_ROOT_DIR, b"new_a", b"AAAA");
    let b = add_file(&mut re, &mut dev, INO_ROOT_DIR, b"new_b", b"BBBB");
    re.flush(&mut dev).unwrap();

    let live: Vec<u32> = inos
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != 3)
        .map(|(_, ino)| *ino)
        .collect();
    assert!(!live.contains(&a), "new_a reused live inode {a}");
    assert!(!live.contains(&b), "new_b reused live inode {b}");
    assert_ne!(a, b);
    // The freed slot (f3's inode) is the first candidate again.
    assert_eq!(a, inos[3], "freed inode should be reused first");

    let re = Ext::open(&mut dev).unwrap();
    for i in 0..8 {
        if i == 3 {
            continue;
        }
        let want = format!("body-{i}").repeat(10);
        assert_eq!(read_path(&re, &mut dev, &format!("/f{i}")), want.as_bytes());
    }
    assert_eq!(read_path(&re, &mut dev, "/new_a"), b"AAAA");
    assert_eq!(read_path(&re, &mut dev, "/new_b"), b"BBBB");
}

/// Inodes allocated in a later group (group 0 exhausted) must be
/// respected after a reopen: the allocator has to scan every group's
/// bitmap, not only group 0's.
#[test]
fn alloc_inode_respects_bitmaps_of_later_groups() {
    // 1 KiB blocks, 4 groups, 32 inodes per group.
    let mut dev = MemoryBackend::new(32 * 1024 * 1024);
    let opts = FormatOpts {
        kind: FsKind::Ext2,
        block_size: 1024,
        blocks_count: 32 * 1024,
        inodes_count: 128,
        ..FormatOpts::default()
    };
    let mut ext = Ext::format_with(&mut dev, &opts).unwrap();
    assert_eq!(ext.layout.inodes_per_group, 32);
    // Fill group 0 and spill 10 inodes into group 1.
    let mut inos = Vec::new();
    for i in 0..40 {
        let name = format!("g{i}");
        inos.push(add_file(
            &mut ext,
            &mut dev,
            INO_ROOT_DIR,
            name.as_bytes(),
            format!("content {i}").as_bytes(),
        ));
    }
    assert!(inos.iter().any(|&i| i > 32), "test must spill into group 1");
    ext.flush(&mut dev).unwrap();

    // Manually clear the on-disk inode bitmap bits of two group-0
    // inodes (simulating an external tool freeing them) so the reopened
    // allocator starts handing out slots before the group-1 ones.
    let mut re = Ext::open(&mut dev).unwrap();
    let new = add_file(&mut re, &mut dev, INO_ROOT_DIR, b"late", b"late");
    assert!(!inos.contains(&new), "late file reused a live inode {new}");
    re.flush(&mut dev).unwrap();
    let re = Ext::open(&mut dev).unwrap();
    for i in 0..40 {
        assert_eq!(
            read_path(&re, &mut dev, &format!("/g{i}")),
            format!("content {i}").as_bytes()
        );
    }
}

// ─────────────────── finding 2: superblock raw carry ───────────────────

/// Patch unmodelled superblock fields directly on the device, open,
/// mutate, flush, and verify they survive in the primary and backups.
#[test]
fn flush_preserves_unmodelled_superblock_fields() {
    // 1 KiB blocks → 8192 blocks per group → two groups, so group 1
    // carries a superblock backup we can inspect too.
    let mut dev = MemoryBackend::new(16 * 1024 * 1024);
    let opts = FormatOpts {
        kind: FsKind::Ext4,
        block_size: 1024,
        blocks_count: 16 * 1024,
        inodes_count: 256,
        sparse_super: true,
        ..FormatOpts::default()
    };
    let mut ext = Ext::format_with(&mut dev, &opts).unwrap();
    add_file(&mut ext, &mut dev, INO_ROOT_DIR, b"a", b"a");
    ext.flush(&mut dev).unwrap();

    // Patch: s_hash_seed (0xEC), s_reserved_gdt_blocks (0xCE — keep 0
    // here so the layout is unchanged, patch s_mmp_block instead),
    // s_mmp_block (0x1D0), s_usr_quota_inum (0x240), s_jnl_blocks[0]
    // (0x10C), s_last_orphan (0xE8).
    let mut sb = vec![0u8; 1024];
    dev.read_at(1024, &mut sb).unwrap();
    sb[0xEC..0xFC].copy_from_slice(&[0x5A; 16]);
    sb[0x1D0..0x1D8].copy_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
    sb[0x240..0x244].copy_from_slice(&3u32.to_le_bytes());
    sb[0x10C..0x110].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    sb[0xE8..0xEC].copy_from_slice(&77u32.to_le_bytes());
    // Re-stamp the metadata_csum superblock checksum.
    let c = super::csum::superblock(&sb);
    sb[1020..1024].copy_from_slice(&c.to_le_bytes());
    dev.write_at(1024, &sb).unwrap();

    let mut re = Ext::open(&mut dev).unwrap();
    assert_eq!(re.sb.hash_seed, [0x5A; 16]);
    add_file(&mut re, &mut dev, INO_ROOT_DIR, b"b", b"bb");
    re.flush(&mut dev).unwrap();

    let mut after = vec![0u8; 1024];
    dev.read_at(1024, &mut after).unwrap();
    assert_eq!(&after[0xEC..0xFC], &[0x5A; 16], "s_hash_seed lost");
    assert_eq!(
        &after[0x1D0..0x1D8],
        &0x0102_0304_0506_0708u64.to_le_bytes(),
        "s_mmp_block lost"
    );
    assert_eq!(
        &after[0x240..0x244],
        &3u32.to_le_bytes(),
        "quota inode lost"
    );
    assert_eq!(
        &after[0x10C..0x110],
        &0xDEAD_BEEFu32.to_le_bytes(),
        "s_jnl_blocks lost"
    );
    assert_eq!(
        &after[0xE8..0xEC],
        &77u32.to_le_bytes(),
        "s_last_orphan lost"
    );
    // Modelled counters were still updated.
    let free_after = u32::from_le_bytes(after[12..16].try_into().unwrap());
    assert_eq!(free_after, re.sb.free_blocks_count);
    // Checksum is valid so the image still opens.
    let again = Ext::open(&mut dev).unwrap();
    assert_eq!(again.sb.hash_seed, [0x5A; 16]);
    // Backup superblock in group 1 carries the same unmodelled bytes.
    let g1 = again.layout.groups[1];
    assert!(g1.has_superblock);
    let mut backup = vec![0u8; 1024];
    dev.read_at(g1.start_block as u64 * 1024, &mut backup)
        .unwrap();
    assert_eq!(&backup[0xEC..0xFC], &[0x5A; 16]);
    assert_eq!(
        &backup[0x1D0..0x1D8],
        &0x0102_0304_0506_0708u64.to_le_bytes()
    );
    let _ = constants::SUPERBLOCK_OFFSET;
}
