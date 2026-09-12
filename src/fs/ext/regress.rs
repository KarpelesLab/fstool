//! Regression tests for on-disk correctness fixes in the ext writer.
//!
//! Every test here builds its image through `MemoryBackend` so it runs
//! without e2fsprogs; where a fix concerns compatibility with mke2fs-made
//! images the on-disk condition is reproduced by patching the bytes the
//! crate's own formatter wrote into the shape mke2fs would produce.

use std::io::Read as _;

use super::constants::INO_ROOT_DIR;
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

#[allow(dead_code)]
fn read_path(ext: &Ext, dev: &mut MemoryBackend, path: &str) -> Vec<u8> {
    let ino = ext.path_to_inode(dev, path).expect("path");
    let mut out = Vec::new();
    ext.open_file_reader(dev, ino)
        .expect("reader")
        .read_to_end(&mut out)
        .expect("read");
    out
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

    // Patch: s_hash_seed (0xEC), s_mmp_block (0x1D0), s_usr_quota_inum
    // (0x240), s_jnl_blocks[0] (0x10C), s_last_orphan (0xE8).
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
}
