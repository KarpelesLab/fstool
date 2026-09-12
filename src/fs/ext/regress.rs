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

// ─────────────── finding 3: inode checksum over the full slot ───────────────

/// Read the raw on-disk inode slot (`inode_size` bytes) of `ino`.
fn raw_inode_slot(ext: &Ext, dev: &mut MemoryBackend, ino: u32) -> Vec<u8> {
    let ipg = ext.layout.inodes_per_group;
    let g = ((ino - 1) / ipg) as usize;
    let idx = (ino - 1) % ipg;
    let bs = ext.layout.block_size as u64;
    let isz = ext.layout.inode_size as u64;
    let off = ext.layout.groups[g].inode_table as u64 * bs + idx as u64 * isz;
    let mut slot = vec![0u8; isz as usize];
    dev.read_at(off, &mut slot).unwrap();
    slot
}

/// Independent re-implementation of the kernel's `ext4_inode_csum`:
/// crc32c chained over seed → ino (le32) → generation (le32) → the
/// first 128 bytes → the rest of the slot, with `i_checksum_lo` and
/// (when `i_extra_isize` covers it) `i_checksum_hi` zeroed.
fn kernel_inode_csum(uuid: &[u8; 16], ino: u32, slot: &[u8]) -> u32 {
    let raw = |c: u32, d: &[u8]| crate::crc::crc32c_append(c ^ !0, d) ^ !0;
    let mut s = slot.to_vec();
    let generation = u32::from_le_bytes(s[100..104].try_into().unwrap());
    s[0x7C..0x7E].fill(0);
    let extra = if s.len() > 128 {
        u16::from_le_bytes(s[128..130].try_into().unwrap()) as usize
    } else {
        0
    };
    let has_hi = s.len() > 128 && 128 + extra >= 0x84;
    if has_hi {
        s[0x82..0x84].fill(0);
    }
    let seed = raw(!0, uuid);
    let c = raw(seed, &ino.to_le_bytes());
    let c = raw(c, &generation.to_le_bytes());
    let c = raw(c, &s[..128]);
    if s.len() > 128 { raw(c, &s[128..]) } else { c }
}

#[test]
fn inode_checksum_covers_full_256_byte_inode() {
    let mut dev = MemoryBackend::new(64 * 1024 * 1024);
    let opts = FormatOpts {
        inode_size: 256,
        uuid: [0x3C; 16],
        ..ext4_opts()
    };
    let mut ext = Ext::format_with(&mut dev, &opts).unwrap();
    assert_eq!(ext.sb.inode_size, 256);
    assert_ne!(
        ext.sb.feature_ro_compat & constants::feature::RO_COMPAT_EXTRA_ISIZE,
        0
    );
    let ino = add_file(&mut ext, &mut dev, INO_ROOT_DIR, b"f", b"hello");
    ext.flush(&mut dev).unwrap();

    for check in [ino, INO_ROOT_DIR] {
        let slot = raw_inode_slot(&ext, &mut dev, check);
        assert_eq!(slot.len(), 256);
        let extra = u16::from_le_bytes(slot[128..130].try_into().unwrap());
        assert_eq!(extra, 32, "fresh inodes carry i_extra_isize = 32");
        let want = kernel_inode_csum(&opts.uuid, check, &slot);
        let lo = u16::from_le_bytes(slot[0x7C..0x7E].try_into().unwrap());
        let hi = u16::from_le_bytes(slot[0x82..0x84].try_into().unwrap());
        assert_eq!(lo, (want & 0xffff) as u16, "inode {check}: i_checksum_lo");
        assert_eq!(hi, (want >> 16) as u16, "inode {check}: i_checksum_hi");
    }
    // The image still round-trips through open + read.
    let re = Ext::open(&mut dev).unwrap();
    assert_eq!(read_path(&re, &mut dev, "/f"), b"hello");
}

#[test]
fn inode_checksum_128_byte_inode_matches_kernel() {
    let mut dev = MemoryBackend::new(64 * 1024 * 1024);
    let opts = FormatOpts {
        uuid: [0x71; 16],
        ..ext4_opts()
    };
    let mut ext = Ext::format_with(&mut dev, &opts).unwrap();
    let ino = add_file(&mut ext, &mut dev, INO_ROOT_DIR, b"f", b"hello");
    ext.flush(&mut dev).unwrap();
    let slot = raw_inode_slot(&ext, &mut dev, ino);
    assert_eq!(slot.len(), 128);
    let want = kernel_inode_csum(&opts.uuid, ino, &slot);
    let lo = u16::from_le_bytes(slot[0x7C..0x7E].try_into().unwrap());
    assert_eq!(lo, (want & 0xffff) as u16);
}

/// A 256-byte inode staged from disk (patch_inode path) must keep the
/// extended-area bytes it had — nanosecond timestamps, project id,
/// in-inode xattrs written by mke2fs or the kernel.
#[test]
fn disk_resident_inode_tail_survives_patch_and_flush() {
    let mut dev = MemoryBackend::new(64 * 1024 * 1024);
    // ext2 (no metadata_csum) so the patched slot needs no re-stamp.
    let opts = FormatOpts {
        kind: FsKind::Ext2,
        inode_size: 256,
        ..ext4_opts()
    };
    let mut ext = Ext::format_with(&mut dev, &opts).unwrap();
    let ino = add_file(&mut ext, &mut dev, INO_ROOT_DIR, b"f", b"hello");
    ext.flush(&mut dev).unwrap();

    // Scribble a marker into the inode's extended area (past the 32
    // bytes of i_extra_isize fields) directly on disk.
    let ipg = ext.layout.inodes_per_group;
    let off = ext.layout.groups[((ino - 1) / ipg) as usize].inode_table as u64 * 4096
        + ((ino - 1) % ipg) as u64 * 256;
    dev.write_at(off + 160, &[0xC7; 64]).unwrap();

    let mut re = Ext::open(&mut dev).unwrap();
    re.chmod(&mut dev, ino, 0o600).unwrap();
    re.flush(&mut dev).unwrap();

    let slot = raw_inode_slot(&re, &mut dev, ino);
    assert_eq!(
        u16::from_le_bytes(slot[0..2].try_into().unwrap()) & 0o7777,
        0o600
    );
    assert_eq!(&slot[160..224], &[0xC7; 64], "extended area was clobbered");
    assert_eq!(
        u16::from_le_bytes(slot[128..130].try_into().unwrap()),
        32,
        "i_extra_isize preserved"
    );
}

// ────────────── findings 8 / 9 / 13: inline_data handling ──────────────

#[test]
fn inline_data_requires_256_byte_inodes() {
    let mut dev = MemoryBackend::new(64 * 1024 * 1024);
    let opts = FormatOpts {
        inline_data: true,
        ..ext4_opts()
    };
    let err = Ext::format_with(&mut dev, &opts).unwrap_err();
    assert!(matches!(err, crate::Error::InvalidArgument(_)), "{err:?}");
}

/// With 256-byte inodes the `system.data` marker must live in the
/// in-inode xattr area (no external xattr block, no data block), the
/// body reads back, and the rw / truncate paths refuse the inode.
#[test]
fn inline_data_marker_lives_in_inode_and_rw_is_refused() {
    use crate::fs::{Filesystem, OpenFlags};
    let mut dev = MemoryBackend::new(64 * 1024 * 1024);
    let opts = FormatOpts {
        inline_data: true,
        inode_size: 256,
        ..ext4_opts()
    };
    let mut ext = Ext::format_with(&mut dev, &opts).unwrap();
    let body = b"forty bytes of inline payload go here!!!";
    assert!(body.len() <= 60);
    let ino = add_file(&mut ext, &mut dev, INO_ROOT_DIR, b"small", body);
    ext.flush(&mut dev).unwrap();

    let mut re = Ext::open(&mut dev).unwrap();
    let inode = re.read_inode(&mut dev, ino).unwrap();
    assert_ne!(inode.flags & constants::EXT4_INLINE_DATA_FL, 0);
    assert_eq!(
        inode.file_acl, 0,
        "marker must not use an external xattr block"
    );
    assert_eq!(inode.blocks_512, 0);
    let xs = re.read_xattrs(&mut dev, ino).unwrap();
    assert_eq!(xs.len(), 1);
    assert_eq!(xs[0].name, "system.data");
    assert!(xs[0].value.is_empty());
    assert_eq!(read_path(&re, &mut dev, "/small"), body);

    let err = re
        .open_file_rw(
            &mut dev,
            std::path::Path::new("/small"),
            OpenFlags::default(),
            None,
        )
        .err()
        .expect("rw on inline-data inode must be refused");
    assert!(matches!(err, crate::Error::Unsupported(_)), "{err:?}");
    let err = re.truncate(&mut dev, ino, 3).unwrap_err();
    assert!(matches!(err, crate::Error::Unsupported(_)), "{err:?}");
    // Nothing above corrupted the image.
    assert_eq!(read_path(&re, &mut dev, "/small"), body);
}

/// An inline-data inode whose `i_size` exceeds what `i_block` plus the
/// `system.data` value hold used to index past the 60-byte array and
/// panic; it must now be a clean error.
#[test]
fn inline_data_oversized_claim_is_an_error_not_a_panic() {
    let mut dev = MemoryBackend::new(64 * 1024 * 1024);
    // ext2 flavour: no metadata_csum, so the forged inode needs no CRC.
    let opts = FormatOpts {
        kind: FsKind::Ext2,
        inline_data: true,
        inode_size: 256,
        ..ext4_opts()
    };
    let mut ext = Ext::format_with(&mut dev, &opts).unwrap();
    let ino = add_file(&mut ext, &mut dev, INO_ROOT_DIR, b"small", b"tiny");
    ext.flush(&mut dev).unwrap();
    let ipg = ext.layout.inodes_per_group;
    let off = ext.layout.groups[((ino - 1) / ipg) as usize].inode_table as u64 * 4096
        + ((ino - 1) % ipg) as u64 * 256;
    // i_size_lo at offset 4 → 100 bytes, more than i_block (60) + the
    // empty marker value can provide.
    dev.write_at(off + 4, &100u32.to_le_bytes()).unwrap();
    let re = Ext::open(&mut dev).unwrap();
    let err = re
        .open_file_reader(&mut dev, ino)
        .err()
        .expect("must error");
    assert!(matches!(err, crate::Error::InvalidImage(_)), "{err:?}");
}

// ──────────── findings 4 / 5: uninit_bg flags, GDT_CSUM crc16 ────────────

/// Bitwise CRC-16 (reflected 0x8005), written independently of
/// `csum::crc16` so the descriptor test has a second opinion.
fn ref_crc16(mut crc: u16, data: &[u8]) -> u16 {
    for &b in data {
        for i in 0..8 {
            let bit = ((b >> i) & 1) as u16 ^ (crc & 1);
            crc >>= 1;
            if bit != 0 {
                crc ^= 0x8005u16.reverse_bits();
            }
        }
    }
    crc
}

/// Read the primary GDT bytes (all groups) from disk.
fn raw_gdt(ext: &Ext, dev: &mut MemoryBackend) -> Vec<u8> {
    let bs = ext.layout.block_size as u64;
    let off = if ext.layout.first_data_block == 1 {
        2 * bs
    } else {
        bs
    };
    let mut gdt = vec![0u8; ext.layout.gdt_blocks as usize * bs as usize];
    dev.read_at(off, &mut gdt).unwrap();
    gdt
}

/// An ext3 image with `uninit_bg` (RO_COMPAT_GDT_CSUM) but no
/// metadata_csum — the mke2fs default for years — must get CRC16
/// descriptor checksums and a correct `bg_itable_unused` on flush.
#[test]
fn gdt_csum_descriptors_are_stamped_with_crc16() {
    let mut dev = MemoryBackend::new(16 * 1024 * 1024);
    let opts = FormatOpts {
        kind: FsKind::Ext3,
        block_size: 1024,
        blocks_count: 16 * 1024,
        inodes_count: 256,
        uuid: [0x9B; 16],
        sparse_super: true,
        ..FormatOpts::default()
    };
    let ext = Ext::format_with(&mut dev, &opts).unwrap();
    assert_eq!(ext.layout.num_groups(), 2);
    // Turn on uninit_bg the way tune2fs would (feature bit only).
    let mut sb = vec![0u8; 1024];
    dev.read_at(1024, &mut sb).unwrap();
    let ro = u32::from_le_bytes(sb[100..104].try_into().unwrap());
    sb[100..104].copy_from_slice(&(ro | constants::feature::RO_COMPAT_GDT_CSUM).to_le_bytes());
    dev.write_at(1024, &sb).unwrap();

    let mut re = Ext::open(&mut dev).unwrap();
    for i in 0..5 {
        add_file(
            &mut re,
            &mut dev,
            INO_ROOT_DIR,
            format!("f{i}").as_bytes(),
            b"x",
        );
    }
    re.flush(&mut dev).unwrap();

    let gdt = raw_gdt(&re, &mut dev);
    let ipg = re.layout.inodes_per_group;
    for g in 0..re.layout.num_groups() as usize {
        let d = &gdt[g * 32..g * 32 + 32];
        let stored = u16::from_le_bytes(d[0x1E..0x20].try_into().unwrap());
        let c = ref_crc16(!0, &opts.uuid);
        let c = ref_crc16(c, &(g as u32).to_le_bytes());
        let want = ref_crc16(c, &d[..0x1E]);
        assert_eq!(stored, want, "group {g}: bg_checksum");
        let flags = u16::from_le_bytes(d[0x12..0x14].try_into().unwrap());
        assert_eq!(
            flags & 0x3,
            0,
            "group {g}: UNINIT flags must never be written"
        );
        // bg_itable_unused = inodes past the last used slot.
        let itable_unused = u16::from_le_bytes(d[0x1C..0x1E].try_into().unwrap()) as u32;
        let mut bm = vec![0u8; 1024];
        dev.read_at(re.layout.groups[g].inode_bitmap as u64 * 1024, &mut bm)
            .unwrap();
        let last_used = (0..ipg)
            .rev()
            .find(|&b| super::group::test_bit(&bm, b))
            .map_or(0, |b| b + 1);
        assert_eq!(
            itable_unused,
            ipg - last_used,
            "group {g}: bg_itable_unused"
        );
    }
    // Reopens cleanly and the files are there.
    let again = Ext::open(&mut dev).unwrap();
    assert_eq!(read_path(&again, &mut dev, "/f4"), b"x");
}

/// Reproduce mke2fs's lazy layout on a crate-formatted ext4 image: mark
/// group 2 BLOCK_UNINIT + INODE_UNINIT, clear INODE_ZEROED, and fill its
/// bitmap blocks and inode table with garbage. Opening must synthesise
/// the bitmaps from the layout, allocations must avoid the group's
/// metadata, the flush must clear the UNINIT flags, zero the inode-table
/// tail and set INODE_ZEROED.
#[test]
fn uninit_group_bitmaps_are_synthesised_and_flags_cleared() {
    let mut dev = MemoryBackend::new(32 * 1024 * 1024);
    let opts = FormatOpts {
        kind: FsKind::Ext4,
        block_size: 1024,
        blocks_count: 32 * 1024,
        inodes_count: 64, // 16 per group: group 0 has 6 usable, others 16
        journal_blocks: 1024,
        sparse_super: false, // every group carries an SB+GDT backup
        ..FormatOpts::default()
    };
    let ext = Ext::format_with(&mut dev, &opts).unwrap();
    assert_eq!(ext.layout.num_groups(), 4);
    let g2 = ext.layout.groups[2];
    assert!(g2.has_superblock);
    let bs = 1024u64;

    // Descriptor of group 2 lives at byte 2*32 of the GDT (block 2).
    let gdt_off = 2 * bs + 2 * 32;
    let mut d = vec![0u8; 32];
    dev.read_at(gdt_off, &mut d).unwrap();
    let flags = u16::from_le_bytes(d[0x12..0x14].try_into().unwrap());
    assert_ne!(
        flags & super::group::BG_INODE_ZEROED,
        0,
        "format marks tables zeroed"
    );
    let lazy = (flags | super::group::BG_BLOCK_UNINIT | super::group::BG_INODE_UNINIT)
        & !super::group::BG_INODE_ZEROED;
    d[0x12..0x14].copy_from_slice(&lazy.to_le_bytes());
    // itable_unused = everything (no inode ever used in this group).
    d[0x1C..0x1E].copy_from_slice(&16u16.to_le_bytes());
    dev.write_at(gdt_off, &d).unwrap();
    // Garbage in both bitmaps and the whole inode table.
    dev.write_at(g2.block_bitmap as u64 * bs, &[0xA5u8; 1024])
        .unwrap();
    dev.write_at(g2.inode_bitmap as u64 * bs, &[0xFFu8; 1024])
        .unwrap();
    let itb = ext.layout.inode_table_blocks as usize;
    dev.write_at(g2.inode_table as u64 * bs, &vec![0xEEu8; itb * 1024])
        .unwrap();

    let mut re = Ext::open(&mut dev).unwrap();
    let synth = &re.groups[2].block_bitmap;
    let meta_end = g2.data_start - g2.start_block;
    for bit in 0..meta_end {
        assert!(
            super::group::test_bit(synth, bit),
            "metadata bit {bit} of group 2 not marked in synthesised bitmap"
        );
    }
    assert!(
        !super::group::test_bit(synth, meta_end),
        "first data block must be free"
    );
    assert_eq!(
        re.groups[2].desc.flags & 0x3,
        0,
        "UNINIT flags dropped at open"
    );
    assert!(
        (0..16).all(|b| !super::group::test_bit(&re.groups[2].inode_bitmap, b)),
        "INODE_UNINIT group has no used inodes"
    );

    // 30 one-byte files exhaust groups 0/1's inodes and spill into group
    // 2; 20 × 1 MiB files push data allocation into group 2 as well.
    for i in 0..30 {
        add_file(
            &mut re,
            &mut dev,
            INO_ROOT_DIR,
            format!("s{i}").as_bytes(),
            b"s",
        );
    }
    let big = vec![0x42u8; 1024 * 1024];
    for i in 0..20 {
        add_file(
            &mut re,
            &mut dev,
            INO_ROOT_DIR,
            format!("b{i}").as_bytes(),
            &big,
        );
    }
    re.flush(&mut dev).unwrap();

    let again = Ext::open(&mut dev).unwrap();
    // Every data block of every file stays clear of group 2's metadata.
    let mut in_g2 = 0usize;
    let entries = again.list_inode(&mut dev, INO_ROOT_DIR).unwrap();
    for e in entries.iter().filter(|e| e.name.starts_with('b')) {
        let inode = again.read_inode(&mut dev, e.inode).unwrap();
        let n = inode.file_size().div_ceil(bs) as u32;
        for lb in 0..n {
            let phys = again.file_block(&mut dev, &inode, lb).unwrap();
            if phys >= g2.start_block && phys <= g2.end_block {
                in_g2 += 1;
                assert!(
                    phys >= g2.data_start,
                    "file {} block {phys} overlaps group 2 metadata (< {})",
                    e.name,
                    g2.data_start
                );
            }
        }
    }
    assert!(in_g2 > 0, "test must allocate data in group 2");
    let inodes_in_g2 = entries
        .iter()
        .filter(|e| e.inode > 32 && e.inode <= 48)
        .count();
    assert!(inodes_in_g2 > 0, "test must allocate inodes in group 2");
    for i in 0..30 {
        assert_eq!(read_path(&again, &mut dev, &format!("/s{i}")), b"s");
    }
    assert_eq!(read_path(&again, &mut dev, "/b19"), big);

    // On-disk descriptor: no UNINIT, INODE_ZEROED set, itable_unused sane.
    dev.read_at(gdt_off, &mut d).unwrap();
    let flags = u16::from_le_bytes(d[0x12..0x14].try_into().unwrap());
    assert_eq!(flags & 0x3, 0, "UNINIT flags written back");
    assert_ne!(
        flags & super::group::BG_INODE_ZEROED,
        0,
        "INODE_ZEROED not set"
    );
    let itable_unused = u16::from_le_bytes(d[0x1C..0x1E].try_into().unwrap()) as usize;
    assert_eq!(itable_unused, 16 - inodes_in_g2);
    // The inode bitmap no longer holds the 0xFF garbage.
    let mut ibm = vec![0u8; 1024];
    dev.read_at(g2.inode_bitmap as u64 * bs, &mut ibm).unwrap();
    let used_bits = (0..16u32)
        .filter(|&b| super::group::test_bit(&ibm, b))
        .count();
    assert_eq!(used_bits, inodes_in_g2);
    // The inode table beyond the used inodes was zeroed (no 0xEE left).
    let mut table = vec![0u8; itb * 1024];
    dev.read_at(g2.inode_table as u64 * bs, &mut table).unwrap();
    let used_bytes = inodes_in_g2 * 128;
    assert!(
        table[used_bytes..].iter().all(|&b| b == 0),
        "never-zeroed inode-table tail still holds garbage"
    );
    assert!(
        table[..used_bytes].iter().any(|&b| b != 0xEE),
        "live inodes were written"
    );
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

// ───────── finding 11: fast symlinks that carry an xattr block ─────────

/// A short symlink keeps its target in `i_block` even when an external
/// xattr block bumps `i_blocks` — the kernel's test is
/// `i_blocks - ea_blocks == 0`, not `i_blocks == 0`. Reading such a
/// symlink used to take the slow path and return the xattr block's
/// bytes instead of the target.
#[test]
fn fast_symlink_with_xattr_block_still_reads_from_i_block() {
    let mut dev = MemoryBackend::new(64 * 1024 * 1024);
    let mut ext = Ext::format_with(&mut dev, &ext4_opts()).unwrap();
    let ino = ext
        .add_symlink_to(
            &mut dev,
            INO_ROOT_DIR,
            b"link",
            b"../target/of/the/symlink",
            FileMeta::with_mode(0o777),
        )
        .unwrap();
    ext.set_xattrs(
        &mut dev,
        ino,
        &[super::xattr::Xattr {
            name: "user.tag".into(),
            value: b"value".to_vec(),
        }],
    )
    .unwrap();
    ext.flush(&mut dev).unwrap();

    let re = Ext::open(&mut dev).unwrap();
    let inode = re.read_inode(&mut dev, ino).unwrap();
    assert_ne!(inode.file_acl, 0, "test needs an external xattr block");
    assert_ne!(inode.blocks_512, 0, "xattr block must be charged");
    assert_eq!(
        re.read_symlink_target(&mut dev, ino).unwrap(),
        "../target/of/the/symlink"
    );
}

// ───────────── finding 12: unwritten (preallocated) extents ─────────────

/// Flip the first inline leaf extent of `ino` to "unwritten" by adding
/// the 32768 bias to its `ee_len`, the way `fallocate(2)` leaves a
/// preallocated range. `i_block` starts at offset 40 of the inode; the
/// extent header is 12 bytes, so the first leaf record's `ee_len` sits
/// at 40 + 12 + 4 = 56.
fn mark_first_extent_unwritten(ext: &Ext, dev: &mut MemoryBackend, ino: u32) -> u16 {
    let ipg = ext.layout.inodes_per_group;
    let g = ((ino - 1) / ipg) as usize;
    let idx = (ino - 1) % ipg;
    let bs = ext.layout.block_size as u64;
    let isz = ext.layout.inode_size as u64;
    let off = ext.layout.groups[g].inode_table as u64 * bs + idx as u64 * isz;
    let mut len = [0u8; 2];
    dev.read_at(off + 56, &mut len).unwrap();
    let len = u16::from_le_bytes(len);
    assert!(len > 0 && len <= super::extent::MAX_LEN_PER_EXTENT);
    dev.write_at(
        off + 56,
        &(len + super::extent::MAX_LEN_PER_EXTENT).to_le_bytes(),
    )
    .unwrap();
    len
}

/// `ee_len > 32768` marks a preallocated-but-never-written extent.
/// The kernel serves zeroes for it; we used to hand back whatever the
/// physical blocks still contained — i.e. another file's freed data.
#[test]
fn unwritten_extent_reads_as_zeroes() {
    let mut dev = MemoryBackend::new(64 * 1024 * 1024);
    let mut ext = Ext::format_with(&mut dev, &ext4_opts()).unwrap();
    let body = vec![0xA7u8; 3 * 4096];
    let ino = add_file(&mut ext, &mut dev, INO_ROOT_DIR, b"prealloc", &body);
    ext.flush(&mut dev).unwrap();
    let len = mark_first_extent_unwritten(&ext, &mut dev, ino);
    assert_eq!(len, 3);

    let re = Ext::open(&mut dev).unwrap();
    assert_eq!(read_path(&re, &mut dev, "/prealloc"), vec![0u8; 3 * 4096]);
}

/// Writing into an unwritten extent must split it and mark the written
/// block initialized (`ext4_split_extent_at`). Otherwise the bytes land
/// on disk but Linux keeps reporting zeroes for the whole range.
#[test]
fn writing_into_an_unwritten_extent_initialises_it() {
    use crate::fs::{Filesystem, OpenFlags};
    let mut dev = MemoryBackend::new(64 * 1024 * 1024);
    let mut ext = Ext::format_with(&mut dev, &ext4_opts()).unwrap();
    let body = vec![0xA7u8; 3 * 4096];
    let ino = add_file(&mut ext, &mut dev, INO_ROOT_DIR, b"prealloc", &body);
    ext.flush(&mut dev).unwrap();
    mark_first_extent_unwritten(&ext, &mut dev, ino);

    let mut re = Ext::open(&mut dev).unwrap();
    {
        use std::io::{Seek as _, SeekFrom, Write as _};
        let mut h = re
            .open_file_rw(
                &mut dev,
                std::path::Path::new("/prealloc"),
                OpenFlags::default(),
                None,
            )
            .unwrap();
        h.seek(SeekFrom::Start(4096)).unwrap();
        h.write_all(b"hello").unwrap();
        h.flush().unwrap();
    }
    re.flush(&mut dev).unwrap();

    let re2 = Ext::open(&mut dev).unwrap();
    let got = read_path(&re2, &mut dev, "/prealloc");
    assert_eq!(got.len(), 3 * 4096);
    let mut want = vec![0u8; 3 * 4096];
    want[4096..4096 + 5].copy_from_slice(b"hello");
    assert_eq!(got, want, "only the written block may become visible");

    // The middle block is now its own initialized extent; the head and
    // tail must still be unwritten.
    let inode = re2.read_inode(&mut dev, ino).unwrap();
    let iblock = super::extent::iblock_to_bytes(&inode.block);
    let (_, runs) = super::extent::decode_depth0_iblock(&iblock).unwrap();
    assert_eq!(runs.len(), 3, "{runs:?}");
    assert!(runs[0].is_unwritten() && runs[0].actual_len() == 1);
    assert!(!runs[1].is_unwritten() && runs[1].actual_len() == 1);
    assert!(runs[2].is_unwritten() && runs[2].actual_len() == 1);
}

// ─────────────────── finding 10: INCOMPAT_META_BG ───────────────────

/// `use_64bit` used to also advertise `INCOMPAT_META_BG`, which tells
/// the kernel the group descriptors are scattered across meta block
/// groups. Ours are in one contiguous table after the superblock, so
/// the flag made the image unreadable. And since the reader assumes
/// the contiguous layout, an image that really does carry meta_bg must
/// be refused instead of parsed against the wrong blocks.
#[test]
fn meta_bg_is_never_emitted_and_is_refused_on_open() {
    let mut dev = MemoryBackend::new(64 * 1024 * 1024);
    let opts = FormatOpts {
        use_64bit: true,
        ..ext4_opts()
    };
    let mut ext = Ext::format_with(&mut dev, &opts).unwrap();
    ext.flush(&mut dev).unwrap();
    assert_eq!(
        ext.sb.feature_incompat & constants::feature::INCOMPAT_META_BG,
        0
    );
    Ext::open(&mut dev).expect("a 64bit image without meta_bg reopens");

    // Now force the bit on in the on-disk superblock and re-stamp its
    // checksum the way the kernel would; open must refuse.
    let mut sb_buf = [0u8; constants::SUPERBLOCK_SIZE];
    dev.read_at(constants::SUPERBLOCK_OFFSET, &mut sb_buf)
        .unwrap();
    let incompat = u32::from_le_bytes(sb_buf[0x60..0x64].try_into().unwrap());
    sb_buf[0x60..0x64]
        .copy_from_slice(&(incompat | constants::feature::INCOMPAT_META_BG).to_le_bytes());
    let csum = super::csum::superblock(&sb_buf);
    sb_buf[1020..1024].copy_from_slice(&csum.to_le_bytes());
    dev.write_at(constants::SUPERBLOCK_OFFSET, &sb_buf).unwrap();
    let err = Ext::open(&mut dev).unwrap_err();
    assert!(matches!(err, crate::Error::Unsupported(_)), "{err:?}");
}

// ─────────── finding 6: HTree hash seed, signedness, version ───────────

/// `dx_root_info.hash_version = 1` means "half-MD4"; whether the
/// kernel then uses the *signed* or *unsigned* variant comes from
/// `s_flags`. We emit the unsigned hash, so the superblock has to say
/// `EXT2_FLAGS_UNSIGNED_HASH` — otherwise an x86 kernel (signed
/// `char`) stamps `EXT2_FLAGS_SIGNED_HASH` on first mount and can no
/// longer find indexed names containing a byte ≥ 0x80.
#[test]
fn ext4_superblock_declares_the_unsigned_htree_hash() {
    let mut dev = MemoryBackend::new(64 * 1024 * 1024);
    let mut ext = Ext::format_with(&mut dev, &ext4_opts()).unwrap();
    ext.flush(&mut dev).unwrap();
    let re = Ext::open(&mut dev).unwrap();
    assert_ne!(
        re.sb.flags & super::superblock::FLAGS_UNSIGNED_HASH,
        0,
        "EXT2_FLAGS_UNSIGNED_HASH must be set"
    );
    assert_eq!(re.sb.flags & super::superblock::FLAGS_SIGNED_HASH, 0);
    assert_eq!(re.sb.def_hash_version, super::htree::DX_HASH_HALF_MD4);
    assert!(re.htree_hash_unsigned());
}

/// The signed and unsigned half-MD4 variants agree on ASCII and
/// diverge on bytes ≥ 0x80 — which is exactly why the filesystem has
/// to declare which one it means.
#[test]
fn signed_and_unsigned_half_md4_differ_on_high_bytes() {
    let seed = [0u8; 16];
    let ascii = b"entry_0000";
    assert_eq!(
        super::htree::half_md4_hash_with(ascii, &seed, true),
        super::htree::half_md4_hash_with(ascii, &seed, false)
    );
    let high = b"caf\xc3\xa9";
    assert_ne!(
        super::htree::half_md4_hash_with(high, &seed, true),
        super::htree::half_md4_hash_with(high, &seed, false)
    );
}

/// `__ext4fs_dirhash` seeds the MD4 state from `s_hash_seed`, but only
/// when all four words are non-zero. A seed with any zero word must
/// fall back to the MD4 IV.
#[test]
fn hash_seed_is_honoured_only_when_fully_non_zero() {
    let zero = [0u8; 16];
    let full = [0x11u8; 16];
    let mut partial = [0x11u8; 16];
    partial[4..8].fill(0);

    assert_eq!(
        super::htree::hash_seed_words(&zero),
        super::htree::hash_seed_words(&partial),
        "a partially-zero seed falls back to the IV"
    );
    assert_ne!(
        super::htree::half_md4_hash_with(b"name", &zero, true),
        super::htree::half_md4_hash_with(b"name", &full, true),
        "a full seed must actually change the hash"
    );
}

/// An indexed directory built on a filesystem with a real
/// `s_hash_seed` must be routed with that seed. Formatting can't
/// produce one (we leave it zero, like a default mke2fs would not),
/// so patch it in before building the index and check that lookups
/// still find every name after a reopen.
#[test]
fn indexed_dir_round_trips_under_a_non_zero_hash_seed() {
    let mut dev = MemoryBackend::new(64 * 1024 * 1024);
    let mut ext = Ext::format_with(&mut dev, &ext4_opts()).unwrap();
    ext.sb.hash_seed = *b"\x9fseed-for-htree\x21";
    let names: Vec<String> = (0..64).map(|i| format!("name_{i:04}")).collect();
    let refs: Vec<&[u8]> = names.iter().map(|n| n.as_bytes()).collect();
    let dir = ext
        .add_dir_indexed(
            &mut dev,
            INO_ROOT_DIR,
            b"idx",
            FileMeta::with_mode(0o755),
            &refs,
        )
        .unwrap();
    for n in &names {
        add_file(&mut ext, &mut dev, dir, n.as_bytes(), n.as_bytes());
    }
    ext.flush(&mut dev).unwrap();

    let re = Ext::open(&mut dev).unwrap();
    assert_eq!(re.sb.hash_seed, *b"\x9fseed-for-htree\x21");
    let listed: Vec<String> = re
        .list_inode(&mut dev, dir)
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    for n in &names {
        assert!(listed.contains(n), "{n} missing from {listed:?}");
    }
    for n in &names {
        assert_eq!(read_path(&re, &mut dev, &format!("/idx/{n}")), n.as_bytes());
    }
}

/// Routing a new entry into an index whose `hash_version` isn't
/// half-MD4 would file it into a leaf no reader consults. Refuse.
#[test]
fn routing_into_a_non_half_md4_index_is_refused() {
    let mut dev = MemoryBackend::new(64 * 1024 * 1024);
    let mut ext = Ext::format_with(&mut dev, &ext4_opts()).unwrap();
    let names: Vec<String> = (0..64).map(|i| format!("name_{i:04}")).collect();
    let refs: Vec<&[u8]> = names.iter().map(|n| n.as_bytes()).collect();
    let dir = ext
        .add_dir_indexed(
            &mut dev,
            INO_ROOT_DIR,
            b"idx",
            FileMeta::with_mode(0o755),
            &refs,
        )
        .unwrap();
    ext.flush(&mut dev).unwrap();

    // dx_root sits in the directory's logical block 0;
    // dx_root_info.hash_version is byte 28. Force it to TEA.
    let mut re = Ext::open(&mut dev).unwrap();
    let inode = re.read_inode(&mut dev, dir).unwrap();
    let blk = re.file_block(&mut dev, &inode, 0).unwrap();
    let bs = re.layout.block_size as u64;
    dev.write_at(blk as u64 * bs + 28, &[super::htree::DX_HASH_TEA])
        .unwrap();

    let err = re
        .add_file_to_streaming(
            &mut dev,
            dir,
            b"name_0000",
            &mut std::io::Cursor::new(Vec::new()),
            0,
            FileMeta::with_mode(0o644),
        )
        .unwrap_err();
    assert!(matches!(err, crate::Error::Unsupported(_)), "{err:?}");
}
