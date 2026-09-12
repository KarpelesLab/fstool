//! Regression tests for on-disk correctness fixes in the XFS backend.
//!
//! Every test builds its image through the crate's own formatter on a
//! [`MemoryBackend`], so the suite runs without xfsprogs installed. Where a
//! fix concerns an on-disk condition the formatter never produces (a feature
//! bit the crate does not set, say), the image is formatted first and the
//! relevant superblock / inode bytes are then patched into the shape
//! `mkfs.xfs` would have written, after which the volume is re-opened
//! through the normal read path.

use crate::block::{BlockDevice, MemoryBackend};
use crate::fs::Filesystem;

use super::write::{DeviceKind, EntryMeta};
use super::{FormatOpts, Xfs};

/// Format a fresh image of `size` bytes and begin writes on it.
fn fresh(size: u64) -> (MemoryBackend, Xfs) {
    let mut dev = MemoryBackend::new(size);
    let opts = FormatOpts::default();
    let mut xfs = super::format(&mut dev, &opts).unwrap();
    xfs.begin_writes([0u8; 16]);
    (dev, xfs)
}

// ---------------------------------------------------------------------
// Finding 22 — device-node rdev encoding (`xfs_dev_t`, SysV packing).
// ---------------------------------------------------------------------

#[test]
fn device_nodes_round_trip_major_minor() {
    let (mut dev, mut xfs) = fresh(64 * 1024 * 1024);
    let root = xfs.superblock().rootino;
    xfs.add_device(
        &mut dev,
        root,
        "ttyS0",
        DeviceKind::Char,
        4,
        64,
        EntryMeta::default(),
    )
    .unwrap();
    xfs.add_device(
        &mut dev,
        root,
        "sda1",
        DeviceKind::Block,
        8,
        1,
        EntryMeta::default(),
    )
    .unwrap();
    // A major/minor pair that needs more than the 8 low bits of each field,
    // so a wrong shift shows up immediately.
    xfs.add_device(
        &mut dev,
        root,
        "big",
        DeviceKind::Char,
        4095,
        0x3_fffe,
        EntryMeta::default(),
    )
    .unwrap();
    xfs.flush_writes(&mut dev).unwrap();

    // Re-open through the read path.
    let mut xfs = Xfs::open(&mut dev).unwrap();
    for (path, kind, major, minor) in [
        ("/ttyS0", crate::fs::EntryKind::Char, 4u32, 64u32),
        ("/sda1", crate::fs::EntryKind::Block, 8, 1),
        ("/big", crate::fs::EntryKind::Char, 4095, 0x3_fffe),
    ] {
        let a = xfs.getattr(&mut dev, std::path::Path::new(path)).unwrap();
        assert_eq!(a.kind, kind, "{path}");
        assert_eq!(
            crate::fs::devnum::decode_devnum(a.rdev),
            (major, minor),
            "{path}"
        );
    }
}

#[test]
fn device_node_on_disk_word_matches_sysv_encoding() {
    let (mut dev, mut xfs) = fresh(64 * 1024 * 1024);
    let root = xfs.superblock().rootino;
    let ino = xfs
        .add_device(
            &mut dev,
            root,
            "null",
            DeviceKind::Char,
            1,
            3,
            EntryMeta::default(),
        )
        .unwrap();
    xfs.flush_writes(&mut dev).unwrap();

    let off = xfs.ino_byte_offset(ino).unwrap();
    let mut buf = vec![0u8; xfs.inode_size() as usize];
    dev.read_at(off, &mut buf).unwrap();
    // di_format == XFS_DINODE_FMT_DEV, and the data fork holds the 4-byte
    // big-endian `xfs_dev_t`: minor | (major << 18).
    assert_eq!(buf[5], 0);
    let raw = u32::from_be_bytes(buf[176..180].try_into().unwrap());
    assert_eq!(raw, 3 | (1 << 18));
    // The four bytes past it must stay zero — the old encoder wrote an
    // 8-byte word here.
    assert_eq!(&buf[180..184], &[0u8; 4]);
}

#[test]
fn fifo_and_socket_report_zero_rdev() {
    let (mut dev, mut xfs) = fresh(64 * 1024 * 1024);
    let root = xfs.superblock().rootino;
    xfs.add_device(
        &mut dev,
        root,
        "pipe",
        DeviceKind::Fifo,
        0,
        0,
        EntryMeta::default(),
    )
    .unwrap();
    xfs.add_device(
        &mut dev,
        root,
        "sock",
        DeviceKind::Socket,
        0,
        0,
        EntryMeta::default(),
    )
    .unwrap();
    xfs.flush_writes(&mut dev).unwrap();

    let mut xfs = Xfs::open(&mut dev).unwrap();
    for (path, kind) in [
        ("/pipe", crate::fs::EntryKind::Fifo),
        ("/sock", crate::fs::EntryKind::Socket),
    ] {
        let a = xfs.getattr(&mut dev, std::path::Path::new(path)).unwrap();
        assert_eq!(a.kind, kind, "{path}");
        assert_eq!(a.rdev, 0, "{path}");
    }
}
