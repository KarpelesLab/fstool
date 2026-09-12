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

// ---------------------------------------------------------------------
// Finding 23 — attribute flag bits (`XFS_ATTR_LOCAL/ROOT/SECURE`).
// ---------------------------------------------------------------------

#[test]
fn xattr_flag_constants_match_xfs_da_format() {
    use super::xattr::{XFS_ATTR_INCOMPLETE, XFS_ATTR_LOCAL, XFS_ATTR_ROOT, XFS_ATTR_SECURE};
    assert_eq!(XFS_ATTR_LOCAL, 0x01);
    assert_eq!(XFS_ATTR_ROOT, 0x02);
    assert_eq!(XFS_ATTR_SECURE, 0x04);
    assert_eq!(XFS_ATTR_INCOMPLETE, 0x80);
    // The leaf module must agree — it re-exports the same set.
    assert_eq!(super::xattr_leaf::XFS_ATTR_SECURE, XFS_ATTR_SECURE);
}

#[test]
fn shortform_xattr_namespaces_round_trip_on_disk() {
    let (mut dev, mut xfs) = fresh(64 * 1024 * 1024);
    let root = xfs.superblock().rootino;
    let mut src = std::io::Cursor::new(b"body".to_vec());
    let ino = xfs
        .add_file(&mut dev, root, "f", EntryMeta::default(), 4, &mut src)
        .unwrap();
    xfs.add_xattr(&mut dev, ino, "user.u", b"1").unwrap();
    xfs.add_xattr(&mut dev, ino, "trusted.t", b"2").unwrap();
    xfs.add_xattr(&mut dev, ino, "security.s", b"3").unwrap();
    xfs.flush_writes(&mut dev).unwrap();

    // Byte-level: the shortform area must carry XFS_ATTR_SECURE (0x04) on
    // the security entry, not 0x01 (which is XFS_ATTR_LOCAL).
    let off = xfs.ino_byte_offset(ino).unwrap();
    let mut buf = vec![0u8; xfs.inode_size() as usize];
    dev.read_at(off, &mut buf).unwrap();
    let forkoff = buf[82] as usize;
    assert_ne!(forkoff, 0);
    assert_eq!(buf[83], 1, "aformat should be LOCAL (shortform)");
    let sf = &buf[176 + forkoff * 8..];
    let count = sf[2] as usize;
    assert_eq!(count, 3);
    let mut pos = 4usize;
    let mut seen = Vec::new();
    for _ in 0..count {
        let namelen = sf[pos] as usize;
        let valuelen = sf[pos + 1] as usize;
        let flags = sf[pos + 2];
        let name = std::str::from_utf8(&sf[pos + 3..pos + 3 + namelen])
            .unwrap()
            .to_string();
        seen.push((name, flags));
        pos += 3 + namelen + valuelen;
    }
    seen.sort();
    assert_eq!(
        seen,
        vec![
            ("s".to_string(), 0x04u8),
            ("t".to_string(), 0x02u8),
            ("u".to_string(), 0x00u8),
        ]
    );

    // And the decode side must give the names back.
    let xfs = Xfs::open(&mut dev).unwrap();
    let attrs = xfs.read_xattrs(&mut dev, ino).unwrap();
    assert_eq!(attrs.get("user.u"), Some(&b"1".to_vec()));
    assert_eq!(attrs.get("trusted.t"), Some(&b"2".to_vec()));
    assert_eq!(attrs.get("security.s"), Some(&b"3".to_vec()));
}

#[test]
fn leaf_xattr_namespaces_round_trip_on_disk() {
    let (mut dev, mut xfs) = fresh(64 * 1024 * 1024);
    let root = xfs.superblock().rootino;
    let mut src = std::io::Cursor::new(b"body".to_vec());
    let ino = xfs
        .add_file(&mut dev, root, "f", EntryMeta::default(), 4, &mut src)
        .unwrap();
    // Values big enough that the shortform area cannot hold them, forcing
    // the leaf-block path.
    let big = vec![b'x'; 200];
    xfs.add_xattr(&mut dev, ino, "user.u", &big).unwrap();
    xfs.add_xattr(&mut dev, ino, "trusted.t", &big).unwrap();
    xfs.add_xattr(&mut dev, ino, "security.s", &big).unwrap();
    xfs.flush_writes(&mut dev).unwrap();

    let off = xfs.ino_byte_offset(ino).unwrap();
    let mut buf = vec![0u8; xfs.inode_size() as usize];
    dev.read_at(off, &mut buf).unwrap();
    assert_eq!(buf[83], 2, "aformat should be EXTENTS (leaf spill)");

    let xfs = Xfs::open(&mut dev).unwrap();
    let attrs = xfs.read_xattrs(&mut dev, ino).unwrap();
    assert_eq!(attrs.get("user.u"), Some(&big));
    assert_eq!(attrs.get("trusted.t"), Some(&big));
    assert_eq!(attrs.get("security.s"), Some(&big));
}
