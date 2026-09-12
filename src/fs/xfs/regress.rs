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

// ---------------------------------------------------------------------
// Finding 24 — inode rebuilds must carry the attribute fork through.
// ---------------------------------------------------------------------

#[test]
fn file_xattr_survives_a_read_write_handle_writeback() {
    use crate::fs::OpenFlags;
    use std::io::{Seek as _, SeekFrom, Write as _};

    let (mut dev, mut xfs) = fresh(64 * 1024 * 1024);
    let root = xfs.superblock().rootino;
    let mut src = std::io::Cursor::new(vec![b'a'; 4096]);
    let ino = xfs
        .add_file(&mut dev, root, "f", EntryMeta::default(), 4096, &mut src)
        .unwrap();
    xfs.add_xattr(&mut dev, ino, "user.keep", b"me").unwrap();
    xfs.add_xattr(&mut dev, ino, "security.selinux", b"ctx")
        .unwrap();
    xfs.flush_writes(&mut dev).unwrap();

    // Write through the rw handle — this goes through `XfsFileHandle::persist`.
    let mut xfs = Xfs::open(&mut dev).unwrap();
    {
        let mut h = Filesystem::open_file_rw(
            &mut xfs,
            &mut dev,
            std::path::Path::new("/f"),
            OpenFlags::default(),
            None,
        )
        .unwrap();
        h.seek(SeekFrom::Start(0)).unwrap();
        h.write_all(b"ZZZZ").unwrap();
        h.sync().unwrap();
    }

    let xfs = Xfs::open(&mut dev).unwrap();
    let attrs = xfs.read_xattrs(&mut dev, ino).unwrap();
    assert_eq!(attrs.get("user.keep"), Some(&b"me".to_vec()));
    assert_eq!(attrs.get("security.selinux"), Some(&b"ctx".to_vec()));
}

#[test]
fn leaf_form_file_xattr_survives_writeback_with_aformat_intact() {
    use crate::fs::OpenFlags;
    use std::io::{Seek as _, SeekFrom, Write as _};

    let (mut dev, mut xfs) = fresh(64 * 1024 * 1024);
    let root = xfs.superblock().rootino;
    let mut src = std::io::Cursor::new(vec![b'a'; 4096]);
    let ino = xfs
        .add_file(&mut dev, root, "f", EntryMeta::default(), 4096, &mut src)
        .unwrap();
    let big = vec![b'v'; 300];
    xfs.add_xattr(&mut dev, ino, "user.big", &big).unwrap();
    xfs.flush_writes(&mut dev).unwrap();
    // Confirm we really are exercising the leaf (EXTENTS) attr fork.
    {
        let off = xfs.ino_byte_offset(ino).unwrap();
        let mut buf = vec![0u8; xfs.inode_size() as usize];
        dev.read_at(off, &mut buf).unwrap();
        assert_eq!(buf[83], 2, "aformat");
        assert_eq!(u16::from_be_bytes(buf[80..82].try_into().unwrap()), 1);
    }

    let mut xfs = Xfs::open(&mut dev).unwrap();
    {
        let mut h = Filesystem::open_file_rw(
            &mut xfs,
            &mut dev,
            std::path::Path::new("/f"),
            OpenFlags::default(),
            None,
        )
        .unwrap();
        h.seek(SeekFrom::Start(10)).unwrap();
        h.write_all(b"QQQQ").unwrap();
        h.sync().unwrap();
    }

    // aformat / anextents must still describe the leaf fork.
    let xfs = Xfs::open(&mut dev).unwrap();
    let off = xfs.ino_byte_offset(ino).unwrap();
    let mut buf = vec![0u8; xfs.inode_size() as usize];
    dev.read_at(off, &mut buf).unwrap();
    assert_eq!(buf[83], 2, "aformat clobbered to LOCAL");
    assert_eq!(
        u16::from_be_bytes(buf[80..82].try_into().unwrap()),
        1,
        "di_anextents zeroed"
    );
    let attrs = xfs.read_xattrs(&mut dev, ino).unwrap();
    assert_eq!(attrs.get("user.big"), Some(&big));
}

#[test]
fn directory_xattr_survives_entry_add_and_remove() {
    let (mut dev, mut xfs) = fresh(64 * 1024 * 1024);
    let root = xfs.superblock().rootino;
    let dir = xfs
        .add_dir(&mut dev, root, "d", EntryMeta::default())
        .unwrap();
    xfs.add_xattr(&mut dev, dir, "user.dirattr", b"yes")
        .unwrap();
    xfs.add_xattr(&mut dev, dir, "trusted.t", b"1").unwrap();
    xfs.flush_writes(&mut dev).unwrap();

    // Adding entries rewrites the directory inode via `rebuild_dir_inode`.
    for i in 0..8 {
        let mut src = std::io::Cursor::new(vec![b'x'; 8]);
        xfs.add_file(
            &mut dev,
            dir,
            &format!("child{i}"),
            EntryMeta::default(),
            8,
            &mut src,
        )
        .unwrap();
    }
    xfs.flush_writes(&mut dev).unwrap();
    {
        let attrs = xfs.read_xattrs(&mut dev, dir).unwrap();
        assert_eq!(attrs.get("user.dirattr"), Some(&b"yes".to_vec()));
        assert_eq!(attrs.get("trusted.t"), Some(&b"1".to_vec()));
    }

    // Removing an entry goes down the `remove()` parent-rewrite path.
    xfs.remove(&mut dev, dir, "child3").unwrap();
    xfs.flush_writes(&mut dev).unwrap();

    let xfs = Xfs::open(&mut dev).unwrap();
    let attrs = xfs.read_xattrs(&mut dev, dir).unwrap();
    assert_eq!(attrs.get("user.dirattr"), Some(&b"yes".to_vec()));
    assert_eq!(attrs.get("trusted.t"), Some(&b"1".to_vec()));
}

// ---------------------------------------------------------------------
// Finding 25 — `xfs_bmdr_block` pointer-array offset.
// ---------------------------------------------------------------------

#[test]
fn bmdr_root_pointers_sit_after_the_full_key_array() {
    use super::bmbt::{bmdr_ptrs_offset, decode_root};

    // XFS_BMDR_PTR_ADDR: ptrs start at sizeof(hdr) + maxrecs * sizeof(key),
    // with maxrecs = xfs_bmdr_maxrecs(dfork_size, 0) = (size - 4) / 16.
    for (size, want) in [(64usize, 28usize), (80, 36), (336, 164), (96, 44)] {
        assert_eq!(bmdr_ptrs_offset(size), want, "dfork_size {size}");
    }

    // A root with slack: 3 key/ptr slots' worth of room, 2 in use. The
    // pointers must be read from the reserved position, not from directly
    // after the two used keys and not from the tail of the fork.
    let mut root = vec![0u8; 64];
    root[0..2].copy_from_slice(&1u16.to_be_bytes()); // level
    root[2..4].copy_from_slice(&2u16.to_be_bytes()); // numrecs
    root[4..12].copy_from_slice(&0u64.to_be_bytes());
    root[12..20].copy_from_slice(&64u64.to_be_bytes());
    // Decoys at the two wrong places the old heuristic would have picked.
    root[20..28].copy_from_slice(&0xDEADu64.to_be_bytes()); // packed
    root[48..56].copy_from_slice(&0xBEEFu64.to_be_bytes()); // tail
    let pp = bmdr_ptrs_offset(64);
    root[pp..pp + 8].copy_from_slice(&111u64.to_be_bytes());
    root[pp + 8..pp + 16].copy_from_slice(&222u64.to_be_bytes());

    let (level, numrecs, keys, ptrs) = decode_root(&root).unwrap();
    assert_eq!((level, numrecs), (1, 2));
    assert_eq!(keys, vec![0, 64]);
    assert_eq!(ptrs, vec![111, 222]);
}

#[test]
fn bmdr_root_rejects_more_records_than_the_fork_can_hold() {
    use super::bmbt::decode_root;
    // maxrecs for a 64-byte fork is 3; claim 4.
    let mut root = vec![0u8; 64];
    root[0..2].copy_from_slice(&1u16.to_be_bytes());
    root[2..4].copy_from_slice(&4u16.to_be_bytes());
    assert!(matches!(
        decode_root(&root),
        Err(crate::Error::InvalidImage(_))
    ));
}

// ---------------------------------------------------------------------
// Finding 28 — `Extent::encode` must not truncate to the 21-bit field.
// ---------------------------------------------------------------------

#[test]
fn extent_encode_rejects_out_of_range_fields() {
    use super::bmbt::{Extent, MAX_EXTENT_BLOCKS};

    assert_eq!(MAX_EXTENT_BLOCKS, (1 << 21) - 1);
    let ok = Extent {
        offset: 0,
        startblock: 1,
        blockcount: MAX_EXTENT_BLOCKS,
        unwritten: false,
    };
    assert_eq!(Extent::decode(&ok.encode().unwrap()).unwrap(), ok);

    // One block past the field width used to wrap around to 0 — which
    // `decode` then rejected as blockcount=0, or worse, silently described
    // a different range than was allocated.
    let too_many = Extent {
        blockcount: MAX_EXTENT_BLOCKS + 1,
        ..ok
    };
    assert!(matches!(
        too_many.encode(),
        Err(crate::Error::InvalidArgument(_))
    ));
    let wrapped = Extent {
        blockcount: MAX_EXTENT_BLOCKS + 2,
        ..ok
    };
    assert!(wrapped.encode().is_err());

    assert!(
        Extent {
            offset: 1 << 54,
            ..ok
        }
        .encode()
        .is_err()
    );
    assert!(
        Extent {
            startblock: 1 << 52,
            ..ok
        }
        .encode()
        .is_err()
    );
    assert!(
        Extent {
            blockcount: 0,
            ..ok
        }
        .encode()
        .is_err()
    );
}

// ---------------------------------------------------------------------
// Finding 27 — a file that does not fit one contiguous run must be
// written as several extents instead of failing "out of space".
// ---------------------------------------------------------------------

/// How many extents inode `ino` records in its data fork.
fn nextents_of(xfs: &Xfs, dev: &mut MemoryBackend, ino: u64) -> u32 {
    let off = xfs.ino_byte_offset(ino).unwrap();
    let mut buf = vec![0u8; xfs.inode_size() as usize];
    dev.read_at(off, &mut buf).unwrap();
    u32::from_be_bytes(buf[76..80].try_into().unwrap())
}

/// Chop the free pool of a small single-AG image into equal-sized islands:
/// fill it with `chunk`-byte files until the allocator runs dry, then delete
/// every other one. Returns the island size in bytes.
fn fragment_free_space(dev: &mut MemoryBackend, xfs: &mut Xfs, chunk: u64) -> u64 {
    let root = xfs.superblock().rootino;
    let mut names = Vec::new();
    for i in 0.. {
        let name = format!("fill{i}");
        let mut src = std::io::Cursor::new(vec![b'0' + (i as u8 % 10); chunk as usize]);
        match xfs.add_file(
            &mut *dev,
            root,
            &name,
            EntryMeta::default(),
            chunk,
            &mut src,
        ) {
            Ok(_) => names.push(name),
            Err(_) => break,
        }
    }
    assert!(names.len() > 8, "test image too small to fragment");
    xfs.flush_writes(dev).unwrap();
    for name in names.iter().step_by(2) {
        xfs.remove(&mut *dev, root, name).unwrap();
    }
    xfs.flush_writes(dev).unwrap();
    chunk
}

#[test]
fn file_larger_than_the_longest_free_run_spans_several_extents() {
    // Small single-AG image: 16 MiB / 4 KiB blocks.
    let (mut dev, mut xfs) = fresh(16 * 1024 * 1024);
    let chunk = 256 * 1024u64; // 64 blocks per island
    let island = fragment_free_space(&mut dev, &mut xfs, chunk);

    // Ask for three islands' worth. No single free run is that long, so
    // the old single-extent allocator returned "out of space".
    let want = island * 3;
    let body: Vec<u8> = (0..want).map(|i| (i % 251) as u8).collect();
    let root = xfs.superblock().rootino;
    let mut src = std::io::Cursor::new(body.clone());
    let ino = xfs
        .add_file(&mut dev, root, "big", EntryMeta::default(), want, &mut src)
        .unwrap();
    xfs.flush_writes(&mut dev).unwrap();
    assert!(
        nextents_of(&xfs, &mut dev, ino) > 1,
        "expected the multi-extent path to be exercised"
    );

    // And it must read back byte for byte.
    let xfs = Xfs::open(&mut dev).unwrap();
    let mut out = Vec::new();
    {
        let mut r = xfs.open_file_reader(&mut dev, "/big").unwrap();
        std::io::Read::read_to_end(&mut r, &mut out).unwrap();
    }
    assert_eq!(out.len(), body.len());
    assert!(out == body, "multi-extent file did not round-trip");
}

/// `sb_fdblocks` as last stamped by `flush_writes`.
fn free_blocks(dev: &mut MemoryBackend) -> u64 {
    let mut sb = [0u8; 512];
    dev.read_at(0, &mut sb).unwrap();
    u64::from_be_bytes(sb[144..152].try_into().unwrap())
}

#[test]
fn file_too_fragmented_for_the_inline_fork_reports_the_limit() {
    let (mut dev, mut xfs) = fresh(16 * 1024 * 1024);
    let bs = xfs.block_size() as u64;
    let root = xfs.superblock().rootino;
    let islands = super::rw::MAX_INLINE_EXTENTS + 5;

    // Lay down `islands * 2` small files so that deleting every other one
    // leaves that many 8-block holes, then hog whatever tail is left so no
    // long run remains.
    let small = 8 * bs;
    let mut names = Vec::new();
    for i in 0..islands * 2 {
        let name = format!("s{i}");
        let mut src = std::io::Cursor::new(vec![b'a'; small as usize]);
        xfs.add_file(&mut dev, root, &name, EntryMeta::default(), small, &mut src)
            .unwrap();
        names.push(name);
    }
    xfs.flush_writes(&mut dev).unwrap();
    let mut hog = free_blocks(&mut dev);
    loop {
        assert!(hog > 0, "could not hog the AG tail");
        let bytes = hog * bs;
        let mut src = std::io::Cursor::new(vec![b'h'; bytes as usize]);
        if xfs
            .add_file(&mut dev, root, "hog", EntryMeta::default(), bytes, &mut src)
            .is_ok()
        {
            break;
        }
        hog = hog * 9 / 10;
    }
    xfs.flush_writes(&mut dev).unwrap();
    for name in names.iter().step_by(2) {
        xfs.remove(&mut dev, root, name).unwrap();
    }
    xfs.flush_writes(&mut dev).unwrap();

    // Now ask for more islands than the inline data fork can describe.
    let want = 8 * bs * (islands as u64 - 1);
    let mut src = std::io::Cursor::new(vec![b'z'; want as usize]);
    let err = xfs
        .add_file(
            &mut dev,
            root,
            "toobig",
            EntryMeta::default(),
            want,
            &mut src,
        )
        .unwrap_err();
    match &err {
        crate::Error::Unsupported(m) => assert!(
            m.contains(&super::rw::MAX_INLINE_EXTENTS.to_string()),
            "error should name the extent limit, got: {m}"
        ),
        other => panic!("expected Unsupported naming the extent limit, got {other:?}"),
    }
    // The rolled-back allocation must not have leaked: the same request
    // fails the same way rather than progressively shrinking the pool.
    let mut src = std::io::Cursor::new(vec![b'z'; want as usize]);
    assert!(matches!(
        xfs.add_file(
            &mut dev,
            root,
            "toobig2",
            EntryMeta::default(),
            want,
            &mut src
        ),
        Err(crate::Error::Unsupported(_))
    ));
}
