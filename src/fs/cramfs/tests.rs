use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use super::*;
use crate::block::MemoryBackend;
use crate::fs::{DeviceKind, FileMeta, FileSource, Filesystem};

fn meta(mode: u16, uid: u32, gid: u32) -> FileMeta {
    FileMeta {
        mode,
        uid,
        gid,
        ..FileMeta::default()
    }
}

fn src(bytes: &[u8]) -> FileSource {
    FileSource::Reader {
        reader: Box::new(std::io::Cursor::new(bytes.to_vec())),
        len: bytes.len() as u64,
    }
}

/// Deterministic, poorly compressible bytes.
fn noise(len: usize, seed: u32) -> Vec<u8> {
    let mut x = seed.wrapping_mul(2_654_435_761).max(1);
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

struct Fixture {
    dev: MemoryBackend,
    multi: Vec<u8>,
    holey: Vec<u8>,
    exact: Vec<u8>,
}

fn build(opts: &FormatOpts) -> Fixture {
    let mut dev = MemoryBackend::new(8 * 1024 * 1024);
    let mut fs = Cramfs::format(&mut dev, opts).unwrap();
    let multi = noise(3 * 4096 + 123, 1);
    let mut holey = noise(4096, 2);
    holey.extend(std::iter::repeat_n(0u8, 8192));
    holey.extend(noise(100, 3));
    let exact = noise(2 * 4096, 4);
    fs.create_dir(&mut dev, Path::new("/etc"), meta(0o750, 1000, 100))
        .unwrap();
    fs.create_file(
        &mut dev,
        Path::new("/etc/hostname"),
        src(b"router\n"),
        meta(0o644, 0, 0),
    )
    .unwrap();
    fs.create_file(
        &mut dev,
        Path::new("/bin/busybox"),
        src(&multi),
        meta(0o4755, 0, 0),
    )
    .unwrap();
    fs.create_file(
        &mut dev,
        Path::new("/holey"),
        src(&holey),
        meta(0o600, 70000, 300),
    )
    .unwrap();
    fs.create_file(
        &mut dev,
        Path::new("/exact"),
        src(&exact),
        meta(0o644, 0, 0),
    )
    .unwrap();
    fs.create_file(&mut dev, Path::new("/empty"), src(b""), meta(0o644, 0, 0))
        .unwrap();
    fs.create_symlink(
        &mut dev,
        Path::new("/bin/sh"),
        Path::new("busybox"),
        meta(0o777, 0, 0),
    )
    .unwrap();
    fs.create_device(
        &mut dev,
        Path::new("/dev/ttyS0"),
        DeviceKind::Char,
        4,
        64,
        meta(0o660, 0, 5),
    )
    .unwrap();
    fs.create_device(
        &mut dev,
        Path::new("/dev/mtdblock0"),
        DeviceKind::Block,
        31,
        0,
        meta(0o640, 0, 6),
    )
    .unwrap();
    fs.create_device(
        &mut dev,
        Path::new("/dev/initctl"),
        DeviceKind::Fifo,
        0,
        0,
        meta(0o600, 0, 0),
    )
    .unwrap();
    fs.create_dir(&mut dev, Path::new("/mnt"), meta(0o755, 0, 0))
        .unwrap();
    fs.hardlink(&mut dev, Path::new("/bin/busybox"), Path::new("/bin/ls"))
        .unwrap();
    fs.flush(&mut dev).unwrap();
    Fixture {
        dev,
        multi,
        holey,
        exact,
    }
}

fn read_all(fs: &mut Cramfs, dev: &mut MemoryBackend, path: &str) -> Vec<u8> {
    let mut out = Vec::new();
    fs.read_file(dev, Path::new(path))
        .unwrap()
        .read_to_end(&mut out)
        .unwrap();
    out
}

fn names(fs: &mut Cramfs, dev: &mut MemoryBackend, path: &str) -> Vec<String> {
    fs.list(dev, Path::new(path))
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect()
}

fn check_tree(fs: &mut Cramfs, dev: &mut MemoryBackend, fx: &Fixture) {
    assert_eq!(
        names(fs, dev, "/"),
        ["bin", "dev", "empty", "etc", "exact", "holey", "mnt"]
    );
    assert_eq!(names(fs, dev, "/bin"), ["busybox", "ls", "sh"]);
    assert!(names(fs, dev, "/mnt").is_empty());
    assert_eq!(read_all(fs, dev, "/etc/hostname"), b"router\n");
    assert_eq!(read_all(fs, dev, "/bin/busybox"), fx.multi);
    assert_eq!(read_all(fs, dev, "/bin/ls"), fx.multi);
    assert_eq!(read_all(fs, dev, "/holey"), fx.holey);
    assert_eq!(read_all(fs, dev, "/exact"), fx.exact);
    assert!(read_all(fs, dev, "/empty").is_empty());
    assert_eq!(Cramfs::read_symlink(fs, dev, "/bin/sh").unwrap(), "busybox");

    let a = fs.getattr(dev, Path::new("/etc")).unwrap();
    assert_eq!(
        (a.kind, a.mode, a.uid, a.gid),
        (EntryKind::Dir, 0o750, 1000, 100)
    );
    let a = fs.getattr(dev, Path::new("/bin/busybox")).unwrap();
    assert_eq!((a.mode, a.size), (0o4755, fx.multi.len() as u64));
    // Hard links share the data, so the inode number too.
    let b = fs.getattr(dev, Path::new("/bin/ls")).unwrap();
    assert_eq!(a.inode, b.inode);
    // uid is 16 bits and gid 8 on disk.
    let a = fs.getattr(dev, Path::new("/holey")).unwrap();
    assert_eq!((a.uid, a.gid), (70000 & 0xFFFF, 300 & 0xFF));
    let a = fs.getattr(dev, Path::new("/dev/ttyS0")).unwrap();
    assert_eq!(
        (a.kind, a.rdev, a.size, a.gid),
        (EntryKind::Char, 4 << 8 | 64, 0, 5)
    );
    let a = fs.getattr(dev, Path::new("/dev/mtdblock0")).unwrap();
    assert_eq!((a.kind, a.rdev), (EntryKind::Block, 31 << 8));
    let a = fs.getattr(dev, Path::new("/dev/initctl")).unwrap();
    assert_eq!(a.kind, EntryKind::Fifo);

    // Every inode number is distinct apart from the hard link.
    let mut seen = std::collections::HashMap::new();
    for p in [
        "/",
        "/bin",
        "/dev",
        "/empty",
        "/etc",
        "/exact",
        "/holey",
        "/mnt",
        "/etc/hostname",
        "/bin/busybox",
        "/bin/sh",
        "/dev/ttyS0",
        "/dev/mtdblock0",
        "/dev/initctl",
    ] {
        let ino = fs.getattr(dev, Path::new(p)).unwrap().inode;
        assert!(
            seen.insert(ino, p).is_none(),
            "{p} shares inode with {:?}",
            seen[&ino]
        );
    }
}

#[test]
fn round_trip() {
    let mut fx = build(&FormatOpts::default());
    let mut dev = MemoryBackend::from_bytes(fx.dev.as_slice().to_vec());
    let mut fs = Cramfs::open(&mut dev).unwrap();
    assert_eq!(fs.block_size(), 4096);
    assert!(!fs.big_endian());
    assert_eq!(fs.volume_name(), "Compressed");
    assert_eq!(fs.file_count(), 15);
    assert_eq!(fs.total_bytes() % 4096, 0);
    assert_eq!(fs.image_len(), Some(fs.total_bytes()));
    // Holes are written, but without FLAG_HOLES (fsck.cramfs rejects it).
    assert_eq!(
        fs.superblock().flags,
        FLAG_FSID_VERSION_2 | FLAG_SORTED_DIRS
    );
    check_tree(&mut fs, &mut dev, &fx);
    let _ = &mut fx.dev;
}

#[test]
fn crc_matches_mkfs_definition() {
    let fx = build(&FormatOpts::default());
    let mut dev = MemoryBackend::from_bytes(fx.dev.as_slice().to_vec());
    let fs = Cramfs::open(&mut dev).unwrap();
    let mut img = fx.dev.as_slice()[..fs.total_bytes() as usize].to_vec();
    let stored = u32::from_le_bytes(img[32..36].try_into().unwrap());
    img[32..36].fill(0);
    assert_eq!(crate::crc::crc32(&img), stored);
}

#[test]
fn directory_data_precedes_file_data() {
    // fsck.cramfs insists the directory area ends where file data begins.
    let fx = build(&FormatOpts::default());
    let img = fx.dev.as_slice();
    let root = RawInode::decode(&img[64..76], Endian::Little);
    assert_eq!(root.data_offset(), SUPER_SIZE);
    let mut dirs_end = 0u64;
    let mut data_start = u64::MAX;
    let mut queue = vec![root];
    while let Some(d) = queue.pop() {
        let (start, len) = (d.data_offset(), u64::from(d.size));
        dirs_end = dirs_end.max(start + len);
        let mut at = start;
        while at < start + len {
            let i = RawInode::decode(&img[at as usize..at as usize + 12], Endian::Little);
            match i.kind() {
                EntryKind::Dir if i.size > 0 => queue.push(i),
                EntryKind::Regular | EntryKind::Symlink if i.size > 0 => {
                    data_start = data_start.min(i.data_offset());
                }
                _ => assert_eq!(i.offset, 0, "special/empty inode with data"),
            }
            at += 12 + u64::from(i.namelen) * 4;
        }
    }
    assert_eq!(dirs_end, data_start);
}

#[test]
fn random_access_reads() {
    let fx = build(&FormatOpts::default());
    let mut dev = MemoryBackend::from_bytes(fx.dev.as_slice().to_vec());
    let mut fs = Cramfs::open(&mut dev).unwrap();
    let mut h = fs
        .open_file_ro(&mut dev, Path::new("/bin/busybox"))
        .unwrap();
    assert_eq!(h.len(), fx.multi.len() as u64);
    let mut buf = [0u8; 300];
    h.seek(SeekFrom::Start(4000)).unwrap();
    h.read_exact(&mut buf).unwrap();
    assert_eq!(&buf[..], &fx.multi[4000..4300]);
    h.seek(SeekFrom::End(-50)).unwrap();
    let mut tail = Vec::new();
    h.read_to_end(&mut tail).unwrap();
    assert_eq!(tail, fx.multi[fx.multi.len() - 50..]);
}

#[test]
fn larger_block_size_is_detected() {
    let opts = FormatOpts {
        block_size: 16384,
        ..FormatOpts::default()
    };
    let fx = build(&opts);
    let mut dev = MemoryBackend::from_bytes(fx.dev.as_slice().to_vec());
    let mut fs = Cramfs::open(&mut dev).unwrap();
    assert_eq!(fs.block_size(), 16384);
    check_tree(&mut fs, &mut dev, &fx);
}

/// Rewrite a little-endian image as the big-endian one a big-endian host
/// would have built: every word swapped, inode bitfields repacked.
fn to_big_endian(img: &[u8]) -> Vec<u8> {
    fn be_inode(i: &RawInode) -> [u8; 12] {
        let w0 = (u32::from(i.mode) << 16) | u32::from(i.uid);
        let w1 = (i.size << 8) | u32::from(i.gid);
        let w2 = (u32::from(i.namelen) << 26) | i.offset;
        let mut o = [0u8; 12];
        o[0..4].copy_from_slice(&w0.to_be_bytes());
        o[4..8].copy_from_slice(&w1.to_be_bytes());
        o[8..12].copy_from_slice(&w2.to_be_bytes());
        o
    }
    let mut out = img.to_vec();
    // magic, size, flags, future, then the fsid; the signature and the
    // name are byte strings.
    for w in [0, 1, 2, 3, 8, 9, 10, 11] {
        let r = w * 4..w * 4 + 4;
        let v = u32::from_le_bytes(img[r.clone()].try_into().unwrap());
        out[r].copy_from_slice(&v.to_be_bytes());
    }
    let root = RawInode::decode(&img[64..76], Endian::Little);
    out[64..76].copy_from_slice(&be_inode(&root));
    let mut queue = vec![root];
    while let Some(d) = queue.pop() {
        let (start, len) = (d.data_offset() as usize, d.size as usize);
        let mut at = start;
        while at < start + len {
            let i = RawInode::decode(&img[at..at + 12], Endian::Little);
            out[at..at + 12].copy_from_slice(&be_inode(&i));
            match i.kind() {
                EntryKind::Dir => queue.push(i),
                EntryKind::Regular | EntryKind::Symlink if i.size > 0 => {
                    let t = i.data_offset() as usize;
                    for b in 0..(i.size as usize).div_ceil(4096) {
                        let r = t + b * 4..t + b * 4 + 4;
                        let v = u32::from_le_bytes(img[r.clone()].try_into().unwrap());
                        out[r].copy_from_slice(&v.to_be_bytes());
                    }
                }
                _ => {}
            }
            at += 12 + usize::from(i.namelen) * 4;
        }
    }
    out
}

#[test]
fn big_endian_image_reads() {
    let fx = build(&FormatOpts::default());
    let mut dev = MemoryBackend::from_bytes(to_big_endian(fx.dev.as_slice()));
    assert!(probe(&mut dev).unwrap());
    let mut fs = Cramfs::open(&mut dev).unwrap();
    assert!(fs.big_endian());
    check_tree(&mut fs, &mut dev, &fx);
}

#[test]
fn padded_superblock_at_512_is_found() {
    // An image whose superblock sits at 512: probe and open find it there.
    let fx = build(&FormatOpts::default());
    let mut img = vec![0u8; 512];
    img.extend_from_slice(&fx.dev.as_slice()[..SUPER_SIZE as usize]);
    // The root is empty so no offsets need shifting.
    img[512 + 64 + 4..512 + 64 + 12].fill(0);
    let w0 = u32::from_le_bytes(img[512 + 64..512 + 68].try_into().unwrap());
    assert_eq!(w0 & 0o170000, 0o040000);
    img[512 + 4..512 + 8].copy_from_slice(&0u32.to_le_bytes());
    img[512 + 8..512 + 12].copy_from_slice(&FLAG_SORTED_DIRS.to_le_bytes());
    let mut dev = MemoryBackend::from_bytes(img);
    assert!(probe(&mut dev).unwrap());
    let mut fs = Cramfs::open(&mut dev).unwrap();
    assert!(fs.list(&mut dev, Path::new("/")).unwrap().is_empty());
}

#[test]
fn format_limits_are_enforced() {
    let mut dev = MemoryBackend::new(64 * 1024 * 1024);
    let mut fs = Cramfs::format(&mut dev, &FormatOpts::default()).unwrap();
    let big = FileSource::Zero(MAX_FILE_SIZE + 1);
    assert!(
        fs.create_file(&mut dev, Path::new("/big"), big, FileMeta::default())
            .is_err()
    );
    assert!(
        fs.create_device(
            &mut dev,
            Path::new("/d"),
            DeviceKind::Char,
            256,
            0,
            FileMeta::default()
        )
        .is_err()
    );
    let long = "x".repeat(MAX_NAME_LEN + 1);
    assert!(
        fs.create_dir(
            &mut dev,
            Path::new(&format!("/{long}")),
            FileMeta::default()
        )
        .is_err()
    );
    let ok = "y".repeat(MAX_NAME_LEN);
    fs.create_dir(&mut dev, Path::new(&format!("/{ok}")), FileMeta::default())
        .unwrap();
    fs.create_file(&mut dev, Path::new("/a"), src(b"1"), FileMeta::default())
        .unwrap();
    assert!(
        fs.create_file(&mut dev, Path::new("/a"), src(b"2"), FileMeta::default())
            .is_err()
    );
    assert!(fs.remove(&mut dev, Path::new("/a")).is_err());
    fs.flush(&mut dev).unwrap();
    assert_eq!(names(&mut fs, &mut dev, "/"), ["a".to_string(), ok]);
    // Read-only once built.
    assert!(
        fs.create_dir(&mut dev, Path::new("/z"), FileMeta::default())
            .is_err()
    );
}

#[test]
fn empty_image() {
    let mut dev = MemoryBackend::new(1024 * 1024);
    let mut fs = Cramfs::format(&mut dev, &FormatOpts::default()).unwrap();
    fs.flush(&mut dev).unwrap();
    assert!(fs.list(&mut dev, Path::new("/")).unwrap().is_empty());
    assert_eq!(fs.total_bytes(), 4096);
}

#[test]
fn corrupt_images_error_cleanly() {
    let fx = build(&FormatOpts::default());
    let good = fx.dev.as_slice()[..Cramfs::open(&mut MemoryBackend::from_bytes(
        fx.dev.as_slice().to_vec(),
    ))
    .unwrap()
    .total_bytes() as usize]
        .to_vec();
    // Flip bytes across the image; nothing may panic.
    for step in [7usize, 13, 101] {
        let mut img = good.clone();
        for i in (0..img.len()).step_by(step) {
            img[i] ^= 0x5A;
        }
        let mut dev = MemoryBackend::from_bytes(img);
        if let Ok(mut fs) = Cramfs::open(&mut dev) {
            let _ = crate::fs::Filesystem::list(&mut fs, &mut dev, Path::new("/"));
            for p in ["/bin/busybox", "/holey", "/etc/hostname"] {
                if let Ok(mut r) = fs.read_file(&mut dev, Path::new(p)) {
                    let mut v = Vec::new();
                    let _ = r.read_to_end(&mut v);
                }
            }
        }
    }
}
