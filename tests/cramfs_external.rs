#![cfg(all(unix, feature = "cramfs"))]
//! cramfs end-to-end validation against util-linux's `mkfs.cramfs` and
//! `fsck.cramfs`.
//!
//! 1. fstool writer → `fsck.cramfs` (CRC + structure check), then
//!    `fsck.cramfs -x` extraction compared byte for byte.
//! 2. `mkfs.cramfs` → fstool reader, in both byte orders and at a larger
//!    block size, compared against the source tree.
//!
//! Each test returns early with `skipping: …` when the tool is missing, so
//! the suite stays green where util-linux lacks the cramfs tools (macOS).

use std::fs;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use fstool::block::{BlockDevice, FileBackend};
use fstool::fs::cramfs::{Cramfs, FormatOpts};
use fstool::fs::{DeviceKind, EntryKind, FileMeta, FileSource, Filesystem};

fn find_tool(name: &str) -> Option<PathBuf> {
    // The cramfs tools live in /sbin, which isn't always on a user's PATH.
    let out = Command::new("sh")
        .arg("-c")
        .arg(format!("PATH=$PATH:/sbin:/usr/sbin command -v {name}"))
        .output()
        .ok()?;
    let s = String::from_utf8(out.stdout).ok()?;
    let p = s.trim();
    (out.status.success() && !p.is_empty()).then(|| p.into())
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

/// The files every test uses: (path, contents).
fn fixture_files() -> Vec<(&'static str, Vec<u8>)> {
    let mut holey = noise(4096, 9);
    holey.extend(std::iter::repeat_n(0u8, 3 * 4096));
    holey.extend(b"tail");
    vec![
        ("etc/hostname", b"router\n".to_vec()),
        ("etc/empty", Vec::new()),
        ("bin/busybox", noise(5 * 4096 + 77, 1)),
        ("lib/exact", noise(16384, 2)),
        ("lib/text", b"cramfs ".repeat(20_000)),
        ("holey", holey),
        ("deep/a/b/c/d", b"deep".to_vec()),
    ]
}

fn build_with_fstool(img: &Path, devices: bool) -> u64 {
    let mut dev = FileBackend::create(img, 32 * 1024 * 1024).unwrap();
    let mut fs = Cramfs::format(&mut dev, &FormatOpts::default()).unwrap();
    let m = |mode| FileMeta {
        mode,
        uid: 0,
        gid: 0,
        ..FileMeta::default()
    };
    for (p, data) in fixture_files() {
        let src = FileSource::Reader {
            reader: Box::new(std::io::Cursor::new(data.clone())),
            len: data.len() as u64,
        };
        fs.create_file(&mut dev, Path::new(&format!("/{p}")), src, m(0o644))
            .unwrap();
    }
    fs.create_dir(&mut dev, Path::new("/mnt"), m(0o755))
        .unwrap();
    fs.create_symlink(
        &mut dev,
        Path::new("/bin/sh"),
        Path::new("busybox"),
        m(0o777),
    )
    .unwrap();
    fs.hardlink(&mut dev, Path::new("/bin/busybox"), Path::new("/bin/ls"))
        .unwrap();
    if devices {
        fs.create_device(
            &mut dev,
            Path::new("/dev/console"),
            DeviceKind::Char,
            5,
            1,
            m(0o600),
        )
        .unwrap();
        fs.create_device(
            &mut dev,
            Path::new("/dev/sda"),
            DeviceKind::Block,
            8,
            0,
            m(0o660),
        )
        .unwrap();
        fs.create_device(
            &mut dev,
            Path::new("/dev/fifo"),
            DeviceKind::Fifo,
            0,
            0,
            m(0o600),
        )
        .unwrap();
    }
    fs.flush(&mut dev).unwrap();
    let len = fs.image_len().unwrap();
    dev.sync().unwrap();
    drop(dev);
    fs::OpenOptions::new()
        .write(true)
        .open(img)
        .unwrap()
        .set_len(len)
        .unwrap();
    len
}

fn run(cmd: &mut Command) -> String {
    let out = cmd.output().unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success(), "{cmd:?} failed:\n{text}");
    text
}

#[test]
fn fstool_image_passes_fsck_cramfs() {
    let Some(fsck) = find_tool("fsck.cramfs") else {
        eprintln!("skipping: fsck.cramfs not installed");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("dev.cramfs");
    build_with_fstool(&img, true);
    // Without -x, fsck still walks every inode and inflates every block.
    let out = run(Command::new(&fsck)
        .arg("-v")
        .arg("-b")
        .arg("4096")
        .arg(&img));
    eprintln!("{out}");
}

#[test]
fn fstool_image_extracts_with_fsck_cramfs() {
    let Some(fsck) = find_tool("fsck.cramfs") else {
        eprintln!("skipping: fsck.cramfs not installed");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("tree.cramfs");
    // No device nodes: extracting them needs root.
    build_with_fstool(&img, false);
    let out = tmp.path().join("out");
    run(Command::new(&fsck)
        .arg("-b")
        .arg("4096")
        .arg("-x")
        .arg(&out)
        .arg(&img));
    for (p, data) in fixture_files() {
        assert_eq!(fs::read(out.join(p)).unwrap(), data, "{p}");
    }
    assert_eq!(
        fs::read_link(out.join("bin/sh")).unwrap(),
        Path::new("busybox")
    );
    assert_eq!(fs::read(out.join("bin/ls")).unwrap(), fixture_files()[2].1);
    assert!(out.join("mnt").is_dir());
}

/// Lay the fixture out on the host for mkfs.cramfs.
fn host_tree(root: &Path) {
    for (p, data) in fixture_files() {
        let path = root.join(p);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, data).unwrap();
    }
    fs::set_permissions(root.join("bin/busybox"), fs::Permissions::from_mode(0o755)).unwrap();
    fs::create_dir(root.join("mnt")).unwrap();
    std::os::unix::fs::symlink("busybox", root.join("bin/sh")).unwrap();
    fs::hard_link(root.join("bin/busybox"), root.join("bin/ls")).unwrap();
}

fn read_back(img: &Path, src: &Path, expect_bs: u32, big_endian: bool) {
    let mut dev = FileBackend::open(img).unwrap();
    let kind = fstool::inspect::detect_fs(&mut dev).unwrap();
    assert_eq!(kind, fstool::inspect::FsKind::Cramfs);
    let mut fs = Cramfs::open(&mut dev).unwrap();
    assert_eq!(fs.block_size(), expect_bs);
    assert_eq!(fs.big_endian(), big_endian);
    for (p, data) in fixture_files() {
        let mut got = Vec::new();
        fs.read_file(&mut dev, Path::new(&format!("/{p}")))
            .unwrap()
            .read_to_end(&mut got)
            .unwrap();
        assert_eq!(got, data, "{p}");
        let a = fs.getattr(&mut dev, Path::new(&format!("/{p}"))).unwrap();
        let host = fs::metadata(src.join(p)).unwrap();
        assert_eq!(u32::from(a.mode), host.mode() & 0o7777, "{p} mode");
        assert_eq!(a.uid, host.uid() & 0xFFFF, "{p} uid");
        assert_eq!(a.gid, host.gid() & 0xFF, "{p} gid");
    }
    assert_eq!(
        Cramfs::read_symlink(&fs, &mut dev, "/bin/sh").unwrap(),
        "busybox"
    );
    let a = fs.getattr(&mut dev, Path::new("/bin/busybox")).unwrap();
    let b = fs.getattr(&mut dev, Path::new("/bin/ls")).unwrap();
    assert_eq!(a.inode, b.inode, "hard links share data");
    let root: Vec<_> = fs
        .list(&mut dev, Path::new("/"))
        .unwrap()
        .into_iter()
        .map(|e| (e.name, e.kind))
        .collect();
    assert!(root.contains(&("mnt".into(), EntryKind::Dir)));
    assert!(root.contains(&("holey".into(), EntryKind::Regular)));
}

fn mkfs_case(extra: &[&str], expect_bs: u32, big_endian: bool) {
    let Some(mkfs) = find_tool("mkfs.cramfs") else {
        eprintln!("skipping: mkfs.cramfs not installed");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    host_tree(&src);
    let img = tmp.path().join("ref.cramfs");
    run(Command::new(&mkfs).args(extra).arg(&src).arg(&img));
    read_back(&img, &src, expect_bs, big_endian);
}

#[test]
fn mkfs_cramfs_little_endian_reads() {
    mkfs_case(&["-b", "4096", "-N", "little"], 4096, false);
}

#[test]
fn mkfs_cramfs_big_endian_reads() {
    mkfs_case(&["-b", "4096", "-N", "big"], 4096, true);
}

#[test]
fn mkfs_cramfs_16k_blocks_read() {
    mkfs_case(&["-b", "16384", "-N", "little"], 16384, false);
}

#[test]
fn mkfs_cramfs_explicit_holes_read() {
    // -z stores all-zero blocks as holes.
    mkfs_case(&["-b", "4096", "-z"], 4096, false);
}

#[test]
fn mkfs_cramfs_padded_image_reads() {
    // -p leaves 512 bytes in front of the superblock for a boot sector.
    mkfs_case(&["-b", "4096", "-p"], 4096, false);
}
