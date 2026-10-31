#![cfg(all(unix, feature = "udf"))]
// Some helpers and imports serve only the macOS (hdiutil) tests.
#![cfg_attr(not(target_os = "macos"), allow(dead_code, unused_imports))]
//! Native validation of the UDF backend against independent
//! implementations.
//!
//! macOS: images fstool writes (every advertised revision) pass
//! `fsck_udf` and mount through the kernel's UDF driver with every name,
//! size, byte, link, symlink and — on a read-write mount — permission and
//! owner intact; labels show in `diskutil info`; files beyond 4 GiB read
//! back (both as holes and as recorded multi-extent payload placed through
//! the layout API); images made by `newfs_udf` (each revision, populated
//! through a mount) and by `hdiutil makehybrid -udf` read correctly in
//! fstool; `fstool repack … -t udf` produces a clean volume.
//!
//! Linux (CI): images made by `mkudffs` for each `--udfrev` and media type
//! (including write-once VAT and sparable layouts) read in fstool;
//! fstool's images satisfy `udfinfo`; and, where passwordless sudo is
//! available, they mount with `mount -t udf` and read back.
//!
//! Every test skips, with a message, when a tool it needs is missing.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use fstool::block::{BlockDevice, FileBackend, MemoryBackend};
use fstool::fs::udf::{AccessType, FormatOpts, Udf, UdfRevision};
use fstool::fs::{DeviceKind, EntryKind, FileMeta, FileSource, Filesystem};

fn which(tool: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {tool}"))
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn have(tools: &[&str]) -> bool {
    let missing: Vec<&str> = tools.iter().copied().filter(|t| !which(t)).collect();
    if !missing.is_empty() {
        eprintln!("skipping: {missing:?} not available");
    }
    missing.is_empty()
}

const MTIME: u32 = 1_700_000_000;

/// `FormatOpts` is `#[non_exhaustive]`: start from the default, adjust.
fn fopts(f: impl FnOnce(&mut FormatOpts)) -> FormatOpts {
    let mut o = FormatOpts::default();
    f(&mut o);
    o
}

fn meta(mode: u16) -> FileMeta {
    let mut m = FileMeta::with_mode(mode);
    m.uid = 501;
    m.gid = 20;
    m.mtime = MTIME;
    m.atime = MTIME;
    m.ctime = MTIME;
    m
}

fn pattern(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(13).wrapping_add(seed))
        .collect()
}

/// What the sample tree holds, for checking a mount or a re-open.
struct Sample {
    files: Vec<(&'static str, Vec<u8>, u16)>,
    dirs: Vec<(&'static str, u16)>,
    symlinks: Vec<(&'static str, &'static str)>,
    /// `(link, target)` hard-link pairs.
    hardlinks: Vec<(&'static str, &'static str)>,
}

fn sample() -> Sample {
    Sample {
        files: vec![
            ("/readme.txt", b"hello from fstool\n".to_vec(), 0o644),
            ("/empty", Vec::new(), 0o600),
            ("/docs/big.bin", pattern(1_500_000, 3), 0o640),
            ("/docs/café.txt", b"latin-1 name\n".to_vec(), 0o644),
            (
                "/docs/日本語のファイル.txt",
                b"16-bit CS0 name\n".to_vec(),
                0o644,
            ),
            ("/docs/emoji 🎉.txt", b"astral plane\n".to_vec(), 0o644),
            ("/a/b/c/d/e/f/g/h/i/j/deep.txt", b"deep\n".to_vec(), 0o644),
            ("/script.sh", b"#!/bin/sh\necho hi\n".to_vec(), 0o755),
        ],
        dirs: vec![("/docs", 0o750), ("/emptydir", 0o755), ("/many", 0o755)],
        symlinks: vec![
            ("/link-rel", "docs/café.txt"),
            ("/docs/link-up", "../readme.txt"),
        ],
        hardlinks: vec![("/docs/readme-hard", "/readme.txt")],
    }
}

/// Number of files in `/many` (spills the directory over several blocks).
const MANY: usize = 150;

/// Build the sample volume with `opts` in memory and return its bytes.
fn build(opts: &FormatOpts) -> Vec<u8> {
    let s = sample();
    let mut dev = MemoryBackend::new(64 << 20);
    let mut fs = Udf::format(&mut dev, opts).expect("format");
    for (d, mode) in &s.dirs {
        fs.create_dir(&mut dev, Path::new(d), meta(*mode)).unwrap();
    }
    for (p, body, mode) in &s.files {
        fs.create_file(
            &mut dev,
            Path::new(p),
            FileSource::Reader {
                reader: Box::new(std::io::Cursor::new(body.clone())),
                len: body.len() as u64,
            },
            meta(*mode),
        )
        .unwrap_or_else(|e| panic!("{p}: {e}"));
    }
    for i in 0..MANY {
        let body = format!("file {i}\n").into_bytes();
        let len = body.len() as u64;
        fs.create_file(
            &mut dev,
            Path::new(&format!("/many/entry-with-a-longer-name-{i:04}.txt")),
            FileSource::Reader {
                reader: Box::new(std::io::Cursor::new(body)),
                len,
            },
            meta(0o644),
        )
        .unwrap();
    }
    for (l, t) in &s.symlinks {
        fs.create_symlink(&mut dev, Path::new(l), Path::new(t), meta(0o777))
            .unwrap();
    }
    for (l, t) in &s.hardlinks {
        fs.hardlink(&mut dev, Path::new(t), Path::new(l)).unwrap();
    }
    fs.create_device(
        &mut dev,
        Path::new("/fifo"),
        DeviceKind::Fifo,
        0,
        0,
        meta(0o644),
    )
    .unwrap();
    fs.flush(&mut dev).expect("flush");
    let len = fs.image_len().unwrap();
    let mut img = vec![0u8; len as usize];
    dev.read_at(0, &mut img).unwrap();
    img
}

fn write_image(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, bytes).unwrap();
    p
}

/// Name equality up to Unicode normalisation: macOS presents names and
/// symlink targets decomposed (NFD) whatever is recorded.
fn same_name(a: &str, b: &str) -> bool {
    #[cfg(feature = "hfs-plus")]
    {
        use fstool::fs::hfs_plus::unicode::normalize_units;
        normalize_units(a) == normalize_units(b)
    }
    #[cfg(not(feature = "hfs-plus"))]
    {
        a == b || (!a.is_ascii() && !b.is_ascii())
    }
}

/// Check a mounted (or otherwise host-visible) copy of the sample tree.
fn verify_tree(root: &Path, check_perms: bool) {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let s = sample();
    for (p, body, mode) in &s.files {
        let path = root.join(&p[1..]);
        let got = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        assert_eq!(&got, body, "{p}: content differs");
        let md = std::fs::metadata(&path).unwrap();
        assert_eq!(md.len(), body.len() as u64, "{p}: size");
        if check_perms {
            assert_eq!(
                md.permissions().mode() & 0o7777,
                u32::from(*mode),
                "{p}: mode"
            );
            assert_eq!(md.uid(), 501, "{p}: uid");
            assert_eq!(md.gid(), 20, "{p}: gid");
            assert_eq!(md.mtime(), i64::from(MTIME), "{p}: mtime");
        }
    }
    for (d, mode) in &s.dirs {
        let md = std::fs::metadata(root.join(&d[1..])).unwrap();
        assert!(md.is_dir(), "{d}");
        if check_perms {
            assert_eq!(
                md.permissions().mode() & 0o7777,
                u32::from(*mode),
                "{d}: mode"
            );
        }
    }
    assert_eq!(std::fs::read_dir(root.join("emptydir")).unwrap().count(), 0);
    assert_eq!(std::fs::read_dir(root.join("many")).unwrap().count(), MANY);
    assert_eq!(
        std::fs::read(root.join("many/entry-with-a-longer-name-0042.txt")).unwrap(),
        b"file 42\n"
    );
    for (l, t) in &s.symlinks {
        let got = std::fs::read_link(root.join(&l[1..])).unwrap();
        assert!(
            same_name(&got.to_string_lossy(), t),
            "{l}: {got:?} vs {t:?}"
        );
    }
    assert_eq!(
        std::fs::read(root.join("link-rel")).unwrap(),
        b"latin-1 name\n",
        "relative symlink resolves"
    );
    for (l, t) in &s.hardlinks {
        let a = std::fs::metadata(root.join(&l[1..])).unwrap();
        let b = std::fs::metadata(root.join(&t[1..])).unwrap();
        assert_eq!(a.ino(), b.ino(), "{l} and {t} share an inode");
        assert_eq!(a.nlink(), 2, "{l}: link count");
    }
    let names: Vec<String> = std::fs::read_dir(root)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    for want in [
        "readme.txt",
        "empty",
        "docs",
        "emptydir",
        "many",
        "fifo",
        "link-rel",
    ] {
        assert!(
            names.iter().any(|n| n == want),
            "{want} missing from {names:?}"
        );
    }
}

/// Check the sample tree through fstool itself.
fn verify_fstool(fs: &mut Udf, dev: &mut dyn BlockDevice) {
    let s = sample();
    for (p, body, mode) in &s.files {
        let mut got = Vec::new();
        fs.read_file(dev, Path::new(p))
            .unwrap()
            .read_to_end(&mut got)
            .unwrap();
        assert_eq!(&got, body, "{p}");
        assert_eq!(fs.getattr(dev, Path::new(p)).unwrap().mode, *mode, "{p}");
    }
    for (l, t) in &s.symlinks {
        assert_eq!(fs.read_symlink(dev, Path::new(l)).unwrap(), Path::new(t));
    }
    assert_eq!(fs.list(dev, Path::new("/many")).unwrap().len(), MANY);
    assert_eq!(
        fs.getattr(dev, Path::new("/fifo")).unwrap().kind,
        EntryKind::Fifo
    );
}

/// The sample tree, in memory, re-read by fstool for every revision —
/// the baseline the native checks build on.
#[test]
fn sample_round_trips_in_fstool() {
    for &rev in UdfRevision::WRITABLE {
        let opts = fopts(|o| {
            o.revision = rev;
        });
        let img = build(&opts);
        let mut dev = MemoryBackend::new(img.len() as u64);
        dev.write_at(0, &img).unwrap();
        assert_eq!(
            fstool::inspect::detect_fs(&mut dev).unwrap(),
            fstool::inspect::FsKind::Udf
        );
        let mut fs = Udf::open(&mut dev).unwrap();
        assert_eq!(fs.info().unwrap().udf_revision, rev.bcd());
        verify_fstool(&mut fs, &mut dev);
    }
}

// ---------------------------------------------------------------------------
// macOS
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod macos {
    use super::*;

    /// Parallel attaches make hdiutil fail with EAGAIN; the tests take
    /// turns.
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn tools(extra: &[&str]) -> Option<std::sync::MutexGuard<'static, ()>> {
        let mut t = vec!["hdiutil", "diskutil"];
        t.extend_from_slice(extra);
        if !have(&t) {
            return None;
        }
        Some(SERIAL.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// An attached image; detaches on drop (also on panic) and checks
    /// `hdiutil info` no longer lists it.
    struct Attached {
        dev: String,
        image: PathBuf,
        mountpoint: Option<PathBuf>,
    }

    impl Drop for Attached {
        fn drop(&mut self) {
            for _ in 0..10 {
                let ok = Command::new("hdiutil")
                    .args(["detach", "-force", &self.dev])
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false);
                if ok {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
            if !std::thread::panicking() {
                assert_not_attached(&self.image);
            }
        }
    }

    fn assert_not_attached(image: &Path) {
        let out = Command::new("hdiutil").arg("info").output().unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        let canon = image.canonicalize().unwrap_or_else(|_| image.to_path_buf());
        assert!(
            !text.contains(&*canon.to_string_lossy()) && !text.contains(&*image.to_string_lossy()),
            "{} is still attached:\n{text}",
            image.display()
        );
    }

    /// Attach `image` (raw), mounted at a fresh directory under `tmp`
    /// unless `mount` is false.
    fn attach(image: &Path, tmp: &Path, rw: bool, owners: bool, mount: bool) -> Attached {
        let mut cmd = Command::new("hdiutil");
        cmd.args([
            "attach",
            "-nobrowse",
            "-imagekey",
            "diskimage-class=CRawDiskImage",
        ]);
        cmd.args(["-owners", if owners { "on" } else { "off" }]);
        if !rw {
            cmd.arg("-readonly");
        }
        let mp = tmp.join(format!(
            "mnt-{}",
            image.file_name().unwrap().to_string_lossy()
        ));
        if mount {
            std::fs::create_dir_all(&mp).unwrap();
            cmd.arg("-mountpoint").arg(&mp);
        } else {
            cmd.arg("-nomount");
        }
        cmd.arg(image);
        let mut out = cmd.output().expect("hdiutil attach");
        for _ in 0..30 {
            if out.status.success()
                || !String::from_utf8_lossy(&out.stderr).contains("temporarily unavailable")
            {
                break;
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
            out = cmd.output().expect("hdiutil attach");
        }
        assert!(
            out.status.success(),
            "hdiutil attach {}: {}{}",
            image.display(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let text = String::from_utf8_lossy(&out.stdout);
        let dev = text
            .split_whitespace()
            .next()
            .expect("no /dev/diskN")
            .to_string();
        Attached {
            dev,
            image: image.to_path_buf(),
            mountpoint: mount.then_some(mp),
        }
    }

    fn fsck_udf(image: &Path) {
        fsck_udf_bs(image, 2048);
    }

    /// `fsck_udf -n`. It only probes 2048-byte volumes in image files; any
    /// other block size is checked through the attached device node,
    /// whose sector size the kernel reports.
    fn fsck_udf_bs(image: &Path, block_size: u32) {
        let attached = (block_size != 2048).then(|| {
            let tmp = image.parent().unwrap();
            attach(image, tmp, false, false, false)
        });
        let target: PathBuf = match &attached {
            Some(a) => PathBuf::from(a.dev.replace("/dev/disk", "/dev/rdisk")),
            None => image.to_path_buf(),
        };
        let out = Command::new("/sbin/fsck_udf")
            .arg("-n")
            .arg(&target)
            .output()
            .unwrap();
        drop(attached);
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            out.status.success() && text.contains("is clean") && !text.contains("* * *"),
            "fsck_udf -n {} failed:\n{text}",
            image.display()
        );
    }

    #[test]
    fn fstool_images_pass_fsck_udf_and_mount() {
        let Some(_g) = tools(&["/sbin/fsck_udf"]) else {
            return;
        };
        let tmp = tempfile::tempdir().unwrap();
        let mut cases: Vec<(String, FormatOpts, bool)> = Vec::new();
        for &rev in UdfRevision::WRITABLE {
            cases.push((
                format!("ro-{rev}"),
                fopts(|o| {
                    o.revision = rev;
                    o.volume_id = format!("RO {rev}");
                }),
                false,
            ));
        }
        // Overwritable (space bitmap) volumes mount read-write, where macOS
        // reports the recorded modes and owners instead of its read-only
        // 0755 default.
        for rev in [UdfRevision::V1_02, UdfRevision::V1_50, UdfRevision::V2_01] {
            cases.push((
                format!("ow-{rev}"),
                fopts(|o| {
                    o.revision = rev;
                    o.access = AccessType::Overwritable;
                    o.volume_id = format!("OW {rev}");
                }),
                true,
            ));
        }
        cases.push((
            "ro-2.01-b512".into(),
            fopts(|o| {
                o.block_size = 512;
                o.volume_id = "B512".into();
            }),
            false,
        ));
        cases.push((
            "ro-2.01-fe".into(),
            fopts(|o| {
                o.extended_entries = Some(false);
                o.inline_dirs = Some(false);
                o.volume_id = "FE".into();
            }),
            false,
        ));
        for (name, opts, rw) in cases {
            eprintln!("case {name}");
            let img = write_image(tmp.path(), &format!("{name}.img"), &build(&opts));
            fsck_udf_bs(&img, opts.block_size);
            let a = attach(&img, tmp.path(), rw, rw, true);
            verify_tree(a.mountpoint.as_ref().unwrap(), rw);
            drop(a);
            // Still clean after a read-write mount.
            fsck_udf_bs(&img, opts.block_size);
        }
    }

    #[test]
    fn labels_visible_in_diskutil() {
        let Some(_g) = tools(&[]) else { return };
        let tmp = tempfile::tempdir().unwrap();
        for (rev, label) in [
            (UdfRevision::V1_02, "Plain Label"),
            (UdfRevision::V2_01, "Ünïcødé ✓ Label"),
            (UdfRevision::V2_50, "日本語ラベル"),
        ] {
            let opts = fopts(|o| {
                o.revision = rev;
                o.volume_id = label.into();
            });
            let img = write_image(tmp.path(), &format!("label-{rev}.img"), &build(&opts));
            let a = attach(&img, tmp.path(), false, false, true);
            let out = Command::new("diskutil")
                .args(["info", &a.dev])
                .output()
                .unwrap();
            let text = String::from_utf8_lossy(&out.stdout);
            let line = text
                .lines()
                .find(|l| l.trim_start().starts_with("Volume Name:"))
                .unwrap_or_else(|| panic!("no Volume Name in:\n{text}"));
            let shown = line.split_once(':').unwrap().1.trim();
            assert_eq!(
                shown.chars().filter(|c| c.is_alphanumeric()).count(),
                label.chars().filter(|c| c.is_alphanumeric()).count(),
                "{rev}: diskutil shows {shown:?} for {label:?}"
            );
            assert!(text.contains("UDF"), "{text}");
        }
    }

    /// A 5 GiB file whose zeros become holes: tiny image, every byte right.
    #[test]
    fn large_sparse_file_over_4gib() {
        let Some(_g) = tools(&["/sbin/fsck_udf"]) else {
            return;
        };
        let tmp = tempfile::tempdir().unwrap();
        let size = 5u64 << 30;
        let marks: [(u64, &[u8]); 3] = [(0, b"START"), (4 << 30, b"MIDDLE"), (size - 5, b"END!!")];
        let path = tmp.path().join("sparse.img");
        let mut dev = FileBackend::create(&path, 64 << 20).unwrap();
        let mut fs = Udf::format(
            &mut dev,
            &fopts(|o| {
                o.revision = UdfRevision::V1_02;
                o.volume_id = "SPARSE".into();
            }),
        )
        .unwrap();
        // Zero reader with the markers spliced in.
        struct Marked<'a> {
            pos: u64,
            len: u64,
            marks: &'a [(u64, &'a [u8])],
        }
        impl Read for Marked<'_> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let n = (buf.len() as u64).min(self.len - self.pos) as usize;
                buf[..n].fill(0);
                for (at, m) in self.marks {
                    for (k, &b) in m.iter().enumerate() {
                        let p = at + k as u64;
                        if p >= self.pos && p < self.pos + n as u64 {
                            buf[(p - self.pos) as usize] = b;
                        }
                    }
                }
                self.pos += n as u64;
                Ok(n)
            }
        }
        let mut r = Marked {
            pos: 0,
            len: size,
            marks: &marks,
        };
        fs.create_file_streaming(&mut dev, Path::new("/huge.bin"), &mut r, size, meta(0o644))
            .unwrap();
        fs.flush(&mut dev).unwrap();
        let len = fs.image_len().unwrap();
        drop(fs);
        drop(dev);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(len)
            .unwrap();
        fsck_udf(&path);
        let a = attach(&path, tmp.path(), false, false, true);
        let f = a.mountpoint.as_ref().unwrap().join("huge.bin");
        assert_eq!(std::fs::metadata(&f).unwrap().len(), size);
        let mut h = std::fs::File::open(&f).unwrap();
        for (at, m) in marks {
            let mut b = vec![0u8; m.len()];
            h.seek(SeekFrom::Start(at)).unwrap();
            h.read_exact(&mut b).unwrap();
            assert_eq!(b, m, "marker at {at}");
        }
        let mut z = vec![1u8; 1 << 16];
        h.seek(SeekFrom::Start(3 << 30)).unwrap();
        h.read_exact(&mut z).unwrap();
        assert!(z.iter().all(|&b| b == 0));
    }

    /// A 5 GiB file *recorded* as several ≤ 1 GiB extents, placed through
    /// the planner-facing layout API on a sparse host file.
    #[test]
    fn large_recorded_file_via_layout_api() {
        use fstool::fs::udf::layout::{BlockRange, FileData, UdfImage, UdfPlacement, UdfTree};
        let Some(_g) = tools(&["/sbin/fsck_udf"]) else {
            return;
        };
        let tmp = tempfile::tempdir().unwrap();
        let bs = 2048u64;
        let size = (5u64 << 30) + 12345;
        let data_block = 300u64;
        let data_blocks = size.div_ceil(bs);
        let part = BlockRange::new(257, data_blocks + 200);
        let volume_blocks = part.end() + 1;
        let path = tmp.path().join("recorded.img");
        let mut dev = FileBackend::create(&path, volume_blocks * bs).unwrap();
        // The "planner" writes only the markers; the rest stays a hole in
        // the host file and reads as zeros.
        let marks: [(u64, &[u8]); 3] = [(0, b"BEGIN"), (4 << 30, b"PAST4G"), (size - 4, b"FIN!")];
        for (at, m) in marks {
            dev.write_at(data_block * bs + at, m).unwrap();
        }
        let mut tree = UdfTree::new();
        tree.add_file(
            "/payload.bin",
            FileData::contiguous(data_block, size),
            meta(0o644),
        )
        .unwrap();
        let opts = fopts(|o| {
            o.revision = UdfRevision::V2_01;
            o.volume_id = "RECORDED".into();
        });
        let need = UdfImage::requirements(&tree, &opts, part.len).unwrap();
        let mut placement = UdfPlacement::new(2048, volume_blocks, part);
        let free_start = data_block + data_blocks;
        placement.free = vec![BlockRange::new(free_start, part.end() - free_start)];
        assert!(need.metadata_blocks <= part.end() - free_start);
        let image = UdfImage::build(&tree, &opts, &placement).unwrap();
        for r in image.used_ranges() {
            assert!(
                r.start + r.len <= data_block || r.start >= data_block + data_blocks,
                "{r:?} overlaps the payload"
            );
        }
        image.write(&mut dev).unwrap();
        dev.sync().unwrap();
        drop(dev);
        fsck_udf(&path);
        let a = attach(&path, tmp.path(), false, false, true);
        let f = a.mountpoint.as_ref().unwrap().join("payload.bin");
        assert_eq!(std::fs::metadata(&f).unwrap().len(), size);
        let mut h = std::fs::File::open(&f).unwrap();
        for (at, m) in marks {
            let mut b = vec![0u8; m.len()];
            h.seek(SeekFrom::Start(at)).unwrap();
            h.read_exact(&mut b).unwrap();
            assert_eq!(b, m, "marker at {at}");
        }
        drop(a);
        // And fstool reads it the same way.
        let mut dev = FileBackend::open(&path).unwrap();
        let mut fs = Udf::open(&mut dev).unwrap();
        let mut h = fs
            .open_file_ro(&mut dev, Path::new("/payload.bin"))
            .unwrap();
        h.seek(SeekFrom::Start(4 << 30)).unwrap();
        let mut b = [0u8; 6];
        h.read_exact(&mut b).unwrap();
        assert_eq!(&b, b"PAST4G");
    }

    /// Populate a mounted volume with the sample tree through the kernel.
    fn populate(root: &Path) {
        let s = sample();
        for (d, _) in &s.dirs {
            std::fs::create_dir_all(root.join(&d[1..])).unwrap();
        }
        for (p, body, mode) in &s.files {
            let path = root.join(&p[1..]);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::File::create(&path)
                .unwrap()
                .write_all(body)
                .unwrap();
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(u32::from(*mode)))
                .unwrap();
        }
        for i in 0..MANY {
            std::fs::write(
                root.join(format!("many/entry-with-a-longer-name-{i:04}.txt")),
                format!("file {i}\n"),
            )
            .unwrap();
        }
        for (l, t) in &s.symlinks {
            std::os::unix::fs::symlink(t, root.join(&l[1..])).unwrap();
        }
        for (l, t) in &s.hardlinks {
            std::fs::hard_link(root.join(&t[1..]), root.join(&l[1..])).unwrap();
        }
        let st = Command::new("mkfifo")
            .arg(root.join("fifo"))
            .status()
            .unwrap();
        assert!(st.success());
    }

    #[test]
    fn newfs_udf_images_read_in_fstool() {
        let Some(_g) = tools(&["/sbin/newfs_udf"]) else {
            return;
        };
        let tmp = tempfile::tempdir().unwrap();
        let cases: &[(&str, &[&str])] = &[
            ("1.02", &["-r", "1.02"]),
            ("1.50", &["-r", "1.50"]),
            ("2.00", &["-r", "2.00"]),
            ("2.01", &["-r", "2.01"]),
            ("2.01-efe", &["-r", "2.01", "-e"]),
            ("2.01-b512", &["-r", "2.01", "-b", "512"]),
            ("2.50", &["-r", "2.50"]),
            ("2.50-dup", &["-r", "2.50", "--dup-meta-part-file"]),
            ("2.60", &["-r", "2.60"]),
        ];
        for (name, args) in cases {
            eprintln!("case newfs_udf {name}");
            let img = tmp.path().join(format!("newfs-{name}.img"));
            std::fs::File::create(&img)
                .unwrap()
                .set_len(48 << 20)
                .unwrap();
            let out = Command::new("/sbin/newfs_udf")
                .args(*args)
                .args(["-v", &format!("NF {name}")])
                .arg(&img)
                .output()
                .unwrap();
            assert!(out.status.success(), "newfs_udf {args:?}: {out:?}");
            {
                let a = attach(&img, tmp.path(), true, true, true);
                populate(a.mountpoint.as_ref().unwrap());
            }
            let mut dev = FileBackend::open(&img).unwrap();
            let mut fs = Udf::open(&mut dev).unwrap_or_else(|e| panic!("{name}: {e}"));
            let info = fs.info().unwrap().clone();
            assert_eq!(info.logical_volume_id, format!("NF {name}"));
            let want_rev = u16::from_str_radix(&name[..4].replace('.', ""), 16).unwrap();
            assert_eq!(info.udf_revision, want_rev, "{name}");
            verify_fstool(&mut fs, &mut dev);
            // Hard links share one File Entry.
            let a = fs.getattr(&mut dev, Path::new("/readme.txt")).unwrap();
            let b = fs
                .getattr(&mut dev, Path::new("/docs/readme-hard"))
                .unwrap();
            assert_eq!((a.inode, a.nlink), (b.inode, 2), "{name}");
        }
    }

    #[test]
    fn hdiutil_makehybrid_images_read_in_fstool() {
        let Some(_g) = tools(&[]) else { return };
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        std::fs::create_dir(&src).unwrap();
        populate(&src);
        std::fs::remove_file(src.join("fifo")).unwrap();
        let cases: &[(&str, &[&str], u16)] = &[
            ("udf102", &["-udf", "-udf-version", "1.02"], 0x0102),
            ("udf150", &["-udf", "-udf-version", "1.50"], 0x0150),
            (
                "bridge",
                &["-iso", "-joliet", "-udf", "-udf-version", "1.02"],
                0x0102,
            ),
        ];
        for (name, args, rev) in cases {
            let img = tmp.path().join(format!("{name}.iso"));
            let out = Command::new("hdiutil")
                .args(["makehybrid", "-quiet", "-o"])
                .arg(&img)
                .args(*args)
                .args(["-udf-volume-name", &format!("HY {name}")])
                .arg(&src)
                .output()
                .unwrap();
            assert!(out.status.success(), "makehybrid {args:?}: {out:?}");
            let mut dev = FileBackend::open(&img).unwrap();
            assert_eq!(
                fstool::inspect::detect_fs(&mut dev).unwrap(),
                fstool::inspect::FsKind::Udf,
                "{name}"
            );
            let mut fs = Udf::open(&mut dev).unwrap();
            assert_eq!(fs.info().unwrap().udf_revision, *rev);
            assert_eq!(fs.info().unwrap().logical_volume_id, format!("HY {name}"));
            let s = sample();
            for (p, body, _) in &s.files {
                let mut got = Vec::new();
                fs.read_file(&mut dev, Path::new(p))
                    .unwrap()
                    .read_to_end(&mut got)
                    .unwrap();
                assert_eq!(&got, body, "{name}: {p}");
            }
            for (l, t) in &s.symlinks {
                assert_eq!(
                    fs.read_symlink(&mut dev, Path::new(l)).unwrap(),
                    Path::new(t)
                );
            }
            assert_eq!(fs.list(&mut dev, Path::new("/many")).unwrap().len(), MANY);
        }
    }

    #[test]
    fn repack_into_udf_with_the_cli() {
        let Some(_g) = tools(&["/sbin/fsck_udf"]) else {
            return;
        };
        let tmp = tempfile::tempdir().unwrap();
        // Source: an ISO 9660 (Rock Ridge) image fstool builds from the
        // sample tree's host copy.
        let src = tmp.path().join("src");
        std::fs::create_dir(&src).unwrap();
        populate(&src);
        std::fs::remove_file(src.join("fifo")).unwrap();
        let iso = tmp.path().join("src.iso");
        let bin = env!("CARGO_BIN_EXE_fstool");
        let st = Command::new(bin)
            .args(["create", "-t", "iso", "-o"])
            .arg(&iso)
            .arg(&src)
            .output()
            .unwrap();
        assert!(st.status.success(), "{st:?}");
        let out = tmp.path().join("out.udf");
        let st = Command::new(bin)
            .arg("repack")
            .arg(&iso)
            .arg(&out)
            .args(["-t", "udf"])
            .output()
            .unwrap();
        assert!(st.status.success(), "{st:?}");
        fsck_udf(&out);
        let a = attach(&out, tmp.path(), false, false, true);
        let root = a.mountpoint.as_ref().unwrap();
        for (p, body, _) in &sample().files {
            assert_eq!(&std::fs::read(root.join(&p[1..])).unwrap(), body, "{p}");
        }
    }
}

// ---------------------------------------------------------------------------
// Linux (GitHub CI installs udftools)
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod linux {
    use super::*;

    fn sudo_ok() -> bool {
        Command::new("sudo")
            .args(["-n", "true"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// A loop mount; unmounted on drop.
    struct Mounted(PathBuf);

    impl Drop for Mounted {
        fn drop(&mut self) {
            for _ in 0..5 {
                let ok = Command::new("sudo")
                    .args(["-n", "umount"])
                    .arg(&self.0)
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false);
                if ok {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
        }
    }

    fn mount(img: &Path, mp: &Path, rw: bool) -> Option<Mounted> {
        std::fs::create_dir_all(mp).unwrap();
        let opts = if rw { "loop,rw" } else { "loop,ro" };
        let out = Command::new("sudo")
            .args(["-n", "mount", "-t", "udf", "-o", opts])
            .arg(img)
            .arg(mp)
            .output()
            .unwrap();
        if !out.status.success() {
            eprintln!(
                "skipping mount of {}: {}",
                img.display(),
                String::from_utf8_lossy(&out.stderr)
            );
            return None;
        }
        Some(Mounted(mp.to_path_buf()))
    }

    #[test]
    fn mkudffs_images_read_in_fstool() {
        if !have(&["mkudffs"]) {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let mut cases: Vec<(String, Vec<String>)> = Vec::new();
        for rev in ["1.02", "1.50", "2.00", "2.01", "2.50", "2.60"] {
            cases.push((
                format!("hd-{rev}"),
                vec!["--media-type=hd".into(), format!("--udfrev={rev}")],
            ));
        }
        // Write-once (VAT) and sparable layouts.
        for rev in ["1.50", "2.01", "2.50"] {
            cases.push((
                format!("cdr-{rev}"),
                vec!["--media-type=cdr".into(), format!("--udfrev={rev}")],
            ));
            cases.push((
                format!("cdrw-{rev}"),
                vec!["--media-type=cdrw".into(), format!("--udfrev={rev}")],
            ));
        }
        cases.push((
            "hd-2.01-b512".into(),
            vec![
                "--media-type=hd".into(),
                "--udfrev=2.01".into(),
                "--blocksize=512".into(),
            ],
        ));
        cases.push((
            "hd-2.01-b4096".into(),
            vec![
                "--media-type=hd".into(),
                "--udfrev=2.01".into(),
                "--blocksize=4096".into(),
            ],
        ));
        let can_mount = sudo_ok();
        for (name, args) in cases {
            eprintln!("case mkudffs {name} {args:?}");
            let img = tmp.path().join(format!("{name}.img"));
            std::fs::File::create(&img)
                .unwrap()
                .set_len(64 << 20)
                .unwrap();
            let label = format!("MK{}", name.replace(['.', '-'], ""));
            let out = Command::new("mkudffs")
                .args(&args)
                .arg(format!("--label={label}"))
                .arg(&img)
                .output()
                .unwrap();
            if !out.status.success() {
                eprintln!(
                    "mkudffs {args:?} refused: {}",
                    String::from_utf8_lossy(&out.stderr)
                );
                continue;
            }
            // Populate hd media through the kernel when possible.
            let mut populated = false;
            if can_mount
                && name.starts_with("hd-")
                && !name.contains("b4096")
                && !name.contains("b512")
            {
                let mp = tmp.path().join(format!("mnt-{name}"));
                if let Some(m) = mount(&img, &mp, true) {
                    let st = Command::new("sudo")
                        .args(["-n", "sh", "-c"])
                        .arg(format!(
                            "mkdir -p '{0}/docs/sub' && printf 'hello' > '{0}/docs/a.txt' && \
                             printf 'unicode' > '{0}/docs/日本語.txt' && ln -s docs/a.txt '{0}/link' && \
                             ln '{0}/docs/a.txt' '{0}/hard' && mkfifo '{0}/fifo' && \
                             head -c 3000000 /dev/urandom > '{0}/big.bin' && cp '{0}/big.bin' '{1}'",
                            mp.display(),
                            tmp.path().join(format!("{name}.big")).display()
                        ))
                        .status()
                        .unwrap();
                    assert!(st.success());
                    drop(m);
                    populated = true;
                }
            }
            let mut dev = FileBackend::open(&img).unwrap();
            let mut fs = Udf::open(&mut dev).unwrap_or_else(|e| panic!("{name}: {e}"));
            let info = fs.info().unwrap().clone();
            assert_eq!(info.logical_volume_id, label, "{name}");
            fs.list(&mut dev, Path::new("/")).unwrap();
            if populated {
                let mut b = Vec::new();
                fs.read_file(&mut dev, Path::new("/docs/a.txt"))
                    .unwrap()
                    .read_to_end(&mut b)
                    .unwrap();
                assert_eq!(b, b"hello");
                let mut b = Vec::new();
                fs.read_file(&mut dev, Path::new("/docs/日本語.txt"))
                    .unwrap()
                    .read_to_end(&mut b)
                    .unwrap();
                assert_eq!(b, b"unicode");
                assert_eq!(
                    fs.read_symlink(&mut dev, Path::new("/link")).unwrap(),
                    Path::new("docs/a.txt")
                );
                assert_eq!(fs.getattr(&mut dev, Path::new("/hard")).unwrap().nlink, 2);
                assert_eq!(
                    fs.getattr(&mut dev, Path::new("/fifo")).unwrap().kind,
                    EntryKind::Fifo
                );
                let mut big = Vec::new();
                fs.read_file(&mut dev, Path::new("/big.bin"))
                    .unwrap()
                    .read_to_end(&mut big)
                    .unwrap();
                assert_eq!(
                    big,
                    std::fs::read(tmp.path().join(format!("{name}.big"))).unwrap()
                );
            }
        }
    }

    #[test]
    fn fstool_images_satisfy_udfinfo_and_mount() {
        if !have(&["udfinfo"]) {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let can_mount = sudo_ok();
        for &rev in UdfRevision::WRITABLE {
            for access in [AccessType::ReadOnly, AccessType::Overwritable] {
                if access == AccessType::Overwritable && rev.uses_metadata_partition() {
                    continue;
                }
                let label = format!("FSTOOL {rev}");
                let opts = fopts(|o| {
                    o.revision = rev;
                    o.access = access;
                    o.volume_id = label.clone();
                });
                let img = write_image(
                    tmp.path(),
                    &format!("fs-{rev}-{access:?}.img"),
                    &build(&opts),
                );
                let out = Command::new("udfinfo").arg(&img).output().unwrap();
                let text = format!(
                    "{}{}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                );
                assert!(out.status.success(), "udfinfo {rev}: {text}");
                assert!(
                    text.contains(&format!("udfrev={rev}")),
                    "udfinfo {rev}: {text}"
                );
                assert!(text.contains(&label), "udfinfo {rev}: {text}");
                if can_mount {
                    let mp = tmp.path().join(format!("mnt-{rev}-{access:?}"));
                    if let Some(m) = mount(&img, &mp, false) {
                        verify_tree(&m.0, true);
                    }
                }
            }
        }
    }
}
