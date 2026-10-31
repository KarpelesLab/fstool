#![cfg(all(target_os = "macos", feature = "hfs-plus", feature = "cli"))]
//! Native acceptance for HFS+ / HFSX verification and resizing (issue #63).
//!
//! * fstool's verifier (`fstool check`) agrees with `fsck_hfs -fn`: macOS-made HFS+, JHFS+,
//!   HFSX and journaled HFSX images with content verify clean, and
//!   deliberately corrupted copies are flagged by both.
//! * After fstool grows and shrinks a volume — bare, and inside GPT, MBR
//!   and APM disks laid out by `diskutil` — `fsck_hfs -fn` is clean, the
//!   volume mounts, `df` and `diskutil info` report the new size, and the
//!   payload and metadata (file bytes, xattrs, resource forks, hard links,
//!   symlinks) read back through the kernel. Neighbouring partitions are
//!   byte-for-byte unchanged and the disk / partition identifiers kept.
//!
//! Skips (with a message) when `hdiutil`, `fsck_hfs`, `diskutil` or
//! `xattr` is missing. Every attached image is detached on drop.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use fstool::block::{BlockDevice, FileBackend};
use fstool::fs::hfs_plus::resize::{ResizeOpts, apply_resize, plan_resize};
use fstool::fs::hfs_plus::verify::verify;
use fstool::fs::hfs_plus::{FormatOpts, HfsPlus};
use fstool::fs::verify::VerifyOpts;

const FSTOOL: &str = env!("CARGO_BIN_EXE_fstool");
const MIB: u64 = 1024 * 1024;

fn which(tool: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {tool}"))
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn tools_present() -> bool {
    let ok = ["hdiutil", "fsck_hfs", "diskutil", "xattr"]
        .iter()
        .all(|t| which(t));
    if !ok {
        eprintln!("skipping: hdiutil / fsck_hfs / diskutil / xattr not available");
    }
    ok
}

/// Detaches the attached image when dropped (also on panic).
struct Attached(String);

impl Drop for Attached {
    fn drop(&mut self) {
        for _ in 0..5 {
            let ok = Command::new("hdiutil")
                .args(["detach", "-force", &self.0])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            if ok {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    }
}

fn attach(image: &Path, readonly: bool) -> Attached {
    let mut cmd = Command::new("hdiutil");
    cmd.args([
        "attach",
        "-nomount",
        "-imagekey",
        "diskimage-class=CRawDiskImage",
    ]);
    if readonly {
        cmd.arg("-readonly");
    }
    let out = cmd.arg(image).output().expect("hdiutil attach");
    assert!(
        out.status.success(),
        "hdiutil attach {}: {}",
        image.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    let dev = text
        .split_whitespace()
        .next()
        .expect("no /dev/diskN")
        .to_string();
    Attached(dev)
}

fn fsck_dev(dev: &str) -> (bool, String) {
    let out = Command::new("fsck_hfs")
        .arg("-fn")
        .arg(dev)
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (
        out.status.success() && text.contains("appears to be OK"),
        text,
    )
}

/// `fsck_hfs -fn` on slice `slice` (`None` = the whole image).
fn fsck(image: &Path, slice: Option<usize>) -> (bool, String) {
    let a = attach(image, true);
    let dev = match slice {
        Some(s) => format!("{}s{s}", a.0),
        None => a.0.clone(),
    };
    fsck_dev(&dev)
}

fn assert_fsck(image: &Path, slice: Option<usize>, what: &str) {
    let (ok, text) = fsck(image, slice);
    assert!(ok, "{what}: fsck_hfs -fn not clean:\n{text}");
}

fn assert_verify_clean_bytes(image: &Path, offset: u64, len: u64, what: &str) {
    let mut dev = FileBackend::open_read_only(image).unwrap();
    let mut slice = fstool::block::SlicedBackend::new(&mut dev, offset, len).unwrap();
    let r = verify(&mut slice, &VerifyOpts::default()).unwrap();
    assert!(r.is_clean(), "{what}: fstool verify: {:#?}", r.diagnostics);
}

/// A source tree with content and metadata the kernel must hand back.
fn make_src(dir: &Path) -> PathBuf {
    let src = dir.join("src");
    std::fs::create_dir_all(src.join("dir/sub")).unwrap();
    let mut x: u32 = 0x1234_5678;
    for i in 1..=8u32 {
        let body: Vec<u8> = (0..i * 70_000)
            .map(|_| {
                x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
                (x >> 16) as u8
            })
            .collect();
        std::fs::write(src.join(format!("dir/f{i}")), body).unwrap();
    }
    std::fs::write(src.join("x.txt"), b"hello\n").unwrap();
    std::fs::write(src.join("r"), b"").unwrap();
    std::fs::write(src.join("r/..namedfork/rsrc"), vec![0x5Au8; 9000]).unwrap();
    std::fs::hard_link(src.join("dir/f2"), src.join("dir/sub/hardlink")).unwrap();
    std::os::unix::fs::symlink("../x.txt", src.join("dir/sym")).unwrap();
    xattr_w(&src.join("x.txt"), "user.test", "some value");
    xattr_w(&src.join("dir/f1"), "com.example.big", &"a".repeat(6000));
    src
}

fn xattr_w(p: &Path, name: &str, value: &str) {
    let ok = Command::new("xattr")
        .args(["-w", name, value])
        .arg(p)
        .status()
        .unwrap()
        .success();
    assert!(ok, "xattr -w {name}");
}

fn xattr_p(p: &Path, name: &str) -> Option<String> {
    let out = Command::new("xattr")
        .args(["-p", name])
        .arg(p)
        .output()
        .unwrap();
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim_end().to_string())
}

/// Compare a mounted volume against the source tree.
fn check_payload(mp: &Path, src: &Path) {
    for i in 1..=8 {
        let rel = format!("dir/f{i}");
        assert_eq!(
            std::fs::read(mp.join(&rel)).unwrap(),
            std::fs::read(src.join(&rel)).unwrap(),
            "{rel} differs"
        );
    }
    assert_eq!(std::fs::read(mp.join("x.txt")).unwrap(), b"hello\n");
    assert_eq!(
        std::fs::read(mp.join("r/..namedfork/rsrc")).unwrap(),
        vec![0x5Au8; 9000],
        "resource fork"
    );
    assert_eq!(
        xattr_p(&mp.join("x.txt"), "user.test").as_deref(),
        Some("some value")
    );
    assert_eq!(
        xattr_p(&mp.join("dir/f1"), "com.example.big").map(|s| s.len()),
        Some(6000)
    );
    let a = std::fs::metadata(mp.join("dir/f2")).unwrap();
    let b = std::fs::metadata(mp.join("dir/sub/hardlink")).unwrap();
    assert_eq!(a.ino(), b.ino(), "hard link inode");
    assert_eq!(a.nlink(), 2);
    assert_eq!(
        std::fs::read_link(mp.join("dir/sym")).unwrap(),
        PathBuf::from("../x.txt")
    );
}

/// Mount `dev` read-only at `mp`, run `f`, unmount.
fn with_mount(dev: &str, mp: &Path, f: impl FnOnce(&Path)) {
    std::fs::create_dir_all(mp).unwrap();
    let out = Command::new("diskutil")
        .args(["mount", "readOnly", "-mountPoint"])
        .arg(mp)
        .arg(dev)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "diskutil mount {dev}: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    struct Unmount(PathBuf);
    impl Drop for Unmount {
        fn drop(&mut self) {
            let _ = Command::new("diskutil")
                .args(["unmount", "force"])
                .arg(&self.0)
                .output();
        }
    }
    let _u = Unmount(mp.to_path_buf());
    f(mp);
}

fn df_total(mp: &Path) -> u64 {
    let out = Command::new("df").arg("-k").arg(mp).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text.lines().nth(1).expect("df line");
    line.split_whitespace()
        .nth(1)
        .unwrap()
        .parse::<u64>()
        .unwrap()
        * 1024
}

fn diskutil_int(dev: &str, key: &str) -> Option<u64> {
    let out = Command::new("diskutil")
        .args(["info", "-plist", dev])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let k = format!("<key>{key}</key>");
    let i = text.find(&k)? + k.len();
    let rest = &text[i..];
    let a = rest.find("<integer>")? + 9;
    let b = rest.find("</integer>")?;
    rest[a..b].trim().parse().ok()
}

fn diskutil_str(dev: &str, key: &str) -> Option<String> {
    let out = Command::new("diskutil")
        .args(["info", "-plist", dev])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let k = format!("<key>{key}</key>");
    let i = text.find(&k)? + k.len();
    let rest = &text[i..];
    let a = rest.find("<string>")? + 8;
    let b = rest.find("</string>")?;
    Some(rest[a..b].to_string())
}

/// Mount and check size + payload of slice `slice` of `image`.
fn check_mounted(image: &Path, slice: Option<usize>, size: u64, src: &Path, dir: &Path) {
    let a = attach(image, true);
    let dev = match slice {
        Some(s) => format!("{}s{s}", a.0),
        None => a.0.clone(),
    };
    with_mount(&dev, &dir.join("mp"), |mp| {
        assert_eq!(
            diskutil_int(&dev, "VolumeSize"),
            Some(size),
            "diskutil VolumeSize of {dev}"
        );
        assert_eq!(df_total(mp), size, "df total of {dev}");
        check_payload(mp, src);
    });
}

/// `hdiutil create -srcfolder` a raw image of `fs`.
fn mac_image(dir: &Path, src: &Path, fs: &str, size_mb: u32) -> Option<PathBuf> {
    let base = dir.join(format!("mac-{}", fs.replace(['+', ' '], "")));
    let out = Command::new("hdiutil")
        .args(["create", "-quiet", "-fs", fs, "-layout", "NONE"])
        .args(["-size", &format!("{size_mb}m"), "-volname", "Native"])
        .arg("-srcfolder")
        .arg(src)
        .args(["-format", "UDTO"])
        .arg(&base)
        .output()
        .unwrap();
    let img = base.with_extension("cdr");
    if !out.status.success() || !img.exists() {
        eprintln!(
            "skipping {fs}: hdiutil create failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        return None;
    }
    Some(img)
}

/// The same tree written by fstool's own writer.
fn fstool_image(dir: &Path, src: &Path, case_sensitive: bool) -> PathBuf {
    let img = dir.join(if case_sensitive {
        "fstool-hfsx.img"
    } else {
        "fstool-hfs.img"
    });
    let mut dev = FileBackend::create(&img, 40 * MIB).unwrap();
    let mut opts = FormatOpts::default();
    opts.case_sensitive = case_sensitive;
    opts.volume_name = "FsTool".into();
    let mut fs = HfsPlus::format(&mut dev, &opts).unwrap();
    for d in ["/dir", "/dir/sub"] {
        fs.create_dir(&mut dev, d, 0o755, 501, 20, 0).unwrap();
    }
    let put = |fs: &mut HfsPlus, dev: &mut FileBackend, rel: &str| {
        let body = std::fs::read(src.join(rel.trim_start_matches('/'))).unwrap();
        fs.create_file(
            dev,
            rel,
            &mut std::io::Cursor::new(&body),
            body.len() as u64,
            0o644,
            501,
            20,
            0,
        )
        .unwrap();
    };
    for i in 1..=8 {
        put(&mut fs, &mut dev, &format!("/dir/f{i}"));
    }
    put(&mut fs, &mut dev, "/x.txt");
    put(&mut fs, &mut dev, "/r");
    let rsrc = vec![0x5Au8; 9000];
    fs.write_resource_fork(&mut dev, "/r", &mut std::io::Cursor::new(&rsrc), 9000)
        .unwrap();
    fs.create_hardlink(&mut dev, "/dir/f2", "/dir/sub/hardlink")
        .unwrap();
    fs.create_symlink(&mut dev, "/dir/sym", "../x.txt", 0o755, 501, 20, 0)
        .unwrap();
    fs.set_xattr(&mut dev, "/x.txt", "user.test", b"some value")
        .unwrap();
    fs.set_xattr(
        &mut dev,
        "/dir/f1",
        "com.example.big",
        "a".repeat(6000).as_bytes(),
    )
    .unwrap();
    fs.flush(&mut dev).unwrap();
    img
}

fn set_len(p: &Path, n: u64) {
    std::fs::OpenOptions::new()
        .write(true)
        .open(p)
        .unwrap()
        .set_len(n)
        .unwrap();
}

/// Resize a bare image file with the library API, growing / cutting the
/// file around the apply as the plan contract says.
fn resize_bare(img: &Path, new_size: u64) {
    let cur = std::fs::metadata(img).unwrap().len();
    let plan = {
        let mut dev = FileBackend::open_read_only(img).unwrap();
        plan_resize(&mut dev, new_size, &ResizeOpts::default()).unwrap()
    };
    assert!(plan.is_feasible(), "{}: {:?}", img.display(), plan.refusals);
    if new_size > cur {
        set_len(img, new_size);
    }
    {
        let mut dev = FileBackend::open(img).unwrap();
        apply_resize(&mut dev, &plan).unwrap();
        dev.sync().unwrap();
    }
    if new_size < cur {
        set_len(img, new_size);
    }
}

// ---------------------------------------------------------------------
// Verification vs fsck_hfs
// ---------------------------------------------------------------------

fn be32(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes(b[o..o + 4].try_into().unwrap())
}

fn rw(img: &Path, off: u64, f: impl FnOnce(&mut [u8])) {
    use std::os::unix::fs::FileExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(img)
        .unwrap();
    let mut buf = vec![0u8; 512];
    file.read_at(&mut buf, off).unwrap();
    f(&mut buf);
    file.write_at(&buf, off).unwrap();
}

fn vh(img: &Path) -> Vec<u8> {
    let mut b = vec![0u8; 512];
    use std::os::unix::fs::FileExt;
    std::fs::File::open(img)
        .unwrap()
        .read_at(&mut b, 1024)
        .unwrap();
    b
}

type Corruption = (&'static str, fn(&Path));

fn corruptions() -> Vec<Corruption> {
    fn bump(img: &Path, off: usize, by: i64) {
        rw(img, 1024, |b| {
            let v = be32(b, off) as i64 + by;
            b[off..off + 4].copy_from_slice(&(v as u32).to_be_bytes());
        });
    }
    fn bitmap_bit(img: &Path, blk: u64, set: bool) {
        let h = vh(img);
        let bs = u64::from(be32(&h, 40));
        let alloc_start = u64::from(be32(&h, 0x70 + 16));
        let off = alloc_start * bs + blk / 8;
        rw(img, off - off % 512, |b| {
            let i = (off % 512) as usize;
            let m = 0x80u8 >> (blk % 8);
            if set { b[i] |= m } else { b[i] &= !m }
        });
    }
    fn catalog_base(img: &Path) -> (u64, u32) {
        let h = vh(img);
        let bs = u64::from(be32(&h, 40));
        let base = u64::from(be32(&h, 0x110 + 16)) * bs;
        let mut n0 = vec![0u8; 512];
        use std::os::unix::fs::FileExt;
        std::fs::File::open(img)
            .unwrap()
            .read_at(&mut n0, base)
            .unwrap();
        let node_size = u16::from_be_bytes([n0[14 + 18], n0[14 + 19]]);
        (base, u32::from(node_size))
    }
    vec![
        ("free count", |p| bump(p, 48, 7)),
        ("folder count", |p| bump(p, 36, 1)),
        ("file count", |p| bump(p, 32, -1)),
        ("in-use block marked free", |p| {
            let h = vh(p);
            bitmap_bit(p, u64::from(be32(&h, 0x110 + 16)), false);
        }),
        ("leaked block", |p| {
            let h = vh(p);
            let total = u64::from(be32(&h, 44));
            bitmap_bit(p, total - 100, true);
            bump(p, 48, -1);
        }),
        ("catalog leaf count", |p| {
            let (base, _) = catalog_base(p);
            rw(p, base, |b| {
                let v = be32(b, 14 + 6) + 1;
                b[20..24].copy_from_slice(&v.to_be_bytes());
            });
        }),
        ("catalog sibling link", |p| {
            let (base, ns) = catalog_base(p);
            let mut first_leaf = 0u32;
            rw(p, base, |b| first_leaf = be32(b, 14 + 10));
            rw(p, base + u64::from(first_leaf) * u64::from(ns), |b| {
                b[0..4].copy_from_slice(&0x0000_FFF0u32.to_be_bytes());
            });
        }),
        ("file record CNID", |p| {
            // The x.txt file record: key (parent 2, "x.txt").
            let (base, ns) = catalog_base(p);
            let mut first_leaf = 0u32;
            rw(p, base, |b| first_leaf = be32(b, 14 + 10));
            let leaf = base + u64::from(first_leaf) * u64::from(ns);
            use std::os::unix::fs::FileExt;
            let f = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(p)
                .unwrap();
            let mut node = vec![0u8; ns as usize];
            f.read_at(&mut node, leaf).unwrap();
            let mut key = vec![0u8, 16, 0, 0, 0, 2, 0, 5];
            for c in "x.txt".encode_utf16() {
                key.extend_from_slice(&c.to_be_bytes());
            }
            let at = node
                .windows(key.len())
                .position(|w| w == key.as_slice())
                .expect("x.txt record");
            let body = at + key.len();
            let id = be32(&node, body + 8) + 1000;
            node[body + 8..body + 12].copy_from_slice(&id.to_be_bytes());
            f.write_at(&node, leaf).unwrap();
        }),
        ("alternate header", |p| {
            let n = std::fs::metadata(p).unwrap().len();
            rw(p, n - 1024, |b| b.fill(0));
        }),
    ]
}

#[test]
fn verify_agrees_with_fsck_hfs() {
    if !tools_present() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let src = make_src(dir.path());
    let mut images: Vec<PathBuf> = ["HFS+", "JHFS+", "HFSX", "JHFSX"]
        .iter()
        .filter_map(|fs| mac_image(dir.path(), &src, fs, 40))
        .collect();
    images.push(fstool_image(dir.path(), &src, false));
    images.push(fstool_image(dir.path(), &src, true));
    for img in &images {
        let name = img.file_name().unwrap().to_string_lossy().to_string();
        let (ok, text) = fsck(img, None);
        assert!(ok, "{name}: precondition, fsck_hfs not clean:\n{text}");
        let len = std::fs::metadata(img).unwrap().len();
        assert_verify_clean_bytes(img, 0, len, &name);
        for (what, corrupt) in corruptions() {
            let copy = dir.path().join("corrupt.img");
            std::fs::copy(img, &copy).unwrap();
            corrupt(&copy);
            let (fsck_ok, fsck_text) = fsck(&copy, None);
            let mut dev = FileBackend::open_read_only(&copy).unwrap();
            let r = verify(&mut dev, &VerifyOpts::default()).unwrap();
            assert!(
                !fsck_ok,
                "{name} / {what}: fsck_hfs did not flag it (test corruption too weak?):\n{fsck_text}"
            );
            assert!(
                r.error_count > 0,
                "{name} / {what}: fsck_hfs flags it but fstool verify does not:\n{fsck_text}"
            );
        }
    }
}

// ---------------------------------------------------------------------
// Bare volumes
// ---------------------------------------------------------------------

#[test]
fn grow_and_shrink_bare_volumes() {
    if !tools_present() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let src = make_src(dir.path());
    let mut images: Vec<PathBuf> = ["HFS+", "JHFS+", "HFSX", "JHFSX"]
        .iter()
        .filter_map(|fs| mac_image(dir.path(), &src, fs, 40))
        .collect();
    images.push(fstool_image(dir.path(), &src, false));
    images.push(fstool_image(dir.path(), &src, true));
    for img in &images {
        let name = img.file_name().unwrap().to_string_lossy().to_string();
        // Within the bitmap's capacity, then far past it.
        for size in [96 * MIB, 600 * MIB] {
            resize_bare(img, size);
            assert_fsck(img, None, &format!("{name} grown to {size}"));
            assert_verify_clean_bytes(img, 0, size, &name);
            check_mounted(img, None, size, &src, dir.path());
        }
        // Back below the original size.
        let min = {
            let mut dev = FileBackend::open_read_only(img).unwrap();
            plan_resize(&mut dev, 1 << 20, &ResizeOpts::default())
                .unwrap()
                .min_size
        };
        let target = (min + 2 * MIB).div_ceil(MIB) * MIB;
        assert!(target < 40 * MIB, "{name}: min size {min}");
        resize_bare(img, target);
        assert_eq!(std::fs::metadata(img).unwrap().len(), target);
        assert_fsck(img, None, &format!("{name} shrunk to {target}"));
        assert_verify_clean_bytes(img, 0, target, &name);
        check_mounted(img, None, target, &src, dir.path());
        // A shrink past the data is refused with a typed reason.
        let mut dev = FileBackend::open_read_only(img).unwrap();
        let plan = plan_resize(&mut dev, min - 4096 * 4, &ResizeOpts::default()).unwrap();
        assert!(!plan.is_feasible());
    }
}

// ---------------------------------------------------------------------
// Partitioned disks
// ---------------------------------------------------------------------

/// One partition: (start LBA, size LBA, kind, name, GUID).
type Part = (u64, u64, String, Option<String>, Option<uuid::Uuid>);

/// Byte ranges and identity of every partition, via fstool.
fn layout(img: &Path) -> Vec<Part> {
    let mut dev = FileBackend::open_read_only(img).unwrap();
    let t = fstool::inspect::detect_partition_table(&mut dev)
        .unwrap()
        .expect("table");
    t.partitions()
        .iter()
        .map(|p| {
            (
                p.start_lba,
                p.size_lba,
                format!("{:?}", p.kind),
                p.name.clone(),
                p.uuid,
            )
        })
        .collect()
}

fn disk_guid(img: &Path) -> Option<uuid::Uuid> {
    let mut dev = FileBackend::open_read_only(img).unwrap();
    fstool::part::Gpt::read(&mut dev).ok().map(|g| g.disk_guid)
}

fn slice_bytes(img: &Path, start_lba: u64, size_lba: u64) -> Vec<u8> {
    use std::os::unix::fs::FileExt;
    let mut b = vec![0u8; (size_lba * 512) as usize];
    std::fs::File::open(img)
        .unwrap()
        .read_at(&mut b, start_lba * 512)
        .unwrap();
    b
}

fn cli(args: &[&str]) {
    let out = Command::new(FSTOOL).args(args).output().unwrap();
    assert!(
        out.status.success(),
        "fstool {}: {}{}",
        args.join(" "),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn cli_fails(args: &[&str]) -> String {
    let out = Command::new(FSTOOL).args(args).output().unwrap();
    assert!(!out.status.success(), "fstool {} succeeded", args.join(" "));
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// Index (1-based, as `IMG:N`) of the partition named / typed `want`.
fn find(img: &Path, want: &str) -> usize {
    let l = layout(img);
    l.iter()
        .position(|p| p.3.as_deref() == Some(want) || p.2.contains(want))
        .unwrap_or_else(|| panic!("no partition {want} in {l:?}"))
        + 1
}

/// Lay out a disk with `diskutil partitionDisk`: A (JHFS+, 40 MB) and
/// B (case-sensitive HFS+, 30 MB), the rest free, then copy the source
/// tree into both through the kernel.
fn native_disk(dir: &Path, scheme: &str, src: &Path) -> PathBuf {
    let img = dir.join(format!("disk-{scheme}.img"));
    let f = std::fs::File::create(&img).unwrap();
    f.set_len(128 * MIB).unwrap();
    drop(f);
    let a = attach(&img, false);
    let mut cmd = Command::new("diskutil");
    cmd.args(["partitionDisk", &a.0]);
    if scheme == "APM" {
        cmd.args([
            "2",
            "APM",
            "JHFS+",
            "A",
            "40M",
            "Case-sensitive HFS+",
            "B",
            "30M",
        ]);
    } else {
        cmd.args([
            "3",
            scheme,
            "JHFS+",
            "A",
            "40M",
            "Case-sensitive HFS+",
            "B",
            "30M",
            "Free Space",
            "C",
            "R",
        ]);
    }
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "diskutil partitionDisk {scheme}: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    // diskutil mounted both; copy the tree in through the kernel.
    let slices: [usize; 2] = if scheme == "APM" { [2, 3] } else { [1, 2] };
    for s in slices {
        let dev = format!("{}s{s}", a.0);
        let mp = (0..40)
            .find_map(|_| {
                let m = diskutil_str(&dev, "MountPoint").filter(|m| !m.is_empty());
                if m.is_none() {
                    std::thread::sleep(std::time::Duration::from_millis(250));
                }
                m
            })
            .unwrap_or_else(|| panic!("{dev} did not mount"));
        let ok = Command::new("ditto")
            .arg(src)
            .arg(&mp)
            .status()
            .unwrap()
            .success();
        assert!(ok, "ditto into {mp}");
    }
    let _ = Command::new("diskutil")
        .args(["unmountDisk", &a.0])
        .output();
    drop(a);
    img
}

fn check_partition(img: &Path, idx: usize, src: &Path, dir: &Path, what: &str) {
    let l = layout(img);
    let (start, size, ..) = l[idx - 1];
    assert_fsck(img, Some(idx), what);
    assert_verify_clean_bytes(img, start * 512, size * 512, what);
    check_mounted(img, Some(idx), size * 512, src, dir);
}

fn partitioned(scheme: &str) {
    if !tools_present() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let src = make_src(dir.path());
    let img = native_disk(dir.path(), scheme, &src);
    let path = img.to_str().unwrap().to_string();
    let guid0 = disk_guid(&img);
    let mbr_sig = slice_bytes(&img, 0, 1)[440..444].to_vec();
    let ident = |img: &Path| -> Vec<(u64, String, Option<String>, Option<uuid::Uuid>)> {
        layout(img)
            .into_iter()
            .filter(|p| !p.2.contains("Apple_Free"))
            .map(|p| (p.0, p.2, p.3, p.4))
            .collect()
    };
    let ident0 = ident(&img);
    // GPT / MBR: slices 1 and 2. APM: entry 1 is the map itself.
    let (a, b) = if scheme == "APM" { (2, 3) } else { (1, 2) };
    check_partition(&img, a, &src, dir.path(), "A before");
    check_partition(&img, b, &src, dir.path(), "B before");

    let bytes_of = |img: &Path, idx: usize| {
        let l = layout(img);
        slice_bytes(img, l[idx - 1].0, l[idx - 1].1)
    };
    let same_ids = |img: &Path, what: &str| {
        assert_eq!(
            ident(img),
            ident0,
            "{scheme} {what}: partition identity changed"
        );
        assert_eq!(disk_guid(img), guid0, "{scheme} {what}: disk GUID changed");
        assert_eq!(
            slice_bytes(img, 0, 1)[440..444],
            mbr_sig[..],
            "{scheme} {what}: MBR disk signature changed"
        );
    };

    // 1. A is boxed in by B: growing it is refused.
    let out = cli_fails(&["resize-fs", &format!("{path}:{a}"), "60m"]);
    assert!(out.contains("refused"), "{out}");

    // 2. B grows into the free space after it, then past the end of the
    //    disk (the image file grows, a GPT backup moves).
    let a_bytes = bytes_of(&img, a);
    let b_big = if scheme == "APM" { 120 * MIB } else { 80 * MIB };
    for size in [b_big, 200 * MIB] {
        cli(&["resize-fs", &format!("{path}:{b}"), &format!("{size}")]);
        let b_now = if scheme == "APM" {
            find(&img, "Apple_HFSX")
        } else {
            b
        };
        assert_eq!(
            bytes_of(&img, a),
            a_bytes,
            "{scheme}: A changed when B grew"
        );
        same_ids(&img, "after growing B");
        assert_eq!(layout(&img)[b_now - 1].1 * 512, size);
        check_partition(&img, b_now, &src, dir.path(), "B grown");
    }
    assert!(std::fs::metadata(&img).unwrap().len() > 128 * MIB);

    // 3. A shrinks (leaving free space before B), then grows back into it.
    let b = if scheme == "APM" {
        find(&img, "Apple_HFSX")
    } else {
        b
    };
    let b_bytes = bytes_of(&img, b);
    for size in [24 * MIB, 32 * MIB] {
        cli(&["resize-fs", &format!("{path}:{a}"), &format!("{size}")]);
        let b_now = if scheme == "APM" {
            find(&img, "Apple_HFSX")
        } else {
            b
        };
        assert_eq!(
            bytes_of(&img, b_now),
            b_bytes,
            "{scheme}: B changed when A resized"
        );
        let ids: Vec<_> = ident(&img);
        assert_eq!(ids, ident0, "{scheme}: identity after resizing A");
        assert_eq!(layout(&img)[a - 1].1 * 512, size);
        check_partition(&img, a, &src, dir.path(), "A resized");
        check_partition(&img, b_now, &src, dir.path(), "B after A resized");
    }

    // 4. B shrinks and the disk image with it.
    let b = if scheme == "APM" {
        find(&img, "Apple_HFSX")
    } else {
        b
    };
    let before = std::fs::metadata(&img).unwrap().len();
    cli(&[
        "resize-fs",
        &format!("{path}:{b}"),
        &format!("{}", 40 * MIB),
        "--shrink-disk",
    ]);
    let after = std::fs::metadata(&img).unwrap().len();
    assert!(
        after < before,
        "{scheme}: disk image not cut ({before} -> {after})"
    );
    let b = if scheme == "APM" {
        find(&img, "Apple_HFSX")
    } else {
        b
    };
    same_ids(&img, "after shrinking B and the disk");
    check_partition(&img, a, &src, dir.path(), "A at the end");
    check_partition(&img, b, &src, dir.path(), "B at the end");
    if scheme == "GPT" {
        let a = attach(&img, true);
        let out = Command::new("diskutil")
            .args(["list", &a.0])
            .output()
            .unwrap();
        assert!(String::from_utf8_lossy(&out.stdout).contains("GUID_partition_scheme"));
        assert!(diskutil_str(&format!("{}s2", a.0), "DiskUUID").is_some());
    }
}

#[test]
fn grow_and_shrink_inside_gpt() {
    partitioned("GPT");
}

#[test]
fn grow_and_shrink_inside_mbr() {
    partitioned("MBR");
}

#[test]
fn grow_and_shrink_inside_apm() {
    partitioned("APM");
}
