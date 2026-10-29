#![cfg(all(target_os = "macos", feature = "hfs-plus"))]
//! Native validation of the HFS+ authoring-metadata API on macOS: build a
//! decorated volume with fstool (Finder info, resource forks, xattrs,
//! normalised names, explicit creation dates, a file added after the
//! identities were read), then check it with `fsck_hfs -fn`, mount it
//! read-only with `hdiutil`, and read everything back through the
//! kernel — `com.apple.FinderInfo` / other xattrs via `xattr`, the
//! resource fork via `..namedfork/rsrc`, and `st_ino` / `st_birthtime`
//! against the CNIDs and dates fstool reported *before* the flush.
//!
//! Skips (with a message) when `hdiutil`, `fsck_hfs` or `xattr` is missing.

use std::io::{Cursor, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use fstool::block::{BlockDevice, FileBackend};
use fstool::fs::hfs_plus::finder::flags;
use fstool::fs::hfs_plus::{FinderInfo, FormatOpts, HfsPlus, hfs_date_from_unix};
use tempfile::{NamedTempFile, TempDir};

const VOL_BYTES: u64 = 32 * 1024 * 1024;

fn which(tool: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {tool}"))
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn tools_present() -> bool {
    ["hdiutil", "fsck_hfs", "xattr"].iter().all(|t| which(t))
}

fn whole_disk(plist: &str) -> Option<String> {
    let mut rest = plist;
    while let Some(i) = rest.find("<string>/dev/disk") {
        let after = &rest[i + "<string>".len()..];
        let j = after.find("</string>")?;
        let dev = after[..j].trim();
        if !dev.trim_start_matches("/dev/disk").contains('s') {
            return Some(dev.to_string());
        }
        rest = &after[j..];
    }
    None
}

/// Detaches the attached image when dropped (also on panic).
struct Attached(String);

impl Drop for Attached {
    fn drop(&mut self) {
        let _ = Command::new("hdiutil")
            .args(["detach", "-force", &self.0])
            .output();
    }
}

fn attach(image: &Path, mountpoint: Option<&Path>) -> Attached {
    let mut cmd = Command::new("hdiutil");
    cmd.args(["attach", "-readonly", "-plist", "-nobrowse"])
        .args(["-imagekey", "diskimage-class=CRawDiskImage"]);
    match mountpoint {
        Some(m) => cmd.arg("-mountpoint").arg(m),
        None => cmd.arg("-nomount"),
    };
    let out = cmd.arg(image).output().expect("hdiutil attach");
    assert!(
        out.status.success(),
        "hdiutil attach failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let dev = whole_disk(&String::from_utf8_lossy(&out.stdout)).expect("no /dev/diskN");
    Attached(dev)
}

fn fsck(image: &Path) {
    let a = attach(image, None);
    let out = Command::new("fsck_hfs")
        .arg("-fn")
        .arg(&a.0)
        .output()
        .unwrap();
    drop(a);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.status.success() && text.contains("appears to be OK"),
        "fsck_hfs -fn failed:\n{text}"
    );
}

/// `xattr -px name path` → bytes, `None` when the attribute is absent.
fn xattr(path: &Path, name: &str) -> Option<Vec<u8>> {
    let out = Command::new("xattr")
        .args(["-px", name])
        .arg(path)
        .output()
        .unwrap();
    if !out.status.success() {
        return None;
    }
    let hex: String = String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .collect();
    Some(
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect(),
    )
}

fn xattr_names(path: &Path) -> Vec<String> {
    let out = Command::new("xattr").arg(path).output().unwrap();
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_string)
        .collect()
}

fn birth_unix(path: &Path) -> i64 {
    let t = std::fs::metadata(path).unwrap().created().unwrap();
    t.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

#[test]
fn decorated_volume_reads_back_through_the_kernel() {
    if !tools_present() {
        eprintln!("skipping: hdiutil / fsck_hfs / xattr not available");
        return;
    }
    let tmp = NamedTempFile::new().unwrap();
    let mut dev = FileBackend::create(tmp.path(), VOL_BYTES).unwrap();
    let vol_date = hfs_date_from_unix(1_600_000_000);
    let mut opts = FormatOpts::default();
    opts.volume_name = "Décor".into(); // normalised like any name
    opts.create_date = vol_date;
    let mut hfs = HfsPlus::format(&mut dev, &opts).unwrap();

    // Tree: an app bundle, a document with Finder info + rsrc + xattrs,
    // tricky names, a symlink and a hard link.
    hfs.create_dir(&mut dev, "/App.app", 0o755, 0, 0, 0)
        .unwrap();
    let doc = b"document body\n";
    let doc_cnid = hfs
        .create_file(
            &mut dev,
            "/App.app/doc.txt",
            &mut Cursor::new(&doc[..]),
            doc.len() as u64,
            0o644,
            0,
            0,
            0,
        )
        .unwrap();
    let doc_date = hfs_date_from_unix(1_650_000_000);
    hfs.set_create_date("/App.app/doc.txt", doc_date).unwrap();

    let mut fi = FinderInfo::default();
    fi.set_file_type(*b"TEXT");
    fi.set_creator(*b"ttxt");
    fi.set_finder_flags(flags::HAS_BEEN_INITED | flags::NAME_LOCKED);
    fi.set_location(40, 120);
    hfs.set_finder_info("/App.app/doc.txt", &fi).unwrap();
    let mut bundle_fi = FinderInfo::default();
    bundle_fi.set_finder_flags(flags::HAS_BUNDLE);
    hfs.set_finder_info("/App.app", &bundle_fi).unwrap();
    let mut root_fi = FinderInfo::default();
    root_fi.set_finder_flags(flags::HAS_CUSTOM_ICON);
    hfs.set_finder_info("/", &root_fi).unwrap();

    let rsrc: Vec<u8> = (0..70_000u32).map(|i| (i * 31 % 256) as u8).collect();
    hfs.write_resource_fork(
        &mut dev,
        "/App.app/doc.txt",
        &mut Cursor::new(&rsrc[..]),
        rsrc.len() as u64,
    )
    .unwrap();
    hfs.set_xattr(&mut dev, "/App.app/doc.txt", "user.small", b"hello")
        .unwrap();
    let big: Vec<u8> = (0..9000u32).map(|i| b'a' + (i % 26) as u8).collect();
    hfs.set_xattr(&mut dev, "/App.app/doc.txt", "com.example.big", &big)
        .unwrap();
    hfs.set_xattr(&mut dev, "/", "com.example.root", b"root-attr")
        .unwrap();
    hfs.set_xattr(&mut dev, "/App.app", "com.example.dir", b"dir-attr")
        .unwrap();

    // Names: NFC input (stored NFD), a Hangul syllable, excluded-range
    // characters that must *not* be decomposed, a `/` (shown as `:`).
    let names = [
        "caf\u{e9}",
        "\u{d55c}\u{ae00}",
        "\u{2126}hm \u{212b}",
        "\u{f900}",
        "a:b",
    ];
    for n in names {
        hfs.create_file(
            &mut dev,
            &format!("/{n}"),
            &mut Cursor::new(&b"n"[..]),
            1,
            0o644,
            0,
            0,
            0,
        )
        .unwrap();
    }
    // Collisions are rejected under the catalog comparator.
    assert!(
        hfs.create_file(
            &mut dev,
            "/CAFE\u{301}",
            &mut Cursor::new(&b""[..]),
            0,
            0o644,
            0,
            0,
            0
        )
        .is_err()
    );

    hfs.create_symlink(&mut dev, "/link", "App.app/doc.txt", 0o755, 0, 0, 0)
        .unwrap();
    let body = b"linked";
    hfs.create_file(
        &mut dev,
        "/hl1",
        &mut Cursor::new(&body[..]),
        body.len() as u64,
        0o644,
        0,
        0,
        0,
    )
    .unwrap();
    let link_ino = hfs.create_hardlink(&mut dev, "/hl1", "/hl2").unwrap();

    // Identities read back *before* the flush …
    let doc_info = hfs.entry_info("/App.app/doc.txt").unwrap();
    assert_eq!(doc_info.cnid, doc_cnid);
    let app_info = hfs.entry_info("/App.app").unwrap();
    let vol_crdate = hfs.volume_create_date().unwrap();
    assert_eq!(vol_crdate, vol_date);
    assert_eq!(hfs.entry_info("/hl2").unwrap().cnid, link_ino);
    // … then a generated file goes in, and only now do we flush.
    let ds = b"\0\0\0\x01Bud1";
    let ds_cnid = hfs
        .create_file(
            &mut dev,
            "/App.app/.DS_Store",
            &mut Cursor::new(&ds[..]),
            ds.len() as u64,
            0o644,
            0,
            0,
            0,
        )
        .unwrap();
    hfs.flush(&mut dev).unwrap();
    assert_eq!(hfs.entry_info("/App.app/doc.txt").unwrap(), doc_info);
    dev.sync().unwrap();
    drop(dev);

    fsck(tmp.path());

    let mnt = TempDir::new().unwrap();
    let _a = attach(tmp.path(), Some(mnt.path()));
    let m = mnt.path();
    let docp: PathBuf = m.join("App.app/doc.txt");

    // Identities and dates.
    assert_eq!(std::fs::metadata(&docp).unwrap().ino(), u64::from(doc_cnid));
    assert_eq!(
        std::fs::metadata(m.join("App.app")).unwrap().ino(),
        u64::from(app_info.cnid)
    );
    assert_eq!(
        std::fs::metadata(m.join("App.app/.DS_Store"))
            .unwrap()
            .ino(),
        u64::from(ds_cnid)
    );
    assert_eq!(std::fs::metadata(m).unwrap().ino(), 2);
    assert_eq!(birth_unix(&docp), 1_650_000_000);
    assert_eq!(birth_unix(m), 1_600_000_000, "volume (root) creation date");
    assert_eq!(
        std::fs::metadata(m.join("hl2")).unwrap().ino(),
        u64::from(link_ino),
        "hard links report the shared iNode's CNID"
    );

    // Finder info (the xattr view hides nothing we set).
    assert_eq!(
        xattr(&docp, "com.apple.FinderInfo").unwrap(),
        fi.to_bytes().to_vec()
    );
    assert_eq!(
        xattr(&m.join("App.app"), "com.apple.FinderInfo").unwrap(),
        bundle_fi.to_bytes().to_vec()
    );
    assert_eq!(
        xattr(m, "com.apple.FinderInfo").unwrap(),
        root_fi.to_bytes().to_vec()
    );

    // Resource fork and xattrs.
    assert_eq!(std::fs::read(docp.join("..namedfork/rsrc")).unwrap(), rsrc);
    assert_eq!(xattr(&docp, "user.small").unwrap(), b"hello");
    assert_eq!(xattr(&docp, "com.example.big").unwrap(), big);
    assert_eq!(xattr(m, "com.example.root").unwrap(), b"root-attr");
    assert_eq!(
        xattr(&m.join("App.app"), "com.example.dir").unwrap(),
        b"dir-attr"
    );
    let listed = xattr_names(&docp);
    for n in [
        "com.apple.FinderInfo",
        "com.apple.ResourceFork",
        "com.example.big",
        "user.small",
    ] {
        assert!(listed.iter().any(|l| l == n), "{n} missing from {listed:?}");
    }

    // Names as the kernel lists them, and lookups by any spelling.
    let listed: Vec<String> = std::fs::read_dir(m)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    for want in [
        "cafe\u{301}",
        "\u{1112}\u{1161}\u{11ab}\u{1100}\u{1173}\u{11af}",
        "\u{2126}hm \u{212b}",
        "\u{f900}",
        "a:b",
    ] {
        assert!(
            listed.iter().any(|l| l == want),
            "{want:?} not in {listed:?}"
        );
    }
    assert!(m.join("caf\u{e9}").exists());
    assert_eq!(
        std::fs::read_link(m.join("link")).unwrap(),
        Path::new("App.app/doc.txt")
    );
    assert_eq!(std::fs::read(m.join("hl1")).unwrap(), body);
    assert_eq!(std::fs::read(m.join("App.app/.DS_Store")).unwrap(), ds);
}

/// Re-open an image macOS itself wrote metadata into (via `hdiutil` +
/// `xattr` / `..namedfork/rsrc` on a read-write mount), confirm fstool
/// reads it, add an entry, flush, and confirm `fsck_hfs` and the kernel
/// still see the original metadata.
#[test]
fn native_metadata_survives_an_fstool_rewrite() {
    if !tools_present() {
        eprintln!("skipping: hdiutil / fsck_hfs / xattr not available");
        return;
    }
    let tmp = NamedTempFile::new().unwrap();
    {
        let mut dev = FileBackend::create(tmp.path(), VOL_BYTES).unwrap();
        let mut opts = FormatOpts::default();
        opts.volume_name = "Native".into();
        let mut hfs = HfsPlus::format(&mut dev, &opts).unwrap();
        hfs.create_file(
            &mut dev,
            "/f",
            &mut Cursor::new(&b"x"[..]),
            1,
            0o644,
            0,
            0,
            0,
        )
        .unwrap();
        hfs.flush(&mut dev).unwrap();
        dev.sync().unwrap();
    }
    // macOS writes the metadata.
    {
        let mnt = TempDir::new().unwrap();
        let out = Command::new("hdiutil")
            .args(["attach", "-plist", "-nobrowse", "-owners", "off"])
            .args(["-imagekey", "diskimage-class=CRawDiskImage", "-mountpoint"])
            .arg(mnt.path())
            .arg(tmp.path())
            .output()
            .unwrap();
        assert!(out.status.success());
        let a = Attached(whole_disk(&String::from_utf8_lossy(&out.stdout)).unwrap());
        let f = mnt.path().join("f");
        let big = "y".repeat(6000);
        for (n, v) in [("user.native", "nv"), ("com.example.nbig", big.as_str())] {
            assert!(
                Command::new("xattr")
                    .args(["-w", n, v])
                    .arg(&f)
                    .status()
                    .unwrap()
                    .success()
            );
        }
        std::fs::write(f.join("..namedfork/rsrc"), b"NATIVE-RSRC").unwrap();
        drop(a);
    }
    let fid;
    {
        let mut dev = FileBackend::open(tmp.path()).unwrap();
        let mut hfs = HfsPlus::open(&mut dev).unwrap();
        fid = hfs.entry_info("/f").unwrap().cnid;
        assert_eq!(
            hfs.get_xattr(&mut dev, "/f", "user.native")
                .unwrap()
                .unwrap(),
            b"nv"
        );
        assert_eq!(
            hfs.get_xattr(&mut dev, "/f", "com.example.nbig")
                .unwrap()
                .unwrap()
                .len(),
            6000
        );
        assert_eq!(
            hfs.get_xattr(&mut dev, "/f", "com.apple.ResourceFork")
                .unwrap()
                .unwrap(),
            b"NATIVE-RSRC"
        );
        hfs.create_file(
            &mut dev,
            "/g",
            &mut Cursor::new(&b"g"[..]),
            1,
            0o644,
            0,
            0,
            0,
        )
        .unwrap();
        hfs.set_xattr(&mut dev, "/g", "user.added", b"a").unwrap();
        hfs.flush(&mut dev).unwrap();
        dev.sync().unwrap();
    }
    fsck(tmp.path());
    let mnt = TempDir::new().unwrap();
    let _a = attach(tmp.path(), Some(mnt.path()));
    let f = mnt.path().join("f");
    assert_eq!(std::fs::metadata(&f).unwrap().ino(), u64::from(fid));
    assert_eq!(xattr(&f, "user.native").unwrap(), b"nv");
    assert_eq!(xattr(&f, "com.example.nbig").unwrap().len(), 6000);
    assert_eq!(
        std::fs::read(f.join("..namedfork/rsrc")).unwrap(),
        b"NATIVE-RSRC"
    );
    assert_eq!(xattr(&mnt.path().join("g"), "user.added").unwrap(), b"a");
}

/// Fragment the free space so an extent-based xattr needs more than
/// eight runs (an `HFSPlusAttrExtents` record) and a resource fork
/// spills into the extents-overflow tree, then let fsck and the kernel
/// read both back. The attributes B-tree is reserved at format time —
/// the documented way to keep it from competing with data for space.
#[test]
fn fragmented_xattr_and_resource_fork_read_back() {
    if !tools_present() {
        eprintln!("skipping: hdiutil / fsck_hfs / xattr not available");
        return;
    }
    let tmp = NamedTempFile::new().unwrap();
    let mut dev = FileBackend::create(tmp.path(), 8 * 1024 * 1024).unwrap();
    let mut opts = FormatOpts::default();
    opts.volume_name = "Frag".into();
    opts.attributes_nodes = 8;
    let mut hfs = HfsPlus::format(&mut dev, &opts).unwrap();
    let bs = u64::from(hfs.block_size());
    let one = vec![7u8; bs as usize];
    for i in 0..41 {
        hfs.create_file(
            &mut dev,
            &format!("/s{i:02}"),
            &mut Cursor::new(&one[..]),
            bs,
            0o644,
            0,
            0,
            0,
        )
        .unwrap();
    }
    hfs.create_file(
        &mut dev,
        "/t",
        &mut Cursor::new(&b"t"[..]),
        1,
        0o644,
        0,
        0,
        0,
    )
    .unwrap();
    let fill = hfs.free_bytes();
    hfs.create_file(
        &mut dev,
        "/filler",
        &mut std::io::repeat(0).take(fill),
        fill,
        0o644,
        0,
        0,
        0,
    )
    .unwrap();
    assert_eq!(hfs.free_bytes(), 0);
    // Free every other one-block file: 20 single-block holes.
    for i in (1..41).step_by(2) {
        hfs.remove(&mut dev, &format!("/s{i:02}")).unwrap();
    }
    assert_eq!(hfs.free_bytes(), 20 * bs);
    let xv: Vec<u8> = (0..10 * bs).map(|i| (i % 253) as u8).collect();
    hfs.set_xattr(&mut dev, "/t", "com.example.frag", &xv)
        .unwrap();
    let rv: Vec<u8> = (0..10 * bs).map(|i| (i % 249) as u8).collect();
    hfs.write_resource_fork(&mut dev, "/t", &mut Cursor::new(&rv[..]), rv.len() as u64)
        .unwrap();
    assert_eq!(hfs.free_bytes(), 0);
    // Out of space is an error, not a silent drop.
    assert!(
        hfs.set_xattr(&mut dev, "/t", "user.more", &vec![1; 5000])
            .is_err()
    );
    hfs.flush(&mut dev).unwrap();
    dev.sync().unwrap();
    drop(dev);

    fsck(tmp.path());
    let mnt = TempDir::new().unwrap();
    let _a = attach(tmp.path(), Some(mnt.path()));
    let t = mnt.path().join("t");
    assert_eq!(xattr(&t, "com.example.frag").unwrap(), xv);
    assert_eq!(std::fs::read(t.join("..namedfork/rsrc")).unwrap(), rv);
}
