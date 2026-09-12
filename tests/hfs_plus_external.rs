#![cfg(all(unix, feature = "hfs-plus"))]
//! HFS+ end-to-end native-tool validation.
//!
//! Round-trips fstool-built images through `fsck.hfs` / `fsck.hfsplus`
//! (the Linux `hfsprogs` package ships the latter spelling), and
//! optionally lets `newfs_hfsplus` format an image that fstool then
//! reads back. Every test skips with a printed reason when the
//! required native tool is missing, mirroring the policy used by
//! `tests/ext4_external.rs`.

use std::io::{Cursor, Read};
use std::path::PathBuf;
use std::process::Command;

use fstool::block::{BlockDevice, FileBackend};
use fstool::fs::hfs_plus::{FormatOpts, HfsPlus};
use tempfile::NamedTempFile;

/// Volume size used by every writer test. 8 MiB is small enough to keep
/// the tests fast but large enough that the default writer layout
/// (allocation file + catalog file + extents-overflow + optional
/// journal stub) fits with plenty of free blocks left over.
const VOL_BYTES: u64 = 8 * 1024 * 1024;

/// Look for `tool` on `$PATH` the same way the ext4 tests do — invoking
/// `command -v` keeps us identical to `tests/ext4_external.rs` without
/// pulling in a new crate.
fn which(tool: &str) -> Option<PathBuf> {
    let out = Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {tool}"))
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?;
    let p = s.trim();
    if p.is_empty() { None } else { Some(p.into()) }
}

/// Locate an `fsck.hfs`-equivalent binary. Linux ships the tool from
/// the `hfsprogs` package as `fsck.hfsplus`; macOS ships it as
/// `fsck.hfs`. Either spelling is acceptable — return the first one
/// we find. Also gate on the tool actually being runnable (some
/// distros ship a broken stub that errors on `-V`).
fn find_fsck_hfs() -> Option<(PathBuf, &'static str)> {
    for (name, label) in [("fsck.hfs", "fsck.hfs"), ("fsck.hfsplus", "fsck.hfsplus")] {
        if let Some(p) = which(name) {
            // Quick sanity check: ask the binary to print its version /
            // banner. We don't care if the exit code is non-zero (some
            // builds return 1 for "no operation"); we only want to
            // confirm the binary is loadable.
            if Command::new(&p).arg("-V").output().is_ok() {
                return Some((p, label));
            }
        }
    }
    // macOS ships Apple's checker as `fsck_hfs`. It refuses plain files
    // ("Can't get device block size"), so `assert_fsck_clean` attaches
    // the image read-only through `hdiutil` first — only offer it when
    // both tools are present.
    if cfg!(target_os = "macos")
        && which("hdiutil").is_some()
        && let Some(p) = which("fsck_hfs")
    {
        return Some((p, "fsck_hfs"));
    }
    None
}

/// Scrape the whole-disk `/dev/diskN` node out of `hdiutil attach
/// -plist` output (same trick as `tests/apfs_external.rs`).
fn parse_hdiutil_whole_disk(plist: &str) -> Option<String> {
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

/// Run Apple's `fsck_hfs -nf` against `image` by attaching it read-only
/// (no mount) with `hdiutil`, checking the device node, and detaching.
/// Returns the process output of the fsck run.
fn fsck_hfs_via_hdiutil(fsck: &std::path::Path, image: &std::path::Path) -> std::process::Output {
    let attach = Command::new("hdiutil")
        .args(["attach", "-nomount", "-readonly", "-plist"])
        .args(["-imagekey", "diskimage-class=CRawDiskImage"])
        .arg(image)
        .output()
        .expect("hdiutil attach");
    assert!(
        attach.status.success(),
        "hdiutil attach failed on {}:\n{}",
        image.display(),
        String::from_utf8_lossy(&attach.stderr)
    );
    let plist = String::from_utf8_lossy(&attach.stdout);
    let dev = parse_hdiutil_whole_disk(&plist).expect("no /dev/diskN in hdiutil output");
    let out = Command::new(fsck).arg("-nf").arg(&dev).output().unwrap();
    let detach = Command::new("hdiutil")
        .args(["detach", "-force"])
        .arg(&dev)
        .output();
    if let Ok(d) = detach
        && !d.status.success()
    {
        eprintln!(
            "warn: hdiutil detach {dev} failed: {}",
            String::from_utf8_lossy(&d.stderr)
        );
    }
    out
}

/// Build an empty fstool-formatted HFS+ image in `tmp` and return the
/// (still-open) device + a handle on the formatted volume.
fn fresh_image(tmp: &NamedTempFile, opts: &FormatOpts) -> (FileBackend, HfsPlus) {
    let mut dev = FileBackend::create(tmp.path(), VOL_BYTES).unwrap();
    let hfs = HfsPlus::format(&mut dev, opts).unwrap();
    (dev, hfs)
}

/// Run `fsck.hfs(plus) -nf <image>` and assert it exits with status 0.
/// `-n` answers "no" to all repair prompts; `-f` forces a check even
/// when the volume already looks clean. The combined flag is what
/// Apple's tool, the macports port, and `hfsprogs` all support.
fn assert_fsck_clean(fsck: &std::path::Path, label: &str, image: &std::path::Path) {
    let out = if label == "fsck_hfs" {
        fsck_hfs_via_hdiutil(fsck, image)
    } else {
        Command::new(fsck).arg("-nf").arg(image).output().unwrap()
    };
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "{label} -nf failed on {}:\nstatus: {}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        image.display(),
        out.status
    );
    // A clean check from either tool prints lines like "The volume
    // appears to be OK". Make sure we did NOT get any of the loud
    // failure markers fsck.hfs(plus) emits when it finds damage.
    let combined = format!("{stdout}\n{stderr}");
    for bad in [
        "Invalid",
        "INVALID",
        "corrupt",
        "CORRUPT",
        "** Repairs are needed",
        "The volume needs to be repaired",
        "could not be verified",
    ] {
        assert!(
            !combined.contains(bad),
            "{label} reported `{bad}` on {}:\n{combined}",
            image.display()
        );
    }
}

/// Fully-loaded writer test: format, populate with a directory tree
/// covering every entry kind we support (regular file, nested dir,
/// symlink, hard link), flush, then validate with `fsck.hfs(-plus)`.
#[test]
fn writer_image_passes_fsck_hfs() {
    let Some((fsck, label)) = find_fsck_hfs() else {
        eprintln!("skipping: fsck.hfs / fsck.hfsplus not installed");
        return;
    };

    let tmp = NamedTempFile::new().unwrap();
    let opts = FormatOpts {
        volume_name: "FstoolHFS".into(),
        ..FormatOpts::default()
    };
    let (mut dev, mut hfs) = fresh_image(&tmp, &opts);

    // /etc + /etc/conf
    hfs.create_dir(&mut dev, "/etc", 0o755, 0, 0, 0).unwrap();
    let body = b"x=1\n";
    let mut src = Cursor::new(&body[..]);
    hfs.create_file(
        &mut dev,
        "/etc/conf",
        &mut src,
        body.len() as u64,
        0o644,
        0,
        0,
        0,
    )
    .unwrap();

    // /readme — bigger file that will exercise several extents
    let big: Vec<u8> = (0..16 * 1024).map(|i| (i & 0xFF) as u8).collect();
    let mut src = Cursor::new(&big[..]);
    hfs.create_file(
        &mut dev,
        "/readme",
        &mut src,
        big.len() as u64,
        0o644,
        0,
        0,
        0,
    )
    .unwrap();

    // /link -> etc/conf  (symlink target is a relative path)
    hfs.create_symlink(&mut dev, "/link", "etc/conf", 0o777, 0, 0, 0)
        .unwrap();

    // /alias hardlinks /readme. Promotion moves /readme into the
    // HFS+ private-data directory as iNode<N>; both names then become
    // hlnk indirect-node entries pointing at that iNode.
    hfs.create_hardlink(&mut dev, "/readme", "/alias").unwrap();

    hfs.flush(&mut dev).unwrap();
    dev.sync().unwrap();
    drop(dev);

    assert_fsck_clean(&fsck, label, tmp.path());
}

/// Format with the journal stub enabled, then ensure `fsck.hfs(-plus)`
/// still considers the volume clean — proves our journal info block +
/// header are coherent enough for the tool to accept them.
#[test]
fn writer_journaled_image_passes_fsck_hfs() {
    let Some((fsck, label)) = find_fsck_hfs() else {
        eprintln!("skipping: fsck.hfs / fsck.hfsplus not installed");
        return;
    };

    let tmp = NamedTempFile::new().unwrap();
    let opts = FormatOpts {
        volume_name: "FstoolJrnl".into(),
        journaled: true,
        ..FormatOpts::default()
    };
    let (mut dev, mut hfs) = fresh_image(&tmp, &opts);

    // Sprinkle a single regular file so the catalog has something to
    // checksum beyond the root thread record.
    let body = b"journaled hello\n";
    let mut src = Cursor::new(&body[..]);
    hfs.create_file(
        &mut dev,
        "/hello.txt",
        &mut src,
        body.len() as u64,
        0o644,
        0,
        0,
        0,
    )
    .unwrap();

    hfs.flush(&mut dev).unwrap();
    dev.sync().unwrap();
    drop(dev);

    assert_fsck_clean(&fsck, label, tmp.path());
}

/// If a native HFS+ formatter is available, format with it and make
/// sure fstool's reader can mount the result + sees an empty root.
/// This is opportunistic — skipped silently when no tool is present.
#[test]
fn newfs_hfsplus_image_opens_via_fstool() {
    let Some(newfs) = which("newfs_hfsplus").or_else(|| which("newfs_hfs")) else {
        eprintln!("skipping: newfs_hfsplus / newfs_hfs not installed");
        return;
    };

    let tmp = NamedTempFile::new().unwrap();
    // newfs needs the file to exist with the right length first; it
    // doesn't grow the backing file itself.
    std::fs::File::create(tmp.path())
        .and_then(|f| f.set_len(VOL_BYTES))
        .unwrap();

    // -v sets the volume label. Both newfs_hfsplus (Linux/hfsprogs)
    // and newfs_hfs (macOS) accept it.
    let out = Command::new(&newfs)
        .arg("-v")
        .arg("ExtHFS")
        .arg(tmp.path())
        .output()
        .unwrap();
    if !out.status.success() {
        // Some hfsprogs builds refuse to operate on plain files. Skip
        // rather than fail the test — we have no way to provide a
        // loop device from inside `cargo test`.
        eprintln!(
            "skipping: {} refused to format image: {}",
            newfs.display(),
            String::from_utf8_lossy(&out.stderr)
        );
        return;
    }

    let mut dev = FileBackend::open(tmp.path()).unwrap();
    let hfs = HfsPlus::open(&mut dev).expect("fstool failed to open newfs image");
    let entries = hfs.list_path(&mut dev, "/").unwrap();
    assert!(
        entries.is_empty(),
        "freshly-formatted root should be empty, got: {entries:?}"
    );
}

/// HFS+ device / FIFO / socket nodes round-trip through the catalog
/// without corrupting the volume. Plants one of each kind under root,
/// flushes, reopens, and confirms `getattr` surfaces the right
/// `EntryKind` plus the `rdev` we stored — encoded the same way fstool
/// encodes elsewhere (`fs::devnum::encode_devnum`). `fsck.hfsplus`
/// stays clean: it doesn't interpret the device-number bytes, only the
/// surrounding catalog structure, so this proves the structural side
/// of the encoder.
#[test]
fn writer_device_nodes_round_trip() {
    let tmp = NamedTempFile::new().unwrap();
    let opts = FormatOpts {
        volume_name: "FstoolDev".into(),
        ..FormatOpts::default()
    };
    let (mut dev, mut hfs) = fresh_image(&tmp, &opts);

    use fstool::fs::DeviceKind;
    // (path, kind, major, minor)
    let plan: [(&str, DeviceKind, u32, u32); 4] = [
        ("/null", DeviceKind::Char, 1, 3),   // /dev/null
        ("/loop0", DeviceKind::Block, 7, 0), // /dev/loop0
        ("/pipe.fifo", DeviceKind::Fifo, 0, 0),
        ("/srv.sock", DeviceKind::Socket, 0, 0),
    ];
    for (path, kind, major, minor) in plan {
        hfs.create_device(&mut dev, path, kind, major, minor, 0o644, 0, 0, 0)
            .unwrap();
    }
    hfs.flush(&mut dev).unwrap();
    dev.sync().unwrap();
    drop(dev);

    // Reopen + inspect via the generic Filesystem trait so we exercise
    // the same path a consumer would.
    let mut dev = FileBackend::open(tmp.path()).unwrap();
    let mut fs = fstool::inspect::open(&mut dev).unwrap();
    use std::path::Path;
    for (path, kind, major, minor) in plan {
        let attrs = fs.getattr(&mut dev, Path::new(path)).unwrap();
        let want_kind = match kind {
            DeviceKind::Char => fstool::fs::EntryKind::Char,
            DeviceKind::Block => fstool::fs::EntryKind::Block,
            DeviceKind::Fifo => fstool::fs::EntryKind::Fifo,
            DeviceKind::Socket => fstool::fs::EntryKind::Socket,
        };
        assert_eq!(attrs.kind, want_kind, "kind mismatch for {path}");
        let expected_rdev = match kind {
            DeviceKind::Char | DeviceKind::Block => fstool::fs::devnum::encode_devnum(major, minor),
            _ => 0,
        };
        assert_eq!(
            attrs.rdev, expected_rdev,
            "rdev mismatch for {path} (kind {kind:?}, major={major}, minor={minor})"
        );
        // Mode bits we requested (0o644) survive in the low bits.
        assert_eq!(
            attrs.mode & 0o777,
            0o644,
            "permission bits got mangled for {path}"
        );
    }
    drop(dev);

    // fsck.hfsplus stays clean.
    if let Some((fsck, label)) = find_fsck_hfs() {
        assert_fsck_clean(&fsck, label, tmp.path());
    } else {
        eprintln!("skipping fsck oracle: not installed");
    }
}

/// Debug helper: dumps mkfs.hfsplus's extents-overflow header bytes
/// alongside ours. Always fails to surface the diff in CI logs.
#[test]
#[ignore = "diagnostic — run explicitly via `cargo test -- --ignored`"]
fn dump_mkfs_vs_fstool_extents_header() {
    // Linux ships the formatter as `mkfs.hfsplus`; macOS as `newfs_hfs`.
    let Some(newfs) = which("mkfs.hfsplus")
        .or_else(|| which("newfs_hfsplus"))
        .or_else(|| which("newfs_hfs"))
    else {
        eprintln!("skipping: no native hfs+ formatter on PATH");
        return;
    };

    // mkfs image
    let mkfs_tmp = NamedTempFile::new().unwrap();
    std::fs::File::create(mkfs_tmp.path())
        .and_then(|f| f.set_len(VOL_BYTES))
        .unwrap();
    let out = Command::new(&newfs)
        .arg("-v")
        .arg("MkfsHFS")
        .arg(mkfs_tmp.path())
        .output()
        .unwrap();
    if !out.status.success() {
        eprintln!(
            "skipping: {} refused to format: {}\n{}",
            newfs.display(),
            String::from_utf8_lossy(&out.stderr),
            String::from_utf8_lossy(&out.stdout),
        );
        return;
    }
    let mkfs_bytes = std::fs::read(mkfs_tmp.path()).unwrap();

    // fstool image — same setup as writer_image_passes_fsck_hfs
    let fstool_tmp = NamedTempFile::new().unwrap();
    {
        let mut dev = FileBackend::create(fstool_tmp.path(), VOL_BYTES).unwrap();
        let opts = FormatOpts {
            volume_name: "FstoolHFS".into(),
            ..FormatOpts::default()
        };
        let mut hfs = HfsPlus::format(&mut dev, &opts).unwrap();
        hfs.flush(&mut dev).unwrap();
        dev.sync().unwrap();
    }
    let fstool_bytes = std::fs::read(fstool_tmp.path()).unwrap();

    // Parse VH offsets for both
    let parse = |buf: &[u8], label: &str| -> String {
        let vh = &buf[1024..1024 + 512];
        let sig = u16::from_be_bytes([vh[0], vh[1]]);
        let bs = u32::from_be_bytes(vh[0x28..0x2C].try_into().unwrap()) as usize;
        let ext_start = u32::from_be_bytes(vh[0xC0 + 16..0xC0 + 20].try_into().unwrap()) as usize;
        let ext_clump = u32::from_be_bytes(vh[0xC0 + 8..0xC0 + 12].try_into().unwrap());
        let ext_total = u32::from_be_bytes(vh[0xC0 + 12..0xC0 + 16].try_into().unwrap());
        let ext_off = ext_start * bs;
        let header_bytes = &buf[ext_off..ext_off + 256];
        let mut s = String::new();
        s += &format!("== {label} ==\n");
        s += &format!(
            "  VH sig=0x{:04x} bs={} ext_start={} ext_clump={} ext_total={}\n",
            sig, bs, ext_start, ext_clump, ext_total
        );
        s += &format!(
            "  header byte 0..32 (descriptor):\n   {:02x?}\n",
            &header_bytes[..32]
        );
        s += &format!(
            "  header byte 32..64 (start of BTHeaderRec):\n   {:02x?}\n",
            &header_bytes[32..64]
        );
        s += &format!("  header byte 64..96:\n   {:02x?}\n", &header_bytes[64..96]);
        s += &format!(
            "  header byte 96..128:\n   {:02x?}\n",
            &header_bytes[96..128]
        );
        s += &format!(
            "  header byte 128..256 (user/map area):\n   {:02x?}\n",
            &header_bytes[128..256]
        );
        // Last 16 bytes (record offsets)
        let ns_field = u16::from_be_bytes(header_bytes[32..34].try_into().unwrap()) as usize;
        let node_end = ext_off + ns_field;
        s += &format!(
            "  nodeSize={} → tail offsets: {:02x?}\n",
            ns_field,
            &buf[node_end - 16..node_end]
        );
        s
    };

    let m = parse(&mkfs_bytes, "mkfs.hfsplus");
    let f = parse(&fstool_bytes, "fstool");
    panic!("\n{m}\n{f}");
}

/// Diagnostic: dumps catalog leaf bytes from the failing test so we can
/// see what's actually on disk that fsck.hfsplus rejects.
#[test]
#[ignore = "diagnostic — run via `cargo test -- --ignored`"]
fn dump_fstool_catalog_leaf() {
    let tmp = NamedTempFile::new().unwrap();
    let opts = FormatOpts {
        volume_name: "FstoolHFS".into(),
        ..FormatOpts::default()
    };
    let (mut dev, mut hfs) = fresh_image(&tmp, &opts);
    hfs.create_dir(&mut dev, "/etc", 0o755, 0, 0, 0).unwrap();
    let body = b"x=1\n";
    let mut src = Cursor::new(&body[..]);
    hfs.create_file(
        &mut dev,
        "/etc/conf",
        &mut src,
        body.len() as u64,
        0o644,
        0,
        0,
        0,
    )
    .unwrap();
    let big: Vec<u8> = (0..16 * 1024).map(|i| (i & 0xFF) as u8).collect();
    let mut src = Cursor::new(&big[..]);
    hfs.create_file(
        &mut dev,
        "/readme",
        &mut src,
        big.len() as u64,
        0o644,
        0,
        0,
        0,
    )
    .unwrap();
    hfs.create_symlink(&mut dev, "/link", "etc/conf", 0o777, 0, 0, 0)
        .unwrap();
    hfs.create_hardlink(&mut dev, "/readme", "/alias").unwrap();
    hfs.flush(&mut dev).unwrap();
    dev.sync().unwrap();
    drop(dev);

    let data = std::fs::read(tmp.path()).unwrap();
    let vh = &data[1024..1024 + 512];
    let bs = u32::from_be_bytes(vh[0x28..0x2C].try_into().unwrap()) as usize;
    let cat_start = u32::from_be_bytes(vh[0x110 + 16..0x110 + 20].try_into().unwrap()) as usize;
    let cat_off = cat_start * bs;
    let h = &data[cat_off..cat_off + 256];
    let node_size = u16::from_be_bytes(h[32..34].try_into().unwrap()) as usize;
    let first_leaf = u32::from_be_bytes(h[24..28].try_into().unwrap()) as usize;
    let leaf_off = cat_off + first_leaf * node_size;
    let n = &data[leaf_off..leaf_off + node_size];
    let num_records = u16::from_be_bytes(n[10..12].try_into().unwrap()) as usize;
    let mut offs = Vec::new();
    for i in 0..(num_records + 1) {
        let p = node_size - 2 * (i + 1);
        offs.push(u16::from_be_bytes(n[p..p + 2].try_into().unwrap()) as usize);
    }
    let mut out = String::new();
    out += &format!(
        "first leaf has {} records, node_size={}\n",
        num_records, node_size
    );
    for i in 0..num_records {
        let s = offs[i];
        let e = offs[i + 1];
        let rec = &n[s..e];
        let key_len = u16::from_be_bytes(rec[0..2].try_into().unwrap()) as usize;
        let parent = u32::from_be_bytes(rec[2..6].try_into().unwrap());
        let name_len = u16::from_be_bytes(rec[6..8].try_into().unwrap()) as usize;
        let mut name = String::new();
        for j in 0..name_len {
            let bo = 8 + 2 * j;
            let u = u16::from_be_bytes(rec[bo..bo + 2].try_into().unwrap());
            if u == 0 {
                name.push_str("\\0");
            } else if u < 0x80 {
                name.push(u as u8 as char);
            } else {
                name.push_str(&format!("\\u{{{:x}}}", u));
            }
        }
        let body_start = 2 + key_len + ((2 + key_len) & 1); // 2-byte align after key
        let body_len = e - s - body_start;
        let rec_type_bytes = &rec[body_start..body_start.min(rec.len() - 2) + 2];
        let rec_type = if rec_type_bytes.len() >= 2 {
            i16::from_be_bytes([rec_type_bytes[0], rec_type_bytes[1]])
        } else {
            -99
        };
        out += &format!(
            "[{i:02}] key_len={key_len} parent={parent} name=\"{name}\" body_start={body_start} body_len={body_len} rec_type={rec_type}\n"
        );
        // Dump first 32 bytes of body
        let body_end = (body_start + 32).min(e - s);
        out += &format!(
            "     body[0..{}]: {:02x?}\n",
            body_end - body_start,
            &rec[body_start..body_end]
        );
    }
    panic!("\n{}", out);
}

/// Large single directory on a volume big enough to exercise both
/// follow-up fixes at once. 6,000 files force several hundred catalog
/// nodes, so the catalog B-tree must grow past the nodes reserved at
/// format (`grow_catalog_fork` appends an extent); and on a ≥512 MiB
/// volume `fsck.hfsplus` enforces the catalog fork's clump size (it must
/// be the ≈0.8%/1 MiB-capped value, not the node size), so this also
/// guards the `btree_clump_size` formula. fsck must stay clean throughout.
#[test]
fn writer_large_directory_grows_catalog_passes_fsck() {
    let Some((fsck, label)) = find_fsck_hfs() else {
        eprintln!("skipping: fsck.hfs / fsck.hfsplus not installed");
        return;
    };
    let tmp = NamedTempFile::new().unwrap();
    // 600 MiB: above the ~512 MiB point where fsck checks the clump size.
    let mut dev = FileBackend::create(tmp.path(), 600 * 1024 * 1024).unwrap();
    let opts = FormatOpts {
        volume_name: "FstoolBig".into(),
        ..FormatOpts::default()
    };
    let mut hfs = HfsPlus::format(&mut dev, &opts).unwrap();
    hfs.create_dir(&mut dev, "/big", 0o755, 0, 0, 0).unwrap();
    for i in 0..6000 {
        let body = b"x";
        let mut src = Cursor::new(&body[..]);
        hfs.create_file(
            &mut dev,
            &format!("/big/file{i:05}"),
            &mut src,
            body.len() as u64,
            0o644,
            0,
            0,
            0,
        )
        .unwrap();
    }
    hfs.flush(&mut dev).unwrap();
    dev.sync().unwrap();
    drop(dev);

    assert_fsck_clean(&fsck, label, tmp.path());

    // Reopen and confirm every entry is listed back.
    let mut dev = FileBackend::open(tmp.path()).unwrap();
    let hfs = HfsPlus::open(&mut dev).unwrap();
    let entries = hfs.list_path(&mut dev, "/big").unwrap();
    let files = entries
        .iter()
        .filter(|e| e.name != "." && e.name != "..")
        .count();
    assert_eq!(files, 6000, "listed {files} of 6000 files in /big");
}

/// xnu's journal checksum (`calc_checksum` in `vfs_journal.c`): the
/// test needs it to re-seal a journal header after rewinding `start`.
fn journal_checksum(buf: &[u8]) -> u32 {
    let mut c: u32 = 0;
    for &b in buf {
        c = (c << 8) ^ c.wrapping_add(u32::from(b));
    }
    !c
}

/// A journaled HFS+ image made by macOS itself (`hdiutil create -fs
/// "Journaled HFS+"`) must open and list. Apple writes the journal header
/// and block lists little-endian with an 8 KiB `blhdr_size` and xnu's
/// byte-wise checksum, none of which matched the writer's own
/// big-endian / CRC assumptions before the fix. The second half forces
/// a replay of the transaction hdiutil left sealed in the ring: rewind
/// `start`, scribble over the blocks it describes, reopen, and check the
/// journal copy came back — then hand the result to `fsck_hfs`.
#[test]
fn hdiutil_journaled_image_opens_and_replays() {
    if !cfg!(target_os = "macos") || which("hdiutil").is_none() {
        eprintln!("skipping: needs macOS hdiutil");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let img = dir.path().join("jhfs.dmg");
    let out = Command::new("hdiutil")
        .args([
            "create",
            "-fs",
            "Journaled HFS+",
            "-layout",
            "NONE",
            "-size",
            "8m",
        ])
        .args(["-volname", "JTest"])
        .arg(&img)
        .output()
        .unwrap();
    if !out.status.success() || !img.exists() {
        eprintln!(
            "skipping: hdiutil create failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        return;
    }

    // 1. Plain open + list.
    {
        let mut dev = FileBackend::open(&img).unwrap();
        let hfs = HfsPlus::open(&mut dev).expect("open hdiutil journaled image");
        let entries = hfs.list_path(&mut dev, "/").unwrap();
        // macOS leaves only its housekeeping entries (.journal,
        // .journal_info_block, the private directories) in the root.
        for e in &entries {
            assert!(
                e.name.starts_with('.') || e.name.contains("HFS+ Private"),
                "unexpected root entry {e:?}"
            );
        }
        assert!(
            entries.iter().any(|e| e.name == ".journal"),
            "expected the .journal file in {entries:?}"
        );
    }

    // 2. Locate the journal and decode its header in whatever byte
    //    order the Mac used.
    let mut bytes = std::fs::read(&img).unwrap();
    let be32 = |b: &[u8], o: usize| u32::from_be_bytes(b[o..o + 4].try_into().unwrap());
    let be64 = |b: &[u8], o: usize| u64::from_be_bytes(b[o..o + 8].try_into().unwrap());
    let bs = be32(&bytes[1024..], 40) as usize;
    let jib = be32(&bytes[1024..], 12) as usize;
    let jbuf = be64(&bytes[jib * bs..], 36) as usize;
    let little = &bytes[jbuf..jbuf + 4] == b"xLNJ";
    assert!(
        little || &bytes[jbuf..jbuf + 4] == b"JNLx",
        "journal magic {:02x?}",
        &bytes[jbuf..jbuf + 4]
    );
    let rd16 = |b: &[u8], o: usize| {
        let a: [u8; 2] = b[o..o + 2].try_into().unwrap();
        if little {
            u16::from_le_bytes(a)
        } else {
            u16::from_be_bytes(a)
        }
    };
    let rd32 = |b: &[u8], o: usize| {
        let a: [u8; 4] = b[o..o + 4].try_into().unwrap();
        if little {
            u32::from_le_bytes(a)
        } else {
            u32::from_be_bytes(a)
        }
    };
    let rd64 = |b: &[u8], o: usize| {
        let a: [u8; 8] = b[o..o + 8].try_into().unwrap();
        if little {
            u64::from_le_bytes(a)
        } else {
            u64::from_be_bytes(a)
        }
    };
    let hdr = bytes[jbuf..jbuf + 48].to_vec();
    let (start, end) = (rd64(&hdr, 8), rd64(&hdr, 16));
    let blhdr = rd32(&hdr, 32) as usize;
    let jhdr = rd32(&hdr, 40) as usize;
    assert_eq!(start, end, "hdiutil leaves the journal sealed");
    if end as usize == jhdr {
        eprintln!("journal ring is empty on this macOS; replay half skipped");
        return;
    }

    // 3. Walk the block lists in [jhdr, end) and remember every target.
    let mut targets: Vec<(usize, Vec<u8>)> = Vec::new();
    let mut pos = jhdr;
    while pos < end as usize {
        let bl = &bytes[jbuf + pos..];
        let num = rd16(bl, 2) as usize;
        let used = rd32(bl, 4) as usize;
        assert!(
            num >= 1 && used >= blhdr,
            "block list at {pos}: num {num} used {used}"
        );
        let mut data = pos + blhdr;
        for i in 1..num {
            let slot = 16 + i * 16;
            let bnum = rd64(bl, slot);
            let bsize = rd32(bl, slot + 8) as usize;
            if bnum != u64::MAX {
                let off = bnum as usize * jhdr;
                targets.push((off, bytes[jbuf + data..jbuf + data + bsize].to_vec()));
            }
            data += bsize;
        }
        pos += used;
    }
    assert!(
        !targets.is_empty(),
        "sealed transaction describes no blocks"
    );

    // 4. Scribble over every described block except the primary volume
    //    header (replay needs it to find the journal), then rewind
    //    `start` with a valid checksum so the journal looks unreplayed.
    let mut scribbled = 0;
    for (off, data) in &targets {
        if *off == 1024 {
            continue;
        }
        bytes[*off..*off + data.len()].fill(0xEE);
        scribbled += 1;
    }
    let mut h = hdr.clone();
    let start_bytes = if little {
        (jhdr as u64).to_le_bytes()
    } else {
        (jhdr as u64).to_be_bytes()
    };
    h[8..16].copy_from_slice(&start_bytes);
    h[36..40].fill(0);
    let ck = journal_checksum(&h[..44]);
    h[36..40].copy_from_slice(&if little {
        ck.to_le_bytes()
    } else {
        ck.to_be_bytes()
    });
    bytes[jbuf..jbuf + 48].copy_from_slice(&h);
    std::fs::write(&img, &bytes).unwrap();

    // 5. Reopen: `HfsPlus::open` replays the ring before reading the
    //    catalog; every scribbled block must carry the journal's copy.
    {
        let mut dev = FileBackend::open(&img).unwrap();
        let hfs = HfsPlus::open(&mut dev).expect("open with a dirty Apple journal");
        assert!(
            hfs.list_path(&mut dev, "/")
                .unwrap()
                .iter()
                .any(|e| e.name == ".journal")
        );
    }
    let after = std::fs::read(&img).unwrap();
    for (off, data) in &targets {
        assert_eq!(
            &after[*off..*off + data.len()],
            &data[..],
            "block at byte {off} restored"
        );
    }
    let hdr2 = &after[jbuf..jbuf + 48];
    assert_eq!(&hdr2[0..4], &hdr[0..4], "byte order preserved");
    assert_eq!(rd64(hdr2, 8), rd64(hdr2, 16), "journal sealed after replay");
    assert_eq!(rd64(hdr2, 16), end, "end untouched by replay");
    let mut z = hdr2[..44].to_vec();
    z[36..40].fill(0);
    assert_eq!(
        rd32(hdr2, 36),
        journal_checksum(&z),
        "rewritten header checksum"
    );
    eprintln!(
        "replayed {scribbled} scribbled blocks out of {}",
        targets.len()
    );

    // 6. Apple's own checker agrees.
    if let Some((fsck, label)) = find_fsck_hfs() {
        assert_fsck_clean(&fsck, label, &img);
    } else {
        eprintln!("skipping fsck oracle: not installed");
    }
}

/// A reopened journaled volume routes its metadata flush through the
/// journal. The format-time ring is only 64 KiB, so a catalog rewrite of
/// a few hundred entries cannot fit in one transaction — the log must
/// split it into several sealed transactions instead of refusing (or
/// silently dropping the flush from `Drop`). Every file must survive and
/// `fsck_hfs` must stay clean.
#[test]
fn writer_journaled_reopen_multi_transaction_flush() {
    let tmp = NamedTempFile::new().unwrap();
    let opts = FormatOpts {
        volume_name: "FstoolJrnl2".into(),
        journaled: true,
        ..FormatOpts::default()
    };
    let (mut dev, mut hfs) = fresh_image(&tmp, &opts);
    hfs.create_dir(&mut dev, "/d", 0o755, 0, 0, 0).unwrap();
    hfs.flush(&mut dev).unwrap();
    dev.sync().unwrap();
    drop(dev);

    // Second session: the on-disk journal header exists now, so this
    // flush is journaled. 400 files need ~30+ catalog nodes plus the
    // bitmap and both volume headers — well over one 56 KiB transaction.
    let mut dev = FileBackend::open(tmp.path()).unwrap();
    let mut hfs = HfsPlus::open(&mut dev).unwrap();
    for i in 0..400 {
        let body = format!("file {i}\n");
        let mut src = Cursor::new(body.as_bytes());
        hfs.create_file(
            &mut dev,
            &format!("/d/file-with-a-longish-name-{i:04}.txt"),
            &mut src,
            body.len() as u64,
            0o644,
            0,
            0,
            0,
        )
        .unwrap();
    }
    hfs.flush(&mut dev).unwrap();
    dev.sync().unwrap();
    drop(dev);

    let mut dev = FileBackend::open(tmp.path()).unwrap();
    let hfs = HfsPlus::open(&mut dev).unwrap();
    let entries = hfs.list_path(&mut dev, "/d").unwrap();
    assert_eq!(entries.len(), 400, "listed {} of 400 files", entries.len());
    let mut got = Vec::new();
    hfs.open_file_reader(&mut dev, "/d/file-with-a-longish-name-0399.txt")
        .unwrap()
        .read_to_end(&mut got)
        .unwrap();
    assert_eq!(got, b"file 399\n");
    // The journal header's sequence_num counts transactions: it starts
    // at 1 on format, so anything above 2 proves the flush was split.
    let mut vh = [0u8; 512];
    dev.read_at(1024, &mut vh).unwrap();
    let bs = u64::from(u32::from_be_bytes(vh[40..44].try_into().unwrap()));
    let jib = u64::from(u32::from_be_bytes(vh[12..16].try_into().unwrap()));
    let mut info = [0u8; 52];
    dev.read_at(jib * bs, &mut info).unwrap();
    let jbuf = u64::from_be_bytes(info[36..44].try_into().unwrap());
    let mut hdr = [0u8; 48];
    dev.read_at(jbuf, &mut hdr).unwrap();
    let seq = u32::from_be_bytes(hdr[44..48].try_into().unwrap());
    assert!(
        seq > 2,
        "expected several transactions, sequence_num is {seq}"
    );
    drop(dev);

    if let Some((fsck, label)) = find_fsck_hfs() {
        assert_fsck_clean(&fsck, label, tmp.path());
    } else {
        eprintln!("skipping fsck oracle: not installed");
    }
}
