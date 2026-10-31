#![cfg(feature = "hybrid")]
// Some helpers and imports serve only the macOS (hdiutil) tests.
#![cfg_attr(not(target_os = "macos"), allow(dead_code, unused_imports))]
//! Native validation of ISO 9660 / Joliet / HFS+ hybrids: independent
//! readers must see the same intended tree and the same payload bytes
//! through every advertised view.
//!
//! * macOS: `hdiutil attach` (raw) mounts the HFS+ view, `mount_cd9660`
//!   the Rock Ridge, Joliet and plain ISO 9660 views of the same device,
//!   `fsck_hfs -fn` checks the HFS+ volume; images from
//!   `hdiutil makehybrid` are read through every fstool view.
//! * With feature `udf`, on macOS: `mount_udf` mounts the UDF view of
//!   fstool's four-view hybrids (every revision) and ISO 9660 + UDF
//!   bridges, `fsck_udf -n` checks them, per-view globs reach UDF, and
//!   `hdiutil makehybrid -udf` images read through fstool's UDF view.
//! * Linux (CI): `xorriso` extracts the Rock Ridge tree, `isoinfo`
//!   lists the Joliet and plain hierarchies, `fsck.hfsplus` checks the
//!   HFS+ partition, `udfinfo` reads the UDF view; with passwordless
//!   `sudo`, the kernel's iso9660, hfsplus and udf drivers mount the
//!   image read-only.
//!
//! Every test skips (with a message) when a tool it needs is missing,
//! and every attach / mount is undone by a guard, also on panic.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use fstool::block::{BlockDevice, FileBackend, SlicedBackend};
use fstool::fs::Filesystem;
use fstool::fs::hfs_plus::HfsPlus;
use fstool::fs::hybrid::{EntryMeta, HybridOptions, HybridPlan, Payload, SourceTree};
use fstool::fs::iso9660::{Iso9660, ReadView};
#[cfg(feature = "udf")]
use fstool::fs::udf::{Udf, UdfRevision};
use tempfile::TempDir;

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

/// One entry of a tree snapshot: a directory, a file's bytes, or a
/// symlink's target.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Snap {
    Dir,
    File(Vec<u8>),
    Link(String),
}

/// Snapshot a host directory (names normalised with `norm`).
fn snapshot(dir: &Path, norm: &dyn Fn(&str) -> String) -> BTreeMap<String, Snap> {
    fn go(dir: &Path, rel: &str, norm: &dyn Fn(&str) -> String, out: &mut BTreeMap<String, Snap>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let e = e.unwrap();
            let name = e.file_name().to_string_lossy().into_owned();
            if rel.is_empty() && (name == ".Trashes" || name == ".fseventsd" || name == ".DS_Store")
            {
                continue;
            }
            let p = format!("{rel}/{}", norm(&name));
            let md = std::fs::symlink_metadata(e.path()).unwrap();
            if md.file_type().is_symlink() {
                let t = std::fs::read_link(e.path()).unwrap();
                out.insert(p, Snap::Link(t.to_string_lossy().into_owned()));
            } else if md.is_dir() {
                out.insert(p.clone(), Snap::Dir);
                go(&e.path(), &p, norm, out);
            } else {
                out.insert(p, Snap::File(std::fs::read(e.path()).unwrap()));
            }
        }
    }
    let mut out = BTreeMap::new();
    go(dir, "", norm, &mut out);
    out
}

/// Snapshot a view through an fstool reader.
fn fs_snapshot(fs: &mut dyn Filesystem, dev: &mut dyn BlockDevice) -> BTreeMap<String, Snap> {
    fn go(
        fs: &mut dyn Filesystem,
        dev: &mut dyn BlockDevice,
        dir: &str,
        out: &mut BTreeMap<String, Snap>,
    ) {
        let list = fs
            .list(dev, Path::new(if dir.is_empty() { "/" } else { dir }))
            .unwrap();
        for e in list {
            if e.name.starts_with('\0') || e.name == ".journal" || e.name == ".journal_info_block" {
                continue;
            }
            let p = format!("{dir}/{}", e.name);
            match fs.getattr(dev, Path::new(&p)).unwrap().kind {
                fstool::fs::EntryKind::Dir => {
                    out.insert(p.clone(), Snap::Dir);
                    go(fs, dev, &p, out);
                }
                fstool::fs::EntryKind::Symlink => {
                    let t = fs.read_symlink(dev, Path::new(&p)).unwrap();
                    out.insert(p, Snap::Link(t.to_string_lossy().into_owned()));
                }
                _ => {
                    let mut v = Vec::new();
                    fs.read_file(dev, Path::new(&p))
                        .unwrap()
                        .read_to_end(&mut v)
                        .unwrap();
                    out.insert(p, Snap::File(v));
                }
            }
        }
    }
    let mut out = BTreeMap::new();
    go(fs, dev, "", &mut out);
    out
}

fn same(name: &str, got: &BTreeMap<String, Snap>, want: &BTreeMap<String, Snap>) {
    let missing: Vec<&String> = want.keys().filter(|k| !got.contains_key(*k)).collect();
    let extra: Vec<&String> = got.keys().filter(|k| !want.contains_key(*k)).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "{name}: missing {missing:?}, unexpected {extra:?}"
    );
    for (k, v) in want {
        assert!(got[k] == *v, "{name}: {k} differs");
    }
}

/// Drop symlinks (for views that cannot hold them).
fn without_links(s: &BTreeMap<String, Snap>) -> BTreeMap<String, Snap> {
    s.iter()
        .filter(|(_, v)| !matches!(v, Snap::Link(_)))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

fn ident(s: &str) -> String {
    s.to_string()
}

fn nfd(s: &str) -> String {
    fstool::fs::hfs_plus::unicode::normalize_name(s)
}

/// A source directory exercising Unicode names, a long name, nesting,
/// a hard link, a symlink, an empty file and a multi-sector payload.
fn make_source() -> TempDir {
    let d = TempDir::new().unwrap();
    let r = d.path();
    std::fs::create_dir_all(r.join("sub/deeper")).unwrap();
    std::fs::create_dir_all(r.join("Ünïcödé dir")).unwrap();
    std::fs::write(r.join("hello.txt"), b"hello hybrid\n").unwrap();
    let big: Vec<u8> = (0..1_234_567u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    std::fs::write(r.join("sub/payload.bin"), &big).unwrap();
    std::fs::write(r.join("sub/deeper/empty"), b"").unwrap();
    std::fs::write(
        r.join("Ünïcödé dir/a rather long file name, with — punctuation ✓.txt"),
        "ünïcode\n".as_bytes(),
    )
    .unwrap();
    std::fs::write(r.join("secret.txt"), b"only on iso\n").unwrap();
    std::fs::hard_link(r.join("hello.txt"), r.join("sub/hello-again.txt")).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("hello.txt", r.join("link")).unwrap();
    d
}

fn build(src: &Path, opts: &HybridOptions, out: &Path) -> HybridPlan {
    let tree = SourceTree::from_host_dir(src).unwrap();
    let plan = HybridPlan::new(tree, opts).unwrap();
    let mut dev = FileBackend::create(out, plan.total_bytes()).unwrap();
    plan.write(&mut dev).unwrap();
    plan.verify(&mut dev).unwrap();
    dev.sync().unwrap();
    plan
}

fn hfs_partition(img: &Path) -> (u64, u64) {
    let mut dev = FileBackend::open_read_only(img).unwrap();
    let apm = fstool::part::Apm::read(&mut dev).unwrap();
    use fstool::part::PartitionTable;
    let p = apm
        .partitions()
        .iter()
        .find(|p| matches!(&p.kind, fstool::part::PartitionKind::Apm(t) if t == "Apple_HFS"))
        .expect("an Apple_HFS partition")
        .clone();
    (p.start_lba * 512, p.size_lba * 512)
}

/// Every view through fstool's own readers, against the source.
fn check_with_fstool(img: &Path, src: &BTreeMap<String, Snap>, hfs_src: &BTreeMap<String, Snap>) {
    let mut dev = FileBackend::open_read_only(img).unwrap();
    let mut iso = Iso9660::open(&mut dev).unwrap();
    iso.set_read_view(ReadView::RockRidge).unwrap();
    same("fstool rock ridge", &fs_snapshot(&mut iso, &mut dev), src);
    iso.set_read_view(ReadView::Joliet).unwrap();
    same(
        "fstool joliet",
        &fs_snapshot(&mut iso, &mut dev),
        &without_links(src),
    );
    let (off, len) = hfs_partition(img);
    let mut slice = SlicedBackend::new(&mut dev, off, len).unwrap();
    let mut hfs = HfsPlus::open(&mut slice).unwrap();
    same("fstool hfs+", &fs_snapshot(&mut hfs, &mut slice), hfs_src);
}

// ---------------------------------------------------------------------
// macOS
// ---------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod macos {
    use super::*;

    /// Detaches the attached image when dropped (also on panic).
    pub(super) struct Attached {
        pub dev: String,
        pub mounts: Vec<String>,
    }

    impl Drop for Attached {
        fn drop(&mut self) {
            for _ in 0..3 {
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
        }
    }

    fn plist_strings(plist: &str, key: &str) -> Vec<String> {
        let mut out = Vec::new();
        let pat = format!("<key>{key}</key>");
        let mut rest = plist;
        while let Some(i) = rest.find(&pat) {
            let after = &rest[i + pat.len()..];
            if let Some(s) = after.find("<string>") {
                let v = &after[s + 8..];
                if let Some(e) = v.find("</string>") {
                    out.push(v[..e].trim().to_string());
                }
            }
            rest = after;
        }
        out
    }

    /// Attach `img` raw and read-only; with `mount_root`, let macOS mount
    /// what it recognises under it.
    pub(super) fn attach(img: &Path, mount_root: Option<&Path>) -> Attached {
        let mut cmd = Command::new("hdiutil");
        cmd.args(["attach", "-plist", "-nobrowse", "-readonly", "-noverify"])
            .args(["-imagekey", "diskimage-class=CRawDiskImage"]);
        match mount_root {
            Some(r) => cmd.arg("-mountrandom").arg(r),
            None => cmd.arg("-nomount"),
        };
        let mut last = String::new();
        for _ in 0..5 {
            let out = cmd.arg(img).output().expect("hdiutil attach");
            if out.status.success() {
                let text = String::from_utf8_lossy(&out.stdout).into_owned();
                let devs = plist_strings(&text, "dev-entry");
                let dev = devs
                    .iter()
                    .find(|d| !d.trim_start_matches("/dev/disk").contains('s'))
                    .expect("whole disk")
                    .clone();
                return Attached {
                    dev,
                    mounts: plist_strings(&text, "mount-point"),
                };
            }
            last = String::from_utf8_lossy(&out.stderr).into_owned();
            // hdiutil sometimes answers EAGAIN under load.
            std::thread::sleep(std::time::Duration::from_secs(1));
            cmd = Command::new("hdiutil");
            cmd.args(["attach", "-plist", "-nobrowse", "-readonly", "-noverify"])
                .args(["-imagekey", "diskimage-class=CRawDiskImage"]);
            match mount_root {
                Some(r) => cmd.arg("-mountrandom").arg(r),
                None => cmd.arg("-nomount"),
            };
        }
        panic!("hdiutil attach failed: {last}");
    }

    /// Unmounts a `mount_cd9660` mount when dropped.
    pub(super) struct Mounted(pub PathBuf);

    impl Drop for Mounted {
        fn drop(&mut self) {
            let _ = Command::new("umount").arg(&self.0).output();
        }
    }

    /// Mount the ISO 9660 side of `dev` (`-r`: no Rock Ridge, `-j`: no
    /// Joliet).
    pub(super) fn mount_cd9660(dev: &str, at: &Path, flags: &[&str]) -> Option<Mounted> {
        let out = Command::new("mount_cd9660")
            .args(flags)
            .args(["-o", "rdonly"])
            .arg(dev)
            .arg(at)
            .output()
            .unwrap();
        if !out.status.success() {
            eprintln!(
                "skipping cd9660 view {flags:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            return None;
        }
        Some(Mounted(at.to_path_buf()))
    }

    pub(super) fn fsck_hfs(slice_dev: &str) {
        let out = Command::new("fsck_hfs")
            .arg("-fn")
            .arg(slice_dev)
            .output()
            .unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            text.contains("appears to be OK"),
            "fsck_hfs -fn {slice_dev}:\n{text}"
        );
    }

    pub(super) fn assert_detached(img: &Path) {
        let out = Command::new("hdiutil").arg("info").output().unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        let name = img.to_string_lossy();
        assert!(
            !text.contains(name.as_ref()),
            "{name} is still attached:\n{text}"
        );
    }
}

/// fstool's hybrid, mounted by macOS: HFS+ by `hdiutil attach`, the
/// ISO 9660 views by `mount_cd9660` on the same device; all show the
/// source tree and bytes; `fsck_hfs` is clean; fstool's readers agree.
#[cfg(target_os = "macos")]
#[test]
fn macos_mounts_every_view_of_an_fstool_hybrid() {
    if !have(&["hdiutil", "fsck_hfs", "mount_cd9660"]) {
        return;
    }
    let src = make_source();
    let work = TempDir::new().unwrap();
    let img = work.path().join("hybrid.iso");
    let mut opts = HybridOptions::new("Hybrid Native");
    opts.create_date = 1_700_000_000;
    let plan = build(src.path(), &opts, &img);
    assert!(plan.wrap().is_some());

    let want = snapshot(src.path(), &ident);
    let want_hfs = snapshot(src.path(), &nfd);
    check_with_fstool(&img, &want, &want_hfs);

    {
        let a = macos::attach(&img, Some(work.path()));
        let hfs_mount = a
            .mounts
            .first()
            .cloned()
            .expect("macOS mounted the HFS+ view");
        same(
            "macOS hfs+",
            &snapshot(Path::new(&hfs_mount), &nfd),
            &want_hfs,
        );
        macos::fsck_hfs(&format!("{}s2", a.dev));

        let rr = work.path().join("rr");
        std::fs::create_dir_all(&rr).unwrap();
        if let Some(_m) = macos::mount_cd9660(&a.dev, &rr, &[]) {
            same("macOS rock ridge", &snapshot(&rr, &ident), &want);
        }
        let j = work.path().join("joliet");
        std::fs::create_dir_all(&j).unwrap();
        if let Some(_m) = macos::mount_cd9660(&a.dev, &j, &["-r"]) {
            // macOS's cd9660 hands Joliet names out decomposed.
            same(
                "macOS joliet",
                &snapshot(&j, &nfd),
                &without_links(&snapshot(src.path(), &nfd)),
            );
        }
        let plain = work.path().join("plain");
        std::fs::create_dir_all(&plain).unwrap();
        if let Some(_m) = macos::mount_cd9660(&a.dev, &plain, &["-r", "-j"]) {
            // Two independent readers of the ECMA-119 hierarchy agree.
            let mut dev = FileBackend::open_read_only(&img).unwrap();
            let mut iso = Iso9660::open(&mut dev).unwrap();
            iso.set_read_view(ReadView::Primary).unwrap();
            let ours = fs_snapshot(&mut iso, &mut dev);
            let theirs = snapshot(&plain, &ident);
            same("macOS plain iso9660", &theirs, &ours);
        }
    }
    macos::assert_detached(&img);
}

/// `--hide-*` / `--only-*`: each native view shows its intended tree.
#[cfg(target_os = "macos")]
#[test]
fn macos_sees_per_view_trees() {
    if !have(&["hdiutil", "fsck_hfs", "mount_cd9660"]) {
        return;
    }
    let src = make_source();
    let work = TempDir::new().unwrap();
    let img = work.path().join("globs.iso");
    let mut opts = HybridOptions::new("Globs");
    opts.hfs.hide.push("*.bin".into());
    opts.joliet.hide.push("/sub".into());
    opts.iso.only.push("secret.txt".into());
    build(src.path(), &opts, &img);
    let all = snapshot(src.path(), &ident);
    let drop = |s: &BTreeMap<String, Snap>, f: &dyn Fn(&str) -> bool| {
        s.iter()
            .filter(|(k, _)| !f(k))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<BTreeMap<_, _>>()
    };
    let want_rr = all.clone();
    let want_j = drop(&without_links(&all), &|k| {
        k == "/sub" || k.starts_with("/sub/") || k == "/secret.txt"
    });
    let want_hfs = drop(&snapshot(src.path(), &nfd), &|k| {
        k.ends_with(".bin") || k == "/secret.txt"
    });
    {
        let a = macos::attach(&img, Some(work.path()));
        let m = a.mounts.first().cloned().expect("HFS+ mounted");
        same("macOS hfs+", &snapshot(Path::new(&m), &nfd), &want_hfs);
        macos::fsck_hfs(&format!("{}s2", a.dev));
        let rr = work.path().join("rr");
        std::fs::create_dir_all(&rr).unwrap();
        if let Some(_m) = macos::mount_cd9660(&a.dev, &rr, &[]) {
            same("macOS rock ridge", &snapshot(&rr, &ident), &want_rr);
        }
        let j = work.path().join("j");
        std::fs::create_dir_all(&j).unwrap();
        if let Some(_m) = macos::mount_cd9660(&a.dev, &j, &["-r"]) {
            let want_j: BTreeMap<String, Snap> =
                want_j.iter().map(|(k, v)| (nfd(k), v.clone())).collect();
            same("macOS joliet", &snapshot(&j, &nfd), &want_j);
        }
    }
    macos::assert_detached(&img);
}

/// Images from `hdiutil makehybrid` read correctly through every fstool
/// view, and have the same structure as fstool's: an APM whose
/// `Apple_HFS` partition starts after the ISO 9660 metadata and holds
/// the file data both views share.
#[cfg(target_os = "macos")]
#[test]
fn fstool_reads_hdiutil_makehybrid_images() {
    if !have(&["hdiutil"]) {
        return;
    }
    let src = make_source();
    let work = TempDir::new().unwrap();
    let theirs = work.path().join("makehybrid.iso");
    let out = Command::new("hdiutil")
        .args(["makehybrid", "-iso", "-joliet", "-hfs", "-ov", "-o"])
        .arg(&theirs)
        .arg(src.path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "makehybrid: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let ours = work.path().join("fstool.iso");
    build(src.path(), &HybridOptions::new("Same"), &ours);

    let want = snapshot(src.path(), &ident);
    let want_hfs = snapshot(src.path(), &nfd);
    for img in [&theirs, &ours] {
        let mut dev = FileBackend::open_read_only(img).unwrap();
        // Structure: APM + PVD at 16, partition after the ISO metadata,
        // ISO file extents inside the partition.
        assert!(fstool::part::Apm::probe(&mut dev), "{}", img.display());
        let (off, len) = hfs_partition(img);
        let mut iso = Iso9660::open(&mut dev).unwrap();
        assert!(
            u64::from(iso.pvd.volume_space_size) * 2048 >= off + len,
            "{}: the ISO volume covers the HFS+ partition",
            img.display()
        );
        assert!(iso.pvd.root.extent_lba as u64 * 2048 < off);
        iso.set_read_view(ReadView::Joliet).unwrap();
        let list = iso.list(&mut dev, Path::new("/sub")).unwrap();
        let p = list.iter().find(|e| e.name == "payload.bin").unwrap();
        let at = u64::from(p.inode) * 2048;
        assert!(
            at >= off && at < off + len,
            "{}: payload at {at} outside the HFS+ partition {off}+{len}",
            img.display()
        );
        // makehybrid records the symlink in Joliet too (as a file);
        // fstool leaves it out (and reports it).
        let mut got = fs_snapshot(&mut iso, &mut dev);
        got.remove("/link");
        same(
            &format!("joliet of {}", img.display()),
            &got,
            &without_links(&want),
        );
        let mut slice = SlicedBackend::new(&mut dev, off, len).unwrap();
        let mut hfs = HfsPlus::open(&mut slice).unwrap();
        same(
            &format!("hfs+ of {}", img.display()),
            &fs_snapshot(&mut hfs, &mut slice),
            &want_hfs,
        );
    }
}

// ---------------------------------------------------------------------
// Linux tools (CI) — skip without them.
// ---------------------------------------------------------------------

fn tool_source_and_image() -> (TempDir, TempDir, PathBuf, HybridPlan) {
    let src = make_source();
    let work = TempDir::new().unwrap();
    let img = work.path().join("hybrid.iso");
    #[allow(unused_mut)]
    let mut opts = HybridOptions::new("Hybrid CI");
    // The ISO 9660 and HFS+ tools must be happy with a UDF view beside
    // their own.
    #[cfg(feature = "udf")]
    {
        opts.udf.enabled = true;
    }
    let plan = build(src.path(), &opts, &img);
    (src, work, img, plan)
}

/// `xorriso` extracts the Rock Ridge tree byte-identical to the source.
#[test]
fn xorriso_extracts_the_rock_ridge_view() {
    if !have(&["xorriso"]) {
        return;
    }
    let (src, work, img, _) = tool_source_and_image();
    let out_dir = work.path().join("extract");
    let out = Command::new("xorriso")
        .args(["-osirrox", "on", "-indev"])
        .arg(&img)
        .args(["-extract", "/"])
        .arg(&out_dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "xorriso: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    same(
        "xorriso rock ridge",
        &snapshot(&out_dir, &ident),
        &snapshot(src.path(), &ident),
    );
    // xorriso's own check of the image.
    let out = Command::new("xorriso")
        .args(["-indev"])
        .arg(&img)
        .args(["-find", "/", "-exec", "lsdl"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("payload.bin") && text.contains("-> 'hello.txt'"),
        "{text}"
    );
}

fn isoinfo_paths(img: &Path, flags: &[&str]) -> Vec<String> {
    let out = Command::new("isoinfo")
        .args(flags)
        .arg("-f")
        .arg("-i")
        .arg(img)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "isoinfo: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut v: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| l.trim().trim_end_matches(";1").to_string())
        .filter(|l| !l.is_empty())
        .collect();
    v.sort();
    v
}

/// `isoinfo` lists the Joliet, Rock Ridge and plain hierarchies.
#[test]
fn isoinfo_lists_every_iso_view() {
    if !have(&["isoinfo"]) {
        return;
    }
    let (src, _work, img, _) = tool_source_and_image();
    let want: Vec<String> = snapshot(src.path(), &ident).keys().cloned().collect();
    assert_eq!(isoinfo_paths(&img, &["-R"]), want, "rock ridge");
    let want_j: Vec<String> = without_links(&snapshot(src.path(), &ident))
        .keys()
        .cloned()
        .collect();
    // genisoimage's isoinfo has no UTF-8 output charset: it prints
    // Latin-1 characters as raw bytes and others as `_`. Compare with
    // every non-ASCII character (and `_`) masked as `?` on both sides.
    let mask = |v: Vec<String>| -> Vec<String> {
        let mut v: Vec<String> = v
            .into_iter()
            .map(|p| {
                p.chars()
                    .map(|c| if c.is_ascii() && c != '_' { c } else { '?' })
                    .collect()
            })
            .collect();
        v.sort();
        v
    };
    assert_eq!(mask(isoinfo_paths(&img, &["-J"])), mask(want_j), "joliet");
    // The plain hierarchy holds every entry (symlinks as empty files).
    assert_eq!(isoinfo_paths(&img, &[]).len(), want.len(), "plain");
    let out = Command::new("isoinfo")
        .args(["-d", "-i"])
        .arg(&img)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("Rock Ridge signatures version"), "{text}");
    assert!(text.contains("Joliet with UCS level 3"), "{text}");
}

/// `fsck.hfsplus` on the HFS+ partition, cut out of the image.
#[test]
fn fsck_hfsplus_checks_the_hfs_partition() {
    if cfg!(target_os = "macos") || !have(&["fsck.hfsplus"]) {
        return;
    }
    let (_src, work, img, _) = tool_source_and_image();
    let (off, len) = hfs_partition(&img);
    let bytes = std::fs::read(&img).unwrap();
    let part = work.path().join("hfs.img");
    std::fs::write(&part, &bytes[off as usize..(off + len) as usize]).unwrap();
    let out = Command::new("fsck.hfsplus")
        .args(["-n", "-f"])
        .arg(&part)
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.status.success() && text.contains("appears to be OK"),
        "{text}"
    );
}

#[cfg(target_os = "linux")]
fn sudo_ok() -> bool {
    Command::new("sudo")
        .args(["-n", "true"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Unmounts a `sudo mount` when dropped.
#[cfg(target_os = "linux")]
struct SudoMount(PathBuf);

#[cfg(target_os = "linux")]
impl Drop for SudoMount {
    fn drop(&mut self) {
        let _ = Command::new("sudo").arg("umount").arg(&self.0).output();
    }
}

#[cfg(target_os = "linux")]
fn sudo_mount(args: &[&str], img: &Path, at: &Path) -> Option<SudoMount> {
    let out = Command::new("sudo")
        .args(["-n", "mount"])
        .args(args)
        .arg(img)
        .arg(at)
        .output()
        .unwrap();
    if !out.status.success() {
        eprintln!(
            "skipping mount {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        return None;
    }
    Some(SudoMount(at.to_path_buf()))
}

/// The Linux kernel's iso9660 (Rock Ridge, Joliet) and hfsplus drivers.
#[cfg(target_os = "linux")]
#[test]
fn linux_kernel_mounts_every_view() {
    if !sudo_ok() {
        eprintln!("skipping: no passwordless sudo");
        return;
    }
    let (src, work, img, _) = tool_source_and_image();
    let want = snapshot(src.path(), &ident);
    let rr = work.path().join("rr");
    std::fs::create_dir_all(&rr).unwrap();
    if let Some(_m) = sudo_mount(&["-o", "loop,ro", "-t", "iso9660"], &img, &rr) {
        same("linux rock ridge", &snapshot(&rr, &ident), &want);
    }
    let j = work.path().join("j");
    std::fs::create_dir_all(&j).unwrap();
    if let Some(_m) = sudo_mount(&["-o", "loop,ro,norock", "-t", "iso9660"], &img, &j) {
        same("linux joliet", &snapshot(&j, &ident), &without_links(&want));
    }
    let h = work.path().join("hfs");
    std::fs::create_dir_all(&h).unwrap();
    let (off, len) = hfs_partition(&img);
    let opt = format!("loop,ro,offset={off},sizelimit={len}");
    if let Some(_m) = sudo_mount(&["-o", &opt, "-t", "hfsplus"], &img, &h) {
        same(
            "linux hfsplus",
            &snapshot(&h, &nfd),
            &snapshot(src.path(), &nfd),
        );
    }
}

/// The CLI writes through a temporary sibling, refuses to overwrite
/// without `--force`, and `--dry-run` writes nothing.
#[cfg(feature = "cli")]
#[test]
fn cli_makehybrid() {
    let src = make_source();
    let work = TempDir::new().unwrap();
    let out = work.path().join("cli.iso");
    let bin = env!("CARGO_BIN_EXE_fstool");
    let run = |extra: &[&str]| {
        Command::new(bin)
            .arg("makehybrid")
            .arg(src.path())
            .arg("-o")
            .arg(&out)
            .args(["--create-date", "0"])
            .args(extra)
            .output()
            .unwrap()
    };
    let r = run(&["--dry-run"]);
    assert!(r.status.success(), "{}", String::from_utf8_lossy(&r.stderr));
    assert!(!out.exists());
    let text = String::from_utf8_lossy(&r.stdout);
    #[cfg(feature = "udf")]
    assert!(text.contains("views: iso9660, joliet, hfs+, udf"), "{text}");
    #[cfg(not(feature = "udf"))]
    assert!(text.contains("views: iso9660, joliet, hfs+"), "{text}");
    let r = run(&["--hide-hfs", "*.bin", "-V", "Cli Test", "--iso-level", "3"]);
    assert!(r.status.success(), "{}", String::from_utf8_lossy(&r.stderr));
    assert!(out.exists());
    let leftovers: Vec<_> = std::fs::read_dir(work.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .filter(|n| n.to_string_lossy().contains("fstool-tmp"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
    assert!(!run(&[]).status.success(), "overwrote without --force");
    assert!(run(&["--force", "--iso"]).status.success());
    let mut dev = FileBackend::open_read_only(&out).unwrap();
    assert!(
        !fstool::part::Apm::probe(&mut dev),
        "--iso alone has no HFS+"
    );
    drop(dev);
    #[cfg(feature = "udf")]
    {
        let r = run(&[
            "--force",
            "--iso",
            "--udf",
            "--udf-version",
            "2.01",
            "--udf-volume-name",
            "Cli UDF",
            "--hide-udf",
            "*.bin",
            "--only-udf",
            "secret.txt",
        ]);
        assert!(r.status.success(), "{}", String::from_utf8_lossy(&r.stderr));
        let mut dev = FileBackend::open_read_only(&out).unwrap();
        let mut udf = Udf::open(&mut dev).unwrap();
        assert_eq!(udf.volume_label(), "Cli UDF");
        assert_eq!(udf.info().unwrap().udf_revision, 0x0201);
        let names: Vec<String> = udf
            .list(&mut dev, Path::new("/sub"))
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert!(!names.contains(&"payload.bin".to_string()), "{names:?}");
        assert!(udf.getattr(&mut dev, Path::new("/secret.txt")).is_ok());
        let mut iso = Iso9660::open(&mut dev).unwrap();
        assert!(iso.getattr(&mut dev, Path::new("/secret.txt")).is_err());
        assert!(iso.getattr(&mut dev, Path::new("/sub/payload.bin")).is_ok());
        let r = run(&["--force", "--udf-version", "3.0", "--dry-run"]);
        assert!(!r.status.success());
    }
}

/// A tree built by hand (the library path), with a payload too long for
/// its declared length, is refused at write time with a typed error.
#[test]
fn payload_length_is_checked_at_write() {
    let mut t = SourceTree::new();
    t.add_file(
        "/f",
        Payload::Bytes(Arc::from(&b"longer than declared"[..])),
        4,
        EntryMeta::default(),
    )
    .unwrap();
    let plan = HybridPlan::new(t, &HybridOptions::new("Len")).unwrap();
    let mut dev = fstool::block::MemoryBackend::new(plan.total_bytes());
    assert!(matches!(
        plan.write(&mut dev),
        Err(fstool::fs::hybrid::HybridError::PayloadLength { .. })
    ));
}

// ---------------------------------------------------------------------
// The UDF view (feature `udf`).
// ---------------------------------------------------------------------

/// Hybrid options with the UDF view on.
#[cfg(feature = "udf")]
fn udf_opts(name: &str, rev: UdfRevision) -> HybridOptions {
    let mut o = HybridOptions::new(name);
    o.create_date = 1_700_000_000;
    o.udf.enabled = true;
    o.udf.revision = rev;
    o
}

/// The UDF view through fstool's reader.
#[cfg(feature = "udf")]
fn udf_snapshot(img: &Path) -> BTreeMap<String, Snap> {
    let mut dev = FileBackend::open_read_only(img).unwrap();
    let mut udf = Udf::open(&mut dev).unwrap();
    fs_snapshot(&mut udf, &mut dev)
}

/// `(partition start, length)` in sectors of the UDF partition, and
/// the anchors found at 256 and N-1 — read straight off the image.
#[cfg(feature = "udf")]
fn udf_layout(img: &Path) -> (u64, u64, bool, bool) {
    let bytes = std::fs::read(img).unwrap();
    let n = bytes.len() / 2048;
    let tag = |s: usize| u16::from_le_bytes([bytes[s * 2048], bytes[s * 2048 + 1]]);
    let anchor_256 = tag(256) == 2;
    let anchor_end = tag(n - 1) == 2 || tag(n - 257) == 2;
    // The main VDS from the anchor at 256; its Partition Descriptor.
    let a = 256 * 2048;
    let main = u32::from_le_bytes(bytes[a + 20..a + 24].try_into().unwrap()) as usize;
    for s in main..main + 16 {
        if tag(s) == 5 {
            let o = s * 2048;
            let start = u32::from_le_bytes(bytes[o + 188..o + 192].try_into().unwrap());
            let len = u32::from_le_bytes(bytes[o + 192..o + 196].try_into().unwrap());
            return (u64::from(start), u64::from(len), anchor_256, anchor_end);
        }
    }
    panic!("{}: no UDF partition descriptor", img.display());
}

/// The UDF recognition sequence follows the ISO 9660 terminator.
#[cfg(feature = "udf")]
fn vrs_after_terminator(img: &Path) -> bool {
    let bytes = std::fs::read(img).unwrap();
    let mut s = 16;
    while &bytes[s * 2048 + 1..s * 2048 + 6] == b"CD001" {
        if bytes[s * 2048] == 255 {
            let next = &bytes[(s + 1) * 2048 + 1..(s + 1) * 2048 + 6];
            return next == b"BEA01";
        }
        s += 1;
    }
    false
}

#[cfg(all(target_os = "macos", feature = "udf"))]
mod macos_udf {
    use super::*;

    pub(super) fn mount_udf(dev: &str, at: &Path) -> macos::Mounted {
        std::fs::create_dir_all(at).unwrap();
        let mut last = String::new();
        for _ in 0..5 {
            let out = Command::new("/sbin/mount_udf")
                .args(["-o", "rdonly"])
                .arg(dev)
                .arg(at)
                .output()
                .unwrap();
            if out.status.success() {
                return macos::Mounted(at.to_path_buf());
            }
            last = String::from_utf8_lossy(&out.stderr).into_owned();
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        panic!("mount_udf {dev}: {last}");
    }

    pub(super) fn fsck_udf(img: &Path) {
        let out = Command::new("/sbin/fsck_udf")
            .arg("-n")
            .arg(img)
            .output()
            .unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            out.status.success() && text.contains("is clean") && !text.contains("* * *"),
            "fsck_udf -n {}:\n{text}",
            img.display()
        );
    }
}

/// Parallel attaches make hdiutil answer EAGAIN; the UDF tests take turns.
#[cfg(all(target_os = "macos", feature = "udf"))]
static UDF_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// fstool's ISO 9660 + Joliet + HFS+ + UDF hybrid, every revision:
/// macOS mounts HFS+ on attach, `mount_udf` the UDF view of the same
/// device, `mount_cd9660` the ISO 9660 views; every one shows the source
/// tree with the same bytes; `fsck_udf -n` and `fsck_hfs -fn` are clean.
#[cfg(all(target_os = "macos", feature = "udf"))]
#[test]
fn macos_mounts_every_view_of_an_fstool_udf_hybrid() {
    if !have(&[
        "hdiutil",
        "fsck_hfs",
        "mount_cd9660",
        "/sbin/mount_udf",
        "/sbin/fsck_udf",
    ]) {
        return;
    }
    let _g = UDF_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let src = make_source();
    let want = snapshot(src.path(), &ident);
    let want_hfs = snapshot(src.path(), &nfd);
    for &rev in UdfRevision::WRITABLE {
        eprintln!("UDF {rev}");
        let work = TempDir::new().unwrap();
        let img = work.path().join(format!("hybrid-udf-{rev}.iso"));
        let plan = build(src.path(), &udf_opts("Hybrid UDF", rev), &img);
        assert!(plan.wrap().is_some());
        check_with_fstool(&img, &want, &want_hfs);
        same("fstool udf", &udf_snapshot(&img), &want);
        assert!(vrs_after_terminator(&img));
        let (start, len, a256, aend) = udf_layout(&img);
        assert!(a256 && aend, "anchors");
        let (off, hlen) = hfs_partition(&img);
        assert!(
            start * 2048 <= off + hlen && (start + len) * 2048 >= off + hlen,
            "the UDF partition {start}+{len} spans the HFS+ payloads"
        );
        macos_udf::fsck_udf(&img);
        {
            let a = macos::attach(&img, Some(work.path()));
            let hfs_mount = a.mounts.first().cloned().expect("HFS+ mounted");
            same(
                "macOS hfs+",
                &snapshot(Path::new(&hfs_mount), &nfd),
                &want_hfs,
            );
            macos::fsck_hfs(&format!("{}s2", a.dev));
            let u = work.path().join("udf");
            {
                let _m = macos_udf::mount_udf(&a.dev, &u);
                same("macOS udf", &snapshot(&u, &nfd), &want_hfs);
            }
            let rr = work.path().join("rr");
            std::fs::create_dir_all(&rr).unwrap();
            if let Some(_m) = macos::mount_cd9660(&a.dev, &rr, &[]) {
                same("macOS rock ridge", &snapshot(&rr, &ident), &want);
            }
            let j = work.path().join("joliet");
            std::fs::create_dir_all(&j).unwrap();
            if let Some(_m) = macos::mount_cd9660(&a.dev, &j, &["-r"]) {
                same(
                    "macOS joliet",
                    &snapshot(&j, &nfd),
                    &without_links(&want_hfs),
                );
            }
        }
        macos::assert_detached(&img);
    }
}

/// An ISO 9660 + Joliet + UDF bridge (no HFS+, no partition map):
/// `mount_udf` and `mount_cd9660` on the attached device.
#[cfg(all(target_os = "macos", feature = "udf"))]
#[test]
fn macos_mounts_an_iso_udf_bridge() {
    if !have(&[
        "hdiutil",
        "mount_cd9660",
        "/sbin/mount_udf",
        "/sbin/fsck_udf",
    ]) {
        return;
    }
    let _g = UDF_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let src = make_source();
    let want = snapshot(src.path(), &ident);
    let want_nfd = snapshot(src.path(), &nfd);
    for rev in [UdfRevision::V1_02, UdfRevision::V2_01] {
        let work = TempDir::new().unwrap();
        let img = work.path().join(format!("bridge-{rev}.iso"));
        let mut opts = udf_opts("Bridge", rev);
        opts.hfs.enabled = false;
        let plan = build(src.path(), &opts, &img);
        assert!(plan.wrap().is_none());
        assert!(vrs_after_terminator(&img));
        same("fstool udf", &udf_snapshot(&img), &want);
        macos_udf::fsck_udf(&img);
        {
            let a = macos::attach(&img, None);
            let u = work.path().join("udf");
            {
                let _m = macos_udf::mount_udf(&a.dev, &u);
                same("macOS udf", &snapshot(&u, &nfd), &want_nfd);
            }
            let rr = work.path().join("rr");
            std::fs::create_dir_all(&rr).unwrap();
            if let Some(_m) = macos::mount_cd9660(&a.dev, &rr, &[]) {
                same("macOS rock ridge", &snapshot(&rr, &ident), &want);
            }
        }
        macos::assert_detached(&img);
    }
}

/// `hide` / `only` on the UDF view, seen through macOS's UDF driver.
#[cfg(all(target_os = "macos", feature = "udf"))]
#[test]
fn macos_sees_per_view_trees_with_udf() {
    if !have(&[
        "hdiutil",
        "mount_cd9660",
        "/sbin/mount_udf",
        "/sbin/fsck_udf",
    ]) {
        return;
    }
    let _g = UDF_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let src = make_source();
    let work = TempDir::new().unwrap();
    let img = work.path().join("udf-globs.iso");
    let mut opts = udf_opts("UDF Globs", UdfRevision::V1_50);
    opts.udf.hide.push("/sub/deeper".into());
    opts.udf.only.push("payload.bin".into());
    opts.iso.only.push("secret.txt".into());
    build(src.path(), &opts, &img);
    let drop = |s: &BTreeMap<String, Snap>, f: &dyn Fn(&str) -> bool| {
        s.iter()
            .filter(|(k, _)| !f(k))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<BTreeMap<_, _>>()
    };
    let all = snapshot(src.path(), &ident);
    let want_udf = drop(&snapshot(src.path(), &nfd), &|k| {
        k.starts_with("/sub/deeper") || k == "/secret.txt"
    });
    let want_rr = drop(&all, &|k| k == "/sub/payload.bin");
    let want_hfs = drop(&snapshot(src.path(), &nfd), &|k| {
        k == "/sub/payload.bin" || k == "/secret.txt"
    });
    let nfc_udf: BTreeMap<String, Snap> = drop(&all, &|k| {
        k.starts_with("/sub/deeper") || k == "/secret.txt"
    });
    same("fstool udf", &udf_snapshot(&img), &nfc_udf);
    macos_udf::fsck_udf(&img);
    {
        let a = macos::attach(&img, Some(work.path()));
        let m = a.mounts.first().cloned().expect("HFS+ mounted");
        same("macOS hfs+", &snapshot(Path::new(&m), &nfd), &want_hfs);
        let u = work.path().join("udf");
        {
            let _m = macos_udf::mount_udf(&a.dev, &u);
            same("macOS udf", &snapshot(&u, &nfd), &want_udf);
        }
        let rr = work.path().join("rr");
        std::fs::create_dir_all(&rr).unwrap();
        if let Some(_m) = macos::mount_cd9660(&a.dev, &rr, &[]) {
            same("macOS rock ridge", &snapshot(&rr, &ident), &want_rr);
        }
    }
    macos::assert_detached(&img);
}

/// `hdiutil makehybrid -iso -joliet -hfs -udf -udf-version 1.50` reads
/// through every fstool view, UDF included, and has the structure
/// fstool's own four-view hybrid has: the UDF recognition sequence after
/// the ISO 9660 terminator, an anchor at 256 and one at the end, and a
/// UDF partition spanning the HFS+ partition's shared payloads.
#[cfg(all(target_os = "macos", feature = "udf"))]
#[test]
fn fstool_reads_hdiutil_makehybrid_udf_images() {
    if !have(&["hdiutil"]) {
        return;
    }
    let _g = UDF_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let src = make_source();
    let work = TempDir::new().unwrap();
    let theirs = work.path().join("makehybrid-udf.iso");
    let out = Command::new("hdiutil")
        .args([
            "makehybrid",
            "-iso",
            "-joliet",
            "-hfs",
            "-udf",
            "-udf-version",
            "1.50",
            "-ov",
            "-o",
        ])
        .arg(&theirs)
        .arg(src.path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "makehybrid: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let ours = work.path().join("fstool-udf.iso");
    build(src.path(), &udf_opts("Same", UdfRevision::V1_50), &ours);
    let want = snapshot(src.path(), &ident);
    let want_hfs = snapshot(src.path(), &nfd);
    for img in [&theirs, &ours] {
        let name = img.display().to_string();
        assert!(vrs_after_terminator(img), "{name}");
        let (start, len, a256, aend) = udf_layout(img);
        assert!(a256 && aend, "{name}: anchors");
        let (off, hlen) = hfs_partition(img);
        let mut dev = FileBackend::open_read_only(img).unwrap();
        let mut udf = Udf::open(&mut dev).unwrap();
        assert_eq!(udf.info().unwrap().udf_revision, 0x0150, "{name}");
        // The UDF record of the payload names a sector inside the HFS+
        // partition — the one the ISO 9660 record names.
        let mut iso = Iso9660::open(&mut dev).unwrap();
        iso.set_read_view(ReadView::Joliet).unwrap();
        let list = iso.list(&mut dev, Path::new("/sub")).unwrap();
        let p = list.iter().find(|e| e.name == "payload.bin").unwrap();
        let at = u64::from(p.inode) * 2048;
        assert!(at >= off && at < off + hlen, "{name}");
        assert!(
            at >= start * 2048 && at < (start + len) * 2048,
            "{name}: payload at {at} outside the UDF partition {start}+{len}"
        );
        let mut first = vec![0u8; 2048];
        udf.read_file(&mut dev, Path::new("/sub/payload.bin"))
            .unwrap()
            .read_exact(&mut first)
            .unwrap();
        let mut raw = vec![0u8; 2048];
        dev.read_at(at, &mut raw).unwrap();
        assert_eq!(first, raw, "{name}: UDF and ISO 9660 share the payload");
        same(
            &format!("udf of {name}"),
            &fs_snapshot(&mut udf, &mut dev),
            &want,
        );
        let mut slice = SlicedBackend::new(&mut dev, off, hlen).unwrap();
        let mut hfs = HfsPlus::open(&mut slice).unwrap();
        same(
            &format!("hfs+ of {name}"),
            &fs_snapshot(&mut hfs, &mut slice),
            &want_hfs,
        );
    }
}

/// Structure of fstool's UDF hybrids, everywhere: the recognition
/// sequence after the ISO 9660 terminator, anchors at 256 and N-1, a UDF
/// partition holding every payload, fstool's UDF reader seeing the tree.
#[cfg(feature = "udf")]
#[test]
fn fstool_udf_hybrid_structure() {
    let src = make_source();
    let want = snapshot(src.path(), &ident);
    let work = TempDir::new().unwrap();
    for hfs in [true, false] {
        let img = work.path().join(format!("structure-{hfs}.iso"));
        let mut opts = udf_opts("Structure", UdfRevision::V1_50);
        opts.hfs.enabled = hfs;
        let plan = build(src.path(), &opts, &img);
        assert!(vrs_after_terminator(&img));
        let (start, len, a256, aend) = udf_layout(&img);
        assert!(a256 && aend);
        assert!(start > 256 && start + len < u64::from(plan.total_sectors()));
        for f in plan.files() {
            assert!(
                u64::from(f.extent.lba) >= start && f.extent.end() <= start + len,
                "{} outside the UDF partition",
                f.path
            );
        }
        same("fstool udf", &udf_snapshot(&img), &want);
    }
}

/// `udfinfo` (udftools) on fstool's four-view hybrids and on an
/// ISO 9660 / UDF bridge; with passwordless sudo the kernel's udf driver
/// mounts them and shows the source tree.
#[cfg(feature = "udf")]
#[test]
fn udfinfo_and_linux_udf_mount_read_fstool_hybrids() {
    if cfg!(target_os = "macos") || !have(&["udfinfo"]) {
        return;
    }
    let src = make_source();
    let want = snapshot(src.path(), &ident);
    let work = TempDir::new().unwrap();
    for (name, hfs, rev) in [
        ("full-1.50", true, UdfRevision::V1_50),
        ("full-2.01", true, UdfRevision::V2_01),
        ("full-2.50", true, UdfRevision::V2_50),
        ("bridge-1.02", false, UdfRevision::V1_02),
    ] {
        let img = work.path().join(format!("{name}.iso"));
        let label = format!("Hybrid {name}");
        let mut opts = udf_opts(&label, rev);
        opts.hfs.enabled = hfs;
        build(src.path(), &opts, &img);
        same(&format!("fstool udf {name}"), &udf_snapshot(&img), &want);
        let out = Command::new("udfinfo").arg(&img).output().unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.status.success(), "udfinfo {name}: {text}");
        assert!(
            text.contains(&format!("udfrev={rev}")),
            "udfinfo {name}: {text}"
        );
        assert!(text.contains(&label), "udfinfo {name}: {text}");
        #[cfg(target_os = "linux")]
        if sudo_ok() {
            let at = work.path().join(format!("mnt-{name}"));
            std::fs::create_dir_all(&at).unwrap();
            if let Some(_m) = sudo_mount(&["-o", "loop,ro", "-t", "udf"], &img, &at) {
                same(&format!("linux udf {name}"), &snapshot(&at, &ident), &want);
            }
        }
    }
}
