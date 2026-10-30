#![cfg(all(target_os = "macos", feature = "hfs-plus"))]
//! Native validation, on macOS, of the HFS+ authoring guarantees a
//! decorated-volume builder (cargo-bundle) relies on:
//!
//! * name normalisation is byte-for-byte what the kernel stores — names
//!   created through a read-write mount are read back with fstool and
//!   compared with [`normalize_units`], and names authored by fstool are
//!   reachable by any spelling and list exactly like the native ones;
//! * HFSX: case-only-different names coexist, normalisation-equivalent
//!   ones collide (and both collide on plain HFS+), `fsck_hfs`-clean;
//! * the volume header's Finder info: `diskutil` reports the volume UUID
//!   derived from the identifier fstool wrote, `bless --info` the
//!   blessed / open folders;
//! * a classic Alias Manager record built from identities fstool reports
//!   *before* the final flush resolves on the mounted volume — by CNID,
//!   with the name deliberately wrong — and is rejected when the CNID or
//!   the volume creation date is wrong.
//!
//! Every test skips (with a message) when a tool it needs is missing.

use std::io::Cursor;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use fstool::block::{BlockDevice, FileBackend};
use fstool::fs::hfs_plus::finder::flags;
use fstool::fs::hfs_plus::unicode::normalize_units;
use fstool::fs::hfs_plus::{FinderInfo, FormatOpts, HfsPlus, VolumeFinderInfo, hfs_date_from_unix};
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

fn have(tools: &[&str]) -> bool {
    let missing: Vec<&str> = tools.iter().copied().filter(|t| !which(t)).collect();
    if !missing.is_empty() {
        eprintln!("skipping: {missing:?} not available");
    }
    missing.is_empty()
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

/// Attach `image`; mounted at `mountpoint` (or not at all), read-only
/// unless `rw`.
fn attach(image: &Path, mountpoint: Option<&Path>, rw: bool) -> Attached {
    let mut cmd = Command::new("hdiutil");
    cmd.args(["attach", "-plist", "-nobrowse", "-owners", "off"])
        .args(["-imagekey", "diskimage-class=CRawDiskImage"]);
    if !rw {
        cmd.arg("-readonly");
    }
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
    let a = attach(image, None, false);
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

fn touch(hfs: &mut HfsPlus, dev: &mut dyn BlockDevice, path: &str, body: &[u8]) -> u32 {
    hfs.create_file(
        dev,
        path,
        &mut Cursor::new(body),
        body.len() as u64,
        0o644,
        0,
        0,
        0,
    )
    .unwrap_or_else(|e| panic!("create {path:?}: {e}"))
}

fn try_touch(hfs: &mut HfsPlus, dev: &mut dyn BlockDevice, path: &str) -> bool {
    hfs.create_file(dev, path, &mut std::io::empty(), 0, 0o644, 0, 0, 0)
        .is_ok()
}

fn format(path: &Path, opts: &FormatOpts) -> (FileBackend, HfsPlus) {
    let mut dev = FileBackend::create(path, VOL_BYTES).unwrap();
    let hfs = HfsPlus::format(&mut dev, opts).unwrap();
    (dev, hfs)
}

fn finish(mut dev: FileBackend, mut hfs: HfsPlus) {
    hfs.flush(&mut dev).unwrap();
    dev.sync().unwrap();
}

// ---------------------------------------------------------------------
// Normalisation
// ---------------------------------------------------------------------

/// Names that exercise every corner of the kernel's decomposition: NFC
/// Latin, recursive decompositions, Hangul, the excluded ranges, non-BMP
/// characters, combining runs that reorder, marks unassigned in Unicode
/// 3.2 (which the kernel does not reorder), characters that only gained
/// a decomposition after 3.2, and compatibility-only forms.
const TRICKY: &[&str] = &[
    "caf\u{e9}",
    "\u{1e09}",
    "a\u{344}",
    "\u{1ec7}",
    "\u{d55c}\u{ae00}",
    "\u{ac00}",
    "\u{1100}\u{1161}\u{11a8}",
    "\u{2126}\u{212b}",
    "\u{f900}\u{faff}",
    "\u{2f800}",
    "\u{1d15e}",
    "a\u{301}\u{323}",
    "e\u{301}\u{327}",
    "a\u{351}\u{323}",
    "a\u{323}\u{351}\u{301}",
    "a\u{1dc0}\u{323}",
    "o\u{35c}\u{301}\u{323}",
    "\u{1b06}",
    "\u{1026}",
    "\u{237}",
    "\u{958}",
    "\u{f73}",
    "\u{304c}",
    "\u{ff76}\u{ff9e}",
    "\u{fb2c}",
    "x\u{20d0}\u{301}\u{323}",
    "a:b",
    "x\u{2400}y",
];

fn tricky_name(i: usize, n: &str) -> String {
    format!("{i:02}-{n}")
}

#[test]
fn normalisation_matches_the_kernel_byte_for_byte() {
    if !have(&["hdiutil", "fsck_hfs"]) {
        return;
    }
    let tmp = NamedTempFile::new().unwrap();
    {
        let mut opts = FormatOpts::default();
        opts.volume_name = "Norm".into();
        let (mut dev, mut hfs) = format(tmp.path(), &opts);
        hfs.create_dir(&mut dev, "/native", 0o777, 0, 0, 0).unwrap();
        hfs.create_dir(&mut dev, "/authored", 0o777, 0, 0, 0)
            .unwrap();
        for (i, n) in TRICKY.iter().enumerate() {
            touch(
                &mut hfs,
                &mut dev,
                &format!("/authored/{}", tricky_name(i, n)),
                b"f",
            );
        }
        finish(dev, hfs);
    }

    // 1. The kernel creates the same names; fstool reads back what it stored.
    {
        let mnt = TempDir::new().unwrap();
        let _a = attach(tmp.path(), Some(mnt.path()), true);
        for (i, n) in TRICKY.iter().enumerate() {
            // A path component can't carry '/', and ':' is how the VFS
            // spells the on-disk '/', so `a:b` is created as is.
            let p = mnt.path().join("native").join(tricky_name(i, n));
            std::fs::write(&p, b"n").unwrap_or_else(|e| panic!("native create {p:?}: {e}"));
        }
    }
    fsck(tmp.path());
    let mut dev = FileBackend::open(tmp.path()).unwrap();
    let hfs = HfsPlus::open(&mut dev).unwrap();
    let stored: Vec<Vec<u16>> = hfs
        .list_path(&mut dev, "/native")
        .unwrap()
        .into_iter()
        .map(|e| e.name.replace(':', "/").encode_utf16().collect())
        .collect();
    assert_eq!(stored.len(), TRICKY.len());
    for (i, n) in TRICKY.iter().enumerate() {
        // `tricky_name` is a path component: ':' stands for '/'.
        let want = normalize_units(&tricky_name(i, n).replace(':', "/"));
        assert!(
            stored.contains(&want),
            "kernel stored {:04X?}\nfstool expects {want:04X?} for {n:?}",
            stored
                .iter()
                .find(|s| s.starts_with(&want[..3]))
                .cloned()
                .unwrap_or_default()
        );
    }
    drop(hfs);
    drop(dev);

    // 2. Names fstool authored list exactly like the kernel's own, and
    //    are reachable by the spelling they were created with.
    let mnt = TempDir::new().unwrap();
    let _a = attach(tmp.path(), Some(mnt.path()), false);
    let listing = |d: &str| {
        let mut v: Vec<Vec<u8>> = std::fs::read_dir(mnt.path().join(d))
            .unwrap()
            .map(|e| e.unwrap().file_name().as_bytes().to_vec())
            .collect();
        v.sort();
        v
    };
    assert_eq!(listing("authored"), listing("native"));
    for (i, n) in TRICKY.iter().enumerate() {
        let p = mnt.path().join("authored").join(tricky_name(i, n));
        assert_eq!(std::fs::read(&p).unwrap(), b"f", "{p:?}");
    }
}

// ---------------------------------------------------------------------
// HFSX
// ---------------------------------------------------------------------

#[test]
fn hfsx_is_case_sensitive_and_hfs_plus_is_not() {
    if !have(&["hdiutil", "fsck_hfs", "diskutil"]) {
        return;
    }
    // HFSX: README and readme coexist; café spelled two ways collides.
    let tmp = NamedTempFile::new().unwrap();
    {
        let mut opts = FormatOpts::default();
        opts.volume_name = "CaseX".into();
        opts.case_sensitive = true;
        let (mut dev, mut hfs) = format(tmp.path(), &opts);
        touch(&mut hfs, &mut dev, "/README", b"upper");
        touch(&mut hfs, &mut dev, "/readme", b"lower");
        hfs.create_dir(&mut dev, "/Dir", 0o777, 0, 0, 0).unwrap();
        hfs.create_dir(&mut dev, "/dir", 0o777, 0, 0, 0).unwrap();
        touch(&mut hfs, &mut dev, "/caf\u{e9}", b"nfc");
        assert!(!try_touch(&mut hfs, &mut dev, "/cafe\u{301}"));
        assert!(!try_touch(&mut hfs, &mut dev, "/readme"));
        finish(dev, hfs);
    }
    fsck(tmp.path());
    {
        let mnt = TempDir::new().unwrap();
        let a = attach(tmp.path(), Some(mnt.path()), true);
        let m = mnt.path();
        assert_eq!(std::fs::read(m.join("README")).unwrap(), b"upper");
        assert_eq!(std::fs::read(m.join("readme")).unwrap(), b"lower");
        assert!(m.join("Dir").is_dir() && m.join("dir").is_dir());
        assert!(!m.join("ReadMe").exists());
        assert_eq!(std::fs::read(m.join("cafe\u{301}")).unwrap(), b"nfc");
        let info = Command::new("diskutil")
            .arg("info")
            .arg(m)
            .output()
            .unwrap();
        let info = String::from_utf8_lossy(&info.stdout);
        assert!(
            info.contains("Case-sensitive"),
            "diskutil doesn't see HFSX:\n{info}"
        );
        // The kernel agrees on both rules when it writes.
        std::fs::write(m.join("ReadMe"), b"mixed").unwrap();
        let e = std::fs::File::create_new(m.join("CAF\u{c9}")).map(|_| ());
        assert!(e.is_ok(), "case variant must be a new file on HFSX");
        let e = std::fs::File::create_new(m.join("cafe\u{301}")).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists);
        drop(a);
    }
    fsck(tmp.path());
    {
        let mut dev = FileBackend::open(tmp.path()).unwrap();
        let mut hfs = HfsPlus::open(&mut dev).unwrap();
        let mut names: Vec<String> = hfs
            .list_path(&mut dev, "/")
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .filter(|n| !n.starts_with(['.', '\0']))
            .collect();
        names.sort();
        assert_eq!(
            names,
            [
                "CAFE\u{301}",
                "Dir",
                "README",
                "ReadMe",
                "cafe\u{301}",
                "dir",
                "readme"
            ]
        );
        // fstool keeps honouring binary order on the macOS-written catalog.
        assert!(!try_touch(&mut hfs, &mut dev, "/ReadMe"));
        assert!(try_touch(&mut hfs, &mut dev, "/READme"));
        finish(dev, hfs);
    }
    fsck(tmp.path());

    // Plain HFS+: case variants and normalisation variants both collide.
    let tmp = NamedTempFile::new().unwrap();
    {
        let mut opts = FormatOpts::default();
        opts.volume_name = "CaseI".into();
        let (mut dev, mut hfs) = format(tmp.path(), &opts);
        touch(&mut hfs, &mut dev, "/README", b"upper");
        assert!(!try_touch(&mut hfs, &mut dev, "/readme"));
        touch(&mut hfs, &mut dev, "/caf\u{e9}", b"nfc");
        assert!(!try_touch(&mut hfs, &mut dev, "/CAFE\u{301}"));
        finish(dev, hfs);
    }
    fsck(tmp.path());
    let mnt = TempDir::new().unwrap();
    let _a = attach(tmp.path(), Some(mnt.path()), true);
    let m = mnt.path();
    assert_eq!(std::fs::read(m.join("readme")).unwrap(), b"upper");
    let e = std::fs::File::create_new(m.join("readme")).unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists);
    let e = std::fs::File::create_new(m.join("CAFE\u{301}")).unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists);
}

// ---------------------------------------------------------------------
// Volume-header Finder info
// ---------------------------------------------------------------------

fn uuid_string(u: [u8; 16]) -> String {
    let h: String = u.iter().map(|b| format!("{b:02X}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

#[test]
fn volume_finder_info_is_seen_by_diskutil_and_bless() {
    if !have(&["hdiutil", "fsck_hfs", "diskutil", "bless"]) {
        return;
    }
    let tmp = NamedTempFile::new().unwrap();
    let mut vfi = VolumeFinderInfo::default();
    let (sys, open);
    {
        let mut opts = FormatOpts::default();
        opts.volume_name = "Blessed".into();
        let (mut dev, mut hfs) = format(tmp.path(), &opts);
        sys = hfs.create_dir(&mut dev, "/System", 0o755, 0, 0, 0).unwrap();
        open = hfs
            .create_dir(&mut dev, "/Open Me", 0o755, 0, 0, 0)
            .unwrap();
        vfi.set_blessed_folder(sys);
        vfi.set_open_folder(open);
        vfi.set_volume_identifier(0x0123_4567_89AB_CDEF);
        hfs.set_volume_finder_info(&vfi).unwrap();
        assert_eq!(hfs.volume_finder_info().unwrap(), vfi);
        finish(dev, hfs);
    }
    fsck(tmp.path());
    let mnt = TempDir::new().unwrap();
    let _a = attach(tmp.path(), Some(mnt.path()), false);
    let m = mnt.path();

    let out = Command::new("diskutil")
        .args(["info", "-plist"])
        .arg(m)
        .output()
        .unwrap();
    let plist = String::from_utf8_lossy(&out.stdout);
    let want = uuid_string(vfi.volume_uuid().unwrap());
    let key = "<key>VolumeUUID</key>";
    let at = plist.find(key).expect("diskutil reports no VolumeUUID") + key.len();
    let got = plist[at..]
        .split("<string>")
        .nth(1)
        .and_then(|s| s.split("</string>").next())
        .unwrap();
    assert_eq!(got, want, "diskutil's Volume UUID");

    let out = Command::new("bless").arg("--info").arg(m).output().unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let word = |i: usize| -> u32 {
        let tag = format!("finderinfo[{i}]:");
        let line = text
            .lines()
            .find(|l| l.trim_start().starts_with(&tag))
            .unwrap_or_else(|| panic!("no {tag} in bless --info:\n{text}"));
        line.trim_start()[tag.len()..]
            .split_whitespace()
            .next()
            .unwrap()
            .parse()
            .unwrap()
    };
    assert_eq!(word(0), sys, "{text}");
    assert_eq!(word(2), open, "{text}");
    assert!(text.contains("/System"), "blessed folder path:\n{text}");
    assert!(
        text.to_ascii_lowercase().contains("0x0123456789abcdef"),
        "volume id:\n{text}"
    );
}

// ---------------------------------------------------------------------
// Finder aliases
// ---------------------------------------------------------------------

/// What a classic (version 2) `AliasRecord` needs to know about its
/// target — every field taken from fstool *before* the final flush.
struct AliasTarget<'a> {
    volume_name: &'a str,
    /// The volume creation date **as the Alias Manager stores it: local
    /// time** — `volume_create_date()` (UTC) plus the UTC offset of the
    /// time zone the alias is resolved in.
    volume_date_local: u32,
    parent_cnid: u32,
    name: &'a str,
    cnid: u32,
    create_date: u32,
    is_dir: bool,
}

/// Serialise a minimal AliasRecord v2 (Inside Macintosh: Files / the
/// layout `Aliases.h` documents): the 150-byte fixed part, then tagged
/// Unicode file and volume names, no paths — so resolution has to go
/// through the volume identity and the CNID.
fn alias_record(t: &AliasTarget) -> Vec<u8> {
    fn pstr(s: &str, cap: usize) -> Vec<u8> {
        let b = s.as_bytes();
        assert!(b.len() < cap);
        let mut v = vec![b.len() as u8];
        v.extend_from_slice(b);
        v.resize(cap, 0);
        v
    }
    fn tag(out: &mut Vec<u8>, t: i16, data: &[u8]) {
        out.extend_from_slice(&t.to_be_bytes());
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(data);
        if data.len() % 2 == 1 {
            out.push(0);
        }
    }
    fn uni(s: &str) -> Vec<u8> {
        let units: Vec<u16> = s.encode_utf16().collect();
        let mut v = (units.len() as u16).to_be_bytes().to_vec();
        for u in units {
            v.extend_from_slice(&u.to_be_bytes());
        }
        v
    }
    let mut r = Vec::new();
    r.extend_from_slice(&[0; 4]); // userType
    r.extend_from_slice(&[0; 2]); // aliasSize, patched below
    r.extend_from_slice(&2u16.to_be_bytes()); // version
    r.extend_from_slice(&u16::from(t.is_dir).to_be_bytes()); // thisAliasKind
    r.extend_from_slice(&pstr(&t.volume_name.replace(':', "/"), 28));
    r.extend_from_slice(&t.volume_date_local.to_be_bytes());
    r.extend_from_slice(b"H+"); // volume signature
    r.extend_from_slice(&5u16.to_be_bytes()); // drive type: ejectable
    r.extend_from_slice(&t.parent_cnid.to_be_bytes());
    r.extend_from_slice(&pstr(&t.name.replace(':', "/"), 64));
    r.extend_from_slice(&t.cnid.to_be_bytes());
    r.extend_from_slice(&t.create_date.to_be_bytes());
    r.extend_from_slice(&[0; 8]); // fileType, fileCreator
    r.extend_from_slice(&(-1i16).to_be_bytes()); // nlvlFrom
    r.extend_from_slice(&(-1i16).to_be_bytes()); // nlvlTo
    r.extend_from_slice(&[0; 4]); // volAttributes
    r.extend_from_slice(&[0; 2]); // volFSID
    r.extend_from_slice(&[0; 10]); // reserved
    assert_eq!(r.len(), 150);
    tag(&mut r, 14, &uni(t.name)); // Unicode file name
    tag(&mut r, 15, &uni(t.volume_name)); // Unicode volume name
    r.extend_from_slice(&(-1i16).to_be_bytes());
    r.extend_from_slice(&0u16.to_be_bytes());
    let len = r.len() as u16;
    r[4..6].copy_from_slice(&len.to_be_bytes());
    r
}

/// A resource fork holding one resource, `'alis'` ID 0 — what makes a
/// file with `kIsAlias` an alias file.
fn alis_resource_fork(alias: &[u8]) -> Vec<u8> {
    let data_off = 256u32;
    let data_len = 4 + alias.len() as u32;
    // Map: 16 header copy + 4 handle + 2 refnum + 2 attrs + 2 type-list
    // offset + 2 name-list offset, type list (2 + 8), ref list (12).
    let map_len = 28 + 10 + 12;
    let map_off = data_off + data_len;
    let mut header = Vec::new();
    for v in [data_off, map_off, data_len, map_len] {
        header.extend_from_slice(&v.to_be_bytes());
    }
    let mut f = header.clone();
    f.resize(256, 0);
    f.extend_from_slice(&(alias.len() as u32).to_be_bytes());
    f.extend_from_slice(alias);
    f.extend_from_slice(&header);
    f.extend_from_slice(&[0; 8]); // next map, refnum, attributes
    f.extend_from_slice(&28u16.to_be_bytes()); // type list offset
    f.extend_from_slice(&(map_len as u16).to_be_bytes()); // name list (empty)
    f.extend_from_slice(&0u16.to_be_bytes()); // types - 1
    f.extend_from_slice(b"alis");
    f.extend_from_slice(&0u16.to_be_bytes()); // resources - 1
    f.extend_from_slice(&10u16.to_be_bytes()); // ref list, from type list
    f.extend_from_slice(&0i16.to_be_bytes()); // resource ID
    f.extend_from_slice(&0xFFFFu16.to_be_bytes()); // no name
    f.extend_from_slice(&[0; 4]); // attributes + data offset 0
    f.extend_from_slice(&[0; 4]); // handle
    assert_eq!(f.len() as u32, map_off + map_len);
    f
}

const RESOLVER: &str = r#"
import Foundation
// resolve raw <alias record file> | resolve file <alias file>
let a = CommandLine.arguments
do {
    let url: URL
    if a[1] == "raw" {
        let d = try Data(contentsOf: URL(fileURLWithPath: a[2]))
        guard let bm = CFURLCreateBookmarkDataFromAliasRecord(nil, d as CFData) else {
            print("ERR cannot convert"); exit(1)
        }
        var stale = false
        url = try URL(resolvingBookmarkData: bm.takeRetainedValue() as Data,
                      options: [.withoutUI, .withoutMounting],
                      relativeTo: nil, bookmarkDataIsStale: &stale)
    } else {
        url = try URL(resolvingAliasFileAt: URL(fileURLWithPath: a[2]),
                      options: [.withoutUI, .withoutMounting])
    }
    print(url.path)
} catch {
    print("ERR \(error)"); exit(1)
}
"#;

/// Build the Swift resolver, `None` when no Swift toolchain works here.
fn build_resolver(dir: &Path) -> Option<PathBuf> {
    let src = dir.join("resolve.swift");
    std::fs::write(&src, RESOLVER).unwrap();
    let bin = dir.join("resolve");
    let ok = Command::new("swiftc")
        .arg("-o")
        .arg(&bin)
        .arg(&src)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    ok.then_some(bin)
}

/// Resolve with the time zone pinned, so "local time" is known.
fn resolve(bin: &Path, mode: &str, arg: &Path, tz: &str) -> Result<PathBuf, String> {
    let out = Command::new(bin)
        .env("TZ", tz)
        .arg(mode)
        .arg(arg)
        .output()
        .unwrap();
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if out.status.success() {
        Ok(std::fs::canonicalize(&s).unwrap_or_else(|_| PathBuf::from(s)))
    } else {
        Err(s)
    }
}

#[test]
fn alias_built_before_flush_resolves_by_cnid_and_dates() {
    if !have(&["hdiutil", "fsck_hfs", "swiftc"]) {
        return;
    }
    let work = TempDir::new().unwrap();
    let Some(resolver) = build_resolver(work.path()) else {
        eprintln!("skipping: swiftc could not build the alias resolver");
        return;
    };
    // Asia/Tokyo has had no DST since 1951: a fixed +9 h.
    const TZ: &str = "Asia/Tokyo";
    const TZ_OFFSET: u32 = 9 * 3600;
    // Unique, so no other mounted volume can match by name and date.
    let vol_name = format!("fstool alias {}", std::process::id());

    let tmp = NamedTempFile::new().unwrap();
    let (good, wrong_cnid, wrong_volume_date);
    {
        let mut opts = FormatOpts::default();
        opts.volume_name = vol_name.clone();
        opts.create_date = hfs_date_from_unix(1_700_000_000);
        let (mut dev, mut hfs) = format(tmp.path(), &opts);
        hfs.create_dir(&mut dev, "/Docs", 0o755, 0, 0, 0).unwrap();
        touch(&mut hfs, &mut dev, "/Docs/decoy.txt", b"decoy");
        let cnid = touch(&mut hfs, &mut dev, "/Docs/target.txt", b"target");
        hfs.set_create_date("/Docs/target.txt", hfs_date_from_unix(1_710_000_000))
            .unwrap();

        // Identities, before anything is flushed.
        let info = hfs.entry_info("/Docs/target.txt").unwrap();
        assert_eq!(info.cnid, cnid);
        let target = AliasTarget {
            volume_name: &vol_name,
            volume_date_local: hfs.volume_create_date().unwrap() + TZ_OFFSET,
            parent_cnid: info.parent_cnid,
            // Deliberately not the target's name: only the CNID can find it.
            name: "renamed.txt",
            cnid: info.cnid,
            create_date: info.create_date,
            is_dir: false,
        };
        good = alias_record(&target);
        wrong_cnid = alias_record(&AliasTarget {
            cnid: info.cnid + 1000,
            ..target
        });
        wrong_volume_date = alias_record(&AliasTarget {
            volume_date_local: target.volume_date_local + 3600,
            ..target
        });

        // The alias also goes into the volume as a Finder alias file —
        // a file generated after the identities were read.
        touch(&mut hfs, &mut dev, "/target alias", b"");
        hfs.write_resource_fork(
            &mut dev,
            "/target alias",
            &mut Cursor::new(alis_resource_fork(&good)),
            alis_resource_fork(&good).len() as u64,
        )
        .unwrap();
        let mut fi = FinderInfo::default();
        fi.set_finder_flags(flags::IS_ALIAS);
        hfs.set_finder_info("/target alias", &fi).unwrap();
        hfs.flush(&mut dev).unwrap();
        assert_eq!(hfs.entry_info("/Docs/target.txt").unwrap(), info);
        dev.sync().unwrap();
    }
    fsck(tmp.path());

    let raw = |name: &str, bytes: &[u8]| {
        let p = work.path().join(name);
        std::fs::write(&p, bytes).unwrap();
        p
    };
    let good_p = raw("good.alias", &good);
    let wrong_cnid_p = raw("wrong-cnid.alias", &wrong_cnid);
    let wrong_date_p = raw("wrong-date.alias", &wrong_volume_date);

    let mnt = TempDir::new().unwrap();
    let _a = attach(tmp.path(), Some(mnt.path()), false);
    let want = std::fs::canonicalize(mnt.path().join("Docs/target.txt")).unwrap();
    assert_eq!(
        resolve(&resolver, "raw", &good_p, TZ),
        Ok(want.clone()),
        "alias record with the right CNID and dates"
    );
    assert_eq!(
        resolve(&resolver, "file", &mnt.path().join("target alias"), TZ),
        Ok(want),
        "alias file on the volume"
    );
    assert!(
        resolve(&resolver, "raw", &wrong_cnid_p, TZ).is_err(),
        "a wrong CNID (and name) must not resolve"
    );
    assert!(
        resolve(&resolver, "raw", &wrong_date_p, TZ).is_err(),
        "a wrong volume creation date must not resolve"
    );
}
