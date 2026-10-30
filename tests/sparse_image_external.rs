#![cfg(all(unix, feature = "sparse-image", feature = "hfs-plus"))]
//! `.sparseimage` / `.sparsebundle` interop with macOS' `hdiutil`, in both
//! directions:
//!
//! - hdiutil creates an image, a volume is populated through a real mount,
//!   and fstool reads the files back through its backend;
//! - fstool creates and populates an image, and hdiutil attaches it,
//!   `fsck_hfs` checks the volume, and the files are compared through the
//!   mount.
//!
//! Small bands are used throughout so that a sparseimage needs extension
//! headers (more than 1,008 bands) — the chained band table is the part
//! of the format most worth checking against the real implementation.
//!
//! macOS-only: every test prints `skipping: …` and passes elsewhere.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use fstool::block::{
    BlockDevice, CreateOpts, ShrinkPolicy, SparseBundleBackend, SparseImageBackend,
};

fn hdiutil_ok() -> bool {
    cfg!(target_os = "macos")
        && Command::new("hdiutil")
            .arg("help")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
}

/// The tests attach images and spawn hdiutil; a child forked by one test
/// can briefly hold another test's image lock, so run them one at a time.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

macro_rules! need_hdiutil {
    () => {
        if !hdiutil_ok() {
            eprintln!("skipping: needs macOS hdiutil");
            return;
        }
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    };
}

fn run(cmd: &mut Command) -> String {
    let out = cmd.output().expect("spawn");
    assert!(
        out.status.success(),
        "{cmd:?} failed:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// An attached image; detached on drop, which then waits until hdiutil's
/// helper has really let go of the image file.
struct Attached {
    dev: String,
    image: PathBuf,
}

impl Attached {
    /// `hdiutil attach <image> <args…>`, returning the whole-disk node.
    fn new(image: &Path, args: &[&str]) -> Self {
        let plist = run(Command::new("hdiutil")
            .args(["attach", "-plist", "-nobrowse"])
            .args(args)
            .arg(image));
        let dev = whole_disk(&plist).expect("no /dev/diskN in hdiutil attach output");
        Self {
            dev,
            image: image.to_path_buf(),
        }
    }
}

impl Drop for Attached {
    fn drop(&mut self) {
        let ok = Command::new("hdiutil")
            .args(["detach", &self.dev])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !ok {
            let _ = Command::new("hdiutil")
                .args(["detach", "-force", &self.dev])
                .output();
        }
        wait_unlocked(&self.image);
    }
}

/// hdiutil's helper can keep an image locked for a while after `detach`
/// or `compact` return (seconds, on CI runners). Wait until it opens.
fn wait_unlocked(img: &Path) {
    for _ in 0..300 {
        match fstool::block::sparse::SparseBackend::open_read_only(img) {
            Err(fstool::Error::Io(e)) if e.kind() == std::io::ErrorKind::ResourceBusy => {
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            _ => return,
        }
    }
    panic!("{}: still locked 60 s after detach", img.display());
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

/// Deterministic noise (xorshift64*), so failures reproduce.
fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    let mut v = Vec::with_capacity(len + 8);
    while v.len() < len {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        v.extend_from_slice(&x.wrapping_mul(0x2545_F491_4F6C_DD1D).to_le_bytes());
    }
    v.truncate(len);
    v
}

/// hdiutil-made, HFS+ (no partition map), populated through a mount.
fn hdiutil_image(
    dir: &Path,
    name: &str,
    kind: &str,
    band_sectors: u32,
    files: &[(&str, &[u8])],
) -> PathBuf {
    let img = dir.join(name);
    run(Command::new("hdiutil")
        .args(["create", "-quiet", "-size", "64m", "-type", kind])
        .args(["-fs", "HFS+", "-layout", "NONE", "-volname", "FSTOOLT"])
        .args(["-imagekey", &format!("sparse-band-size={band_sectors}")])
        .arg(&img));
    let mnt = dir.join(format!("{name}.mnt"));
    std::fs::create_dir_all(&mnt).unwrap();
    {
        let _a = Attached::new(&img, &["-mountpoint", mnt.to_str().unwrap()]);
        for (n, data) in files {
            std::fs::write(mnt.join(n), data).unwrap();
        }
    }
    img
}

/// Read `path` from the HFS+ volume on `dev`.
fn read_file(dev: &mut dyn BlockDevice, path: &str) -> Vec<u8> {
    let mut fs = fstool::inspect::AnyFs::open(dev).expect("open HFS+ volume");
    let mut out = Vec::new();
    fs.copy_file_to(dev, path, &mut out).expect("read file");
    out
}

/// Format `dev` as HFS+ and add `files`.
fn populate(dev: &mut dyn BlockDevice, dir: &Path, files: &[(&str, &[u8])]) {
    let mut opts = fstool::fs::hfs_plus::FormatOpts::default();
    opts.volume_name = "FSTOOLW".into();
    let mut hfs = fstool::fs::hfs_plus::HfsPlus::format(dev, &opts).unwrap();
    hfs.flush(dev).unwrap();
    drop(hfs);
    let mut fs = fstool::inspect::AnyFs::open_writable(dev).unwrap();
    for (n, data) in files {
        let host = dir.join(format!("host-{n}"));
        std::fs::write(&host, data).unwrap();
        fs.add_file(dev, &format!("/{n}"), &host).unwrap();
    }
    fs.flush(dev).unwrap();
    dev.sync().unwrap();
}

/// Attach read-only, `fsck_hfs -n` the volume, mount it and compare files.
fn check_with_hdiutil(img: &Path, dir: &Path, files: &[(&str, &[u8])]) {
    if Path::new("/sbin/fsck_hfs").exists() {
        let a = Attached::new(img, &["-readonly", "-nomount"]);
        let out = Command::new("/sbin/fsck_hfs")
            .args(["-n", &a.dev])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "fsck_hfs on {}:\n{}{}",
            img.display(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let mnt = dir.join("check.mnt");
    std::fs::create_dir_all(&mnt).unwrap();
    let _a = Attached::new(img, &["-readonly", "-mountpoint", mnt.to_str().unwrap()]);
    for (n, data) in files {
        let got = std::fs::read(mnt.join(n)).unwrap();
        assert!(got == *data, "{n}: hdiutil reads different bytes");
    }
}

#[test]
fn hdiutil_sparseimage_reads_through_fstool() {
    need_hdiutil!();
    let d = tempfile::tempdir().unwrap();
    let big = noise(24 << 20, 1);
    let files: [(&str, &[u8]); 2] = [("big.bin", &big), ("hello.txt", b"hello sparse\n")];
    // 16 KiB bands: 24 MiB of data is ~1,500 bands, so three headers.
    let img = hdiutil_image(d.path(), "h.sparseimage", "SPARSE", 32, &files);

    let mut dev = SparseImageBackend::open_read_only(&img).unwrap();
    assert_eq!(dev.total_size(), 64 << 20);
    assert_eq!(dev.band_size(), 16 << 10);
    assert!(dev.header_count() >= 2, "{} headers", dev.header_count());
    for (n, data) in files {
        assert!(read_file(&mut dev, &format!("/{n}")) == data, "{n}");
    }
    drop(dev);
    // And through the auto-detecting entry point.
    let mut dev = fstool::block::open_image_read_only(&img).unwrap();
    assert_eq!(read_file(dev.as_mut(), "/hello.txt"), b"hello sparse\n");
}

#[test]
fn hdiutil_sparsebundle_reads_through_fstool() {
    need_hdiutil!();
    let d = tempfile::tempdir().unwrap();
    let big = noise(20 << 20, 2);
    let files: [(&str, &[u8]); 2] = [("big.bin", &big), ("hello.txt", b"hello bundle\n")];
    // 1 MiB bands.
    let img = hdiutil_image(d.path(), "h.sparsebundle", "SPARSEBUNDLE", 2048, &files);

    let mut dev = SparseBundleBackend::open_read_only(&img).unwrap();
    assert_eq!(dev.total_size(), 64 << 20);
    assert_eq!(dev.band_size(), 1 << 20);
    for (n, data) in files {
        assert!(read_file(&mut dev, &format!("/{n}")) == data, "{n}");
    }
    drop(dev);
    let mut dev = fstool::block::open_image(&img).unwrap();
    assert_eq!(read_file(dev.as_mut(), "/hello.txt"), b"hello bundle\n");
}

#[test]
fn fstool_sparseimage_attaches_in_hdiutil() {
    need_hdiutil!();
    let d = tempfile::tempdir().unwrap();
    let big = noise(24 << 20, 3);
    let files: [(&str, &[u8]); 2] = [("big.bin", &big), ("note.txt", b"written by fstool\n")];
    let img = d.path().join("w.sparseimage");
    let mut opts = CreateOpts::default();
    opts.sparse_band_size = 16 << 10;
    {
        let mut dev = fstool::block::create_image(&img, 64 << 20, &opts).unwrap();
        populate(dev.as_mut(), d.path(), &files);
    }
    let dev = SparseImageBackend::open_read_only(&img).unwrap();
    assert!(dev.header_count() >= 2, "{} headers", dev.header_count());
    drop(dev);
    check_with_hdiutil(&img, d.path(), &files);
}

#[test]
fn fstool_sparsebundle_attaches_in_hdiutil() {
    need_hdiutil!();
    let d = tempfile::tempdir().unwrap();
    let big = noise(20 << 20, 4);
    let files: [(&str, &[u8]); 2] = [("big.bin", &big), ("note.txt", b"bundle by fstool\n")];
    let img = d.path().join("w.sparsebundle");
    let mut opts = CreateOpts::default();
    opts.sparse_band_size = 1 << 20;
    {
        let mut dev = fstool::block::create_image(&img, 64 << 20, &opts).unwrap();
        populate(dev.as_mut(), d.path(), &files);
    }
    check_with_hdiutil(&img, d.path(), &files);
}

/// Scattered raw writes over many tiny bands, then the whole device read
/// back through hdiutil — after compaction and a resize as well.
#[test]
fn raw_pattern_round_trips_both_ways() {
    need_hdiutil!();
    let d = tempfile::tempdir().unwrap();
    let size: u64 = 4 << 20;
    let img = d.path().join("raw.sparseimage");
    let mut want = vec![0u8; size as usize];
    {
        // 512-byte bands: up to 8,192 of them, several extension headers.
        let mut dev = SparseImageBackend::create(&img, size, 512).unwrap();
        let mut seed = 10;
        let mut off = 7u64;
        while off < size - 3000 {
            seed += 1;
            let chunk = noise(1 + (seed as usize * 37) % 2500, seed);
            dev.write_at(off, &chunk).unwrap();
            want[off as usize..off as usize + chunk.len()].copy_from_slice(&chunk);
            off += chunk.len() as u64 + (seed * 131) % 4000;
        }
        // Zero a run so compaction has something to drop.
        dev.write_at(size / 2, &vec![0u8; 64 << 10]).unwrap();
        want[(size / 2) as usize..(size / 2) as usize + (64 << 10)].fill(0);
        dev.sync().unwrap();
        assert!(dev.header_count() > 3);
        let before = dev.allocated_bands();
        assert!(dev.compact().unwrap() >= 10);
        assert!(dev.allocated_bands() < before);
        dev.resize(size * 2, ShrinkPolicy::RequireZero).unwrap();
    }
    want.resize((size * 2) as usize, 0);
    {
        let a = Attached::new(&img, &["-readonly", "-nomount"]);
        let mut got = vec![0u8; want.len()];
        std::fs::File::open(&a.dev)
            .unwrap()
            .read_exact(&mut got)
            .unwrap();
        assert!(got == want, "hdiutil reads a different device");
    }

    // The other way: hdiutil writes, fstool reads.
    let img2 = d.path().join("raw2.sparseimage");
    run(Command::new("hdiutil")
        .args([
            "create", "-quiet", "-size", "4m", "-type", "SPARSE", "-layout", "NONE",
        ])
        .args(["-imagekey", "sparse-band-size=1"])
        .arg(&img2));
    let pattern = noise(3 << 20, 99);
    {
        let a = Attached::new(&img2, &["-nomount"]);
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(&a.dev)
            .unwrap();
        // Back to front, so allocation order is not band order.
        for i in (0..pattern.len() / 4096).rev() {
            f.seek(SeekFrom::Start((i * 8192 % pattern.len()) as u64))
                .unwrap();
            f.write_all(&pattern[i * 4096..(i + 1) * 4096]).unwrap();
        }
        drop(f);
    }
    let mut expect = vec![0u8; 4 << 20];
    for i in (0..pattern.len() / 4096).rev() {
        let at = i * 8192 % pattern.len();
        expect[at..at + 4096].copy_from_slice(&pattern[i * 4096..(i + 1) * 4096]);
    }
    let mut dev = SparseImageBackend::open_read_only(&img2).unwrap();
    assert!(dev.header_count() > 1, "{} headers", dev.header_count());
    let mut got = vec![0u8; expect.len()];
    dev.read_at(0, &mut got).unwrap();
    assert!(got == expect, "fstool reads a different device");
}

/// An image hdiutil has attached read/write is locked against fstool.
#[test]
fn attached_images_are_locked() {
    need_hdiutil!();
    let d = tempfile::tempdir().unwrap();
    for name in ["l.sparseimage", "l.sparsebundle"] {
        let img = d.path().join(name);
        drop(fstool::block::create_image(&img, 8 << 20, &CreateOpts::default()).unwrap());
        {
            let _a = Attached::new(&img, &["-nomount"]);
            assert!(fstool::block::open_image(&img).is_err(), "{name}: rw open");
            assert!(
                fstool::block::open_image_read_only(&img).is_err(),
                "{name}: ro open"
            );
        }
        // And the other way round: hdiutil can't attach what fstool holds.
        let dev = fstool::block::open_image(&img).unwrap();
        let out = Command::new("hdiutil")
            .args(["attach", "-plist", "-nomount"])
            .arg(&img)
            .output()
            .unwrap();
        if out.status.success() {
            // Clean up before failing.
            if let Some(disk) = whole_disk(&String::from_utf8_lossy(&out.stdout)) {
                let _ = Command::new("hdiutil").args(["detach", &disk]).output();
            }
            panic!("{name}: hdiutil attached an image fstool holds open");
        }
        drop(dev);
    }
}

/// Copy a sparseimage file or a sparsebundle directory.
fn copy_image(src: &Path, dst: &Path) {
    if src.is_dir() {
        std::fs::create_dir_all(dst).unwrap();
        for e in std::fs::read_dir(src).unwrap() {
            let e = e.unwrap();
            copy_image(&e.path(), &dst.join(e.file_name()));
        }
    } else {
        std::fs::copy(src, dst).unwrap();
    }
}

fn allocated_bands(img: &Path) -> u64 {
    wait_unlocked(img);
    fstool::block::sparse::SparseBackend::open_read_only(img)
        .unwrap()
        .allocated_bands()
}

/// `fsck_<fs> -n` (`-fn` for HFS+, which otherwise skips a journaled
/// volume) on the data partition of `img`.
fn fsck_image(img: &Path, fsck: &str) {
    let tool = format!("/sbin/{fsck}");
    if !Path::new(&tool).exists() {
        eprintln!("no {tool}: not checking");
        return;
    }
    let plist = run(Command::new("hdiutil")
        .args(["attach", "-plist", "-nobrowse", "-readonly", "-nomount"])
        .arg(img));
    let whole = whole_disk(&plist).expect("attached disk");
    let _a = Attached {
        dev: whole.clone(),
        image: img.to_path_buf(),
    };
    // The data partition is the last /dev/diskNsM listed.
    let prefix = format!("{whole}s");
    let part = plist
        .split("<string>")
        .filter_map(|s| s.split("</string>").next())
        .filter(|s| s.starts_with(&prefix))
        .last()
        .unwrap_or(&whole)
        .to_string();
    let flags = if fsck == "fsck_hfs" { "-fn" } else { "-n" };
    let out = Command::new(&tool).args([flags, &part]).output().unwrap();
    assert!(
        out.status.success(),
        "{fsck} {part} ({}):\n{}{}",
        img.display(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Make an image with hdiutil (1 MiB bands), fill a volume in a GPT
/// partition through a real mount, delete most of it, and detach: free
/// space full of nonzero bytes that compaction can't touch. Returns the
/// files that stay.
fn image_with_deleted_files(img: &Path, kind: &str, fs: &str, seed: u64) -> Vec<(String, Vec<u8>)> {
    run(Command::new("hdiutil")
        .args(["create", "-quiet", "-size", "96m", "-type", kind])
        .args(["-fs", fs, "-layout", "GPTSPUD", "-volname", "RECLAIM"])
        .args(["-imagekey", "sparse-band-size=2048"])
        .arg(img));
    let mnt = img.with_extension("mnt");
    std::fs::create_dir_all(&mnt).unwrap();
    let keep = vec![
        ("keep.bin".to_string(), noise(6 << 20, seed)),
        ("small.txt".to_string(), b"still here\n".to_vec()),
    ];
    {
        let _a = Attached::new(img, &["-mountpoint", mnt.to_str().unwrap()]);
        std::fs::write(mnt.join("gone1.bin"), noise(30 << 20, seed + 1)).unwrap();
        for (n, data) in &keep {
            std::fs::write(mnt.join(n), data).unwrap();
        }
        std::fs::write(mnt.join("gone2.bin"), noise(24 << 20, seed + 2)).unwrap();
        std::fs::remove_file(mnt.join("gone1.bin")).unwrap();
        std::fs::remove_file(mnt.join("gone2.bin")).unwrap();
    }
    keep
}

fn read_back(img: &Path, dir: &Path, files: &[(String, Vec<u8>)]) {
    let mnt = dir.join("readback.mnt");
    std::fs::create_dir_all(&mnt).unwrap();
    let _a = Attached::new(img, &["-readonly", "-mountpoint", mnt.to_str().unwrap()]);
    for (n, data) in files {
        let got = std::fs::read(mnt.join(n)).unwrap();
        assert!(got == *data, "{n}: different bytes after reclaim");
    }
}

/// Filesystem-aware reclamation on a journaled HFS+ volume inside a GPT
/// partition: the bands of deleted files go, fsck stays clean, kept files
/// read back, and the result is at least as small as `hdiutil compact`
/// makes it.
#[test]
fn reclaim_releases_deleted_files_like_hdiutil_compact() {
    need_hdiutil!();
    use fstool::block::sparse::{PartialBandPolicy, ReclaimOpts, SparseBackend, reclaim};
    let d = tempfile::tempdir().unwrap();
    for (name, kind) in [
        ("r.sparseimage", "SPARSE"),
        ("r.sparsebundle", "SPARSEBUNDLE"),
    ] {
        let img = d.path().join(name);
        let keep = image_with_deleted_files(&img, kind, "JHFS+", 40);
        let twin = d.path().join(format!("twin-{name}"));
        copy_image(&img, &twin);
        let before = allocated_bands(&img);
        // Zero-band compaction finds (almost) nothing: the deleted files'
        // bytes are still there.
        let compacted = SparseBackend::open(&img).unwrap().compact().unwrap();
        assert!(compacted <= 2, "{name}: compact dropped {compacted}");
        let before = before - compacted;

        let mut opts = ReclaimOpts::default();
        opts.dry_run = true;
        let dry = reclaim(&img, &opts).unwrap();
        assert_eq!(allocated_bands(&img), before, "{name}: dry run changed it");
        opts.dry_run = false;
        let rep = reclaim(&img, &opts).unwrap();
        assert_eq!(rep.stats.bands_released, dry.stats.bands_released);
        assert_eq!(rep.volumes.len(), 1, "{name}");
        assert_eq!(rep.volumes[0].fs, "hfs+");
        assert!(rep.volumes[0].offset > 0, "{name}: volume in a partition");
        let after = allocated_bands(&img);
        assert_eq!(rep.stats.bands_after(), after);
        // 54 MiB deleted, in 1 MiB bands.
        assert!(
            after + 45 <= before,
            "{name}: {before} → {after} bands only"
        );
        fsck_image(&img, "fsck_hfs");
        read_back(&img, d.path(), &keep);

        // hdiutil compact on the twin, for comparison. Some macOS hosts
        // refuse it outright ("Function not implemented"), so only compare
        // when it ran.
        let out = Command::new("hdiutil")
            .args(["compact", "-quiet"])
            .arg(&twin)
            .output()
            .expect("spawn");
        if out.status.success() {
            let theirs = allocated_bands(&twin);
            eprintln!(
                "{name}: {before} bands; fstool reclaim → {after}, hdiutil compact → {theirs}"
            );
            assert!(after <= theirs, "{name}: fstool {after} > hdiutil {theirs}");
        } else {
            eprintln!(
                "{name}: hdiutil compact unavailable here ({}); skipping the comparison",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }

        // Zeroing the free parts of kept bands leaves the volume intact.
        opts.partial = PartialBandPolicy::ZeroFree;
        let rep = reclaim(&img, &opts).unwrap();
        assert!(rep.stats.bands_zeroed > 0, "{name}: nothing to zero");
        fsck_image(&img, "fsck_hfs");
        read_back(&img, d.path(), &keep);
    }
}

/// The same for the FAT32 and exFAT volumes hdiutil makes, which
/// `hdiutil compact` does not reclaim at all.
#[test]
fn reclaim_handles_fat32_and_exfat() {
    need_hdiutil!();
    let d = tempfile::tempdir().unwrap();
    for (fs, fsck) in [("MS-DOS FAT32", "fsck_msdos"), ("ExFAT", "fsck_exfat")] {
        let img = d.path().join(format!("{fsck}.sparseimage"));
        let keep = image_with_deleted_files(&img, "SPARSE", fs, 50);
        let before = allocated_bands(&img);
        let rep = fstool::block::sparse::reclaim(&img, &Default::default()).unwrap();
        let after = allocated_bands(&img);
        eprintln!("{fs}: {before} → {after} bands");
        assert!(after + 45 <= before, "{fs}: {before} → {after} bands only");
        assert_eq!(rep.stats.bands_after(), after);
        fsck_image(&img, fsck);
        read_back(&img, d.path(), &keep);
    }
}

/// A volume that was not cleanly unmounted is refused, image untouched.
#[test]
fn reclaim_refuses_a_mounted_volume() {
    need_hdiutil!();
    let d = tempfile::tempdir().unwrap();
    let img = d.path().join("m.sparseimage");
    image_with_deleted_files(&img, "SPARSE", "HFS+", 60);
    let mnt = d.path().join("live.mnt");
    std::fs::create_dir_all(&mnt).unwrap();
    let copy = d.path().join("snap.sparseimage");
    {
        let _a = Attached::new(&img, &["-mountpoint", mnt.to_str().unwrap()]);
        std::fs::write(mnt.join("x"), b"x").unwrap();
        // Attached: the image itself is locked.
        assert!(fstool::block::sparse::reclaim(&img, &Default::default()).is_err());
        // A copy taken while mounted holds a volume marked mounted.
        std::fs::copy(&img, &copy).unwrap();
    }
    let raw = std::fs::read(&copy).unwrap();
    let err = fstool::block::sparse::reclaim(&copy, &Default::default()).unwrap_err();
    assert!(matches!(err, fstool::Error::InvalidImage(_)), "{err}");
    assert!(
        std::fs::read(&copy).unwrap() == raw,
        "refusal changed the image"
    );
}

/// `fstool compact` / `reclaim` / `resize` end to end on images fstool
/// makes itself — no hdiutil needed, so this runs on every Unix host.
#[cfg(feature = "cli")]
#[test]
fn cli_compact_reclaim_resize() {
    let fstool = env!("CARGO_BIN_EXE_fstool");
    let d = tempfile::tempdir().unwrap();
    let cli = |args: &[&str]| -> (bool, String) {
        let out = Command::new(fstool).args(args).output().unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (out.status.success(), text)
    };
    let ok = |args: &[&str]| -> String {
        let (good, text) = cli(args);
        assert!(good, "fstool {args:?}:\n{text}");
        text
    };
    let big = d.path().join("big.bin");
    let keep = d.path().join("keep.bin");
    std::fs::write(&big, noise(30 << 20, 70)).unwrap();
    let kept = noise(1 << 20, 71);
    std::fs::write(&keep, &kept).unwrap();
    for name in ["c.sparseimage", "c.sparsebundle"] {
        let img = d.path().join(name);
        let img_s = img.to_str().unwrap();
        ok(&["create", "-t", "hfs+", "-o", img_s, "--size", "64MiB"]);
        ok(&["add", img_s, big.to_str().unwrap(), "/big.bin"]);
        ok(&["add", img_s, keep.to_str().unwrap(), "/keep.bin"]);
        ok(&["rm", img_s, "/big.bin"]);
        let before = allocated_bands(&img);

        // Zero-band compaction can't see the deleted file.
        let out = ok(&["compact", img_s]);
        assert!(out.contains("bands"), "{out}");
        let after_compact = allocated_bands(&img);
        assert!(
            after_compact + 2 >= before,
            "{name}: compact {before} → {after_compact}"
        );

        let dry = ok(&["reclaim", "--dry-run", img_s]);
        assert!(dry.contains("would release"), "{dry}");
        assert_eq!(allocated_bands(&img), after_compact);
        let out = ok(&["reclaim", img_s]);
        assert!(out.contains("hfs+"), "{out}");
        let after = allocated_bands(&img);
        let band = fstool::block::sparse::SparseBackend::open_read_only(&img)
            .unwrap()
            .band_size();
        let freed = (after_compact - after) * band;
        assert!(
            freed >= 10 << 20,
            "{name}: only {freed} bytes released\n{out}"
        );
        let (good, cat) = {
            let out = Command::new(fstool)
                .args(["cat", img_s, "/keep.bin"])
                .output()
                .unwrap();
            (out.status.success(), out.stdout)
        };
        assert!(good && cat == kept, "{name}: kept file changed");

        // Shrinking over the volume's tail (its alternate header) is
        // refused without --discard and leaves the image as it was.
        let (good, text) = cli(&["resize", img_s, "32MiB"]);
        assert!(!good && text.contains("--discard"), "{text}");
        assert_eq!(
            fstool::block::open_image_read_only(&img)
                .unwrap()
                .total_size(),
            64 << 20
        );
        ok(&["resize", img_s, "96MiB"]);
        assert_eq!(
            fstool::block::open_image_read_only(&img)
                .unwrap()
                .total_size(),
            96 << 20
        );
        // A non-sparse file is refused.
        let raw = d.path().join("plain.img");
        std::fs::write(&raw, vec![0u8; 4096]).unwrap();
        let (good, _) = cli(&["compact", raw.to_str().unwrap()]);
        assert!(!good);
    }
}
