#![cfg(all(unix, feature = "dmg-write"))]
//! Native validation of fstool's UDIF writer against macOS' `hdiutil`.
//!
//! Each test builds a reference HFS+ volume with `hdiutil` (a populated
//! `UDRW` image converted to a raw `UDTO` sector dump), re-encodes that
//! raw dump with [`fstool::block::dmg::write_udif_from_reader`] in one
//! format, and then asks Apple's own engine to accept it:
//!
//! - `hdiutil verify` — checks the partition and master CRC-32s;
//! - `hdiutil imageinfo` — the format code it reports must match;
//! - `hdiutil convert -format UDTO` — the decoded sectors must equal the
//!   raw dump byte for byte;
//! - `hdiutil attach -readonly -nomount` — the attached device's raw
//!   bytes must equal the raw dump too (detached afterwards);
//! - for UDZO, a real read-only mount, comparing the files.
//!
//! macOS-only: elsewhere (or without `hdiutil`) every test prints
//! `skipping: …` and passes, matching `tests/dmg_external.rs`.

use std::path::{Path, PathBuf};
use std::process::Command;

use fstool::block::dmg::{
    UdifChecksum, UdifFormat, UdifWriteOptions, ZeroRunEncoding, write_udif_from_reader,
};

fn skip_unless_macos_hdiutil() -> bool {
    if !cfg!(target_os = "macos") {
        eprintln!("skipping: UDIF writer e2e requires macOS (hdiutil)");
        return true;
    }
    let ok = Command::new("hdiutil")
        .arg("help")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !ok {
        eprintln!("skipping: hdiutil not usable");
        return true;
    }
    false
}

/// Run `hdiutil` and return stdout, or `None` (with the reason printed)
/// when it refuses.
fn hdiutil(args: &[&std::ffi::OsStr]) -> Option<String> {
    let out = Command::new("hdiutil")
        .args(args)
        .output()
        .expect("hdiutil failed to spawn");
    if !out.status.success() {
        eprintln!(
            "hdiutil {:?} failed:\nstdout:\n{}\nstderr:\n{}",
            args,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn populate(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    let mut text = String::new();
    for i in 0..20_000 {
        text.push_str(&format!(
            "line {i} the quick brown fox jumps over the lazy dog\n"
        ));
    }
    std::fs::write(dir.join("text.txt"), text).unwrap();
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let noise: Vec<u8> = (0..300_000)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect();
    std::fs::write(dir.join("noise.bin"), noise).unwrap();
}

/// A raw HFS+ volume made by `hdiutil`, plus the folder it was made from.
fn reference_volume(dir: &Path) -> Option<(PathBuf, PathBuf)> {
    let src = dir.join("src");
    populate(&src);
    let base = dir.join("base.dmg");
    hdiutil(&[
        "create".as_ref(),
        "-srcfolder".as_ref(),
        src.as_os_str(),
        "-fs".as_ref(),
        "HFS+".as_ref(),
        "-layout".as_ref(),
        "NONE".as_ref(),
        "-volname".as_ref(),
        "FstoolUdif".as_ref(),
        "-format".as_ref(),
        "UDRW".as_ref(),
        "-ov".as_ref(),
        base.as_os_str(),
    ])?;
    let raw = dir.join("ref.cdr");
    hdiutil(&[
        "convert".as_ref(),
        base.as_os_str(),
        "-format".as_ref(),
        "UDTO".as_ref(),
        "-ov".as_ref(),
        "-o".as_ref(),
        raw.as_os_str(),
    ])?;
    Some((raw, src))
}

fn encode(raw: &Path, out: &Path, opts: &UdifWriteOptions) {
    let len = std::fs::metadata(raw).unwrap().len();
    let src = std::io::BufReader::new(std::fs::File::open(raw).unwrap());
    // Finish into a caller-owned file, then close it — the writer never
    // touches the path itself.
    let file = std::fs::File::create(out).unwrap();
    let (file, summary) = write_udif_from_reader(src, len, file, opts)
        .unwrap_or_else(|e| panic!("{}: {e}", opts.format.name()));
    file.sync_all().unwrap();
    drop(file);
    assert_eq!(std::fs::metadata(out).unwrap().len(), summary.bytes_written);
}

/// `/dev/diskN` from `hdiutil attach` output (the first line naming one;
/// checksum progress may precede it).
fn attached_device(stdout: &str) -> Option<String> {
    stdout
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .find(|d| d.starts_with("/dev/disk"))
        .map(str::to_owned)
}

fn read_device(path: &str, len: usize) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut out = vec![0u8; len];
    for piece in out.chunks_mut(1 << 20) {
        f.read_exact(piece)?;
    }
    Ok(out)
}

struct Detach(String);
impl Drop for Detach {
    fn drop(&mut self) {
        let _ = Command::new("hdiutil")
            .args(["detach", &self.0, "-force"])
            .output();
    }
}

fn check_native(format: UdifFormat, tweak: impl Fn(&mut UdifWriteOptions)) {
    if skip_unless_macos_hdiutil() {
        return;
    }
    if !format.writable() {
        eprintln!("skipping {}: not writable in this build", format.name());
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let Some((raw, _)) = reference_volume(dir.path()) else {
        eprintln!("skipping: hdiutil could not build the reference volume");
        return;
    };
    let expected = std::fs::read(&raw).unwrap();
    let mut opts = UdifWriteOptions::default();
    opts.format = format;
    tweak(&mut opts);
    let dmg = dir.path().join("out.dmg");
    encode(&raw, &dmg, &opts);
    let name = format.name();

    if opts.checksum == UdifChecksum::None {
        // Nothing to verify: hdiutil refuses with "has no checksum".
        assert!(hdiutil(&["verify".as_ref(), dmg.as_os_str()]).is_none());
    } else {
        let verify = hdiutil(&["verify".as_ref(), dmg.as_os_str()])
            .unwrap_or_else(|| panic!("{name}: hdiutil verify rejected the image"));
        eprintln!("{name} verify:\n{verify}");
    }

    let info = hdiutil(&["imageinfo".as_ref(), dmg.as_os_str()])
        .unwrap_or_else(|| panic!("{name}: hdiutil imageinfo rejected the image"));
    let reported = info
        .lines()
        .find_map(|l| l.strip_prefix("Format: "))
        .unwrap_or_default()
        .trim()
        .to_owned();
    assert_eq!(
        reported, name,
        "hdiutil imageinfo reports format {reported}"
    );

    // Decode through Apple's engine back to raw sectors.
    let back = dir.path().join("back.cdr");
    hdiutil(&[
        "convert".as_ref(),
        dmg.as_os_str(),
        "-format".as_ref(),
        "UDTO".as_ref(),
        "-ov".as_ref(),
        "-o".as_ref(),
        back.as_os_str(),
    ])
    .unwrap_or_else(|| panic!("{name}: hdiutil convert rejected the image"));
    assert!(
        std::fs::read(&back).unwrap() == expected,
        "{name}: hdiutil's decode differs from the source sectors"
    );

    // Attach without mounting and read the raw device back.
    let Some(out) = hdiutil(&[
        "attach".as_ref(),
        "-readonly".as_ref(),
        "-nomount".as_ref(),
        "-nobrowse".as_ref(),
        dmg.as_os_str(),
    ]) else {
        panic!("{name}: hdiutil attach rejected the image");
    };
    let dev = attached_device(&out).unwrap_or_else(|| panic!("no device in {out:?}"));
    let _guard = Detach(dev.clone());
    // Raw character devices want sector-aligned transfers; read the
    // expected length in 1 MiB pieces.
    let rdev = dev.replacen("/dev/disk", "/dev/rdisk", 1);
    let bytes = read_device(&rdev, expected.len())
        .unwrap_or_else(|e| panic!("{name}: reading {rdev}: {e}"));
    assert!(
        bytes == expected,
        "{name}: attached device bytes differ from the source sectors"
    );
}

#[test]
fn udro_passes_hdiutil() {
    check_native(UdifFormat::Udro, |_| {});
}

#[test]
fn udco_passes_hdiutil() {
    check_native(UdifFormat::Udco, |_| {});
}

#[test]
fn udzo_passes_hdiutil() {
    check_native(UdifFormat::Udzo, |_| {});
}

#[test]
fn udzo_level9_ignore_runs_small_chunks_passes_hdiutil() {
    check_native(UdifFormat::Udzo, |o| {
        o.level = Some(9);
        o.zero_runs = ZeroRunEncoding::Ignore;
        o.chunk_sectors = 64;
    });
}

#[test]
fn udzo_without_checksums_passes_hdiutil() {
    check_native(UdifFormat::Udzo, |o| o.checksum = UdifChecksum::None);
}

#[test]
fn udbz_passes_hdiutil() {
    check_native(UdifFormat::Udbz, |_| {});
}

#[test]
fn ulmo_passes_hdiutil() {
    check_native(UdifFormat::Ulmo, |_| {});
}

/// The largest chunk the writer allows, for the codecs Apple's engine
/// decodes in place.
#[test]
fn max_chunk_size_passes_hdiutil() {
    use fstool::block::dmg::MAX_WRITE_CHUNK_SECTORS;
    for f in [UdifFormat::Ulmo, UdifFormat::Udzo, UdifFormat::Udco] {
        check_native(f, |o| o.chunk_sectors = MAX_WRITE_CHUNK_SECTORS);
    }
}

/// Mount a writer-produced UDZO image read-only and compare the files.
#[test]
fn udzo_mounts_and_files_read_back() {
    if skip_unless_macos_hdiutil() || !UdifFormat::Udzo.writable() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let Some((raw, src)) = reference_volume(dir.path()) else {
        return;
    };
    let dmg = dir.path().join("mount.dmg");
    encode(&raw, &dmg, &UdifWriteOptions::default());
    let mnt = dir.path().join("mnt");
    std::fs::create_dir_all(&mnt).unwrap();
    let out = hdiutil(&[
        "attach".as_ref(),
        "-readonly".as_ref(),
        "-nobrowse".as_ref(),
        "-mountpoint".as_ref(),
        mnt.as_os_str(),
        dmg.as_os_str(),
    ])
    .expect("hdiutil attach (mount) rejected the image");
    let dev = attached_device(&out).unwrap();
    let _guard = Detach(dev);
    for f in ["text.txt", "noise.bin"] {
        assert!(
            std::fs::read(mnt.join(f)).unwrap() == std::fs::read(src.join(f)).unwrap(),
            "{f} differs on the mounted image"
        );
    }
}

/// cargo-bundle's path end to end, all through public APIs: author an
/// HFS+ volume with fstool on an in-memory device, encode that device as
/// UDZO with [`fstool::block::dmg::write_udif`], then have macOS verify,
/// mount and read it.
#[cfg(feature = "hfs-plus")]
#[test]
fn fstool_hfs_plus_volume_to_udzo_mounts() {
    use fstool::block::MemoryBackend;
    use fstool::block::dmg::write_udif;
    use fstool::fs::hfs_plus::{FormatOpts, HfsPlus};

    if skip_unless_macos_hdiutil() || !UdifFormat::Udzo.writable() {
        return;
    }
    let mut dev = MemoryBackend::new(16 * 1024 * 1024);
    let mut fo = FormatOpts::default();
    fo.volume_name = "FstoolBundle".into();
    let mut hfs = HfsPlus::format(&mut dev, &fo).unwrap();
    let body: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    hfs.create_dir(&mut dev, "/App", 0o755, 0, 0, 0).unwrap();
    hfs.create_file(
        &mut dev,
        "/App/payload.bin",
        &mut std::io::Cursor::new(&body),
        body.len() as u64,
        0o644,
        0,
        0,
        0,
    )
    .unwrap();
    hfs.flush(&mut dev).unwrap();

    let dir = tempfile::tempdir().unwrap();
    let dmg = dir.path().join("bundle.dmg");
    let file = std::fs::File::create(&dmg).unwrap();
    let (file, summary) = write_udif(&mut dev, file, &UdifWriteOptions::default()).unwrap();
    file.sync_all().unwrap();
    drop(file);
    assert_eq!(summary.sector_count, 16 * 1024 * 1024 / 512);

    hdiutil(&["verify".as_ref(), dmg.as_os_str()]).expect("hdiutil verify");
    let mnt = dir.path().join("mnt");
    std::fs::create_dir_all(&mnt).unwrap();
    let out = hdiutil(&[
        "attach".as_ref(),
        "-readonly".as_ref(),
        "-nobrowse".as_ref(),
        "-mountpoint".as_ref(),
        mnt.as_os_str(),
        dmg.as_os_str(),
    ])
    .expect("hdiutil attach (mount)");
    let _guard = Detach(attached_device(&out).unwrap());
    assert!(std::fs::read(mnt.join("App/payload.bin")).unwrap() == body);
}

/// A zero run longer than one descriptor may carry (512 MiB) is split,
/// and a sparse ~600 MiB device still verifies and attaches.
#[test]
fn long_zero_runs_pass_hdiutil() {
    if skip_unless_macos_hdiutil() || !UdifFormat::Udzo.writable() {
        return;
    }
    const LEN: u64 = 600 * 1024 * 1024;
    let dir = tempfile::tempdir().unwrap();
    let raw = dir.path().join("sparse.img");
    {
        use std::io::{Seek, SeekFrom, Write};
        let mut f = std::fs::File::create(&raw).unwrap();
        f.set_len(LEN).unwrap();
        for (off, tag) in [(0u64, b"head"), (LEN / 2, b"half"), (LEN - 512, b"tail")] {
            f.seek(SeekFrom::Start(off)).unwrap();
            f.write_all(tag).unwrap();
        }
    }
    let dmg = dir.path().join("sparse.dmg");
    encode(&raw, &dmg, &UdifWriteOptions::default());
    assert!(std::fs::metadata(&dmg).unwrap().len() < 64 * 1024);
    hdiutil(&["verify".as_ref(), dmg.as_os_str()]).expect("hdiutil verify");
    let out = hdiutil(&[
        "attach".as_ref(),
        "-readonly".as_ref(),
        "-nomount".as_ref(),
        "-nobrowse".as_ref(),
        dmg.as_os_str(),
    ])
    .expect("hdiutil attach");
    let dev = attached_device(&out).unwrap();
    let _guard = Detach(dev.clone());
    let rdev = dev.replacen("/dev/disk", "/dev/rdisk", 1);
    let bytes = read_device(&rdev, LEN as usize).unwrap();
    assert!(bytes == std::fs::read(&raw).unwrap());
}

/// `fstool convert SRC out.dmg` publishes only a complete image: a
/// success verifies natively, a refused format leaves nothing behind.
#[cfg(feature = "cli")]
#[test]
fn cli_convert_to_dmg() {
    if skip_unless_macos_hdiutil() || !UdifFormat::Ulmo.writable() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let Some((raw, _)) = reference_volume(dir.path()) else {
        return;
    };
    let fstool = env!("CARGO_BIN_EXE_fstool");
    let dmg = dir.path().join("cli.dmg");
    let st = Command::new(fstool)
        .args(["convert".as_ref(), raw.as_os_str(), dmg.as_os_str()])
        .args(["--dmg-format", "ulmo", "--dmg-level", "1"])
        .status()
        .unwrap();
    assert!(st.success());
    hdiutil(&["verify".as_ref(), dmg.as_os_str()]).expect("hdiutil verify");
    let info = hdiutil(&["imageinfo".as_ref(), dmg.as_os_str()]).unwrap();
    assert!(info.lines().any(|l| l == "Format: ULMO"), "{info}");

    let bad = dir.path().join("bad.dmg");
    let st = Command::new(fstool)
        .args(["convert".as_ref(), raw.as_os_str(), bad.as_os_str()])
        .args(["--dmg-format", "ULFO"])
        .status()
        .unwrap();
    assert!(!st.success());
    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains("bad.dmg"))
        .collect();
    assert!(leftovers.is_empty(), "left behind: {leftovers:?}");
}
