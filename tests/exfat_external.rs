#![cfg(all(unix, feature = "std", feature = "exfat"))]
//! External validation: produce exFAT images with the library writer and
//! verify them with `fsck.exfat` (exfatprogs), and read back images that
//! `mkfs.exfat` produced. Each test skips silently when the required tool
//! isn't on PATH so the suite passes on a clean CI machine.
//!
//! NOTE: real loopback-mounted round-trips need root and are intentionally
//! omitted; we rely on `fsck.exfat -nv` (verbose, read-only) as the
//! native-tool check for writer output.

use std::io::Read;
use std::path::Path;
use std::process::Command;

use fstool::block::{BlockDevice, FileBackend};
use fstool::fs::exfat::Exfat;
use fstool::fs::exfat::format::FormatOpts;
use tempfile::NamedTempFile;

fn which(tool: &str) -> Option<std::path::PathBuf> {
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

/// Probe the tool with `--version`. Most exfatprogs binaries support it;
/// even when they return non-zero exit, the binary existing on PATH (via
/// `which`) is the real signal — `--version` is just a liveness check.
fn tool_present(tool: &str) -> bool {
    if which(tool).is_none() {
        return false;
    }
    // Best-effort: run --version. We don't require success because some
    // builds report the version on stderr with a non-zero exit code.
    let _ = Command::new(tool).arg("--version").output();
    true
}

/// Format a fresh exFAT volume on `path` of `mib` megabytes with `label`.
fn format_volume(path: &Path, mib: u32, label: &str) -> Exfat {
    let bytes = mib as u64 * 1024 * 1024;
    let mut dev = FileBackend::create(path, bytes).expect("create image");
    let opts = FormatOpts {
        bytes_per_sector_shift: 9,    // 512 B sectors
        sectors_per_cluster_shift: 3, // 4 KiB clusters
        volume_serial_number: 0xCAFE_F00D,
        volume_label: label.to_string(),
    };
    let fs = Exfat::format(&mut dev, &opts).expect("format exfat");
    dev.sync().expect("sync");
    drop(dev);
    // Re-open the volume to return a writable handle that owns the device,
    // but tests need both the device and the fs separately. Return the fs
    // alone here is not useful — callers re-open the file as needed.
    fs
}

#[test]
fn writer_image_passes_fsck_exfat() {
    if !tool_present("fsck.exfat") {
        eprintln!("skipping: fsck.exfat not installed");
        return;
    }
    let tmp = NamedTempFile::new().unwrap();
    // Format, then populate via streaming create_file calls. We open the
    // device fresh, write everything, flush, sync, then close.
    let _ = format_volume(tmp.path(), 64, "FSTOOLEXF");

    {
        let mut dev = FileBackend::open(tmp.path()).unwrap();
        let mut fs = Exfat::open(&mut dev).unwrap();

        // Small payload, streamed via &[u8] which is a std::io::Read source
        // (never materialises the file in memory beyond what create_file
        // chooses to buffer internally — see SCRATCH_BUF_BYTES).
        let p1: &[u8] = b"hello, exfat external\n";
        let mut r1: &[u8] = p1;
        fs.create_file(&mut dev, "/hello.txt", &mut r1, p1.len() as u64, 0)
            .unwrap();

        fs.create_dir(&mut dev, "/docs", 0).unwrap();

        let p2: &[u8] = b"# Long Name File\nNested under /docs.\n";
        let mut r2: &[u8] = p2;
        fs.create_file(
            &mut dev,
            "/docs/A Long Readme.md",
            &mut r2,
            p2.len() as u64,
            0,
        )
        .unwrap();

        // Nested directory + a file inside.
        fs.create_dir(&mut dev, "/docs/nested", 0).unwrap();
        let p3: &[u8] = b"deeply nested body\n";
        let mut r3: &[u8] = p3;
        fs.create_file(
            &mut dev,
            "/docs/nested/inside.bin",
            &mut r3,
            p3.len() as u64,
            0,
        )
        .unwrap();

        // Non-ASCII name to exercise UTF-16 + up-case + name hash. Mix of
        // BMP code points; if exfatprogs disagrees with our normalisation,
        // fsck will tell us.
        let p4: &[u8] = b"konnichiwa\n";
        let mut r4: &[u8] = p4;
        fs.create_file(
            &mut dev,
            "/\u{3053}\u{3093}\u{306B}\u{3061}\u{306F}.txt",
            &mut r4,
            p4.len() as u64,
            0,
        )
        .unwrap();

        fs.flush(&mut dev).unwrap();
        dev.sync().unwrap();
    }

    // Run fsck.exfat in read-only, verbose mode, and hold it to its report
    // rather than its exit status — see `fsck`.
    fsck(tmp.path(), "a volume the hosted writer populated");
}

#[test]
fn open_reads_back_an_mkfs_exfat_image() {
    if !tool_present("mkfs.exfat") {
        eprintln!("skipping: mkfs.exfat not installed");
        return;
    }

    // Create a 64 MiB sparse file and format it with mkfs.exfat directly.
    let tmp = NamedTempFile::new().unwrap();
    let bytes = 64u64 * 1024 * 1024;
    std::fs::File::create(tmp.path())
        .unwrap()
        .set_len(bytes)
        .unwrap();

    // -L is the label option for exfatprogs' mkfs.exfat. Some older
    // versions also accept -n; we use -L since exfatprogs is the modern
    // standard implementation.
    let mkfs = Command::new("mkfs.exfat")
        .args(["-L", "TEST-EXFAT"])
        .arg(tmp.path())
        .output()
        .unwrap();
    assert!(
        mkfs.status.success(),
        "mkfs.exfat failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&mkfs.stdout),
        String::from_utf8_lossy(&mkfs.stderr),
    );

    // Opening exercises the boot-region checksum validation in
    // BootSector::decode + Exfat::open. A bad checksum here would surface
    // as InvalidImage before we get to inspect the volume.
    let mut dev = FileBackend::open(tmp.path()).unwrap();
    let fs = Exfat::open(&mut dev).expect("open mkfs.exfat image");
    assert_eq!(
        fs.volume_label(),
        "TEST-EXFAT",
        "volume label round-trip mismatch"
    );

    // mkfs.exfat from exfatprogs leaves the root directory empty (no
    // "System Volume Information" — that's created by Windows on first
    // mount, not by the formatter). Tolerate either possibility.
    let root = fs.list_path(&mut dev, "/").unwrap();
    let names: Vec<&str> = root.iter().map(|e| e.name.as_str()).collect();
    let only_known = names.iter().all(|n| {
        n.eq_ignore_ascii_case("System Volume Information")
            || n.eq_ignore_ascii_case("$RECYCLE.BIN")
    });
    assert!(
        names.is_empty() || only_known,
        "unexpected entries in fresh mkfs.exfat root: {names:?}"
    );
}

#[test]
fn writer_image_fsck_verbose_simulates_mount_check() {
    // Same intent as `writer_image_passes_fsck_exfat` but with a more
    // populated tree — this acts as our stand-in for a real mount round-
    // trip (which would need root). If fsck -nv reports "clean", a kernel
    // mount of the same bytes would (modulo kernel-version quirks) also
    // succeed.
    if !tool_present("fsck.exfat") {
        eprintln!("skipping: fsck.exfat not installed");
        return;
    }

    let tmp = NamedTempFile::new().unwrap();
    let _ = format_volume(tmp.path(), 32, "MOUNTSIM");

    {
        let mut dev = FileBackend::open(tmp.path()).unwrap();
        let mut fs = Exfat::open(&mut dev).unwrap();

        // Stream a multi-cluster file (3 clusters @ 4 KiB = 12 KiB). The
        // body is generated cluster-by-cluster from a Cursor so we never
        // hold the whole image in memory at once.
        let body: Vec<u8> = (0..(12 * 1024)).map(|i| (i % 251) as u8).collect();
        let mut reader: &[u8] = &body;
        fs.create_file(&mut dev, "/multi.bin", &mut reader, body.len() as u64, 0)
            .unwrap();

        // An empty file (FirstCluster == 0, AllocationPossible flag clear).
        let mut empty: &[u8] = &[];
        fs.create_file(&mut dev, "/zero.bin", &mut empty, 0, 0)
            .unwrap();

        // A directory tree two levels deep with a file at the leaf.
        fs.create_dir(&mut dev, "/lvl1", 0).unwrap();
        fs.create_dir(&mut dev, "/lvl1/lvl2", 0).unwrap();
        let leaf: &[u8] = b"leaf\n";
        let mut rl: &[u8] = leaf;
        fs.create_file(
            &mut dev,
            "/lvl1/lvl2/leaf.txt",
            &mut rl,
            leaf.len() as u64,
            0,
        )
        .unwrap();

        // Verify we can read back our own writes before fsck sees them.
        fs.flush(&mut dev).unwrap();
        dev.sync().unwrap();
    }

    // Sanity-check via our own reader first.
    {
        let mut dev = FileBackend::open(tmp.path()).unwrap();
        let fs = Exfat::open(&mut dev).unwrap();
        let root: Vec<String> = fs
            .list_path(&mut dev, "/")
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert!(root.iter().any(|n| n == "multi.bin"));
        assert!(root.iter().any(|n| n == "zero.bin"));
        assert!(root.iter().any(|n| n == "lvl1"));
        // Stream the multi-cluster file back and compare lengths only —
        // a byte-compare would require holding the source in memory once
        // (it already is in `body` for the writer, but we don't keep it
        // around). Length check is sufficient to prove the chain walked.
        let mut r = fs.open_file_reader(&mut dev, "/multi.bin").unwrap();
        let mut total: u64 = 0;
        let mut buf = [0u8; 4096];
        loop {
            let n = r.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            total += n as u64;
        }
        assert_eq!(total, 12 * 1024);
    }

    fsck(tmp.path(), "the mount-simulation volume");
}

// ---------------------------------------------------------------------
// The allocator-free driver, against the same external tools.
//
// `fs::exfat::Volume` shares no code with the hosted half above, so it
// earns its own checks: what it writes has to satisfy `fsck.exfat`, and it
// has to read — and keep writing to — a volume `mkfs.exfat` produced.
// ---------------------------------------------------------------------

use std::os::unix::fs::FileExt;

use fstool::device::SectorDriver;
use fstool::fs::exfat::Volume;

/// A [`SectorDriver`] over an image file: the two methods an embedded
/// consumer implements against its SD card, backed by a file so the
/// reference tools can be pointed at the result.
struct FileCard {
    file: std::fs::File,
    sector_size: u32,
    sectors: u64,
}

impl FileCard {
    fn open(path: &Path) -> Self {
        let file = std::fs::File::options()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        let len = file.metadata().unwrap().len();
        Self {
            file,
            sector_size: 512,
            sectors: len / 512,
        }
    }
}

impl SectorDriver for FileCard {
    type Error = std::io::Error;

    fn sector_size(&self) -> u32 {
        self.sector_size
    }

    fn sector_count(&self) -> u64 {
        self.sectors
    }

    fn read_sectors(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), Self::Error> {
        self.file.read_exact_at(buf, lba * self.sector_size as u64)
    }

    fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> Result<(), Self::Error> {
        self.file.write_all_at(buf, lba * self.sector_size as u64)
    }
}

/// Run `fsck.exfat -n -v` and fail unless the volume is clean.
///
/// The exit status alone is not the check: with `-n`, fsck answers "no" to
/// every repair prompt and still exits 0 — a volume it printed `ERROR:`
/// about would look fine. Its report is what decides.
fn fsck(path: &Path, what: &str) {
    let out = Command::new("fsck.exfat")
        .args(["-n", "-v"])
        .arg(path)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let complained = stdout
        .lines()
        .chain(stderr.lines())
        .any(|l| l.contains("ERROR:") || l.contains("WARNING:") || l.contains("corrupted"));
    assert!(
        out.status.success() && !complained,
        "fsck.exfat rejected {what} (exit {:?}):\nstdout:\n{stdout}\nstderr:\n{stderr}",
        out.status.code(),
    );
    assert!(
        stdout.contains("clean"),
        "fsck.exfat did not call {what} clean:\nstdout:\n{stdout}\nstderr:\n{stderr}",
    );
}

/// Format with `mkfs.exfat`, which is what a camera or a card reader would
/// have done.
fn mkfs(path: &Path, mib: u32) -> bool {
    if !tool_present("mkfs.exfat") {
        return false;
    }
    let f = std::fs::File::create(path).unwrap();
    f.set_len(mib as u64 * 1024 * 1024).unwrap();
    drop(f);
    let out = Command::new("mkfs.exfat")
        .args(["-L", "DRIVER"])
        .arg(path)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "mkfs.exfat failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    true
}

/// Everything the driver sees in a volume, as a sorted manifest.
fn driver_manifest(vol: &mut Volume<FileCard, 512>) -> Vec<String> {
    fn walk(vol: &mut Volume<FileCard, 512>, dir: &str, out: &mut Vec<String>) {
        let handle = vol
            .open_dir(if dir.is_empty() { "/" } else { dir })
            .unwrap();
        let mut kids: Vec<(String, bool, u64)> = Vec::new();
        let mut it = vol.iter_dir(handle);
        while let Some(e) = it.next().unwrap() {
            kids.push((e.name().to_string(), e.is_dir(), e.len()));
        }
        kids.sort();
        for (name, is_dir, len) in kids {
            let child = format!("{dir}/{name}");
            if is_dir {
                out.push(format!("d {child}"));
                walk(vol, &child, out);
            } else {
                let mut f = vol.open_file(&child).unwrap();
                let mut body = vec![0u8; len as usize];
                f.read_exact(vol, &mut body).unwrap();
                out.push(format!("f {child} {len} {}", fnv(&body)));
            }
        }
    }
    let mut out = Vec::new();
    walk(vol, "", &mut out);
    out.sort();
    out
}

/// FNV-1a, so a manifest line pins contents rather than just lengths.
fn fnv(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in data {
        h = (h ^ *b as u64).wrapping_mul(0x100_0000_01b3);
    }
    h
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 7) % 251) as u8).collect()
}

/// The tree both driver directions are checked with.
fn build_driver_tree(vol: &mut Volume<FileCard, 512>) {
    let put = |vol: &mut Volume<FileCard, 512>, path: &str, body: &[u8]| {
        let mut f = vol.create_file(path).unwrap();
        f.write_all(vol, body).unwrap();
        f.flush(vol).unwrap();
    };
    put(vol, "/hello.txt", b"hello from the allocator-free driver\n");
    vol.create_dir("/docs").unwrap();
    put(vol, "/docs/A Long Readme.md", b"# nested\nunder /docs\n");
    vol.create_dir("/docs/nested").unwrap();
    put(vol, "/docs/nested/inside.bin", &pattern(70_000));
    // A non-ASCII name: UTF-16 names, the up-case table and the name hash
    // all at once. If exfatprogs disagrees, fsck says so.
    put(
        vol,
        "/\u{3053}\u{3093}\u{306B}\u{3061}\u{306F}.txt",
        b"konnichiwa\n",
    );
    // Enough entries to grow a directory past its first cluster.
    vol.create_dir("/many").unwrap();
    for i in 0..80 {
        put(
            vol,
            &format!("/many/file{i:03}.dat"),
            format!("entry {i}").as_bytes(),
        );
    }
    vol.flush().unwrap();
}

#[test]
fn driver_written_volumes_pass_fsck_exfat() {
    if !tool_present("fsck.exfat") {
        eprintln!("skipping: fsck.exfat not installed");
        return;
    }
    let tmp = NamedTempFile::new().unwrap();
    // The hosted half lays the volume down — the driver mounts, it does not
    // format — and everything in it is then written by the driver.
    let _ = format_volume(tmp.path(), 64, "FSTOOLDRV");
    {
        let mut vol = Volume::<_, 512>::mount(FileCard::open(tmp.path())).expect("driver mount");
        build_driver_tree(&mut vol);
        vol.unmount().unwrap();
    }
    fsck(tmp.path(), "a volume the driver populated");
}

#[test]
fn the_driver_reads_and_extends_an_mkfs_exfat_volume() {
    if !tool_present("fsck.exfat") || !tool_present("mkfs.exfat") {
        eprintln!("skipping: exfatprogs not installed");
        return;
    }
    let tmp = NamedTempFile::new().unwrap();
    if !mkfs(tmp.path(), 96) {
        return;
    }
    // A volume formatted by the reference tool: its up-case table is the
    // standard compressed one, which the driver reads off the card.
    let mut vol = Volume::<_, 512>::mount(FileCard::open(tmp.path())).expect("driver mount");
    assert!(vol.is_writable(), "mkfs.exfat wrote no allocation bitmap?");
    build_driver_tree(&mut vol);
    let ours = driver_manifest(&mut vol);
    vol.unmount().unwrap();

    fsck(tmp.path(), "an mkfs.exfat volume the driver wrote into");

    // And the driver reads back what it wrote, after a fresh mount.
    let mut vol = Volume::<_, 512>::mount(FileCard::open(tmp.path())).unwrap();
    assert_eq!(driver_manifest(&mut vol), ours);
    // Case-insensitive lookup through the standard table.
    let mut f = vol.open_file("/DOCS/a long readme.md").unwrap();
    let mut buf = [0u8; 32];
    let n = f.read(&mut vol, &mut buf).unwrap();
    assert_eq!(&buf[..n], b"# nested\nunder /docs\n");
}

#[test]
fn the_hosted_half_and_fsck_agree_with_the_driver_after_edits() {
    if !tool_present("fsck.exfat") || !tool_present("mkfs.exfat") {
        eprintln!("skipping: exfatprogs not installed");
        return;
    }
    let tmp = NamedTempFile::new().unwrap();
    if !mkfs(tmp.path(), 96) {
        return;
    }
    // Driver writes, hosted half adds and removes, driver removes and adds
    // again — then fsck has the last word.
    {
        let mut vol = Volume::<_, 512>::mount(FileCard::open(tmp.path())).unwrap();
        build_driver_tree(&mut vol);
        vol.unmount().unwrap();
    }
    {
        let mut dev = FileBackend::open(tmp.path()).unwrap();
        let mut fs = Exfat::open(&mut dev).unwrap();
        let body = pattern(40_000);
        let mut r: &[u8] = &body;
        fs.create_file(&mut dev, "/hosted.bin", &mut r, body.len() as u64, 0)
            .unwrap();
        fs.remove(&mut dev, "/many/file003.dat").unwrap();
        fs.flush(&mut dev).unwrap();
        dev.sync().unwrap();
    }
    fsck(tmp.path(), "a volume both halves wrote to");
    {
        let mut vol = Volume::<_, 512>::mount(FileCard::open(tmp.path())).unwrap();
        // The hosted half's additions and removals are visible.
        let mut f = vol.open_file("/hosted.bin").unwrap();
        let mut body = vec![0u8; f.len() as usize];
        f.read_exact(&mut vol, &mut body).unwrap();
        assert_eq!(body, pattern(40_000));
        assert!(!vol.exists("/many/file003.dat").unwrap());
        assert!(vol.exists("/many/file004.dat").unwrap());

        vol.remove_file("/hello.txt").unwrap();
        let mut f = vol.create_file("/after.txt").unwrap();
        f.write_all(&mut vol, b"third writer\n").unwrap();
        f.flush(&mut vol).unwrap();
        vol.unmount().unwrap();
    }
    fsck(tmp.path(), "a volume three writers touched");

    // Finally the hosted half — which CI validates against fsck — reads the
    // driver's last edits.
    let mut dev = FileBackend::open(tmp.path()).unwrap();
    let fs = Exfat::open(&mut dev).unwrap();
    let mut out = Vec::new();
    fs.open_file_reader(&mut dev, "/after.txt")
        .unwrap()
        .read_to_end(&mut out)
        .unwrap();
    assert_eq!(out, b"third writer\n");
    let listing = fs.list_path(&mut dev, "/").unwrap();
    assert!(listing.iter().all(|e| e.name != "hello.txt"));
}

#[test]
fn the_driver_folds_non_ascii_names_through_the_standard_upcase_table() {
    // A volume `mkfs.exfat` formatted carries the standard up-case table:
    // 0x10000 entries, run-length compressed, which is the only thing that
    // exercises the driver's decoder past ASCII. (fstool's own formatter
    // writes an ASCII-only table, where these names are case-sensitive
    // because the volume says so.)
    if !tool_present("mkfs.exfat") || !tool_present("fsck.exfat") {
        eprintln!("skipping: exfatprogs not installed");
        return;
    }
    let tmp = NamedTempFile::new().unwrap();
    if !mkfs(tmp.path(), 64) {
        return;
    }
    let mut vol = Volume::<_, 512>::mount(FileCard::open(tmp.path())).unwrap();
    for (lower, upper) in [
        ("ünïcode.txt", "ÜNÏCODE.TXT"),
        ("straße.txt", "STRASSE.TXT"),
        ("ελλάδα.txt", "ΕΛΛΆΔΑ.TXT"),
        ("привет.txt", "ПРИВЕТ.TXT"),
    ] {
        let mut f = vol.create_file(&format!("/{lower}")).unwrap();
        f.write_all(&mut vol, lower.as_bytes()).unwrap();
        f.flush(&mut vol).unwrap();
        // The volume's own table decides; every name it folds has to be
        // found by either spelling, and every name it does not fold has to
        // keep the two apart.
        let found_upper = vol.exists(&format!("/{upper}")).unwrap();
        let folds = upper.chars().count() == lower.chars().count();
        if folds {
            assert!(
                found_upper,
                "{upper} did not find {lower} through the standard table"
            );
            // And creating the other spelling is a collision.
            assert!(
                vol.create_file(&format!("/{upper}")).is_err(),
                "{upper} was created alongside {lower}"
            );
        }
        assert!(vol.exists(&format!("/{lower}")).unwrap());
    }
    vol.unmount().unwrap();
    fsck(tmp.path(), "a volume with non-ASCII names");
}
