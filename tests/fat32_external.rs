//! External validation: produce FAT12 / FAT16 / FAT32 images and check them
//! with `fsck.vfat` (dosfstools) and `mdir` / `mtype` / `mcopy` (mtools).
//! Each test skips silently when the required tool isn't on PATH.

use std::path::Path;
use std::process::Command;

use std::io::Read;

use fstool::block::FileBackend;
use fstool::fs::fat::{Fat32, FatFormatOpts, FatKind};
use tempfile::{NamedTempFile, TempDir};

/// Every flavour, with a volume size that comfortably lands in its
/// cluster-count band.
const FLAVOURS: &[(FatKind, u32)] = &[
    (FatKind::Fat12, 2),
    (FatKind::Fat16, 16),
    (FatKind::Fat32, 64),
];

/// Run `fsck.vfat -n -v` and assert it is happy.
fn assert_fsck_clean(path: &Path, what: &str) {
    let out = Command::new("fsck.vfat")
        .args(["-n", "-v"])
        .arg(path)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "fsck.vfat failed on {what} (exit {:?}):\nstdout:\n{stdout}\nstderr:\n{stderr}",
        out.status.code()
    );
}

/// A small source tree: a short 8.3 name, a nested long name, and a file
/// spanning several clusters.
fn sample_tree() -> TempDir {
    let src = TempDir::new().unwrap();
    std::fs::write(src.path().join("hello.txt"), b"hello, fat\n").unwrap();
    std::fs::create_dir(src.path().join("docs")).unwrap();
    std::fs::write(
        src.path().join("docs").join("LongNameFile.md"),
        b"long-name-content\n",
    )
    .unwrap();
    std::fs::write(src.path().join("blob.bin"), vec![0xA5u8; 200_000]).unwrap();
    src
}

/// Format `kind` at `mib` megabytes and copy `src` into it.
fn build_flavour(path: &Path, kind: FatKind, mib: u32, src: &Path) {
    use fstool::block::BlockDevice;
    let total_sectors = mib * 1024 * 1024 / 512;
    let mut dev = FileBackend::create(path, total_sectors as u64 * 512).unwrap();
    let opts = FatFormatOpts {
        kind,
        total_sectors,
        volume_id: 0xCAFE_F00D,
        volume_label: *b"FSTOOL     ",
        ..Default::default()
    };
    let mut fs = Fat32::format(&mut dev, &opts).expect("format");
    assert_eq!(fs.kind(), kind, "format produced the wrong flavour");
    fs.populate_from_host_dir(&mut dev, src).expect("populate");
    fs.flush(&mut dev).unwrap();
    dev.sync().unwrap();
}

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

fn format_empty(path: &Path, mib: u32) {
    let total_sectors = mib * 1024 * 1024 / 512;
    let bytes = total_sectors as u64 * 512;
    let mut dev = FileBackend::create(path, bytes).expect("create image");
    let opts = FatFormatOpts {
        total_sectors,
        volume_id: 0xCAFE_F00D,
        volume_label: *b"FSTOOL     ",
        ..Default::default()
    };
    Fat32::format(&mut dev, &opts).expect("format fat32");
    use fstool::block::BlockDevice;
    dev.sync().expect("sync");
}

#[test]
fn empty_fat32_passes_fsck_vfat() {
    let Some(_) = which("fsck.vfat") else {
        eprintln!("skipping: fsck.vfat not installed");
        return;
    };
    let tmp = NamedTempFile::new().unwrap();
    format_empty(tmp.path(), 64);

    let out = Command::new("fsck.vfat")
        .args(["-n", "-v"])
        .arg(tmp.path())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "fsck.vfat failed (exit {:?}):\nstdout:\n{stdout}\nstderr:\n{stderr}",
        out.status.code()
    );
}

#[test]
fn build_from_host_dir_passes_fsck_vfat() {
    let Some(_) = which("fsck.vfat") else {
        eprintln!("skipping: fsck.vfat not installed");
        return;
    };
    let src = TempDir::new().unwrap();
    std::fs::write(src.path().join("hello.txt"), b"hello, fat32\n").unwrap();
    std::fs::create_dir(src.path().join("docs")).unwrap();
    std::fs::write(
        src.path().join("docs").join("README.md"),
        b"# Long Name File\n",
    )
    .unwrap();

    let tmp = NamedTempFile::new().unwrap();
    let total_sectors = 64 * 1024 * 1024 / 512;
    {
        use fstool::block::BlockDevice;
        let mut dev = FileBackend::create(tmp.path(), total_sectors as u64 * 512).unwrap();
        Fat32::build_from_host_dir(
            &mut dev,
            total_sectors,
            src.path(),
            0xCAFE_F00D,
            *b"FSTOOL     ",
        )
        .expect("build fat32");
        dev.sync().unwrap();
    }

    let out = Command::new("fsck.vfat")
        .args(["-n", "-v"])
        .arg(tmp.path())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "fsck.vfat failed (exit {:?}):\nstdout:\n{stdout}\nstderr:\n{stderr}",
        out.status.code()
    );
}

#[test]
fn host_dir_contents_visible_via_mtools() {
    let Some(_) = which("mdir") else {
        eprintln!("skipping: mtools not installed");
        return;
    };
    let Some(_) = which("mtype") else {
        eprintln!("skipping: mtools (mtype) not installed");
        return;
    };

    let src = TempDir::new().unwrap();
    std::fs::write(src.path().join("hello.txt"), b"hello, fat32\n").unwrap();
    std::fs::create_dir(src.path().join("docs")).unwrap();
    std::fs::write(src.path().join("docs").join("README.md"), b"long-name\n").unwrap();

    let tmp = NamedTempFile::new().unwrap();
    let total_sectors = 64 * 1024 * 1024 / 512;
    {
        use fstool::block::BlockDevice;
        let mut dev = FileBackend::create(tmp.path(), total_sectors as u64 * 512).unwrap();
        Fat32::build_from_host_dir(
            &mut dev,
            total_sectors,
            src.path(),
            0xCAFE_F00D,
            *b"FSTOOL     ",
        )
        .unwrap();
        dev.sync().unwrap();
    }

    // mtools needs a drive letter -> file mapping; pass via MTOOLSRC env
    // pointing to a config file naming the image as drive ::.
    let cfg = src.path().join("mtoolsrc");
    std::fs::write(
        &cfg,
        format!("drive +: file=\"{}\"\n", tmp.path().display()),
    )
    .unwrap();

    let out = Command::new("mdir")
        .env("MTOOLSRC", &cfg)
        .args(["-i", &tmp.path().display().to_string(), "::/"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "mdir failed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("hello"),
        "mdir output missing hello.txt:\n{stdout}"
    );
    assert!(
        stdout.contains("docs"),
        "mdir output missing docs/:\n{stdout}"
    );

    // Verify a file's contents via mtype.
    let out = Command::new("mtype")
        .args(["-i", &tmp.path().display().to_string(), "::/hello.txt"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "mtype failed:\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"hello, fat32\n");
}

#[test]
fn open_reads_back_our_own_image() {
    let src = TempDir::new().unwrap();
    std::fs::write(src.path().join("hello.txt"), b"hello, fat32\n").unwrap();
    std::fs::create_dir(src.path().join("docs")).unwrap();
    std::fs::write(
        src.path().join("docs").join("LongNameFile.md"),
        b"long-name-content\n",
    )
    .unwrap();

    let tmp = NamedTempFile::new().unwrap();
    let total_sectors = 64 * 1024 * 1024 / 512;
    {
        use fstool::block::BlockDevice;
        let mut dev = FileBackend::create(tmp.path(), total_sectors as u64 * 512).unwrap();
        Fat32::build_from_host_dir(
            &mut dev,
            total_sectors,
            src.path(),
            0xDEAD_BEEF,
            *b"ROUNDTRIP  ",
        )
        .unwrap();
        dev.sync().unwrap();
    }

    let mut dev = FileBackend::open(tmp.path()).unwrap();
    let fs = Fat32::open(&mut dev).unwrap();
    let root = fs.list_path(&mut dev, "/").unwrap();
    let names: Vec<&str> = root.iter().map(|e| e.name.as_str()).collect();
    assert!(names.iter().any(|n| n.eq_ignore_ascii_case("hello.txt")));
    assert!(names.iter().any(|n| n.eq_ignore_ascii_case("docs")));

    // Long name is preserved verbatim.
    let docs = fs.list_path(&mut dev, "/docs").unwrap();
    let docnames: Vec<&str> = docs.iter().map(|e| e.name.as_str()).collect();
    assert!(
        docnames.contains(&"LongNameFile.md"),
        "long name not reconstructed: {docnames:?}"
    );

    // Read a file back through the streaming reader.
    let mut reader = fs.open_file_reader(&mut dev, "/hello.txt").unwrap();
    let mut body = Vec::new();
    reader.read_to_end(&mut body).unwrap();
    assert_eq!(body, b"hello, fat32\n");

    // The deep file, by full path.
    let mut reader = fs
        .open_file_reader(&mut dev, "/docs/LongNameFile.md")
        .unwrap();
    let mut body = Vec::new();
    reader.read_to_end(&mut body).unwrap();
    assert_eq!(body, b"long-name-content\n");
}

#[test]
fn modify_in_place_add_and_remove() {
    let Some(_) = which("fsck.vfat") else {
        eprintln!("skipping: fsck.vfat not installed");
        return;
    };
    // Build a FAT32 from a small source, then mutate it in place.
    let src = TempDir::new().unwrap();
    std::fs::write(src.path().join("original.txt"), b"original\n").unwrap();

    let img = NamedTempFile::new().unwrap();
    let total_sectors = 64 * 1024 * 1024 / 512;
    {
        use fstool::block::BlockDevice;
        let mut dev = FileBackend::create(img.path(), total_sectors as u64 * 512).unwrap();
        Fat32::build_from_host_dir(
            &mut dev,
            total_sectors,
            src.path(),
            0x1234_5678,
            *b"MUTATE     ",
        )
        .unwrap();
        dev.sync().unwrap();
    }

    // Open + add a file at root, add a directory, drop a long-named file
    // in the new directory, then remove the original file.
    let host = TempDir::new().unwrap();
    let added_file = host.path().join("added.txt");
    std::fs::write(&added_file, b"added body\n").unwrap();
    let nested_file = host.path().join("A Long Name.md");
    std::fs::write(&nested_file, b"nested body\n").unwrap();

    {
        use fstool::block::BlockDevice;
        let mut dev = FileBackend::open(img.path()).unwrap();
        let mut fs = Fat32::open(&mut dev).unwrap();
        fs.add_file(&mut dev, "/added.txt", &added_file).unwrap();
        fs.add_dir(&mut dev, "/new", 0).unwrap();
        fs.add_file(&mut dev, "/new/A Long Name.md", &nested_file)
            .unwrap();
        fs.remove(&mut dev, "/original.txt").unwrap();
        fs.flush(&mut dev).unwrap();
        dev.sync().unwrap();
    }

    let res = Command::new("fsck.vfat")
        .args(["-n", "-v"])
        .arg(img.path())
        .output()
        .unwrap();
    assert!(
        res.status.success(),
        "fsck.vfat failed after modify:\n{}",
        String::from_utf8_lossy(&res.stdout)
    );

    let mut dev = FileBackend::open(img.path()).unwrap();
    let fs = Fat32::open(&mut dev).unwrap();
    let root: Vec<String> = fs
        .list_path(&mut dev, "/")
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert!(!root.iter().any(|n| n == "original.txt"));
    assert!(root.iter().any(|n| n == "added.txt"));
    assert!(root.iter().any(|n| n == "new"));

    let mut reader = fs.open_file_reader(&mut dev, "/added.txt").unwrap();
    let mut body = Vec::new();
    reader.read_to_end(&mut body).unwrap();
    assert_eq!(body, b"added body\n");

    let mut reader = fs
        .open_file_reader(&mut dev, "/new/A Long Name.md")
        .unwrap();
    let mut body = Vec::new();
    reader.read_to_end(&mut body).unwrap();
    assert_eq!(body, b"nested body\n");
}

#[test]
fn remove_rejects_non_empty_directory() {
    let src = TempDir::new().unwrap();
    std::fs::create_dir(src.path().join("dir")).unwrap();
    std::fs::write(src.path().join("dir/inner.txt"), b"x\n").unwrap();

    let img = NamedTempFile::new().unwrap();
    let total_sectors = 64 * 1024 * 1024 / 512;
    {
        use fstool::block::BlockDevice;
        let mut dev = FileBackend::create(img.path(), total_sectors as u64 * 512).unwrap();
        Fat32::build_from_host_dir(
            &mut dev,
            total_sectors,
            src.path(),
            0x1234_5678,
            *b"MUTATE     ",
        )
        .unwrap();
        dev.sync().unwrap();
    }

    let mut dev = FileBackend::open(img.path()).unwrap();
    let mut fs = Fat32::open(&mut dev).unwrap();
    let err = fs.remove(&mut dev, "/dir").unwrap_err();
    assert!(
        format!("{err}").contains("not empty"),
        "expected non-empty error, got {err}"
    );
    // Removing the inner file then the dir must succeed.
    fs.remove(&mut dev, "/dir/inner.txt").unwrap();
    fs.remove(&mut dev, "/dir").unwrap();
}

#[test]
fn open_reads_back_an_mkfs_vfat_image() {
    let Some(_) = which("mkfs.vfat") else {
        eprintln!("skipping: mkfs.vfat not installed");
        return;
    };
    let Some(_) = which("mcopy") else {
        eprintln!("skipping: mcopy not installed");
        return;
    };

    let tmp = NamedTempFile::new().unwrap();
    // Zero a 64 MiB file and format it with mkfs.vfat directly.
    let bytes = 64u64 * 1024 * 1024;
    std::fs::File::create(tmp.path())
        .unwrap()
        .set_len(bytes)
        .unwrap();
    let mkfs = Command::new("mkfs.vfat")
        .args(["-F", "32", "-n", "MKFSVOL", "-i", "ABCDEF12"])
        .arg(tmp.path())
        .output()
        .unwrap();
    assert!(
        mkfs.status.success(),
        "mkfs.vfat failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&mkfs.stdout),
        String::from_utf8_lossy(&mkfs.stderr),
    );

    // Drop a host file into the image via mcopy so we have something to read.
    let host_file = TempDir::new().unwrap();
    let hostf = host_file.path().join("CopiedFile.txt");
    std::fs::write(&hostf, b"copied via mtools\n").unwrap();
    let mc = Command::new("mcopy")
        .args(["-i", &tmp.path().display().to_string()])
        .arg(&hostf)
        .arg("::/CopiedFile.txt")
        .output()
        .unwrap();
    assert!(
        mc.status.success(),
        "mcopy failed:\nstderr:\n{}",
        String::from_utf8_lossy(&mc.stderr)
    );

    // Now read it back with our own reader.
    let mut dev = FileBackend::open(tmp.path()).unwrap();
    let fs = Fat32::open(&mut dev).unwrap();
    let root = fs.list_path(&mut dev, "/").unwrap();
    let names: Vec<&str> = root.iter().map(|e| e.name.as_str()).collect();
    assert!(
        names
            .iter()
            .any(|n| n.eq_ignore_ascii_case("CopiedFile.txt")),
        "missing CopiedFile.txt in mkfs.vfat image: {names:?}"
    );

    let mut reader = fs.open_file_reader(&mut dev, "/CopiedFile.txt").unwrap();
    let mut body = Vec::new();
    reader.read_to_end(&mut body).unwrap();
    assert_eq!(body, b"copied via mtools\n");
}

// ----------------------------------------------------------------------
// FAT12 / FAT16 — the flavours whose root directory is a fixed region and
// whose FAT entries are 12 or 16 bits wide.
// ----------------------------------------------------------------------

/// Every flavour we can write must satisfy dosfstools, empty and populated.
#[test]
fn every_flavour_passes_fsck_vfat() {
    let Some(_) = which("fsck.vfat") else {
        eprintln!("skipping: fsck.vfat not installed");
        return;
    };
    let src = sample_tree();
    for &(kind, mib) in FLAVOURS {
        let empty = NamedTempFile::new().unwrap();
        {
            use fstool::block::BlockDevice;
            let total_sectors = mib * 1024 * 1024 / 512;
            let mut dev = FileBackend::create(empty.path(), total_sectors as u64 * 512).unwrap();
            let opts = FatFormatOpts {
                kind,
                total_sectors,
                volume_id: 0xCAFE_F00D,
                volume_label: *b"FSTOOL     ",
                ..Default::default()
            };
            Fat32::format(&mut dev, &opts).expect("format");
            dev.sync().unwrap();
        }
        assert_fsck_clean(empty.path(), &format!("empty {}", kind.as_str()));

        let full = NamedTempFile::new().unwrap();
        build_flavour(full.path(), kind, mib, src.path());
        assert_fsck_clean(full.path(), &format!("populated {}", kind.as_str()));
    }
}

/// mtools is an independent implementation: if it can list and read our
/// FAT12/FAT16 images, our BPB, FAT packing and fixed root are all right.
#[test]
fn every_flavour_is_readable_by_mtools() {
    let Some(_) = which("mdir") else {
        eprintln!("skipping: mtools not installed");
        return;
    };
    let Some(_) = which("mtype") else {
        eprintln!("skipping: mtools (mtype) not installed");
        return;
    };
    let src = sample_tree();
    for &(kind, mib) in FLAVOURS {
        let img = NamedTempFile::new().unwrap();
        build_flavour(img.path(), kind, mib, src.path());
        let path = img.path().display().to_string();

        let out = Command::new("mdir")
            .args(["-i", &path, "::/"])
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "mdir failed on {}:\n{stdout}\n{}",
            kind.as_str(),
            String::from_utf8_lossy(&out.stderr)
        );
        for want in ["hello", "docs", "blob"] {
            assert!(
                stdout.contains(want),
                "mdir output for {} missing {want:?}:\n{stdout}",
                kind.as_str()
            );
        }

        // A long name in a subdirectory — LFN runs work the same at every
        // entry width, but the subdirectory is reached through the fixed
        // root on FAT12/16.
        let out = Command::new("mtype")
            .args(["-i", &path, "::/docs/LongNameFile.md"])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "mtype failed on {}:\n{}",
            kind.as_str(),
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(out.stdout, b"long-name-content\n", "{}", kind.as_str());
    }
}

/// Round-trip through our own reader, including the multi-cluster file —
/// which exercises chain walking at all three entry widths.
#[test]
fn every_flavour_round_trips_through_our_reader() {
    let src = sample_tree();
    for &(kind, mib) in FLAVOURS {
        let img = NamedTempFile::new().unwrap();
        build_flavour(img.path(), kind, mib, src.path());

        let mut dev = FileBackend::open(img.path()).unwrap();
        let fs = Fat32::open(&mut dev).unwrap();
        assert_eq!(fs.kind(), kind, "re-opened as the wrong flavour");

        let root: Vec<String> = fs
            .list_path(&mut dev, "/")
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        for want in ["hello.txt", "docs", "blob.bin"] {
            assert!(
                root.iter().any(|n| n.eq_ignore_ascii_case(want)),
                "{} root missing {want}: {root:?}",
                kind.as_str()
            );
        }

        let docs: Vec<String> = fs
            .list_path(&mut dev, "/docs")
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert!(
            docs.contains(&"LongNameFile.md".to_string()),
            "{} lost the long name: {docs:?}",
            kind.as_str()
        );

        let mut body = Vec::new();
        fs.open_file_reader(&mut dev, "/blob.bin")
            .unwrap()
            .read_to_end(&mut body)
            .unwrap();
        assert_eq!(body, vec![0xA5u8; 200_000], "{} blob", kind.as_str());
    }
}

/// Modify-in-place on the narrow flavours: adding to the fixed root, adding
/// a subdirectory, and freeing a chain must all leave a volume dosfstools
/// still accepts.
#[test]
fn narrow_flavours_survive_modify_in_place() {
    let Some(_) = which("fsck.vfat") else {
        eprintln!("skipping: fsck.vfat not installed");
        return;
    };
    let src = sample_tree();
    let host = TempDir::new().unwrap();
    let added = host.path().join("added.txt");
    std::fs::write(&added, b"added body\n").unwrap();
    let nested = host.path().join("A Long Name.md");
    std::fs::write(&nested, b"nested body\n").unwrap();

    for &(kind, mib) in &FLAVOURS[..2] {
        let img = NamedTempFile::new().unwrap();
        build_flavour(img.path(), kind, mib, src.path());
        {
            use fstool::block::BlockDevice;
            let mut dev = FileBackend::open(img.path()).unwrap();
            let mut fs = Fat32::open(&mut dev).unwrap();
            fs.add_file(&mut dev, "/added.txt", &added).unwrap();
            fs.add_dir(&mut dev, "/new", 0).unwrap();
            fs.add_file(&mut dev, "/new/A Long Name.md", &nested)
                .unwrap();
            fs.remove(&mut dev, "/hello.txt").unwrap();
            fs.flush(&mut dev).unwrap();
            dev.sync().unwrap();
        }
        assert_fsck_clean(img.path(), &format!("mutated {}", kind.as_str()));

        let mut dev = FileBackend::open(img.path()).unwrap();
        let fs = Fat32::open(&mut dev).unwrap();
        let root: Vec<String> = fs
            .list_path(&mut dev, "/")
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert!(
            !root.iter().any(|n| n == "hello.txt"),
            "{} kept the removed file: {root:?}",
            kind.as_str()
        );
        assert!(root.iter().any(|n| n == "added.txt"), "{root:?}");
        assert!(root.iter().any(|n| n == "new"), "{root:?}");

        let mut body = Vec::new();
        fs.open_file_reader(&mut dev, "/new/A Long Name.md")
            .unwrap()
            .read_to_end(&mut body)
            .unwrap();
        assert_eq!(body, b"nested body\n", "{}", kind.as_str());
    }
}

/// The fixed root cannot grow. Filling it must fail with a message that
/// says so and names the way out — never corrupt the data area behind it.
#[test]
fn fixed_root_reports_a_clear_error_when_full() {
    use fstool::block::BlockDevice;
    let mut dev = fstool::block::MemoryBackend::new(4 * 1024 * 1024);
    let opts = FatFormatOpts {
        kind: FatKind::Fat16,
        total_sectors: 4 * 1024 * 1024 / 512,
        volume_id: 0,
        volume_label: *b"TINYROOT   ",
        // The smallest sector-aligned root: 16 slots, one of which the
        // volume label takes.
        root_entries: Some(16),
    };
    let mut fs = Fat32::format(&mut dev, &opts).unwrap();
    let host = TempDir::new().unwrap();
    let f = host.path().join("f.txt");
    std::fs::write(&f, b"x").unwrap();

    let mut err = None;
    for i in 0..32 {
        // Plain 8.3 names, so each child costs exactly one slot.
        if let Err(e) = fs.add_file(&mut dev, &format!("/F{i}.TXT"), &f) {
            err = Some(e);
            break;
        }
        if let Err(e) = fs.flush(&mut dev) {
            err = Some(e);
            break;
        }
    }
    let err = err.expect("a 16-slot root must fill before 32 files");
    let msg = format!("{err}");
    assert!(
        msg.contains("root directory is fixed at 16 entries"),
        "unhelpful root-full error: {msg}"
    );
    assert!(msg.contains("root_entries"), "no way out offered: {msg}");

    // The volume is still coherent: everything written before the failure
    // reads back.
    fs.flush(&mut dev).ok();
    let fs = Fat32::open(&mut dev).unwrap();
    let root = fs.list_path(&mut dev, "/").unwrap();
    assert!(!root.is_empty());
    assert!(root.len() < 16);
    let _ = dev.sync();
}

/// Read images produced by mkfs.vfat itself at each width, populated by
/// mcopy — the other direction of the interop check.
#[test]
fn open_reads_back_mkfs_vfat_fat12_and_fat16_images() {
    let Some(_) = which("mkfs.vfat") else {
        eprintln!("skipping: mkfs.vfat not installed");
        return;
    };
    let Some(_) = which("mcopy") else {
        eprintln!("skipping: mcopy not installed");
        return;
    };
    let host = TempDir::new().unwrap();
    let hostf = host.path().join("CopiedFile.txt");
    std::fs::write(&hostf, b"copied via mtools\n").unwrap();

    for (bits, kib, want_kind) in [
        (12u32, 1440u64, FatKind::Fat12),
        (16, 32768, FatKind::Fat16),
    ] {
        let tmp = NamedTempFile::new().unwrap();
        std::fs::File::create(tmp.path())
            .unwrap()
            .set_len(kib * 1024)
            .unwrap();
        let mkfs = Command::new("mkfs.vfat")
            .args(["-F", &bits.to_string(), "-n", "MKFSVOL"])
            .arg(tmp.path())
            .output()
            .unwrap();
        assert!(
            mkfs.status.success(),
            "mkfs.vfat -F {bits} failed:\n{}",
            String::from_utf8_lossy(&mkfs.stderr)
        );
        let mc = Command::new("mcopy")
            .args(["-i", &tmp.path().display().to_string()])
            .arg(&hostf)
            .arg("::/CopiedFile.txt")
            .output()
            .unwrap();
        assert!(
            mc.status.success(),
            "mcopy failed:\n{}",
            String::from_utf8_lossy(&mc.stderr)
        );

        let mut dev = FileBackend::open(tmp.path()).unwrap();
        let fs = Fat32::open(&mut dev).unwrap();
        assert_eq!(
            fs.kind(),
            want_kind,
            "mkfs.vfat -F {bits} image classified wrong"
        );
        let names: Vec<String> = fs
            .list_path(&mut dev, "/")
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert!(
            names
                .iter()
                .any(|n| n.eq_ignore_ascii_case("CopiedFile.txt")),
            "missing CopiedFile.txt in -F {bits} image: {names:?}"
        );
        let mut body = Vec::new();
        fs.open_file_reader(&mut dev, "/CopiedFile.txt")
            .unwrap()
            .read_to_end(&mut body)
            .unwrap();
        assert_eq!(body, b"copied via mtools\n");
    }
}

/// `detect_fs` has no magic string to lean on for FAT12/16 — it probes the
/// BPB — so prove it classifies real images of each flavour.
#[test]
fn detect_fs_recognises_every_flavour() {
    let src = sample_tree();
    for &(kind, mib) in FLAVOURS {
        let img = NamedTempFile::new().unwrap();
        build_flavour(img.path(), kind, mib, src.path());
        let mut dev = FileBackend::open(img.path()).unwrap();
        assert_eq!(
            fstool::inspect::detect_fs(&mut dev).unwrap(),
            fstool::inspect::FsKind::Fat32,
            "detect_fs missed a {} volume",
            kind.as_str()
        );
        // And the opened volume reports the real flavour.
        let mut dev = FileBackend::open(img.path()).unwrap();
        assert_eq!(
            fstool::inspect::AnyFs::open(&mut dev)
                .unwrap()
                .kind_string(),
            kind.as_str()
        );
    }
}
