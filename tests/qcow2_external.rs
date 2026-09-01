//! qcow2 backend validation against real `qemu-img`-produced images.
//! Each test skips silently when `qemu-img` isn't on PATH.

use std::io::Read as _;
use std::process::Command;

use fstool::block::{BlockDevice, Qcow2Backend};
use tempfile::NamedTempFile;

fn which(tool: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {tool}"))
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// `qemu-img create -f qcow2 …` produces an empty image whose virtual
/// size and cluster_size we should parse correctly.
#[test]
fn opens_qemu_img_created_image() {
    if !which("qemu-img") {
        eprintln!("skipping: qemu-img not installed");
        return;
    }
    let tmp = NamedTempFile::new().unwrap();
    let out = Command::new("qemu-img")
        .args(["create", "-q", "-f", "qcow2"])
        .arg(tmp.path())
        .arg("64M")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "qemu-img create failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let back = Qcow2Backend::open(tmp.path()).unwrap();
    assert_eq!(back.total_size(), 64 * 1024 * 1024);
    assert_eq!(back.header().cluster_size(), 65536);
    // qemu-img defaults to v3 (`compat=1.1`).
    assert_eq!(back.header().version, 3);
}

/// Read-back invariant: write a pattern into a raw image, convert it to
/// qcow2 via qemu-img, and read it through Qcow2Backend. Bytes must
/// match the original pattern.
#[test]
fn read_back_pattern_via_qemu_img_convert() {
    if !which("qemu-img") {
        eprintln!("skipping: qemu-img not installed");
        return;
    }

    // Build a 4 MiB raw image with a known pattern at a few offsets.
    let raw = NamedTempFile::new().unwrap();
    {
        use std::io::Write as _;
        let mut f = std::fs::File::create(raw.path()).unwrap();
        f.set_len(4 * 1024 * 1024).unwrap();
        f.write_all(b"hello qcow2 reader\n").unwrap();
        // Pattern straddling a 64 KiB cluster boundary.
        use std::io::Seek as _;
        use std::io::SeekFrom;
        f.seek(SeekFrom::Start(65500)).unwrap();
        f.write_all(&[0xAB; 200]).unwrap();
        // Pattern in the middle of a cluster.
        f.seek(SeekFrom::Start(2 * 1024 * 1024)).unwrap();
        f.write_all(b"halfway through\n").unwrap();
        f.sync_all().unwrap();
    }

    // Convert raw → qcow2.
    let qcow = NamedTempFile::new().unwrap();
    let out = Command::new("qemu-img")
        .args(["convert", "-f", "raw", "-O", "qcow2"])
        .arg(raw.path())
        .arg(qcow.path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "qemu-img convert failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Read through Qcow2Backend; bytes should match what we wrote.
    let mut back = Qcow2Backend::open(qcow.path()).unwrap();
    assert_eq!(back.total_size(), 4 * 1024 * 1024);

    let mut head = [0u8; 32];
    back.read_at(0, &mut head).unwrap();
    assert_eq!(&head[..19], b"hello qcow2 reader\n");

    let mut straddle = [0u8; 200];
    back.read_at(65500, &mut straddle).unwrap();
    assert!(straddle.iter().all(|&b| b == 0xAB));

    let mut mid = [0u8; 16];
    back.read_at(2 * 1024 * 1024, &mut mid).unwrap();
    assert_eq!(&mid, b"halfway through\n");

    // Unallocated tail reads as zeros.
    let mut tail = [0xffu8; 4096];
    back.read_at(3 * 1024 * 1024, &mut tail).unwrap();
    assert!(tail.iter().all(|&b| b == 0), "tail should be zero");

    // Stream the whole thing via Read.
    use std::io::Seek as _;
    use std::io::SeekFrom;
    back.seek(SeekFrom::Start(0)).unwrap();
    let mut all = Vec::new();
    back.read_to_end(&mut all).unwrap();
    assert_eq!(all.len(), 4 * 1024 * 1024);
    assert_eq!(&all[..19], b"hello qcow2 reader\n");
}

/// Build a compressible 4 MiB raw source with a few recognizable regions.
#[cfg(test)]
fn compressible_source() -> (NamedTempFile, Vec<u8>) {
    let mut data = vec![0u8; 4 * 1024 * 1024];
    // Highly compressible text spanning the first cluster.
    let text = b"The quick brown fox jumps over the lazy dog.\n";
    for (i, b) in data.iter_mut().take(90_000).enumerate() {
        *b = text[i % text.len()];
    }
    // A less-compressible region straddling a later cluster boundary.
    for (i, b) in data[2_000_000..2_050_000].iter_mut().enumerate() {
        *b = (i * 7 % 256) as u8;
    }
    let raw = NamedTempFile::new().unwrap();
    std::fs::write(raw.path(), &data).unwrap();
    (raw, data)
}

/// Read back a **zlib**-compressed qcow2 (`qemu-img convert -c`), byte-exact.
#[test]
fn read_back_zlib_compressed() {
    if !which("qemu-img") {
        eprintln!("skipping: qemu-img not installed");
        return;
    }
    let (raw, expect) = compressible_source();
    let qcow = NamedTempFile::new().unwrap();
    let out = Command::new("qemu-img")
        .args(["convert", "-f", "raw", "-O", "qcow2", "-c"])
        .arg(raw.path())
        .arg(qcow.path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "qemu-img convert -c failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let mut back = Qcow2Backend::open(qcow.path()).unwrap();
    assert_eq!(back.total_size(), expect.len() as u64);
    use std::io::Seek as _;
    use std::io::SeekFrom;
    back.seek(SeekFrom::Start(0)).unwrap();
    let mut all = Vec::new();
    back.read_to_end(&mut all).unwrap();
    assert_eq!(all, expect, "zlib-compressed read mismatch");
}

/// Read back a **zstd**-compressed qcow2 (sets the COMPRESSION_TYPE incompat
/// bit), byte-exact.
#[test]
fn read_back_zstd_compressed() {
    if !which("qemu-img") {
        eprintln!("skipping: qemu-img not installed");
        return;
    }
    let (raw, expect) = compressible_source();
    let qcow = NamedTempFile::new().unwrap();
    let out = Command::new("qemu-img")
        .args([
            "convert",
            "-f",
            "raw",
            "-O",
            "qcow2",
            "-c",
            "-o",
            "compression_type=zstd",
        ])
        .arg(raw.path())
        .arg(qcow.path())
        .output()
        .unwrap();
    if !out.status.success() {
        // Old qemu without zstd support — skip rather than fail.
        eprintln!(
            "skipping: qemu-img has no zstd compression: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        return;
    }

    let mut back = Qcow2Backend::open(qcow.path()).unwrap();
    assert_eq!(back.header().compression_type, 1, "should be zstd");
    let mut all = Vec::new();
    use std::io::Read as _;
    back.read_to_end(&mut all).unwrap();
    assert_eq!(all, expect, "zstd-compressed read mismatch");
}

/// Writing into a compressed cluster copies it out to a plain cluster
/// (COW): the edit sticks, untouched compressed clusters survive byte-exact,
/// and `qemu-img check` stays clean (refcounts intact).
#[test]
fn cow_write_into_compressed_cluster() {
    if !which("qemu-img") {
        eprintln!("skipping: qemu-img not installed");
        return;
    }
    let (raw, mut expect) = compressible_source();
    let qcow = NamedTempFile::new().unwrap();
    let out = Command::new("qemu-img")
        .args(["convert", "-f", "raw", "-O", "qcow2", "-c"])
        .arg(raw.path())
        .arg(qcow.path())
        .output()
        .unwrap();
    assert!(out.status.success(), "convert -c failed");

    // Overwrite a 100-byte window inside the first (compressed) cluster and a
    // window inside the later compressed region at 2 MiB.
    let patch = [0x5Au8; 100];
    {
        let mut back = Qcow2Backend::open(qcow.path()).unwrap();
        back.write_at(10, &patch).unwrap();
        back.write_at(2_000_100, &patch).unwrap();
        back.sync().unwrap();
    }
    expect[10..110].copy_from_slice(&patch);
    expect[2_000_100..2_000_200].copy_from_slice(&patch);

    // qemu-img check: structural + refcount validation.
    let check = Command::new("qemu-img")
        .arg("check")
        .arg(qcow.path())
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "qemu-img check failed after COW:\n{}\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );

    // Reopen and confirm the whole image matches (edits applied, rest intact).
    let mut back = Qcow2Backend::open(qcow.path()).unwrap();
    let mut all = Vec::new();
    use std::io::Read as _;
    back.read_to_end(&mut all).unwrap();
    assert_eq!(all, expect, "post-COW image mismatch");
}

/// Produce a compressed qcow2 with our serializer; qemu-img must validate
/// it (check clean) and decode it back to the original bytes.
fn write_compressed_roundtrip(ctype: u8) {
    if !which("qemu-img") {
        eprintln!("skipping: qemu-img not installed");
        return;
    }
    let (raw, expect) = compressible_source();
    let src_dev = fstool::block::FileBackend::open(raw.path()).unwrap();
    let out = NamedTempFile::new().unwrap();
    let mut src: Box<dyn BlockDevice> = Box::new(src_dev);
    let written = fstool::block::qcow2::compress::write_compressed_image(
        src.as_mut(),
        out.path(),
        65536,
        ctype,
        6,
    )
    .unwrap();
    assert!(
        written < expect.len() as u64,
        "compressed output ({written}) should be smaller than the {} source",
        expect.len()
    );

    // qemu-img check: structural + refcount validation.
    let check = Command::new("qemu-img")
        .arg("check")
        .arg(out.path())
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "qemu-img check failed:\n{}\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );

    // qemu decodes it back to the original raw bytes.
    let back = NamedTempFile::new().unwrap();
    let conv = Command::new("qemu-img")
        .args(["convert", "-O", "raw"])
        .arg(out.path())
        .arg(back.path())
        .output()
        .unwrap();
    assert!(
        conv.status.success(),
        "qemu-img convert -O raw failed:\n{}",
        String::from_utf8_lossy(&conv.stderr)
    );
    let got = std::fs::read(back.path()).unwrap();
    assert_eq!(got, expect, "qemu round-trip mismatch");

    // Our own reader also reads it byte-exact.
    let mut ours = Qcow2Backend::open(out.path()).unwrap();
    let mut all = Vec::new();
    use std::io::Read as _;
    ours.read_to_end(&mut all).unwrap();
    assert_eq!(
        all, expect,
        "our reader mismatch on our own compressed image"
    );
}

#[test]
fn write_compressed_zlib_roundtrip() {
    write_compressed_roundtrip(0);
}

#[test]
fn write_compressed_zstd_roundtrip() {
    write_compressed_roundtrip(1);
}

/// Qcow2Backend::create makes a fresh image that qemu-img validates.
#[test]
fn create_then_qemu_img_check() {
    if !which("qemu-img") {
        eprintln!("skipping: qemu-img not installed");
        return;
    }
    let tmp = NamedTempFile::new().unwrap();
    {
        let mut back = Qcow2Backend::create(tmp.path(), 64 * 1024 * 1024, 65536).unwrap();
        // Write a few patterns through the allocator.
        back.write_at(0, b"hello fresh qcow2\n").unwrap();
        back.write_at(1024 * 1024, &[0xCDu8; 128]).unwrap();
        back.write_at(63 * 1024 * 1024, &[0xEFu8; 4096]).unwrap();
        back.sync().unwrap();
    }

    // qemu-img info: parses as a real qcow2 v3 with the expected size.
    let info = Command::new("qemu-img")
        .args(["info", "--output=json"])
        .arg(tmp.path())
        .output()
        .unwrap();
    assert!(
        info.status.success(),
        "qemu-img info failed:\n{}",
        String::from_utf8_lossy(&info.stderr)
    );
    let s = String::from_utf8_lossy(&info.stdout);
    assert!(s.contains("\"virtual-size\": 67108864"), "info:\n{s}");
    assert!(s.contains("\"format\": \"qcow2\""), "info:\n{s}");

    // qemu-img check: structural validation.
    let check = Command::new("qemu-img")
        .arg("check")
        .arg(tmp.path())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&check.stdout);
    let stderr = String::from_utf8_lossy(&check.stderr);
    assert!(
        check.status.success(),
        "qemu-img check failed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    // Reopen through our reader and verify the patterns came back.
    let mut back = Qcow2Backend::open(tmp.path()).unwrap();
    let mut head = [0u8; 32];
    back.read_at(0, &mut head).unwrap();
    assert_eq!(&head[..18], b"hello fresh qcow2\n");
    let mut mid = [0u8; 128];
    back.read_at(1024 * 1024, &mut mid).unwrap();
    assert!(mid.iter().all(|&b| b == 0xCD));
    let mut tail = [0u8; 4096];
    back.read_at(63 * 1024 * 1024, &mut tail).unwrap();
    assert!(tail.iter().all(|&b| b == 0xEF));

    // Unallocated cluster reads as zeros.
    let mut zeros = [0xffu8; 1024];
    back.read_at(8 * 1024 * 1024, &mut zeros).unwrap();
    assert!(zeros.iter().all(|&b| b == 0));
}

/// `fstool create -t ext4 src -o out.qcow2` produces a valid qcow2
/// carrying an ext4 image. Verified with qemu-img check + (after
/// convert-to-raw) e2fsck.
#[cfg(feature = "cli")]
#[test]
fn ext_build_into_qcow2() {
    if !which("qemu-img") || !which("e2fsck") {
        eprintln!("skipping: qemu-img or e2fsck missing");
        return;
    }

    let srcdir = tempfile::tempdir().unwrap();
    std::fs::write(srcdir.path().join("hello"), b"in qcow2\n").unwrap();
    std::fs::create_dir(srcdir.path().join("etc")).unwrap();
    std::fs::write(srcdir.path().join("etc/conf"), b"k=v\n").unwrap();

    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("disk.qcow2");
    let bin = env!("CARGO_BIN_EXE_fstool");
    let r = Command::new(bin)
        .args(["create", "-t", "ext4"])
        .arg(srcdir.path())
        .arg("-o")
        .arg(&out)
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "create failed:\n{}",
        String::from_utf8_lossy(&r.stderr)
    );

    // qemu-img check on the qcow2.
    let chk = Command::new("qemu-img")
        .arg("check")
        .arg(&out)
        .output()
        .unwrap();
    assert!(
        chk.status.success(),
        "qemu-img check failed:\n{}",
        String::from_utf8_lossy(&chk.stdout)
    );

    // Convert to raw and e2fsck.
    let raw = dir.path().join("disk.raw");
    let cv = Command::new("qemu-img")
        .args(["convert", "-O", "raw"])
        .arg(&out)
        .arg(&raw)
        .output()
        .unwrap();
    assert!(cv.status.success(), "qemu-img convert failed");
    let fsck = Command::new("e2fsck")
        .arg("-fn")
        .arg(&raw)
        .output()
        .unwrap();
    assert!(
        fsck.status.success(),
        "e2fsck on converted ext4 failed:\n{}",
        String::from_utf8_lossy(&fsck.stdout)
    );

    // fstool's own ls/cat works on the qcow2 directly.
    let ls = Command::new(bin)
        .arg("ls")
        .arg(&out)
        .arg("/")
        .output()
        .unwrap();
    assert!(ls.status.success());
    let s = String::from_utf8_lossy(&ls.stdout);
    assert!(s.contains("hello"));
    assert!(s.contains("etc"));

    let cat = Command::new(bin)
        .arg("cat")
        .arg(&out)
        .arg("/etc/conf")
        .output()
        .unwrap();
    assert!(cat.status.success());
    assert_eq!(cat.stdout, b"k=v\n");
}

/// `fstool build spec -o disk.qcow2` produces a GPT-partitioned qcow2
/// with two filesystems. The partition target syntax (`disk.qcow2:N`)
/// walks each partition cleanly.
#[cfg(feature = "cli")]
#[test]
fn build_partitioned_qcow2() {
    if !which("qemu-img") {
        eprintln!("skipping: qemu-img not installed");
        return;
    }

    let srcdir = tempfile::tempdir().unwrap();
    std::fs::write(srcdir.path().join("hello"), b"in partition 2\n").unwrap();

    let dir = tempfile::tempdir().unwrap();
    let spec_path = dir.path().join("spec.toml");
    std::fs::write(
        &spec_path,
        format!(
            r#"
            [image]
            size = "128MiB"
            partition_table = "gpt"

            [[partitions]]
            name = "EFI"
            type = "esp"
            size = "48MiB"

            [partitions.filesystem]
            type = "fat32"
            volume_label = "EFI"

            [[partitions]]
            name = "root"
            type = "linux"
            size = "remaining"

            [partitions.filesystem]
            type = "ext4"
            source = "{}"
            block_size = 1024
            "#,
            srcdir.path().display()
        ),
    )
    .unwrap();

    let out = dir.path().join("disk.qcow2");
    let bin = env!("CARGO_BIN_EXE_fstool");
    let r = Command::new(bin)
        .arg("build")
        .arg(&spec_path)
        .arg("-o")
        .arg(&out)
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "build failed:\n{}",
        String::from_utf8_lossy(&r.stderr)
    );

    let chk = Command::new("qemu-img")
        .arg("check")
        .arg(&out)
        .output()
        .unwrap();
    assert!(
        chk.status.success(),
        "qemu-img check failed:\n{}",
        String::from_utf8_lossy(&chk.stdout)
    );

    // info on the qcow2 lists the table.
    let info = Command::new(bin).arg("info").arg(&out).output().unwrap();
    assert!(info.status.success());
    let s = String::from_utf8_lossy(&info.stdout);
    assert!(s.contains("partition table:"));
    assert!(s.contains("EFI"));
    assert!(s.contains("root"));

    // :2 walks the ext4 partition.
    let mut p2 = std::ffi::OsString::from(&out);
    p2.push(":2");
    let ls = Command::new(bin)
        .arg("ls")
        .arg(&p2)
        .arg("/")
        .output()
        .unwrap();
    assert!(ls.status.success(), "ls :2 failed");
    let s = String::from_utf8_lossy(&ls.stdout);
    assert!(s.contains("hello"));
}

/// Writing zeros to an unallocated cluster (whether via `write_at` or
/// `zero_range`) must NOT allocate the cluster on disk — the qcow2
/// allocator already treats unmapped clusters as zero, so the backing
/// file should stay small. Regression: previously the ext formatter's
/// `dev.zero_range(0, total_bytes)` upfront in `format_with` allocated
/// every cluster of the virtual image, turning an 8 GiB repacked
/// qcow2 into an 8 GiB file on disk.
#[test]
fn zero_writes_stay_sparse() {
    let tmp = NamedTempFile::new().unwrap();
    let mut back = Qcow2Backend::create(tmp.path(), 1024 * 1024 * 1024, 65536).unwrap();
    // Zero the entire 1 GiB virtual region.
    back.zero_range(0, 1024 * 1024 * 1024).unwrap();
    // A write of all-zero bytes through write_at is the same situation.
    back.write_at(512 * 1024 * 1024, &[0u8; 4096]).unwrap();
    back.sync().unwrap();
    drop(back);
    let on_disk = std::fs::metadata(tmp.path()).unwrap().len();
    // A fresh 1 GiB qcow2 with cluster_size=64 KiB only needs the
    // header + refcount + L1; well under 1 MiB. Allow a generous bound.
    assert!(
        on_disk < 8 * 1024 * 1024,
        "zero writes bloated the file: {on_disk} bytes on disk",
    );
    // The virtual contents must still read back as zero.
    let mut buf = [0xffu8; 4096];
    let mut back = Qcow2Backend::open(tmp.path()).unwrap();
    back.read_at(0, &mut buf).unwrap();
    assert!(buf.iter().all(|&b| b == 0));
    back.read_at(512 * 1024 * 1024, &mut buf).unwrap();
    assert!(buf.iter().all(|&b| b == 0));
}

/// Writing zeros to an *already allocated* cluster must overwrite the
/// existing data (not silently skip), so a later read returns zero.
#[test]
fn zero_writes_clear_allocated_clusters() {
    let tmp = NamedTempFile::new().unwrap();
    let mut back = Qcow2Backend::create(tmp.path(), 4 * 1024 * 1024, 65536).unwrap();
    // Allocate a cluster by writing a non-zero pattern.
    back.write_at(0, &[0xABu8; 4096]).unwrap();
    // Now write zeros to the same range; the read-back must be zero.
    back.write_at(0, &[0u8; 4096]).unwrap();
    let mut buf = [0xffu8; 4096];
    back.read_at(0, &mut buf).unwrap();
    assert!(buf.iter().all(|&b| b == 0), "stale data persisted");

    // Same via zero_range.
    back.write_at(1024 * 1024, &[0xCDu8; 4096]).unwrap();
    back.zero_range(1024 * 1024, 4096).unwrap();
    back.read_at(1024 * 1024, &mut buf).unwrap();
    assert!(buf.iter().all(|&b| b == 0), "zero_range left stale data");
}

/// fstool::block::open_image dispatches to Qcow2Backend on qcow2 magic.
#[test]
fn open_image_dispatches_to_qcow2() {
    if !which("qemu-img") {
        eprintln!("skipping: qemu-img not installed");
        return;
    }
    let tmp = NamedTempFile::new().unwrap();
    Command::new("qemu-img")
        .args(["create", "-q", "-f", "qcow2"])
        .arg(tmp.path())
        .arg("32M")
        .output()
        .unwrap();

    let mut dev = fstool::block::open_image(tmp.path()).unwrap();
    assert_eq!(dev.total_size(), 32 * 1024 * 1024);
    // Read returns zeros.
    let mut buf = [0xffu8; 1024];
    dev.read_at(0, &mut buf).unwrap();
    assert!(buf.iter().all(|&b| b == 0));
}

// ------------------------------------------------------- backing files

/// Run `qemu-io` over a qcow2 image, returning the process output.
fn qemu_io(path: &std::path::Path, cmds: &[&str]) -> std::process::Output {
    let mut cmd = Command::new("qemu-io");
    cmd.args(["-f", "qcow2"]);
    for c in cmds {
        cmd.arg("-c").arg(c);
    }
    cmd.arg(path).output().expect("spawning qemu-io")
}

/// Build `base.qcow2` with two known patterns in a temp dir, via qemu-img
/// and qemu-io. Returns the directory (kept alive by the caller).
fn build_base(dir: &tempfile::TempDir) -> std::path::PathBuf {
    let base = dir.path().join("base.qcow2");
    let out = Command::new("qemu-img")
        .args(["create", "-q", "-f", "qcow2"])
        .arg(&base)
        .arg("16M")
        .output()
        .unwrap();
    assert!(out.status.success());
    let w = qemu_io(
        &base,
        &["write -P 0x11 0 1M", "write -P 0x22 4194304 65536"],
    );
    assert!(
        w.status.success(),
        "qemu-io write failed: {}",
        String::from_utf8_lossy(&w.stderr)
    );
    base
}

/// An overlay made by `qemu-img create -b` must read through to its base
/// everywhere it has not allocated a cluster of its own.
#[test]
fn reads_through_a_qemu_made_backing_file() {
    if !which("qemu-img") || !which("qemu-io") {
        eprintln!("skipping: qemu-img / qemu-io not installed");
        return;
    }
    let dir = tempfile::TempDir::new().unwrap();
    build_base(&dir);
    let overlay = dir.path().join("overlay.qcow2");
    let out = Command::new("qemu-img")
        .args([
            "create",
            "-q",
            "-f",
            "qcow2",
            "-b",
            "base.qcow2",
            "-F",
            "qcow2",
        ])
        .arg(&overlay)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "qemu-img create -b failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Give the overlay one cluster of its own.
    let w = qemu_io(&overlay, &["write -P 0x33 65536 4096"]);
    assert!(w.status.success());

    let mut back = Qcow2Backend::open_read_only(&overlay).unwrap();
    assert_eq!(back.backing_file(), Some("base.qcow2"));
    assert_eq!(back.backing_format(), Some("qcow2"));
    assert_eq!(back.total_size(), 16 * 1024 * 1024);

    let mut buf = [0u8; 16];
    // From the base.
    back.read_at(0, &mut buf).unwrap();
    assert!(
        buf.iter().all(|&b| b == 0x11),
        "base pattern not read through"
    );
    back.read_at(4 * 1024 * 1024, &mut buf).unwrap();
    assert!(
        buf.iter().all(|&b| b == 0x22),
        "second base pattern missing"
    );
    // The overlay's own cluster.
    back.read_at(65536, &mut buf).unwrap();
    assert!(buf.iter().all(|&b| b == 0x33), "overlay pattern missing");
    // The rest of that cluster was copied up from the base by qemu.
    back.read_at(65536 + 4096, &mut buf).unwrap();
    assert!(
        buf.iter().all(|&b| b == 0x11),
        "COW tail lost the base bytes"
    );
    // Past everything either image wrote.
    back.read_at(8 * 1024 * 1024, &mut buf).unwrap();
    assert!(buf.iter().all(|&b| b == 0));
}

/// An overlay *we* create must satisfy qemu: `qemu-img check` has to pass,
/// `qemu-img info` has to report the backing file, and qemu's own reader
/// has to see both the base's bytes and ours.
#[test]
fn qemu_reads_an_overlay_we_created() {
    if !which("qemu-img") || !which("qemu-io") {
        eprintln!("skipping: qemu-img / qemu-io not installed");
        return;
    }
    let dir = tempfile::TempDir::new().unwrap();
    build_base(&dir);
    let overlay = dir.path().join("overlay.qcow2");

    {
        // Virtual size 0 → inherit the base's, as `qemu-img create -b` does.
        let mut back = Qcow2Backend::create_with_backing(
            &overlay,
            0,
            65536,
            Some((std::path::Path::new("base.qcow2"), Some("qcow2"))),
        )
        .unwrap();
        assert_eq!(back.total_size(), 16 * 1024 * 1024);
        // A sub-cluster write: the rest of the cluster must be copied up
        // from the base, or qemu will read our zeros over its 0x11s.
        back.write_at(4096, &[0x44u8; 4096]).unwrap();
        back.sync().unwrap();
    }

    let info = Command::new("qemu-img")
        .args(["info", "--output=json"])
        .arg(&overlay)
        .output()
        .unwrap();
    let info = String::from_utf8_lossy(&info.stdout);
    assert!(
        info.contains("base.qcow2"),
        "qemu-img info lost the backing file:\n{info}"
    );

    let check = Command::new("qemu-img")
        .arg("check")
        .arg(&overlay)
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "qemu-img check failed: {}{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );

    // qemu must see our write, the copied-up head of that cluster, and
    // the base beyond it.
    let r = qemu_io(
        &overlay,
        &[
            "read -P 0x11 0 4096",
            "read -P 0x44 4096 4096",
            "read -P 0x11 8192 4096",
            "read -P 0x22 4194304 65536",
        ],
    );
    assert!(
        r.status.success(),
        "qemu-io disagreed with our overlay: {}{}",
        String::from_utf8_lossy(&r.stdout),
        String::from_utf8_lossy(&r.stderr)
    );
}

/// `zero_range` over a backing file must actually shadow it — the ZERO
/// flag, not the "unallocated already reads zero" shortcut.
#[test]
fn zeroing_over_a_backing_file_shadows_it() {
    if !which("qemu-img") || !which("qemu-io") {
        eprintln!("skipping: qemu-img / qemu-io not installed");
        return;
    }
    let dir = tempfile::TempDir::new().unwrap();
    build_base(&dir);
    let overlay = dir.path().join("overlay.qcow2");

    {
        let mut back = Qcow2Backend::create_with_backing(
            &overlay,
            0,
            65536,
            Some((std::path::Path::new("base.qcow2"), Some("qcow2"))),
        )
        .unwrap();
        // A whole cluster (takes the ZERO-flag path) and a partial range
        // (takes the copy-up path).
        back.zero_range(0, 65536).unwrap();
        back.zero_range(65536, 4096).unwrap();
        // Writing zeros through the normal write path must shadow too.
        back.write_at(131072, &[0u8; 4096]).unwrap();
        back.sync().unwrap();

        let mut buf = [0xffu8; 16];
        back.read_at(0, &mut buf).unwrap();
        assert!(
            buf.iter().all(|&b| b == 0),
            "whole-cluster zero did not stick"
        );
        back.read_at(65536, &mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 0), "partial zero did not stick");
        back.read_at(131072, &mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 0), "zero write did not stick");
        // …and the rest of the partially-zeroed cluster still shows the base.
        back.read_at(65536 + 4096, &mut buf).unwrap();
        assert!(
            buf.iter().all(|&b| b == 0x11),
            "copy-up lost the base bytes"
        );
    }

    let r = qemu_io(
        &overlay,
        &[
            "read -P 0x00 0 65536",
            "read -P 0x00 65536 4096",
            "read -P 0x11 69632 4096",
            "read -P 0x00 131072 4096",
        ],
    );
    assert!(
        r.status.success(),
        "qemu-io disagreed about the zeroed ranges: {}{}",
        String::from_utf8_lossy(&r.stdout),
        String::from_utf8_lossy(&r.stderr)
    );
}

/// A raw backing file, declared as such, must be opened as raw.
#[test]
fn supports_a_raw_backing_file() {
    if !which("qemu-img") || !which("qemu-io") {
        eprintln!("skipping: qemu-img / qemu-io not installed");
        return;
    }
    let dir = tempfile::TempDir::new().unwrap();
    let base = dir.path().join("base.raw");
    {
        use std::io::Write as _;
        let mut f = std::fs::File::create(&base).unwrap();
        f.set_len(8 * 1024 * 1024).unwrap();
        f.write_all(&[0x55u8; 4096]).unwrap();
        f.sync_all().unwrap();
    }
    let overlay = dir.path().join("overlay.qcow2");
    {
        let mut back = Qcow2Backend::create_with_backing(
            &overlay,
            0,
            65536,
            Some((std::path::Path::new("base.raw"), Some("raw"))),
        )
        .unwrap();
        assert_eq!(back.total_size(), 8 * 1024 * 1024);
        let mut buf = [0u8; 16];
        back.read_at(0, &mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 0x55));
        back.write_at(0, &[0x66u8; 512]).unwrap();
        back.sync().unwrap();
    }

    let r = qemu_io(
        &overlay,
        &[
            "read -P 0x66 0 512",
            "read -P 0x55 512 3584",
            "read -P 0x00 4096 4096",
        ],
    );
    assert!(
        r.status.success(),
        "qemu-io disagreed about the raw-backed overlay: {}{}",
        String::from_utf8_lossy(&r.stdout),
        String::from_utf8_lossy(&r.stderr)
    );
}

/// A backing chain three images deep must resolve, and a self-referential
/// one must be refused rather than recursing forever.
#[test]
fn follows_a_chain_and_refuses_a_loop() {
    let dir = tempfile::TempDir::new().unwrap();
    let a = dir.path().join("a.qcow2");
    let b = dir.path().join("b.qcow2");
    let c = dir.path().join("c.qcow2");

    {
        let mut base = Qcow2Backend::create(&a, 4 * 1024 * 1024, 65536).unwrap();
        base.write_at(0, &[0xA1u8; 4096]).unwrap();
        base.write_at(1024 * 1024, &[0xA2u8; 4096]).unwrap();
        base.sync().unwrap();
    }
    {
        let mut mid = Qcow2Backend::create_with_backing(
            &b,
            0,
            65536,
            Some((std::path::Path::new("a.qcow2"), Some("qcow2"))),
        )
        .unwrap();
        mid.write_at(1024 * 1024, &[0xB2u8; 4096]).unwrap();
        mid.sync().unwrap();
    }
    {
        let mut top = Qcow2Backend::create_with_backing(
            &c,
            0,
            65536,
            Some((std::path::Path::new("b.qcow2"), Some("qcow2"))),
        )
        .unwrap();
        top.write_at(2 * 1024 * 1024, &[0xC3u8; 4096]).unwrap();
        top.sync().unwrap();
    }

    let mut top = Qcow2Backend::open_read_only(&c).unwrap();
    let mut buf = [0u8; 16];
    top.read_at(0, &mut buf).unwrap();
    assert!(
        buf.iter().all(|&x| x == 0xA1),
        "bottom of the chain missing"
    );
    top.read_at(1024 * 1024, &mut buf).unwrap();
    assert!(
        buf.iter().all(|&x| x == 0xB2),
        "middle should shadow the base"
    );
    top.read_at(2 * 1024 * 1024, &mut buf).unwrap();
    assert!(buf.iter().all(|&x| x == 0xC3), "top's own cluster missing");
    drop(top);

    // Point an image at itself; opening must fail rather than recurse.
    let loop_img = dir.path().join("loop.qcow2");
    Qcow2Backend::create_with_backing(
        &loop_img,
        4 * 1024 * 1024,
        65536,
        Some((std::path::Path::new("a.qcow2"), Some("qcow2"))),
    )
    .unwrap();
    // Rewrite the backing name in place to point at itself.
    {
        use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&loop_img)
            .unwrap();
        let mut head = vec![0u8; 65536];
        f.read_exact(&mut head).unwrap();
        let off = u64::from_be_bytes(head[8..16].try_into().unwrap()) as usize;
        let name = b"loop.qcow2";
        head[off..off + name.len()].copy_from_slice(name);
        head[16..20].copy_from_slice(&(name.len() as u32).to_be_bytes());
        f.seek(SeekFrom::Start(0)).unwrap();
        f.write_all(&head).unwrap();
        f.sync_all().unwrap();
    }
    let err = Qcow2Backend::open_read_only(&loop_img).unwrap_err();
    assert!(
        matches!(err, fstool::Error::InvalidImage(_)),
        "a backing loop should be refused, got: {err}"
    );
}

/// A missing backing file is a clear error naming the path we looked at,
/// not a confusing I/O failure deep in a read.
#[test]
fn missing_backing_file_is_reported_clearly() {
    let dir = tempfile::TempDir::new().unwrap();
    let overlay = dir.path().join("overlay.qcow2");
    let err = Qcow2Backend::create_with_backing(
        &overlay,
        4 * 1024 * 1024,
        65536,
        Some((std::path::Path::new("nope.qcow2"), Some("qcow2"))),
    )
    .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("nope.qcow2"), "unhelpful error: {msg}");
}

// ------------------------------------------------------------ encryption

/// Run qemu-io against an encrypted qcow2 through qemu's own crypto layer.
#[cfg(feature = "qcow2-crypto")]
fn qemu_io_encrypted(
    path: &std::path::Path,
    password: &str,
    cmds: &[&str],
) -> std::process::Output {
    let mut cmd = Command::new("qemu-io");
    cmd.arg("--object")
        .arg(format!("secret,id=sec0,data={password}"))
        .arg("--image-opts")
        .arg(format!(
            "driver=qcow2,file.filename={},encrypt.key-secret=sec0",
            path.display()
        ));
    for c in cmds {
        cmd.arg("-c").arg(c);
    }
    cmd.output().expect("spawning qemu-io")
}

/// An image `qemu-img create -o encrypt.format=luks` produced must open
/// with its passphrase and hand back the plaintext qemu wrote.
#[test]
#[cfg(feature = "qcow2-crypto")]
fn opens_a_qemu_encrypted_luks_image() {
    if !which("qemu-img") || !which("qemu-io") {
        eprintln!("skipping: qemu-img / qemu-io not installed");
        return;
    }
    let dir = tempfile::TempDir::new().unwrap();
    let img = dir.path().join("enc.qcow2");
    let out = Command::new("qemu-img")
        .arg("create")
        .arg("--object")
        .arg("secret,id=sec0,data=hunter2")
        .args([
            "-f",
            "qcow2",
            "-o",
            "encrypt.format=luks,encrypt.key-secret=sec0,encrypt.iter-time=10",
        ])
        .arg(&img)
        .arg("16M")
        .output()
        .unwrap();
    if !out.status.success() {
        eprintln!(
            "skipping: this qemu-img cannot create encrypted qcow2: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        return;
    }
    let w = qemu_io_encrypted(
        &img,
        "hunter2",
        &["write -P 0x77 0 65536", "write -P 0x88 1048576 4096"],
    );
    assert!(
        w.status.success(),
        "qemu-io write failed: {}",
        String::from_utf8_lossy(&w.stderr)
    );

    let mut back = Qcow2Backend::open_encrypted(&img, "hunter2").unwrap();
    assert_eq!(back.total_size(), 16 * 1024 * 1024);
    let mut buf = [0u8; 32];
    back.read_at(0, &mut buf).unwrap();
    assert!(buf.iter().all(|&b| b == 0x77), "first pattern wrong");
    // Mid-cluster, to exercise the sector-aligned widening.
    back.read_at(32768 + 7, &mut buf).unwrap();
    assert!(buf.iter().all(|&b| b == 0x77), "unaligned read wrong");
    back.read_at(1024 * 1024, &mut buf).unwrap();
    assert!(buf.iter().all(|&b| b == 0x88), "second pattern wrong");
    // Never-written clusters are unallocated: plaintext zeros.
    back.read_at(8 * 1024 * 1024, &mut buf).unwrap();
    assert!(buf.iter().all(|&b| b == 0));

    // A wrong passphrase must be refused, not silently yield garbage.
    let err = Qcow2Backend::open_encrypted(&img, "wrong").unwrap_err();
    assert!(matches!(err, fstool::Error::InvalidArgument(_)), "{err}");

    // …and so must opening it with no passphrase at all.
    let err = Qcow2Backend::open(&img).unwrap_err();
    assert!(matches!(err, fstool::Error::InvalidArgument(_)), "{err}");
}

/// An encrypted image *we* create must satisfy `qemu-img check` and read
/// back correctly through qemu's crypto layer — including an unaligned
/// write, which exercises the read-modify-write path on a 512-byte unit.
#[test]
#[cfg(feature = "qcow2-crypto")]
fn qemu_reads_an_encrypted_image_we_created() {
    use fstool::block::luks::{FormatOpts, Version};

    if !which("qemu-img") || !which("qemu-io") {
        eprintln!("skipping: qemu-img / qemu-io not installed");
        return;
    }
    let dir = tempfile::TempDir::new().unwrap();
    let img = dir.path().join("ours-enc.qcow2");
    let opts = FormatOpts {
        version: Version::V1,
        ..FormatOpts::fast_for_tests()
    };
    {
        let mut back =
            Qcow2Backend::create_encrypted(&img, 16 * 1024 * 1024, 65536, "s3cret", &opts).unwrap();
        back.write_at(0, &[0x99u8; 65536]).unwrap();
        back.write_at(1024 * 1024, &[0xAAu8; 4096]).unwrap();
        back.write_at(1024 * 1024 + 100, b"unaligned!").unwrap();
        back.sync().unwrap();
    }

    let check = Command::new("qemu-img")
        .arg("check")
        .arg("--object")
        .arg("secret,id=sec0,data=s3cret")
        .arg("--image-opts")
        .arg(format!(
            "driver=qcow2,file.filename={},encrypt.key-secret=sec0",
            img.display()
        ))
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "qemu-img check failed: {}{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );

    let r = qemu_io_encrypted(
        &img,
        "s3cret",
        &[
            "read -P 0x99 0 65536",
            "read -P 0xAA 1048576 100",
            "read -v 1048676 10",
            "read -P 0xAA 1048686 100",
            "read -P 0x00 8388608 4096",
        ],
    );
    let stdout = String::from_utf8_lossy(&r.stdout);
    assert!(
        r.status.success(),
        "qemu-io disagreed with our encrypted image: {stdout}{}",
        String::from_utf8_lossy(&r.stderr)
    );
    // Match the hex column: qemu-io's ASCII column renders some
    // printable bytes as `.`, so it is not a reliable needle.
    assert!(
        stdout.contains("75 6e 61 6c 69 67 6e 65 64 21"),
        "the unaligned write did not survive:\n{stdout}"
    );
}

/// The legacy `crypt_method = 1` scheme. qemu has refused to *create*
/// these since 2.9, so the image is built here — a plain image with the
/// method byte flipped, then written through the AES engine — and qemu
/// only has to read it.
#[test]
#[cfg(feature = "qcow2-crypto")]
fn qemu_reads_a_legacy_aes_image() {
    if !which("qemu-io") {
        eprintln!("skipping: qemu-io not installed");
        return;
    }
    let dir = tempfile::TempDir::new().unwrap();
    let img = dir.path().join("aes.qcow2");
    Qcow2Backend::create(&img, 16 * 1024 * 1024, 65536).unwrap();
    {
        // crypt_method lives at byte 32 of the header.
        use std::io::{Seek as _, SeekFrom, Write as _};
        let mut f = std::fs::OpenOptions::new().write(true).open(&img).unwrap();
        f.seek(SeekFrom::Start(32)).unwrap();
        f.write_all(&1u32.to_be_bytes()).unwrap();
        f.sync_all().unwrap();
    }

    {
        let mut back = Qcow2Backend::open_encrypted(&img, "hunter2").unwrap();
        assert_eq!(back.header().crypt_method, 1);
        back.write_at(0, &[0x5eu8; 65536]).unwrap();
        back.write_at(1024 * 1024, b"legacy aes payload").unwrap();
        back.sync().unwrap();
        // Round-trips through our own reader too.
        let mut buf = [0u8; 18];
        back.read_at(1024 * 1024, &mut buf).unwrap();
        assert_eq!(&buf, b"legacy aes payload");
    }

    let r = qemu_io_encrypted(
        &img,
        "hunter2",
        &["read -P 0x5e 0 65536", "read -v 1048576 16"],
    );
    let stdout = String::from_utf8_lossy(&r.stdout);
    assert!(
        r.status.success(),
        "qemu-io could not read our legacy-AES image: {stdout}{}",
        String::from_utf8_lossy(&r.stderr)
    );
    assert!(
        stdout.contains("6c 65 67 61 63 79 20 61 65 73 20 70 61 79 6c 6f"),
        "qemu did not see our bytes:\n{stdout}"
    );
}

/// A filesystem inside an encrypted image, reopened from scratch.
#[test]
#[cfg(feature = "qcow2-crypto")]
fn hosts_a_filesystem_inside_an_encrypted_image() {
    use fstool::block::luks::{FormatOpts as LuksOpts, Version};
    use fstool::fs::ext::{Ext, FormatOpts as ExtOpts};
    use fstool::fs::{FileMeta, FileSource, Filesystem};

    let dir = tempfile::TempDir::new().unwrap();
    let img = dir.path().join("fs-enc.qcow2");
    let luks = LuksOpts {
        version: Version::V1,
        ..LuksOpts::fast_for_tests()
    };
    let body = b"secret payload\n";
    {
        let mut dev =
            Qcow2Backend::create_encrypted(&img, 16 * 1024 * 1024, 65536, "pw", &luks).unwrap();
        let ext_opts = ExtOpts {
            blocks_count: (dev.total_size() / 1024) as u32,
            ..ExtOpts::default()
        };
        let mut fs = Ext::format_with(&mut dev, &ext_opts).unwrap();
        fs.create_file(
            &mut dev,
            std::path::Path::new("/secret.txt"),
            FileSource::Reader {
                reader: Box::new(std::io::Cursor::new(body.to_vec())),
                len: body.len() as u64,
            },
            FileMeta::default(),
        )
        .unwrap();
        fs.flush(&mut dev).unwrap();
        dev.sync().unwrap();
    }

    let mut dev = Qcow2Backend::open_encrypted(&img, "pw").unwrap();
    let mut fs = Ext::open(&mut dev).unwrap();
    let mut got = Vec::new();
    {
        use std::io::Read as _;
        let mut r = fs
            .read_file(&mut dev, std::path::Path::new("/secret.txt"))
            .unwrap();
        r.read_to_end(&mut got).unwrap();
    }
    assert_eq!(got, body);
}

/// Zeroing an *allocated* cluster of an image with no backing file must
/// really overwrite it on disk, not just flag it — a caller reaching for
/// `zero_range` on a plain image expects the old bytes gone.
#[test]
fn zero_range_overwrites_allocated_clusters_on_disk() {
    let tmp = NamedTempFile::new().unwrap();
    {
        let mut back = Qcow2Backend::create(tmp.path(), 4 * 1024 * 1024, 65536).unwrap();
        back.write_at(0, b"SENSITIVE-PAYLOAD").unwrap();
        back.write_at(65536, b"SECOND-CLUSTER").unwrap();
        back.zero_range(0, 2 * 65536).unwrap();
        back.sync().unwrap();
    }
    let raw = std::fs::read(tmp.path()).unwrap();
    assert!(
        !raw.windows(17).any(|w| w == b"SENSITIVE-PAYLOAD"),
        "zeroed bytes are still on disk"
    );
    assert!(
        !raw.windows(14).any(|w| w == b"SECOND-CLUSTER"),
        "zeroed bytes are still on disk"
    );
}

/// …and zeroing a range that was never allocated must stay sparse: no L2
/// table, no data cluster, no growth.
#[test]
fn zero_range_over_unallocated_clusters_allocates_nothing() {
    let tmp = NamedTempFile::new().unwrap();
    let before;
    {
        let mut back = Qcow2Backend::create(tmp.path(), 1024 * 1024 * 1024, 65536).unwrap();
        back.sync().unwrap();
        before = std::fs::metadata(tmp.path()).unwrap().len();
        back.zero_range(0, 1024 * 1024 * 1024).unwrap();
        back.sync().unwrap();
    }
    let after = std::fs::metadata(tmp.path()).unwrap().len();
    assert_eq!(
        after, before,
        "zeroing an all-unallocated 1 GiB image grew the file from {before} to {after}"
    );
}
