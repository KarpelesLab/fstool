//! LUKS backend validation against the reference tools.
//!
//! Two independent implementations check us here:
//!
//! - **`cryptsetup`** — the reference. It formats containers we must open,
//!   reads back headers we wrote, and `luksDump --dump-master-key` lets us
//!   compare the master key we recovered against the one it recovers, byte
//!   for byte. All of this works on a plain file without root; only
//!   `luksOpen` needs device-mapper, and we never call it.
//! - **`qemu-io`** — QEMU's own LUKS driver, which reads and writes the
//!   *payload* without root. That closes the loop the header dumps cannot:
//!   plaintext written by one implementation must read back through the
//!   other. (QEMU's LUKS driver is LUKS1-only in the versions shipping
//!   today, so the payload round-trips are LUKS1.)
//!
//! Every test skips silently when its tool isn't on PATH.

#![cfg(feature = "luks")]

use std::path::Path;
use std::process::Command;

use fstool::block::luks::{FormatOpts, LuksBackend, Version, format};
use fstool::block::{BlockDevice, FileBackend};
use tempfile::TempDir;

fn which(tool: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {tool}"))
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

const PASSPHRASE: &str = "correct horse battery staple";

/// `cryptsetup luksFormat` with a deliberately cheap KDF, so the tests
/// stay fast. Returns false when cryptsetup refused (e.g. a cipher the
/// host kernel's crypto API doesn't offer), so the caller can skip.
fn cryptsetup_format(path: &Path, extra: &[&str]) -> bool {
    let mut cmd = Command::new("cryptsetup");
    cmd.arg("luksFormat")
        .arg("-q")
        .arg("--pbkdf")
        .arg("pbkdf2")
        .arg("--pbkdf-force-iterations")
        .arg("1000")
        .args(extra)
        .arg(path)
        .arg("-");
    let out = cmd
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write as _;
            child
                .stdin
                .as_mut()
                .expect("stdin piped")
                .write_all(PASSPHRASE.as_bytes())?;
            child.wait_with_output()
        })
        .expect("spawning cryptsetup");
    if !out.status.success() {
        eprintln!(
            "cryptsetup luksFormat {extra:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    out.status.success()
}

/// The master key `cryptsetup luksDump --dump-master-key` recovers, as raw
/// bytes. Returns `None` when cryptsetup couldn't open the header.
fn cryptsetup_master_key(path: &Path) -> Option<Vec<u8>> {
    let out = Command::new("cryptsetup")
        .args(["luksDump", "--dump-master-key", "-q"])
        .arg(path)
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write as _;
            child
                .stdin
                .as_mut()
                .expect("stdin piped")
                .write_all(PASSPHRASE.as_bytes())?;
            child.wait_with_output()
        })
        .ok()?;
    if !out.status.success() {
        eprintln!(
            "cryptsetup luksDump failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        return None;
    }
    // The dump prints `MK dump:` followed by indented hex lines; hex runs
    // to the end of the output.
    let text = String::from_utf8_lossy(&out.stdout);
    let after = text.split("MK dump:").nth(1)?;
    let mut key = Vec::new();
    for tok in after.split_whitespace() {
        match u8::from_str_radix(tok, 16) {
            Ok(b) if tok.len() == 2 => key.push(b),
            _ => break,
        }
    }
    (!key.is_empty()).then_some(key)
}

fn cryptsetup_dump(path: &Path) -> String {
    let out = Command::new("cryptsetup")
        .arg("luksDump")
        .arg(path)
        .output()
        .expect("spawning cryptsetup");
    assert!(
        out.status.success(),
        "cryptsetup luksDump rejected our header: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Run `qemu-io` against a LUKS image through QEMU's own crypto driver.
fn qemu_io(path: &Path, cmds: &[&str]) -> std::process::Output {
    let mut cmd = Command::new("qemu-io");
    cmd.arg("--object")
        .arg(format!("secret,id=sec0,data={PASSPHRASE}"))
        .arg("--image-opts")
        .arg(format!(
            "driver=luks,file.filename={},key-secret=sec0",
            path.display()
        ));
    for c in cmds {
        cmd.arg("-c").arg(c);
    }
    cmd.output().expect("spawning qemu-io")
}

/// Create a sparse file of `size` bytes for a tool to format.
fn blank(dir: &TempDir, name: &str, size: u64) -> std::path::PathBuf {
    let path = dir.path().join(name);
    let f = std::fs::File::create(&path).unwrap();
    f.set_len(size).unwrap();
    path
}

// ---------------------------------------------------- cryptsetup → fstool

/// The master key fstool recovers from a cryptsetup-made container must be
/// the one cryptsetup itself recovers.
fn open_cryptsetup_container(name: &str, extra: &[&str]) {
    if !which("cryptsetup") {
        eprintln!("skipping: cryptsetup not installed");
        return;
    }
    let dir = TempDir::new().unwrap();
    let img = blank(&dir, name, 64 * 1024 * 1024);
    if !cryptsetup_format(&img, extra) {
        eprintln!("skipping {name}: this host's cryptsetup refused {extra:?}");
        return;
    }
    let Some(expect) = cryptsetup_master_key(&img) else {
        eprintln!("skipping {name}: cryptsetup would not dump the master key");
        return;
    };

    let vol = LuksBackend::open(FileBackend::open(&img).unwrap(), PASSPHRASE).unwrap();
    assert_eq!(
        vol.master_key().as_bytes(),
        &expect[..],
        "{name}: master key mismatch"
    );
    assert!(vol.total_size() > 0);
    assert!(!vol.header().uuid().is_empty());
}

#[test]
fn opens_cryptsetup_luks1() {
    open_cryptsetup_container("cs-luks1.img", &["--type", "luks1"]);
}

#[test]
fn opens_cryptsetup_luks2() {
    open_cryptsetup_container("cs-luks2.img", &["--type", "luks2"]);
}

/// LUKS1's other historical default: AES-CBC with an ESSIV IV generator.
#[test]
fn opens_cryptsetup_luks1_cbc_essiv() {
    open_cryptsetup_container(
        "cs-luks1-cbc.img",
        &["--type", "luks1", "-c", "aes-cbc-essiv:sha256", "-s", "256"],
    );
}

/// A LUKS2 volume with 4096-byte payload sectors — the sector size has to
/// reach the IV generator, or every sector past the first decrypts wrong.
#[test]
fn opens_cryptsetup_luks2_4k_sectors() {
    open_cryptsetup_container(
        "cs-luks2-4k.img",
        &["--type", "luks2", "--sector-size", "4096"],
    );
}

/// An Argon2id keyslot, with the cost dialled to the floor so the test is
/// quick. This is the KDF cryptsetup actually defaults to.
#[test]
fn opens_cryptsetup_luks2_argon2id() {
    if !which("cryptsetup") {
        eprintln!("skipping: cryptsetup not installed");
        return;
    }
    let dir = TempDir::new().unwrap();
    let img = blank(&dir, "cs-argon2id.img", 64 * 1024 * 1024);
    // Not via cryptsetup_format: that helper forces pbkdf2.
    let ok = Command::new("cryptsetup")
        .args([
            "luksFormat",
            "-q",
            "--type",
            "luks2",
            "--pbkdf",
            "argon2id",
            "--pbkdf-force-iterations",
            "4",
            "--pbkdf-memory",
            "32",
            "--pbkdf-parallel",
            "1",
        ])
        .arg(&img)
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write as _;
            child
                .stdin
                .as_mut()
                .unwrap()
                .write_all(PASSPHRASE.as_bytes())?;
            child.wait_with_output()
        })
        .expect("spawning cryptsetup");
    if !ok.status.success() {
        eprintln!(
            "skipping: cryptsetup refused argon2id: {}",
            String::from_utf8_lossy(&ok.stderr)
        );
        return;
    }
    let Some(expect) = cryptsetup_master_key(&img) else {
        eprintln!("skipping: cryptsetup would not dump the master key");
        return;
    };
    let vol = LuksBackend::open(FileBackend::open(&img).unwrap(), PASSPHRASE).unwrap();
    assert_eq!(vol.master_key().as_bytes(), &expect[..]);
}

/// A wrong passphrase must be refused, not silently accepted with a
/// garbage key.
#[test]
fn refuses_a_wrong_passphrase_on_a_real_container() {
    if !which("cryptsetup") {
        eprintln!("skipping: cryptsetup not installed");
        return;
    }
    let dir = TempDir::new().unwrap();
    let img = blank(&dir, "cs-wrongpw.img", 64 * 1024 * 1024);
    if !cryptsetup_format(&img, &["--type", "luks2"]) {
        return;
    }
    let err =
        LuksBackend::open(FileBackend::open(&img).unwrap(), "not the passphrase").unwrap_err();
    assert!(matches!(err, fstool::Error::InvalidArgument(_)), "{err}");
}

// ---------------------------------------------------- fstool → cryptsetup

/// A header fstool wrote must satisfy cryptsetup: it has to parse the
/// metadata *and* recover the same master key from our keyslot.
fn cryptsetup_reads_our_header(version: Version, name: &str) {
    if !which("cryptsetup") {
        eprintln!("skipping: cryptsetup not installed");
        return;
    }
    let dir = TempDir::new().unwrap();
    let path = dir.path().join(name);
    let dev = FileBackend::create(&path, 64 * 1024 * 1024).unwrap();
    let opts = FormatOpts {
        version,
        ..FormatOpts::fast_for_tests()
    };
    let vol = format(dev, PASSPHRASE, &opts).unwrap();
    let ours = vol.master_key().as_bytes().to_vec();
    let uuid = vol.header().uuid().to_owned();
    drop(vol);

    let dump = cryptsetup_dump(&path);
    assert!(
        dump.contains(&uuid),
        "cryptsetup did not report our UUID:\n{dump}"
    );
    assert!(
        dump.contains("aes-xts-plain64") || dump.contains("xts-plain64"),
        "cryptsetup did not report our cipher:\n{dump}"
    );

    let theirs = cryptsetup_master_key(&path)
        .unwrap_or_else(|| panic!("cryptsetup could not unlock our {version:?} keyslot"));
    assert_eq!(theirs, ours, "{name}: cryptsetup recovered a different key");
}

#[test]
fn cryptsetup_reads_our_luks1_header() {
    cryptsetup_reads_our_header(Version::V1, "ours-luks1.img");
}

#[test]
fn cryptsetup_reads_our_luks2_header() {
    cryptsetup_reads_our_header(Version::V2, "ours-luks2.img");
}

// ------------------------------------------------- payload interop (qemu)

/// Plaintext written by QEMU's LUKS driver must read back through fstool.
#[test]
fn reads_payload_written_by_qemu_io() {
    if !which("qemu-img") || !which("qemu-io") {
        eprintln!("skipping: qemu-img / qemu-io not installed");
        return;
    }
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("qemu.luks");
    let out = Command::new("qemu-img")
        .arg("create")
        .arg("--object")
        .arg(format!("secret,id=sec0,data={PASSPHRASE}"))
        .args(["-f", "luks", "-o", "key-secret=sec0,iter-time=10"])
        .arg(&path)
        .arg("8M")
        .output()
        .expect("spawning qemu-img");
    if !out.status.success() {
        eprintln!(
            "skipping: qemu-img cannot create LUKS here: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        return;
    }

    let w = qemu_io(
        &path,
        &["write -P 0xab 0 8192", "write -P 0x5c 1048576 4096"],
    );
    assert!(
        w.status.success(),
        "qemu-io write failed: {}",
        String::from_utf8_lossy(&w.stderr)
    );

    let mut vol = LuksBackend::open(FileBackend::open(&path).unwrap(), PASSPHRASE).unwrap();
    let mut buf = vec![0u8; 8192];
    vol.read_at(0, &mut buf).unwrap();
    assert!(buf.iter().all(|&b| b == 0xab), "head pattern mismatch");
    let mut buf = vec![0u8; 4096];
    vol.read_at(1024 * 1024, &mut buf).unwrap();
    assert!(buf.iter().all(|&b| b == 0x5c), "1 MiB pattern mismatch");
}

/// …and the other way: a container fstool formatted and wrote into must
/// read back through QEMU's driver, byte for byte.
#[test]
fn qemu_io_reads_payload_we_wrote() {
    if !which("qemu-io") {
        eprintln!("skipping: qemu-io not installed");
        return;
    }
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("ours-payload.luks");
    let dev = FileBackend::create(&path, 32 * 1024 * 1024).unwrap();
    let opts = FormatOpts {
        // QEMU's LUKS driver reads LUKS1 only.
        version: Version::V1,
        ..FormatOpts::fast_for_tests()
    };
    let mut vol = format(dev, PASSPHRASE, &opts).unwrap();
    vol.write_at(0, &[0x31u8; 8192]).unwrap();
    vol.write_at(2 * 1024 * 1024, b"fstool wrote this").unwrap();
    vol.sync().unwrap();
    drop(vol);

    // 16 bytes exactly: `read -v` dumps 16 per line, so the marker lands
    // in a single hex row and its ASCII column is not split.
    let r = qemu_io(&path, &["read -P 0x31 0 8192", "read -v 2097152 16"]);
    let stdout = String::from_utf8_lossy(&r.stdout);
    assert!(
        r.status.success(),
        "qemu-io read failed: {}\n{stdout}",
        String::from_utf8_lossy(&r.stderr)
    );
    // The ASCII column renders our marker with `.` for the spaces.
    assert!(
        stdout.contains("fstool.wrote.thi"),
        "qemu-io did not see our bytes:\n{stdout}"
    );
}

// ------------------------------------------------------ filesystem on top

/// The point of all this: put a real filesystem inside the encrypted
/// volume, close the whole stack, and read it back through the LUKS
/// layer from the container file.
#[test]
fn hosts_an_ext2_filesystem() {
    use fstool::fs::ext::{Ext, FormatOpts as ExtOpts};
    use fstool::fs::{FileMeta, FileSource, Filesystem};

    let dir = TempDir::new().unwrap();
    let path = dir.path().join("fs.luks");
    let dev = FileBackend::create(&path, 32 * 1024 * 1024).unwrap();
    let mut vol = format(dev, PASSPHRASE, &FormatOpts::fast_for_tests()).unwrap();

    // Size the filesystem to whatever the payload turned out to be.
    let ext_opts = ExtOpts {
        blocks_count: (vol.total_size() / 1024) as u32,
        ..ExtOpts::default()
    };
    let mut fs = Ext::format_with(&mut vol, &ext_opts).unwrap();
    let body = b"encrypted at rest\n";
    fs.create_file(
        &mut vol,
        Path::new("/hello.txt"),
        FileSource::Reader {
            reader: Box::new(std::io::Cursor::new(body.to_vec())),
            len: body.len() as u64,
        },
        FileMeta::default(),
    )
    .unwrap();
    fs.flush(&mut vol).unwrap();
    vol.sync().unwrap();
    drop(fs);
    drop(vol);

    // Reopen the whole stack from the container file.
    let mut vol = LuksBackend::open(FileBackend::open(&path).unwrap(), PASSPHRASE).unwrap();
    let mut fs = Ext::open(&mut vol).unwrap();
    let mut got = Vec::new();
    {
        use std::io::Read as _;
        let mut r = fs.read_file(&mut vol, Path::new("/hello.txt")).unwrap();
        r.read_to_end(&mut got).unwrap();
    }
    assert_eq!(got, body);
}
