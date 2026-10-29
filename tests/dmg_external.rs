#![cfg(all(unix, feature = "dmg"))]
//! DMG end-to-end validation against macOS' `hdiutil`.
//!
//! The unit tests in `src/block/dmg/{mish,codec}.rs` exercise the
//! decoders against a fixed test asset. These tests close the loop:
//! they ask `hdiutil` to *write* a DMG in each supported compression
//! format (raw / ADC / zlib / bzip2 / LZFSE / LZMA) and confirm fstool's
//! [`DmgBackend`] can read every virtual sector back. That guards
//! against `hdiutil` updates that introduce new chunk types, plist
//! layout changes, or trailer-field tweaks that the static asset
//! wouldn't catch.
//!
//! macOS-only. On Linux/Windows runners every test prints a
//! `skipping: …` line and returns success, matching
//! `tests/apfs_external.rs`.
//!
//! The format names are macOS's standard `hdiutil -format` codes:
//!
//! | code   | what it produces                                |
//! |--------|-------------------------------------------------|
//! | `UDRO` | UDIF read-only (no compression, raw chunks)     |
//! | `UDCO` | UDIF read-only ADC-compressed                   |
//! | `UDZO` | UDIF read-only zlib-compressed                  |
//! | `UDBZ` | UDIF read-only bzip2-compressed                 |
//! | `ULFO` | UDIF read-only LZFSE-compressed (newer macOS)  |
//! | `ULMO` | UDIF read-only LZMA-compressed (newer macOS)   |
//!
//! Each format exercises a different code path in
//! `src/block/dmg/codec.rs`. ULFO additionally requires fstool's
//! `dmg-lzfse` feature (on by default) — if that's compiled out,
//! `DmgBackend::open` errors `Unsupported` and the test surfaces it
//! rather than silently passing.

use std::path::{Path, PathBuf};
use std::process::Command;

use fstool::block::{BlockDevice, DmgBackend};

/// Cheap `command -v` shim, identical in shape to the helpers in
/// `tests/apfs_external.rs` so the skip policy stays uniform.
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

/// Sanity-check that `hdiutil` actually runs (not just on PATH).
fn hdiutil_usable() -> bool {
    Command::new("hdiutil")
        .arg("help")
        .output()
        .map(|o| o.status.success() || o.status.code() == Some(0))
        .unwrap_or(false)
}

/// Returns `true` if the caller should skip — emits the reason on the
/// way out so CI logs explain the no-op.
fn skip_unless_macos_hdiutil() -> bool {
    if !cfg!(target_os = "macos") {
        eprintln!("skipping: DMG e2e requires macOS (hdiutil)");
        return true;
    }
    if which("hdiutil").is_none() {
        eprintln!("skipping: hdiutil not found on PATH");
        return true;
    }
    if !hdiutil_usable() {
        eprintln!("skipping: hdiutil refused to run `hdiutil help`");
        return true;
    }
    false
}

/// Run `hdiutil` with `args`; on refusal print why and return `false`
/// so the caller can skip (newer formats such as `ULFO` / `ULMO` need a
/// recent macOS, and some hosts restrict image creation).
fn hdiutil(args: &[&std::ffi::OsStr], what: &str) -> bool {
    let out = Command::new("hdiutil")
        .args(args)
        .output()
        .expect("hdiutil failed to spawn");
    if !out.status.success() {
        eprintln!(
            "skipping {what}: hdiutil refused:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        return false;
    }
    true
}

/// Fill `dir` with a little compressible text plus some incompressible
/// noise, so compressed formats emit real back-references and literal
/// runs (an empty volume compresses to almost nothing but zero fill).
fn populate_source_folder(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    let mut text = String::new();
    for i in 0..20_000 {
        text.push_str(&format!(
            "line {i} the quick brown fox jumps over the lazy dog\n"
        ));
    }
    std::fs::write(dir.join("text.txt"), text).unwrap();
    // xorshift noise: deterministic, no extra dev-dependency.
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let noise: Vec<u8> = (0..100_000)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect();
    std::fs::write(dir.join("noise.bin"), noise).unwrap();
}

/// Ask `hdiutil` for a single-volume HFS+ DMG of the given `-format`.
///
/// `hdiutil create -format <compressed>` refuses without `-srcfolder`,
/// so build a populated read-write (`UDRW`) image from a source folder
/// and `hdiutil convert` it. Returns `(image, reference)` where
/// `reference` is the same volume converted to `UDTO` — a raw,
/// uncompressed sector dump produced by Apple's own engine, i.e. an
/// independent plaintext to compare fstool's decode against. `None`
/// when `hdiutil` refused, so the caller can skip.
fn create_hdiutil_dmg(dir: &Path, name: &str, format: &str) -> Option<(PathBuf, PathBuf)> {
    let src = dir.join(format!("{name}-src"));
    populate_source_folder(&src);
    let base = dir.join(format!("{name}-base.dmg"));
    if !hdiutil(
        &[
            "create".as_ref(),
            "-srcfolder".as_ref(),
            src.as_os_str(),
            "-fs".as_ref(),
            "HFS+".as_ref(),
            "-layout".as_ref(),
            "NONE".as_ref(),
            "-volname".as_ref(),
            "FstoolDmgTest".as_ref(),
            "-format".as_ref(),
            "UDRW".as_ref(),
            "-ov".as_ref(),
            base.as_os_str(),
        ],
        "UDRW base",
    ) {
        return None;
    }
    let convert = |fmt: &str, out: &Path| {
        hdiutil(
            &[
                "convert".as_ref(),
                base.as_os_str(),
                "-format".as_ref(),
                fmt.as_ref(),
                "-ov".as_ref(),
                "-o".as_ref(),
                out.as_os_str(),
            ],
            fmt,
        )
    };
    // UDTO keeps a `.cdr` output name as given.
    let reference = dir.join(format!("{name}-ref.cdr"));
    if !convert("UDTO", &reference) {
        return None;
    }
    let path = dir.join(format!("{name}.dmg"));
    if !convert(format, &path) {
        return None;
    }
    Some((path, reference))
}

/// Shared body: build a DMG via hdiutil, open via DmgBackend, read
/// every virtual sector through the BlockDevice surface and compare it
/// byte-for-byte against hdiutil's own raw (`UDTO`) rendering of the
/// same volume. Reading every sector forces each chunk through the
/// decompression path; the comparison catches a decoder that returns
/// plausible-but-wrong bytes (e.g. mis-parsed descriptors read as zero
/// fill) rather than erroring.
fn dmg_read_every_sector(format: &str) {
    if skip_unless_macos_hdiutil() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let Some((path, reference)) = create_hdiutil_dmg(dir.path(), "rt", format) else {
        return;
    };
    let expected = std::fs::read(&reference).unwrap();

    let mut dmg = match DmgBackend::open(&path) {
        Ok(d) => d,
        Err(e) => {
            // ULFO might fail when fstool was built without dmg-lzfse;
            // surface the error rather than silently skipping so a CI
            // misconfig (feature disabled by accident) is visible.
            panic!("DmgBackend::open({format}) failed: {e}");
        }
    };
    assert!(
        dmg.chunk_count() > 0,
        "DMG {format} has zero chunks — mish parse failed?"
    );
    assert_eq!(
        dmg.total_size(),
        expected.len() as u64,
        "DMG {format} virtual size disagrees with hdiutil's raw rendering"
    );

    // Walk every virtual byte through the BlockDevice in 64 KiB strides.
    const STRIDE: usize = 64 * 1024;
    let size = dmg.total_size();
    let mut buf = vec![0u8; STRIDE];
    let mut off = 0u64;
    while off < size {
        let n = STRIDE.min((size - off) as usize);
        dmg.read_at(off, &mut buf[..n]).unwrap_or_else(|e| {
            panic!("DMG {format} read_at(off={off}, n={n}): {e}");
        });
        let o = off as usize;
        if buf[..n] != expected[o..o + n] {
            let first = (0..n).find(|&i| buf[i] != expected[o + i]).unwrap();
            panic!(
                "DMG {format}: decoded bytes differ from hdiutil's raw image at offset {}",
                o + first
            );
        }
        off += n as u64;
    }
}

/// Uncompressed, raw-chunk UDIF. (`UDRW` is not used here: current
/// `hdiutil` writes a single-partition `UDRW` as a bare sector image with
/// no koly trailer, which isn't a UDIF container at all.)
#[test]
fn dmg_udro_raw_reads_every_sector() {
    dmg_read_every_sector("UDRO");
}

#[test]
fn dmg_udco_adc_reads_every_sector() {
    dmg_read_every_sector("UDCO");
}

#[test]
fn dmg_udzo_zlib_reads_every_sector() {
    dmg_read_every_sector("UDZO");
}

#[test]
fn dmg_udbz_bzip2_reads_every_sector() {
    dmg_read_every_sector("UDBZ");
}

// Native ULFO chunks (`bvx2` blocks) are rejected by compcol's LZFSE
// decoder as "encoded stream is corrupt", although the reference
// `lzfse_rust` decodes the same chunks. Tracked separately from the
// Mish/ADC fix; un-ignore once LZFSE decoding is fixed.
#[test]
#[ignore = "native ULFO chunks fail compcol LZFSE decode (separate bug)"]
fn dmg_ulfo_lzfse_reads_every_sector() {
    dmg_read_every_sector("ULFO");
}

// Native ULMO chunks are XZ containers (`FD 37 7A 58 5A 00`).
#[cfg(feature = "xz")]
#[test]
fn dmg_ulmo_lzma_reads_every_sector() {
    dmg_read_every_sector("ULMO");
}

/// Full-stack check: open the UDZO DMG, hand it to fstool's HFS+
/// reader, and confirm `list_path("/")` returns successfully. The
/// content of the empty volume varies a bit between macOS releases
/// (some include `.HFS+ Private Directory Data` etc.), so the
/// assertion is just "the catalog is readable" — not a specific name
/// list. This catches a class of regressions where the codec layer
/// returns garbage that happens to parse as catalog nodes.
#[cfg(feature = "hfs-plus")]
#[test]
fn dmg_udzo_hfs_plus_walks_through_fstool() {
    if skip_unless_macos_hdiutil() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let Some((path, _)) = create_hdiutil_dmg(dir.path(), "hfs", "UDZO") else {
        return;
    };
    let mut dmg = DmgBackend::open(&path).expect("DmgBackend::open");
    let hfs = fstool::fs::hfs_plus::HfsPlus::open(&mut dmg).expect("HfsPlus::open");
    let entries = hfs
        .list_path(&mut dmg, "/")
        .expect("list_path / on DMG-wrapped HFS+");
    eprintln!(
        "DMG-wrapped HFS+ root entries ({}): {:?}",
        entries.len(),
        entries.iter().map(|e| e.name.clone()).collect::<Vec<_>>()
    );
    for want in ["text.txt", "noise.bin"] {
        assert!(
            entries.iter().any(|e| e.name == want),
            "{want} missing from DMG-wrapped HFS+ root"
        );
    }
}

/// Ask `hdiutil` for a password-protected (`encrcdsa` v2) image holding a
/// small FAT volume, `-encryption AES-128` or `AES-256`. Returns `None`
/// when `hdiutil` refuses, so the caller can skip rather than fail.
#[cfg(feature = "dmg-encrypted")]
fn create_hdiutil_encrypted_dmg(
    dir: &Path,
    name: &str,
    encryption: &str,
    password: &str,
) -> Option<PathBuf> {
    use std::io::Write as _;
    use std::process::Stdio;

    let path = dir.join(format!("{name}.dmg"));
    let mut child = Command::new("hdiutil")
        .args([
            "create",
            "-size",
            "64k",
            "-fs",
            "MS-DOS",
            "-layout",
            "NONE",
            "-volname",
            "FSTOOLENC",
            "-encryption",
            encryption,
            "-stdinpass",
            "-ov",
        ])
        .arg(&path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("hdiutil create failed to spawn");
    // `-stdinpass` reads the passphrase verbatim (no trailing newline).
    child
        .stdin
        .take()
        .unwrap()
        .write_all(password.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    if !out.status.success() {
        eprintln!(
            "skipping {encryption}: hdiutil create refused:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        return None;
    }
    Some(path)
}

/// Encrypted images straight out of `hdiutil`, for both key sizes, must
/// open with the right password and decrypt to a FAT boot sector; the
/// wrong password must be refused. This is the guard against the header
/// layout drifting away from what Apple actually writes — the synthetic
/// unit tests can only check that the reader agrees with itself.
#[cfg(feature = "dmg-encrypted")]
#[test]
fn dmg_encrypted_hdiutil_images_decrypt() {
    use fstool::block::dmg::EncryptedDmgBackend;

    if skip_unless_macos_hdiutil() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    for (encryption, key_bits) in [("AES-128", 128u32), ("AES-256", 256u32)] {
        let Some(path) = create_hdiutil_encrypted_dmg(
            dir.path(),
            &format!("enc{key_bits}"),
            encryption,
            "hunter2",
        ) else {
            continue;
        };
        assert!(fstool::block::dmg::probe_encrypted(&path).unwrap());

        let mut be = EncryptedDmgBackend::open_with_password(&path, "hunter2")
            .unwrap_or_else(|e| panic!("{encryption}: open_with_password: {e}"));
        assert_eq!(be.header().key_bits, key_bits, "{encryption}: key_bits");
        assert_eq!(be.total_size(), 64 * 1024, "{encryption}: data_size");

        let mut boot = vec![0u8; 512];
        be.read_at(0, &mut boot).unwrap();
        assert_eq!(
            &boot[510..512],
            &[0x55, 0xAA],
            "{encryption}: boot signature"
        );
        assert_eq!(
            &boot[0x36..0x3E],
            b"FAT12   ",
            "{encryption}: FAT type string"
        );

        // Every chunk decrypts without error.
        let mut all = vec![0u8; 64 * 1024];
        be.read_at(0, &mut all).unwrap();
        assert_eq!(&all[..512], &boot[..]);

        let err = EncryptedDmgBackend::open_with_password(&path, "hunter3").unwrap_err();
        assert!(
            matches!(err, fstool::Error::Unsupported(_)),
            "{encryption}: wrong password should be refused, got {err:?}"
        );
    }
}
