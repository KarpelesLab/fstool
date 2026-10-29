#![cfg(all(unix, feature = "dmg-encrypted-write"))]
//! Encrypted-DMG creation and passphrase rotation, validated against
//! macOS' `hdiutil` in both directions:
//!
//! - an `encrcdsa` image fstool creates — wrapping a raw HFS+ volume or a
//!   compressed UDIF — attaches with `hdiutil attach -stdinpass` and its
//!   files read back; `hdiutil imageinfo -stdinpass` accepts it;
//! - after fstool rotates the passphrase, `hdiutil` attaches with the new
//!   one and refuses the old;
//! - an image `hdiutil create -encryption` made and `hdiutil chpass`
//!   rotated opens in fstool with the new passphrase, and fstool can
//!   rotate it again for `hdiutil` to open.
//!
//! macOS-only; elsewhere every test prints `skipping: …` and passes.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use fstool::block::BlockDevice;
use fstool::block::dmg::EncryptedDmgBackend;
use fstool::block::dmg::encrypted::{
    ContentCipher, ContentKeys, CreateOptions, KeyRecordKind, OsRandom, RekeyOptions,
    change_passphrase, create_encrypted_image, inspect_encrypted_image,
};

/// Low enough to keep the suite quick, high enough that nothing treats
/// it as degenerate.
const TEST_ITERATIONS: u32 = 20_000;

fn rekey_opts() -> RekeyOptions {
    let mut o = RekeyOptions::default();
    o.pbkdf2_iterations = TEST_ITERATIONS;
    o
}

fn skip_unless_macos_hdiutil() -> bool {
    if !cfg!(target_os = "macos") {
        eprintln!("skipping: encrypted-DMG e2e requires macOS (hdiutil)");
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

/// Run `hdiutil args…` with `stdin` piped in verbatim. Returns
/// `(success, stdout, stderr)`.
fn hdiutil_stdin(args: &[&str], path: Option<&Path>, stdin: &[u8]) -> (bool, String, String) {
    let mut cmd = Command::new("hdiutil");
    cmd.args(args);
    if let Some(p) = path {
        cmd.arg(p);
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn hdiutil");
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    let out = child.wait_with_output().unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// An attached image, detached on drop.
struct Attached {
    mountpoint: PathBuf,
}

impl Drop for Attached {
    fn drop(&mut self) {
        let _ = Command::new("hdiutil")
            .args(["detach", "-force"])
            .arg(&self.mountpoint)
            .output();
    }
}

/// `hdiutil attach -stdinpass` at a fresh mountpoint, or `None` if the
/// passphrase was refused (stderr is printed).
fn attach(image: &Path, mountpoint: &Path, password: &str) -> Option<Attached> {
    std::fs::create_dir_all(mountpoint).unwrap();
    let (ok, _out, err) = hdiutil_stdin(
        &[
            "attach",
            "-stdinpass",
            "-nobrowse",
            "-noautoopen",
            "-noverify",
            "-mountpoint",
            mountpoint.to_str().unwrap(),
        ],
        Some(image),
        password.as_bytes(),
    );
    if !ok {
        eprintln!("hdiutil attach {} refused: {err}", image.display());
        return None;
    }
    Some(Attached {
        mountpoint: mountpoint.to_path_buf(),
    })
}

/// A source tree with a couple of files, its contents returned for
/// comparison.
fn make_tree(dir: &Path) -> Vec<(&'static str, Vec<u8>)> {
    let files: Vec<(&'static str, Vec<u8>)> = vec![
        ("hello.txt", b"hello from fstool encrcdsa\n".to_vec()),
        (
            "blob.bin",
            (0..70_000u32)
                .map(|i| (i.wrapping_mul(2_654_435_761u32) >> 13) as u8)
                .collect(),
        ),
    ];
    std::fs::create_dir_all(dir).unwrap();
    for (name, data) in &files {
        std::fs::write(dir.join(name), data).unwrap();
    }
    files
}

/// `hdiutil create -srcfolder` a plain (unencrypted) payload image in
/// `format`; `None` if hdiutil refuses.
fn make_payload(dir: &Path, src: &Path, name: &str, format: &str) -> Option<PathBuf> {
    let base = dir.join(name);
    let out = Command::new("hdiutil")
        .args([
            "create",
            "-quiet",
            "-ov",
            "-fs",
            "HFS+",
            "-volname",
            "FSTOOLENC",
            "-layout",
            "NONE",
            "-format",
            format,
            "-srcfolder",
        ])
        .arg(src)
        .arg(&base)
        .output()
        .unwrap();
    if !out.status.success() {
        eprintln!(
            "skipping {format}: hdiutil create refused: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        return None;
    }
    // hdiutil appends its own extension (.cdr for UDTO, .dmg otherwise).
    ["cdr", "dmg"]
        .iter()
        .map(|ext| base.with_extension(ext))
        .find(|p| p.exists())
}

/// Wrap `payload` with fstool.
fn fstool_encrypt(payload: &Path, out: &Path, cipher: ContentCipher, password: &str) {
    let mut src = std::fs::File::open(payload).unwrap();
    let len = src.metadata().unwrap().len();
    let mut dst = std::fs::File::create(out).unwrap();
    let keys = ContentKeys::generate(cipher, &mut OsRandom);
    let mut opts = CreateOptions::default();
    opts.pbkdf2_iterations = TEST_ITERATIONS;
    let made = create_encrypted_image(
        &mut dst,
        &mut src,
        len,
        password,
        &keys,
        &opts,
        &mut OsRandom,
    )
    .unwrap();
    assert_eq!(made.payload_len, len);
    assert_eq!(dst.metadata().unwrap().len(), made.image_len);
}

fn check_files(mnt: &Path, files: &[(&str, Vec<u8>)], what: &str) {
    for (name, data) in files {
        let got = std::fs::read(mnt.join(name))
            .unwrap_or_else(|e| panic!("{what}: read {name} from the mounted image: {e}"));
        assert_eq!(&got, data, "{what}: {name} differs");
    }
}

/// fstool-made encrypted images over a raw HFS+ volume (UDTO) and over a
/// zlib UDIF (UDZO), both key sizes: `hdiutil imageinfo` and `attach`
/// accept them, the files read back, the fstool reader agrees with the
/// payload, a wrong passphrase is refused — then fstool rotates the
/// passphrase and `hdiutil` follows.
#[test]
fn fstool_created_images_attach_in_hdiutil() {
    if skip_unless_macos_hdiutil() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let files = make_tree(&dir.path().join("src"));
    let mut ran = 0;
    for format in ["UDTO", "UDZO"] {
        let Some(payload) = make_payload(dir.path(), &dir.path().join("src"), format, format)
        else {
            continue;
        };
        let payload_bytes = std::fs::read(&payload).unwrap();
        for cipher in [ContentCipher::Aes128, ContentCipher::Aes256] {
            let what = format!("{format}/{cipher:?}");
            let enc = dir
                .path()
                .join(format!("enc-{format}-{}.dmg", cipher.key_bits()));
            fstool_encrypt(&payload, &enc, cipher, "fstool pw");

            // fstool's own reader returns the payload unchanged.
            let mut be = EncryptedDmgBackend::open_with_password(&enc, "fstool pw").unwrap();
            let mut back = vec![0u8; be.total_size() as usize];
            be.read_at(0, &mut back).unwrap();
            assert_eq!(back, payload_bytes, "{what}: fstool reader");
            drop(be);

            let (ok, out, err) =
                hdiutil_stdin(&["imageinfo", "-stdinpass"], Some(&enc), b"fstool pw");
            assert!(ok, "{what}: hdiutil imageinfo refused: {err}");
            assert!(
                out.contains(&format!("AES-{}", cipher.key_bits())) || out.contains("Encrypted"),
                "{what}: imageinfo output:\n{out}"
            );

            let mnt = dir
                .path()
                .join(format!("mnt-{format}-{}", cipher.key_bits()));
            {
                let att = attach(&enc, &mnt, "fstool pw")
                    .unwrap_or_else(|| panic!("{what}: hdiutil attach refused"));
                check_files(&att.mountpoint, &files, &what);
            }
            assert!(
                attach(&enc, &mnt, "not it").is_none(),
                "{what}: hdiutil accepted a wrong passphrase"
            );

            // Rotate in place with fstool; hdiutil must follow.
            let before = std::fs::read(&enc).unwrap();
            {
                let mut f = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&enc)
                    .unwrap();
                change_passphrase(
                    &mut f,
                    "fstool pw",
                    "rotated pw",
                    &rekey_opts(),
                    &mut OsRandom,
                )
                .unwrap();
            }
            let after = std::fs::read(&enc).unwrap();
            assert_eq!(after.len(), before.len());
            assert_eq!(
                &after[0x2C8..],
                &before[0x2C8..],
                "{what}: payload must not change"
            );
            {
                let att = attach(&enc, &mnt, "rotated pw")
                    .unwrap_or_else(|| panic!("{what}: attach after rotation refused"));
                check_files(&att.mountpoint, &files, &format!("{what} rotated"));
            }
            assert!(
                attach(&enc, &mnt, "fstool pw").is_none(),
                "{what}: old passphrase still attaches after rotation"
            );
            ran += 1;
        }
    }
    assert!(ran > 0, "no payload format could be built");
}

/// `hdiutil create -encryption` + `hdiutil chpass`, then fstool opens it
/// with the new passphrase (and not the old), inspects it, rotates it
/// again, and `hdiutil` attaches with fstool's passphrase.
#[test]
fn hdiutil_chpass_images_open_in_fstool() {
    if skip_unless_macos_hdiutil() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let files = make_tree(&dir.path().join("src"));
    for (enc_name, cipher) in [
        ("AES-128", ContentCipher::Aes128),
        ("AES-256", ContentCipher::Aes256),
    ] {
        let img = dir.path().join(format!("hd-{}.dmg", cipher.key_bits()));
        let (ok, _, err) = hdiutil_stdin(
            &[
                "create",
                "-quiet",
                "-ov",
                "-fs",
                "HFS+",
                "-volname",
                "HDENC",
                "-format",
                "UDZO",
                "-encryption",
                enc_name,
                "-stdinpass",
                "-srcfolder",
                dir.path().join("src").to_str().unwrap(),
            ],
            Some(&img),
            b"first",
        );
        assert!(ok, "{enc_name}: hdiutil create: {err}");

        // `-oldstdinpass -newstdinpass`: both read from stdin, NUL-separated.
        let (ok, _, err) = hdiutil_stdin(
            &["chpass", "-oldstdinpass", "-newstdinpass"],
            Some(&img),
            b"first\0second",
        );
        assert!(ok, "{enc_name}: hdiutil chpass: {err}");

        let info = inspect_encrypted_image(&mut std::fs::File::open(&img).unwrap()).unwrap();
        assert_eq!(info.cipher, Some(cipher), "{enc_name}");
        assert!(info.kdf_within_limits(), "{enc_name}: {info:?}");
        assert!(
            info.key_records
                .iter()
                .any(|r| r.kind == KeyRecordKind::Passphrase),
            "{enc_name}: {info:?}"
        );

        assert!(
            EncryptedDmgBackend::open_with_password(&img, "first").is_err(),
            "{enc_name}: old passphrase still opens after hdiutil chpass"
        );
        let mut be = EncryptedDmgBackend::open_with_password(&img, "second")
            .unwrap_or_else(|e| panic!("{enc_name}: open after chpass: {e}"));
        // The payload is a UDIF: its koly trailer sits at the very end.
        let size = be.total_size();
        let mut koly = [0u8; 4];
        be.read_at(size - 512, &mut koly).unwrap();
        assert_eq!(&koly, b"koly", "{enc_name}: decrypted payload is a UDIF");
        drop(be);

        // fstool rotates hdiutil's image; hdiutil opens it.
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&img)
            .unwrap();
        change_passphrase(&mut f, "second", "third", &rekey_opts(), &mut OsRandom).unwrap();
        drop(f);
        let mnt = dir.path().join(format!("mnt-hd-{}", cipher.key_bits()));
        {
            let att = attach(&img, &mnt, "third")
                .unwrap_or_else(|| panic!("{enc_name}: attach after fstool rotation"));
            check_files(&att.mountpoint, &files, enc_name);
        }
        assert!(attach(&img, &mnt, "second").is_none(), "{enc_name}");
    }
}
