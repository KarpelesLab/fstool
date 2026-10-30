#![cfg(all(
    unix,
    feature = "dmg-encrypted-write",
    feature = "dmg-encrypted-recovery"
))]
//! Certificate / public-key recovery records and multi-passphrase images,
//! validated against macOS' `hdiutil` in both directions:
//!
//! - an image fstool creates for a recipient certificate plus a passphrase
//!   attaches in `hdiutil` with the passphrase, and with only the private
//!   key via `hdiutil attach -recover <keychain>`; a certificate-only image
//!   attaches with `-recover`;
//! - a certificate record fstool adds to an `hdiutil`-made passphrase image
//!   recovers natively, and once fstool removes it again it no longer does;
//! - images with several passphrase records (made by fstool, or grown with
//!   `add_passphrase`) attach in `hdiutil` with each passphrase;
//! - an image `hdiutil create -certificate` made opens in fstool with the
//!   certificate's private key alone, and decrypts to the same bytes as
//!   with the passphrase.
//!
//! The certificate and key are made with `openssl` in a temporary
//! directory. For `-recover` they are imported into a throw-away keychain
//! (`security create-keychain`) that is deleted when the test ends; the
//! user's keychain search list is snapshotted and restored, and never
//! changed on purpose.
//!
//! macOS-only; elsewhere, or without `openssl` / `security`, every test
//! prints `skipping: …` and passes.

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use fstool::block::BlockDevice;
use fstool::block::dmg::EncryptedDmgBackend;
use fstool::block::dmg::encrypted::{
    ContentCipher, ContentKeys, CreateOptions, Credential, KeyRecordKind, OsRandom, Protector,
    RecipientKey, RecoveryKey, RekeyOptions, add_passphrase, add_recipient,
    create_encrypted_image_with, inspect_encrypted_image, remove_key_record_with,
};

const TEST_ITERATIONS: u32 = 20_000;

/// Give up on (and kill) any external command after this long, so a
/// `hdiutil` that decides to prompt can't hang the suite.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(120);

fn skip() -> bool {
    if !cfg!(target_os = "macos") {
        eprintln!("skipping: recovery-record e2e requires macOS (hdiutil, security)");
        return true;
    }
    for (cmd, args) in [
        ("hdiutil", &["help"][..]),
        ("openssl", &["version"][..]),
        ("security", &["help"][..]),
    ] {
        // `security help` exits non-zero on some releases; only its
        // presence matters.
        let present = Command::new(cmd)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .is_ok();
        if !present {
            eprintln!("skipping: {cmd} not available");
            return true;
        }
    }
    false
}

/// Run `cmd args…` with `stdin` piped in, killing it after
/// [`COMMAND_TIMEOUT`]. Returns `(success, stdout, stderr)`.
fn run(cmd: &str, args: &[&str], stdin: &[u8]) -> (bool, String, String) {
    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {cmd}: {e}"));
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            let mut out = String::new();
            let mut err = String::new();
            child.stdout.take().unwrap().read_to_string(&mut out).ok();
            child.stderr.take().unwrap().read_to_string(&mut err).ok();
            return (status.success(), out, err);
        }
        if start.elapsed() > COMMAND_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            return (false, String::new(), format!("{cmd} timed out"));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn p(path: &Path) -> &str {
    path.to_str().unwrap()
}

/// A self-signed RSA certificate and its key, made by `openssl`.
struct Identity {
    cert_der: Vec<u8>,
    key_pkcs8_der: Vec<u8>,
    p12: PathBuf,
}

fn make_identity(dir: &Path, name: &str) -> Identity {
    let key_pem = dir.join(format!("{name}.key.pem"));
    let cert_pem = dir.join(format!("{name}.cert.pem"));
    let cert_der = dir.join(format!("{name}.cer"));
    let key_der = dir.join(format!("{name}.key.der"));
    let p12 = dir.join(format!("{name}.p12"));
    let subj = format!("/CN=fstool recovery test {name}");
    let (ok, _, err) = run(
        "openssl",
        &[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "2",
            "-subj",
            &subj,
            "-keyout",
            p(&key_pem),
            "-out",
            p(&cert_pem),
        ],
        b"",
    );
    assert!(ok, "openssl req: {err}");
    let (ok, _, err) = run(
        "openssl",
        &[
            "x509",
            "-in",
            p(&cert_pem),
            "-outform",
            "DER",
            "-out",
            p(&cert_der),
        ],
        b"",
    );
    assert!(ok, "openssl x509: {err}");
    let (ok, _, err) = run(
        "openssl",
        &[
            "pkcs8",
            "-topk8",
            "-nocrypt",
            "-in",
            p(&key_pem),
            "-outform",
            "DER",
            "-out",
            p(&key_der),
        ],
        b"",
    );
    assert!(ok, "openssl pkcs8: {err}");
    // `security import` reads only the legacy PKCS#12 ciphers; OpenSSL 3+
    // needs `-legacy` for them, LibreSSL doesn't know the flag.
    let mut args = vec![
        "pkcs12",
        "-export",
        "-inkey",
        p(&key_pem),
        "-in",
        p(&cert_pem),
        "-out",
        p(&p12),
        "-passout",
        "pass:p12pass",
    ];
    let (mut ok, _, mut err) = run("openssl", &[&args[..], &["-legacy"]].concat(), b"");
    if !ok {
        args.retain(|a| *a != "-legacy");
        (ok, _, err) = run("openssl", &args, b"");
    }
    assert!(ok, "openssl pkcs12: {err}");
    Identity {
        cert_der: std::fs::read(cert_der).unwrap(),
        key_pkcs8_der: std::fs::read(key_der).unwrap(),
        p12,
    }
}

fn search_list() -> String {
    run("security", &["list-keychains", "-d", "user"], b"").1
}

/// Parse `security list-keychains` output back into paths.
fn parse_search_list(s: &str) -> Vec<String> {
    s.lines()
        .map(|l| l.trim().trim_matches('"').to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

/// A throw-away keychain holding one identity; deleted on drop, with the
/// user's keychain search list restored if anything changed it.
struct TempKeychain {
    path: PathBuf,
    saved_list: String,
}

impl TempKeychain {
    fn new(dir: &Path, id: &Identity) -> Option<Self> {
        let path = dir.join("fstool-recovery-test.keychain");
        let saved_list = search_list();
        let (ok, _, err) = run(
            "security",
            &["create-keychain", "-p", "kc-pass", p(&path)],
            b"",
        );
        let kc = Self { path, saved_list };
        kc.restore_list();
        if !ok {
            eprintln!("skipping -recover checks: security create-keychain: {err}");
            return None;
        }
        let (ok, _, err) = run(
            "security",
            &[
                "import",
                p(&id.p12),
                "-k",
                p(&kc.path),
                "-P",
                "p12pass",
                "-A",
            ],
            b"",
        );
        if !ok {
            eprintln!("skipping -recover checks: security import: {err}");
            return None;
        }
        Some(kc)
    }

    fn restore_list(&self) {
        if search_list() != self.saved_list {
            let paths = parse_search_list(&self.saved_list);
            let mut args = vec!["list-keychains", "-d", "user", "-s"];
            args.extend(paths.iter().map(String::as_str));
            run("security", &args, b"");
        }
    }
}

impl Drop for TempKeychain {
    fn drop(&mut self) {
        run("security", &["delete-keychain", p(&self.path)], b"");
        self.restore_list();
        let _ = std::fs::remove_file(&self.path);
    }
}

/// An attached image, detached on drop.
struct Attached {
    mountpoint: PathBuf,
}

impl Drop for Attached {
    fn drop(&mut self) {
        run("hdiutil", &["detach", "-force", p(&self.mountpoint)], b"");
    }
}

const ATTACH: &[&str] = &["attach", "-nobrowse", "-noautoopen", "-noverify"];

fn attach_with_passphrase(image: &Path, mnt: &Path, pw: &str) -> Option<Attached> {
    std::fs::create_dir_all(mnt).unwrap();
    let args = [ATTACH, &["-stdinpass", "-mountpoint", p(mnt), p(image)]].concat();
    let (ok, _, err) = run("hdiutil", &args, pw.as_bytes());
    if !ok {
        eprintln!(
            "hdiutil attach -stdinpass {} refused: {err}",
            image.display()
        );
        return None;
    }
    Some(Attached {
        mountpoint: mnt.to_path_buf(),
    })
}

/// `hdiutil attach -recover <keychain>`, no passphrase. (`-stdinpass`
/// would take precedence over `-recover`.) With stdin not a terminal,
/// `hdiutil` fails rather than prompts when recovery doesn't work; the
/// timeout in [`run`] covers a release that would prompt anyway.
fn attach_with_recovery(image: &Path, mnt: &Path, kc: &TempKeychain) -> Option<Attached> {
    std::fs::create_dir_all(mnt).unwrap();
    let args = [
        ATTACH,
        &["-recover", p(&kc.path), "-mountpoint", p(mnt), p(image)],
    ]
    .concat();
    let (ok, _, err) = run("hdiutil", &args, b"");
    if !ok {
        eprintln!("hdiutil attach -recover {} refused: {err}", image.display());
        return None;
    }
    Some(Attached {
        mountpoint: mnt.to_path_buf(),
    })
}

fn make_tree(dir: &Path) -> Vec<(&'static str, Vec<u8>)> {
    let files: Vec<(&'static str, Vec<u8>)> = vec![
        (
            "hello.txt",
            b"hello from an fstool recovery image\n".to_vec(),
        ),
        (
            "blob.bin",
            (0..40_000u32)
                .map(|i| (i.wrapping_mul(2_654_435_761u32) >> 11) as u8)
                .collect(),
        ),
    ];
    std::fs::create_dir_all(dir).unwrap();
    for (name, data) in &files {
        std::fs::write(dir.join(name), data).unwrap();
    }
    files
}

fn check_files(mnt: &Path, files: &[(&str, Vec<u8>)], what: &str) {
    for (name, data) in files {
        let got = std::fs::read(mnt.join(name))
            .unwrap_or_else(|e| panic!("{what}: read {name} from the mounted image: {e}"));
        assert_eq!(&got, data, "{what}: {name} differs");
    }
}

/// A raw (UDTO) HFS+ payload built by `hdiutil create -srcfolder`.
fn make_payload(dir: &Path, src: &Path) -> PathBuf {
    let base = dir.join("payload");
    let (ok, _, err) = run(
        "hdiutil",
        &[
            "create",
            "-quiet",
            "-ov",
            "-fs",
            "HFS+",
            "-volname",
            "FSTOOLREC",
            "-layout",
            "NONE",
            "-format",
            "UDTO",
            "-srcfolder",
            p(src),
            p(&base),
        ],
        b"",
    );
    assert!(ok, "hdiutil create payload: {err}");
    base.with_extension("cdr")
}

fn fstool_create(payload: &Path, out: &Path, protectors: &[Protector<'_>]) {
    let mut src = std::fs::File::open(payload).unwrap();
    let len = src.metadata().unwrap().len();
    let mut dst = std::fs::File::create(out).unwrap();
    let keys = ContentKeys::generate(ContentCipher::Aes256, &mut OsRandom);
    let mut opts = CreateOptions::default();
    opts.pbkdf2_iterations = TEST_ITERATIONS;
    create_encrypted_image_with(
        &mut dst,
        &mut src,
        len,
        protectors,
        &keys,
        &opts,
        &mut OsRandom,
    )
    .unwrap();
}

fn open_rw(path: &Path) -> std::fs::File {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap()
}

fn rekey() -> RekeyOptions {
    let mut o = RekeyOptions::default();
    o.pbkdf2_iterations = TEST_ITERATIONS;
    o
}

fn read_all(mut be: EncryptedDmgBackend) -> Vec<u8> {
    let mut v = vec![0u8; be.total_size() as usize];
    be.read_at(0, &mut v).unwrap();
    v
}

/// fstool-made certificate images in `hdiutil`: passphrase and
/// `-recover` both attach; a certificate-only image recovers; a
/// recipient added to an `hdiutil` image recovers, and stops recovering
/// once fstool removes the record.
#[test]
fn fstool_recovery_records_work_in_hdiutil() {
    if skip() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let id = make_identity(dir.path(), "alice");
    let Some(kc) = TempKeychain::new(dir.path(), &id) else {
        return;
    };
    let recipient = RecipientKey::from_certificate_der(&id.cert_der).unwrap();
    let key = RecoveryKey::from_der(&id.key_pkcs8_der).unwrap();
    let files = make_tree(&dir.path().join("src"));
    let payload = make_payload(dir.path(), &dir.path().join("src"));
    let payload_bytes = std::fs::read(&payload).unwrap();
    let mnt = dir.path().join("mnt");

    // 1. Passphrase + certificate, in hdiutil's record order.
    let both = dir.path().join("both.dmg");
    fstool_create(
        &payload,
        &both,
        &[
            Protector::Recipient(&recipient),
            Protector::Passphrase("fstool pw"),
        ],
    );
    assert_eq!(
        read_all(EncryptedDmgBackend::open_with_recovery_key(&both, &key).unwrap()),
        payload_bytes
    );
    {
        let a = attach_with_passphrase(&both, &mnt, "fstool pw").expect("passphrase attach");
        check_files(&a.mountpoint, &files, "both/passphrase");
    }
    {
        let a = attach_with_recovery(&both, &mnt, &kc).expect("hdiutil -recover attach");
        check_files(&a.mountpoint, &files, "both/recover");
    }

    // 2. Certificate only.
    let cert_only = dir.path().join("cert-only.dmg");
    fstool_create(&payload, &cert_only, &[Protector::Recipient(&recipient)]);
    {
        let a = attach_with_recovery(&cert_only, &mnt, &kc).expect("cert-only -recover attach");
        check_files(&a.mountpoint, &files, "cert-only/recover");
    }

    // 3. A recipient added to an hdiutil-made passphrase image.
    let hd = dir.path().join("hd.dmg");
    let (ok, _, err) = run(
        "hdiutil",
        &[
            "create",
            "-quiet",
            "-ov",
            "-fs",
            "HFS+",
            "-volname",
            "HDREC",
            "-format",
            "UDZO",
            "-encryption",
            "AES-128",
            "-stdinpass",
            "-srcfolder",
            p(&dir.path().join("src")),
            p(&hd),
        ],
        b"hd pw",
    );
    assert!(ok, "hdiutil create -encryption: {err}");
    let idx = add_recipient(
        &mut open_rw(&hd),
        Credential::Passphrase("hd pw"),
        &recipient,
        &mut OsRandom,
    )
    .unwrap();
    {
        let a = attach_with_recovery(&hd, &mnt, &kc).expect("-recover after add_recipient");
        check_files(&a.mountpoint, &files, "hd+recipient/recover");
    }
    {
        let a = attach_with_passphrase(&hd, &mnt, "hd pw").expect("passphrase after add");
        check_files(&a.mountpoint, &files, "hd+recipient/passphrase");
    }
    // …and removed again: recovery stops working, the passphrase doesn't.
    remove_key_record_with(&mut open_rw(&hd), idx, Credential::Passphrase("hd pw")).unwrap();
    assert!(
        attach_with_recovery(&hd, &mnt, &kc).is_none(),
        "-recover still attaches after the record was removed"
    );
    {
        let a = attach_with_passphrase(&hd, &mnt, "hd pw").expect("passphrase after removal");
        check_files(&a.mountpoint, &files, "hd-recipient/passphrase");
    }
    drop(kc);
}

/// Images with several passphrase records attach in `hdiutil` with each.
#[test]
fn several_passphrase_records_attach_in_hdiutil() {
    if skip() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let files = make_tree(&dir.path().join("src"));
    let payload = make_payload(dir.path(), &dir.path().join("src"));
    let mnt = dir.path().join("mnt");

    let img = dir.path().join("two.dmg");
    fstool_create(
        &payload,
        &img,
        &[
            Protector::Passphrase("first"),
            Protector::Passphrase("second"),
        ],
    );
    add_passphrase(
        &mut open_rw(&img),
        Credential::Passphrase("second"),
        "third",
        &rekey(),
        &mut OsRandom,
    )
    .unwrap();
    let info = inspect_encrypted_image(&mut std::fs::File::open(&img).unwrap()).unwrap();
    assert_eq!(
        info.key_records
            .iter()
            .filter(|r| r.kind == KeyRecordKind::Passphrase)
            .count(),
        3
    );
    for pw in ["first", "second", "third"] {
        let a = attach_with_passphrase(&img, &mnt, pw)
            .unwrap_or_else(|| panic!("hdiutil refused passphrase record {pw:?}"));
        check_files(&a.mountpoint, &files, pw);
    }
    assert!(attach_with_passphrase(&img, &mnt, "fourth").is_none());
}

/// `hdiutil create -certificate`: fstool opens it with the private key
/// alone, inspects the record, and gets the same plaintext as with the
/// passphrase; a different key is refused.
#[test]
fn hdiutil_certificate_images_open_in_fstool() {
    if skip() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let id = make_identity(dir.path(), "bob");
    let other = make_identity(dir.path(), "mallory");
    let cer = dir.path().join("bob.cer");
    let recipient = RecipientKey::from_certificate_der(&id.cert_der).unwrap();
    let key = RecoveryKey::from_der(&id.key_pkcs8_der).unwrap();
    let wrong = RecoveryKey::from_der(&other.key_pkcs8_der).unwrap();
    for (enc_name, cipher) in [
        ("AES-128", ContentCipher::Aes128),
        ("AES-256", ContentCipher::Aes256),
    ] {
        let img = dir.path().join(format!("hdcert-{}.dmg", cipher.key_bits()));
        let (ok, _, err) = run(
            "hdiutil",
            &[
                "create",
                "-quiet",
                "-ov",
                "-size",
                "1m",
                "-fs",
                "HFS+",
                "-volname",
                "HDCERT",
                "-encryption",
                enc_name,
                "-certificate",
                p(&cer),
                "-stdinpass",
                p(&img),
            ],
            b"hd pw",
        );
        assert!(ok, "{enc_name}: hdiutil create -certificate: {err}");

        let info = inspect_encrypted_image(&mut std::fs::File::open(&img).unwrap()).unwrap();
        assert_eq!(info.cipher, Some(cipher));
        let pk = info
            .key_records
            .iter()
            .find_map(|r| r.public_key.as_ref())
            .unwrap_or_else(|| panic!("{enc_name}: no public-key record: {info:?}"));
        assert_eq!(pk.key_id, recipient.key_id(), "{enc_name}");
        assert!(pk.supported, "{enc_name}: {pk:?}");

        let by_key = read_all(EncryptedDmgBackend::open_with_recovery_key(&img, &key).unwrap());
        let by_pw = read_all(EncryptedDmgBackend::open_with_password(&img, "hd pw").unwrap());
        assert_eq!(by_key, by_pw, "{enc_name}");
        assert!(
            matches!(
                EncryptedDmgBackend::open_with_recovery_key(&img, &wrong).unwrap_err(),
                fstool::Error::Unsupported(_)
            ),
            "{enc_name}"
        );
    }
}
