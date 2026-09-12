#![cfg(feature = "iso9660")]
//! External validation of the ISO 9660 writer against native tooling.
//!
//! Currently focused on the Rock Ridge `SP` (System Use Sharing
//! Protocol) marker on the root's "." record: IEEE P1282 / SUSP §5.3
//! requires it so that conformant readers (e.g. `isoinfo -d`) recognise
//! that Rock Ridge extensions are present on the volume.
//!
//! Tests degrade gracefully when the native tools aren't installed.

use std::path::Path;
use std::process::Command;

use fstool::block::FileBackend;
use fstool::fs::iso9660::{FormatOpts, Iso9660Writer};
use fstool::fs::{FileMeta, FileSource};
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

/// Build a tiny RR-enabled ISO image at `path` containing a single
/// directory and one regular file, sized large enough for the writer's
/// pass-1 layout (a few sectors of overhead).
fn build_tiny_iso(path: &Path) {
    let capacity: u64 = 4 * 1024 * 1024;
    let mut dev = FileBackend::create(path, capacity).unwrap();
    let opts = FormatOpts {
        volume_id: "SPCHECK".into(),
        joliet: true,
        rock_ridge: true,
        ..FormatOpts::default()
    };
    let mut w = Iso9660Writer::new(opts);
    w.add_dir(Path::new("/etc"), FileMeta::default()).unwrap();
    let body = b"hi\n".to_vec();
    let src = FileSource::Reader {
        reader: Box::new(std::io::Cursor::new(body.clone())),
        len: body.len() as u64,
    };
    w.add_file(&mut dev, Path::new("/etc/conf"), src, FileMeta::default())
        .unwrap();
    w.flush(&mut dev).unwrap();
}

/// A 400-entry Rock Ridge directory spans several sectors, and records
/// never straddle a sector boundary; the extent size must include that
/// padding or a native reader loses the tail of the listing. Symlink
/// targets (absolute and relative) must come back exactly as given.
/// Verified with libarchive's `bsdtar`, which understands Rock Ridge.
#[test]
fn bsdtar_lists_large_rock_ridge_directory_and_symlinks() {
    let Some(_) = which("bsdtar") else {
        eprintln!("skipping: bsdtar not installed");
        return;
    };
    const N: usize = 400;
    let tmp = NamedTempFile::new().unwrap();
    {
        let mut dev = FileBackend::create(tmp.path(), 16 * 1024 * 1024).unwrap();
        let opts = FormatOpts {
            volume_id: "BIGDIR".into(),
            joliet: true,
            rock_ridge: true,
            ..FormatOpts::default()
        };
        let mut w = Iso9660Writer::new(opts);
        for i in 0..N {
            let name = format!("/big/file-number-{i:03}-with-a-longish-name.txt");
            let body = format!("{i}\n").into_bytes();
            let src = FileSource::Reader {
                reader: Box::new(std::io::Cursor::new(body.clone())),
                len: body.len() as u64,
            };
            w.add_file(&mut dev, Path::new(&name), src, FileMeta::default())
                .unwrap();
        }
        w.add_symlink(
            Path::new("/abs"),
            Path::new("/usr/lib/libc.so"),
            FileMeta::default(),
        )
        .unwrap();
        w.add_symlink(
            Path::new("/rel"),
            Path::new("big/file-number-000-with-a-longish-name.txt"),
            FileMeta::default(),
        )
        .unwrap();
        w.flush(&mut dev).unwrap();
    }

    let out = Command::new("bsdtar")
        .arg("-tvf")
        .arg(tmp.path())
        .output()
        .expect("bsdtar failed to spawn");
    let listing = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "bsdtar -tvf failed: {:?}\n{}\n{}",
        out.status,
        listing,
        String::from_utf8_lossy(&out.stderr)
    );
    let files = listing
        .lines()
        .filter(|l| {
            l.contains("big/file-number-")
                && l.contains("-with-a-longish-name.txt")
                && !l.contains(" -> ")
        })
        .count();
    assert_eq!(files, N, "bsdtar saw {files} of {N} files:\n{listing}");
    for i in [0usize, N / 2, N - 1] {
        let want = format!("file-number-{i:03}-with-a-longish-name.txt");
        assert!(listing.contains(&want), "missing {want}:\n{listing}");
    }
    assert!(
        listing.contains("abs -> /usr/lib/libc.so"),
        "absolute symlink target mangled:\n{listing}"
    );
    assert!(
        listing.contains("rel -> big/file-number-000-with-a-longish-name.txt"),
        "relative symlink target mangled:\n{listing}"
    );
}

#[test]
fn isoinfo_recognises_rock_ridge_sp_marker() {
    let Some(_) = which("isoinfo") else {
        eprintln!("skipping: isoinfo not installed");
        return;
    };

    let tmp = NamedTempFile::new().unwrap();
    build_tiny_iso(tmp.path());

    // `isoinfo -d -i <image>` dumps the volume descriptors. When the
    // SP entry is present on the root's "." record it prints either a
    // "Rock Ridge ... found" line, or — depending on isoinfo version —
    // a "SUSP signatures version 1 found" line. Without SP it prints
    // "NO SUSP/Rock Ridge present".
    let out = Command::new("isoinfo")
        .arg("-d")
        .arg("-i")
        .arg(tmp.path())
        .output()
        .expect("isoinfo failed to spawn");
    assert!(out.status.success(), "isoinfo failed: {:?}", out.status);
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let lower = combined.to_lowercase();
    let detected = (lower.contains("rock ridge") || lower.contains("susp signatures"))
        && !lower.contains("no susp")
        && !lower.contains("no rock ridge");
    assert!(
        detected,
        "isoinfo did not detect SUSP/Rock Ridge on the image. Output:\n{combined}"
    );
}
