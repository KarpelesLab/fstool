#![cfg(all(target_os = "macos", feature = "fat"))]
//! Native cross-check of `fstool::fs::fat::verify` against `fsck_msdos -n`:
//! macOS-made FAT12 / FAT16 / FAT32 images with content verify clean, and
//! deliberately corrupted copies are flagged by both.
//!
//! Skips (with a message) when `hdiutil` or `fsck_msdos` is missing.

use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use fstool::block::FileBackend;
use fstool::fs::fat::verify::verify;
use fstool::fs::verify::VerifyOpts;

fn which(tool: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {tool}"))
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

struct Attached(String);
impl Drop for Attached {
    fn drop(&mut self) {
        for _ in 0..5 {
            if Command::new("hdiutil")
                .args(["detach", "-force", &self.0])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
            {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    }
}

fn fsck(img: &Path) -> (bool, String) {
    let out = Command::new("hdiutil")
        .args(["attach", "-nomount", "-readonly", "-imagekey"])
        .arg("diskimage-class=CRawDiskImage")
        .arg(img)
        .output()
        .unwrap();
    assert!(out.status.success(), "hdiutil attach");
    let a = Attached(
        String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .next()
            .unwrap()
            .to_string(),
    );
    let out = Command::new("fsck_msdos")
        .arg("-n")
        .arg(&a.0)
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), text)
}

fn make_src(dir: &Path) -> PathBuf {
    let src = dir.join("src");
    std::fs::create_dir_all(src.join("dir/sub")).unwrap();
    for i in 1..=5u8 {
        std::fs::write(
            src.join(format!("dir/f{i}.bin")),
            vec![i; 30_000 * i as usize],
        )
        .unwrap();
    }
    std::fs::write(src.join("a.txt"), b"hello\n").unwrap();
    std::fs::write(src.join("dir/sub/Long File Name.txt"), b"x\n").unwrap();
    src
}

fn image(dir: &Path, src: &Path, fs: &str, size: &str) -> Option<PathBuf> {
    let base = dir.join(fs.replace(' ', "-"));
    let out = Command::new("hdiutil")
        .args([
            "create", "-quiet", "-fs", fs, "-layout", "NONE", "-size", size,
        ])
        .args(["-volname", "NATIVE", "-srcfolder"])
        .arg(src)
        .args(["-format", "UDTO"])
        .arg(&base)
        .output()
        .unwrap();
    let img = base.with_extension("cdr");
    (out.status.success() && img.exists()).then_some(img)
}

struct Geo {
    kind: u8,
    reserved: u64,
    fat_size: u64,
    fats: u64,
    data: u64,
    cluster: u64,
}

fn geo(img: &Path) -> Geo {
    let mut b = [0u8; 512];
    std::fs::File::open(img)
        .unwrap()
        .read_at(&mut b, 0)
        .unwrap();
    let mut dev = FileBackend::open_read_only(img).unwrap();
    let _ = &mut dev;
    let bs = fstool::fs::fat::boot::BootSector::decode(&b).unwrap();
    Geo {
        kind: match bs.kind {
            fstool::fs::fat::FatKind::Fat12 => 12,
            fstool::fs::fat::FatKind::Fat16 => 16,
            _ => 32,
        },
        reserved: u64::from(bs.reserved_sector_count) * 512,
        fat_size: u64::from(bs.fat_size) * 512,
        fats: u64::from(bs.num_fats),
        data: u64::from(bs.data_start_sector()) * 512,
        cluster: u64::from(bs.sectors_per_cluster) * 512,
    }
}

/// Set FAT entry `n` to `v` in the given copies.
fn set_entry(img: &Path, g: &Geo, n: u64, v: u32, copies: std::ops::Range<u64>) {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(img)
        .unwrap();
    for c in copies {
        let base = g.reserved + c * g.fat_size;
        match g.kind {
            12 => {
                let o = base + n * 3 / 2;
                let mut w = [0u8; 2];
                f.read_at(&mut w, o).unwrap();
                let mut x = u16::from_le_bytes(w);
                if n.is_multiple_of(2) {
                    x = (x & 0xF000) | (v as u16 & 0xFFF);
                } else {
                    x = (x & 0x000F) | ((v as u16 & 0xFFF) << 4);
                }
                f.write_at(&x.to_le_bytes(), o).unwrap();
            }
            16 => {
                f.write_at(&(v as u16).to_le_bytes(), base + n * 2).unwrap();
            }
            _ => {
                f.write_at(&v.to_le_bytes(), base + n * 4).unwrap();
            }
        }
    }
}

fn get_entry(img: &Path, g: &Geo, n: u64) -> u32 {
    let f = std::fs::File::open(img).unwrap();
    match g.kind {
        12 => {
            let mut w = [0u8; 2];
            f.read_at(&mut w, g.reserved + n * 3 / 2).unwrap();
            let x = u16::from_le_bytes(w);
            u32::from(if n.is_multiple_of(2) {
                x & 0xFFF
            } else {
                x >> 4
            })
        }
        16 => {
            let mut w = [0u8; 2];
            f.read_at(&mut w, g.reserved + n * 2).unwrap();
            u32::from(u16::from_le_bytes(w))
        }
        _ => {
            let mut w = [0u8; 4];
            f.read_at(&mut w, g.reserved + n * 4).unwrap();
            u32::from_le_bytes(w) & 0x0FFF_FFFF
        }
    }
}

/// Byte offset of the 8.3 directory entry `name` (first match after the FATs).
fn dirent(img: &Path, g: &Geo, name: &[u8; 11]) -> u64 {
    let bytes = std::fs::read(img).unwrap();
    let from = (g.reserved + g.fats * g.fat_size) as usize;
    let at = bytes[from..]
        .windows(11)
        .enumerate()
        .find(|(i, w)| w == name && (from + i).is_multiple_of(32))
        .map(|(i, _)| from + i)
        .expect("dir entry");
    at as u64
}

fn first_cluster(img: &Path, g: &Geo, at: u64) -> u32 {
    let mut e = [0u8; 32];
    std::fs::File::open(img)
        .unwrap()
        .read_at(&mut e, at)
        .unwrap();
    let lo = u32::from(u16::from_le_bytes([e[26], e[27]]));
    let hi = u32::from(u16::from_le_bytes([e[20], e[21]]));
    if g.kind == 32 { (hi << 16) | lo } else { lo }
}

fn desync_fat_copy(p: &Path) {
    let g = geo(p);
    let at = dirent(p, &g, b"F3      BIN");
    let c = u64::from(first_cluster(p, &g, at));
    set_entry(p, &g, c, 0x0FFF_FFFF, 1..2);
}

type Corruption = (&'static str, fn(&Path));

fn corruptions() -> Vec<Corruption> {
    vec![
        ("lost cluster", |p| {
            let g = geo(p);
            let total = (std::fs::metadata(p).unwrap().len() - g.data) / g.cluster;
            set_entry(p, &g, total - 3, 0x0FFF_FFFF, 0..g.fats);
        }),
        ("chain into a free cluster", |p| {
            let g = geo(p);
            let at = dirent(p, &g, b"F4      BIN");
            let c = u64::from(first_cluster(p, &g, at));
            let next = u64::from(get_entry(p, &g, c));
            set_entry(p, &g, next, 0, 0..g.fats);
        }),
        ("file size", |p| {
            let g = geo(p);
            let at = dirent(p, &g, b"F2      BIN");
            let f = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(p)
                .unwrap();
            f.write_at(&(4 * 60_000u32).to_le_bytes(), at + 28).unwrap();
        }),
        ("cross-linked files", |p| {
            let g = geo(p);
            let a = dirent(p, &g, b"F1      BIN");
            let b = dirent(p, &g, b"F5      BIN");
            let mut e = [0u8; 32];
            let f = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(p)
                .unwrap();
            f.read_at(&mut e, b).unwrap();
            f.write_at(&e[20..22], a + 20).unwrap();
            f.write_at(&e[26..28], a + 26).unwrap();
        }),
    ]
}

#[test]
fn fat_verify_agrees_with_fsck_msdos() {
    if !which("hdiutil") || !which("fsck_msdos") {
        eprintln!("skipping: hdiutil / fsck_msdos not available");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let src = make_src(dir.path());
    for (fs, size) in [
        ("MS-DOS FAT12", "8m"),
        ("MS-DOS FAT16", "40m"),
        ("MS-DOS FAT32", "300m"),
    ] {
        let Some(img) = image(dir.path(), &src, fs, size) else {
            eprintln!("skipping {fs}: hdiutil create failed");
            continue;
        };
        let (ok, text) = fsck(&img);
        assert!(ok, "{fs}: precondition, fsck_msdos -n not clean:\n{text}");
        let mut dev = FileBackend::open_read_only(&img).unwrap();
        let r = verify(&mut dev, &VerifyOpts::default()).unwrap();
        assert!(r.is_clean(), "{fs}: {:#?}", r.diagnostics);
        drop(dev);
        // Differing FAT copies: fsck_msdos works from the first copy and
        // calls this clean; fstool warns.
        let copy = dir.path().join("corrupt.img");
        std::fs::copy(&img, &copy).unwrap();
        desync_fat_copy(&copy);
        let (fsck_ok, text) = fsck(&copy);
        let mut dev = FileBackend::open_read_only(&copy).unwrap();
        let r = verify(&mut dev, &VerifyOpts::default()).unwrap();
        assert!(fsck_ok, "{fs}: {text}");
        assert!(r.is_clean() && r.has(fstool::fs::verify::DiagCode::TableCopiesDiffer));
        for (what, corrupt) in corruptions() {
            let copy = dir.path().join("corrupt.img");
            std::fs::copy(&img, &copy).unwrap();
            corrupt(&copy);
            let (fsck_ok, text) = fsck(&copy);
            let mut dev = FileBackend::open_read_only(&copy).unwrap();
            let r = verify(&mut dev, &VerifyOpts::default()).unwrap();
            assert!(
                !fsck_ok,
                "{fs} / {what}: fsck_msdos did not flag it:\n{text}"
            );
            assert!(
                r.error_count > 0,
                "{fs} / {what}: fsck_msdos flags it, fstool does not:\n{text}\n{:#?}",
                r.diagnostics
            );
        }
    }
}
