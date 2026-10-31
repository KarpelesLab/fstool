#![cfg(all(unix, feature = "dmg-write"))]
//! Native validation of fstool's container operations (conversion,
//! checksums, verification, segmenting, resources, container resize,
//! signature removal) against macOS' own `hdiutil` / `codesign`.
//!
//! - converted images pass `hdiutil verify` and attach with the source's
//!   exact raw bytes; a partitioned source keeps its blkx map;
//! - fstool's logical-sector checksums equal `hdiutil checksum`, and
//!   `verify_udif` agrees with `hdiutil verify` on good images and flags a
//!   corrupted one that `hdiutil verify` also rejects;
//! - segment sets made by fstool attach in hdiutil, and ones made by
//!   `hdiutil segment` open, verify and join in fstool;
//! - resources added by fstool are what `hdiutil udifderez` and
//!   `imageinfo` see (an SLA turns "Software License Agreement" on), and
//!   resources added by `hdiutil udifrez` are what fstool reads;
//! - resized containers attach with the expected size;
//! - a `codesign`-ed image is refused until the signature is explicitly
//!   removed, after which `codesign` reports it unsigned.
//!
//! Everything attached is detached again. Elsewhere, or without `hdiutil`,
//! every test prints `skipping: …` and passes.

use std::path::{Path, PathBuf};
use std::process::Command;

use fstool::block::BlockDevice;
use fstool::block::dmg::{
    ChecksumStatus, JoinOptions, ResourceEdit, SegmentOptions, SignaturePolicy, UdifFormat,
    UdifResource, UdifResources, edit_udif_resources, inspect_udif, join_udif,
    remove_code_signature, segment_udif, udif_segment_path, verify_udif,
};
use fstool::block::imageops::{
    ChecksumAlgorithm, ChecksumOptions, ContainerResizeOptions, ConvertOptions, ImageKind,
    ResourcePolicy, convert_image, image_checksum, resize_container,
};

fn hdiutil_ok() -> bool {
    cfg!(target_os = "macos")
        && Command::new("hdiutil")
            .arg("help")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
}

/// Attaching images from parallel tests races hdiutil's helper; run them
/// one at a time.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

macro_rules! need_hdiutil {
    () => {
        if !hdiutil_ok() {
            eprintln!("skipping: needs macOS hdiutil");
            return;
        }
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    };
}

/// Run `hdiutil`, returning (success, stdout + stderr).
fn hdiutil(args: &[&str], paths: &[&Path]) -> (bool, String) {
    let out = Command::new("hdiutil")
        .args(args)
        .args(paths)
        .output()
        .expect("spawn hdiutil");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), text)
}

fn hdiutil_ok_out(args: &[&str], paths: &[&Path]) -> String {
    let (ok, text) = hdiutil(args, paths);
    assert!(ok, "hdiutil {args:?} {paths:?} failed:\n{text}");
    text
}

/// An attached image, detached on drop.
struct Attached {
    dev: String,
}

impl Attached {
    fn new(image: &Path) -> Self {
        let plist = hdiutil_ok_out(
            &[
                "attach",
                "-plist",
                "-nobrowse",
                "-readonly",
                "-nomount",
                "-noverify",
                "-noautoopen",
            ],
            &[image],
        );
        let dev = whole_disk(&plist).expect("no /dev/diskN in hdiutil attach output");
        Self { dev }
    }

    fn read_all(&self, len: u64) -> Vec<u8> {
        use std::io::Read;
        let mut f = std::fs::File::open(&self.dev).unwrap();
        let mut v = vec![0u8; len as usize];
        for piece in v.chunks_mut(1 << 20) {
            f.read_exact(piece).unwrap();
        }
        v
    }

    fn size(&self) -> u64 {
        let out = Command::new("diskutil")
            .args(["info", "-plist", &self.dev])
            .output()
            .unwrap();
        let s = String::from_utf8_lossy(&out.stdout);
        let i = s.find("<key>Size</key>").expect("diskutil Size");
        let t = &s[i..];
        let a = t.find("<integer>").unwrap() + 9;
        let b = t.find("</integer>").unwrap();
        t[a..b].trim().parse().unwrap()
    }
}

impl Drop for Attached {
    fn drop(&mut self) {
        for args in [&["detach", &self.dev][..], &["detach", "-force", &self.dev]] {
            let ok = Command::new("hdiutil")
                .args(args)
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            if ok {
                break;
            }
        }
        // hdiutil's helper can hold the image briefly after detach.
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
}

fn whole_disk(plist: &str) -> Option<String> {
    let mut rest = plist;
    while let Some(i) = rest.find("<string>/dev/disk") {
        let after = &rest[i + "<string>".len()..];
        let j = after.find("</string>")?;
        let dev = after[..j].trim();
        if !dev.trim_start_matches("/dev/disk").contains('s') {
            return Some(dev.to_string());
        }
        rest = &after[j..];
    }
    None
}

/// The logical sectors of an image, through fstool.
fn logical(p: &Path) -> Vec<u8> {
    let mut d = fstool::block::open_image_read_only(p).unwrap();
    let mut v = vec![0u8; d.total_size() as usize];
    d.read_at(0, &mut v).unwrap();
    v
}

/// A populated GPT + HFS+ disk made by hdiutil (UDZO), its partition map
/// holding protective MBR, GPT headers/tables, the partition and free
/// space.
fn reference(dir: &Path) -> PathBuf {
    let src = dir.join("src");
    std::fs::create_dir_all(&src).unwrap();
    let mut text = String::new();
    for i in 0..30_000 {
        text.push_str(&format!("line {i} lorem ipsum dolor sit amet\n"));
    }
    std::fs::write(src.join("t.txt"), text).unwrap();
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let noise: Vec<u8> = (0..2_500_000)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect();
    std::fs::write(src.join("n.bin"), noise).unwrap();
    let out = dir.join("ref.dmg");
    hdiutil_ok_out(
        &[
            "create",
            "-fs",
            "HFS+",
            "-layout",
            "GPTSPUD",
            "-format",
            "UDZO",
            "-volname",
            "Ops",
            "-ov",
            "-srcfolder",
        ],
        &[&src, &out],
    );
    out
}

fn hd_checksum(p: &Path, kind: &str) -> String {
    let out = hdiutil_ok_out(&["checksum", "-type", kind], &[p]);
    let line = out
        .lines()
        .rev()
        .find(|l| l.starts_with("calculated"))
        .expect("checksum line");
    line.rsplit('$').next().unwrap().trim().to_ascii_lowercase()
}

#[test]
fn conversions_pass_hdiutil_and_keep_sectors_and_layout() {
    need_hdiutil!();
    let dir = tempfile::tempdir().unwrap();
    let src = reference(dir.path());
    let want = logical(&src);
    let src_info = inspect_udif(&src).unwrap();
    assert!(src_info.blkx.len() > 1, "hdiutil made a partitioned image");
    let names = |p: &Path| {
        inspect_udif(p)
            .unwrap()
            .blkx
            .iter()
            .map(|b| (b.name.clone(), b.id, b.first_sector, b.sector_count))
            .collect::<Vec<_>>()
    };
    let formats = [
        UdifFormat::Udro,
        UdifFormat::Udco,
        UdifFormat::Udzo,
        UdifFormat::Udbz,
        UdifFormat::Ulmo,
        UdifFormat::Ufbi,
    ];
    for f in formats.into_iter().filter(|f| f.writable()) {
        let out = dir.path().join(format!("c-{}.dmg", f.name()));
        let mut o = ConvertOptions::default();
        o.udif.format = f;
        convert_image(&src, &out, &o).unwrap();
        let v = hdiutil_ok_out(&["verify"], &[&out]);
        assert!(v.contains("VALID"), "{}: {v}", f.name());
        assert!(verify_udif(&out).unwrap().is_valid());
        assert_eq!(names(&out), names(&src), "{}: blkx map kept", f.name());
        let a = Attached::new(&out);
        assert!(
            a.read_all(want.len() as u64) == want,
            "{}: attached bytes",
            f.name()
        );
    }
    // UDIF → sparseimage → UDIF, and UDIF → raw, through hdiutil too.
    let sp = dir.path().join("c.sparseimage");
    convert_image(&src, &sp, &ConvertOptions::default()).unwrap();
    {
        let a = Attached::new(&sp);
        assert!(a.read_all(want.len() as u64) == want, "sparseimage bytes");
    }
    let back = dir.path().join("back.dmg");
    let mut o = ConvertOptions::default();
    o.udif.format = UdifFormat::Udro;
    let r = convert_image(&sp, &back, &o).unwrap();
    assert_eq!(
        (r.source, r.target),
        (ImageKind::SparseImage, ImageKind::Udif)
    );
    assert!(hdiutil_ok_out(&["verify"], &[&back]).contains("VALID"));
    assert!(logical(&back) == want);
    let raw = dir.path().join("c.img");
    convert_image(&src, &raw, &ConvertOptions::default()).unwrap();
    assert!(std::fs::read(&raw).unwrap() == want);
}

#[test]
fn checksums_agree_with_hdiutil() {
    need_hdiutil!();
    let dir = tempfile::tempdir().unwrap();
    let src = reference(dir.path());
    let mut o = ConvertOptions::default();
    o.udif.format = UdifFormat::Udco;
    let ours = dir.path().join("ours.dmg");
    convert_image(&src, &ours, &o).unwrap();
    let seg = dir.path().join("seg.dmg");
    hdiutil_ok_out(&["segment", "-segmentSize", "1m", "-o"], &[&seg, &src]);
    for img in [&src, &ours, &seg] {
        for (alg, hd) in [
            (ChecksumAlgorithm::Crc32, "CRC32"),
            (ChecksumAlgorithm::Md5, "MD5"),
        ] {
            let c = image_checksum(img, alg, &ChecksumOptions::default()).unwrap();
            assert_eq!(c.hex(), hd_checksum(img, hd), "{} {hd}", img.display());
        }
        // Embedded checksums: fstool and hdiutil agree it is valid.
        let r = verify_udif(img).unwrap();
        assert!(r.is_valid() && r.checked_any(), "{}: {r:?}", img.display());
        assert!(hdiutil_ok_out(&["verify"], &[img]).contains("VALID"));
        // For hdiutil's own encoding, the recorded master is what
        // `checksum -type UDIF-CRC32` computes. (That type re-derives the
        // checksums the way hdiutil would encode the image — its own
        // free-space detection — so it is no check of another writer's.)
        if *img != ours {
            assert_eq!(r.master.stored.hex(), hd_checksum(img, "UDIF-CRC32"));
        }
    }
    // Unsupported algorithms are explicit.
    assert!(matches!(
        ChecksumAlgorithm::from_name("sha256"),
        Err(fstool::Error::Unsupported(_))
    ));

    // Corrupt one stored byte of a raw chunk: hdiutil verify rejects the
    // image, and so does fstool.
    let udro = dir.path().join("udro.dmg");
    let mut o = ConvertOptions::default();
    o.udif.format = UdifFormat::Udro;
    convert_image(&src, &udro, &o).unwrap();
    let info = inspect_udif(&udro).unwrap();
    let (b, c) = info
        .blkx
        .iter()
        .enumerate()
        .find_map(|(i, b)| {
            b.chunks
                .iter()
                .find(|c| {
                    c.kind == fstool::block::dmg::ChunkType::Raw && c.compressed_length > 1000
                })
                .map(|c| (i, *c))
        })
        .unwrap();
    let mut img = std::fs::read(&udro).unwrap();
    img[(c.compressed_offset_in_fork + 500) as usize] ^= 0x10;
    std::fs::write(&udro, &img).unwrap();
    let (ok, text) = hdiutil(&["verify"], &[&udro]);
    assert!(!ok, "hdiutil should reject the corrupted image:\n{text}");
    let r = verify_udif(&udro).unwrap();
    assert!(!r.is_valid());
    assert_eq!(r.partitions[b].status, ChecksumStatus::Mismatch);
    assert_eq!(r.data_forks[0].status, ChecksumStatus::Mismatch);
}

#[test]
fn segment_sets_interoperate_with_hdiutil() {
    need_hdiutil!();
    let dir = tempfile::tempdir().unwrap();
    let src = reference(dir.path());
    let want = logical(&src);
    // A source with a data-fork checksum, so every segment carries one.
    let udro = dir.path().join("udro.dmg");
    let mut o = ConvertOptions::default();
    o.udif.format = UdifFormat::Udro;
    convert_image(&src, &udro, &o).unwrap();

    // fstool segments → hdiutil.
    let ours = dir.path().join("ours.dmg");
    let mut so = SegmentOptions::default();
    so.segment_size = 1 << 20;
    let r = segment_udif(&udro, &ours, &so).unwrap();
    assert!(r.paths.len() >= 3);
    assert!(r.paths[1].ends_with("ours.002.dmgpart"));
    assert!(hdiutil_ok_out(&["verify"], &[&ours]).contains("VALID"));
    let info = hdiutil_ok_out(&["imageinfo"], &[&ours]);
    for p in &r.paths {
        assert!(
            info.contains(&*p.file_name().unwrap().to_string_lossy()),
            "{info}"
        );
    }
    {
        let a = Attached::new(&ours);
        assert!(a.read_all(want.len() as u64) == want);
    }

    // hdiutil segments (the same image) → fstool: identical slices.
    let theirs = dir.path().join("theirs.dmg");
    hdiutil_ok_out(&["segment", "-segmentSize", "1m", "-o"], &[&theirs, &udro]);
    let ti = inspect_udif(&theirs).unwrap();
    assert_eq!(ti.segments.len(), r.paths.len());
    for (n, s) in ti.segments.iter().enumerate() {
        assert_eq!(s.trailer.segment_number, n as u32 + 1);
        assert_eq!(s.trailer.data_fork_length, r.fork_lengths[n]);
        let mine = std::fs::read(udif_segment_path(&ours, n as u32 + 1)).unwrap();
        let hd = std::fs::read(s.path.as_ref().unwrap()).unwrap();
        let len = s.trailer.data_fork_length as usize;
        assert_eq!(mine[..len], hd[..len], "segment {} data", n + 1);
        let mk = fstool::block::dmg::KolyTrailer::decode(&mine[mine.len() - 512..]).unwrap();
        assert_eq!(
            mk.data_checksum,
            s.trailer.data_checksum,
            "segment {}",
            n + 1
        );
        assert_eq!(
            mk.running_data_fork_offset,
            s.trailer.running_data_fork_offset
        );
    }
    assert!(logical(&theirs) == want);
    assert!(verify_udif(&theirs).unwrap().is_valid());
    // ...and joins into an image hdiutil accepts.
    let joined = dir.path().join("joined.dmg");
    join_udif(&theirs, &joined, &JoinOptions::default()).unwrap();
    assert!(hdiutil_ok_out(&["verify"], &[&joined]).contains("VALID"));
    assert!(
        std::fs::read(&joined).unwrap()[..ti.fork_length as usize]
            == std::fs::read(&udro).unwrap()[..ti.fork_length as usize]
    );
    // An hdiutil-created UDZO (no data-fork checksums, entry-relative chunk
    // offsets once segmented) also round-trips.
    let zseg = dir.path().join("zseg.dmg");
    hdiutil_ok_out(&["segment", "-segmentSize", "1m", "-o"], &[&zseg, &src]);
    let zj = dir.path().join("zjoined.dmg");
    join_udif(&zseg, &zj, &JoinOptions::default()).unwrap();
    assert!(hdiutil_ok_out(&["verify"], &[&zj]).contains("VALID"));
    assert!(logical(&zj) == want);
    // A missing part is reported by name.
    std::fs::remove_file(udif_segment_path(&zseg, 2)).unwrap();
    let e = join_udif(&zseg, &dir.path().join("x.dmg"), &JoinOptions::default())
        .unwrap_err()
        .to_string();
    assert!(e.contains("zseg.002.dmgpart"), "{e}");
}

/// A US-English SLA: `LPic` + `STR#` buttons + `TEXT`.
fn sla() -> UdifResources {
    let mut r = UdifResources::new();
    r.insert(UdifResource::new(
        "LPic",
        5000,
        vec![0, 0, 0, 1, 0, 0, 0, 0, 0, 0],
    ));
    let mut strs = vec![0u8, 6];
    for s in [
        "English",
        "Agree",
        "Disagree",
        "Print",
        "Save...",
        "Please agree.",
    ] {
        strs.push(s.len() as u8);
        strs.extend_from_slice(s.as_bytes());
    }
    let mut s = UdifResource::new("STR#", 5000, strs);
    s.name = "English buttons".into();
    r.insert(s);
    let mut t = UdifResource::new("TEXT", 5000, b"Licence text from fstool.".to_vec());
    t.name = "English SLA".into();
    r.insert(t);
    r
}

#[test]
fn resources_interoperate_with_udifrez() {
    need_hdiutil!();
    let dir = tempfile::tempdir().unwrap();
    let src = reference(dir.path());
    let img = dir.path().join("rez.dmg");
    std::fs::copy(&src, &img).unwrap();
    let sla_flag = |p: &Path| {
        hdiutil_ok_out(&["imageinfo"], &[p])
            .lines()
            .find(|l| l.contains("Software License Agreement"))
            .map(|l| l.trim().to_string())
            .unwrap_or_default()
    };
    assert!(sla_flag(&img).ends_with("false"));
    // fstool adds an SLA: hdiutil sees it, and sees our bytes.
    let mut e = ResourceEdit::default();
    e.add = sla();
    edit_udif_resources(&img, &img, &e).unwrap();
    assert!(sla_flag(&img).ends_with("true"), "{}", sla_flag(&img));
    assert!(hdiutil_ok_out(&["verify"], &[&img]).contains("VALID"));
    let derez = hdiutil_ok_out(&["udifderez", "-xml"], &[&img]);
    let xml = &derez[derez.find("<?xml").unwrap()..];
    let theirs = UdifResources::from_xml(xml).unwrap();
    for r in &sla().entries {
        assert_eq!(
            theirs.get(&r.kind, r.id),
            Some(r),
            "{} via udifderez",
            r.kind
        );
    }
    // blkx is untouched.
    assert_eq!(
        theirs.of_kind("blkx").count(),
        inspect_udif(&src).unwrap().blkx.len()
    );
    // Converting keeps the SLA; removing it turns the flag off again.
    let conv = dir.path().join("conv.dmg");
    let mut o = ConvertOptions::default();
    o.udif.format = if UdifFormat::Udbz.writable() {
        UdifFormat::Udbz
    } else {
        UdifFormat::Udro
    };
    convert_image(&img, &conv, &o).unwrap();
    assert!(sla_flag(&conv).ends_with("true"));
    let raw = dir.path().join("conv.img");
    assert!(convert_image(&img, &raw, &ConvertOptions::default()).is_err());
    let mut o = ConvertOptions::default();
    o.resources = ResourcePolicy::Drop;
    convert_image(&img, &raw, &o).unwrap();
    let mut e = ResourceEdit::default();
    e.remove = vec![("LPic".into(), None)];
    edit_udif_resources(&img, &img, &e).unwrap();
    assert!(sla_flag(&img).ends_with("false"));

    // hdiutil udifrez adds a resource: fstool reads it.
    let rez = dir.path().join("in.xml");
    let mut add = UdifResources::new();
    let mut t = UdifResource::new("TEXT", 5002, b"from udifrez".to_vec());
    t.name = "Note".into();
    add.insert(t.clone());
    std::fs::write(&rez, add.to_xml()).unwrap();
    let out = Command::new("hdiutil")
        .arg("udifrez")
        .arg(&img)
        .arg("-xml")
        .arg(&rez)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let info = inspect_udif(&img).unwrap();
    assert_eq!(info.resources.get("TEXT", 5002), Some(&t));
    assert!(verify_udif(&img).unwrap().is_valid());
}

#[test]
fn resized_containers_attach_with_the_new_size() {
    need_hdiutil!();
    let dir = tempfile::tempdir().unwrap();
    let src = reference(dir.path());
    let want = logical(&src);
    let size = want.len() as u64;
    let grown = size + (3 << 20);
    // UDIF.
    let img = dir.path().join("r.dmg");
    let mut o = ConvertOptions::default();
    o.udif.format = UdifFormat::Udco;
    convert_image(&src, &img, &o).unwrap();
    let r = resize_container(&img, grown, &ContainerResizeOptions::default()).unwrap();
    assert_eq!((r.old_size, r.new_size), (size, grown));
    assert!(hdiutil_ok_out(&["verify"], &[&img]).contains("VALID"));
    {
        let a = Attached::new(&img);
        assert_eq!(a.size(), grown);
        let got = a.read_all(grown);
        assert!(got[..want.len()] == want[..]);
        assert!(got[want.len()..].iter().all(|&b| b == 0));
    }
    // Shrinking back over the zero tail; further would cut the backup GPT.
    resize_container(&img, size, &ContainerResizeOptions::default()).unwrap();
    assert!(logical(&img) == want);
    assert!(resize_container(&img, size - 4096, &ContainerResizeOptions::default()).is_err());
    // sparseimage.
    let sp = dir.path().join("r.sparseimage");
    convert_image(&src, &sp, &ConvertOptions::default()).unwrap();
    resize_container(&sp, grown, &ContainerResizeOptions::default()).unwrap();
    {
        let a = Attached::new(&sp);
        assert_eq!(a.size(), grown);
    }
}

#[test]
fn signed_images_need_explicit_removal() {
    need_hdiutil!();
    let ok = Command::new("codesign")
        .arg("--help")
        .output()
        .map(|o| !o.stderr.is_empty() || o.status.success())
        .unwrap_or(false);
    if !ok {
        eprintln!("skipping: needs codesign");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let src = reference(dir.path());
    let img = dir.path().join("signed.dmg");
    let mut o = ConvertOptions::default();
    o.udif.format = UdifFormat::Udro;
    convert_image(&src, &img, &o).unwrap();
    let unsigned = std::fs::read(&img).unwrap();
    let out = Command::new("codesign")
        .args(["-s", "-"])
        .arg(&img)
        .output()
        .unwrap();
    if !out.status.success() {
        eprintln!(
            "skipping: ad-hoc codesign failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        return;
    }
    let sig = inspect_udif(&img)
        .unwrap()
        .code_signature()
        .expect("signature");
    assert!(sig.length > 0);
    let signed = std::fs::read(&img).unwrap();
    let conv = dir.path().join("conv.dmg");
    assert!(convert_image(&img, &conv, &ConvertOptions::default()).is_err());
    assert!(edit_udif_resources(&img, &img, &ResourceEdit::default()).is_err());
    assert_eq!(
        std::fs::read(&img).unwrap(),
        signed,
        "refusals change nothing"
    );
    let mut o = ConvertOptions::default();
    o.policy.signature = SignaturePolicy::Remove;
    convert_image(&img, &conv, &o).unwrap();
    assert!(inspect_udif(&conv).unwrap().code_signature().is_none());
    remove_code_signature(&img, &img).unwrap();
    assert_eq!(std::fs::read(&img).unwrap(), unsigned);
    let cs = Command::new("codesign")
        .arg("-dv")
        .arg(&img)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&cs.stderr);
    assert!(text.contains("not signed"), "{text}");
    assert!(hdiutil_ok_out(&["verify"], &[&img]).contains("VALID"));
}

#[test]
fn cli_operations() {
    need_hdiutil!();
    let bin = env!("CARGO_BIN_EXE_fstool");
    let dir = tempfile::tempdir().unwrap();
    let src = reference(dir.path());
    let run = |args: &[&std::ffi::OsStr]| {
        let out = Command::new(bin).args(args).output().unwrap();
        (
            out.status.success(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        )
    };
    let (ok, text) = run(&["verify".as_ref(), src.as_os_str()]);
    assert!(ok && text.contains("VALID"), "{text}");
    let (ok, text) = run(&[
        "checksum".as_ref(),
        "-t".as_ref(),
        "md5".as_ref(),
        src.as_os_str(),
    ]);
    assert!(ok, "{text}");
    assert!(text.contains(&hd_checksum(&src, "MD5")), "{text}");
    let (ok, text) = run(&[
        "checksum".as_ref(),
        "-t".as_ref(),
        "sha256".as_ref(),
        src.as_os_str(),
    ]);
    assert!(!ok && text.contains("not supported"), "{text}");
    let bz = dir.path().join("c.dmg");
    let (ok, text) = run(&[
        "convert".as_ref(),
        src.as_os_str(),
        bz.as_os_str(),
        "--dmg-format".as_ref(),
        "UDCO".as_ref(),
    ]);
    assert!(ok, "{text}");
    assert!(hdiutil_ok_out(&["verify"], &[&bz]).contains("VALID"));
    let seg = dir.path().join("s.dmg");
    let (ok, text) = run(&[
        "segment".as_ref(),
        bz.as_os_str(),
        seg.as_os_str(),
        "--segment-size".as_ref(),
        "1m".as_ref(),
    ]);
    assert!(ok, "{text}");
    assert!(hdiutil_ok_out(&["verify"], &[&seg]).contains("VALID"));
    let joined = dir.path().join("j.dmg");
    let (ok, text) = run(&["join".as_ref(), seg.as_os_str(), joined.as_os_str()]);
    assert!(ok, "{text}");
    assert!(logical(&joined) == logical(&src));
    let size = std::fs::metadata(&src)
        .ok()
        .map(|_| logical(&src).len() as u64)
        .unwrap();
    let (ok, text) = run(&[
        "resize".as_ref(),
        joined.as_os_str(),
        format!("{}", size + (1 << 20)).as_ref(),
    ]);
    assert!(ok && text.contains("container"), "{text}");
    let xml = dir.path().join("sla.xml");
    std::fs::write(&xml, sla().to_xml()).unwrap();
    let (ok, text) = run(&[
        "udif-rez".as_ref(),
        joined.as_os_str(),
        "--xml".as_ref(),
        xml.as_os_str(),
    ]);
    assert!(ok, "{text}");
    let (ok, text) = run(&[
        "udif-derez".as_ref(),
        joined.as_os_str(),
        "--kind".as_ref(),
        "TEXT".as_ref(),
    ]);
    assert!(
        ok && text.contains("<key>TEXT</key>") && !text.contains("<key>blkx</key>"),
        "{text}"
    );
    assert!(hdiutil_ok_out(&["verify"], &[&joined]).contains("VALID"));
}
