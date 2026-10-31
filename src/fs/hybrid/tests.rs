//! In-library round trips: every view read back with fstool's own
//! readers, payloads shared, layouts validated.

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Arc;

use super::*;
use crate::block::{BlockDevice, MemoryBackend, SlicedBackend};
use crate::fs::hfs_plus::HfsPlus;
use crate::fs::iso9660::{Iso9660, ReadView};
use crate::fs::{DeviceKind, EntryKind, Filesystem};

fn bytes(b: &[u8]) -> Payload {
    Payload::Bytes(Arc::from(b))
}

fn sample_tree() -> SourceTree {
    let mut t = SourceTree::new();
    let m = EntryMeta::with_mode(0o644).at(1_700_000_000);
    t.add_file("/hello.txt", bytes(b"hello world\n"), 12, m)
        .unwrap();
    let big: Vec<u8> = (0..300_000u32).map(|i| (i * 7 % 253) as u8).collect();
    t.add_file("/sub/rand.bin", bytes(&big), big.len() as u64, m)
        .unwrap();
    t.add_file(
        "/sub/naïve file name that is rather long.txt",
        bytes("é\n".as_bytes()),
        3,
        m,
    )
    .unwrap();
    t.add_file("/empty", Payload::Zero, 0, m).unwrap();
    t.add_symlink("/link", "hello.txt", EntryMeta::with_mode(0o777))
        .unwrap();
    t.add_hardlink("/sub/hard.txt", "/hello.txt").unwrap();
    t.add_device("/dev/null", DeviceKind::Char, 3, 2, m)
        .unwrap();
    t.add_dir("/a/b/c/d/e/f/g/h/i", EntryMeta::with_mode(0o755))
        .unwrap();
    t
}

fn read_all(fs: &mut dyn Filesystem, dev: &mut dyn BlockDevice, p: &str) -> Vec<u8> {
    let mut v = Vec::new();
    fs.read_file(dev, Path::new(p))
        .unwrap_or_else(|e| panic!("read {p}: {e}"))
        .read_to_end(&mut v)
        .unwrap();
    v
}

fn hfs_clean(dev: &mut dyn BlockDevice) {
    let r = crate::fs::hfs_plus::verify::verify(dev, &crate::fs::verify::VerifyOpts::default())
        .unwrap();
    assert!(
        r.error_count == 0 && r.warning_count == 0,
        "{:?}",
        r.diagnostics
    );
}

fn hfs_slice<'a>(
    dev: &'a mut MemoryBackend,
    plan: &HybridPlan,
) -> SlicedBackend<'a, MemoryBackend> {
    let w = plan.wrap().unwrap();
    SlicedBackend::new(
        dev,
        u64::from(w.start) * 2048,
        u64::from(w.end - w.start) * 2048,
    )
    .unwrap()
}

#[test]
fn every_view_reads_the_same_tree_and_payload() {
    let tree = sample_tree();
    let mut opts = HybridOptions::new("Hybrid Test");
    opts.create_date = 1_700_000_000;
    let plan = HybridPlan::new(tree, &opts).unwrap();
    let mut dev = MemoryBackend::new(plan.total_bytes());
    plan.write(&mut dev).unwrap();
    plan.verify(&mut dev).unwrap();

    // Payload placed once: the ISO record and the HFS+ fork share it.
    let rand = plan
        .files()
        .iter()
        .find(|f| f.path == "/sub/rand.bin")
        .unwrap()
        .clone();
    assert_eq!(rand.zone, PayloadZone::Wrapped);
    assert_eq!(plan.files().len(), 3, "hello+hard share, empty has none");

    let mut iso = Iso9660::open(&mut dev).unwrap();
    iso.set_read_view(ReadView::RockRidge).unwrap();
    assert_eq!(read_all(&mut iso, &mut dev, "/hello.txt"), b"hello world\n");
    assert_eq!(
        read_all(&mut iso, &mut dev, "/sub/hard.txt"),
        b"hello world\n"
    );
    let list = iso.list(&mut dev, Path::new("/sub")).unwrap();
    let r = list.iter().find(|e| e.name == "rand.bin").unwrap();
    assert_eq!(r.inode, rand.extent.lba);
    assert_eq!(
        iso.read_symlink(&mut dev, Path::new("/link")).unwrap(),
        Path::new("hello.txt")
    );
    let a = iso.getattr(&mut dev, Path::new("/dev/null")).unwrap();
    assert_eq!(a.kind, EntryKind::Char);
    iso.set_read_view(ReadView::Joliet).unwrap();
    assert_eq!(
        read_all(
            &mut iso,
            &mut dev,
            "/sub/naïve file name that is rather long.txt"
        ),
        "é\n".as_bytes()
    );
    iso.set_read_view(ReadView::Primary).unwrap();
    let names: Vec<String> = iso
        .list(&mut dev, Path::new("/"))
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert!(names.contains(&"HELLO.TXT".to_string()), "{names:?}");
    assert_eq!(iso.volume_id(), "Hybrid Test");
    assert_eq!(iso.pvd.volume_id, "HYBRID_TEST");

    // The HFS+ view, through the partition map.
    assert!(crate::part::Apm::probe(&mut dev));
    let rand_bytes = {
        let mut iso = Iso9660::open(&mut dev).unwrap();
        read_all(&mut iso, &mut dev, "/sub/rand.bin")
    };
    let mut slice = hfs_slice(&mut dev, &plan);
    let mut hfs = HfsPlus::open(&mut slice).unwrap();
    assert_eq!(hfs.volume_name(), "Hybrid Test");
    assert_eq!(read_all(&mut hfs, &mut slice, "/sub/rand.bin"), rand_bytes);
    assert_eq!(
        read_all(&mut hfs, &mut slice, "/sub/hard.txt"),
        b"hello world\n"
    );
    assert_eq!(
        hfs.read_symlink(&mut slice, Path::new("/link")).unwrap(),
        Path::new("hello.txt")
    );
    let a = hfs.getattr(&mut slice, Path::new("/hello.txt")).unwrap();
    assert_eq!(a.mtime, 1_700_000_000);
    assert_eq!(a.mode & 0o7777, 0o644);
    hfs_clean(&mut slice);

    // Joliet cannot hold the symlink or the device; reported.
    let omitted: Vec<&ReportItem> = plan
        .report()
        .for_view(ViewId::Joliet)
        .filter(|i| matches!(i.kind, ReportKind::Omitted(_)))
        .collect();
    assert_eq!(omitted.len(), 2, "{omitted:?}");
    assert!(
        plan.report()
            .for_view(ViewId::Iso9660)
            .any(|i| matches!(i.kind, ReportKind::DepthExceeded { .. }))
    );
}

#[test]
fn hide_and_only_globs_shape_each_view() {
    let tree = sample_tree();
    let mut opts = HybridOptions::new("Globs");
    opts.hfs.hide.push("*.bin".into());
    opts.joliet.hide.push("/sub".into());
    opts.iso.only.push("hello.txt".into());
    let plan = HybridPlan::new(tree, &opts).unwrap();
    let mut dev = MemoryBackend::new(plan.total_bytes());
    plan.write(&mut dev).unwrap();
    plan.verify(&mut dev).unwrap();

    // rand.bin is hidden from HFS+, so it lives outside the partition.
    let rand = plan
        .files()
        .iter()
        .find(|f| f.path == "/sub/rand.bin")
        .unwrap();
    assert_eq!(rand.zone, PayloadZone::Outside);
    assert!(rand.extent.lba >= plan.wrap().unwrap().end);

    let mut iso = Iso9660::open(&mut dev).unwrap();
    iso.set_read_view(ReadView::RockRidge).unwrap();
    assert!(iso.getattr(&mut dev, Path::new("/hello.txt")).is_ok());
    assert!(iso.getattr(&mut dev, Path::new("/sub/rand.bin")).is_ok());
    iso.set_read_view(ReadView::Joliet).unwrap();
    assert!(iso.getattr(&mut dev, Path::new("/sub")).is_err());
    assert!(iso.getattr(&mut dev, Path::new("/hello.txt")).is_err());

    let mut slice = hfs_slice(&mut dev, &plan);
    let mut hfs = HfsPlus::open(&mut slice).unwrap();
    assert!(hfs.getattr(&mut slice, Path::new("/hello.txt")).is_err());
    assert!(hfs.getattr(&mut slice, Path::new("/sub/rand.bin")).is_err());
    assert!(hfs.getattr(&mut slice, Path::new("/sub/hard.txt")).is_ok());
    hfs_clean(&mut slice);
}

#[test]
fn iso_only_and_hfs_only_images() {
    let mut opts = HybridOptions::new("OneView");
    opts.hfs.enabled = false;
    let plan = HybridPlan::new(sample_tree(), &opts).unwrap();
    assert!(plan.wrap().is_none());
    let mut dev = MemoryBackend::new(plan.total_bytes());
    plan.write(&mut dev).unwrap();
    plan.verify(&mut dev).unwrap();
    assert!(!crate::part::Apm::probe(&mut dev));

    let mut opts = HybridOptions::new("OneView");
    opts.iso.enabled = false;
    opts.joliet.enabled = false;
    let plan = HybridPlan::new(sample_tree(), &opts).unwrap();
    let mut dev = MemoryBackend::new(plan.total_bytes());
    plan.write(&mut dev).unwrap();
    plan.verify(&mut dev).unwrap();

    let mut opts = HybridOptions::new("None");
    opts.iso.enabled = false;
    opts.joliet.enabled = false;
    opts.hfs.enabled = false;
    assert!(matches!(
        HybridPlan::new(sample_tree(), &opts),
        Err(HybridError::NoViews)
    ));
}

#[test]
fn level_one_names_are_reported_without_rock_ridge() {
    let mut opts = HybridOptions::new("L1");
    opts.iso.level = IsoLevel::L1;
    opts.iso.rock_ridge = false;
    let plan = HybridPlan::new(sample_tree(), &opts).unwrap();
    let mapped: Vec<&ReportItem> = plan
        .report()
        .for_view(ViewId::Iso9660)
        .filter(|i| matches!(i.kind, ReportKind::NameTruncated { .. }))
        .collect();
    assert!(
        mapped
            .iter()
            .any(|i| i.path == "/sub/naïve file name that is rather long.txt"),
        "{mapped:?}"
    );
    let mut dev = MemoryBackend::new(plan.total_bytes());
    plan.write(&mut dev).unwrap();
    plan.verify(&mut dev).unwrap();
    let mut iso = Iso9660::open(&mut dev).unwrap();
    assert!(!iso.rock_ridge);
    iso.set_read_view(ReadView::Primary).unwrap();
    let names: Vec<String> = iso
        .list(&mut dev, Path::new("/SUB"))
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert!(names.iter().all(|n| n.len() <= 12), "{names:?}");
}

#[test]
fn el_torito_boot_image_may_be_hidden() {
    let mut t = sample_tree();
    let img = vec![0x90u8; 2048 * 3];
    t.add_file(
        "/boot/boot.img",
        bytes(&img),
        img.len() as u64,
        EntryMeta::default(),
    )
    .unwrap();
    let mut opts = HybridOptions::new("Boot");
    opts.iso.boot.push(BootOptions::new("/boot/boot.img"));
    opts.iso.hide.push("/boot".into());
    opts.joliet.hide.push("/boot".into());
    opts.hfs.hide.push("/boot".into());
    let plan = HybridPlan::new(t, &opts).unwrap();
    let mut dev = MemoryBackend::new(plan.total_bytes());
    plan.write(&mut dev).unwrap();
    plan.verify(&mut dev).unwrap();
    let iso = Iso9660::open(&mut dev).unwrap();
    let cat = iso.boot.as_ref().unwrap();
    let mut first = vec![0u8; 2048];
    dev.read_at(u64::from(cat.default_entry.load_rba) * 2048, &mut first)
        .unwrap();
    assert!(first.iter().all(|&b| b == 0x90));
    assert_eq!(cat.default_entry.sector_count, 4);

    let mut opts = HybridOptions::new("Boot");
    opts.iso.boot.push(BootOptions::new("/nope"));
    assert!(matches!(
        HybridPlan::new(sample_tree(), &opts),
        Err(HybridError::UnknownPath { .. })
    ));
}

#[test]
fn hfs_options_bless_and_finder_info() {
    let mut t = sample_tree();
    t.set_xattr(
        "/hello.txt",
        "com.apple.ResourceFork",
        b"resource fork bytes".to_vec(),
    )
    .unwrap();
    t.set_xattr("/hello.txt", "user.note", b"kept on HFS+".to_vec())
        .unwrap();
    let mut opts = HybridOptions::new("Blessed");
    opts.hfs.blessed_folder = Some("/sub".into());
    opts.hfs.open_folder = Some("/sub".into());
    opts.hfs.volume_identifier = Some(0x1122_3344_5566_7788);
    let mut fi = FinderInfo::default();
    fi.set_file_type(*b"TEXT");
    fi.set_creator(*b"ttxt");
    opts.hfs.finder_info.push(("/hello.txt".into(), fi));
    let plan = HybridPlan::new(t, &opts).unwrap();
    assert!(
        plan.report()
            .for_view(ViewId::Joliet)
            .any(|i| matches!(i.kind, ReportKind::MetadataDropped { what: "xattrs" }))
    );
    let mut dev = MemoryBackend::new(plan.total_bytes());
    plan.write(&mut dev).unwrap();
    plan.verify(&mut dev).unwrap();
    let mut slice = hfs_slice(&mut dev, &plan);
    let hfs = HfsPlus::open(&mut slice).unwrap();
    let vfi = hfs.volume_finder_info().unwrap();
    let sub = hfs.entry_info("/sub").unwrap().cnid;
    assert_eq!(vfi.blessed_folder(), sub);
    assert_eq!(vfi.open_folder(), sub);
    assert_eq!(vfi.volume_identifier(), 0x1122_3344_5566_7788);
    assert_eq!(hfs.finder_info("/hello.txt").unwrap().file_type(), *b"TEXT");
    assert_eq!(
        hfs.get_xattr(&mut slice, "/hello.txt", "user.note")
            .unwrap(),
        Some(b"kept on HFS+".to_vec())
    );
    assert_eq!(
        hfs.get_xattr(&mut slice, "/hello.txt", "com.apple.ResourceFork")
            .unwrap(),
        Some(b"resource fork bytes".to_vec())
    );
    hfs_clean(&mut slice);
}

#[test]
fn overlapping_requests_are_refused() {
    let mut a = ViewNeeds {
        vrs_sectors: 4,
        ..ViewNeeds::default()
    };
    a.fixed.push(FixedRequest::new("anchor", 18, 1));
    let mut payload = PayloadLayout::default();
    let err = plan::assign_for_test(&[ViewId::Iso9660], &[a], None, &mut payload).unwrap_err();
    assert!(matches!(err, HybridError::Overlap { .. }), "{err}");

    let mut a = ViewNeeds::default();
    a.system_area.push(ByteRequest::new("map", 0, 1536));
    let mut b = ViewNeeds::default();
    b.system_area.push(ByteRequest::new("mbr", 0, 512));
    let err = plan::assign_for_test(
        &[ViewId::HfsPlus, ViewId::Udf],
        &[a, b],
        None,
        &mut PayloadLayout::default(),
    )
    .unwrap_err();
    assert!(matches!(err, HybridError::Overlap { .. }), "{err}");

    let mut a = ViewNeeds::default();
    a.system_area
        .push(ByteRequest::new("too big", 30_000, 4000));
    let err = plan::assign_for_test(&[ViewId::Udf], &[a], None, &mut PayloadLayout::default())
        .unwrap_err();
    assert!(matches!(err, HybridError::OutOfBounds { .. }), "{err}");

    // A UDF-like set of needs lands where it asked, clear of the rest.
    let mut iso = ViewNeeds {
        vrs_sectors: 3,
        ..ViewNeeds::default()
    };
    iso.head.push(SectorRequest::new("iso", 230));
    let mut udf = ViewNeeds {
        vrs_sectors: 3,
        ..ViewNeeds::default()
    };
    udf.fixed.push(FixedRequest::new("avdp", 256, 1));
    udf.head.push(SectorRequest::new("vds", 16));
    udf.from_end.push(EndRequest::new("avdp end", 1, 1));
    let (regions, total) = plan::assign_for_test(
        &[ViewId::Iso9660, ViewId::Udf],
        &[iso, udf],
        None,
        &mut PayloadLayout::default(),
    )
    .unwrap();
    let find = |l: &str| regions.iter().find(|r| r.label == l).unwrap().extent;
    assert_eq!(find("avdp").lba, 256);
    assert_eq!(find("avdp end").lba, total - 1);
    assert_eq!(find("iso").lba, 22, "head skips nothing before 256");
    assert!(
        find("vds").lba >= 257,
        "the run that would hit 256 moves past it"
    );
}

/// A sparse device: unwritten (or zeroed) 64 KiB chunks cost nothing,
/// so a file of 4 GiB and more can be planned, written and read back.
struct SparseDev {
    chunks: HashMap<u64, Vec<u8>>,
    size: u64,
    pos: u64,
}

const CHUNK: u64 = 65536;

impl SparseDev {
    fn new(size: u64) -> Self {
        Self {
            chunks: HashMap::new(),
            size,
            pos: 0,
        }
    }
}

impl Read for SparseDev {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = buf.len().min((self.size - self.pos) as usize);
        self.read_at(self.pos, &mut buf[..n])
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Write for SparseDev {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.write_at(self.pos, buf)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        self.pos += buf.len() as u64;
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Seek for SparseDev {
    fn seek(&mut self, p: SeekFrom) -> std::io::Result<u64> {
        self.pos = match p {
            SeekFrom::Start(x) => x,
            SeekFrom::End(x) => (self.size as i64 + x) as u64,
            SeekFrom::Current(x) => (self.pos as i64 + x) as u64,
        };
        Ok(self.pos)
    }
}

impl BlockDevice for SparseDev {
    fn block_size(&self) -> u32 {
        512
    }
    fn total_size(&self) -> u64 {
        self.size
    }
    fn sync(&mut self) -> crate::Result<()> {
        Ok(())
    }
    fn zero_range(&mut self, offset: u64, len: u64) -> crate::Result<()> {
        let mut at = offset;
        let end = offset + len;
        while at < end {
            let c = at / CHUNK;
            let off = (at % CHUNK) as usize;
            let n = ((end - at).min(CHUNK - off as u64)) as usize;
            if off == 0 && n == CHUNK as usize {
                self.chunks.remove(&c);
            } else if let Some(ch) = self.chunks.get_mut(&c) {
                ch[off..off + n].fill(0);
            }
            at += n as u64;
        }
        Ok(())
    }
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> crate::Result<()> {
        if offset + buf.len() as u64 > self.size {
            return Err(crate::Error::OutOfBounds {
                offset,
                len: buf.len() as u64,
                size: self.size,
            });
        }
        let mut done = 0usize;
        while done < buf.len() {
            let at = offset + done as u64;
            let c = at / CHUNK;
            let off = (at % CHUNK) as usize;
            let n = (buf.len() - done).min(CHUNK as usize - off);
            match self.chunks.get(&c) {
                Some(ch) => buf[done..done + n].copy_from_slice(&ch[off..off + n]),
                None => buf[done..done + n].fill(0),
            }
            done += n;
        }
        Ok(())
    }
    fn write_at(&mut self, offset: u64, buf: &[u8]) -> crate::Result<()> {
        if offset + buf.len() as u64 > self.size {
            return Err(crate::Error::OutOfBounds {
                offset,
                len: buf.len() as u64,
                size: self.size,
            });
        }
        let mut done = 0usize;
        while done < buf.len() {
            let at = offset + done as u64;
            let c = at / CHUNK;
            let off = (at % CHUNK) as usize;
            let n = (buf.len() - done).min(CHUNK as usize - off);
            let src = &buf[done..done + n];
            if src.iter().any(|&b| b != 0) || self.chunks.contains_key(&c) {
                let ch = self
                    .chunks
                    .entry(c)
                    .or_insert_with(|| vec![0u8; CHUNK as usize]);
                ch[off..off + n].copy_from_slice(src);
            }
            done += n;
        }
        Ok(())
    }
}

#[test]
fn files_of_four_gib_and_more() {
    const BIG: u64 = (5 << 30) + 12345;
    let mut t = SourceTree::new();
    t.add_file("/big.img", Payload::Zero, BIG, EntryMeta::default())
        .unwrap();
    t.add_file("/after.txt", bytes(b"after\n"), 6, EntryMeta::default())
        .unwrap();

    // Level 2 cannot hold it: omitted from both ISO hierarchies, reported,
    // still on HFS+.
    let opts = HybridOptions::new("Big");
    let plan = HybridPlan::new(t.clone(), &opts).unwrap();
    for v in [ViewId::Iso9660, ViewId::Joliet] {
        assert!(
            plan.report()
                .for_view(v)
                .any(|i| matches!(i.kind, ReportKind::Omitted(OmitReason::TooLarge { .. })))
        );
    }
    let mut dev = SparseDev::new(plan.total_bytes());
    plan.write(&mut dev).unwrap();
    plan.verify(&mut dev).unwrap();

    // Level 3: multi-extent records, read back whole.
    let mut opts = HybridOptions::new("Big");
    opts.iso.level = IsoLevel::L3;
    let plan = HybridPlan::new(t, &opts).unwrap();
    let mut dev = SparseDev::new(plan.total_bytes());
    plan.write(&mut dev).unwrap();
    plan.verify(&mut dev).unwrap();
    let mut iso = Iso9660::open(&mut dev).unwrap();
    for v in [ReadView::RockRidge, ReadView::Joliet, ReadView::Primary] {
        iso.set_read_view(v).unwrap();
        let name = if v == ReadView::Primary {
            "/BIG.IMG"
        } else {
            "/big.img"
        };
        let a = iso.getattr(&mut dev, Path::new(name)).unwrap();
        assert_eq!(a.size, BIG, "{v:?}");
        let after = if v == ReadView::Primary {
            "/AFTER.TXT"
        } else {
            "/after.txt"
        };
        assert_eq!(read_all(&mut iso, &mut dev, after), b"after\n");
    }
}

#[cfg(feature = "udf")]
mod udf {
    use super::*;
    use crate::fs::udf::{Udf, UdfRevision};

    fn udf_opts(rev: UdfRevision) -> HybridOptions {
        let mut opts = HybridOptions::new("Hybrid UDF");
        opts.create_date = 1_700_000_000;
        opts.udf.enabled = true;
        opts.udf.revision = rev;
        opts
    }

    fn build(tree: SourceTree, opts: &HybridOptions) -> (HybridPlan, MemoryBackend) {
        let plan = HybridPlan::new(tree, opts).unwrap();
        let mut dev = MemoryBackend::new(plan.total_bytes());
        plan.write(&mut dev).unwrap();
        plan.verify(&mut dev).unwrap();
        (plan, dev)
    }

    /// First sector of `path` as the ISO 9660 hierarchy records it.
    fn iso_lba(dev: &mut MemoryBackend, path: &str) -> u64 {
        let mut iso = Iso9660::open(dev).unwrap();
        iso.set_read_view(ReadView::Joliet).unwrap();
        let parent = Path::new(path).parent().unwrap();
        let name = Path::new(path).file_name().unwrap().to_str().unwrap();
        let list = iso.list(dev, parent).unwrap();
        u64::from(list.iter().find(|e| e.name == name).unwrap().inode)
    }

    fn rand() -> Vec<u8> {
        (0..300_000u32).map(|i| (i * 7 % 253) as u8).collect()
    }

    #[test]
    fn every_revision_shares_the_payload() {
        for &rev in UdfRevision::WRITABLE {
            let (plan, mut dev) = build(sample_tree(), &udf_opts(rev));
            assert_eq!(
                plan.view_ids(),
                vec![
                    ViewId::Iso9660,
                    ViewId::Joliet,
                    ViewId::HfsPlus,
                    ViewId::Udf
                ]
            );
            let lba = iso_lba(&mut dev, "/sub/rand.bin");
            let mut udf = Udf::open(&mut dev).unwrap();
            assert_eq!(udf.volume_label(), "Hybrid UDF");
            assert_eq!(udf.info().unwrap().udf_revision, rev.bcd(), "{rev}");
            let want = rand();
            assert_eq!(read_all(&mut udf, &mut dev, "/sub/rand.bin"), want);
            assert_eq!(
                read_all(&mut udf, &mut dev, "/sub/hard.txt"),
                b"hello world\n"
            );
            let a = udf.getattr(&mut dev, Path::new("/hello.txt")).unwrap();
            assert_eq!(a.nlink, 2);
            assert_eq!(a.mtime, 1_700_000_000);
            assert_eq!(
                udf.read_symlink(&mut dev, Path::new("/link")).unwrap(),
                Path::new("hello.txt")
            );
            let d = udf.getattr(&mut dev, Path::new("/dev/null")).unwrap();
            assert_eq!(d.kind, EntryKind::Char);
            // The ISO 9660 record names the sectors UDF reads from.
            let mut raw = vec![0u8; 2048];
            dev.read_at(lba * 2048, &mut raw).unwrap();
            assert_eq!(raw, want[..2048]);
            let mut s = hfs_slice(&mut dev, &plan);
            hfs_clean(&mut s);
            let regions = plan.regions();
            assert!(
                regions
                    .iter()
                    .any(|r| r.view == Some(ViewId::Udf) && r.extent.lba == 256)
            );
            assert!(
                regions.iter().any(
                    |r| r.view == Some(ViewId::Udf) && r.extent.lba == plan.total_sectors() - 1
                )
            );
        }
    }

    #[test]
    fn iso_and_udf_bridge_without_hfs() {
        let mut opts = udf_opts(UdfRevision::V1_02);
        opts.hfs.enabled = false;
        let (plan, mut dev) = build(sample_tree(), &opts);
        assert!(plan.wrap().is_none());
        let mut udf = Udf::open(&mut dev).unwrap();
        assert_eq!(read_all(&mut udf, &mut dev, "/sub/rand.bin"), rand());
        let mut iso = Iso9660::open(&mut dev).unwrap();
        assert_eq!(read_all(&mut iso, &mut dev, "/sub/rand.bin"), rand());
    }

    #[test]
    fn udf_only_image() {
        let mut opts = udf_opts(UdfRevision::V2_01);
        opts.iso.enabled = false;
        opts.joliet.enabled = false;
        opts.hfs.enabled = false;
        let (plan, mut dev) = build(sample_tree(), &opts);
        assert_eq!(plan.view_ids(), vec![ViewId::Udf]);
        let mut udf = Udf::open(&mut dev).unwrap();
        assert_eq!(read_all(&mut udf, &mut dev, "/hello.txt"), b"hello world\n");
    }

    #[test]
    fn udf_hide_only_labels_and_report() {
        let mut t = sample_tree();
        let long = format!("{}.txt", "L".repeat(300));
        t.add_file(&format!("/{long}"), bytes(b"x"), 1, EntryMeta::default())
            .unwrap();
        t.set_xattr("/hello.txt", "user.test", b"v".to_vec())
            .unwrap();
        let mut opts = udf_opts(UdfRevision::V1_50);
        opts.udf.hide.push("*.bin".into());
        opts.udf.only.push("empty".into());
        let label = "A label much longer than the thirty-character volume id";
        opts.udf.volume_name = Some(label.into());
        let (plan, mut dev) = build(t, &opts);
        let items: Vec<&ReportItem> = plan.report().for_view(ViewId::Udf).collect();
        assert!(items.iter().any(|i| i.path == "/sub/rand.bin"
            && matches!(i.kind, ReportKind::Omitted(OmitReason::Hidden { .. }))));
        assert!(
            items
                .iter()
                .any(|i| matches!(i.kind, ReportKind::NameTruncated { .. }))
        );
        assert!(items.iter().any(|i| i.path == "/hello.txt"
            && matches!(i.kind, ReportKind::MetadataDropped { what: "xattrs" })));
        // `only` hides the entry from the other views.
        assert!(
            plan.report()
                .items()
                .iter()
                .any(|i| i.view == ViewId::HfsPlus
                    && i.path == "/empty"
                    && matches!(i.kind, ReportKind::Omitted(OmitReason::Hidden { .. })))
        );
        let mut udf = Udf::open(&mut dev).unwrap();
        assert_eq!(udf.volume_label(), label);
        assert_eq!(
            udf.info().unwrap().volume_id,
            "A label much longer than the t"
        );
        assert!(
            udf.list(&mut dev, Path::new("/sub"))
                .unwrap()
                .iter()
                .all(|e| e.name != "rand.bin")
        );
        assert!(udf.getattr(&mut dev, Path::new("/empty")).is_ok());
        let mut iso = Iso9660::open(&mut dev).unwrap();
        assert_eq!(read_all(&mut iso, &mut dev, "/sub/rand.bin"), rand());
    }
}
