//! Round-trip tests for the UDF writer and reader.

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use super::layout::{BlockRange, DataExtent, FileData, UdfImage, UdfPlacement, UdfTree};
use super::*;
use crate::block::{BlockDevice, MemoryBackend};
use crate::fs::{DeviceKind, Filesystem};

fn meta(mode: u16) -> FileMeta {
    FileMeta {
        mode,
        uid: 1000,
        gid: 100,
        mtime: 1_700_000_000,
        atime: 1_700_000_100,
        ctime: 1_700_000_200,
    }
}

fn body(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

fn add(fs: &mut Udf, dev: &mut dyn BlockDevice, path: &str, data: &[u8], mode: u16) {
    fs.create_file(
        dev,
        Path::new(path),
        FileSource::Reader {
            reader: Box::new(std::io::Cursor::new(data.to_vec())),
            len: data.len() as u64,
        },
        meta(mode),
    )
    .unwrap();
}

fn read_all(fs: &mut Udf, dev: &mut dyn BlockDevice, path: &str) -> Vec<u8> {
    let mut v = Vec::new();
    fs.read_file(dev, Path::new(path))
        .unwrap()
        .read_to_end(&mut v)
        .unwrap();
    v
}

/// Build a representative tree, flush, reopen, and check everything.
fn round_trip(opts: FormatOpts) {
    let mut dev = MemoryBackend::new(32 << 20);
    let mut fs = Udf::format(&mut dev, &opts).unwrap();
    let big = body(300_000, 7);
    fs.create_dir(&mut dev, Path::new("/dir"), meta(0o750))
        .unwrap();
    add(&mut fs, &mut dev, "/dir/small.txt", b"hello udf\n", 0o640);
    add(&mut fs, &mut dev, "/dir/big.bin", &big, 0o644);
    add(&mut fs, &mut dev, "/empty", b"", 0o600);
    add(&mut fs, &mut dev, "/café.txt", b"latin1", 0o644);
    add(&mut fs, &mut dev, "/日本語のファイル.txt", b"cjk", 0o644);
    add(&mut fs, &mut dev, "/emoji 🎉", b"astral", 0o644);
    add(&mut fs, &mut dev, "/suid", b"x", 0o4755);
    fs.create_symlink(
        &mut dev,
        Path::new("/dir/rel"),
        Path::new("../café.txt"),
        meta(0o777),
    )
    .unwrap();
    fs.create_symlink(
        &mut dev,
        Path::new("/abs"),
        Path::new("/dir/small.txt"),
        meta(0o777),
    )
    .unwrap();
    fs.hardlink(&mut dev, Path::new("/dir/small.txt"), Path::new("/hard"))
        .unwrap();
    fs.create_device(
        &mut dev,
        Path::new("/tty"),
        DeviceKind::Char,
        4,
        64,
        meta(0o620),
    )
    .unwrap();
    fs.create_device(
        &mut dev,
        Path::new("/sda"),
        DeviceKind::Block,
        8,
        0,
        meta(0o660),
    )
    .unwrap();
    fs.create_device(
        &mut dev,
        Path::new("/fifo"),
        DeviceKind::Fifo,
        0,
        0,
        meta(0o644),
    )
    .unwrap();
    // Deep tree.
    let mut deep = String::new();
    for i in 0..40 {
        deep.push_str(&format!("/d{i}"));
    }
    fs.create_dir(&mut dev, Path::new(&deep), meta(0o755))
        .unwrap();
    add(&mut fs, &mut dev, &format!("{deep}/leaf"), b"deep", 0o644);
    // A directory spanning several blocks.
    for i in 0..300 {
        add(
            &mut fs,
            &mut dev,
            &format!("/many/file-with-a-longish-name-{i:04}"),
            &[i as u8],
            0o644,
        );
    }
    fs.flush(&mut dev).unwrap();
    let len = fs.image_len().unwrap();
    assert!(len < 32 << 20);

    let mut fs = Udf::open(&mut dev).unwrap();
    let info = fs.info().unwrap().clone();
    assert_eq!(info.udf_revision, opts.revision.bcd(), "{info:?}");
    assert_eq!(info.block_size, opts.block_size);
    assert_eq!(info.logical_volume_id, opts.logical_volume_id());
    assert!(info.warnings.is_empty(), "{:?}", info.warnings);

    let mut names: Vec<String> = fs
        .list(&mut dev, Path::new("/"))
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    names.sort();
    for want in [
        "café.txt",
        "日本語のファイル.txt",
        "emoji 🎉",
        "dir",
        "empty",
        "hard",
        "tty",
    ] {
        assert!(
            names.iter().any(|n| n == want),
            "{want} missing from {names:?}"
        );
    }
    assert_eq!(
        read_all(&mut fs, &mut dev, "/dir/small.txt"),
        b"hello udf\n"
    );
    assert_eq!(read_all(&mut fs, &mut dev, "/hard"), b"hello udf\n");
    assert_eq!(read_all(&mut fs, &mut dev, "/dir/big.bin"), big);
    assert_eq!(read_all(&mut fs, &mut dev, "/empty"), b"");
    assert_eq!(read_all(&mut fs, &mut dev, "/日本語のファイル.txt"), b"cjk");
    assert_eq!(read_all(&mut fs, &mut dev, "/emoji 🎉"), b"astral");
    assert_eq!(
        read_all(&mut fs, &mut dev, &format!("{deep}/leaf")),
        b"deep"
    );
    assert_eq!(fs.list(&mut dev, Path::new("/many")).unwrap().len(), 300);
    assert_eq!(
        read_all(&mut fs, &mut dev, "/many/file-with-a-longish-name-0123"),
        [123u8]
    );

    let a = fs.getattr(&mut dev, Path::new("/dir/small.txt")).unwrap();
    assert_eq!(a.mode, 0o640);
    assert_eq!((a.uid, a.gid), (1000, 100));
    assert_eq!(a.mtime, 1_700_000_000);
    assert_eq!(a.atime, 1_700_000_100);
    assert_eq!(a.nlink, 2);
    let h = fs.getattr(&mut dev, Path::new("/hard")).unwrap();
    assert_eq!(h.inode, a.inode);
    assert_eq!(
        fs.getattr(&mut dev, Path::new("/suid")).unwrap().mode,
        0o4755
    );
    let d = fs.getattr(&mut dev, Path::new("/dir")).unwrap();
    assert_eq!(d.kind, EntryKind::Dir);
    assert_eq!(d.mode, 0o750);
    let t = fs.getattr(&mut dev, Path::new("/tty")).unwrap();
    assert_eq!(t.kind, EntryKind::Char);
    assert_eq!(crate::fs::devnum::decode_devnum(t.rdev), (4, 64));
    assert_eq!(
        fs.getattr(&mut dev, Path::new("/sda")).unwrap().kind,
        EntryKind::Block
    );
    assert_eq!(
        fs.getattr(&mut dev, Path::new("/fifo")).unwrap().kind,
        EntryKind::Fifo
    );
    assert_eq!(
        fs.read_symlink(&mut dev, Path::new("/dir/rel")).unwrap(),
        Path::new("../café.txt")
    );
    assert_eq!(
        fs.read_symlink(&mut dev, Path::new("/abs")).unwrap(),
        Path::new("/dir/small.txt")
    );
    // Random access.
    let mut h = fs
        .open_file_ro(&mut dev, Path::new("/dir/big.bin"))
        .unwrap();
    h.seek(SeekFrom::Start(200_001)).unwrap();
    let mut b = [0u8; 100];
    h.read_exact(&mut b).unwrap();
    assert_eq!(&b[..], &big[200_001..200_101]);
}

#[test]
fn round_trip_every_revision() {
    for &rev in UdfRevision::WRITABLE {
        let opts = FormatOpts {
            revision: rev,
            volume_id: "Test Vol".into(),
            ..FormatOpts::default()
        };
        round_trip(opts);
    }
}

#[test]
fn round_trip_block_sizes_and_options() {
    for bs in [512u32, 1024, 4096] {
        round_trip(FormatOpts {
            block_size: bs,
            ..FormatOpts::default()
        });
    }
    round_trip(FormatOpts {
        access: AccessType::Overwritable,
        inline_dirs: Some(false),
        revision: UdfRevision::V1_02,
        ..FormatOpts::default()
    });
    round_trip(FormatOpts {
        extended_entries: Some(false),
        revision: UdfRevision::V2_01,
        logical_volume_id: Some("ラベル".into()),
        ..FormatOpts::default()
    });
}

#[test]
fn fill_device_overwritable() {
    let mut dev = MemoryBackend::new(8 << 20);
    let opts = FormatOpts {
        fill_device: true,
        access: AccessType::Overwritable,
        ..FormatOpts::default()
    };
    let mut fs = Udf::format(&mut dev, &opts).unwrap();
    add(&mut fs, &mut dev, "/a", b"abc", 0o644);
    fs.flush(&mut dev).unwrap();
    assert_eq!(fs.image_len(), Some(8 << 20));
    let fs = Udf::open(&mut dev).unwrap();
    let p = &fs.info().unwrap().partitions[0];
    assert_eq!(p.access_type, 4);
    assert_eq!(p.start + p.length, (8 << 20) / 2048 - 1);
}

#[test]
fn sparse_large_file() {
    // 5 GiB of zeros with a little data at the end: the zeros become
    // holes, so this runs on a small in-memory device.
    let mut dev = MemoryBackend::new(8 << 20);
    let mut fs = Udf::format(&mut dev, &FormatOpts::default()).unwrap();
    let size = 5u64 << 30;
    let tail = b"tail!";
    let reader = std::io::Read::chain(std::io::repeat(0).take(size - 5), &tail[..]);
    let mut reader = reader;
    fs.create_file_streaming(&mut dev, Path::new("/huge"), &mut reader, size, meta(0o644))
        .unwrap();
    fs.flush(&mut dev).unwrap();
    let mut fs = Udf::open(&mut dev).unwrap();
    let a = fs.getattr(&mut dev, Path::new("/huge")).unwrap();
    assert_eq!(a.size, size);
    let mut h = fs.open_file_ro(&mut dev, Path::new("/huge")).unwrap();
    h.seek(SeekFrom::Start(size - 10)).unwrap();
    let mut b = Vec::new();
    h.read_to_end(&mut b).unwrap();
    assert_eq!(b, b"\0\0\0\0\0tail!");
    h.seek(SeekFrom::Start(3 << 30)).unwrap();
    let mut z = [1u8; 64];
    h.read_exact(&mut z).unwrap();
    assert!(z.iter().all(|&x| x == 0));
}

#[test]
fn planner_api_shares_payload_and_chains_aeds() {
    // Payload "placed by someone else" at blocks 300..; a fragmented file
    // with 1500 one-block extents forces Allocation Extent Descriptors.
    let bs = 2048u64;
    let mut dev = MemoryBackend::new(16 << 20);
    let a = body(5000, 1);
    dev.write_at(300 * bs, &a).unwrap();
    let mut frag = Vec::new();
    let mut extents = Vec::new();
    for i in 0..1500u64 {
        let blk = 400 + 2 * i;
        let chunk = body(2048, i as u8);
        dev.write_at(blk * bs, &chunk).unwrap();
        frag.extend_from_slice(&chunk);
        extents.push(DataExtent::recorded(blk, 2048));
    }
    for &rev in UdfRevision::WRITABLE {
        let mut tree = UdfTree::new();
        tree.add_file(
            "/a.bin",
            FileData::contiguous(300, a.len() as u64),
            meta(0o644),
        )
        .unwrap();
        tree.add_file(
            "/frag",
            FileData::from_extents(extents.clone()),
            meta(0o644),
        )
        .unwrap();
        tree.add_hardlink("/sub/a-again", "/a.bin").unwrap();
        let opts = FormatOpts {
            revision: rev,
            ..FormatOpts::default()
        };
        let part = BlockRange::new(257, 7000);
        let need = UdfImage::requirements(&tree, &opts, part.len).unwrap();
        let mut placement = UdfPlacement::new(2048, 7258, part);
        placement.free = vec![BlockRange::new(4000, need.metadata_blocks + 8)];
        let image = UdfImage::build(&tree, &opts, &placement).unwrap();
        for r in image.used_ranges() {
            // Nothing UDF writes may land on the payload.
            assert!(r.start + r.len <= 300 || r.start >= 3400, "{r:?}");
        }
        image.write(&mut dev).unwrap();
        let mut fs = Udf::open(&mut dev).unwrap();
        assert_eq!(read_all(&mut fs, &mut dev, "/a.bin"), a);
        assert_eq!(read_all(&mut fs, &mut dev, "/sub/a-again"), a);
        assert_eq!(read_all(&mut fs, &mut dev, "/frag"), frag, "{rev}");
    }
}

#[test]
fn placement_is_validated() {
    let tree = UdfTree::new();
    let opts = FormatOpts::default();
    let mut p = UdfPlacement::new(2048, 1000, BlockRange::new(200, 700));
    p.free = vec![BlockRange::new(300, 50)];
    assert!(
        UdfImage::build(&tree, &opts, &p).is_err(),
        "partition overlaps the anchor"
    );
    let mut p = UdfPlacement::new(2048, 1000, BlockRange::new(257, 700));
    p.free = vec![BlockRange::new(100, 50)];
    assert!(
        UdfImage::build(&tree, &opts, &p).is_err(),
        "free range outside the partition"
    );
    let mut t = UdfTree::new();
    t.add_file("/x", FileData::contiguous(10, 5), FileMeta::default())
        .unwrap();
    let mut p = UdfPlacement::new(2048, 1000, BlockRange::new(257, 700));
    p.free = vec![BlockRange::new(300, 50)];
    assert!(
        UdfImage::build(&t, &opts, &p).is_err(),
        "payload outside the partition"
    );
    let mut t2 = UdfTree::new();
    t2.add_file("/x", FileData::contiguous(320, 5000), FileMeta::default())
        .unwrap();
    let mut p = UdfPlacement::new(2048, 1000, BlockRange::new(257, 700));
    p.free = vec![BlockRange::new(300, 50)];
    assert!(
        UdfImage::build(&t2, &opts, &p).is_err(),
        "payload inside the metadata free range"
    );
    let mut p = UdfPlacement::new(2048, 1000, BlockRange::new(257, 700));
    p.free = vec![BlockRange::new(300, 1)];
    assert!(
        UdfImage::build(&t, &opts, &p).is_err(),
        "not enough metadata space"
    );
}

#[test]
fn limits_are_reported() {
    let mut dev = MemoryBackend::new(4 << 20);
    let mut fs = Udf::format(&mut dev, &FormatOpts::default()).unwrap();
    add(
        &mut fs,
        &mut dev,
        &format!("/{}", "x".repeat(255)),
        b"",
        0o644,
    );
    assert!(
        fs.flush(&mut dev).is_err(),
        "255 Latin-1 chars + compression id > 255"
    );
    let mut fs = Udf::format(&mut dev, &FormatOpts::default()).unwrap();
    add(
        &mut fs,
        &mut dev,
        &format!("/{}", "x".repeat(254)),
        b"",
        0o644,
    );
    fs.flush(&mut dev).unwrap();
    let mut fs = Udf::format(&mut dev, &FormatOpts::default()).unwrap();
    add(
        &mut fs,
        &mut dev,
        &format!("/{}", "日".repeat(128)),
        b"",
        0o644,
    );
    assert!(fs.flush(&mut dev).is_err());
    assert!(
        Udf::format(
            &mut dev,
            &FormatOpts {
                volume_id: "x".repeat(31),
                ..FormatOpts::default()
            }
        )
        .is_err()
    );
    let mut fs = Udf::format(&mut dev, &FormatOpts::default()).unwrap();
    add(&mut fs, &mut dev, "/f", b"1", 0o644);
    assert!(matches!(
        fs.set_xattr(&mut dev, Path::new("/f"), "user.k", b"v"),
        Err(crate::Error::Unsupported(_))
    ));
    assert_eq!(fs.unsupported().len(), 1);
    assert_eq!(fs.unsupported()[0].item, "xattr user.k");
}

#[test]
fn damaged_images_error_cleanly() {
    let mut dev = MemoryBackend::new(4 << 20);
    let mut fs = Udf::format(&mut dev, &FormatOpts::default()).unwrap();
    add(&mut fs, &mut dev, "/f", b"data", 0o644);
    fs.create_dir(&mut dev, Path::new("/d"), meta(0o755))
        .unwrap();
    fs.flush(&mut dev).unwrap();
    let len = fs.image_len().unwrap();
    let mut img = vec![0u8; len as usize];
    dev.read_at(0, &mut img).unwrap();

    // A damaged first anchor: the one at N-1 takes over.
    let mut d = MemoryBackend::new(len);
    let mut i2 = img.clone();
    i2[256 * 2048 + 20] ^= 0xFF;
    d.write_at(0, &i2).unwrap();
    let mut fs = Udf::open(&mut d).unwrap();
    assert_eq!(read_all(&mut fs, &mut d, "/f"), b"data");

    // Flip every byte of the metadata area one at a time (sampled): never a
    // panic, and either a clean error or a usable volume.
    let meta_start = 257 * 2048;
    let volume_structures = (16 * 2048..67 * 2048).step_by(29);
    for off in (meta_start..img.len()).step_by(97).chain(volume_structures) {
        let mut i3 = img.clone();
        i3[off] ^= 0x5A;
        let mut d = MemoryBackend::new(len);
        d.write_at(0, &i3).unwrap();
        if let Ok(mut fs) = Udf::open(&mut d) {
            if let Ok(list) = fs.list(&mut d, Path::new("/")) {
                for e in list {
                    let _ = fs.getattr(&mut d, Path::new(&format!("/{}", e.name)));
                }
            }
            let _ = fs.read_file(&mut d, Path::new("/f")).map(|mut r| {
                let mut v = Vec::new();
                let _ = r.read_to_end(&mut v);
            });
        }
    }
}

#[test]
fn writer_mode_reads_back() {
    let mut dev = MemoryBackend::new(4 << 20);
    let mut fs = Udf::format(&mut dev, &FormatOpts::default()).unwrap();
    add(&mut fs, &mut dev, "/x/y", b"buffered", 0o644);
    let l = fs.list(&mut dev, Path::new("/x")).unwrap();
    assert_eq!(l.len(), 1);
    assert_eq!(read_all(&mut fs, &mut dev, "/x/y"), b"buffered");
    fs.remove(&mut dev, Path::new("/x")).unwrap();
    assert!(fs.list(&mut dev, Path::new("/")).unwrap().is_empty());
}

#[test]
fn flush_between_edits() {
    for fill in [false, true] {
        let mut dev = MemoryBackend::new(8 << 20);
        let opts = FormatOpts {
            fill_device: fill,
            ..FormatOpts::default()
        };
        let mut fs = Udf::format(&mut dev, &opts).unwrap();
        add(&mut fs, &mut dev, "/one", b"first", 0o644);
        fs.flush(&mut dev).unwrap();
        let first_len = fs.image_len().unwrap();
        fs.flush(&mut dev).unwrap();
        assert_eq!(
            fs.image_len().unwrap(),
            first_len,
            "an idle flush changes nothing"
        );
        add(&mut fs, &mut dev, "/two", b"second", 0o644);
        fs.create_dir(&mut dev, Path::new("/d"), meta(0o755))
            .unwrap();
        fs.flush(&mut dev).unwrap();
        let mut fs = Udf::open(&mut dev).unwrap();
        assert_eq!(read_all(&mut fs, &mut dev, "/one"), b"first");
        assert_eq!(read_all(&mut fs, &mut dev, "/two"), b"second");
        assert!(fs.info().unwrap().warnings.is_empty());
    }
}

#[test]
fn probe_detects_udf() {
    let mut dev = MemoryBackend::new(4 << 20);
    assert!(!probe(&mut dev));
    let mut fs = Udf::format(&mut dev, &FormatOpts::default()).unwrap();
    fs.flush(&mut dev).unwrap();
    assert!(probe(&mut dev));
}

/// Build a 1.50 image covering the whole (oversized) device, so the end of
/// the partition is free for the synthetic structures below. Returns the
/// device and `(fsd lbn, partition start, partition length)`.
fn spare_room_image() -> (MemoryBackend, u32, u64, u64) {
    let mut dev = MemoryBackend::new(8 << 20);
    let opts = FormatOpts {
        revision: UdfRevision::V1_50,
        fill_device: true,
        ..FormatOpts::default()
    };
    let mut fs = Udf::format(&mut dev, &opts).unwrap();
    add(&mut fs, &mut dev, "/file.txt", b"through the map", 0o644);
    fs.flush(&mut dev).unwrap();
    let mut lvd = vec![0u8; 2048];
    dev.read_at(35 * 2048, &mut lvd).unwrap();
    let fsd = ecma::LongAd::parse(&lvd[248..264]).loc.lbn;
    let mut pd = vec![0u8; 2048];
    dev.read_at(34 * 2048, &mut pd).unwrap();
    let start = u64::from(ecma::u32le(&pd, 188));
    let len = u64::from(ecma::u32le(&pd, 192));
    (dev, fsd, start, len)
}

fn rewrite_lvd(dev: &mut MemoryBackend, f: impl FnOnce(&mut Vec<u8>)) {
    let mut lvd = vec![0u8; 2048];
    dev.read_at(35 * 2048, &mut lvd).unwrap();
    f(&mut lvd);
    let len = 440 + ecma::u32le(&lvd, 264) as usize;
    ecma::finish_tag(&mut lvd[..len], ecma::TAG_LVD, 2, 1, 35, len - 16);
    dev.write_at(35 * 2048, &lvd).unwrap();
}

#[test]
fn reads_through_a_vat() {
    for vat20 in [true, false] {
        let (mut dev, fsd, start, plen) = spare_room_image();
        // Virtual block 0 → the FSD; the rest unmapped.
        let mut entries: Vec<u32> = vec![fsd];
        entries.extend([u32::MAX; 7]);
        let mut body = Vec::new();
        if vat20 {
            let mut hdr = vec![0u8; 152];
            ecma::put_u16(&mut hdr, 0, 152);
            hdr[4..132].copy_from_slice(&ecma::encode_dstring("VAT LABEL", 128, "id").unwrap());
            ecma::put_u32(&mut hdr, 136, 1);
            ecma::put_u32(&mut hdr, 140, 1);
            ecma::put_u16(&mut hdr, 144, 0x0200);
            body.extend_from_slice(&hdr);
        }
        for e in &entries {
            body.extend_from_slice(&e.to_le_bytes());
        }
        if !vat20 {
            body.extend_from_slice(&ecma::entity_id("*UDF Virtual Alloc Tbl", [0; 8]));
            body.extend_from_slice(&u32::MAX.to_le_bytes());
        }
        // The VAT File Entry, data embedded, in the last partition block.
        let vat_lbn = (plen - 1) as u32;
        let mut fe = vec![0u8; 176 + body.len()];
        ecma::put_u16(&mut fe, 20, 4);
        ecma::put_u16(&mut fe, 24, 1);
        fe[27] = if vat20 { read::FT_VAT20 } else { 0 };
        ecma::put_u16(&mut fe, 34, ecma::ICB_AD_INLINE);
        ecma::put_u64(&mut fe, 56, body.len() as u64);
        ecma::put_u32(&mut fe, 172, body.len() as u32);
        fe[176..].copy_from_slice(&body);
        let l = fe.len();
        ecma::finish_tag(&mut fe, ecma::TAG_FE, 2, 1, vat_lbn, l - 16);
        dev.write_at((start + u64::from(vat_lbn)) * 2048, &fe)
            .unwrap();
        rewrite_lvd(&mut dev, |lvd| {
            // FSD through partition reference 1, the virtual partition.
            ecma::put_u32(lvd, 252, 0);
            ecma::put_u16(lvd, 256, 1);
            let mut m = [0u8; 64];
            m[0] = 2;
            m[1] = 64;
            m[4..36].copy_from_slice(&ecma::entity_id(
                "*UDF Virtual Partition",
                ecma::udf_suffix(0x150),
            ));
            ecma::put_u16(&mut m, 36, 1);
            lvd[446..510].copy_from_slice(&m);
            ecma::put_u32(lvd, 264, 70);
            ecma::put_u32(lvd, 268, 2);
        });
        let mut fs = Udf::open(&mut dev).unwrap();
        let info = fs.info().unwrap().clone();
        assert_eq!(info.partitions[1].kind, PartitionMapKind::Virtual);
        assert_eq!(info.partitions[1].length, 8);
        if vat20 {
            assert_eq!(info.logical_volume_id, "VAT LABEL");
        }
        assert_eq!(read_all(&mut fs, &mut dev, "/file.txt"), b"through the map");
    }
}

#[test]
fn reads_through_a_sparing_table() {
    let (mut dev, fsd, start, plen) = spare_room_image();
    let packet = 32u32;
    let p = fsd - fsd % packet;
    // Move that packet to the end of the partition, zero the original,
    // and record the move in a sparing table.
    let spare_abs = start + plen - 2 * u64::from(packet);
    let table_abs = spare_abs - 1;
    let mut buf = vec![0u8; packet as usize * 2048];
    dev.read_at((start + u64::from(p)) * 2048, &mut buf)
        .unwrap();
    dev.write_at(spare_abs * 2048, &buf).unwrap();
    dev.write_at((start + u64::from(p)) * 2048, &vec![0u8; buf.len()])
        .unwrap();
    let mut st = vec![0u8; 64];
    st[16..48].copy_from_slice(&ecma::entity_id(
        "*UDF Sparing Table",
        ecma::udf_suffix(0x150),
    ));
    ecma::put_u16(&mut st, 48, 1);
    ecma::put_u32(&mut st, 52, 1);
    ecma::put_u32(&mut st, 56, p);
    ecma::put_u32(&mut st, 60, spare_abs as u32);
    ecma::finish_tag(&mut st, 0, 2, 1, table_abs as u32, 48);
    dev.write_at(table_abs * 2048, &st).unwrap();
    rewrite_lvd(&mut dev, |lvd| {
        let mut m = [0u8; 64];
        m[0] = 2;
        m[1] = 64;
        m[4..36].copy_from_slice(&ecma::entity_id(
            "*UDF Sparable Partition",
            ecma::udf_suffix(0x150),
        ));
        ecma::put_u16(&mut m, 36, 1);
        ecma::put_u16(&mut m, 38, 0);
        ecma::put_u16(&mut m, 40, packet as u16);
        m[42] = 1;
        ecma::put_u32(&mut m, 44, 64);
        ecma::put_u32(&mut m, 48, table_abs as u32);
        lvd[440..504].copy_from_slice(&m);
        ecma::put_u32(lvd, 264, 64);
        ecma::put_u32(lvd, 268, 1);
    });
    let mut fs = Udf::open(&mut dev).unwrap();
    assert_eq!(
        fs.info().unwrap().partitions[0].kind,
        PartitionMapKind::Sparable
    );
    assert_eq!(read_all(&mut fs, &mut dev, "/file.txt"), b"through the map");
}
