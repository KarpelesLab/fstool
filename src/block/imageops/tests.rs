//! Unit tests for the container operations, against images fstool's own
//! writer makes. (Native cross-checks with `hdiutil` are in
//! `tests/dmg_ops_external.rs`.)

use std::io::Cursor;
use std::path::{Path, PathBuf};

use super::*;
use crate::block::dmg::{
    ChecksumStatus, DmgBackend, JoinOptions, KolyTrailer, ResourceEdit, SegmentOptions,
    SignaturePolicy, UdifChecksum, UdifFormat, UdifLayout, UdifMapEntry, UdifResource,
    UdifResources, UdifWriteOptions, edit_udif_resources, inspect_udif, join_udif,
    remove_code_signature, segment_udif, udif_segment_path, verify_udif, write_udif_from_reader,
};

/// A 2 MiB disk: text, noise, zeros, more text.
fn disk() -> Vec<u8> {
    let mut d = Vec::new();
    for i in 0..20_000 {
        d.extend_from_slice(format!("row {i} some compressible words\n").as_bytes());
    }
    d.resize(1 << 20, 0);
    let mut x: u64 = 0x1234_5678_9ABC_DEF1;
    for _ in 0..(512 << 10) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        d.push(x as u8);
    }
    d.resize(2 << 20, 0);
    let n = d.len();
    d[n - 1024..n - 512].fill(0xAB);
    d
}

fn udif(dir: &Path, name: &str, data: &[u8], o: &UdifWriteOptions) -> PathBuf {
    let (cur, _) =
        write_udif_from_reader(data, data.len() as u64, Cursor::new(Vec::new()), o).unwrap();
    let p = dir.join(name);
    std::fs::write(&p, cur.into_inner()).unwrap();
    p
}

fn opts(format: UdifFormat) -> UdifWriteOptions {
    UdifWriteOptions {
        format,
        chunk_sectors: 64,
        segment_id: Some([5; 16]),
        ..Default::default()
    }
}

fn read_all(p: &Path) -> Vec<u8> {
    let mut d = open_source(p, None).unwrap();
    let mut v = vec![0u8; d.total_size() as usize];
    d.read_at(0, &mut v).unwrap();
    v
}

/// A partition-style map over a 2 MiB disk: head, data, free gap, tail.
fn map() -> Vec<UdifMapEntry> {
    let mut v = Vec::new();
    for (i, (name, start, count, free)) in [
        ("Head (Head : 0)", 0u64, 40u64, false),
        ("disk image (Apple_HFS : 1)", 40, 3060, false),
        (" (Apple_Free : 2)", 3100, 940, true),
        ("Tail (Tail : 3)", 4040, 56, false),
    ]
    .into_iter()
    .enumerate()
    {
        let mut e = UdifMapEntry::new(name, start, count);
        e.id = i as i32 - 1;
        e.descriptor = i as i32;
        e.free_space = free;
        v.push(e);
    }
    v
}

#[test]
fn verify_detects_corruption() {
    let dir = tempfile::tempdir().unwrap();
    let data = disk();
    for checksum in [UdifChecksum::Crc32, UdifChecksum::Md5] {
        let mut o = opts(UdifFormat::Udco);
        o.checksum = checksum;
        let p = udif(dir.path(), "v.dmg", &data, &o);
        let r = verify_udif(&p).unwrap();
        assert!(r.is_valid() && r.checked_any(), "{r:?}");
        assert_eq!(r.partitions.len(), 1);
        assert_eq!(r.data_forks.len(), 1);
        // Flip a byte of a raw (incompressible) chunk: the data fork and the
        // partition no longer match; the master (over the stored partition
        // checksums) still does.
        let mut img = std::fs::read(&p).unwrap();
        let t = KolyTrailer::decode(&img[img.len() - 512..]).unwrap();
        let info = inspect_udif(&p).unwrap();
        let raw = info.blkx[0]
            .chunks
            .iter()
            .find(|c| c.kind == crate::block::dmg::ChunkType::Raw)
            .copied()
            .unwrap();
        img[(t.data_fork_offset + raw.compressed_offset_in_fork + 7) as usize] ^= 0x40;
        std::fs::write(&p, &img).unwrap();
        let r = verify_udif(&p).unwrap();
        assert!(!r.is_valid());
        assert_eq!(r.partitions[0].status, ChecksumStatus::Mismatch);
        assert_eq!(r.data_forks[0].status, ChecksumStatus::Mismatch);
        assert_eq!(r.master.status, ChecksumStatus::Valid);
        assert_eq!(r.failures().count(), 2);
    }
    // No checksums at all: valid, nothing checked.
    let mut o = opts(UdifFormat::Udro);
    o.checksum = UdifChecksum::None;
    let p = udif(dir.path(), "n.dmg", &data, &o);
    let r = verify_udif(&p).unwrap();
    assert!(r.is_valid() && !r.checked_any());
}

#[test]
fn checksum_scopes_on_udif() {
    let dir = tempfile::tempdir().unwrap();
    let data = disk();
    let p = udif(dir.path(), "c.dmg", &data, &opts(UdifFormat::Udco));
    let logical =
        image_checksum(&p, ChecksumAlgorithm::Crc32, &ChecksumOptions::default()).unwrap();
    assert_eq!(logical.value, crate::crc::crc32(&data).to_be_bytes());
    let stored = image_checksum(
        &p,
        ChecksumAlgorithm::Crc32,
        &ChecksumOptions {
            scope: ChecksumScope::StoredBytes,
            ..Default::default()
        },
    )
    .unwrap();
    let t = inspect_udif(&p).unwrap();
    assert_eq!(stored.bytes, t.fork_length);
    assert_eq!(stored.value, t.segments[0].data_checksum().value());
}

#[test]
fn segment_and_join_roundtrip_and_validation() {
    let dir = tempfile::tempdir().unwrap();
    let data = disk();
    let src = udif(dir.path(), "src.dmg", &data, &opts(UdifFormat::Udro));
    let src_len = inspect_udif(&src).unwrap().fork_length;
    let first = dir.path().join("set.dmg");
    let so = SegmentOptions {
        segment_size: 300_000,
        segment_id: Some([9; 16]),
        ..Default::default()
    };
    let r = segment_udif(&src, &first, &so).unwrap();
    assert_eq!(r.paths.len() as u64, src_len.div_ceil(300_000));
    assert_eq!(r.paths[1], udif_segment_path(&first, 2));
    let info = inspect_udif(&first).unwrap();
    assert!(info.is_segmented());
    for (i, s) in info.segments.iter().enumerate() {
        assert_eq!(s.trailer.segment_number, i as u32 + 1);
        assert_eq!(s.trailer.segment_count, r.paths.len() as u32);
        assert_eq!(s.trailer.segment_id, [9; 16]);
        assert_eq!(s.fork_start(), i as u64 * 300_000);
    }
    // Reads through the set, and verifies (per-segment fork checksums).
    assert!(read_all(&first) == data);
    assert!(verify_udif(&first).unwrap().is_valid());
    assert_eq!(verify_udif(&first).unwrap().data_forks.len(), r.paths.len());
    // Existing outputs are not replaced without overwrite.
    assert!(segment_udif(&src, &first, &so).is_err());
    // Join back: same data fork, single segment, valid.
    let joined = dir.path().join("joined.dmg");
    join_udif(&first, &joined, &JoinOptions::default()).unwrap();
    let a = std::fs::read(&src).unwrap();
    let b = std::fs::read(&joined).unwrap();
    assert_eq!(a[..src_len as usize], b[..src_len as usize]);
    let jt = KolyTrailer::decode(&b[b.len() - 512..]).unwrap();
    assert_eq!((jt.segment_number, jt.segment_count), (1, 1));
    assert!(verify_udif(&joined).unwrap().is_valid());

    // A corrupted segment: open still works (structure is fine), but the
    // join refuses and verify flags it.
    let p2 = udif_segment_path(&first, 2);
    let mut seg = std::fs::read(&p2).unwrap();
    seg[100] ^= 1;
    std::fs::write(&p2, &seg).unwrap();
    assert!(!verify_udif(&first).unwrap().is_valid());
    let bad = dir.path().join("bad.dmg");
    assert!(join_udif(&first, &bad, &JoinOptions::default()).is_err());
    assert!(!bad.exists(), "a failed join publishes nothing");
    seg[100] ^= 1;
    std::fs::write(&p2, &seg).unwrap();

    // Swapped segments, a foreign segment and a missing one are refused.
    let p3 = udif_segment_path(&first, 3);
    let s3 = std::fs::read(&p3).unwrap();
    std::fs::write(&p2, &s3).unwrap();
    assert!(DmgBackend::open(&first).is_err());
    std::fs::write(&p2, &seg).unwrap();
    let mut foreign = seg.clone();
    let n = foreign.len();
    foreign[n - 512 + 0x40] ^= 0xFF; // segment ID
    std::fs::write(&p2, &foreign).unwrap();
    let e = DmgBackend::open(&first).unwrap_err().to_string();
    assert!(e.contains("another segment set"), "{e}");
    std::fs::remove_file(&p2).unwrap();
    assert!(DmgBackend::open(&first).is_err());
    std::fs::write(&p2, &seg).unwrap();

    // Re-segmenting over the set with overwrite removes its surplus parts.
    let so2 = SegmentOptions {
        segment_count: Some(2),
        overwrite: true,
        ..Default::default()
    };
    let r2 = segment_udif(&joined, &first, &so2).unwrap();
    assert_eq!(r2.paths.len(), 2);
    assert!(!udif_segment_path(&first, 3).exists());
    assert!(read_all(&first) == data);
}

#[test]
fn resources_edit_keeps_blkx_and_checksums() {
    let dir = tempfile::tempdir().unwrap();
    let data = disk();
    let p = udif(dir.path(), "r.dmg", &data, &opts(UdifFormat::Udco));
    let mut add = UdifResources::new();
    let mut t = UdifResource::new("TEXT", 5000, b"terms".to_vec());
    t.name = "English".into();
    add.insert(t);
    add.insert(UdifResource::new(
        "LPic",
        5000,
        vec![0, 0, 0, 1, 0, 0, 0, 0, 0, 0],
    ));
    let e = ResourceEdit {
        add,
        ..Default::default()
    };
    let res = edit_udif_resources(&p, &p, &e).unwrap();
    assert_eq!(res.of_kind("blkx").count(), 1);
    let info = inspect_udif(&p).unwrap();
    assert_eq!(info.resources.get("TEXT", 5000).unwrap().data, b"terms");
    assert!(info.resources.get("plst", 0).is_some());
    assert!(verify_udif(&p).unwrap().is_valid());
    assert!(read_all(&p) == data);
    // blkx is protected.
    let bad = ResourceEdit {
        remove: vec![("blkx".into(), None)],
        ..Default::default()
    };
    assert!(matches!(
        edit_udif_resources(&p, &p, &bad),
        Err(crate::Error::InvalidArgument(_))
    ));
    let mut b = UdifResources::new();
    b.insert(UdifResource::new("blkx", 0, vec![1, 2, 3]));
    let bad = ResourceEdit {
        add: b,
        ..Default::default()
    };
    assert!(edit_udif_resources(&p, &p, &bad).is_err());
    // replace_all keeps blkx, drops the rest.
    let e = ResourceEdit {
        replace_all: true,
        ..Default::default()
    };
    let res = edit_udif_resources(&p, &p, &e).unwrap();
    assert_eq!(res.kinds(), ["blkx"]);
    assert!(read_all(&p) == data);
}

/// Mark `p` code-signed: a fake blob between the plist and the trailer.
fn fake_sign(p: &Path) {
    let mut img = std::fs::read(p).unwrap();
    let koly = img.split_off(img.len() - 512);
    let off = img.len() as u64;
    img.extend_from_slice(&[0xFA; 64]);
    let mut k = koly;
    k[0x128..0x130].copy_from_slice(&off.to_be_bytes());
    k[0x130..0x138].copy_from_slice(&64u64.to_be_bytes());
    img.extend_from_slice(&k);
    std::fs::write(p, img).unwrap();
}

#[test]
fn signed_images_need_an_explicit_policy() {
    let dir = tempfile::tempdir().unwrap();
    let data = disk();
    let p = udif(dir.path(), "s.dmg", &data, &opts(UdifFormat::Udro));
    let unsigned = std::fs::read(&p).unwrap();
    fake_sign(&p);
    let sig = inspect_udif(&p).unwrap().code_signature().unwrap();
    assert_eq!(sig.length, 64);
    let before = std::fs::read(&p).unwrap();
    // Every rewrite refuses by default, and leaves outputs alone.
    let out = dir.path().join("o.dmg");
    assert!(convert_image(&p, &out, &ConvertOptions::default()).is_err());
    assert!(!out.exists());
    assert!(edit_udif_resources(&p, &p, &ResourceEdit::default()).is_err());
    assert!(
        segment_udif(
            &p,
            &out,
            &SegmentOptions {
                segment_size: 1 << 20,
                ..Default::default()
            }
        )
        .is_err()
    );
    assert!(resize_container(&p, 4 << 20, &ContainerResizeOptions::default()).is_err());
    assert_eq!(std::fs::read(&p).unwrap(), before);
    // Remove: the output carries no signature.
    let mut co = ConvertOptions::default();
    co.policy.signature = SignaturePolicy::Remove;
    co.udif.format = UdifFormat::Udro;
    convert_image(&p, &out, &co).unwrap();
    assert!(inspect_udif(&out).unwrap().code_signature().is_none());
    // remove_code_signature restores the unsigned bytes exactly.
    remove_code_signature(&p, &p).unwrap();
    assert_eq!(std::fs::read(&p).unwrap(), unsigned);
}

#[test]
fn convert_preserves_sectors_layout_and_resources() {
    let dir = tempfile::tempdir().unwrap();
    let data = disk();
    let mut o = opts(UdifFormat::Udco);
    o.layout = UdifLayout::Map(map());
    let mut res = UdifResources::new();
    res.insert(UdifResource::new("TEXT", 5000, b"licence".to_vec()));
    o.resources = res;
    let src = udif(dir.path(), "m.dmg", &data, &o);
    let src_info = inspect_udif(&src).unwrap();
    assert_eq!(src_info.blkx.len(), 4);

    // UDIF → UDIF in another format: layout and resources kept.
    let out = dir.path().join("o.dmg");
    let mut co = ConvertOptions::default();
    co.udif.format = UdifFormat::Udro;
    let r = convert_image(&src, &out, &co).unwrap();
    assert_eq!((r.source, r.target), (ImageKind::Udif, ImageKind::Udif));
    let info = inspect_udif(&out).unwrap();
    let names = |i: &crate::block::dmg::UdifInfo| {
        i.blkx
            .iter()
            .map(|b| {
                (
                    b.name.clone(),
                    b.id,
                    b.descriptor,
                    b.first_sector,
                    b.sector_count,
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(names(&info), names(&src_info));
    assert!(info.blkx[2].is_free_space());
    assert_eq!(info.resources.get("TEXT", 5000).unwrap().data, b"licence");
    assert_eq!(info.format_hint(), "UDRO");
    assert!(read_all(&out) == data);
    assert!(verify_udif(&out).unwrap().is_valid());

    // UDIF → raw needs the resources dropped explicitly.
    let raw = dir.path().join("o.img");
    assert!(matches!(
        convert_image(&src, &raw, &ConvertOptions::default()),
        Err(crate::Error::InvalidArgument(_))
    ));
    let co = ConvertOptions {
        resources: ResourcePolicy::Drop,
        ..Default::default()
    };
    let r = convert_image(&src, &raw, &co).unwrap();
    assert!(r.dropped_resources.contains(&"TEXT".to_string()));
    assert!(std::fs::read(&raw).unwrap() == data);

    // raw → sparse → UDIF → sparsebundle, sectors intact all the way.
    let sp = dir.path().join("o.sparseimage");
    let bundle = dir.path().join("o.sparsebundle");
    let back = dir.path().join("back.dmg");
    #[cfg(feature = "sparse-image")]
    {
        convert_image(&raw, &sp, &ConvertOptions::default()).unwrap();
        assert!(read_all(&sp) == data);
        convert_image(&sp, &back, &co).unwrap();
        assert!(read_all(&back) == data);
        convert_image(&back, &bundle, &co).unwrap();
        assert!(read_all(&bundle) == data);
        // Replacing an existing sparsebundle swaps the directory.
        convert_image(&raw, &bundle, &co).unwrap();
        assert!(read_all(&bundle) == data);
    }
    let _ = (sp, bundle, back);

    // A failed conversion leaves an existing destination untouched.
    std::fs::write(&raw, b"keep me").unwrap();
    let mut co = ConvertOptions {
        target: Some(ImageKind::Udif),
        ..Default::default()
    };
    co.udif.format = UdifFormat::Udro;
    co.udif.chunk_sectors = 0; // invalid → refused
    assert!(convert_image(&out, &raw, &co).is_err());
    assert_eq!(std::fs::read(&raw).unwrap(), b"keep me");
    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().contains(".partial"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

#[test]
fn resize_is_container_only() {
    let dir = tempfile::tempdir().unwrap();
    let data = disk();
    // Raw: grow, shrink over zeros, refuse over data, discard on request.
    let raw = dir.path().join("r.img");
    std::fs::write(&raw, &data).unwrap();
    let o = ContainerResizeOptions::default();
    let r = resize_container(&raw, 3 << 20, &o).unwrap();
    assert_eq!(
        (r.old_size, r.new_size, r.kind),
        (2 << 20, 3 << 20, ImageKind::Raw)
    );
    resize_container(&raw, 2 << 20, &o).unwrap();
    assert!(std::fs::read(&raw).unwrap() == data);
    assert!(resize_container(&raw, (2 << 20) - 1024, &o).is_err());
    assert!(
        std::fs::read(&raw).unwrap() == data,
        "a refused shrink changes nothing"
    );
    let d = ContainerResizeOptions {
        shrink: ShrinkData::Discard,
        ..Default::default()
    };
    let r = resize_container(&raw, (2 << 20) - 1024, &d).unwrap();
    assert!(r.discarded_data);
    assert!(resize_container(&raw, 1000, &o).is_err());

    // UDIF with a map: grown tail is a free entry, shrink clips.
    let mut uo = opts(UdifFormat::Udco);
    uo.layout = UdifLayout::Map(map());
    let p = udif(dir.path(), "r.dmg", &data, &uo);
    resize_container(&p, 3 << 20, &o).unwrap();
    let info = inspect_udif(&p).unwrap();
    assert_eq!(info.sector_count, 6144);
    assert_eq!(info.format_hint(), "UDCO");
    let last = info.blkx.last().unwrap();
    assert!(last.is_free_space());
    assert_eq!((last.first_sector, last.sector_count), (4096, 2048));
    assert_eq!(info.trailer().segment_id, [5; 16]);
    let mut grown = data.clone();
    grown.resize(3 << 20, 0);
    assert!(read_all(&p) == grown);
    assert!(verify_udif(&p).unwrap().is_valid());
    resize_container(&p, 2 << 20, &o).unwrap();
    assert!(read_all(&p) == data);
    assert_eq!(inspect_udif(&p).unwrap().blkx.len(), 4);
    assert!(resize_container(&p, 1 << 20, &o).is_err());
    assert!(read_all(&p) == data);
    #[cfg(feature = "sparse-image")]
    {
        let sp = dir.path().join("r.sparseimage");
        convert_image(&raw, &sp, &ConvertOptions::default()).unwrap();
        resize_container(&sp, 4 << 20, &o).unwrap();
        assert_eq!(open_source(&sp, None).unwrap().total_size(), 4 << 20);
    }
}
