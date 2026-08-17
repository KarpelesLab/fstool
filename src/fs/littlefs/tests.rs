//! In-tree tests for the littlefs backend: format, mutate, re-open, and
//! read back through the same code paths the CLI drives.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::block::{BlockDevice, MemoryBackend};
use crate::fs::{EntryKind, FileMeta, FileSource, Filesystem, OpenFlags};

use super::*;

/// A 256 KiB volume with 4 KiB blocks — 64 blocks, the smallest geometry
/// that still exercises directory splits and multi-block files.
fn fresh(size: u64) -> (MemoryBackend, LittleFs) {
    let mut dev = MemoryBackend::new(size);
    let fs = LittleFs::format(&mut dev, &LittleFsFormatOpts::default()).unwrap();
    (dev, fs)
}

fn write_file(fs: &mut LittleFs, dev: &mut dyn BlockDevice, path: &str, data: &[u8]) {
    fs.create_file(
        dev,
        Path::new(path),
        FileSource::Reader {
            reader: Box::new(std::io::Cursor::new(data.to_vec())),
            len: data.len() as u64,
        },
        FileMeta::default(),
    )
    .unwrap();
}

fn read_file(fs: &mut LittleFs, dev: &mut dyn BlockDevice, path: &str) -> Vec<u8> {
    let mut out = Vec::new();
    fs.read_file(dev, Path::new(path))
        .unwrap()
        .read_to_end(&mut out)
        .unwrap();
    out
}

fn names(fs: &mut LittleFs, dev: &mut dyn BlockDevice, path: &str) -> Vec<String> {
    fs.list(dev, Path::new(path))
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect()
}

#[test]
fn format_writes_a_superblock_at_the_documented_offset() {
    let (mut dev, fs) = fresh(256 * 1024);
    let mut head = [0u8; 16];
    dev.read_at(0, &mut head).unwrap();
    assert_eq!(&head[8..16], b"littlefs");
    assert_eq!(fs.geometry(), (4096, 64));
    assert_eq!(fs.version(), (2, 1));
    // Both halves of the root pair are valid commits after a format, as
    // lfs_format also guarantees.
    let mut second = [0u8; 16];
    dev.read_at(4096, &mut second).unwrap();
    assert_eq!(&second[8..16], b"littlefs");
}

#[test]
fn inline_and_outlined_files_round_trip() {
    let (mut dev, mut fs) = fresh(512 * 1024);
    let small = b"hello littlefs\n".to_vec();
    let big: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
    write_file(&mut fs, &mut dev, "/small.txt", &small);
    write_file(&mut fs, &mut dev, "/big.bin", &big);

    assert_eq!(read_file(&mut fs, &mut dev, "/small.txt"), small);
    assert_eq!(read_file(&mut fs, &mut dev, "/big.bin"), big);

    // The small one stays in metadata, the large one gets a skip-list.
    let entries = fs.list(&mut dev, Path::new("/")).unwrap();
    let big_entry = entries.iter().find(|e| e.name == "big.bin").unwrap();
    assert_eq!(big_entry.size, big.len() as u64);
    assert!(small.len() as u32 <= fs.inline_max());
}

#[test]
fn reopening_an_image_sees_everything() {
    let mut dev = MemoryBackend::new(512 * 1024);
    {
        let mut fs = LittleFs::format(&mut dev, &LittleFsFormatOpts::default()).unwrap();
        fs.create_dir(&mut dev, Path::new("/etc"), FileMeta::default())
            .unwrap();
        write_file(&mut fs, &mut dev, "/etc/motd", b"be excellent\n");
        let payload: Vec<u8> = (0..30_000u32).map(|i| i as u8).collect();
        write_file(&mut fs, &mut dev, "/etc/blob", &payload);
        fs.flush(&mut dev).unwrap();
    }
    let mut fs = LittleFs::open(&mut dev).unwrap();
    assert_eq!(names(&mut fs, &mut dev, "/"), vec!["etc"]);
    assert_eq!(names(&mut fs, &mut dev, "/etc"), vec!["blob", "motd"]);
    assert_eq!(read_file(&mut fs, &mut dev, "/etc/motd"), b"be excellent\n");
    assert_eq!(read_file(&mut fs, &mut dev, "/etc/blob").len(), 30_000);

    // And it is still writable after the round trip.
    write_file(&mut fs, &mut dev, "/etc/extra", b"more");
    assert_eq!(
        names(&mut fs, &mut dev, "/etc"),
        vec!["blob", "extra", "motd"]
    );
}

#[test]
fn directory_entries_are_kept_in_name_order() {
    let (mut dev, mut fs) = fresh(512 * 1024);
    for name in ["zulu", "alpha", "mike", "bravo"] {
        write_file(&mut fs, &mut dev, &format!("/{name}"), name.as_bytes());
    }
    assert_eq!(
        names(&mut fs, &mut dev, "/"),
        vec!["alpha", "bravo", "mike", "zulu"]
    );
}

#[test]
fn removing_reclaims_blocks() {
    let (mut dev, mut fs) = fresh(512 * 1024);
    let before = fs.used_blocks(&mut dev).unwrap();
    let payload: Vec<u8> = vec![7u8; 60_000];
    write_file(&mut fs, &mut dev, "/blob", &payload);
    let during = fs.used_blocks(&mut dev).unwrap();
    assert!(during > before + 10, "{during} vs {before}");

    fs.remove(&mut dev, Path::new("/blob")).unwrap();
    assert_eq!(fs.used_blocks(&mut dev).unwrap(), before);
    assert!(fs.list(&mut dev, Path::new("/")).unwrap().is_empty());
}

#[test]
fn directories_must_be_empty_to_be_removed() {
    let (mut dev, mut fs) = fresh(512 * 1024);
    fs.create_dir(&mut dev, Path::new("/d"), FileMeta::default())
        .unwrap();
    write_file(&mut fs, &mut dev, "/d/f", b"x");
    assert!(fs.remove(&mut dev, Path::new("/d")).is_err());
    fs.remove(&mut dev, Path::new("/d/f")).unwrap();
    let used_before = fs.used_blocks(&mut dev).unwrap();
    fs.remove(&mut dev, Path::new("/d")).unwrap();
    // The directory's own metadata pair comes back to the free pool.
    assert_eq!(fs.used_blocks(&mut dev).unwrap(), used_before - 2);
    assert!(fs.list(&mut dev, Path::new("/")).unwrap().is_empty());
}

#[test]
fn many_entries_split_the_directory_across_pairs() {
    let (mut dev, mut fs) = fresh(2 * 1024 * 1024);
    for i in 0..200 {
        write_file(
            &mut fs,
            &mut dev,
            &format!("/file{i:04}"),
            format!("contents of {i}").as_bytes(),
        );
    }
    let listed = names(&mut fs, &mut dev, "/");
    assert_eq!(listed.len(), 200);
    // Still sorted, and still readable, across the split.
    let mut sorted = listed.clone();
    sorted.sort();
    assert_eq!(listed, sorted);
    assert_eq!(
        read_file(&mut fs, &mut dev, "/file0137"),
        b"contents of 137"
    );

    // A re-opened image agrees.
    fs.flush(&mut dev).unwrap();
    let mut fs = LittleFs::open(&mut dev).unwrap();
    assert_eq!(names(&mut fs, &mut dev, "/").len(), 200);
}

#[test]
fn in_place_writes_patch_a_file() {
    let (mut dev, mut fs) = fresh(1024 * 1024);
    let payload: Vec<u8> = (0..50_000u32).map(|i| (i % 97) as u8).collect();
    write_file(&mut fs, &mut dev, "/data.bin", &payload);

    {
        let mut h = fs
            .open_file_rw(&mut dev, Path::new("/data.bin"), OpenFlags::default(), None)
            .unwrap();
        h.seek(SeekFrom::Start(10_000)).unwrap();
        h.write_all(b"PATCHED").unwrap();
        h.sync().unwrap();
        assert_eq!(h.len(), 50_000);
    }

    let mut expect = payload.clone();
    expect[10_000..10_007].copy_from_slice(b"PATCHED");
    assert_eq!(read_file(&mut fs, &mut dev, "/data.bin"), expect);
}

#[test]
fn appending_past_the_end_extends_the_file() {
    let (mut dev, mut fs) = fresh(1024 * 1024);
    write_file(&mut fs, &mut dev, "/log", b"start");
    {
        let mut h = fs
            .open_file_rw(
                &mut dev,
                Path::new("/log"),
                OpenFlags {
                    append: true,
                    ..OpenFlags::default()
                },
                None,
            )
            .unwrap();
        // Push it well past the inline limit so it has to be outlined.
        h.write_all(&vec![b'z'; 9_000]).unwrap();
        h.sync().unwrap();
    }
    let got = read_file(&mut fs, &mut dev, "/log");
    assert_eq!(got.len(), 9_005);
    assert_eq!(&got[..5], b"start");
    assert!(got[5..].iter().all(|&b| b == b'z'));
}

#[test]
fn truncate_shrinks_and_grows() {
    let (mut dev, mut fs) = fresh(1024 * 1024);
    let payload: Vec<u8> = (0..30_000u32).map(|i| i as u8).collect();
    write_file(&mut fs, &mut dev, "/f", &payload);

    fs.truncate(&mut dev, Path::new("/f"), 20_000).unwrap();
    let got = read_file(&mut fs, &mut dev, "/f");
    assert_eq!(got, payload[..20_000]);

    fs.truncate(&mut dev, Path::new("/f"), 25_000).unwrap();
    let got = read_file(&mut fs, &mut dev, "/f");
    assert_eq!(got.len(), 25_000);
    assert_eq!(&got[..20_000], &payload[..20_000]);
    assert!(got[20_000..].iter().all(|&b| b == 0));

    // Shrinking below the inline limit puts the file back in metadata.
    fs.truncate(&mut dev, Path::new("/f"), 8).unwrap();
    assert_eq!(read_file(&mut fs, &mut dev, "/f"), payload[..8]);
}

#[test]
fn rename_moves_between_directories() {
    let (mut dev, mut fs) = fresh(512 * 1024);
    fs.create_dir(&mut dev, Path::new("/a"), FileMeta::default())
        .unwrap();
    fs.create_dir(&mut dev, Path::new("/b"), FileMeta::default())
        .unwrap();
    write_file(&mut fs, &mut dev, "/a/one", b"payload");
    fs.rename(&mut dev, Path::new("/a/one"), Path::new("/b/two"))
        .unwrap();
    assert!(names(&mut fs, &mut dev, "/a").is_empty());
    assert_eq!(names(&mut fs, &mut dev, "/b"), vec!["two"]);
    assert_eq!(read_file(&mut fs, &mut dev, "/b/two"), b"payload");
}

#[test]
fn user_attributes_surface_as_xattrs() {
    let (mut dev, mut fs) = fresh(512 * 1024);
    write_file(&mut fs, &mut dev, "/f", b"x");
    fs.set_xattr(&mut dev, Path::new("/f"), "user.littlefs.42", b"meta")
        .unwrap();
    let attrs = fs.list_xattrs(&mut dev, Path::new("/f")).unwrap();
    assert_eq!(attrs.len(), 1);
    assert_eq!(attrs[0].name, "user.littlefs.42");
    assert_eq!(attrs[0].value, b"meta");

    // Attributes survive a re-open, and non-littlefs names are refused.
    fs.flush(&mut dev).unwrap();
    let mut fs = LittleFs::open(&mut dev).unwrap();
    assert_eq!(fs.list_xattrs(&mut dev, Path::new("/f")).unwrap().len(), 1);
    assert!(
        fs.set_xattr(&mut dev, Path::new("/f"), "user.something", b"v")
            .is_err()
    );

    fs.remove_xattr(&mut dev, Path::new("/f"), "user.littlefs.42")
        .unwrap();
    assert!(
        fs.list_xattrs(&mut dev, Path::new("/f"))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn nested_directories_and_getattr() {
    let (mut dev, mut fs) = fresh(512 * 1024);
    for d in ["/usr", "/usr/local", "/usr/local/share"] {
        fs.create_dir(&mut dev, Path::new(d), FileMeta::default())
            .unwrap();
    }
    write_file(&mut fs, &mut dev, "/usr/local/share/greeting", b"hi");
    let a = fs
        .getattr(&mut dev, Path::new("/usr/local/share/greeting"))
        .unwrap();
    assert_eq!(a.kind, EntryKind::Regular);
    assert_eq!(a.size, 2);
    let d = fs.getattr(&mut dev, Path::new("/usr/local")).unwrap();
    assert_eq!(d.kind, EntryKind::Dir);
    assert_eq!(d.mode, 0o755);
    assert_eq!(fs.total_file_bytes(&mut dev).unwrap(), 2);
}

#[test]
fn symlinks_and_devices_are_refused_cleanly() {
    let (mut dev, mut fs) = fresh(256 * 1024);
    let err = fs
        .create_symlink(
            &mut dev,
            Path::new("/link"),
            Path::new("/target"),
            FileMeta::default(),
        )
        .unwrap_err();
    assert!(matches!(err, crate::Error::Unsupported(_)));
    let err = fs
        .create_device(
            &mut dev,
            Path::new("/null"),
            crate::fs::DeviceKind::Char,
            1,
            3,
            FileMeta::default(),
        )
        .unwrap_err();
    assert!(matches!(err, crate::Error::Unsupported(_)));
}

#[test]
fn a_full_volume_reports_out_of_space() {
    // 16 blocks of 4 KiB: enough to format, nowhere near enough for 200 KiB.
    let mut dev = MemoryBackend::new(64 * 1024);
    let mut fs = LittleFs::format(&mut dev, &LittleFsFormatOpts::default()).unwrap();
    let err = fs
        .create_file(
            &mut dev,
            Path::new("/toobig"),
            FileSource::Zero(200 * 1024),
            FileMeta::default(),
        )
        .unwrap_err();
    assert!(
        err.to_string().contains("no free blocks"),
        "unexpected error: {err}"
    );
}

#[test]
fn version_2_0_images_omit_forward_crcs() {
    let mut dev = MemoryBackend::new(256 * 1024);
    let opts = LittleFsFormatOpts {
        disk_version: DISK_VERSION_2_0,
        ..LittleFsFormatOpts::default()
    };
    let mut fs = LittleFs::format(&mut dev, &opts).unwrap();
    write_file(&mut fs, &mut dev, "/f", b"data");
    assert_eq!(fs.version(), (2, 0));

    // A pre-lfs2.1 reader mistakes an FCRC tag for a commit CRC, so a 2.0
    // image must not contain one anywhere.
    let mut block = vec![0u8; 4096];
    dev.read_at(0, &mut block).unwrap();
    let mut ptag = tag::PTAG_INIT;
    let mut off = 0usize;
    loop {
        off += tag::Tag(ptag).dsize();
        if off + 4 > block.len() {
            break;
        }
        let t = tag::Tag(tag::be32(&block[off..off + 4]) ^ ptag);
        if !t.is_valid() {
            break;
        }
        assert_ne!(t.type3(), tag::TYPE_FCRC, "2.0 image carries an FCRC tag");
        ptag = t.0;
        if t.type2() == tag::TYPE_CCRC {
            ptag ^= ((t.chunk() & 1) as u32) << 31;
        }
    }

    let mut fs = LittleFs::open(&mut dev).unwrap();
    assert_eq!(fs.version(), (2, 0));
    assert_eq!(read_file(&mut fs, &mut dev, "/f"), b"data");
}

// ---------------------------------------------------------------------
// Robustness: torn writes and malformed images. These probe the code
// paths a hostile or half-written image reaches, where the contract is
// "a structured error, never a panic and never a hang".
// ---------------------------------------------------------------------

#[test]
fn a_torn_commit_falls_back_to_the_pairs_other_block() {
    // littlefs's central promise: a metadata pair keeps the previous
    // commit in its other block, so a write interrupted by power loss
    // leaves the volume mountable at its last consistent state.
    let (mut dev, mut fs) = fresh(512 * 1024);
    write_file(&mut fs, &mut dev, "/first.txt", b"committed first");
    fs.flush(&mut dev).unwrap();
    write_file(&mut fs, &mut dev, "/second.txt", b"committed second");
    fs.flush(&mut dev).unwrap();
    drop(fs);

    // Find the live half of the root pair (higher revision count) and
    // scribble over everything after its revision count — the shape a
    // torn program leaves behind.
    let mut rev0 = [0u8; 4];
    let mut rev1 = [0u8; 4];
    dev.read_at(0, &mut rev0).unwrap();
    dev.read_at(4096, &mut rev1).unwrap();
    let live = if u32::from_le_bytes(rev1) > u32::from_le_bytes(rev0) {
        4096
    } else {
        0
    };
    dev.write_at(live + 4, &vec![0xffu8; 4096 - 4]).unwrap();

    let mut fs = LittleFs::open(&mut dev).expect("volume still mounts after a torn commit");
    let listed = names(&mut fs, &mut dev, "/");
    assert!(
        listed.contains(&"first.txt".to_string()),
        "the older commit should have survived, got {listed:?}"
    );
    assert_eq!(
        read_file(&mut fs, &mut dev, "/first.txt"),
        b"committed first"
    );
    // And the recovered volume is still writable.
    write_file(&mut fs, &mut dev, "/third.txt", b"after recovery");
    assert_eq!(
        read_file(&mut fs, &mut dev, "/third.txt"),
        b"after recovery"
    );
}

#[test]
fn corrupted_images_error_rather_than_panic() {
    // Build one good image, then splatter bytes over it in many places
    // and drive the whole read surface. Any outcome is acceptable except
    // a panic or a hang — this is the path an untrusted image takes.
    let good = {
        let (mut dev, mut fs) = fresh(64 * 1024);
        fs.create_dir(&mut dev, Path::new("/dir"), FileMeta::default())
            .unwrap();
        write_file(&mut fs, &mut dev, "/dir/inline.txt", b"small body");
        write_file(&mut fs, &mut dev, "/outlined.bin", &vec![0xa5u8; 9_000]);
        fs.flush(&mut dev).unwrap();
        dev.into_bytes()
    };

    // Deterministic xorshift so a failure is reproducible.
    let mut state = 0x1234_5678_9abc_def0u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    for round in 0..300 {
        let mut image = good.clone();
        // One to four splatters per round, of a few bytes each.
        for _ in 0..(1 + next() % 4) {
            let off = (next() as usize) % image.len();
            let len = (1 + next() as usize % 32).min(image.len() - off);
            let byte = next() as u8;
            image[off..off + len].fill(byte);
        }
        let mut dev = MemoryBackend::from_bytes(image);
        let Ok(mut fs) = LittleFs::open(&mut dev) else {
            continue; // rejected outright — fine
        };
        // Walk whatever it claims to hold.
        let entries = match fs.list(&mut dev, Path::new("/")) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for e in entries {
            let p = format!("/{}", e.name);
            match e.kind {
                EntryKind::Dir => {
                    let _ = fs.list(&mut dev, Path::new(&p));
                }
                _ => {
                    if let Ok(mut r) = fs.read_file(&mut dev, Path::new(&p)) {
                        let mut sink = Vec::new();
                        let _ = r.read_to_end(&mut sink);
                    }
                }
            }
            let _ = fs.getattr(&mut dev, Path::new(&p));
        }
        let _ = fs.statfs(&mut dev);
        let _ = round;
    }
}

#[test]
fn hostile_superblock_geometry_is_rejected() {
    // The superblock's block size and count are the first attacker-
    // controlled numbers we read, and everything downstream (buffer
    // sizes, the allocator bitmap) is derived from them.
    let (dev, _fs) = fresh(64 * 1024);
    let good = dev.into_bytes();

    let cases: [(&str, u32, u32); 6] = [
        ("zero block size", 0, 16),
        ("zero block count", 4096, 0),
        ("sub-minimum block size", 64, 16),
        ("absurd block size", 0x4000_0000, 16),
        ("block count past the device", 4096, 0x00ff_ffff),
        ("block size past the device", 1 << 24, 1),
    ];
    for (what, bs, bc) in cases {
        let mut image = good.clone();
        image[24..28].copy_from_slice(&bs.to_le_bytes());
        image[28..32].copy_from_slice(&bc.to_le_bytes());
        let mut dev = MemoryBackend::from_bytes(image);
        assert!(
            LittleFs::open(&mut dev).is_err(),
            "{what} ({bs} x {bc}) should be rejected"
        );
    }

    // A future major version is refused rather than misparsed.
    let mut image = good.clone();
    image[20..24].copy_from_slice(&0x0003_0000u32.to_le_bytes());
    let mut dev = MemoryBackend::from_bytes(image);
    assert!(LittleFs::open(&mut dev).is_err(), "lfs3 must be refused");
    // As is a minor version newer than the one we implement.
    let mut image = good.clone();
    image[20..24].copy_from_slice(&0x0002_0009u32.to_le_bytes());
    let mut dev = MemoryBackend::from_bytes(image);
    assert!(LittleFs::open(&mut dev).is_err(), "lfs2.9 must be refused");
}

#[test]
fn metadata_splatter_never_panics() {
    // Same contract as `corrupted_images_error_rather_than_panic`, but
    // aimed squarely at the metadata blocks — tags, ids, lengths, struct
    // pointers — rather than at whatever byte the PRNG happens to pick.
    let good = {
        let (mut dev, mut fs) = fresh(128 * 1024);
        fs.create_dir(&mut dev, Path::new("/d"), FileMeta::default())
            .unwrap();
        write_file(&mut fs, &mut dev, "/d/a", b"body a");
        write_file(&mut fs, &mut dev, "/d/b", &vec![7u8; 20_000]);
        fs.set_xattr(&mut dev, Path::new("/d/a"), "user.littlefs.3", b"attr")
            .unwrap();
        fs.flush(&mut dev).unwrap();
        dev.into_bytes()
    };

    let mut state = 0xfeed_face_dead_beefu64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    // Blocks 0-1 are the root pair; block 2-3 hold /d's pair. Hammer
    // those specifically, byte by byte, with values that flip tag type,
    // id and length fields.
    for _ in 0..600 {
        let mut image = good.clone();
        let block = (next() % 4) as usize;
        let off = block * 4096 + (next() as usize % 512);
        let len = (1 + next() as usize % 8).min(image.len() - off);
        let byte = match next() % 4 {
            0 => 0x00,
            1 => 0xff,
            2 => (next() % 256) as u8,
            _ => 0x3f,
        };
        image[off..off + len].fill(byte);

        let mut dev = MemoryBackend::from_bytes(image);
        let Ok(mut fs) = LittleFs::open(&mut dev) else {
            continue;
        };
        let mut stack = vec!["/".to_string()];
        let mut visited = 0;
        while let Some(dir) = stack.pop() {
            visited += 1;
            if visited > 64 {
                break; // a corrupt tree may claim to be huge
            }
            let Ok(entries) = fs.list(&mut dev, Path::new(&dir)) else {
                continue;
            };
            for e in entries {
                let p = if dir == "/" {
                    format!("/{}", e.name)
                } else {
                    format!("{dir}/{}", e.name)
                };
                match e.kind {
                    EntryKind::Dir => stack.push(p),
                    _ => {
                        if let Ok(mut r) = fs.read_file(&mut dev, Path::new(&p)) {
                            let mut sink = Vec::new();
                            let _ = r.read_to_end(&mut sink);
                        }
                        let _ = fs.list_xattrs(&mut dev, Path::new(&p));
                    }
                }
            }
        }
        // Writing into a damaged volume must also stay structured.
        let _ = fs.create_dir(&mut dev, Path::new("/new"), FileMeta::default());
        let _ = fs.remove(&mut dev, Path::new("/d/a"));
        let _ = fs.statfs(&mut dev);
    }
}

// ---------------------------------------------------------------------
// Geometry, churn and limits.
// ---------------------------------------------------------------------

#[test]
fn every_supported_geometry_round_trips() {
    // Block size drives the inline threshold, the split point and the
    // CTZ payload of every block, so each one is a different layout.
    for (block_size, prog_size, image) in [
        (128u32, 8u32, 256 * 1024u64),
        (512, 128, 512 * 1024),
        (1024, 64, 512 * 1024),
        (4096, 256, 1024 * 1024),
        (16384, 512, 4 * 1024 * 1024),
    ] {
        let mut dev = MemoryBackend::new(image);
        let opts = LittleFsFormatOpts {
            block_size,
            prog_size,
            ..LittleFsFormatOpts::default()
        };
        let mut fs = LittleFs::format(&mut dev, &opts)
            .unwrap_or_else(|e| panic!("format at {block_size}/{prog_size}: {e}"));

        // One file below the inline threshold and one comfortably above
        // it, so both storage forms are exercised at every geometry.
        let inline_max = fs.inline_max();
        let small = vec![0x5au8; (inline_max / 2) as usize];
        let big: Vec<u8> = (0..(block_size as usize * 5 + 37))
            .map(|i| (i % 253) as u8)
            .collect();
        fs.create_dir(&mut dev, Path::new("/sub"), FileMeta::default())
            .unwrap();
        write_file(&mut fs, &mut dev, "/sub/small", &small);
        write_file(&mut fs, &mut dev, "/sub/big", &big);
        fs.flush(&mut dev).unwrap();

        let mut fs = LittleFs::open(&mut dev)
            .unwrap_or_else(|e| panic!("reopen at {block_size}/{prog_size}: {e}"));
        assert_eq!(fs.geometry().0, block_size);
        assert_eq!(
            read_file(&mut fs, &mut dev, "/sub/small"),
            small,
            "inline file at {block_size}/{prog_size}"
        );
        assert_eq!(
            read_file(&mut fs, &mut dev, "/sub/big"),
            big,
            "outlined file at {block_size}/{prog_size}"
        );
        // The program size the image was written with is recovered from
        // the forward-CRC, since the superblock doesn't record it.
        assert_eq!(
            fs.program_size(),
            prog_size,
            "program size at {block_size}/{prog_size}"
        );
    }
}

#[test]
fn churn_across_a_split_directory_chain() {
    // Fill a directory well past one metadata pair, then delete most of
    // it. This walks the paths where an entry lives in a later pair of
    // the chain and where a pair empties out entirely.
    let (mut dev, mut fs) = fresh(4 * 1024 * 1024);
    fs.create_dir(&mut dev, Path::new("/many"), FileMeta::default())
        .unwrap();
    for i in 0..300 {
        write_file(
            &mut fs,
            &mut dev,
            &format!("/many/f{i:04}"),
            format!("body {i}").as_bytes(),
        );
    }
    assert_eq!(names(&mut fs, &mut dev, "/many").len(), 300);

    // Remove every third file, then check the rest are all still there
    // and still readable at their own contents.
    for i in (0..300).step_by(3) {
        fs.remove(&mut dev, Path::new(&format!("/many/f{i:04}")))
            .unwrap();
    }
    let left = names(&mut fs, &mut dev, "/many");
    assert_eq!(left.len(), 200);
    let mut sorted = left.clone();
    sorted.sort();
    assert_eq!(left, sorted, "the chain stayed in name order");
    for i in 0..300 {
        let path = format!("/many/f{i:04}");
        if i % 3 == 0 {
            assert!(fs.getattr(&mut dev, Path::new(&path)).is_err());
        } else {
            assert_eq!(
                read_file(&mut fs, &mut dev, &path),
                format!("body {i}").as_bytes()
            );
        }
    }

    // Empty it completely — including the pairs that are now empty but
    // still chained — and the directory must then be removable.
    for name in left {
        fs.remove(&mut dev, Path::new(&format!("/many/{name}")))
            .unwrap();
    }
    assert!(fs.list(&mut dev, Path::new("/many")).unwrap().is_empty());
    fs.remove(&mut dev, Path::new("/many")).unwrap();
    assert!(fs.list(&mut dev, Path::new("/")).unwrap().is_empty());

    // And the volume is still coherent after all that churn.
    fs.flush(&mut dev).unwrap();
    let mut fs = LittleFs::open(&mut dev).unwrap();
    assert!(fs.list(&mut dev, Path::new("/")).unwrap().is_empty());
    write_file(&mut fs, &mut dev, "/after", b"still writable");
    assert_eq!(read_file(&mut fs, &mut dev, "/after"), b"still writable");
}

#[test]
fn name_limits_are_enforced() {
    let (mut dev, mut fs) = fresh(512 * 1024);
    let longest = "n".repeat(255);
    write_file(&mut fs, &mut dev, &format!("/{longest}"), b"ok");
    assert_eq!(read_file(&mut fs, &mut dev, &format!("/{longest}")), b"ok");

    let too_long = "n".repeat(256);
    let err = fs
        .create_file(
            &mut dev,
            Path::new(&format!("/{too_long}")),
            FileSource::Zero(0),
            FileMeta::default(),
        )
        .unwrap_err();
    assert!(err.to_string().contains("longer than"), "{err}");

    // A volume formatted with a tighter limit enforces its own value.
    let mut dev = MemoryBackend::new(256 * 1024);
    let mut fs = LittleFs::format(
        &mut dev,
        &LittleFsFormatOpts {
            name_max: 8,
            ..LittleFsFormatOpts::default()
        },
    )
    .unwrap();
    write_file(&mut fs, &mut dev, "/12345678", b"fits");
    assert!(
        fs.create_file(
            &mut dev,
            Path::new("/123456789"),
            FileSource::Zero(0),
            FileMeta::default(),
        )
        .is_err()
    );
    // …and still does after a reopen, since name_max lives in the
    // superblock.
    fs.flush(&mut dev).unwrap();
    let mut fs = LittleFs::open(&mut dev).unwrap();
    assert!(
        fs.create_file(
            &mut dev,
            Path::new("/123456789"),
            FileSource::Zero(0),
            FileMeta::default(),
        )
        .is_err()
    );
}
