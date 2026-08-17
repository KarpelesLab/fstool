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
