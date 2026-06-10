//! Unit tests for the in-memory [`Ramfs`].

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use super::{Ramfs, RamfsFormatOpts};
use crate::block::MemoryBackend;
use crate::fs::{
    DeviceKind, EntryKind, FileMeta, FileSource, Filesystem, FilesystemFactory, OpenFlags, SetAttrs,
};

/// A throwaway block device — ramfs ignores it.
fn dev() -> MemoryBackend {
    MemoryBackend::new(0)
}

fn put(fs: &mut Ramfs, d: &mut MemoryBackend, path: &str, data: &[u8]) {
    fs.create_file(
        d,
        Path::new(path),
        FileSource::Reader {
            reader: Box::new(std::io::Cursor::new(data.to_vec())),
            len: data.len() as u64,
        },
        FileMeta::default(),
    )
    .unwrap();
}

fn read_all(fs: &mut Ramfs, d: &mut MemoryBackend, path: &str) -> Vec<u8> {
    let mut r = fs.read_file(d, Path::new(path)).unwrap();
    let mut v = Vec::new();
    r.read_to_end(&mut v).unwrap();
    v
}

#[test]
fn build_tree_round_trips() {
    let mut d = dev();
    let mut fs = Ramfs::new();
    fs.create_dir(&mut d, Path::new("/a"), FileMeta::default())
        .unwrap();
    fs.create_dir(&mut d, Path::new("/a/b"), FileMeta::default())
        .unwrap();
    put(&mut fs, &mut d, "/a/f1", b"hello");
    put(&mut fs, &mut d, "/a/b/f2", b"world");

    let root = fs.list(&mut d, Path::new("/")).unwrap();
    assert_eq!(root.len(), 1);
    assert_eq!(root[0].name, "a");
    assert_eq!(root[0].kind, EntryKind::Dir);

    let a = fs.list(&mut d, Path::new("/a")).unwrap();
    let names: Vec<_> = a.iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&"b") && names.contains(&"f1"));

    assert_eq!(read_all(&mut fs, &mut d, "/a/f1"), b"hello");
    assert_eq!(read_all(&mut fs, &mut d, "/a/b/f2"), b"world");
}

#[test]
fn create_existing_path_errors() {
    let mut d = dev();
    let mut fs = Ramfs::new();
    put(&mut fs, &mut d, "/f", b"x");
    assert!(
        fs.create_file(
            &mut d,
            Path::new("/f"),
            FileSource::Zero(0),
            FileMeta::default()
        )
        .is_err()
    );
}

#[test]
fn rw_handle_partial_write_and_resize() {
    let mut d = dev();
    let mut fs = Ramfs::new();
    put(&mut fs, &mut d, "/x", &[0xAA; 200]);

    {
        let mut h = fs
            .open_file_rw(&mut d, Path::new("/x"), OpenFlags::default(), None)
            .unwrap();
        h.seek(SeekFrom::Start(100)).unwrap();
        h.write_all(&[0x55; 16]).unwrap();
        h.sync().unwrap();
    }
    let got = read_all(&mut fs, &mut d, "/x");
    assert_eq!(got.len(), 200);
    assert!(got[..100].iter().all(|&b| b == 0xAA));
    assert!(got[100..116].iter().all(|&b| b == 0x55));
    assert!(got[116..].iter().all(|&b| b == 0xAA));

    // Shrink then grow.
    {
        let mut h = fs
            .open_file_rw(&mut d, Path::new("/x"), OpenFlags::default(), None)
            .unwrap();
        h.set_len(50).unwrap();
        assert_eq!(h.len(), 50);
        h.set_len(300).unwrap();
        assert_eq!(h.len(), 300);
    }
    let got = read_all(&mut fs, &mut d, "/x");
    assert_eq!(got.len(), 300);
    // Bytes past the original 50 are zero-filled.
    assert!(got[50..].iter().all(|&b| b == 0));
}

#[test]
fn rw_create_and_append() {
    let mut d = dev();
    let mut fs = Ramfs::new();
    {
        let mut h = fs
            .open_file_rw(
                &mut d,
                Path::new("/new"),
                OpenFlags {
                    create: true,
                    ..Default::default()
                },
                Some(FileMeta::default()),
            )
            .unwrap();
        h.write_all(b"abc").unwrap();
    }
    {
        let mut h = fs
            .open_file_rw(
                &mut d,
                Path::new("/new"),
                OpenFlags {
                    append: true,
                    ..Default::default()
                },
                None,
            )
            .unwrap();
        h.write_all(b"def").unwrap();
    }
    assert_eq!(read_all(&mut fs, &mut d, "/new"), b"abcdef");
}

#[test]
fn rename_across_dirs() {
    let mut d = dev();
    let mut fs = Ramfs::new();
    fs.create_dir(&mut d, Path::new("/a"), FileMeta::default())
        .unwrap();
    fs.create_dir(&mut d, Path::new("/b"), FileMeta::default())
        .unwrap();
    put(&mut fs, &mut d, "/a/f", b"data");
    fs.rename(&mut d, Path::new("/a/f"), Path::new("/b/f"))
        .unwrap();
    assert!(fs.read_file(&mut d, Path::new("/a/f")).is_err());
    assert_eq!(read_all(&mut fs, &mut d, "/b/f"), b"data");
    // A directory can't be moved into its own subtree.
    fs.create_dir(&mut d, Path::new("/a/sub"), FileMeta::default())
        .unwrap();
    assert!(
        fs.rename(&mut d, Path::new("/a"), Path::new("/a/sub/a"))
            .is_err()
    );
}

#[test]
fn hardlink_shares_inode() {
    let mut d = dev();
    let mut fs = Ramfs::new();
    put(&mut fs, &mut d, "/f", b"shared");
    fs.hardlink(&mut d, Path::new("/f"), Path::new("/g"))
        .unwrap();

    let af = fs.getattr(&mut d, Path::new("/f")).unwrap();
    let ag = fs.getattr(&mut d, Path::new("/g")).unwrap();
    assert_eq!(af.inode, ag.inode);
    assert_eq!(af.nlink, 2);
    assert_eq!(read_all(&mut fs, &mut d, "/g"), b"shared");

    // Removing one link keeps the other readable.
    fs.remove(&mut d, Path::new("/f")).unwrap();
    assert_eq!(read_all(&mut fs, &mut d, "/g"), b"shared");
    assert_eq!(fs.getattr(&mut d, Path::new("/g")).unwrap().nlink, 1);

    // Directories can't be hard-linked.
    fs.create_dir(&mut d, Path::new("/dir"), FileMeta::default())
        .unwrap();
    assert!(
        fs.hardlink(&mut d, Path::new("/dir"), Path::new("/dir2"))
            .is_err()
    );
}

#[test]
fn symlink_round_trips() {
    let mut d = dev();
    let mut fs = Ramfs::new();
    fs.create_symlink(
        &mut d,
        Path::new("/link"),
        Path::new("/target/file"),
        FileMeta::default(),
    )
    .unwrap();
    assert_eq!(
        fs.read_symlink(&mut d, Path::new("/link")).unwrap(),
        Path::new("/target/file")
    );
    assert_eq!(
        fs.getattr(&mut d, Path::new("/link")).unwrap().kind,
        EntryKind::Symlink
    );
}

#[test]
fn device_node_round_trips_rdev() {
    let mut d = dev();
    let mut fs = Ramfs::new();
    fs.create_dir(&mut d, Path::new("/dev"), FileMeta::default())
        .unwrap();
    fs.create_device(
        &mut d,
        Path::new("/dev/null"),
        DeviceKind::Char,
        1,
        3,
        FileMeta::default(),
    )
    .unwrap();
    let a = fs.getattr(&mut d, Path::new("/dev/null")).unwrap();
    assert_eq!(a.kind, EntryKind::Char);
    assert_eq!(crate::fs::ext::inode::decode_devnum(a.rdev), (1, 3));
}

#[test]
fn xattrs_set_list_remove() {
    let mut d = dev();
    let mut fs = Ramfs::new();
    put(&mut fs, &mut d, "/f", b"x");
    fs.set_xattr(&mut d, Path::new("/f"), "user.foo", b"bar")
        .unwrap();
    let xs = fs.list_xattrs(&mut d, Path::new("/f")).unwrap();
    assert_eq!(xs.len(), 1);
    assert_eq!(xs[0].name, "user.foo");
    assert_eq!(xs[0].value, b"bar");
    fs.remove_xattr(&mut d, Path::new("/f"), "user.foo")
        .unwrap();
    assert!(fs.list_xattrs(&mut d, Path::new("/f")).unwrap().is_empty());
    // Removing a missing xattr errors.
    assert!(
        fs.remove_xattr(&mut d, Path::new("/f"), "user.foo")
            .is_err()
    );
}

#[test]
fn remove_nonempty_dir_errors() {
    let mut d = dev();
    let mut fs = Ramfs::new();
    fs.create_dir(&mut d, Path::new("/d"), FileMeta::default())
        .unwrap();
    put(&mut fs, &mut d, "/d/f", b"x");
    assert!(fs.remove(&mut d, Path::new("/d")).is_err());
    fs.remove(&mut d, Path::new("/d/f")).unwrap();
    fs.remove(&mut d, Path::new("/d")).unwrap();
    assert!(fs.list(&mut d, Path::new("/d")).is_err());
}

#[test]
fn set_attrs_and_truncate() {
    let mut d = dev();
    let mut fs = Ramfs::new();
    put(&mut fs, &mut d, "/f", &[1u8; 100]);
    fs.set_attrs(
        &mut d,
        Path::new("/f"),
        SetAttrs {
            mode: Some(0o600),
            uid: Some(42),
            mtime: Some(12345),
            ..Default::default()
        },
    )
    .unwrap();
    let a = fs.getattr(&mut d, Path::new("/f")).unwrap();
    assert_eq!(a.mode, 0o600);
    assert_eq!(a.uid, 42);
    assert_eq!(a.mtime, 12345);

    fs.truncate(&mut d, Path::new("/f"), 10).unwrap();
    assert_eq!(read_all(&mut fs, &mut d, "/f").len(), 10);
}

#[test]
fn format_is_empty_open_is_unsupported() {
    let mut d = dev();
    let fs = Ramfs::format(&mut d, &RamfsFormatOpts::default()).unwrap();
    assert_eq!(fs.inodes.len(), 1); // just the root
    assert!(Ramfs::open(&mut d).is_err());
}

#[test]
fn repack_to_ext_round_trips() {
    let mut d = dev();
    let mut fs = Ramfs::new();
    fs.create_dir(&mut d, Path::new("/sub"), FileMeta::default())
        .unwrap();
    put(&mut fs, &mut d, "/sub/hello.txt", b"hello ramfs");
    put(&mut fs, &mut d, "/top.bin", &vec![7u8; 5000]);
    fs.create_symlink(
        &mut d,
        Path::new("/sub/link"),
        Path::new("hello.txt"),
        FileMeta::default(),
    )
    .unwrap();

    // Repack into a fresh ext2 image, then reopen it from the device.
    let opts = crate::fs::ext::FormatOpts {
        blocks_count: 8192,
        inodes_count: 256,
        ..Default::default()
    };
    let mut dst = MemoryBackend::new(8192 * 1024);
    fs.repack_to::<crate::fs::ext::Ext>(&mut dst, &opts)
        .unwrap();

    let mut ext = crate::fs::ext::Ext::open(&mut dst).unwrap();
    // /top.bin
    let mut r = ext.read_file(&mut dst, Path::new("/top.bin")).unwrap();
    let mut v = Vec::new();
    r.read_to_end(&mut v).unwrap();
    drop(r);
    assert_eq!(v, vec![7u8; 5000]);
    // /sub/hello.txt
    let mut r = ext
        .read_file(&mut dst, Path::new("/sub/hello.txt"))
        .unwrap();
    let mut v = Vec::new();
    r.read_to_end(&mut v).unwrap();
    drop(r);
    assert_eq!(v, b"hello ramfs");
    // /sub/link symlink target preserved.
    assert_eq!(
        ext.read_symlink(&mut dst, Path::new("/sub/link")).unwrap(),
        Path::new("hello.txt")
    );
}
