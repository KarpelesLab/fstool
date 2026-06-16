//! Regression for GitHub #29: `Ext::rename` / `remove` must find entries in
//! directory blocks past the first. `unlink_dir_entry` used to scan only the
//! first 4 KiB block, so the ~101st entry onward could not be renamed/removed.
#![cfg(unix)]

use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

use fstool::block::MemoryBackend;
use fstool::fs::ext::{Ext, FormatOpts, FsKind};
use fstool::fs::{FileMeta, FileSource, Filesystem, FilesystemFactory, OpenFlags};

#[test]
fn rename_in_large_dir() {
    let size = 256u64 << 20;
    let mut dev = MemoryBackend::new(size);
    let block_size = 4096u32;
    let blocks_count = (size / u64::from(block_size)) as u32;
    let mut fs: Box<dyn Filesystem> = Box::new(
        Ext::format(
            &mut dev,
            &FormatOpts {
                kind: FsKind::Ext4,
                block_size,
                blocks_count,
                inodes_count: (blocks_count / 4).max(16),
                ..Default::default()
            },
        )
        .unwrap(),
    );

    fs.create_dir(&mut dev, Path::new("/d"), FileMeta::with_mode(0o755))
        .unwrap();

    let mut first_fail = None;
    for i in 0..200 {
        let tmp = format!("/d/.apk.{i:08x}");
        let fin = format!("/d/file{i:04}");
        fs.create_file(
            &mut dev,
            Path::new(&tmp),
            FileSource::Zero(0),
            FileMeta::with_mode(0o755),
        )
        .unwrap_or_else(|e| panic!("create {tmp} (#{i}): {e}"));
        {
            let mut h = fs
                .open_file_rw(
                    &mut dev,
                    Path::new(&tmp),
                    OpenFlags {
                        create: false,
                        truncate: false,
                        append: false,
                    },
                    None,
                )
                .unwrap_or_else(|e| panic!("open {tmp} (#{i}): {e}"));
            h.seek(SeekFrom::Start(0)).unwrap();
            h.write_all(&vec![0xab; 1024]).unwrap();
        }
        if let Err(e) = fs.rename(&mut dev, Path::new(&tmp), Path::new(&fin)) {
            eprintln!("RENAME FAILED at #{i}: {tmp} -> {fin}: {e}");
            first_fail.get_or_insert(i);
        }
    }
    assert!(
        first_fail.is_none(),
        "first rename failure at #{first_fail:?}"
    );

    // All 200 final names must now be present, and none of the temp names.
    let names: Vec<String> = fs
        .list(&mut dev, Path::new("/d"))
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    for i in 0..200 {
        let fin = format!("file{i:04}");
        assert!(names.contains(&fin), "{fin} missing after rename");
    }
    assert!(
        !names.iter().any(|n| n.starts_with(".apk.")),
        "a temp name survived the rename"
    );

    // Cross-check the on-disk image with e2fsck.
    fs.flush(&mut dev).unwrap();
    if let Some(dir) = which_e2fsck() {
        let tmpf = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmpf.path(), dev.as_slice()).unwrap();
        let out = std::process::Command::new(dir)
            .args(["-fn"])
            .arg(tmpf.path())
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "e2fsck not clean after large-dir renames:\n{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    } else {
        eprintln!("skipping e2fsck oracle: not installed");
    }
}

fn which_e2fsck() -> Option<String> {
    let out = std::process::Command::new("sh")
        .arg("-c")
        .arg("command -v e2fsck")
        .output()
        .ok()?;
    if out.status.success() {
        Some(String::from_utf8(out.stdout).ok()?.trim().to_string())
    } else {
        None
    }
}
