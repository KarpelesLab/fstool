#![cfg(unix)]
//! littlefs conformance against the reference C implementation.
//!
//! The checks here drive `littlefs-python`, which wraps the upstream C
//! `lfs.c` — so "the reference implementation mounts it" means exactly
//! that. Every test skips (with a note) when no Python with the module
//! installed is available, so the suite stays green on hosts without it:
//!
//! ```sh
//! pip install littlefs-python
//! # or point the tests at a specific interpreter:
//! FSTOOL_LITTLEFS_PYTHON=/path/to/venv/bin/python cargo test --test littlefs_external
//! ```
//!
//! Four directions are covered: images we write must mount and read
//! correctly under littlefs; images littlefs writes must read correctly
//! under fstool; littlefs must be able to *keep writing* to an image we
//! produced (which exercises the erased-state and forward-CRC rules that
//! decide whether a metadata block can be appended to); and we must be able
//! to keep writing to an image it produced.

use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use fstool::block::{BlockDevice, FileBackend};
use fstool::fs::littlefs::{DISK_VERSION_2_0, LittleFs, LittleFsFormatOpts};
use fstool::fs::{EntryKind, FileMeta, FileSource, Filesystem, OpenFlags};
use tempfile::TempDir;

/// Find an interpreter that can `import littlefs`.
fn python() -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(p) = std::env::var("FSTOOL_LITTLEFS_PYTHON") {
        candidates.push(p.into());
    }
    candidates.push("python3".into());
    candidates.push("python".into());
    candidates.into_iter().find(|p| {
        Command::new(p)
            .args(["-c", "import littlefs"])
            .output()
            .is_ok_and(|o| o.status.success())
    })
}

/// The helper script every test drives. Geometry is read out of the image's
/// own superblock so the harness never has to be told it.
const SCRIPT: &str = r#"
import sys, struct
from littlefs import LittleFS
from littlefs.context import UserContext

def fnv(data):
    h = 0xcbf29ce484222325
    for b in data:
        h = ((h ^ b) * 0x100000001b3) & 0xffffffffffffffff
    return h

def load(path):
    data = bytearray(open(path, 'rb').read())
    assert data[8:16] == b'littlefs', 'no littlefs magic'
    bs, bc = struct.unpack('<II', bytes(data[24:32]))
    ctx = UserContext(len(data))
    ctx.buffer = data
    # Caches have to fit inside a block, so derive them from the image
    # rather than assuming the 4 KiB default geometry.
    c = min(256, bs)
    fs = LittleFS(context=ctx, block_size=bs, block_count=bc,
                  read_size=c, prog_size=c, cache_size=c, mount=False)
    fs.mount()
    return fs, data

def save(path, data):
    open(path, 'wb').write(bytes(data))

def manifest(fs):
    out = []
    for root, dirs, files in fs.walk('/'):
        base = '' if root == '/' else root
        for d in sorted(dirs):
            out.append('d %s/%s' % (base, d))
        for f in sorted(files):
            p = '%s/%s' % (base, f)
            body = fs.open(p, 'rb').read()
            out.append('f %s %d %d' % (p, len(body), fnv(body)))
    return sorted(out)

cmd, path = sys.argv[1], sys.argv[2]

if cmd == 'manifest':
    fs, _ = load(path)
    print('\n'.join(manifest(fs)))

elif cmd == 'create':
    # A tree written entirely by the reference implementation.
    bs, bc = 4096, 128
    fs = LittleFS(block_size=bs, block_count=bc, prog_size=256, read_size=256)
    with fs.open('/greeting.txt', 'w') as f:
        f.write('written by littlefs\n')
    fs.mkdir('/data')
    fs.mkdir('/data/inner')
    with fs.open('/data/blob.bin', 'wb') as f:
        f.write(bytes((i * 7) % 251 for i in range(9000)))
    with fs.open('/data/inner/tiny', 'w') as f:
        f.write('t')
    for i in range(40):
        with fs.open('/entry%03d' % i, 'w') as f:
            f.write('body %d' % i)
    fs.setattr('/greeting.txt', 7, b'attrvalue')
    save(path, fs.context.buffer)

elif cmd == 'mutate':
    # Keep writing to an image fstool produced.
    fs, data = load(path)
    with fs.open('/added-by-lfs.txt', 'w') as f:
        f.write('appended by the reference implementation\n')
    fs.mkdir('/lfsdir')
    with fs.open('/lfsdir/payload.bin', 'wb') as f:
        f.write(bytes(range(256)) * 40)
    fs.remove('/README')
    fs.unmount()
    save(path, data)

elif cmd == 'check':
    # littlefs's own traversal, which walks every metadata pair and every
    # file's skip-list, plus the consistency pass it runs before writing.
    fs, _ = load(path)
    fs.fs_mkconsistent()
    print('used %d' % fs.used_block_count)
    print('\n'.join(manifest(fs)))

else:
    raise SystemExit('unknown command %r' % cmd)
"#;

/// FNV-1a, matching the helper script's `fnv`.
fn fnv(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in data {
        h = (h ^ *b as u64).wrapping_mul(0x100_0000_01b3);
    }
    h
}

struct Harness {
    python: PathBuf,
    dir: TempDir,
    script: PathBuf,
}

impl Harness {
    /// `None` when littlefs-python isn't installed — the caller skips.
    fn new() -> Option<Self> {
        let python = python()?;
        let dir = TempDir::new().ok()?;
        let script = dir.path().join("lfs_ref.py");
        std::fs::write(&script, SCRIPT).ok()?;
        Some(Self {
            python,
            dir,
            script,
        })
    }

    fn image(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// Run the helper script, returning its stdout. Panics with the script's
    /// stderr on failure — a mount error there is the finding, not noise.
    fn run(&self, cmd: &str, image: &Path) -> String {
        let out = Command::new(&self.python)
            .arg(&self.script)
            .arg(cmd)
            .arg(image)
            .output()
            .expect("failed to run the littlefs reference helper");
        assert!(
            out.status.success(),
            "littlefs reference `{cmd}` failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }
}

/// Deterministic payload of `len` bytes.
fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 7) % 251) as u8).collect()
}

fn create_image(path: &Path, bytes: u64, opts: &LittleFsFormatOpts) -> (FileBackend, LittleFs) {
    let mut dev = FileBackend::create(path, bytes).unwrap();
    let fs = LittleFs::format(&mut dev, opts).unwrap();
    (dev, fs)
}

fn put(fs: &mut LittleFs, dev: &mut dyn BlockDevice, path: &str, body: &[u8]) {
    fs.create_file(
        dev,
        Path::new(path),
        FileSource::Reader {
            reader: Box::new(std::io::Cursor::new(body.to_vec())),
            len: body.len() as u64,
        },
        FileMeta::default(),
    )
    .unwrap();
}

fn slurp(fs: &mut LittleFs, dev: &mut dyn BlockDevice, path: &str) -> Vec<u8> {
    let mut out = Vec::new();
    fs.read_file(dev, Path::new(path))
        .unwrap()
        .read_to_end(&mut out)
        .unwrap();
    out
}

/// Walk an fstool-mounted volume into the same manifest the helper script
/// prints, so the two implementations can be compared line for line.
fn manifest(fs: &mut LittleFs, dev: &mut dyn BlockDevice) -> Vec<String> {
    fn walk(fs: &mut LittleFs, dev: &mut dyn BlockDevice, dir: &str, out: &mut Vec<String>) {
        let path = if dir.is_empty() { "/" } else { dir };
        let mut entries = fs.list(dev, Path::new(path)).unwrap();
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        for e in &entries {
            let child = format!("{dir}/{}", e.name);
            match e.kind {
                EntryKind::Dir => {
                    out.push(format!("d {child}"));
                    walk(fs, dev, &child, out);
                }
                _ => {
                    let body = slurp(fs, dev, &child);
                    out.push(format!("f {child} {} {}", body.len(), fnv(&body)));
                }
            }
        }
    }
    let mut out = Vec::new();
    walk(fs, dev, "", &mut out);
    out.sort();
    out
}

/// Build the tree both directions of the round trip use.
fn build_reference_tree(fs: &mut LittleFs, dev: &mut dyn BlockDevice) {
    put(fs, dev, "/README", b"written by fstool\n");
    fs.create_dir(dev, Path::new("/etc"), FileMeta::default())
        .unwrap();
    put(fs, dev, "/etc/motd", b"stay curious\n");
    fs.create_dir(dev, Path::new("/etc/deep"), FileMeta::default())
        .unwrap();
    fs.create_dir(dev, Path::new("/etc/deep/nested"), FileMeta::default())
        .unwrap();
    put(fs, dev, "/etc/deep/nested/leaf", &pattern(3));
    // Well past the inline limit: a multi-block CTZ skip-list.
    put(fs, dev, "/big.bin", &pattern(40_000));
    // Enough entries to split the directory across metadata pairs.
    fs.create_dir(dev, Path::new("/many"), FileMeta::default())
        .unwrap();
    for i in 0..80 {
        put(
            fs,
            dev,
            &format!("/many/file{i:03}"),
            format!("entry number {i}").as_bytes(),
        );
    }
    fs.set_xattr(dev, Path::new("/README"), "user.littlefs.7", b"attrvalue")
        .unwrap();
    fs.flush(dev).unwrap();
}

#[test]
fn our_images_mount_in_the_reference_implementation() {
    let Some(h) = Harness::new() else {
        eprintln!("skipping: no python with littlefs-python installed");
        return;
    };
    let img = h.image("written-by-fstool.img");
    let (mut dev, mut fs) = create_image(&img, 4 * 1024 * 1024, &LittleFsFormatOpts::default());
    build_reference_tree(&mut fs, &mut dev);
    let ours = manifest(&mut fs, &mut dev);
    let our_blocks = fs.used_blocks(&mut dev).unwrap();
    drop(dev);

    let out = h.run("check", &img);
    let mut lines = out.lines();
    let their_blocks: u32 = lines
        .next()
        .and_then(|l| l.strip_prefix("used "))
        .and_then(|n| n.parse().ok())
        .expect("check prints the block count first");
    let theirs: Vec<String> = lines.map(|s| s.to_string()).collect();
    assert_eq!(
        theirs, ours,
        "the reference implementation and fstool disagree about the image"
    );
    // Both sides traverse the volume to decide which blocks are live; if
    // they disagree, one of them is leaking or about to reuse a live block.
    assert_eq!(
        their_blocks, our_blocks,
        "block accounting differs between the implementations"
    );
    // Spot-check the shape rather than trusting agreement alone.
    assert!(theirs.iter().any(|l| l.starts_with("f /big.bin 40000 ")));
    assert!(theirs.contains(&"d /etc/deep/nested".to_string()));
    assert_eq!(
        theirs.iter().filter(|l| l.starts_with("f /many/")).count(),
        80
    );
}

#[test]
fn version_2_0_images_mount_in_the_reference_implementation() {
    let Some(h) = Harness::new() else {
        eprintln!("skipping: no python with littlefs-python installed");
        return;
    };
    let img = h.image("v2_0.img");
    let opts = LittleFsFormatOpts {
        disk_version: DISK_VERSION_2_0,
        block_size: 512,
        prog_size: 128,
        ..LittleFsFormatOpts::default()
    };
    let (mut dev, mut fs) = create_image(&img, 1024 * 1024, &opts);
    put(&mut fs, &mut dev, "/a.txt", b"small");
    put(&mut fs, &mut dev, "/b.bin", &pattern(20_000));
    fs.flush(&mut dev).unwrap();
    let ours = manifest(&mut fs, &mut dev);
    drop(dev);

    let theirs: Vec<String> = h
        .run("manifest", &img)
        .lines()
        .map(|s| s.to_string())
        .collect();
    assert_eq!(theirs, ours);
}

#[test]
fn every_geometry_mounts_in_the_reference_implementation() {
    let Some(h) = Harness::new() else {
        eprintln!("skipping: no python with littlefs-python installed");
        return;
    };
    // Block size sets the inline threshold, the metadata split point and
    // every block's CTZ payload, so each geometry is a different layout
    // to agree on — and small blocks are where the margins are tightest.
    for (block_size, prog_size) in [(128u32, 8u32), (512, 128), (1024, 64), (16384, 512)] {
        let img = h.image(&format!("geom-{block_size}-{prog_size}.img"));
        let opts = LittleFsFormatOpts {
            block_size,
            prog_size,
            ..LittleFsFormatOpts::default()
        };
        let (mut dev, mut fs) = create_image(&img, 4 * 1024 * 1024, &opts);
        fs.create_dir(&mut dev, Path::new("/d"), FileMeta::default())
            .unwrap();
        put(&mut fs, &mut dev, "/d/tiny", b"x");
        put(
            &mut fs,
            &mut dev,
            "/d/spans-blocks",
            &pattern(block_size as usize * 5 + 37),
        );
        // Enough entries that the directory has to split at any geometry.
        for i in 0..40 {
            put(
                &mut fs,
                &mut dev,
                &format!("/e{i:02}"),
                format!("{i}").as_bytes(),
            );
        }
        fs.flush(&mut dev).unwrap();
        let ours = manifest(&mut fs, &mut dev);
        drop(dev);

        let theirs: Vec<String> = h
            .run("manifest", &img)
            .lines()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            theirs, ours,
            "disagreement at block_size={block_size} prog_size={prog_size}"
        );
        assert_eq!(theirs.len(), 43, "at block_size={block_size}");
    }
}

#[test]
fn reference_images_read_back_identically() {
    let Some(h) = Harness::new() else {
        eprintln!("skipping: no python with littlefs-python installed");
        return;
    };
    let img = h.image("written-by-littlefs.img");
    h.run("create", &img);
    let theirs: Vec<String> = h
        .run("manifest", &img)
        .lines()
        .map(|s| s.to_string())
        .collect();

    let mut dev = FileBackend::open(&img).unwrap();
    let mut fs = LittleFs::open(&mut dev).unwrap();
    assert_eq!(fs.version(), (2, 1));
    assert_eq!(manifest(&mut fs, &mut dev), theirs);

    // Contents, not just checksums, and the user attribute it set.
    assert_eq!(
        slurp(&mut fs, &mut dev, "/greeting.txt"),
        b"written by littlefs\n"
    );
    assert_eq!(
        slurp(&mut fs, &mut dev, "/data/blob.bin"),
        pattern(9000).as_slice()
    );
    let attrs = fs
        .list_xattrs(&mut dev, Path::new("/greeting.txt"))
        .unwrap();
    assert_eq!(attrs.len(), 1);
    assert_eq!(attrs[0].name, "user.littlefs.7");
    assert_eq!(attrs[0].value, b"attrvalue");
}

#[test]
fn the_reference_implementation_can_keep_writing_to_our_images() {
    let Some(h) = Harness::new() else {
        eprintln!("skipping: no python with littlefs-python installed");
        return;
    };
    let img = h.image("handed-over.img");
    let (mut dev, mut fs) = create_image(&img, 4 * 1024 * 1024, &LittleFsFormatOpts::default());
    build_reference_tree(&mut fs, &mut dev);
    drop(dev);

    // littlefs adds, removes and creates a directory in our image.
    h.run("mutate", &img);

    let mut dev = FileBackend::open(&img).unwrap();
    let mut fs = LittleFs::open(&mut dev).unwrap();
    assert_eq!(
        slurp(&mut fs, &mut dev, "/added-by-lfs.txt"),
        b"appended by the reference implementation\n"
    );
    let payload = slurp(&mut fs, &mut dev, "/lfsdir/payload.bin");
    assert_eq!(payload.len(), 256 * 40);
    assert_eq!(&payload[..4], &[0, 1, 2, 3]);
    // Its removal is visible to us, and everything else survived.
    assert!(
        fs.list(&mut dev, Path::new("/"))
            .unwrap()
            .iter()
            .all(|e| e.name != "README")
    );
    assert_eq!(slurp(&mut fs, &mut dev, "/big.bin"), pattern(40_000));
    assert_eq!(fs.list(&mut dev, Path::new("/many")).unwrap().len(), 80);
}

#[test]
fn in_place_edits_of_large_files_are_readable_by_the_reference() {
    let Some(h) = Harness::new() else {
        eprintln!("skipping: no python with littlefs-python installed");
        return;
    };
    let img = h.image("patched.img");
    let (mut dev, mut fs) = create_image(&img, 4 * 1024 * 1024, &LittleFsFormatOpts::default());
    // Long enough to need several levels of skip pointers (index 20+ at a
    // 4 KiB block size), so a rewrite has to rebuild them correctly.
    let original = pattern(120_000);
    put(&mut fs, &mut dev, "/big.bin", &original);
    put(&mut fs, &mut dev, "/shrink.bin", &pattern(60_000));

    let mut expected = original.clone();
    {
        // A patch in the middle: blocks before it must survive untouched
        // while everything after is rewritten.
        let mut handle = fs
            .open_file_rw(&mut dev, Path::new("/big.bin"), OpenFlags::default(), None)
            .unwrap();
        handle.seek(std::io::SeekFrom::Start(50_000)).unwrap();
        handle.write_all(b"PATCHED-IN-PLACE").unwrap();
        handle.sync().unwrap();
    }
    expected[50_000..50_016].copy_from_slice(b"PATCHED-IN-PLACE");

    // An append past the end, and a truncation of the other file.
    {
        let mut handle = fs
            .open_file_rw(
                &mut dev,
                Path::new("/big.bin"),
                OpenFlags {
                    append: true,
                    ..OpenFlags::default()
                },
                None,
            )
            .unwrap();
        handle.write_all(&pattern(5_000)).unwrap();
        handle.sync().unwrap();
    }
    expected.extend_from_slice(&pattern(5_000));
    fs.truncate(&mut dev, Path::new("/shrink.bin"), 21_000)
        .unwrap();
    fs.flush(&mut dev).unwrap();
    assert_eq!(slurp(&mut fs, &mut dev, "/big.bin"), expected);
    drop(dev);

    let out = h.run("check", &img);
    assert!(
        out.contains(&format!("f /big.bin {} {}", expected.len(), fnv(&expected))),
        "reference read of the patched file differs:\n{out}"
    );
    let shrunk = pattern(60_000)[..21_000].to_vec();
    assert!(
        out.contains(&format!("f /shrink.bin 21000 {}", fnv(&shrunk))),
        "reference read of the truncated file differs:\n{out}"
    );
}

#[test]
fn we_can_keep_writing_to_reference_images() {
    let Some(h) = Harness::new() else {
        eprintln!("skipping: no python with littlefs-python installed");
        return;
    };
    let img = h.image("taken-over.img");
    h.run("create", &img);

    {
        let mut dev = FileBackend::open(&img).unwrap();
        let mut fs = LittleFs::open(&mut dev).unwrap();
        put(&mut fs, &mut dev, "/added-by-fstool.txt", b"our turn\n");
        put(&mut fs, &mut dev, "/data/second.bin", &pattern(12_345));
        fs.create_dir(&mut dev, Path::new("/data/more"), FileMeta::default())
            .unwrap();
        put(&mut fs, &mut dev, "/data/more/deep", b"deep");
        fs.remove(&mut dev, Path::new("/data/inner/tiny")).unwrap();
        fs.remove(&mut dev, Path::new("/data/inner")).unwrap();
        fs.remove(&mut dev, Path::new("/entry007")).unwrap();
        fs.flush(&mut dev).unwrap();
    }

    let out = h.run("check", &img);
    assert!(out.contains("f /added-by-fstool.txt 9 "), "{out}");
    assert!(out.contains("f /data/more/deep 4 "), "{out}");
    assert!(
        out.contains(&format!(
            "f /data/second.bin 12345 {}",
            fnv(&pattern(12_345))
        )),
        "{out}"
    );
    assert!(!out.contains("/data/inner"), "{out}");
    assert!(!out.contains("/entry007"), "{out}");
    // The files it wrote are still intact under its own reader.
    assert!(
        out.contains(&format!("f /data/blob.bin 9000 {}", fnv(&pattern(9000)))),
        "{out}"
    );
}
