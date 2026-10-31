//! Native macOS acceptance test for the APFS formatter: an
//! fstool-formatted container must not merely pass `fsck_apfs`, the
//! kernel must mount it, hand back exactly what fstool wrote, accept
//! new writes, and leave a container both macOS and fstool can reopen.
//!
//! Every test builds a raw disk the way a real one looks — a GPT with a
//! single APFS partition (type `7C3457EF-0000-11AA-AA11-00306543ECAC`)
//! at LBA 2048 holding an fstool-formatted container — attaches the
//! whole disk with `hdiutil attach -imagekey
//! diskimage-class=CRawDiskImage -nomount`, and mounts the volume the
//! kernel synthesizes from the partition. One test probes a bare
//! container (no partition map) separately.
//!
//! The tests run on macOS only; elsewhere (or without `hdiutil`,
//! `diskutil` and `fsck_apfs`) they print `skipping: …` and pass.
//! Every attach is owned by a guard that detaches it on drop, so a
//! failing assertion never leaves a disk image attached.

#![cfg(all(unix, feature = "apfs"))]

use std::collections::BTreeMap;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

use fstool::block::{BlockDevice, FileBackend, SlicedBackend};
use fstool::fs::apfs::Apfs;
use fstool::fs::apfs::write::ApfsWriter;
use fstool::part::{Gpt, Partition, PartitionKind, PartitionTable};

/// GPT partition type of an APFS container.
const APFS_PART_TYPE: &str = "7C3457EF-0000-11AA-AA11-00306543ECAC";
/// `content-hint` hdiutil reports for an APFS volume.
const APFS_VOLUME_HINT: &str = "41504653-0000-11AA-AA11-00306543ECAC";
/// First LBA of the APFS partition.
const PART_START_LBA: u64 = 2048;
const BLOCK_SIZE: u32 = 4096;

fn tools_available() -> bool {
    if !cfg!(target_os = "macos") {
        eprintln!("skipping: native APFS mounting requires macOS");
        return false;
    }
    for tool in ["hdiutil", "diskutil", "fsck_apfs", "xattr"] {
        let found = Command::new("sh")
            .arg("-c")
            .arg(format!("command -v {tool}"))
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !found {
            eprintln!("skipping: {tool} not found on PATH");
            return false;
        }
    }
    true
}

fn run(cmd: &mut Command) -> Output {
    let out = cmd
        .output()
        .unwrap_or_else(|e| panic!("could not run {cmd:?}: {e}"));
    if !out.status.success() {
        panic!(
            "{cmd:?} failed ({:?}):\nstdout:\n{}\nstderr:\n{}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    out
}

// ───────────────────────────── payload ─────────────────────────────

/// What the volume should hold, keyed by path relative to its root.
#[derive(Default, Clone)]
struct Tree {
    files: BTreeMap<String, Vec<u8>>,
    dirs: Vec<String>,
    symlinks: BTreeMap<String, String>,
    /// (path, xattr name) → value.
    xattrs: BTreeMap<(String, String), Vec<u8>>,
}

fn pattern(len: usize, seed: u32) -> Vec<u8> {
    let mut x = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

/// A payload that exercises every record kind the writer emits and is
/// large enough to need multi-leaf fs-tree, omap and extent-ref trees.
fn fstool_payload() -> Tree {
    let mut t = Tree::default();
    t.files
        .insert("hello.txt".into(), b"hello from fstool\n".to_vec());
    t.files.insert("empty".into(), Vec::new());
    t.files.insert("big.bin".into(), pattern(1_300_000, 1));
    t.dirs.push("docs".into());
    t.dirs.push("docs/nested".into());
    t.files
        .insert("docs/nested/deep.txt".into(), b"deep\n".to_vec());
    t.files.insert("docs/odd-size.bin".into(), pattern(4097, 2));
    t.dirs.push("many".into());
    for i in 0..300 {
        t.files.insert(
            format!("many/file-{i:04}.txt"),
            format!("file number {i}\n").into_bytes(),
        );
    }
    t.symlinks.insert("link".into(), "hello.txt".into());
    t.symlinks
        .insert("docs/up".into(), "../docs/nested/deep.txt".into());
    t.xattrs.insert(
        ("hello.txt".into(), "user.note".into()),
        b"xattr on a file".to_vec(),
    );
    t.xattrs.insert(
        ("docs".into(), "user.dir-note".into()),
        b"xattr on a directory".to_vec(),
    );
    t.xattrs
        .insert(("docs".into(), "user.binary".into()), vec![0, 1, 2, 255]);
    t
}

/// What the native write session adds on top of `existing` — including,
/// when there is one, a file inside a directory fstool created.
fn native_payload(existing: &Tree) -> Tree {
    let mut t = Tree::default();
    t.files
        .insert("native.txt".into(), b"written by macOS\n".to_vec());
    t.dirs.push("native-dir".into());
    t.files
        .insert("native-dir/blob.bin".into(), pattern(300_000, 3));
    if let Some(d) = existing.dirs.last() {
        t.files.insert(
            format!("{d}/native-in-fstool-dir.txt"),
            b"new file in an fstool directory\n".to_vec(),
        );
    }
    t.symlinks
        .insert("native-link".into(), "native-dir/blob.bin".into());
    t.xattrs.insert(
        ("native.txt".into(), "user.native".into()),
        b"native xattr".to_vec(),
    );
    t
}

fn merge(a: &Tree, b: &Tree) -> Tree {
    let mut t = a.clone();
    t.files.extend(b.files.clone());
    t.dirs.extend(b.dirs.clone());
    t.symlinks.extend(b.symlinks.clone());
    t.xattrs.extend(b.xattrs.clone());
    t
}

// ───────────────────────────── images ──────────────────────────────

/// Create a raw disk of `mib` MiB at `path`: GPT, one APFS partition
/// at LBA 2048, fstool container inside populated with `tree`.
fn build_disk(path: &Path, mib: u64, tree: &Tree) {
    let total = mib * 1024 * 1024;
    let mut dev = FileBackend::create(path, total).unwrap();
    let (start, len) = partition_extent(total);
    let apfs = uuid::Uuid::parse_str(APFS_PART_TYPE).unwrap();
    let part = Partition {
        start_lba: start / 512,
        size_lba: len / 512,
        kind: PartitionKind::Gpt(apfs),
        name: Some("fstool APFS".into()),
        ..Partition::new(0, 0, PartitionKind::Gpt(apfs))
    };
    Gpt::build(vec![part]).unwrap().write(&mut dev).unwrap();
    {
        let mut slice = SlicedBackend::new(&mut dev, start, len).unwrap();
        format_container(&mut slice, len / BLOCK_SIZE as u64, "FSTOOLVOL", tree);
    }
    dev.sync().unwrap();
}

/// Byte offset and length of the APFS partition on a `total`-byte disk:
/// from LBA 2048 to just before the backup GPT, whole APFS blocks.
fn partition_extent(total: u64) -> (u64, u64) {
    let start = PART_START_LBA * 512;
    let end = total - 34 * 512;
    let len = (end - start) / BLOCK_SIZE as u64 * BLOCK_SIZE as u64;
    (start, len)
}

fn format_container(dev: &mut dyn BlockDevice, blocks: u64, name: &str, tree: &Tree) {
    let mut w = ApfsWriter::new(dev, blocks, BLOCK_SIZE, name).unwrap();
    let mut oids: BTreeMap<String, u64> = BTreeMap::new();
    oids.insert(String::new(), 2);
    let parent_of = |p: &str| -> (String, String) {
        match p.rsplit_once('/') {
            Some((d, n)) => (d.to_string(), n.to_string()),
            None => (String::new(), p.to_string()),
        }
    };
    for d in &tree.dirs {
        let (parent, leaf) = parent_of(d);
        let oid = w.add_dir(oids[&parent], &leaf, 0o755).unwrap();
        oids.insert(d.clone(), oid);
    }
    for (p, body) in &tree.files {
        let (parent, leaf) = parent_of(p);
        let oid = w
            .add_file_from_reader(
                oids[&parent],
                &leaf,
                0o644,
                &mut Cursor::new(body),
                body.len() as u64,
            )
            .unwrap();
        oids.insert(p.clone(), oid);
    }
    for (p, target) in &tree.symlinks {
        let (parent, leaf) = parent_of(p);
        let oid = w.add_symlink(oids[&parent], &leaf, 0o755, target).unwrap();
        oids.insert(p.clone(), oid);
    }
    for ((p, name), value) in &tree.xattrs {
        w.add_xattr(oids[p], name, value).unwrap();
    }
    w.finish().unwrap();
}

// ──────────────────────────── attaching ────────────────────────────

/// An attached disk image. Dropping it unmounts and detaches.
struct Attached {
    image: PathBuf,
    whole: String,
    /// The APFS volume's device node, e.g. `/dev/disk7s1`.
    volume: String,
    /// The APFS container's backing node (the partition, or the whole
    /// disk for a bare container) — what `fsck_apfs` checks.
    store: String,
    mount_point: Option<PathBuf>,
}

impl Attached {
    fn attach(image: &Path, partitioned: bool) -> Attached {
        let out = run(Command::new("hdiutil")
            .args(["attach", "-imagekey", "diskimage-class=CRawDiskImage"])
            .args(["-nomount", "-plist"])
            .arg(image));
        let plist = String::from_utf8_lossy(&out.stdout).into_owned();
        let entities = parse_entities(&plist);
        let whole = entities
            .iter()
            .map(|(dev, _)| dev.clone())
            .find(|d| !d.trim_start_matches("/dev/disk").contains('s'))
            .unwrap_or_else(|| panic!("no whole-disk node in hdiutil output:\n{plist}"));
        // Own the attach before anything else can fail.
        let mut a = Attached {
            image: image.to_path_buf(),
            store: if partitioned {
                format!("{whole}s1")
            } else {
                whole.clone()
            },
            whole,
            volume: String::new(),
            mount_point: None,
        };
        a.volume = match entities.iter().find(|(_, hint)| hint == APFS_VOLUME_HINT) {
            Some((dev, _)) => dev.clone(),
            None => a.wait_for_volume(),
        };
        a
    }

    /// The kernel synthesizes the container disk asynchronously; poll
    /// `diskutil list` for an APFS volume whose physical store is ours.
    fn wait_for_volume(&self) -> String {
        let store = self.store.trim_start_matches("/dev/").to_string();
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let out = Command::new("diskutil").arg("list").output().unwrap();
            let text = String::from_utf8_lossy(&out.stdout);
            for section in text.split("\n\n") {
                if !section.lines().any(|l| {
                    l.contains("Physical Store") && l.split_whitespace().any(|w| w == store)
                }) {
                    continue;
                }
                if let Some(l) = section.lines().find(|l| l.contains("APFS Volume")) {
                    let id = l.split_whitespace().last().unwrap();
                    return format!("/dev/{id}");
                }
            }
            if Instant::now() > deadline {
                panic!(
                    "macOS never exposed an APFS volume for {} (container rejected?)\n{text}\n{}",
                    self.store,
                    String::from_utf8_lossy(
                        &Command::new("diskutil")
                            .args(["apfs", "list"])
                            .output()
                            .unwrap()
                            .stdout
                    )
                );
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    fn mount(&mut self, at: &Path) -> PathBuf {
        std::fs::create_dir_all(at).unwrap();
        let out = Command::new("diskutil")
            .args(["mount", "-mountPoint"])
            .arg(at)
            .arg(&self.volume)
            .output()
            .unwrap();
        if !out.status.success() {
            panic!(
                "macOS refused to mount {}:\nstdout:\n{}\nstderr:\n{}\nkernel log:\n{}",
                self.volume,
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr),
                recent_apfs_log()
            );
        }
        self.mount_point = Some(at.to_path_buf());
        at.to_path_buf()
    }

    fn unmount(&mut self) {
        if self.mount_point.take().is_some() {
            run(Command::new("diskutil").arg("unmount").arg(&self.volume));
        }
    }

    /// `fsck_apfs -n` must find nothing to repair: exit 0 and no
    /// `warning:` / `error:` lines.
    fn fsck(&self, when: &str) {
        let out = Command::new("fsck_apfs")
            .arg("-n")
            .arg(&self.store)
            .output()
            .unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let complaints: Vec<&str> = text
            .lines()
            .filter(|l| l.starts_with("warning:") || l.starts_with("error:"))
            .collect();
        assert!(
            out.status.success() && complaints.is_empty(),
            "fsck_apfs -n {} ({when}) is not clean ({:?}):\n{text}",
            self.store,
            out.status
        );
    }

    fn detach(mut self) {
        self.detach_now();
    }

    fn detach_now(&mut self) {
        if self.whole.is_empty() {
            return;
        }
        self.mount_point = None;
        for attempt in 0..10 {
            let mut cmd = Command::new("hdiutil");
            cmd.arg("detach");
            if attempt >= 5 {
                cmd.arg("-force");
            }
            if let Ok(o) = cmd.arg(&self.whole).output()
                && o.status.success()
            {
                self.whole.clear();
                return;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        eprintln!(
            "warn: could not detach {} ({})",
            self.whole,
            self.image.display()
        );
    }
}

impl Drop for Attached {
    fn drop(&mut self) {
        self.detach_now();
    }
}

/// `(dev-entry, content-hint)` pairs from `hdiutil attach -plist`.
fn parse_entities(plist: &str) -> Vec<(String, String)> {
    let string_after = |chunk: &str, key: &str| -> Option<String> {
        let at = chunk.find(&format!("<key>{key}</key>"))?;
        let rest = &chunk[at..];
        let s = rest.find("<string>")? + "<string>".len();
        let e = rest[s..].find("</string>")? + s;
        Some(rest[s..e].trim().to_string())
    };
    plist
        .split("<dict>")
        .filter_map(|chunk| {
            Some((
                string_after(chunk, "dev-entry")?,
                string_after(chunk, "content-hint").unwrap_or_default(),
            ))
        })
        .collect()
}

fn recent_apfs_log() -> String {
    Command::new("/usr/bin/log")
        .args(["show", "--last", "1m", "--style", "compact"])
        .args([
            "--predicate",
            "process == \"kernel\" AND eventMessage CONTAINS[c] \"apfs\"",
        ])
        .output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter(|l| !l.contains("tx_flush"))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default()
}

fn assert_detached(image: &Path) {
    let out = run(Command::new("hdiutil").arg("info"));
    let info = String::from_utf8_lossy(&out.stdout);
    let canon = std::fs::canonicalize(image).unwrap_or_else(|_| image.to_path_buf());
    assert!(
        !info.contains(&*image.to_string_lossy()) && !info.contains(&*canon.to_string_lossy()),
        "{} is still attached:\n{info}",
        image.display()
    );
}

// ─────────────────────────── verification ──────────────────────────

/// Read `tree` back through the macOS VFS rooted at `root`.
fn verify_native(root: &Path, tree: &Tree) {
    for d in &tree.dirs {
        let md = std::fs::symlink_metadata(root.join(d)).unwrap();
        assert!(md.is_dir(), "{d} is not a directory natively");
    }
    for (p, body) in &tree.files {
        let got = std::fs::read(root.join(p)).unwrap_or_else(|e| panic!("read {p}: {e}"));
        assert!(got == *body, "{p}: macOS returned different bytes");
    }
    for (p, target) in &tree.symlinks {
        let got = std::fs::read_link(root.join(p)).unwrap_or_else(|e| panic!("readlink {p}: {e}"));
        assert_eq!(got, Path::new(target), "{p}: wrong symlink target");
    }
    for ((p, name), value) in &tree.xattrs {
        let out = run(Command::new("xattr").arg("-px").arg(name).arg(root.join(p)));
        let hex: String = String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .collect();
        let got: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        assert_eq!(got, *value, "{p}: xattr {name} differs natively");
    }
    // Directory listings hold exactly the expected children (ignoring
    // the `.fseventsd` macOS adds at the root).
    let mut expected: BTreeMap<String, Vec<String>> = BTreeMap::new();
    expected.entry(String::new()).or_default();
    for d in &tree.dirs {
        expected.entry(d.clone()).or_default();
    }
    for p in tree
        .files
        .keys()
        .chain(tree.symlinks.keys())
        .chain(tree.dirs.iter())
    {
        let (parent, leaf) = p.rsplit_once('/').unwrap_or(("", p));
        expected
            .entry(parent.to_string())
            .or_default()
            .push(leaf.to_string());
    }
    for (dir, mut want) in expected {
        want.sort();
        let mut got: Vec<String> = std::fs::read_dir(root.join(&dir))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| !(dir.is_empty() && n == ".fseventsd"))
            .collect();
        got.sort();
        assert_eq!(got, want, "listing of /{dir} differs natively");
    }
}

/// Write `tree` natively under `root` and flush it.
fn write_native(root: &Path, tree: &Tree) {
    for d in &tree.dirs {
        std::fs::create_dir_all(root.join(d)).unwrap();
    }
    for (p, body) in &tree.files {
        let f = root.join(p);
        std::fs::write(&f, body).unwrap();
        std::fs::File::open(&f).unwrap().sync_all().unwrap();
    }
    for (p, target) in &tree.symlinks {
        std::os::unix::fs::symlink(target, root.join(p)).unwrap();
    }
    for ((p, name), value) in &tree.xattrs {
        let hex: String = value.iter().map(|b| format!("{b:02x}")).collect();
        run(Command::new("xattr")
            .arg("-wx")
            .arg(name)
            .arg(hex)
            .arg(root.join(p)));
    }
    run(&mut Command::new("sync"));
}

/// Open the container with fstool (through the GPT when `partitioned`)
/// and check `tree` reads back.
fn verify_fstool(image: &Path, partitioned: bool, tree: &Tree) {
    let mut file = FileBackend::open(image).unwrap();
    let (start, len) = if partitioned {
        let gpt = Gpt::read(&mut file).unwrap();
        let p = &gpt.partitions()[0];
        (p.start_lba * 512, p.size_lba * 512)
    } else {
        (0, file.total_size())
    };
    let mut dev = SlicedBackend::new(&mut file, start, len).unwrap();
    let fs = Apfs::open(&mut dev).unwrap();
    for (p, body) in &tree.files {
        let mut got = Vec::new();
        fs.open_file_reader(&mut dev, &format!("/{p}"))
            .unwrap_or_else(|e| panic!("fstool open /{p}: {e}"))
            .read_to_end(&mut got)
            .unwrap();
        assert!(got == *body, "/{p}: fstool read different bytes");
    }
    for (p, target) in &tree.symlinks {
        assert_eq!(
            fs.read_symlink(&mut dev, &format!("/{p}")).unwrap(),
            *target,
            "/{p}: fstool read the wrong symlink target"
        );
    }
    for ((p, name), value) in &tree.xattrs {
        let x = fs.read_xattrs(&mut dev, &format!("/{p}")).unwrap();
        assert_eq!(x.get(name), Some(value), "/{p}: fstool xattr {name}");
    }
    for d in &tree.dirs {
        fs.list_path(&mut dev, &format!("/{d}"))
            .unwrap_or_else(|e| panic!("fstool list /{d}: {e}"));
    }
}

// ───────────────────────────── tests ───────────────────────────────

/// Serialize the tests: several attached images at once only make the
/// kernel's disk numbering and `diskutil list` harder to read.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The full acceptance cycle for one formatted image.
fn mount_write_reopen_cycle(fstool_tree: &Tree, mib: u64) {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let image = dir.path().join("disk.img");
    build_disk(&image, mib, fstool_tree);
    let native = native_payload(fstool_tree);
    let all = merge(fstool_tree, &native);

    // 1. Attach, check, mount, read what fstool wrote, add more.
    {
        let mut a = Attached::attach(&image, true);
        a.fsck("freshly formatted");
        let root = a.mount(&dir.path().join("mnt"));
        verify_native(&root, fstool_tree);
        write_native(&root, &native);
        verify_native(&root, &all);
        a.unmount();
        a.fsck("after the native write session");
        a.detach();
    }
    assert_detached(&image);

    // 2. fstool reopens the container macOS last wrote — for reading;
    //    it must decline to write into checkpoints it can't track.
    verify_fstool(&image, true, &all);
    {
        let mut file = FileBackend::open(&image).unwrap();
        let (start, len) = partition_extent(file.total_size());
        let mut dev = SlicedBackend::new(&mut file, start, len).unwrap();
        assert!(
            Apfs::open_writable(&mut dev).is_err(),
            "fstool must not write into a container macOS has written"
        );
    }

    // 3. macOS reopens it too.
    {
        let mut a = Attached::attach(&image, true);
        a.fsck("on reattach");
        let root = a.mount(&dir.path().join("mnt2"));
        verify_native(&root, &all);
        a.unmount();
        a.detach();
    }
    assert_detached(&image);
}

#[test]
fn apfs_populated_volume_mounts_natively_and_survives_native_writes() {
    if !tools_available() {
        return;
    }
    mount_write_reopen_cycle(&fstool_payload(), 64);
}

#[test]
fn apfs_empty_volume_mounts_natively_and_survives_native_writes() {
    if !tools_available() {
        return;
    }
    // 160 MiB: two allocation chunks.
    mount_write_reopen_cycle(&Tree::default(), 160);
}

/// A bare container — no partition map, the container at byte 0 of the
/// raw image — attaches as an APFS physical store of its own.
#[test]
fn apfs_bare_container_mounts_natively() {
    if !tools_available() {
        return;
    }
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let image = dir.path().join("bare.img");
    let tree = fstool_payload();
    {
        let blocks = 16 * 1024 * 1024 / BLOCK_SIZE as u64;
        let mut dev = FileBackend::create(&image, blocks * BLOCK_SIZE as u64).unwrap();
        format_container(&mut dev, blocks, "BAREVOL", &tree);
        dev.sync().unwrap();
    }
    {
        let mut a = Attached::attach(&image, false);
        a.fsck("bare container");
        let root = a.mount(&dir.path().join("mnt"));
        verify_native(&root, &tree);
        a.unmount();
        a.detach();
    }
    assert_detached(&image);
    verify_fstool(&image, false, &tree);
}

/// The kernel recomputes size-dependent spaceman parameters (the main
/// free queue's node limit among them) and silently refuses a container
/// whose values disagree, so mount one container per sizing regime:
/// single chunk, the first multi-chunk sizes, past 1 GiB and past
/// 4 GiB. The images are sparse.
#[test]
fn apfs_container_sizes_mount_natively() {
    if !tools_available() {
        return;
    }
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let mut tree = Tree::default();
    tree.files
        .insert("hello.txt".into(), b"hello from fstool\n".to_vec());
    for mib in [20, 129, 130, 300, 1100, 4200] {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join(format!("disk-{mib}m.img"));
        build_disk(&image, mib, &tree);
        {
            let mut a = Attached::attach(&image, true);
            a.fsck(&format!("{mib} MiB disk"));
            let root = a.mount(&dir.path().join("mnt"));
            verify_native(&root, &tree);
            a.unmount();
            a.detach();
        }
        assert_detached(&image);
    }
}
