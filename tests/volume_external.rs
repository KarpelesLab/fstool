#![cfg(all(
    unix,
    feature = "std",
    feature = "fat",
    feature = "exfat",
    feature = "littlefs"
))]
//! `fs::mount` and the `fs::volume` traits against volumes the reference
//! tools made, on cards laid out the way real ones are.
//!
//! Each driver already has its own conformance suite; what is new here is
//! the layer above them. So every test starts from a card the probe has never
//! seen — `mkfs.fat`, `mkfs.exfat` or littlefs's C implementation wrote the
//! volume, `sgdisk` or a hand-written MBR put it in a partition — asks
//! `fs::mount` what it holds, edits it through code written once against the
//! traits, and hands the result back to the tool's own checker.
//!
//! Every test skips (with a note) when its tool is missing. littlefs needs
//! `littlefs-python`; point `FSTOOL_LITTLEFS_PYTHON` at an interpreter that
//! has it.

use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use fstool::device::SectorDriver;
use fstool::fs::volume::{self, FsType, Volume, VolumeDirIter, VolumeFile};
use tempfile::TempDir;

fn which(tool: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {tool}"))
        .output()
        .is_ok_and(|o| o.status.success() && !o.stdout.is_empty())
}

/// A card backed by an image file.
struct FileCard {
    file: std::fs::File,
    sectors: u64,
}

impl FileCard {
    fn open(path: &Path) -> Self {
        let file = std::fs::File::options()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        let sectors = file.metadata().unwrap().len() / 512;
        Self { file, sectors }
    }
}

impl SectorDriver for FileCard {
    type Error = std::io::Error;

    fn sector_size(&self) -> u32 {
        512
    }

    fn sector_count(&self) -> u64 {
        self.sectors
    }

    fn read_sectors(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), Self::Error> {
        assert!(
            lba + buf.len() as u64 / 512 <= self.sectors,
            "read past the card"
        );
        self.file.read_exact_at(buf, lba * 512)
    }

    fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> Result<(), Self::Error> {
        assert!(
            lba + buf.len() as u64 / 512 <= self.sectors,
            "write past the card"
        );
        self.file.write_all_at(buf, lba * 512)
    }
}

/// Where the partitioned cards put their volume.
const START: u64 = 2048;

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 % 251) as u8).collect()
}

/// Every file and directory, as a sorted manifest, walked through the traits.
fn manifest<V: Volume>(vol: &mut V) -> Vec<String>
where
    V::Error: std::fmt::Debug,
{
    fn walk<V: Volume>(vol: &mut V, dir: &str, out: &mut Vec<String>)
    where
        V::Error: std::fmt::Debug,
    {
        let handle = vol
            .open_dir(if dir.is_empty() { "/" } else { dir })
            .unwrap();
        let mut kids = Vec::new();
        let mut it = vol.iter_dir(handle);
        while let Some(e) = it.next().unwrap() {
            kids.push((e.name_str().unwrap().to_string(), e.is_dir()));
        }
        drop(it);
        kids.sort();
        for (name, is_dir) in kids {
            let path = format!("{dir}/{name}");
            if is_dir {
                out.push(format!("d {path}"));
                walk(vol, &path, out);
            } else {
                let mut f = vol.open_file(&path).unwrap();
                let mut body = vec![0u8; f.len() as usize];
                f.read_exact(vol, &mut body).unwrap();
                out.push(format!("f {path} {}", fnv(&body)));
            }
        }
    }
    let mut out = Vec::new();
    walk(vol, "", &mut out);
    out
}

fn fnv(data: &[u8]) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for &b in data {
        h = (h ^ b as u64).wrapping_mul(0x100_0000_01b3);
    }
    h
}

/// The edit every volume gets, through the traits.
fn edit<V: Volume>(vol: &mut V)
where
    V::Error: std::fmt::Debug,
{
    vol.create_dir("/generic").unwrap();
    let mut f = vol.create_file("/generic/hello.txt").unwrap();
    f.write_all(vol, b"written through fs::volume\n").unwrap();
    f.flush(vol).unwrap();
    let mut f = vol.open_or_create_file("/generic/big.bin").unwrap();
    f.write_all(vol, &pattern(70_000)).unwrap();
    f.flush(vol).unwrap();
    let mut f = vol.open_file("/generic/big.bin").unwrap();
    f.set_len(vol, 50_000).unwrap();
    f.flush(vol).unwrap();
    vol.flush().unwrap();
}

/// Copy `sectors` sectors between two images.
fn copy_sectors(from: &Path, from_lba: u64, to: &Path, to_lba: u64, sectors: u64) {
    let src = std::fs::File::open(from).unwrap();
    let dst = std::fs::File::options().write(true).open(to).unwrap();
    let mut buf = vec![0u8; 1 << 20];
    let mut done = 0u64;
    while done < sectors {
        let n = ((sectors - done) * 512).min(buf.len() as u64) as usize;
        src.read_exact_at(&mut buf[..n], (from_lba + done) * 512)
            .unwrap();
        dst.write_all_at(&buf[..n], (to_lba + done) * 512).unwrap();
        done += n as u64 / 512;
    }
}

fn blank(path: &Path, sectors: u64) {
    std::fs::File::create(path)
        .unwrap()
        .set_len(sectors * 512)
        .unwrap();
}

/// A GPT with one partition at [`START`] of `sectors` sectors.
fn sgdisk(path: &Path, sectors: u64, code: &str) {
    let out = Command::new("sgdisk")
        .args([
            "-o",
            &format!("-n=1:{START}:{}", START + sectors - 1),
            &format!("-t=1:{code}"),
        ])
        .arg(path)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "sgdisk: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// An MBR with one partition at [`START`].
fn write_mbr(path: &Path, kind: u8, sectors: u64) {
    let mut mbr = [0u8; 512];
    mbr[446 + 4] = kind;
    mbr[446 + 8..446 + 12].copy_from_slice(&(START as u32).to_le_bytes());
    mbr[446 + 12..446 + 16].copy_from_slice(&(sectors as u32).to_le_bytes());
    mbr[510] = 0x55;
    mbr[511] = 0xAA;
    std::fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .write_all_at(&mbr, 0)
        .unwrap();
}

fn mount(path: &Path) -> volume::AnyVolume<FileCard, 512, 4096> {
    volume::mount::<_, 512, 4096>(FileCard::open(path))
        .unwrap_or_else(|e| panic!("mounting {}: {e}", path.display()))
}

// -- FAT --------------------------------------------------------------------

fn fsck_fat(path: &Path, what: &str) {
    let out = Command::new("fsck.vfat")
        .arg("-n")
        .arg(path)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    // The version banner and the "N files, M clusters" summary are all a
    // clean volume prints; anything else is a complaint.
    let noise: Vec<&str> = stdout
        .lines()
        .filter(|l| !l.starts_with("fsck.fat") && !l.contains(" files, ") && !l.is_empty())
        .collect();
    assert!(
        out.status.success() && noise.is_empty(),
        "fsck.vfat rejected {what}:\n{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn a_fat32_volume_in_a_gpt_partition_is_found_edited_and_passes_fsck() {
    if !which("mkfs.fat") || !which("fsck.vfat") || !which("sgdisk") {
        eprintln!("skipping: needs mkfs.fat, fsck.vfat and sgdisk");
        return;
    }
    let tmp = TempDir::new().unwrap();
    let sectors = 128 * 1024; // 64 MiB
    let card = tmp.path().join("card.img");
    blank(&card, START + sectors + 34);
    sgdisk(&card, sectors, "0700");
    let vol_img = tmp.path().join("vol.img");
    blank(&vol_img, sectors);
    let out = Command::new("mkfs.fat")
        .args(["-F", "32"])
        .arg(&vol_img)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    copy_sectors(&vol_img, 0, &card, START, sectors);

    let mut card_dev = FileCard::open(&card);
    let found = volume::probe::<_, 512>(&mut card_dev)
        .unwrap()
        .expect("found");
    assert_eq!(
        (found.fs, found.start_lba, found.sectors),
        (FsType::Fat, START, sectors)
    );

    let mut vol = volume::mount_found::<_, 512, 4096>(card_dev, found).unwrap();
    edit(&mut vol);
    let seen = manifest(&mut vol);
    vol.unmount().unwrap();

    copy_sectors(&card, START, &vol_img, 0, sectors);
    fsck_fat(&vol_img, "a FAT32 volume edited through fs::mount");
    // And a fresh mount sees what the edit left.
    let mut vol = mount(&card);
    assert_eq!(manifest(&mut vol), seen);
    assert!(
        seen.contains(&format!("f /generic/big.bin {}", fnv(&pattern(50_000)))),
        "{seen:?}"
    );
}

// -- exFAT ------------------------------------------------------------------

fn fsck_exfat(path: &Path, what: &str) {
    let out = Command::new("fsck.exfat")
        .args(["-n", "-v"])
        .arg(path)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let complained = stdout
        .lines()
        .chain(stderr.lines())
        .any(|l| l.contains("ERROR:") || l.contains("WARNING:") || l.contains("corrupted"));
    assert!(
        out.status.success() && !complained && stdout.contains("clean"),
        "fsck.exfat rejected {what}:\n{stdout}\n{stderr}"
    );
}

#[test]
fn an_exfat_volume_on_a_whole_card_and_in_an_mbr_partition_passes_fsck_after_an_edit() {
    if !which("mkfs.exfat") || !which("fsck.exfat") {
        eprintln!("skipping: needs exfatprogs");
        return;
    }
    let tmp = TempDir::new().unwrap();
    let sectors = 128 * 1024;
    let vol_img = tmp.path().join("vol.img");
    blank(&vol_img, sectors);
    let out = Command::new("mkfs.exfat").arg(&vol_img).output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Whole card.
    let whole = tmp.path().join("whole.img");
    std::fs::copy(&vol_img, &whole).unwrap();
    let mut vol = mount(&whole);
    assert_eq!(vol.fs_type(), FsType::Exfat);
    edit(&mut vol);
    vol.unmount().unwrap();
    fsck_exfat(&whole, "a whole-card exFAT volume edited through fs::mount");

    // Partitioned: an MBR slot typed 0x07, as SDXC cards ship.
    let card = tmp.path().join("card.img");
    blank(&card, START + sectors);
    copy_sectors(&vol_img, 0, &card, START, sectors);
    write_mbr(&card, 0x07, sectors);
    let mut vol = mount(&card);
    assert_eq!(vol.fs_type(), FsType::Exfat);
    edit(&mut vol);
    let seen = manifest(&mut vol);
    vol.unmount().unwrap();
    let back = tmp.path().join("back.img");
    blank(&back, sectors);
    copy_sectors(&card, START, &back, 0, sectors);
    fsck_exfat(
        &back,
        "an MBR-partitioned exFAT volume edited through fs::mount",
    );
    assert_eq!(manifest(&mut mount(&card)), seen);
}

// -- littlefs ---------------------------------------------------------------

fn python() -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(p) = std::env::var("FSTOOL_LITTLEFS_PYTHON") {
        candidates.push(p.into());
    }
    candidates.push("python3".into());
    candidates.into_iter().find(|p| {
        Command::new(p)
            .args(["-c", "import littlefs"])
            .output()
            .is_ok_and(|o| o.status.success())
    })
}

/// Build a littlefs image with the C implementation, or list one.
const SCRIPT: &str = r#"
import sys
from littlefs import LittleFS
from littlefs.context import UserContext

def fnv(data):
    h = 0xcbf29ce484222325
    for b in data:
        h = ((h ^ b) * 0x100000001b3) & 0xffffffffffffffff
    return h

cmd, path, bs, bc = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
if cmd == 'create':
    fs = LittleFS(block_size=bs, block_count=bc, prog_size=bs, read_size=bs)
    fs.mkdir('/data')
    with fs.open('/data/blob.bin', 'wb') as f:
        f.write(bytes((i * 7) % 251 for i in range(30000)))
    # Enough churn that the superblock pair and the root are compacted and
    # rewritten, not just freshly formatted.
    for round in range(3):
        for i in range(60):
            with fs.open('/n%02d' % i, 'w') as f:
                f.write('round %d file %d' % (round, i))
        for i in range(0, 60, 2):
            fs.remove('/n%02d' % i)
        for i in range(0, 60, 2):
            with fs.open('/n%02d' % i, 'w') as f:
                f.write('back %d' % i)
    open(path, 'wb').write(bytes(fs.context.buffer))
elif cmd == 'manifest':
    data = bytearray(open(path, 'rb').read())
    ctx = UserContext(len(data))
    ctx.buffer = data
    fs = LittleFS(context=ctx, block_size=bs, block_count=bc,
                  read_size=bs, prog_size=bs, cache_size=bs, mount=False)
    fs.mount()
    out = []
    for root, dirs, files in fs.walk('/'):
        base = '' if root == '/' else root
        for d in dirs:
            out.append('d %s/%s' % (base, d))
        for f in files:
            p = '%s/%s' % (base, f)
            out.append('f %s %d' % (p, fnv(fs.open(p, 'rb').read())))
    print('\n'.join(sorted(out)))
"#;

fn run_python(py: &Path, args: &[&str]) -> String {
    let out = Command::new(py)
        .arg("-c")
        .arg(SCRIPT)
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "littlefs-python: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn a_littlefs_volume_the_c_implementation_wrote_is_found_on_a_card_and_stays_readable_by_it() {
    let Some(py) = python() else {
        eprintln!("skipping: no python with littlefs-python installed");
        return;
    };
    let tmp = TempDir::new().unwrap();
    for (block_size, partitioned) in [(512u64, false), (4096, true), (1024, true)] {
        let blocks = 16 * 1024 * 1024 / block_size;
        let sectors = blocks * block_size / 512;
        let (bs, bc) = (block_size.to_string(), blocks.to_string());
        let vol_img = tmp.path().join(format!("lfs-{block_size}.img"));
        run_python(&py, &["create", vol_img.to_str().unwrap(), &bs, &bc]);
        let theirs = run_python(&py, &["manifest", vol_img.to_str().unwrap(), &bs, &bc]);

        let card = tmp.path().join(format!("card-{block_size}.img"));
        let start = if partitioned { START } else { 0 };
        blank(&card, start + sectors);
        copy_sectors(&vol_img, 0, &card, start, sectors);
        if partitioned {
            write_mbr(&card, 0x83, sectors);
        }

        let mut dev = FileCard::open(&card);
        let found = volume::probe::<_, 512>(&mut dev).unwrap().expect("found");
        assert_eq!(
            (found.fs, found.start_lba, found.block_size as u64),
            (FsType::LittleFs, start, block_size)
        );
        let mut vol = volume::mount_found::<_, 512, 4096>(dev, found).unwrap();
        // What we read is what the C implementation reads.
        let mut ours = manifest(&mut vol);
        ours.sort();
        assert_eq!(
            ours.join("\n"),
            theirs.trim_end(),
            "at {block_size}-byte blocks"
        );

        edit(&mut vol);
        let mut seen = manifest(&mut vol);
        seen.sort();
        vol.unmount().unwrap();

        // And what we wrote is what the C implementation reads back.
        copy_sectors(&card, start, &vol_img, 0, sectors);
        let after = run_python(&py, &["manifest", vol_img.to_str().unwrap(), &bs, &bc]);
        assert_eq!(
            seen.join("\n"),
            after.trim_end(),
            "after the edit, at {block_size}-byte blocks"
        );
    }
}
