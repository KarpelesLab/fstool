#![cfg(all(unix, feature = "std", feature = "fat", feature = "exfat"))]
//! The allocator-free formatters and partition writers, judged by the tools
//! that own each format.
//!
//! Each driver's formatter lays a volume down a sector at a time through a
//! `SectorDriver`, with no heap; that makes it the thing a card reader or a
//! data logger uses to prepare a blank card, and it has to produce what
//! `mkfs` would have. So every volume here is formatted by the driver —
//! whole-card or inside a partition `device::mbr` / `device::gpt` wrote —
//! checked by `fsck.vfat` / `fsck.exfat`, then filled through the driver and
//! checked again, and finally read by the crate's hosted implementation,
//! which shares no code with the driver.
//!
//! Tests skip (with a note) when their tool is not installed.

use std::os::unix::fs::FileExt;
use std::path::Path;
use std::process::Command;

use fstool::device::{SectorDriver, gpt, mbr};
use tempfile::TempDir;

fn which(tool: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {tool}"))
        .output()
        .is_ok_and(|o| o.status.success() && !o.stdout.is_empty())
}

/// A card backed by an image file, with a chosen sector size.
struct FileCard {
    file: std::fs::File,
    ss: u32,
    sectors: u64,
}

impl FileCard {
    fn create(path: &Path, sectors: u64, ss: u32) -> Self {
        let file = std::fs::File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .unwrap();
        file.set_len(sectors * ss as u64).unwrap();
        // Not zeros: a formatter that leans on a blank medium is caught. A
        // big card keeps its first gigabyte dirty, which covers every
        // structure a format writes, and stays sparse past it.
        let junk = vec![0xE5u8; 1 << 20];
        let mut at = 0;
        while at < (sectors * ss as u64).min(1 << 30) {
            let n = ((sectors * ss as u64).min(1 << 30) - at).min(junk.len() as u64) as usize;
            file.write_all_at(&junk[..n], at).unwrap();
            at += n as u64;
        }
        Self { file, ss, sectors }
    }

    fn open(path: &Path, ss: u32) -> Self {
        let file = std::fs::File::options()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        let sectors = file.metadata().unwrap().len() / ss as u64;
        Self { file, ss, sectors }
    }
}

impl SectorDriver for FileCard {
    type Error = std::io::Error;
    fn sector_size(&self) -> u32 {
        self.ss
    }
    fn sector_count(&self) -> u64 {
        self.sectors
    }
    fn read_sectors(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), Self::Error> {
        assert!(
            buf.len().is_multiple_of(self.ss as usize)
                && lba + (buf.len() / self.ss as usize) as u64 <= self.sectors
        );
        self.file.read_exact_at(buf, lba * self.ss as u64)
    }
    fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> Result<(), Self::Error> {
        assert!(
            buf.len().is_multiple_of(self.ss as usize)
                && lba + (buf.len() / self.ss as usize) as u64 <= self.sectors
        );
        self.file.write_all_at(buf, lba * self.ss as u64)
    }
}

const MIB: u64 = 1 << 20;

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 % 251) as u8).collect()
}

/// Copy a partition's sectors out into an image of their own, which is what
/// the fsck tools want to be pointed at.
fn extract(card: &Path, start: u64, sectors: u64, ss: u32, out: &Path) {
    let src = std::fs::File::open(card).unwrap();
    let dst = std::fs::File::create(out).unwrap();
    dst.set_len(sectors * ss as u64).unwrap();
    let mut buf = vec![0u8; 1 << 20];
    let mut done = 0u64;
    let total = sectors * ss as u64;
    while done < total {
        let n = (total - done).min(buf.len() as u64) as usize;
        src.read_exact_at(&mut buf[..n], start * ss as u64 + done)
            .unwrap();
        dst.write_all_at(&buf[..n], done).unwrap();
        done += n as u64;
    }
}

// -- FAT --------------------------------------------------------------------

use fstool::fs::fat::{FatKind, FormatOpts as FatOpts, Volume as Fat};

/// `fsck.vfat -n`, held to its report: anything past the banner and the
/// summary line is a complaint.
fn fsck_fat(image: &Path, what: &str) {
    let out = Command::new("fsck.vfat")
        .arg("-n")
        .arg(image)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let noise: Vec<&str> = stdout
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with("fsck.fat") && !l.contains(" files, "))
        .collect();
    assert!(
        out.status.success() && noise.is_empty(),
        "fsck.vfat rejected {what}:\n{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn fill_fat(vol: &mut Fat<FileCard, 4096>) {
    vol.create_dir("/DCIM").unwrap();
    vol.create_dir("/DCIM/100CAMERA").unwrap();
    for i in 0..30 {
        let mut f = vol
            .create_file(&format!("/DCIM/100CAMERA/Photo number {i:03}.jpg"))
            .unwrap();
        f.write_all(vol, &pattern(3_000 + i * 997)).unwrap();
        f.flush(vol).unwrap();
    }
    let mut f = vol.create_file("/big.bin").unwrap();
    f.write_all(vol, &pattern(3 * MIB as usize)).unwrap();
    f.flush(vol).unwrap();
    vol.flush().unwrap();
}

/// The hosted implementation reads what the driver formatted and filled.
fn hosted_reads_fat(image: &Path) {
    use fstool::block::FileBackend;
    use fstool::fs::Filesystem;
    use fstool::fs::fat::Fat32;
    use std::io::Read;
    let mut dev = FileBackend::open(image).unwrap();
    let mut fs = Fat32::open(&mut dev).unwrap();
    let names: Vec<String> = fs
        .list(&mut dev, fstool::path::Path::new("/DCIM/100CAMERA"))
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert_eq!(names.len(), 30, "{names:?}");
    let mut body = Vec::new();
    fs.read_file(&mut dev, fstool::path::Path::new("/big.bin"))
        .unwrap()
        .read_to_end(&mut body)
        .unwrap();
    assert_eq!(body, pattern(3 * MIB as usize));
}

#[test]
fn fat_volumes_the_driver_formats_pass_fsck_vfat_before_and_after_use() {
    if !which("fsck.vfat") {
        eprintln!("skipping: fsck.vfat not installed");
        return;
    }
    let tmp = TempDir::new().unwrap();
    let label = *b"FSTOOL CARD";
    for (bytes, kind, ss) in [
        (1440 * 1024, None, 512u32),
        (64 * MIB, None, 512),
        (64 * MIB, Some(FatKind::Fat32), 512),
        (600 * MIB, None, 512),
        (512 * MIB, Some(FatKind::Fat32), 4096),
    ] {
        let what = format!("{bytes} bytes, {kind:?}, {ss}-byte sectors");
        let img = tmp.path().join("vol.img");
        let sectors = bytes / ss as u64;
        let card = FileCard::create(&img, sectors, ss);
        let opts = FatOpts {
            kind,
            label,
            volume_id: 0x2026_0915,
            ..Default::default()
        };
        let vol = Fat::<_, 4096>::format(card, &opts).unwrap_or_else(|e| panic!("{what}: {e:?}"));
        if let Some(k) = kind {
            assert_eq!(vol.kind(), k, "{what}");
        }
        drop(vol.unmount().unwrap());
        fsck_fat(&img, &format!("a fresh volume ({what})"));

        let mut vol = Fat::<_, 4096>::mount(FileCard::open(&img, ss)).unwrap();
        if bytes >= 64 * MIB {
            fill_fat(&mut vol);
        } else {
            let mut f = vol.create_file("/floppy.txt").unwrap();
            f.write_all(&mut vol, b"fits").unwrap();
            f.flush(&mut vol).unwrap();
        }
        drop(vol.unmount().unwrap());
        fsck_fat(&img, &format!("a used volume ({what})"));
        statfs_agrees_with_fsck_vfat(&img, ss, &what);
        if bytes >= 64 * MIB && ss == 512 {
            hosted_reads_fat(&img);
        }
    }
}

#[test]
fn a_fat32_volume_formatted_inside_an_mbr_partition_passes_fsck_vfat() {
    if !which("fsck.vfat") || !which("sfdisk") {
        eprintln!("skipping: needs fsck.vfat and sfdisk");
        return;
    }
    let tmp = TempDir::new().unwrap();
    let img = tmp.path().join("card.img");
    let total = 1024 * MIB / 512;
    let mut card = FileCard::create(&img, total, 512);
    let part = mbr::Entry::new(mbr::FAT32_LBA, mbr::FIRST_LBA, (total - 2048) as u32);
    let mut scratch = [0u8; 512];
    mbr::write(
        &mut card,
        &mut scratch,
        &[Some(part), None, None, None],
        0xC0FF_EE00,
    )
    .unwrap();
    let mut vol =
        Fat::<_, 4096>::format_at(card, 2048, part.sectors as u64, &FatOpts::default()).unwrap();
    assert_eq!(vol.kind(), FatKind::Fat32);
    fill_fat(&mut vol);
    drop(vol.unmount().unwrap());

    let out = Command::new("sfdisk").arg("-d").arg(&img).output().unwrap();
    let dump = String::from_utf8_lossy(&out.stdout);
    assert!(
        dump.contains("start=        2048") && dump.contains("type=c"),
        "{dump}"
    );
    let vol_img = tmp.path().join("vol.img");
    extract(&img, 2048, part.sectors as u64, 512, &vol_img);
    fsck_fat(&vol_img, "a FAT32 volume formatted in an MBR partition");
    hosted_reads_fat(&vol_img);
}

/// `statfs` through the generic interface, against the cluster counts
/// `fsck.vfat` works out by walking the FAT itself.
fn statfs_agrees_with_fsck_vfat(image: &Path, ss: u32, what: &str) {
    use fstool::fs::volume::Volume as _;
    let out = Command::new("fsck.vfat")
        .arg("-n")
        .arg(image)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    // "<image>: N files, used/total clusters"
    let summary = stdout
        .lines()
        .find(|l| l.contains(" files, "))
        .expect("fsck summary");
    let counts = summary
        .rsplit(", ")
        .next()
        .unwrap()
        .trim_end_matches(" clusters");
    let (used, total) = counts.split_once('/').unwrap();
    let (used, total): (u64, u64) = (used.parse().unwrap(), total.parse().unwrap());

    let mut vol = fstool::fs::mount::<_, 4096, 4096>(FileCard::open(image, ss)).unwrap();
    let st = vol.statfs().unwrap();
    assert_eq!(
        (st.blocks, st.blocks - st.blocks_free),
        (total, used),
        "{what}: {st:?} vs {summary}"
    );
    assert_eq!(st.total_bytes(), vol.total_bytes(), "{what}");
}

// -- exFAT ------------------------------------------------------------------

use fstool::fs::exfat::{Volume as Exfat, VolumeFormatOpts as ExfatOpts};

/// `fsck.exfat -n -v`, held to its report: it exits 0 after printing
/// `ERROR:` with `-n`.
fn fsck_exfat(image: &Path, what: &str) {
    let out = Command::new("fsck.exfat")
        .args(["-n", "-v"])
        .arg(image)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let complained = stdout
        .lines()
        .chain(stderr.lines())
        .any(|l| l.contains("ERROR") || l.contains("WARNING") || l.contains("corrupt"));
    assert!(
        out.status.success() && !complained && stdout.contains("clean"),
        "fsck.exfat rejected {what}:\n{stdout}\n{stderr}"
    );
}

fn fill_exfat(vol: &mut Exfat<FileCard, 4096>) {
    vol.create_dir("/DCIM").unwrap();
    for i in 0..30 {
        let mut f = vol
            .create_file(&format!("/DCIM/Bild Nummer {i:03} – Überblick.jpg"))
            .unwrap();
        f.write_all(vol, &pattern(3_000 + i * 997)).unwrap();
        f.flush(vol).unwrap();
    }
    let mut f = vol.create_file("/big.bin").unwrap();
    f.write_all(vol, &pattern(3 * MIB as usize)).unwrap();
    f.flush(vol).unwrap();
    vol.flush().unwrap();
}

/// The hosted implementation reads what the driver formatted and filled.
fn hosted_reads_exfat(image: &Path) {
    use fstool::block::FileBackend;
    use fstool::fs::exfat::Exfat as Hosted;
    let mut dev = FileBackend::open(image).unwrap();
    let fs = Hosted::open(&mut dev).unwrap();
    let names = fs.list_path(&mut dev, "/DCIM").unwrap();
    assert_eq!(names.len(), 30);
    let root: Vec<String> = fs
        .list_path(&mut dev, "/")
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert!(root.contains(&"big.bin".to_string()), "{root:?}");
}

/// `statfs` through the generic interface, against what `dump.exfat` reads
/// out of the volume.
fn statfs_agrees_with_dump_exfat(image: &Path, ss: u32, what: &str) {
    use fstool::fs::volume::Volume as _;
    if !which("dump.exfat") {
        return;
    }
    let out = Command::new("dump.exfat").arg(image).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let field = |name: &str| -> u64 {
        text.lines()
            .find_map(|l| l.strip_prefix(name))
            .unwrap_or_else(|| panic!("no {name} in dump.exfat output:\n{text}"))
            .trim()
            .parse()
            .unwrap()
    };
    let (total, free, cluster) = (
        field("Total Clusters:"),
        field("Free Clusters:"),
        field("Cluster size:"),
    );
    let mut vol = fstool::fs::mount::<_, 4096, 4096>(FileCard::open(image, ss)).unwrap();
    let st = vol.statfs().unwrap();
    assert_eq!(
        (st.blocks, st.blocks_free, st.block_size as u64),
        (total, free, cluster),
        "{what}: {st:?}"
    );
}

#[test]
fn exfat_volumes_the_driver_formats_pass_fsck_exfat_before_and_after_use() {
    if !which("fsck.exfat") {
        eprintln!("skipping: fsck.exfat not installed");
        return;
    }
    let tmp = TempDir::new().unwrap();
    for (bytes, cluster, ss) in [
        (8 * MIB, None, 512u32),
        (512 * MIB, None, 512),
        (4096 * MIB, None, 512),
        (256 * MIB, Some(1 << 20), 512),
        (512 * MIB, None, 4096),
    ] {
        let what = format!("{bytes} bytes, {cluster:?} clusters, {ss}-byte sectors");
        let img = tmp.path().join("vol.img");
        let card = FileCard::create(&img, bytes / ss as u64, ss);
        let opts = ExfatOpts {
            cluster_size: cluster,
            label: "FSTOOL ÉTÉ",
            volume_serial: 0x2026_0915,
        };
        let vol = Exfat::<_, 4096>::format(card, &opts).unwrap_or_else(|e| panic!("{what}: {e:?}"));
        drop(vol.unmount().unwrap());
        fsck_exfat(&img, &format!("a fresh volume ({what})"));

        let mut vol = Exfat::<_, 4096>::mount(FileCard::open(&img, ss)).unwrap();
        fill_exfat(&mut vol);
        drop(vol.unmount().unwrap());
        fsck_exfat(&img, &format!("a used volume ({what})"));
        statfs_agrees_with_dump_exfat(&img, ss, &what);
        if ss == 512 {
            hosted_reads_exfat(&img);
        }
    }
}

#[test]
fn an_exfat_volume_formatted_inside_a_gpt_partition_passes_fsck_and_sgdisk() {
    if !which("fsck.exfat") || !which("sgdisk") {
        eprintln!("skipping: needs fsck.exfat and sgdisk");
        return;
    }
    let tmp = TempDir::new().unwrap();
    let img = tmp.path().join("card.img");
    let total = 1024 * MIB / 512;
    let mut card = FileCard::create(&img, total, 512);
    let mut scratch = [0u8; 512];
    let layout = gpt::Layout::new(total, 512).unwrap();
    let start = layout.first_aligned_lba(512);
    let sectors = (layout.last_usable_lba + 1) / 2048 * 2048 - start;
    let part = gpt::NewPartition {
        name: "SDXC",
        ..gpt::NewPartition::new(
            gpt::BASIC_DATA,
            gpt::Guid::random_v4([0x42; 16]),
            start,
            sectors,
        )
    };
    gpt::write(
        &mut card,
        &mut scratch,
        gpt::Guid::random_v4([0x24; 16]),
        &[part],
    )
    .unwrap();
    let mut vol = Exfat::<_, 4096>::format_at(card, start, sectors, &ExfatOpts::default()).unwrap();
    fill_exfat(&mut vol);
    drop(vol.unmount().unwrap());

    let out = Command::new("sgdisk").arg("-v").arg(&img).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("No problems found")
            && !text.contains("Caution")
            && !text.contains("Warning"),
        "{text}"
    );

    let vol_img = tmp.path().join("vol.img");
    extract(&img, start, sectors, 512, &vol_img);
    fsck_exfat(&vol_img, "an exFAT volume formatted in a GPT partition");
    hosted_reads_exfat(&vol_img);
}
