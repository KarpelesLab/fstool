#![cfg(feature = "std")]
//! Cross-check our MBR/GPT writers against system tools (`sgdisk`, `fdisk`).
//!
//! Each test silently skips if the corresponding tool is missing from PATH —
//! that way `cargo test` still passes on minimal CI images while opportunistically
//! validating against the real tools when they're available.

use std::path::Path;
use std::process::Command;

use fstool::block::{BlockDevice, FileBackend};
use fstool::part::{Gpt, Mbr, Partition, PartitionKind, PartitionTable};
use tempfile::NamedTempFile;

fn which(tool: &str) -> Option<std::path::PathBuf> {
    let out = Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {tool}"))
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?;
    let p = s.trim();
    if p.is_empty() { None } else { Some(p.into()) }
}

fn write_gpt_image(path: &Path, size: u64) {
    let mut dev = FileBackend::create(path, size).unwrap();
    let parts = vec![
        Partition {
            start_lba: 2048,
            size_lba: 2048,
            kind: PartitionKind::EfiSystem,
            name: Some("EFI System".into()),
            ..Partition::new(0, 0, PartitionKind::EfiSystem)
        },
        Partition {
            start_lba: 4096,
            size_lba: size / 512 - 4096 - 34,
            kind: PartitionKind::LinuxFilesystem,
            name: Some("root".into()),
            ..Partition::new(0, 0, PartitionKind::LinuxFilesystem)
        },
    ];
    let gpt = Gpt::build(parts).unwrap();
    gpt.write(&mut dev).unwrap();
    dev.sync().unwrap();
    drop(dev);
}

fn write_mbr_image(path: &Path, size: u64) {
    let mut dev = FileBackend::create(path, size).unwrap();
    let parts = vec![
        Partition {
            start_lba: 2048,
            size_lba: 20480,
            kind: PartitionKind::LinuxFilesystem,
            bootable: true,
            ..Partition::new(0, 0, PartitionKind::LinuxFilesystem)
        },
        Partition {
            start_lba: 22528,
            size_lba: 4096,
            kind: PartitionKind::LinuxSwap,
            ..Partition::new(0, 0, PartitionKind::LinuxSwap)
        },
    ];
    let mbr = Mbr::new(parts).unwrap();
    mbr.write(&mut dev).unwrap();
    dev.sync().unwrap();
    drop(dev);
}

#[test]
fn gpt_validates_with_sgdisk() {
    let Some(_) = which("sgdisk") else {
        eprintln!("skipping: sgdisk not installed");
        return;
    };

    let tmp = NamedTempFile::new().unwrap();
    write_gpt_image(tmp.path(), 64 * 1024 * 1024);

    // -p prints the partition table; non-zero exit means the GPT is broken.
    let out = Command::new("sgdisk")
        .arg("-p")
        .arg(tmp.path())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "sgdisk -p failed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    // Should list two partitions named EFI System and root.
    assert!(
        stdout.contains("EFI System"),
        "missing EFI System in sgdisk output:\n{stdout}"
    );
    assert!(
        stdout.contains("root"),
        "missing root in sgdisk output:\n{stdout}"
    );

    // -v verifies all CRCs and structures.
    let out = Command::new("sgdisk")
        .arg("-v")
        .arg(tmp.path())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "sgdisk -v failed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    // sgdisk -v on a clean GPT prints "No problems found."
    assert!(
        stdout.contains("No problems found") || stdout.contains("no problems found"),
        "sgdisk -v didn't report a clean image:\n{stdout}\n{stderr}"
    );
}

#[test]
fn mbr_validates_with_fdisk() {
    // macOS ships its own `fdisk(8)` with completely different
    // command-line syntax (and no `-l` flag) — the test only makes sense
    // against util-linux fdisk.
    if !cfg!(target_os = "linux") {
        eprintln!("skipping: util-linux fdisk only exists on Linux");
        return;
    }
    let Some(_) = which("fdisk") else {
        eprintln!("skipping: fdisk not installed");
        return;
    };

    let tmp = NamedTempFile::new().unwrap();
    write_mbr_image(tmp.path(), 16 * 1024 * 1024);

    let out = Command::new("fdisk")
        .arg("-l")
        .arg(tmp.path())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "fdisk -l failed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    // Should report a DOS disklabel with our two partitions.
    assert!(
        stdout.contains("Disklabel type: dos") || stdout.contains("type: dos"),
        "fdisk did not detect a DOS partition table:\n{stdout}"
    );
    // Linux type ("83") and Linux swap ("82") should both appear.
    let lower = stdout.to_lowercase();
    assert!(
        lower.contains("linux"),
        "missing 'Linux' partition type:\n{stdout}"
    );
    assert!(
        lower.contains("swap") || lower.contains(" 82 "),
        "missing swap partition:\n{stdout}"
    );
}

// ---------------------------------------------------------------------
// The allocator-free GPT reader, against tables the system tools write.
//
// `device::gpt` shares no code with `part::gpt` above: it walks the table on
// a `SectorDriver` with one sector of scratch, for the filesystems that run
// without an allocator. So it earns its own check against `sgdisk`.
// ---------------------------------------------------------------------

#[cfg(feature = "fat")]
mod noalloc_gpt {
    use super::*;
    use fstool::device::{SectorDriver, gpt};

    /// A RAM-backed medium over an image file's bytes.
    struct Disk(Vec<u8>);

    impl SectorDriver for Disk {
        type Error = std::convert::Infallible;
        fn sector_size(&self) -> u32 {
            512
        }
        fn sector_count(&self) -> u64 {
            self.0.len() as u64 / 512
        }
        fn read_sectors(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), Self::Error> {
            let at = lba as usize * 512;
            buf.copy_from_slice(&self.0[at..at + buf.len()]);
            Ok(())
        }
        fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> Result<(), Self::Error> {
            let at = lba as usize * 512;
            self.0[at..at + buf.len()].copy_from_slice(buf);
            Ok(())
        }
    }

    #[test]
    fn reads_a_table_sgdisk_wrote() {
        let Some(_) = which("sgdisk") else {
            eprintln!("skipping: sgdisk not installed");
            return;
        };
        let tmp = tempfile::NamedTempFile::new().unwrap();
        {
            let f = std::fs::File::create(tmp.path()).unwrap();
            f.set_len(64 * 1024 * 1024).unwrap();
        }
        // Three partitions of three different types, named, so every field
        // the reader decodes is checked against what the tool wrote.
        let out = std::process::Command::new("sgdisk")
            .args([
                "-n",
                "1:2048:+16M",
                "-t",
                "1:EF00",
                "-c",
                "1:ESP",
                "-n",
                "2:+0:+16M",
                "-t",
                "2:0700",
                "-c",
                "2:DATA",
                "-n",
                "3:+0:+8M",
                "-t",
                "3:8300",
                "-c",
                "3:LINUX",
            ])
            .arg(tmp.path())
            .output()
            .expect("run sgdisk");
        assert!(
            out.status.success(),
            "sgdisk failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        let mut dev = Disk(std::fs::read(tmp.path()).unwrap());
        let mut buf = [0u8; 512];
        let table = gpt::Table::read(&mut dev, &mut buf)
            .unwrap()
            .expect("the reader found no GPT where sgdisk wrote one");
        assert!(
            !table.from_backup,
            "the primary header should have checked out"
        );
        assert_eq!(table.header.entry_size, 128);
        assert_eq!(table.header.first_usable_lba, 34);

        // Slot 1: the EFI system partition, which sgdisk typed EF00.
        let esp = table.entry(&mut dev, &mut buf, 0).unwrap().expect("slot 1");
        assert!(esp.is_efi_system(), "{:?}", esp.type_guid);
        assert!(esp.looks_like_fat_family());
        assert_eq!(esp.start_lba, 2048);
        assert_eq!(esp.sectors(), 16 * 1024 * 1024 / 512);

        // Slot 2: Microsoft basic data (0700) — where FAT and exFAT live.
        let data = table.entry(&mut dev, &mut buf, 1).unwrap().expect("slot 2");
        assert!(data.is_basic_data(), "{:?}", data.type_guid);
        assert_eq!(data.start_lba, esp.end_lba + 1);

        // Slot 3: a Linux filesystem (8300), which is not FAT-family.
        let linux = table.entry(&mut dev, &mut buf, 2).unwrap().expect("slot 3");
        assert_eq!(linux.type_guid, gpt::LINUX_FS);
        assert!(!linux.looks_like_fat_family());

        // Slots past the three are unused, and every partition's GUID is its
        // own.
        assert!(table.entry(&mut dev, &mut buf, 3).unwrap().is_none());
        assert_ne!(esp.guid, data.guid);
        assert!(!esp.guid.is_nil());

        // The names sgdisk set come back through the entry bytes.
        let (lba, at) = table.header.entry_position(1, 512).unwrap();
        dev.read_sectors(lba, &mut buf).unwrap();
        let mut units = [0u16; 36];
        let n = gpt::Partition::name_from(&buf[at..], &mut units);
        let name: String = char::decode_utf16(units[..n].iter().copied())
            .map(|c| c.unwrap_or('?'))
            .collect();
        assert_eq!(name, "DATA");
    }

    #[test]
    fn falls_back_to_the_backup_sgdisk_wrote() {
        let Some(_) = which("sgdisk") else {
            eprintln!("skipping: sgdisk not installed");
            return;
        };
        let tmp = tempfile::NamedTempFile::new().unwrap();
        {
            let f = std::fs::File::create(tmp.path()).unwrap();
            f.set_len(32 * 1024 * 1024).unwrap();
        }
        let out = std::process::Command::new("sgdisk")
            .args(["-n", "1:2048:+8M", "-t", "1:0700"])
            .arg(tmp.path())
            .output()
            .unwrap();
        assert!(out.status.success());

        let mut bytes = std::fs::read(tmp.path()).unwrap();
        // Wipe the primary header the way a torn write would.
        bytes[512..1024].fill(0);
        let mut dev = Disk(bytes);
        let mut buf = [0u8; 512];
        let table = gpt::Table::read(&mut dev, &mut buf)
            .unwrap()
            .expect("the backup header sgdisk wrote should have been used");
        assert!(table.from_backup);
        let p = table.entry(&mut dev, &mut buf, 0).unwrap().expect("slot 1");
        assert_eq!(p.start_lba, 2048);
        assert!(p.is_basic_data());
    }
}
