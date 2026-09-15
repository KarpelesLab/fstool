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

    // -- The writers, checked by the same tools ----------------------------

    use fstool::device::mbr;

    /// A GUID in the canonical spelling `sgdisk` prints.
    fn spelled(g: gpt::Guid) -> String {
        let b = g.0;
        format!(
            "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{}",
            u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            u16::from_le_bytes([b[4], b[5]]),
            u16::from_le_bytes([b[6], b[7]]),
            b[8],
            b[9],
            b[10..16]
                .iter()
                .map(|x| format!("{x:02X}"))
                .collect::<String>()
        )
    }

    fn sgdisk(args: &[&str], image: &std::path::Path) -> String {
        let out = std::process::Command::new("sgdisk")
            .args(args)
            .arg(image)
            .output()
            .unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.status.success(), "sgdisk {args:?} failed:\n{text}");
        text
    }

    /// `sgdisk -v`, held to its report: it exits 0 after loading a backup
    /// over a corrupt primary, so the words matter, not the status.
    fn sgdisk_verifies(image: &std::path::Path, what: &str) {
        let text = sgdisk(&["-v"], image);
        let complained = [
            "Warning",
            "Caution",
            "ERROR",
            "Invalid",
            "Problem:",
            "problems found",
        ]
        .iter()
        .any(|w| text.contains(w) && !text.contains("No problems found"))
            || ["Warning", "Caution", "ERROR"]
                .iter()
                .any(|w| text.contains(w));
        assert!(
            text.contains("No problems found") && !complained,
            "sgdisk -v on {what}:\n{text}"
        );
    }

    fn image(sectors: u64) -> (tempfile::NamedTempFile, Disk) {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        (tmp, Disk(vec![0u8; sectors as usize * 512]))
    }

    #[test]
    fn a_gpt_the_writer_lays_down_passes_sgdisk_verification() {
        let Some(_) = which("sgdisk") else {
            eprintln!("skipping: sgdisk not installed");
            return;
        };
        let (tmp, mut dev) = image(128 * 1024);
        let layout = gpt::Layout::new(128 * 1024, 512).unwrap();
        let start = layout.first_aligned_lba(512);
        let parts = [
            gpt::NewPartition {
                name: "EFI system",
                ..gpt::NewPartition::new(
                    gpt::EFI_SYSTEM,
                    gpt::Guid::random_v4([1; 16]),
                    start,
                    32_768,
                )
            },
            gpt::NewPartition {
                name: "données",
                attributes: 1 << 60,
                ..gpt::NewPartition::new(
                    gpt::BASIC_DATA,
                    gpt::Guid::random_v4([2; 16]),
                    start + 32_768,
                    51_200,
                )
            },
            gpt::NewPartition::new(
                gpt::LINUX_FS,
                gpt::Guid::random_v4([3; 16]),
                start + 90_112,
                // Up to the last 1 MiB boundary before the backup table.
                (layout.last_usable_lba + 1) / 2048 * 2048 - (start + 90_112),
            ),
        ];
        let mut scratch = [0u8; 512];
        gpt::write(
            &mut dev,
            &mut scratch,
            gpt::Guid::random_v4([9; 16]),
            &parts,
        )
        .unwrap();
        std::fs::write(tmp.path(), &dev.0).unwrap();

        sgdisk_verifies(tmp.path(), "a table gpt::write laid down");
        let printed = sgdisk(&["-p"], tmp.path());
        assert!(
            printed.contains(&spelled(gpt::Guid::random_v4([9; 16]))),
            "{printed}"
        );
        for (i, p) in parts.iter().enumerate() {
            let info = sgdisk(&["-i", &(i + 1).to_string()], tmp.path());
            assert!(
                info.contains(&format!("First sector: {} ", p.start_lba)),
                "{info}"
            );
            assert!(
                info.contains(&format!("Last sector: {} ", p.end_lba)),
                "{info}"
            );
            assert!(info.contains(&spelled(p.type_guid)), "{info}");
            assert!(info.contains(&spelled(p.guid)), "{info}");
            assert!(
                info.contains(&format!("Partition name: '{}'", p.name)),
                "{info}"
            );
            assert!(
                info.contains(&format!("Attribute flags: {:016X}", p.attributes)),
                "{info}"
            );
        }
    }

    #[test]
    fn set_entry_changes_a_table_sgdisk_wrote_and_repairs_it() {
        let Some(_) = which("sgdisk") else {
            eprintln!("skipping: sgdisk not installed");
            return;
        };
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::File::create(tmp.path())
            .unwrap()
            .set_len(64 * 1024 * 1024)
            .unwrap();
        sgdisk(
            &[
                "-n",
                "1:2048:+8M",
                "-t",
                "1:0700",
                "-n",
                "2:+0:+8M",
                "-t",
                "2:8300",
            ],
            tmp.path(),
        );

        let mut dev = Disk(std::fs::read(tmp.path()).unwrap());
        // The primary header is torn; the change goes through the backup and
        // rewrites both.
        dev.0[512..604].fill(0);
        let mut scratch = [0u8; 512];
        let added = gpt::NewPartition {
            name: "added",
            ..gpt::NewPartition::new(
                gpt::BASIC_DATA,
                gpt::Guid::random_v4([7; 16]),
                40_960,
                20_480,
            )
        };
        gpt::set_entry(&mut dev, &mut scratch, 2, Some(added)).unwrap();
        gpt::set_entry(&mut dev, &mut scratch, 0, None).unwrap();
        // Overlapping what sgdisk put in slot 2 is refused.
        assert!(matches!(
            gpt::set_entry(
                &mut dev,
                &mut scratch,
                3,
                Some(gpt::NewPartition::new(
                    gpt::LINUX_FS,
                    gpt::Guid::random_v4([8; 16]),
                    20_000,
                    10
                )),
            ),
            Err(gpt::WriteError::Overlap(3, 1))
        ));
        std::fs::write(tmp.path(), &dev.0).unwrap();

        sgdisk_verifies(tmp.path(), "a table set_entry changed and repaired");
        let printed = sgdisk(&["-p"], tmp.path());
        assert!(
            !printed.contains("\n   1 "),
            "slot 1 was removed:\n{printed}"
        );
        let info = sgdisk(&["-i", "3"], tmp.path());
        assert!(info.contains("First sector: 40960 "), "{info}");
        assert!(info.contains("Partition name: 'added'"), "{info}");
        let info = sgdisk(&["-i", "2"], tmp.path());
        assert!(
            info.contains("0FC63DAF-8483-4772-8E79-3D69D8477DE4"),
            "sgdisk's own slot 2 kept:\n{info}"
        );
    }

    /// `sfdisk -d`, parsed just enough: the table's label id, and each
    /// partition's start, size, type and bootable flag.
    fn sfdisk_dump(image: &std::path::Path) -> (String, Vec<(u64, u64, String, bool)>) {
        let out = std::process::Command::new("sfdisk")
            .arg("-d")
            .arg(image)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "sfdisk -d: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(text.contains("label: dos"), "{text}");
        let mut id = String::new();
        let mut parts = Vec::new();
        for line in text.lines() {
            if let Some(v) = line.strip_prefix("label-id: ") {
                id = v.trim().to_string();
            }
            let Some((_, fields)) = line.split_once(" : ") else {
                continue;
            };
            let mut p = (0u64, 0u64, String::new(), false);
            for f in fields.split(',').map(str::trim) {
                match f.split_once('=') {
                    Some(("start", v)) => p.0 = v.trim().parse().unwrap(),
                    Some(("size", v)) => p.1 = v.trim().parse().unwrap(),
                    Some(("type", v)) => p.2 = v.trim().to_string(),
                    None if f == "bootable" => p.3 = true,
                    _ => {}
                }
            }
            parts.push(p);
        }
        (id, parts)
    }

    #[test]
    fn an_mbr_the_writer_lays_down_reads_back_through_sfdisk() {
        if !cfg!(target_os = "linux") || which("sfdisk").is_none() {
            eprintln!("skipping: needs util-linux sfdisk");
            return;
        }
        let (tmp, mut dev) = image(128 * 1024);
        let mut scratch = [0u8; 512];
        let entries = [
            Some(mbr::Entry {
                bootable: true,
                ..mbr::Entry::new(mbr::FAT32_LBA, mbr::FIRST_LBA, 65_536)
            }),
            Some(mbr::Entry::new(mbr::EXFAT, 70_000, 30_000)),
            None,
            Some(mbr::Entry::new(mbr::LINUX, 100_000, 30_000)),
        ];
        mbr::write(&mut dev, &mut scratch, &entries, 0xDEAD_BEEF).unwrap();
        std::fs::write(tmp.path(), &dev.0).unwrap();

        let (id, parts) = sfdisk_dump(tmp.path());
        assert_eq!(id, "0xdeadbeef");
        assert_eq!(
            parts,
            vec![
                (2048, 65_536, "c".into(), true),
                (70_000, 30_000, "7".into(), false),
                (100_000, 30_000, "83".into(), false),
            ]
        );

        // Change a table sfdisk wrote: resize its slot 1, add slot 2.
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!(
                "printf 'label: dos\\nstart=2048, size=10000, type=83\\n' | sfdisk {}",
                tmp.path().display()
            ))
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let mut dev = Disk(std::fs::read(tmp.path()).unwrap());
        mbr::set_entry(
            &mut dev,
            &mut scratch,
            1,
            Some(mbr::Entry::new(mbr::LINUX, 2048, 20_000)),
        )
        .unwrap();
        mbr::set_entry(
            &mut dev,
            &mut scratch,
            2,
            Some(mbr::Entry::new(mbr::FAT32_LBA, 30_000, 5_000)),
        )
        .unwrap();
        std::fs::write(tmp.path(), &dev.0).unwrap();
        let (_, parts) = sfdisk_dump(tmp.path());
        assert_eq!(
            parts,
            vec![
                (2048, 20_000, "83".into(), false),
                (30_000, 5_000, "c".into(), false)
            ]
        );
    }
}
