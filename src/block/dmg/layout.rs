//! Partition-oriented `blkx` maps for the UDIF writer.
//!
//! `hdiutil` gives an image with a partition table one `blkx` entry per
//! region of the disk — the partition-table structures themselves, each
//! partition, and the free space between them — rather than one
//! whole-device entry. [`udif_partition_map`] reproduces that map from a
//! source device's GPT, Apple Partition Map or MBR, with `hdiutil`'s
//! naming and numbering:
//!
//! ```text
//! GPT   Protective Master Boot Record (MBR : 0)          ID -1  desc 0
//!       GPT Header (Primary GPT Header : 1)              ID  0  desc 1
//!       GPT Partition Data (Primary GPT Table : 2)       ID  1  desc 2
//!        (Apple_Free : 3)                                ID  2  desc 3
//!       disk image (Apple_HFS : 4)                       ID  3  desc 4
//!        (Apple_Free : 5)                                …
//!       GPT Partition Data (Backup GPT Table : 6)
//!       GPT Header (Backup GPT Header : 7)
//! APM   Driver Descriptor Map (DDM : 0)                  ID -1  desc -1
//!       Apple (Apple_partition_map : 1)                  ID  0  desc 0
//!       disk image (Apple_HFS : 2)                       ID  1  desc 1
//! MBR   Master Boot Record (MBR : 0)                     ID -1  desc 0
//!        (Apple_HFS : 1)                                 ID  0  desc 1
//! ```
//!
//! Each name is `"<partition name> (<type> : <index>)"`. The type is the
//! APM type string, or the Apple name `hdiutil` uses for well-known GPT
//! GUIDs / MBR type bytes (otherwise the GUID, or `0xNN`). Names are
//! informational — Apple's engine maps sectors from the chunk tables, and
//! the attached disk's partitions come from the table in the data itself.

use super::writer::UdifMapEntry;
use crate::Result;
use crate::block::BlockDevice;
use crate::inspect::{DetectedTable, detect_partition_table};
use crate::part::{PartitionKind, PartitionTable};

/// One named region before indices are assigned.
struct Region {
    start: u64,
    count: u64,
    name: String,
    hint: String,
    /// `(ID, block descriptor)` override; `None` takes `hdiutil`'s default
    /// `(index - 1, index)`.
    ids: Option<(i32, i32)>,
}

impl Region {
    fn new(start: u64, count: u64, name: impl Into<String>, hint: impl Into<String>) -> Self {
        Self {
            start,
            count,
            name: name.into(),
            hint: hint.into(),
            ids: None,
        }
    }
}

/// Build the `hdiutil`-style partition-oriented `blkx` map for `dev`.
///
/// Returns `Ok(None)` when `dev` carries no GPT, APM or MBR (a bare
/// filesystem — use a whole-device layout), and an
/// [`crate::Error::InvalidImage`] when the table's regions overlap.
/// Regions running past the end of the device are clipped to it (or
/// dropped when they start beyond it). The map tiles `[0, total sectors)`
/// exactly, so it can be passed straight to
/// [`UdifLayout::Map`](super::UdifLayout::Map).
pub fn udif_partition_map(dev: &mut dyn BlockDevice) -> Result<Option<Vec<UdifMapEntry>>> {
    let total = dev.total_size();
    if !total.is_multiple_of(512) || total == 0 {
        return Ok(None);
    }
    let sectors = total / 512;
    let Some(table) = detect_partition_table(dev)? else {
        return Ok(None);
    };
    let mut regions = match &table {
        DetectedTable::Gpt(g) => gpt_regions(dev, g.partitions(), sectors)?,
        DetectedTable::Apm(a) => apm_regions(a.partitions()),
        DetectedTable::Mbr(m) => mbr_regions(m.partitions()),
    };
    regions.retain(|r| r.count > 0);
    regions.sort_by_key(|r| r.start);
    Ok(Some(tile(regions, sectors)?))
}

fn gpt_regions(
    dev: &mut dyn BlockDevice,
    parts: &[crate::part::Partition],
    sectors: u64,
) -> Result<Vec<Region>> {
    let mut hdr = [0u8; 512];
    dev.read_at(512, &mut hdr)?;
    let alternate = u64::from_le_bytes(hdr[32..40].try_into().unwrap());
    let entries_lba = u64::from_le_bytes(hdr[72..80].try_into().unwrap());
    let entries_bytes = u64::from(u32::from_le_bytes(hdr[80..84].try_into().unwrap()))
        * u64::from(u32::from_le_bytes(hdr[84..88].try_into().unwrap()));
    let entries_sectors = entries_bytes.div_ceil(512);
    let mut out = vec![
        Region::new(0, 1, "Protective Master Boot Record", "MBR"),
        Region::new(1, 1, "GPT Header", "Primary GPT Header"),
        Region::new(
            entries_lba,
            entries_sectors,
            "GPT Partition Data",
            "Primary GPT Table",
        ),
    ];
    for p in parts {
        if p.kind == PartitionKind::Empty || p.size_lba == 0 {
            continue;
        }
        out.push(Region::new(
            p.start_lba,
            p.size_lba,
            p.name.clone().unwrap_or_default(),
            gpt_type_name(&p.kind),
        ));
    }
    // The backup header names its own entries array; trust it only when it
    // carries the signature. A missing backup leaves that space as free.
    if alternate > 1 && alternate < sectors {
        let mut b = [0u8; 512];
        dev.read_at(alternate * 512, &mut b)?;
        if &b[..8] == crate::part::gpt::SIGNATURE {
            let backup_entries = u64::from_le_bytes(b[72..80].try_into().unwrap());
            out.push(Region::new(
                backup_entries,
                entries_sectors,
                "GPT Partition Data",
                "Backup GPT Table",
            ));
            out.push(Region::new(alternate, 1, "GPT Header", "Backup GPT Header"));
        }
    }
    Ok(out)
}

fn apm_regions(parts: &[crate::part::Partition]) -> Vec<Region> {
    let mut out = vec![Region {
        ids: Some((-1, -1)),
        ..Region::new(0, 1, "Driver Descriptor Map", "DDM")
    }];
    for (i, p) in parts.iter().enumerate() {
        let hint = match &p.kind {
            PartitionKind::Apm(t) => t.clone(),
            other => format!("{other:?}"),
        };
        // `hdiutil` numbers APM regions after the DDM: map entry `i` is
        // index `i + 1` with ID and descriptor `i`.
        let i = i32::try_from(i).unwrap_or(i32::MAX);
        out.push(Region {
            ids: Some((i, i)),
            ..Region::new(
                p.start_lba,
                p.size_lba,
                p.name.clone().unwrap_or_default(),
                hint,
            )
        });
    }
    out
}

fn mbr_regions(parts: &[crate::part::Partition]) -> Vec<Region> {
    let mut out = vec![Region::new(0, 1, "Master Boot Record", "MBR")];
    for p in parts {
        if p.kind == PartitionKind::Empty || p.size_lba == 0 {
            continue;
        }
        out.push(Region::new(
            p.start_lba,
            p.size_lba,
            "",
            mbr_type_name(p.kind.as_mbr_byte()),
        ));
    }
    out
}

/// Fill gaps with `Apple_Free` regions, number everything, and check the
/// regions neither overlap nor overrun the device.
fn tile(regions: Vec<Region>, sectors: u64) -> Result<Vec<UdifMapEntry>> {
    let mut out: Vec<UdifMapEntry> = Vec::with_capacity(regions.len() * 2 + 1);
    let mut next = 0u64;
    for mut r in regions {
        // A table may describe space past the end of the image (`hdiutil`'s
        // own APM images end in an `Apple_Free` entry that overhangs a
        // couple of sectors). Clip it, as the attached device does.
        if r.start >= sectors {
            continue;
        }
        r.count = r.count.min(sectors - r.start);
        let end = r.start + r.count;
        if r.start < next {
            return Err(crate::Error::InvalidImage(format!(
                "dmg: partition region '{}' at sector {} overlaps the previous one (ends at {next})",
                r.name, r.start
            )));
        }
        if r.start > next {
            push(
                Region::new(next, r.start - next, "", "Apple_Free"),
                true,
                &mut out,
            );
        }
        let free = r.hint == "Apple_Free";
        push(r, free, &mut out);
        next = end;
    }
    if next < sectors {
        push(
            Region::new(next, sectors - next, "", "Apple_Free"),
            true,
            &mut out,
        );
    }
    Ok(out)
}

/// Append `r` as the next map entry, numbered `hdiutil`'s way.
fn push(r: Region, free: bool, out: &mut Vec<UdifMapEntry>) {
    let index = out.len();
    let i = i32::try_from(index).unwrap_or(i32::MAX);
    let (id, descriptor) = r.ids.unwrap_or((i - 1, i));
    let mut e = UdifMapEntry::new(
        format!("{} ({} : {index})", r.name, r.hint),
        r.start,
        r.count,
    );
    e.id = id;
    e.descriptor = descriptor;
    e.free_space = free;
    out.push(e);
}

/// The type name `hdiutil` shows for a GPT partition type.
fn gpt_type_name(kind: &PartitionKind) -> String {
    let guid = kind.as_gpt_uuid().as_hyphenated().to_string();
    let guid = guid.to_ascii_uppercase();
    match guid.as_str() {
        "48465300-0000-11AA-AA11-00306543ECAC" => "Apple_HFS",
        "7C3457EF-0000-11AA-AA11-00306543ECAC" => "Apple_APFS",
        "426F6F74-0000-11AA-AA11-00306543ECAC" => "Apple_Boot",
        "55465300-0000-11AA-AA11-00306543ECAC" => "Apple_UFS",
        "52414944-0000-11AA-AA11-00306543ECAC" => "Apple_RAID",
        "52414944-5F4F-11AA-AA11-00306543ECAC" => "Apple_RAID_Offline",
        "4C616265-6C00-11AA-AA11-00306543ECAC" => "Apple_Label",
        "5265636F-7665-11AA-AA11-00306543ECAC" => "Apple_TV_Recovery",
        "53746F72-6167-11AA-AA11-00306543ECAC" => "Apple_CoreStorage",
        "C12A7328-F81F-11D2-BA4B-00A0C93EC93B" => "EFI",
        "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7" => "Microsoft Basic Data",
        "0FC63DAF-8483-4772-8E79-3D69D8477DE4" => "Linux",
        "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F" => "Linux_Swap",
        _ => return guid,
    }
    .into()
}

/// The type name `hdiutil` shows for an MBR partition type byte.
fn mbr_type_name(b: u8) -> String {
    match b {
        0x01 => "DOS_FAT_12",
        0x04 | 0x06 | 0x0E => "DOS_FAT_16",
        0x0B | 0x0C => "DOS_FAT_32",
        0x05 | 0x0F => "DOS_Extended",
        0x07 => "Windows_NTFS",
        0x82 => "Linux_Swap",
        0x83 => "Linux",
        0xA8 => "Apple_UFS",
        0xAB => "Apple_Boot",
        0xAF => "Apple_HFS",
        0xEE | 0xEF => "EFI",
        _ => return format!("0x{b:02X}"),
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::MemoryBackend;
    use crate::part::{Gpt, Mbr, Partition};

    fn hfs_kind() -> PartitionKind {
        PartitionKind::Gpt(uuid::Uuid::parse_str("48465300-0000-11AA-AA11-00306543ECAC").unwrap())
    }

    #[test]
    fn gpt_map_matches_hdiutil_shape() {
        // hdiutil's own GPTSPUD geometry for an 8 MiB image.
        let mut dev = MemoryBackend::new(16384 * 512);
        let mut p = Partition::new(40, 16304, hfs_kind());
        p.name = Some("disk image".into());
        Gpt::build(vec![p]).unwrap().write(&mut dev).unwrap();
        let map = udif_partition_map(&mut dev).unwrap().unwrap();
        let got: Vec<(&str, u64, u64, i32, i32, bool)> = map
            .iter()
            .map(|e| {
                (
                    e.name.as_str(),
                    e.start_sector,
                    e.sector_count,
                    e.id,
                    e.descriptor,
                    e.free_space,
                )
            })
            .collect();
        assert_eq!(
            got,
            [
                (
                    "Protective Master Boot Record (MBR : 0)",
                    0,
                    1,
                    -1,
                    0,
                    false
                ),
                ("GPT Header (Primary GPT Header : 1)", 1, 1, 0, 1, false),
                (
                    "GPT Partition Data (Primary GPT Table : 2)",
                    2,
                    32,
                    1,
                    2,
                    false
                ),
                (" (Apple_Free : 3)", 34, 6, 2, 3, true),
                ("disk image (Apple_HFS : 4)", 40, 16304, 3, 4, false),
                (" (Apple_Free : 5)", 16344, 7, 4, 5, true),
                (
                    "GPT Partition Data (Backup GPT Table : 6)",
                    16351,
                    32,
                    5,
                    6,
                    false
                ),
                ("GPT Header (Backup GPT Header : 7)", 16383, 1, 6, 7, false),
            ]
        );
    }

    #[test]
    fn mbr_map_and_bare_volume() {
        let mut dev = MemoryBackend::new(4096 * 512);
        Mbr::new(vec![Partition::new(1, 4095, PartitionKind::Mbr(0xAF))])
            .unwrap()
            .write(&mut dev)
            .unwrap();
        let map = udif_partition_map(&mut dev).unwrap().unwrap();
        let names: Vec<&str> = map.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["Master Boot Record (MBR : 0)", " (Apple_HFS : 1)"]);
        assert_eq!((map[0].id, map[0].descriptor), (-1, 0));
        assert_eq!((map[1].id, map[1].descriptor), (0, 1));

        let mut blank = MemoryBackend::new(4096 * 512);
        assert!(udif_partition_map(&mut blank).unwrap().is_none());
    }

    #[test]
    fn overhanging_regions_are_clipped_and_overlaps_refused() {
        // A partition running 100 sectors past the end, then one wholly
        // beyond it: the first is clipped, the second dropped.
        let mut dev = MemoryBackend::new(1000 * 512);
        Mbr::new(vec![
            Partition::new(8, 1092, PartitionKind::Mbr(0xAF)),
            Partition::new(2000, 10, PartitionKind::Mbr(0x83)),
        ])
        .unwrap()
        .write(&mut dev)
        .unwrap();
        let map = udif_partition_map(&mut dev).unwrap().unwrap();
        let spans: Vec<(u64, u64, bool)> = map
            .iter()
            .map(|e| (e.start_sector, e.sector_count, e.free_space))
            .collect();
        assert_eq!(spans, [(0, 1, false), (1, 7, true), (8, 992, false)]);

        let mut dev = MemoryBackend::new(1000 * 512);
        Mbr::new(vec![
            Partition::new(1, 500, PartitionKind::Mbr(0xAF)),
            Partition::new(400, 500, PartitionKind::Mbr(0x83)),
        ])
        .unwrap()
        .write(&mut dev)
        .unwrap();
        assert!(matches!(
            udif_partition_map(&mut dev),
            Err(crate::Error::InvalidImage(_))
        ));
    }

    #[test]
    fn apm_map_numbering() {
        let mut dev = MemoryBackend::new(16384 * 512);
        let mut ddm = [0u8; 512];
        ddm[..2].copy_from_slice(b"ER");
        dev.write_at(0, &ddm).unwrap();
        let entry = |start: u32, count: u32, name: &str, ty: &str| {
            let mut e = [0u8; 512];
            e[..2].copy_from_slice(b"PM");
            e[4..8].copy_from_slice(&2u32.to_be_bytes());
            e[8..12].copy_from_slice(&start.to_be_bytes());
            e[12..16].copy_from_slice(&count.to_be_bytes());
            e[16..16 + name.len()].copy_from_slice(name.as_bytes());
            e[48..48 + ty.len()].copy_from_slice(ty.as_bytes());
            e
        };
        dev.write_at(512, &entry(1, 63, "Apple", "Apple_partition_map"))
            .unwrap();
        dev.write_at(1024, &entry(64, 16320, "disk image", "Apple_HFS"))
            .unwrap();
        let map = udif_partition_map(&mut dev).unwrap().unwrap();
        let got: Vec<(&str, i32, i32)> = map
            .iter()
            .map(|e| (e.name.as_str(), e.id, e.descriptor))
            .collect();
        assert_eq!(
            got,
            [
                ("Driver Descriptor Map (DDM : 0)", -1, -1),
                ("Apple (Apple_partition_map : 1)", 0, 0),
                ("disk image (Apple_HFS : 2)", 1, 1),
            ]
        );
    }
}
