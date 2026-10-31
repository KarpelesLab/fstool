//! ISO 9660 metadata for file data placed by the caller.
//!
//! [`super::Iso9660Writer`] owns its image: it streams each file into a
//! data area of its own and lays the metadata out behind it. A hybrid
//! image cannot work that way — the file payloads are shared with other
//! filesystem views (HFS+, UDF) and are placed once, by a planner that
//! sees every view (see `fs::hybrid`). This module is the ISO 9660 half
//! of that arrangement: the caller describes one or two directory
//! hierarchies whose files already point at sectors, and this module
//! sizes and writes everything that references them:
//!
//! * the volume descriptor set at LBA 16 — the Primary Volume Descriptor,
//!   an El Torito Boot Record, a Joliet Supplementary Volume Descriptor
//!   and the terminator;
//! * the El Torito boot catalog;
//! * L- and M-type path tables for each hierarchy;
//! * the directory extents, with multi-extent records for files of
//!   4 GiB and more (ECMA-119 interchange level 3);
//! * Rock Ridge (RRIP 1.10, `RRIP_1991A`) System Use entries — `SP`, `ER`,
//!   `RR`, `PX`, `PN`, `SL`, `NM`, `TF` — spilling into `CE`
//!   continuation areas when a record's 255 bytes are not enough, so
//!   long names and symlink targets need no truncation.
//!
//! Sizing is independent of where things end up: every directory extent,
//! path table and continuation area has a size that depends only on the
//! hierarchy, so a planner can ask for [`PlacedIso::metadata_sectors`],
//! decide where the metadata goes, and only then fix file LBAs.
//!
//! The caller supplies identifiers already encoded (d-characters with a
//! `;1` version for primary files, UCS-2 big-endian for Joliet): name
//! mapping, collision resolution and reporting belong to the planner.
//! What this module does check — and refuses with an error rather than
//! writing a damaged image — is everything the format bounds: identifier
//! and record lengths, duplicate identifiers in one directory, 65 535
//! directories per path table, extents past the end of the volume and
//! metadata that would overlap the volume descriptors.

use std::cmp::Ordering;
use std::collections::VecDeque;

use crate::Result;
use crate::block::BlockDevice;

use super::writer::{
    days_to_ymd, put_both_u16, put_both_u32, write_padded_ascii, write_padded_ucs2,
};

/// Logical sector size (ECMA-119 fixes it at 2 KiB for optical media).
pub const SECTOR: u64 = 2048;

/// LBA of the first volume descriptor.
pub const VD_START_LBA: u32 = 16;

/// Largest section of a multi-extent file: the largest multiple of the
/// sector size a 32-bit data length can hold.
pub const MAX_SECTION_BYTES: u64 = 0xFFFF_F800;

/// Longest directory record (its length is one byte).
const MAX_RECORD: usize = 255;
/// Bytes of a `CE` entry.
const CE_LEN: usize = 28;
/// Longest continuation area. Readers (Linux, the BSDs) read one block
/// per area, so an area never crosses a sector.
const MAX_AREA: usize = SECTOR as usize;

/// Which kind of directory hierarchy a [`Hierarchy`] encodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Encoding {
    /// The primary hierarchy: 8-bit identifiers, optionally with Rock
    /// Ridge entries.
    Primary,
    /// A Joliet hierarchy: UCS-2 big-endian identifiers, no Rock Ridge.
    Joliet,
}

/// What a node is, as far as the directory records are concerned.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NodeKind {
    /// A directory; its extent is laid out by this module.
    Dir,
    /// A regular file whose `size` bytes start at sector `lba` and run
    /// contiguously (files of [`MAX_SECTION_BYTES`] or more become
    /// multi-extent records over consecutive sections). An empty file
    /// has `size == 0` and conventionally `lba == 0`.
    File {
        /// First sector of the payload.
        lba: u32,
        /// Payload length in bytes.
        size: u64,
    },
    /// A node with no data extent whose type is carried by Rock Ridge
    /// alone (symbolic link, device, FIFO, socket).
    Special,
}

/// Rock Ridge attributes of a node.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct RockRidge {
    /// The POSIX name (`NM`). Empty on the root.
    pub name: String,
    /// Full `st_mode`, type bits included (`PX`).
    pub mode: u32,
    /// Link count (`PX`).
    pub nlink: u32,
    /// Owner (`PX`).
    pub uid: u32,
    /// Group (`PX`).
    pub gid: u32,
    /// Modification time, seconds since the Unix epoch (`TF`).
    pub mtime: i64,
    /// Access time (`TF`).
    pub atime: i64,
    /// Attribute-change time (`TF`).
    pub ctime: i64,
    /// Symbolic link target (`SL`).
    pub symlink: Option<String>,
    /// Device number `(major, minor)` for character / block devices (`PN`).
    pub rdev: Option<(u32, u32)>,
}

impl RockRidge {
    /// Attributes with the given name and mode, everything else zero
    /// (`nlink` 1).
    pub fn new(name: impl Into<String>, mode: u32) -> Self {
        Self {
            name: name.into(),
            mode,
            nlink: 1,
            ..Self::default()
        }
    }
}

/// One node of a [`Hierarchy`].
#[derive(Debug, Clone)]
struct Node {
    parent: usize,
    identifier: Vec<u8>,
    kind: NodeKind,
    mtime: i64,
    hidden: bool,
    rr: Option<RockRidge>,
    children: Vec<usize>,
}

/// A directory hierarchy (primary or Joliet) whose files point at
/// caller-placed sectors. Node `0` is the root.
#[derive(Debug, Clone)]
pub struct Hierarchy {
    encoding: Encoding,
    nodes: Vec<Node>,
}

impl Hierarchy {
    /// Node id of the root directory.
    pub const ROOT: usize = 0;

    /// An empty hierarchy. `root_rr` is the root's Rock Ridge attributes
    /// (primary hierarchies with Rock Ridge only).
    pub fn new(encoding: Encoding, root_mtime: i64, root_rr: Option<RockRidge>) -> Self {
        Self {
            encoding,
            nodes: vec![Node {
                parent: 0,
                identifier: vec![0],
                kind: NodeKind::Dir,
                mtime: root_mtime,
                hidden: false,
                rr: root_rr,
                children: Vec::new(),
            }],
        }
    }

    /// The encoding the identifiers are in.
    pub fn encoding(&self) -> Encoding {
        self.encoding
    }

    /// Number of nodes, root included.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Never true: the root always exists.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Add a child of directory `parent` and return its node id.
    ///
    /// `identifier` is the on-disk file identifier, already encoded:
    /// d-characters (`NAME.EXT;1` for files, `NAME` for directories) in
    /// a primary hierarchy, UCS-2 big-endian in a Joliet one. Duplicate
    /// identifiers within a directory are refused when the metadata is
    /// laid out. Rock Ridge attributes are ignored in a Joliet hierarchy.
    pub fn add(
        &mut self,
        parent: usize,
        identifier: Vec<u8>,
        kind: NodeKind,
        mtime: i64,
        rr: Option<RockRidge>,
    ) -> Result<usize> {
        let Some(p) = self.nodes.get(parent) else {
            return Err(crate::Error::InvalidArgument(format!(
                "iso9660: parent node {parent} does not exist"
            )));
        };
        if p.kind != NodeKind::Dir {
            return Err(crate::Error::InvalidArgument(format!(
                "iso9660: parent node {parent} is not a directory"
            )));
        }
        if identifier.is_empty() || identifier.len() > 222 {
            return Err(crate::Error::InvalidArgument(format!(
                "iso9660: identifier of {} bytes (1..=222 allowed)",
                identifier.len()
            )));
        }
        if self.encoding == Encoding::Joliet && !identifier.len().is_multiple_of(2) {
            return Err(crate::Error::InvalidArgument(
                "iso9660: Joliet identifiers are UCS-2 (even length)".into(),
            ));
        }
        if self.encoding == Encoding::Primary && identifier.len() == 1 && identifier[0] <= 1 {
            return Err(crate::Error::InvalidArgument(
                "iso9660: identifiers 0x00 / 0x01 are reserved for . and ..".into(),
            ));
        }
        let id = self.nodes.len();
        let rr = if self.encoding == Encoding::Joliet {
            None
        } else {
            rr
        };
        self.nodes.push(Node {
            parent,
            identifier,
            kind,
            mtime,
            hidden: false,
            rr,
            children: Vec::new(),
        });
        self.nodes[parent].children.push(id);
        Ok(id)
    }

    /// Point file node `id` at its payload once it is placed (sizes —
    /// hence the layout — do not change when only the LBA moves, but
    /// `size` must stay what it was when the layout was computed).
    pub fn set_extent(&mut self, id: usize, lba: u32, size: u64) -> Result<()> {
        match self.nodes.get_mut(id) {
            Some(n) if matches!(n.kind, NodeKind::File { .. }) => {
                n.kind = NodeKind::File { lba, size };
                Ok(())
            }
            _ => Err(crate::Error::InvalidArgument(format!(
                "iso9660: node {id} is not a file"
            ))),
        }
    }

    /// Set the ECMA-119 "existence" (hidden) flag on node `id`: readers
    /// that honour it do not list the entry, though it stays reachable.
    pub fn set_hidden(&mut self, id: usize, hidden: bool) {
        if let Some(n) = self.nodes.get_mut(id) {
            n.hidden = hidden;
        }
    }

    /// Directories in path-table order (ECMA-119 6.9.1: by level, then
    /// parent number, then identifier) with their 1-based parent number.
    fn directories(&self) -> Vec<(usize, u16)> {
        let mut out: Vec<(usize, u16)> = vec![(0, 1)];
        let mut queue = VecDeque::from([(0usize, 0usize)]);
        while let Some((dir, idx)) = queue.pop_front() {
            for &c in &self.sorted_children(dir) {
                if self.nodes[c].kind == NodeKind::Dir {
                    out.push((c, (idx + 1) as u16));
                    queue.push_back((c, out.len() - 1));
                }
            }
        }
        out
    }

    fn sorted_children(&self, dir: usize) -> Vec<usize> {
        let mut kids = self.nodes[dir].children.clone();
        let joliet = self.encoding == Encoding::Joliet;
        kids.sort_by(|&a, &b| {
            compare_identifiers(&self.nodes[a].identifier, &self.nodes[b].identifier, joliet)
        });
        kids
    }
}

/// ECMA-119 9.3 record order: by name, then extension (both padded
/// with spaces), then by descending version. Joliet identifiers are
/// compared as UCS-2 code units the same way.
fn compare_identifiers(a: &[u8], b: &[u8], joliet: bool) -> Ordering {
    let units = |s: &[u8]| -> Vec<u16> {
        if joliet {
            s.chunks(2)
                .map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]))
                .collect()
        } else {
            s.iter().map(|&b| u16::from(b)).collect()
        }
    };
    let split = |u: Vec<u16>| -> (Vec<u16>, Vec<u16>, Vec<u16>) {
        let (body, ver) = match u.iter().position(|&c| c == u16::from(b';')) {
            Some(i) => (u[..i].to_vec(), u[i + 1..].to_vec()),
            None => (u, Vec::new()),
        };
        match body.iter().rposition(|&c| c == u16::from(b'.')) {
            Some(i) => (body[..i].to_vec(), body[i + 1..].to_vec(), ver),
            None => (body, Vec::new(), ver),
        }
    };
    let pad_cmp = |x: &[u16], y: &[u16]| -> Ordering {
        let n = x.len().max(y.len());
        for i in 0..n {
            let cx = *x.get(i).unwrap_or(&0x20);
            let cy = *y.get(i).unwrap_or(&0x20);
            match cx.cmp(&cy) {
                Ordering::Equal => continue,
                o => return o,
            }
        }
        Ordering::Equal
    };
    let (an, ae, av) = split(units(a));
    let (bn, be, bv) = split(units(b));
    pad_cmp(&an, &bn)
        .then_with(|| pad_cmp(&ae, &be))
        .then_with(|| pad_cmp(&bv, &av))
}

/// Identification fields of the volume descriptors. Strings longer than
/// their field are cut at the field size (the planner reports that);
/// primary fields are written as bytes, Joliet ones as UCS-2.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct VolumeInfo {
    /// System identifier (32 a-characters).
    pub system_id: String,
    /// Primary volume identifier (32 d-characters).
    pub volume_id: String,
    /// Joliet volume identifier (16 UCS-2 characters).
    pub joliet_volume_id: String,
    /// Volume set identifier (128).
    pub volume_set_id: String,
    /// Publisher identifier (128).
    pub publisher_id: String,
    /// Data preparer identifier (128).
    pub preparer_id: String,
    /// Application identifier (128).
    pub application_id: String,
    /// Copyright file identifier (37) — a file in the root directory.
    pub copyright_file: String,
    /// Abstract file identifier (37).
    pub abstract_file: String,
    /// Bibliographic file identifier (37).
    pub bibliographic_file: String,
    /// Volume creation / modification time, seconds since the Unix epoch.
    pub create_date: i64,
}

/// One El Torito boot entry. The first entry of
/// [`PlacedIso::boot`] is the default (initial) entry; the rest follow
/// in section headers, one section per platform.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BootImage {
    /// Platform id: 0 x86 BIOS, 1 PowerPC, 2 Mac, 0xEF EFI.
    pub platform: u8,
    /// Boot media type: 0 no emulation, 1/2/3 1.2/1.44/2.88 MB floppy,
    /// 4 hard disk.
    pub media_type: u8,
    /// Real-mode load segment (0 = the BIOS default 0x7C0).
    pub load_segment: u16,
    /// Partition type byte, for hard-disk emulation.
    pub system_type: u8,
    /// 512-byte virtual sectors the firmware loads.
    pub sector_count: u16,
    /// First sector of the boot image.
    pub load_rba: u32,
    /// Id string of the validation entry / section header (24 / 28 bytes).
    pub id_string: String,
}

impl BootImage {
    /// A no-emulation x86 boot entry loading `sector_count` 512-byte
    /// sectors from `load_rba`.
    pub fn no_emulation(load_rba: u32, sector_count: u16) -> Self {
        Self {
            platform: 0,
            media_type: 0,
            load_segment: 0,
            system_type: 0,
            sector_count,
            load_rba,
            id_string: String::new(),
        }
    }
}

/// A complete ISO 9660 volume description over caller-placed data.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PlacedIso {
    /// Identification fields.
    pub info: VolumeInfo,
    /// The primary hierarchy.
    pub primary: Hierarchy,
    /// Emit Rock Ridge entries in the primary hierarchy.
    pub rock_ridge: bool,
    /// The Joliet hierarchy, when one is advertised.
    pub joliet: Option<Hierarchy>,
    /// El Torito boot entries (empty: not bootable).
    pub boot: Vec<BootImage>,
    /// Allow files of [`Self::section_bytes`] or more as multi-extent
    /// records (interchange level 3). When false such files are refused.
    pub multi_extent: bool,
    /// Section size of multi-extent files: a multiple of [`SECTOR`] no
    /// larger than [`MAX_SECTION_BYTES`] (the default). Smaller values
    /// exist for tests and for readers with tighter limits.
    pub section_bytes: u64,
}

impl PlacedIso {
    /// A volume over `primary`, Rock Ridge on, no Joliet, not bootable.
    pub fn new(info: VolumeInfo, primary: Hierarchy) -> Self {
        Self {
            info,
            primary,
            rock_ridge: true,
            joliet: None,
            boot: Vec::new(),
            multi_extent: true,
            section_bytes: MAX_SECTION_BYTES,
        }
    }

    /// Sectors of the volume descriptor set starting at LBA 16: the PVD,
    /// the boot record, the Joliet SVD and the terminator.
    pub fn descriptor_sectors(&self) -> u32 {
        2 + u32::from(!self.boot.is_empty()) + u32::from(self.joliet.is_some())
    }

    /// Sectors everything after the descriptor set needs (boot catalog,
    /// path tables, directories, continuation areas). Independent of
    /// where it is placed and of file LBAs.
    pub fn metadata_sectors(&self) -> Result<u32> {
        Ok(self.layout(0)?.end_lba)
    }

    /// Lay the metadata out from `meta_lba` on: boot catalog, path
    /// tables, then each hierarchy's directories and continuation areas.
    pub fn layout(&self, meta_lba: u32) -> Result<IsoLayout> {
        if self.primary.encoding != Encoding::Primary {
            return Err(crate::Error::InvalidArgument(
                "iso9660: the primary hierarchy must use Encoding::Primary".into(),
            ));
        }
        if let Some(j) = &self.joliet
            && j.encoding != Encoding::Joliet
        {
            return Err(crate::Error::InvalidArgument(
                "iso9660: the Joliet hierarchy must use Encoding::Joliet".into(),
            ));
        }
        if self.section_bytes == 0
            || !self.section_bytes.is_multiple_of(SECTOR)
            || self.section_bytes > MAX_SECTION_BYTES
        {
            return Err(crate::Error::InvalidArgument(format!(
                "iso9660: section size {} is not a sector multiple ≤ {MAX_SECTION_BYTES}",
                self.section_bytes
            )));
        }
        if self.boot.len() > 64 {
            return Err(crate::Error::InvalidArgument(
                "iso9660: more El Torito entries than one catalog sector holds".into(),
            ));
        }
        let mut cursor = meta_lba;
        let mut regions = Vec::new();
        let boot_catalog_lba = if self.boot.is_empty() {
            None
        } else {
            regions.push(IsoRegion::new("el-torito-catalog", cursor, 1));
            cursor += 1;
            Some(cursor - 1)
        };
        let mut hier = Vec::new();
        let rr_flags = [self.rock_ridge, false];
        for (i, h) in [Some(&self.primary), self.joliet.as_ref()]
            .into_iter()
            .enumerate()
        {
            let Some(h) = h else { continue };
            let plan = HierPlan::build(h, rr_flags[i], self)?;
            hier.push(plan);
        }
        // Path tables of every hierarchy first, then the directories,
        // then the continuation areas.
        for (i, p) in hier.iter_mut().enumerate() {
            let label = if i == 0 { "primary" } else { "joliet" };
            let secs = sectors(u64::from(p.path_table_bytes))?;
            p.l_table_lba = cursor;
            regions.push(IsoRegion::named(label, "l-path-table", cursor, secs));
            cursor = add(cursor, secs)?;
            p.m_table_lba = cursor;
            regions.push(IsoRegion::named(label, "m-path-table", cursor, secs));
            cursor = add(cursor, secs)?;
        }
        for (i, p) in hier.iter_mut().enumerate() {
            let label = if i == 0 { "primary" } else { "joliet" };
            let start = cursor;
            for d in &mut p.dirs {
                d.lba = cursor;
                cursor = add(cursor, d.sectors)?;
            }
            regions.push(IsoRegion::named(
                label,
                "directories",
                start,
                cursor - start,
            ));
        }
        for (i, p) in hier.iter_mut().enumerate() {
            if p.areas.is_empty() {
                continue;
            }
            let label = if i == 0 { "primary" } else { "joliet" };
            let start = cursor;
            let mut sector = 0u32;
            let mut used = 0usize;
            for a in &mut p.areas {
                if used + a.data.len() > MAX_AREA {
                    sector += 1;
                    used = 0;
                }
                a.lba = start + sector;
                a.offset = used as u32;
                used += a.data.len();
            }
            cursor = add(start, sector + 1)?;
            regions.push(IsoRegion::named(
                label,
                "rock-ridge-continuation",
                start,
                cursor - start,
            ));
        }
        Ok(IsoLayout {
            meta_lba,
            end_lba: cursor,
            boot_catalog_lba,
            regions,
            hier,
        })
    }

    /// Write the descriptor set (at LBA 16) and the metadata `layout`
    /// places, for a volume of `volume_sectors` sectors. File payloads
    /// are not touched; every file extent is checked against the volume
    /// size first, as is the metadata against the descriptor set.
    pub fn write(
        &self,
        dev: &mut dyn BlockDevice,
        layout: &IsoLayout,
        volume_sectors: u32,
    ) -> Result<()> {
        let vd_end = VD_START_LBA + self.descriptor_sectors();
        if layout.meta_lba < vd_end && layout.end_lba > layout.meta_lba {
            return Err(crate::Error::InvalidArgument(format!(
                "iso9660: metadata at LBA {} overlaps the volume descriptors (16..{vd_end})",
                layout.meta_lba
            )));
        }
        if layout.end_lba > volume_sectors || vd_end > volume_sectors {
            return Err(crate::Error::OutOfBounds {
                offset: u64::from(layout.meta_lba) * SECTOR,
                len: u64::from(layout.end_lba - layout.meta_lba) * SECTOR,
                size: u64::from(volume_sectors) * SECTOR,
            });
        }
        let total = u64::from(volume_sectors) * SECTOR;
        let check_extent = |what: &str, lba: u32, bytes: u64| -> Result<()> {
            let end = u64::from(lba) * SECTOR + bytes;
            if end > total {
                return Err(crate::Error::InvalidArgument(format!(
                    "iso9660: {what} at LBA {lba} ({bytes} bytes) runs past the \
                     {volume_sectors}-sector volume"
                )));
            }
            Ok(())
        };
        for h in [Some(&self.primary), self.joliet.as_ref()]
            .into_iter()
            .flatten()
        {
            for n in &h.nodes {
                if let NodeKind::File { lba, size } = n.kind {
                    check_extent("file", lba, size)?;
                }
            }
        }
        for b in &self.boot {
            check_extent("boot image", b.load_rba, u64::from(b.sector_count) * 512)?;
        }

        // Descriptor set.
        let mut lba = VD_START_LBA;
        let primary = &layout.hier[0];
        let pvd = self.encode_vd(primary, volume_sectors, false);
        dev.write_at(u64::from(lba) * SECTOR, &pvd)?;
        lba += 1;
        if let Some(cat) = layout.boot_catalog_lba {
            dev.write_at(u64::from(lba) * SECTOR, &encode_boot_record(cat))?;
            lba += 1;
            dev.write_at(u64::from(cat) * SECTOR, &self.encode_boot_catalog()?)?;
        }
        if self.joliet.is_some() {
            let svd = self.encode_vd(&layout.hier[1], volume_sectors, true);
            dev.write_at(u64::from(lba) * SECTOR, &svd)?;
            lba += 1;
        }
        let mut vdst = vec![0u8; SECTOR as usize];
        vdst[0] = 0xFF;
        vdst[1..6].copy_from_slice(b"CD001");
        vdst[6] = 1;
        dev.write_at(u64::from(lba) * SECTOR, &vdst)?;

        for (i, plan) in layout.hier.iter().enumerate() {
            let h = if i == 0 {
                &self.primary
            } else {
                self.joliet.as_ref().expect("planned from it")
            };
            plan.write(dev, h)?;
        }
        Ok(())
    }

    fn encode_vd(&self, plan: &HierPlan, volume_sectors: u32, joliet: bool) -> Vec<u8> {
        let info = &self.info;
        let mut b = vec![0u8; SECTOR as usize];
        b[0] = if joliet { 2 } else { 1 };
        b[1..6].copy_from_slice(b"CD001");
        b[6] = 1;
        let ascii = |buf: &mut [u8], s: &str| write_padded_ascii(buf, s);
        let ucs = |buf: &mut [u8], s: &str| write_padded_ucs2(buf, &ucs2(s));
        let field = |buf: &mut [u8], s: &str| {
            if joliet { ucs(buf, s) } else { ascii(buf, s) }
        };
        field(&mut b[8..40], &info.system_id);
        if joliet {
            ucs(&mut b[40..72], &info.joliet_volume_id);
            // UCS-2 level 3.
            b[88..91].copy_from_slice(b"%/E");
        } else {
            ascii(&mut b[40..72], &info.volume_id);
        }
        put_both_u32(&mut b[80..88], volume_sectors);
        put_both_u16(&mut b[120..124], 1); // volume set size
        put_both_u16(&mut b[124..128], 1); // volume sequence number
        put_both_u16(&mut b[128..132], SECTOR as u16);
        put_both_u32(&mut b[132..140], plan.path_table_bytes);
        b[140..144].copy_from_slice(&plan.l_table_lba.to_le_bytes());
        b[148..152].copy_from_slice(&plan.m_table_lba.to_be_bytes());
        let root = &plan.dirs[0];
        let mut rec = [0u8; 34];
        rec[0] = 34;
        put_both_u32(&mut rec[2..10], root.lba);
        put_both_u32(&mut rec[10..18], root.sectors * SECTOR as u32);
        rec[18..25].copy_from_slice(&short_date(plan.root_mtime));
        rec[25] = 0x02;
        put_both_u16(&mut rec[28..32], 1);
        rec[32] = 1;
        b[156..190].copy_from_slice(&rec);
        field(&mut b[190..318], &info.volume_set_id);
        field(&mut b[318..446], &info.publisher_id);
        field(&mut b[446..574], &info.preparer_id);
        field(&mut b[574..702], &info.application_id);
        // File identifiers: 37 bytes (18 UCS-2 units plus a pad byte).
        for (range, s) in [
            (702..739, &info.copyright_file),
            (739..776, &info.abstract_file),
            (776..813, &info.bibliographic_file),
        ] {
            if joliet {
                write_padded_ucs2(&mut b[range.start..range.end - 1], &ucs2(s));
                b[range.end - 1] = 0;
            } else {
                ascii(&mut b[range], s);
            }
        }
        let date = long_date(info.create_date);
        b[813..830].copy_from_slice(&date); // creation
        b[830..847].copy_from_slice(&date); // modification
        b[847..864].copy_from_slice(&long_date_unset()); // expiration
        b[864..881].copy_from_slice(&date); // effective
        b[881] = 1; // file structure version
        b
    }

    fn encode_boot_catalog(&self) -> Result<Vec<u8>> {
        let mut c = vec![0u8; SECTOR as usize];
        let first = &self.boot[0];
        // Validation entry.
        c[0] = 1;
        c[1] = first.platform;
        write_id(&mut c[4..28], &first.id_string);
        c[30] = 0x55;
        c[31] = 0xAA;
        let sum = c[..32].chunks(2).fold(0u16, |a, w| {
            a.wrapping_add(u16::from_le_bytes([w[0], w[1]]))
        });
        c[28..30].copy_from_slice(&0u16.wrapping_sub(sum).to_le_bytes());
        encode_boot_entry(&mut c[32..64], first);
        // Further entries: one section per run of equal platforms.
        let rest = &self.boot[1..];
        let mut at = 64usize;
        let mut i = 0usize;
        while i < rest.len() {
            let platform = rest[i].platform;
            let n = rest[i..]
                .iter()
                .take_while(|e| e.platform == platform)
                .count();
            let last = i + n == rest.len();
            if at + 32 * (n + 1) > c.len() {
                return Err(crate::Error::InvalidArgument(
                    "iso9660: El Torito catalog does not fit one sector".into(),
                ));
            }
            c[at] = if last { 0x91 } else { 0x90 };
            c[at + 1] = platform;
            c[at + 2..at + 4].copy_from_slice(&(n as u16).to_le_bytes());
            write_id(&mut c[at + 4..at + 32], &rest[i].id_string);
            at += 32;
            for e in &rest[i..i + n] {
                encode_boot_entry(&mut c[at..at + 32], e);
                at += 32;
            }
            i += n;
        }
        Ok(c)
    }
}

fn write_id(buf: &mut [u8], s: &str) {
    let b = s.as_bytes();
    let n = b.len().min(buf.len());
    buf[..n].copy_from_slice(&b[..n]);
}

fn encode_boot_entry(e: &mut [u8], b: &BootImage) {
    e[0] = 0x88;
    e[1] = b.media_type;
    e[2..4].copy_from_slice(&b.load_segment.to_le_bytes());
    e[4] = b.system_type;
    e[6..8].copy_from_slice(&b.sector_count.to_le_bytes());
    e[8..12].copy_from_slice(&b.load_rba.to_le_bytes());
}

fn encode_boot_record(catalog_lba: u32) -> Vec<u8> {
    let mut b = vec![0u8; SECTOR as usize];
    b[0] = 0;
    b[1..6].copy_from_slice(b"CD001");
    b[6] = 1;
    b[7..7 + 23].copy_from_slice(b"EL TORITO SPECIFICATION");
    b[0x47..0x4B].copy_from_slice(&catalog_lba.to_le_bytes());
    b
}

/// One region the metadata occupies, for inspection and overlap checks.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct IsoRegion {
    /// What it holds, e.g. `"primary/directories"`.
    pub label: String,
    /// First sector.
    pub lba: u32,
    /// Length in sectors.
    pub sectors: u32,
}

impl IsoRegion {
    fn new(label: &str, lba: u32, sectors: u32) -> Self {
        Self {
            label: label.into(),
            lba,
            sectors,
        }
    }
    fn named(h: &str, what: &str, lba: u32, sectors: u32) -> Self {
        Self::new(&format!("{h}/{what}"), lba, sectors)
    }
}

/// Where [`PlacedIso::layout`] put the metadata.
#[derive(Debug, Clone)]
pub struct IsoLayout {
    meta_lba: u32,
    end_lba: u32,
    boot_catalog_lba: Option<u32>,
    regions: Vec<IsoRegion>,
    hier: Vec<HierPlan>,
}

impl IsoLayout {
    /// First sector of the metadata.
    pub fn start_lba(&self) -> u32 {
        self.meta_lba
    }
    /// One past the last sector of the metadata.
    pub fn end_lba(&self) -> u32 {
        self.end_lba
    }
    /// Sectors of metadata.
    pub fn sectors(&self) -> u32 {
        self.end_lba - self.meta_lba
    }
    /// Every region, in sector order.
    pub fn regions(&self) -> &[IsoRegion] {
        &self.regions
    }
    /// LBA of the El Torito boot catalog, when bootable.
    pub fn boot_catalog_lba(&self) -> Option<u32> {
        self.boot_catalog_lba
    }
}

/// Where a `CE` entry sits in a System Use field (byte offset) and the
/// continuation area it points to.
type CeSlot = Option<(usize, usize)>;

/// A continuation area: SUSP entries, maybe ending in a `CE` to the
/// next area of the chain.
#[derive(Debug, Clone)]
struct Area {
    data: Vec<u8>,
    /// Offset of a `CE` entry inside `data` and the area it points to.
    ce: Option<(usize, usize)>,
    lba: u32,
    offset: u32,
}

/// What a record's extent refers to.
#[derive(Debug, Clone, Copy)]
enum Target {
    /// Directory number (index into `HierPlan::dirs`).
    Dir(usize),
    /// A file section.
    Data { lba: u32, len: u32 },
    /// No extent.
    None,
}

#[derive(Debug, Clone)]
struct Record {
    /// Offset of the record inside the directory extent.
    offset: usize,
    target: Target,
    flags: u8,
    mtime: i64,
    identifier: Vec<u8>,
    sua: Vec<u8>,
    /// `CE` inside `sua` and the area it points to.
    ce: Option<(usize, usize)>,
}

#[derive(Debug, Clone)]
struct DirPlan {
    records: Vec<Record>,
    sectors: u32,
    lba: u32,
}

#[derive(Debug, Clone)]
struct HierPlan {
    /// Path-table order: (node, 1-based parent number).
    order: Vec<(usize, u16)>,
    dirs: Vec<DirPlan>,
    areas: Vec<Area>,
    path_table_bytes: u32,
    l_table_lba: u32,
    m_table_lba: u32,
    root_mtime: i64,
}

impl HierPlan {
    fn build(h: &Hierarchy, rock_ridge: bool, iso: &PlacedIso) -> Result<Self> {
        let order = h.directories();
        if order.len() > usize::from(u16::MAX) {
            return Err(crate::Error::InvalidArgument(format!(
                "iso9660: {} directories; a path table numbers at most 65535",
                order.len()
            )));
        }
        let mut dir_index = vec![usize::MAX; h.nodes.len()];
        for (i, (n, _)) in order.iter().enumerate() {
            dir_index[*n] = i;
        }
        let mut path_table_bytes: u64 = 0;
        for (n, _) in &order {
            let len = if *n == 0 {
                1
            } else {
                h.nodes[*n].identifier.len()
            };
            path_table_bytes += 8 + len as u64 + (len as u64 % 2);
        }
        let path_table_bytes = u32::try_from(path_table_bytes).map_err(|_| {
            crate::Error::InvalidArgument("iso9660: path table exceeds 4 GiB".into())
        })?;
        let mut plan = Self {
            order: order.clone(),
            dirs: Vec::with_capacity(order.len()),
            areas: Vec::new(),
            path_table_bytes,
            l_table_lba: 0,
            m_table_lba: 0,
            root_mtime: h.nodes[0].mtime,
        };
        for (dir_no, (node, _)) in order.iter().enumerate() {
            let node = *node;
            let parent = h.nodes[node].parent;
            let mut records = Vec::new();
            // "." and "..".
            for (ident, of) in [(0u8, node), (1u8, parent)] {
                let n = &h.nodes[of];
                let mut entries = Vec::new();
                if rock_ridge {
                    if node == 0 && ident == 0 {
                        entries.push(SP_ENTRY.to_vec());
                        entries.push(er_entry());
                    }
                    if let Some(rr) = &n.rr {
                        entries.push(rr_flags_entry(rr, false));
                        entries.push(px_entry(rr));
                        entries.push(tf_entry(rr));
                    }
                }
                let (sua, ce) = plan.pack_sua(34, entries)?;
                records.push(Record {
                    offset: 0,
                    target: Target::Dir(dir_index[of]),
                    flags: 0x02,
                    mtime: n.mtime,
                    identifier: vec![ident],
                    sua,
                    ce,
                });
            }
            let kids = h.sorted_children(node);
            for w in kids.windows(2) {
                if h.nodes[w[0]].identifier == h.nodes[w[1]].identifier {
                    return Err(crate::Error::InvalidArgument(format!(
                        "iso9660: duplicate identifier {:?} in one directory",
                        String::from_utf8_lossy(&h.nodes[w[0]].identifier)
                    )));
                }
            }
            for c in kids {
                let n = &h.nodes[c];
                let mut entries = Vec::new();
                if rock_ridge && let Some(rr) = &n.rr {
                    entries.push(rr_flags_entry(rr, true));
                    entries.push(px_entry(rr));
                    if let Some((major, minor)) = rr.rdev {
                        entries.push(pn_entry(major, minor));
                    }
                    if let Some(t) = &rr.symlink {
                        entries.extend(sl_entries(t));
                    }
                    entries.extend(nm_entries(&rr.name));
                    entries.push(tf_entry(rr));
                }
                let base =
                    33 + n.identifier.len() + usize::from(n.identifier.len().is_multiple_of(2));
                let (sua, ce) = plan.pack_sua(base, entries)?;
                let hidden = if n.hidden { 0x01 } else { 0 };
                match n.kind {
                    NodeKind::Dir => records.push(Record {
                        offset: 0,
                        target: Target::Dir(dir_index[c]),
                        flags: 0x02 | hidden,
                        mtime: n.mtime,
                        identifier: n.identifier.clone(),
                        sua,
                        ce,
                    }),
                    NodeKind::Special => records.push(Record {
                        offset: 0,
                        target: Target::None,
                        flags: hidden,
                        mtime: n.mtime,
                        identifier: n.identifier.clone(),
                        sua,
                        ce,
                    }),
                    NodeKind::File { lba, size } => {
                        let section = iso.section_bytes;
                        if size > u64::from(u32::MAX) && !iso.multi_extent {
                            return Err(crate::Error::InvalidArgument(format!(
                                "iso9660: file {:?} is {size} bytes; files of 4 GiB or more \
                                 need multi-extent records (interchange level 3)",
                                String::from_utf8_lossy(&n.identifier)
                            )));
                        }
                        let split = if iso.multi_extent {
                            section
                        } else {
                            u64::from(u32::MAX)
                        };
                        let mut off = 0u64;
                        loop {
                            let len = (size - off).min(split);
                            let last = off + len >= size;
                            let sec_lba = u64::from(lba) + off / SECTOR;
                            let sec_lba = u32::try_from(sec_lba).map_err(|_| {
                                crate::Error::InvalidArgument(
                                    "iso9660: file section past LBA 2^32".into(),
                                )
                            })?;
                            records.push(Record {
                                offset: 0,
                                target: Target::Data {
                                    lba: if size == 0 { lba } else { sec_lba },
                                    len: len as u32,
                                },
                                flags: hidden | if last { 0 } else { 0x80 },
                                mtime: n.mtime,
                                identifier: n.identifier.clone(),
                                sua: sua.clone(),
                                ce,
                            });
                            off += len;
                            if last {
                                break;
                            }
                        }
                    }
                }
            }
            // Offsets: records never straddle a sector.
            let mut at = 0usize;
            for r in &mut records {
                let len = record_len(r);
                let used = at % SECTOR as usize;
                if used + len > SECTOR as usize {
                    at += SECTOR as usize - used;
                }
                r.offset = at;
                at += len;
            }
            let secs = sectors(at as u64)?.max(1);
            plan.dirs.push(DirPlan {
                records,
                sectors: secs,
                lba: 0,
            });
            let _ = dir_no;
        }
        Ok(plan)
    }

    /// Split SUSP `entries` between a record whose fixed part is `base`
    /// bytes and a chain of continuation areas. Returns the in-record
    /// System Use bytes and, when it spills, where its `CE` sits.
    fn pack_sua(&mut self, base: usize, entries: Vec<Vec<u8>>) -> Result<(Vec<u8>, CeSlot)> {
        // Keep the record length even.
        let budget = (MAX_RECORD - base) & !1;
        let total: usize = entries.iter().map(Vec::len).sum();
        if total <= budget {
            return Ok((entries.concat(), None));
        }
        let mut sua = Vec::new();
        let mut it = entries.into_iter().peekable();
        while let Some(e) = it.peek() {
            if sua.len() + e.len() + CE_LEN > budget {
                break;
            }
            sua.extend_from_slice(&it.next().unwrap());
        }
        let ce_at = sua.len();
        sua.extend_from_slice(&[0u8; CE_LEN]);
        let first = self.areas.len();
        let mut rest: Vec<Vec<u8>> = it.collect();
        loop {
            let idx = self.areas.len();
            let mut data = Vec::new();
            let total: usize = rest.iter().map(Vec::len).sum();
            if total <= MAX_AREA {
                for e in rest.drain(..) {
                    data.extend_from_slice(&e);
                }
                self.areas.push(Area {
                    data,
                    ce: None,
                    lba: 0,
                    offset: 0,
                });
                break;
            }
            let mut n = 0;
            while n < rest.len() && data.len() + rest[n].len() + CE_LEN <= MAX_AREA {
                data.extend_from_slice(&rest[n]);
                n += 1;
            }
            if n == 0 {
                return Err(crate::Error::InvalidArgument(
                    "iso9660: a System Use entry does not fit a continuation area".into(),
                ));
            }
            rest.drain(..n);
            let at = data.len();
            data.extend_from_slice(&[0u8; CE_LEN]);
            self.areas.push(Area {
                data,
                ce: Some((at, idx + 1)),
                lba: 0,
                offset: 0,
            });
        }
        Ok((sua, Some((ce_at, first))))
    }

    fn write(&self, dev: &mut dyn BlockDevice, h: &Hierarchy) -> Result<()> {
        let joliet = h.encoding == Encoding::Joliet;
        // Path tables.
        let mut l = Vec::with_capacity(self.path_table_bytes as usize);
        let mut m = Vec::with_capacity(self.path_table_bytes as usize);
        for (i, (node, parent)) in self.order.iter().enumerate() {
            let ident: &[u8] = if *node == 0 {
                &[0]
            } else {
                &h.nodes[*node].identifier
            };
            let lba = self.dirs[i].lba;
            for (t, big) in [(&mut l, false), (&mut m, true)] {
                t.push(ident.len() as u8);
                t.push(0);
                if big {
                    t.extend_from_slice(&lba.to_be_bytes());
                    t.extend_from_slice(&parent.to_be_bytes());
                } else {
                    t.extend_from_slice(&lba.to_le_bytes());
                    t.extend_from_slice(&parent.to_le_bytes());
                }
                t.extend_from_slice(ident);
                if ident.len() % 2 == 1 {
                    t.push(0);
                }
            }
        }
        write_padded(dev, self.l_table_lba, &l)?;
        write_padded(dev, self.m_table_lba, &m)?;
        let _ = joliet;

        // Directories.
        for d in &self.dirs {
            let mut buf = vec![0u8; d.sectors as usize * SECTOR as usize];
            for r in &d.records {
                let (lba, len) = match r.target {
                    Target::Dir(i) => (self.dirs[i].lba, self.dirs[i].sectors * SECTOR as u32),
                    Target::Data { lba, len } => (lba, len),
                    Target::None => (0, 0),
                };
                let mut sua = r.sua.clone();
                if let Some((at, area)) = r.ce {
                    sua[at..at + CE_LEN].copy_from_slice(&self.ce_entry(area));
                }
                let rec = encode_record(lba, len, r.flags, r.mtime, &r.identifier, &sua);
                buf[r.offset..r.offset + rec.len()].copy_from_slice(&rec);
            }
            dev.write_at(u64::from(d.lba) * SECTOR, &buf)?;
        }

        // Continuation areas, a sector at a time.
        let mut i = 0;
        while i < self.areas.len() {
            let lba = self.areas[i].lba;
            let mut sector = vec![0u8; SECTOR as usize];
            while i < self.areas.len() && self.areas[i].lba == lba {
                let a = &self.areas[i];
                let mut data = a.data.clone();
                if let Some((at, next)) = a.ce {
                    data[at..at + CE_LEN].copy_from_slice(&self.ce_entry(next));
                }
                let off = a.offset as usize;
                sector[off..off + data.len()].copy_from_slice(&data);
                i += 1;
            }
            dev.write_at(u64::from(lba) * SECTOR, &sector)?;
        }
        Ok(())
    }

    fn ce_entry(&self, area: usize) -> [u8; CE_LEN] {
        let a = &self.areas[area];
        let mut e = [0u8; CE_LEN];
        e[0..2].copy_from_slice(b"CE");
        e[2] = CE_LEN as u8;
        e[3] = 1;
        put_both_u32(&mut e[4..12], a.lba);
        put_both_u32(&mut e[12..20], a.offset);
        put_both_u32(&mut e[20..28], a.data.len() as u32);
        e
    }
}

fn write_padded(dev: &mut dyn BlockDevice, lba: u32, data: &[u8]) -> Result<()> {
    let mut buf = data.to_vec();
    let padded = buf.len().div_ceil(SECTOR as usize).max(1) * SECTOR as usize;
    buf.resize(padded, 0);
    dev.write_at(u64::from(lba) * SECTOR, &buf)
}

fn record_len(r: &Record) -> usize {
    let len_fi = r.identifier.len();
    let pad = usize::from(len_fi.is_multiple_of(2));
    let n = 33 + len_fi + pad + r.sua.len();
    n + n % 2
}

fn encode_record(lba: u32, len: u32, flags: u8, mtime: i64, ident: &[u8], sua: &[u8]) -> Vec<u8> {
    let len_fi = ident.len();
    let pad = usize::from(len_fi.is_multiple_of(2));
    let n = 33 + len_fi + pad + sua.len();
    let total = n + n % 2;
    let mut r = vec![0u8; total];
    r[0] = total as u8;
    put_both_u32(&mut r[2..10], lba);
    put_both_u32(&mut r[10..18], len);
    r[18..25].copy_from_slice(&short_date(mtime));
    r[25] = flags;
    put_both_u16(&mut r[28..32], 1);
    r[32] = len_fi as u8;
    r[33..33 + len_fi].copy_from_slice(ident);
    let at = 33 + len_fi + pad;
    r[at..at + sua.len()].copy_from_slice(sua);
    r
}

fn sectors(bytes: u64) -> Result<u32> {
    u32::try_from(bytes.div_ceil(SECTOR))
        .map_err(|_| crate::Error::InvalidArgument("iso9660: region exceeds 2^32 sectors".into()))
}

fn add(a: u32, b: u32) -> Result<u32> {
    a.checked_add(b)
        .ok_or_else(|| crate::Error::InvalidArgument("iso9660: layout past LBA 2^32".into()))
}

fn ucs2(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_be_bytes).collect()
}

// ----------------------------------------------------------------------
// Dates
// ----------------------------------------------------------------------

/// (year, month, day, hour, minute, second) of a Unix time, clamped to
/// what the 7-byte form can hold (1900..=2155).
fn civil(t: i64) -> (i64, i64, i64, i64, i64, i64) {
    const MIN: i64 = -2_208_988_800; // 1900-01-01
    const MAX: i64 = 5_985_878_399; // 2159-12-31 23:59:59
    let t = t.clamp(MIN, MAX);
    let days = t.div_euclid(86_400);
    let secs = t.rem_euclid(86_400);
    let (y, m, d) = days_to_ymd(days + 719_468);
    (y, m, d, secs / 3600, (secs / 60) % 60, secs % 60)
}

/// The 7-byte directory-record date (ECMA-119 9.1.5), GMT.
fn short_date(t: i64) -> [u8; 7] {
    let (y, mo, d, h, mi, s) = civil(t);
    [
        (y - 1900).clamp(0, 255) as u8,
        mo as u8,
        d as u8,
        h as u8,
        mi as u8,
        s as u8,
        0,
    ]
}

/// The 17-byte volume-descriptor date (ECMA-119 8.4.26.1), GMT.
fn long_date(t: i64) -> [u8; 17] {
    let (y, mo, d, h, mi, s) = civil(t);
    let text = format!("{:04}{mo:02}{d:02}{h:02}{mi:02}{s:02}00", y.clamp(1, 9999));
    let mut out = [0u8; 17];
    out[..16].copy_from_slice(text.as_bytes());
    out
}

/// "Not specified": sixteen ASCII zeros and a zero offset.
fn long_date_unset() -> [u8; 17] {
    let mut out = [b'0'; 17];
    out[16] = 0;
    out
}

// ----------------------------------------------------------------------
// Rock Ridge / SUSP entries
// ----------------------------------------------------------------------

const SP_ENTRY: [u8; 7] = *b"SP\x07\x01\xBE\xEF\x00";

const ER_ID: &str = "RRIP_1991A";
const ER_DESC: &str =
    "THE ROCK RIDGE INTERCHANGE PROTOCOL PROVIDES SUPPORT FOR POSIX FILE SYSTEM SEMANTICS";
const ER_SRC: &str = "PLEASE CONTACT DISC PUBLISHER FOR SPECIFICATION SOURCE.  SEE PUBLISHER \
                      IDENTIFIER IN PRIMARY VOLUME DESCRIPTOR FOR CONTACT INFORMATION.";

fn er_entry() -> Vec<u8> {
    let mut e = vec![b'E', b'R', 0, 1];
    e.push(ER_ID.len() as u8);
    e.push(ER_DESC.len() as u8);
    e.push(ER_SRC.len() as u8);
    e.push(1); // extension version
    e.extend_from_slice(ER_ID.as_bytes());
    e.extend_from_slice(ER_DESC.as_bytes());
    e.extend_from_slice(ER_SRC.as_bytes());
    e[2] = e.len() as u8;
    e
}

/// The RRIP 1.09 `RR` entry: which other entries follow.
fn rr_flags_entry(rr: &RockRidge, child: bool) -> Vec<u8> {
    let mut f = 0x01 | 0x80; // PX, TF
    if child {
        f |= 0x08; // NM
        if rr.rdev.is_some() {
            f |= 0x02;
        }
        if rr.symlink.is_some() {
            f |= 0x04;
        }
    }
    vec![b'R', b'R', 5, 1, f]
}

fn px_entry(rr: &RockRidge) -> Vec<u8> {
    let mut e = vec![0u8; 36];
    e[0..2].copy_from_slice(b"PX");
    e[2] = 36;
    e[3] = 1;
    put_both_u32(&mut e[4..12], rr.mode);
    put_both_u32(&mut e[12..20], rr.nlink.max(1));
    put_both_u32(&mut e[20..28], rr.uid);
    put_both_u32(&mut e[28..36], rr.gid);
    e
}

fn pn_entry(major: u32, minor: u32) -> Vec<u8> {
    let mut e = vec![0u8; 20];
    e[0..2].copy_from_slice(b"PN");
    e[2] = 20;
    e[3] = 1;
    put_both_u32(&mut e[4..12], major);
    put_both_u32(&mut e[12..20], minor);
    e
}

fn tf_entry(rr: &RockRidge) -> Vec<u8> {
    let mut e = vec![b'T', b'F', 26, 1, 0x02 | 0x04 | 0x08];
    for t in [rr.mtime, rr.atime, rr.ctime] {
        e.extend_from_slice(&short_date(t));
    }
    e
}

/// `NM` entries for `name`, split with the CONTINUE flag past 250 bytes.
fn nm_entries(name: &str) -> Vec<Vec<u8>> {
    let bytes = name.as_bytes();
    if bytes.is_empty() {
        return Vec::new();
    }
    let chunks: Vec<&[u8]> = chunk_utf8(bytes, 250);
    let n = chunks.len();
    chunks
        .into_iter()
        .enumerate()
        .map(|(i, c)| {
            let mut e = vec![b'N', b'M', (5 + c.len()) as u8, 1];
            e.push(if i + 1 < n { 0x01 } else { 0 });
            e.extend_from_slice(c);
            e
        })
        .collect()
}

/// Split `b` into chunks of at most `max` bytes (whole bytes; RRIP does
/// not require UTF-8 boundaries, readers concatenate).
fn chunk_utf8(b: &[u8], max: usize) -> Vec<&[u8]> {
    b.chunks(max).collect()
}

/// `SL` entries for a symlink target. Each entry holds at most 250
/// bytes of component records; a component longer than fits is split
/// with the component CONTINUE flag, and an entry followed by another
/// carries the entry CONTINUE flag.
fn sl_entries(target: &str) -> Vec<Vec<u8>> {
    // Component records: (flags, bytes).
    let mut comps: Vec<(u8, Vec<u8>)> = Vec::new();
    let mut parts: Vec<&str> = target.split('/').collect();
    if target.starts_with('/') {
        comps.push((0x08, Vec::new()));
        parts.remove(0);
    }
    for p in parts {
        match p {
            "" => continue,
            "." => comps.push((0x02, Vec::new())),
            ".." => comps.push((0x04, Vec::new())),
            _ => {
                let chunks = chunk_utf8(p.as_bytes(), 248);
                let n = chunks.len();
                for (i, c) in chunks.into_iter().enumerate() {
                    comps.push((if i + 1 < n { 0x01 } else { 0 }, c.to_vec()));
                }
            }
        }
    }
    let mut entries: Vec<Vec<u8>> = Vec::new();
    let mut body: Vec<u8> = Vec::new();
    for (flags, bytes) in comps {
        let rec_len = 2 + bytes.len();
        if body.len() + rec_len > 250 {
            entries.push(std::mem::take(&mut body));
        }
        body.push(flags);
        body.push(bytes.len() as u8);
        body.extend_from_slice(&bytes);
    }
    entries.push(body);
    let n = entries.len();
    entries
        .into_iter()
        .enumerate()
        .map(|(i, b)| {
            let mut e = vec![b'S', b'L', (5 + b.len()) as u8, 1];
            e.push(if i + 1 < n { 0x01 } else { 0 });
            e.extend_from_slice(&b);
            e
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::MemoryBackend;
    use crate::fs::Filesystem;
    use crate::fs::iso9660::{Iso9660, ReadView};
    use std::io::Read;
    use std::path::Path;

    fn rr(name: &str, mode: u32) -> Option<RockRidge> {
        Some(RockRidge::new(name, mode))
    }

    /// Build a small volume: payloads at LBA 100.., metadata at 20.
    fn build(section: u64) -> (MemoryBackend, PlacedIso) {
        let mut dev = MemoryBackend::new(4 * 1024 * 1024);
        let mut p = Hierarchy::new(Encoding::Primary, 0, rr("", 0o040755));
        let mut j = Hierarchy::new(Encoding::Joliet, 0, None);
        let body = b"hello placed world\n";
        dev.write_at(100 * SECTOR, body).unwrap();
        let big: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        dev.write_at(101 * SECTOR, &big).unwrap();
        let d = p
            .add(0, b"SUB".to_vec(), NodeKind::Dir, 0, rr("sub", 0o040755))
            .unwrap();
        let long = "n".repeat(240);
        p.add(
            d,
            b"HELLO.TXT;1".to_vec(),
            NodeKind::File {
                lba: 100,
                size: body.len() as u64,
            },
            0,
            rr(&long, 0o100644),
        )
        .unwrap();
        p.add(
            0,
            b"BIG.BIN;1".to_vec(),
            NodeKind::File {
                lba: 101,
                size: big.len() as u64,
            },
            0,
            rr("big.bin", 0o100644),
        )
        .unwrap();
        let mut l = RockRidge::new("link", 0o120777);
        l.symlink = Some(format!("/{}/../sub/x", "t".repeat(300)));
        p.add(0, b"LINK.;1".to_vec(), NodeKind::Special, 0, Some(l))
            .unwrap();
        let jd = j.add(0, ucs2("sub"), NodeKind::Dir, 0, None).unwrap();
        j.add(
            jd,
            ucs2("héllo.txt"),
            NodeKind::File {
                lba: 100,
                size: body.len() as u64,
            },
            0,
            None,
        )
        .unwrap();
        let mut iso = PlacedIso::new(
            VolumeInfo {
                volume_id: "PLACED".into(),
                joliet_volume_id: "Placed".into(),
                ..VolumeInfo::default()
            },
            p,
        );
        iso.joliet = Some(j);
        iso.section_bytes = section;
        (dev, iso)
    }

    #[test]
    fn three_views_read_back() {
        let (mut dev, iso) = build(4096);
        let layout = iso.layout(16 + iso.descriptor_sectors()).unwrap();
        assert!(layout.end_lba() <= 100, "{:?}", layout.regions());
        iso.write(&mut dev, &layout, 2048).unwrap();

        let mut fs = Iso9660::open(&mut dev).unwrap();
        assert!(fs.rock_ridge);
        // Rock Ridge view: long names, symlink, multi-extent payload.
        fs.set_read_view(ReadView::RockRidge).unwrap();
        let long = "n".repeat(240);
        let mut s = String::new();
        fs.read_file(&mut dev, Path::new(&format!("/sub/{long}")))
            .unwrap()
            .read_to_string(&mut s)
            .unwrap();
        assert_eq!(s, "hello placed world\n");
        let mut big = Vec::new();
        fs.read_file(&mut dev, Path::new("/big.bin"))
            .unwrap()
            .read_to_end(&mut big)
            .unwrap();
        assert_eq!(big.len(), 10_000);
        assert!(big.iter().enumerate().all(|(i, &b)| b == (i % 251) as u8));
        let t = fs.read_symlink(&mut dev, Path::new("/link")).unwrap();
        assert_eq!(
            t.to_str().unwrap(),
            format!("/{}/../sub/x", "t".repeat(300))
        );
        // Primary view: the encoded identifiers.
        fs.set_read_view(ReadView::Primary).unwrap();
        let names: Vec<String> = fs
            .list(&mut dev, Path::new("/"))
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(names, ["BIG.BIN", "LINK", "SUB"]);
        // Joliet view.
        fs.set_read_view(ReadView::Joliet).unwrap();
        let mut s = String::new();
        fs.read_file(&mut dev, Path::new("/sub/héllo.txt"))
            .unwrap()
            .read_to_string(&mut s)
            .unwrap();
        assert_eq!(s, "hello placed world\n");
    }

    #[test]
    fn extents_past_the_volume_are_refused() {
        let (mut dev, iso) = build(MAX_SECTION_BYTES);
        let layout = iso.layout(20).unwrap();
        assert!(iso.write(&mut dev, &layout, 101).is_err());
        assert!(iso.write(&mut dev, &layout, 19).is_err());
        let early = iso.layout(17).unwrap();
        assert!(iso.write(&mut dev, &early, 2048).is_err());
    }

    #[test]
    fn duplicate_identifiers_are_refused() {
        let mut p = Hierarchy::new(Encoding::Primary, 0, None);
        p.add(0, b"A.;1".to_vec(), NodeKind::Special, 0, None)
            .unwrap();
        p.add(0, b"A.;1".to_vec(), NodeKind::Special, 0, None)
            .unwrap();
        let iso = PlacedIso::new(VolumeInfo::default(), p);
        assert!(iso.layout(20).is_err());
    }

    #[test]
    fn boot_catalog_checksums() {
        let p = Hierarchy::new(Encoding::Primary, 0, None);
        let mut iso = PlacedIso::new(VolumeInfo::default(), p);
        iso.boot.push(BootImage::no_emulation(40, 4));
        let mut efi = BootImage::no_emulation(41, 8);
        efi.platform = 0xEF;
        iso.boot.push(efi);
        let mut dev = MemoryBackend::new(1024 * 1024);
        let layout = iso.layout(16 + iso.descriptor_sectors()).unwrap();
        iso.write(&mut dev, &layout, 64).unwrap();
        let fs = Iso9660::open(&mut dev).unwrap();
        let boot = fs.boot.expect("boot catalog parsed");
        assert_eq!(boot.default_entry.load_rba, 40);
        assert_eq!(boot.additional.len(), 1);
        assert_eq!(boot.additional[0].platform, 0xEF);
        let mut cat = vec![0u8; 32];
        dev.read_at(
            u64::from(layout.boot_catalog_lba().unwrap()) * SECTOR,
            &mut cat,
        )
        .unwrap();
        let sum = cat.chunks(2).fold(0u16, |a, w| {
            a.wrapping_add(u16::from_le_bytes([w[0], w[1]]))
        });
        assert_eq!(sum, 0);
    }

    #[test]
    fn record_order_follows_ecma_119() {
        let mut v = [
            b"B.;1".to_vec(),
            b"A.TXT;1".to_vec(),
            b"A;1".to_vec(),
            b"AB".to_vec(),
            b"A.B;1".to_vec(),
        ];
        v.sort_by(|a, b| compare_identifiers(a, b, false));
        let s: Vec<String> = v
            .iter()
            .map(|x| String::from_utf8_lossy(x).into_owned())
            .collect();
        assert_eq!(s, ["A;1", "A.B;1", "A.TXT;1", "AB", "B.;1"]);
    }
}
