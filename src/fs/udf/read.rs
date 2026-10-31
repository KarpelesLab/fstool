//! Read side: volume recognition, anchors, the volume descriptor sequence,
//! partition maps (physical, sparable, virtual / VAT, metadata), File Set
//! Descriptor, ICBs, allocation descriptors and directories.
//!
//! Every count and length that comes off the medium is bounded before it
//! sizes an allocation or a loop — see the `MAX_*` constants — and every
//! descriptor's tag checksum and CRC is verified. A damaged image yields an
//! [`crate::Error::InvalidImage`] naming what was wrong; soft problems (a
//! tag recorded at the wrong location, an unreadable reserve copy) are
//! collected as warnings on the volume instead.

use std::collections::BTreeMap;

use super::ecma::*;
use crate::Result;
use crate::block::BlockDevice;

/// Blocks of a volume descriptor sequence we are willing to walk (both
/// directly and across Volume Descriptor Pointers).
pub(crate) const MAX_VDS_BLOCKS: usize = 512;
/// Volume Descriptor Pointer hops followed.
const MAX_VDP_HOPS: usize = 16;
/// Partition maps in one Logical Volume Descriptor.
const MAX_PARTITION_MAPS: usize = 64;
/// Volume structure descriptors scanned in the recognition sequence.
const MAX_VRS_DESCRIPTORS: usize = 256;
/// Largest directory read into memory.
pub(crate) const MAX_DIR_BYTES: u64 = 256 << 20;
/// Allocation descriptors one file may carry, across all AED blocks.
pub(crate) const MAX_EXTENTS: usize = 1 << 20;
/// Allocation Extent Descriptor blocks chained for one file.
const MAX_AED_CHAIN: usize = 1 << 16;
/// Indirect-entry hops when resolving an ICB.
const MAX_INDIRECT: usize = 64;
/// Largest symlink body.
pub(crate) const MAX_SYMLINK_BYTES: u64 = 64 << 10;
/// Largest VAT read into memory.
const MAX_VAT_BYTES: u64 = 256 << 20;
/// Largest sparing table read.
const MAX_SPARING_BYTES: u32 = 1 << 20;
/// Integrity-sequence blocks / hops walked.
const MAX_LVID_BLOCKS: usize = 256;
/// Blocks scanned back from the end of the medium for a VAT ICB.
const VAT_SEARCH_BLOCKS: u64 = 300;
/// Warnings kept per volume.
const MAX_WARNINGS: usize = 64;
/// Physical runs a single file may resolve to.
pub(crate) const MAX_RUNS: usize = 1 << 22;

/// UDF file types (ECMA-167 4/14.6.6 and UDF 2.3.5.2).
pub(crate) const FT_DIR: u8 = 4;
pub(crate) const FT_FILE: u8 = 5;
pub(crate) const FT_BLOCK: u8 = 6;
pub(crate) const FT_CHAR: u8 = 7;
pub(crate) const FT_FIFO: u8 = 9;
pub(crate) const FT_SOCKET: u8 = 10;
pub(crate) const FT_SYMLINK: u8 = 12;
pub(crate) const FT_VAT20: u8 = 248;
pub(crate) const FT_META_MAIN: u8 = 250;
pub(crate) const FT_META_MIRROR: u8 = 251;

/// FID characteristics bits.
pub(crate) const FID_DIR: u8 = 2;
pub(crate) const FID_DELETED: u8 = 4;
pub(crate) const FID_PARENT: u8 = 8;

/// How a partition reference resolves to physical blocks.
#[derive(Debug, Clone)]
pub(crate) enum PartMap {
    /// Type 1: `start + lbn`.
    Physical { number: u16, start: u64, len: u64 },
    /// Sparable (UDF 2.2.9): physical, with packets remapped by the
    /// sparing table.
    Sparable {
        number: u16,
        start: u64,
        len: u64,
        packet: u32,
        remap: BTreeMap<u32, u64>,
    },
    /// Virtual (UDF 2.2.8): through the VAT onto partition map `under`.
    Virtual {
        number: u16,
        under: usize,
        vat: Vec<u32>,
    },
    /// Metadata (UDF 2.2.10): through the metadata file's extents onto
    /// partition map `under`. Each extent is `(first metadata lbn, blocks,
    /// first lbn in under)`.
    Metadata {
        number: u16,
        under: usize,
        extents: Vec<(u64, u64, u32)>,
        duplicated: bool,
    },
}

/// One partition as reported by [`UdfInfo::partitions`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PartitionSummary {
    /// Partition reference number (index in the LVD's map table).
    pub reference: u16,
    /// Partition number the map refers to.
    pub number: u16,
    /// What kind of partition map it is.
    pub kind: PartitionMapKind,
    /// First physical block (type 1 / sparable maps; for virtual and
    /// metadata maps, the underlying partition's).
    pub start: u64,
    /// Length in blocks (for metadata maps: the metadata file's blocks;
    /// for virtual maps: VAT entries).
    pub length: u64,
    /// Partition Descriptor access type: 1 read-only, 2 write-once,
    /// 3 rewritable, 4 overwritable, 0 unspecified.
    pub access_type: u32,
}

/// Partition map flavour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PartitionMapKind {
    /// Type 1 physical partition.
    Physical,
    /// Sparable partition (CD-RW / DVD-RW defect management).
    Sparable,
    /// Virtual partition with a VAT (write-once media, UDF ≥ 1.50).
    Virtual,
    /// Metadata partition (UDF ≥ 2.50). `duplicated` when the mirror file
    /// carries its own copy.
    Metadata {
        /// The Duplicate Metadata Flag.
        duplicated: bool,
    },
}

/// What [`super::Udf::info`] reports about an opened volume.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct UdfInfo {
    /// Logical block size in bytes.
    pub block_size: u32,
    /// Total blocks on the medium.
    pub total_blocks: u64,
    /// `2` for `NSR02` (ECMA-167 2nd edition, UDF ≤ 1.50), `3` for `NSR03`.
    pub nsr_version: u8,
    /// UDF revision from the LVD domain identifier, as BCD (`0x0201`).
    pub udf_revision: u16,
    /// Minimum UDF read revision from the LVID (or VAT), when recorded.
    pub min_read_revision: Option<u16>,
    /// Minimum UDF write revision.
    pub min_write_revision: Option<u16>,
    /// Maximum UDF write revision.
    pub max_write_revision: Option<u16>,
    /// Primary Volume Descriptor volume identifier.
    pub volume_id: String,
    /// Volume set identifier.
    pub volume_set_id: String,
    /// Logical volume identifier (the name most systems show).
    pub logical_volume_id: String,
    /// File set identifier.
    pub file_set_id: String,
    /// Implementation identifier of the LVD (who wrote the volume).
    pub implementation_id: String,
    /// Recording time from the PVD (Unix seconds).
    pub recording_time: i64,
    /// File and directory counts from the LVID / VAT, when recorded.
    pub num_files: Option<u32>,
    /// Directory count from the LVID / VAT, when recorded.
    pub num_dirs: Option<u32>,
    /// `true` when the integrity descriptor says the volume was left open
    /// (not cleanly closed). Always `false` for VAT volumes.
    pub integrity_open: bool,
    /// Free blocks the LVID records across the physical (and sparable)
    /// partitions, when it records any.
    pub free_blocks: Option<u64>,
    /// Partitions, in partition-reference order.
    pub partitions: Vec<PartitionSummary>,
    /// Soft problems noticed while opening (tag location mismatches, an
    /// unusable reserve copy, …). Bounded.
    pub warnings: Vec<String>,
}

impl UdfInfo {
    /// The UDF revision as `"2.01"`.
    pub fn revision_string(&self) -> String {
        format_rev(self.udf_revision)
    }
}

/// `0x0201` → `"2.01"`.
pub fn format_rev(r: u16) -> String {
    format!("{:x}.{:02x}", r >> 8, r & 0xFF)
}

/// An extent of a file, as decoded from an allocation descriptor.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Extent {
    pub kind: u8,
    pub len: u32,
    pub loc: LbAddr,
}

/// The data of an ICB.
#[derive(Debug, Clone)]
pub(crate) enum InodeData {
    Inline(Vec<u8>),
    Extents(Vec<Extent>),
}

/// A decoded File Entry / Extended File Entry.
#[derive(Debug, Clone)]
pub(crate) struct Inode {
    pub loc: LbAddr,
    pub file_type: u8,
    pub icb_flags: u16,
    pub uid: u32,
    pub gid: u32,
    pub perms: u32,
    pub links: u16,
    pub size: u64,
    pub atime: i64,
    pub mtime: i64,
    pub ctime: i64,
    pub ea: Vec<u8>,
    pub data: InodeData,
}

impl Inode {
    pub fn is_dir(&self) -> bool {
        self.file_type == FT_DIR
    }

    /// POSIX mode bits (permissions + setuid/setgid/sticky) from the UDF
    /// permission word and ICB flags.
    pub fn mode(&self) -> u16 {
        let p = self.perms;
        let mut m = (((p >> 10) & 7) << 6) | (((p >> 5) & 7) << 3) | (p & 7);
        if self.icb_flags & (1 << 6) != 0 {
            m |= 0o4000;
        }
        if self.icb_flags & (1 << 7) != 0 {
            m |= 0o2000;
        }
        if self.icb_flags & (1 << 8) != 0 {
            m |= 0o1000;
        }
        m as u16
    }

    /// Blocks recorded on the medium (512-byte units).
    pub fn blocks512(&self, bs: u32) -> u64 {
        match &self.data {
            InodeData::Inline(_) => 0,
            InodeData::Extents(e) => e
                .iter()
                .filter(|x| x.kind == EXT_RECORDED || x.kind == EXT_ALLOCATED)
                .map(|x| u64::from(x.len).div_ceil(u64::from(bs)) * u64::from(bs) / 512)
                .sum(),
        }
    }

    /// Device numbers from a Device Specification extended attribute.
    pub fn device_numbers(&self) -> Option<(u32, u32)> {
        let mut found = None;
        walk_eas(&self.ea, |ty, _sub, body| {
            if ty == 12 && body.len() >= 12 {
                found = Some((u32le(body, 4), u32le(body, 8)));
            }
        });
        found
    }

    /// The 32 bytes of Finder info from a `*UDF Mac FinderInfo`
    /// implementation-use extended attribute, if one is recorded.
    pub fn finder_info(&self) -> Option<Vec<u8>> {
        let mut found = None;
        walk_eas(&self.ea, |ty, _sub, body| {
            // body: [u32 iu_len][regid 32][iu…]
            if ty == 2048 && body.len() >= 36 {
                let iu_len = u32le(body, 0) as usize;
                let name = entity_name(&body[4..36]);
                if name == "*UDF Mac FinderInfo" && iu_len >= 40 && body.len() >= 36 + 40 {
                    // iu: u16 checksum, u16 reserved, u32 parentDirID,
                    // 16 bytes FInfo / DInfo, 16 bytes FXInfo / DXInfo.
                    found = Some(body[36 + 8..36 + 40].to_vec());
                }
            }
        });
        found
    }
}

/// Visit each extended attribute in an EA space (header descriptor
/// first). `f(type, subtype, body after the 12-byte attribute header)`.
fn walk_eas(ea: &[u8], mut f: impl FnMut(u32, u8, &[u8])) {
    // EA header descriptor: tag (16) + impl attr loc (4) + app attr loc (4).
    if ea.len() < 24 {
        return;
    }
    match Tag::parse(ea) {
        Some(t) if t.id == TAG_EAHD => {}
        _ => return,
    }
    let mut off = 24usize;
    // Each attribute is at least 12 bytes; the count is bounded by the
    // EA space length.
    while off + 12 <= ea.len() {
        let ty = u32le(ea, off);
        let sub = ea[off + 4];
        let len = u32le(ea, off + 8) as usize;
        if len < 12 || off + len > ea.len() {
            break;
        }
        f(ty, sub, &ea[off + 12..off + len]);
        off += len;
    }
}

/// A directory entry decoded from a File Identifier Descriptor.
#[derive(Debug, Clone)]
pub(crate) struct Fid {
    pub name: String,
    pub characteristics: u8,
    pub icb: LongAd,
}

/// The opened volume: geometry, partition maps and the root ICB.
pub(crate) struct Volume {
    pub bs: u32,
    pub maps: Vec<PartMap>,
    pub root: LongAd,
    pub info: UdfInfo,
}

/// Push `msg` onto a bounded warning list.
pub(crate) fn push_warning(list: &mut Vec<String>, msg: String) {
    if list.len() < MAX_WARNINGS {
        list.push(msg);
    }
}

fn read_block(dev: &mut dyn BlockDevice, bs: u32, block: u64) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; bs as usize];
    let off = block
        .checked_mul(u64::from(bs))
        .ok_or_else(|| crate::Error::InvalidImage("udf: block address overflow".into()))?;
    if off.saturating_add(u64::from(bs)) > dev.total_size() {
        return Err(crate::Error::InvalidImage(format!(
            "udf: block {block} lies beyond the end of the medium"
        )));
    }
    dev.read_at(off, &mut buf)?;
    Ok(buf)
}

/// Scan the volume recognition sequence at byte 32768. Returns the NSR
/// version found (2 or 3), or `None` when the sequence carries no `NSR0x`
/// descriptor.
pub(crate) fn scan_vrs(dev: &mut dyn BlockDevice, step: u64) -> Option<u8> {
    let mut nsr = None;
    let mut seen_bea = false;
    for i in 0..MAX_VRS_DESCRIPTORS as u64 {
        let off = 32768 + i * step;
        if off + 7 > dev.total_size() {
            break;
        }
        let mut b = [0u8; 7];
        if dev.read_at(off, &mut b).is_err() {
            break;
        }
        match &b[1..6] {
            b"BEA01" => seen_bea = true,
            b"NSR02" if seen_bea => nsr = Some(2),
            b"NSR03" if seen_bea => nsr = Some(3),
            b"TEA01" => break,
            b"CD001" | b"CDW02" | b"BOOT2" => {}
            _ => break,
        }
    }
    nsr
}

/// Whether `dev` carries a UDF volume recognition sequence (BEA01 …
/// NSR02/NSR03). Cheap: reads at most a few hundred bytes. Used by
/// [`crate::inspect::detect_fs`].
pub fn probe(dev: &mut dyn BlockDevice) -> bool {
    scan_vrs(dev, 2048).is_some() || scan_vrs(dev, 4096).is_some()
}

/// Find a valid Anchor Volume Descriptor Pointer for block size `bs`.
fn find_avdp(dev: &mut dyn BlockDevice, bs: u32) -> Option<(u64, Vec<u8>)> {
    let n = dev.total_size() / u64::from(bs);
    if n < 257 {
        return None;
    }
    let mut cands = vec![256u64, n - 1];
    if n > 512 {
        cands.push(n - 257);
        cands.push(512);
    }
    for b in cands {
        let Ok(buf) = read_block(dev, bs, b) else {
            continue;
        };
        if let Some(t) = Tag::parse(&buf)
            && t.id == TAG_AVDP
            && u64::from(t.location) == b
            && t.crc_ok(&buf)
        {
            return Some((b, buf));
        }
    }
    None
}

/// The prevailing descriptors collected from one volume descriptor
/// sequence.
#[derive(Default)]
struct Vds {
    pvd: Option<(u32, Vec<u8>)>,
    lvd: Option<(u32, Vec<u8>)>,
    iuvd: Option<(u32, Vec<u8>)>,
    pds: BTreeMap<u16, (u32, Vec<u8>)>,
}

impl Vds {
    fn usable(&self) -> bool {
        self.pvd.is_some() && self.lvd.is_some() && !self.pds.is_empty()
    }
}

fn keep_newer(slot: &mut Option<(u32, Vec<u8>)>, num: u32, buf: Vec<u8>) {
    if slot.as_ref().is_none_or(|(n, _)| num >= *n) {
        *slot = Some((num, buf));
    }
}

/// Walk one VDS extent, following Volume Descriptor Pointers.
fn read_vds(
    dev: &mut dyn BlockDevice,
    bs: u32,
    loc: u32,
    len: u32,
    warnings: &mut Vec<String>,
) -> Result<Vds> {
    let mut vds = Vds::default();
    let mut block = u64::from(loc);
    let mut remaining = (u64::from(len) / u64::from(bs)) as usize;
    let mut total = 0usize;
    let mut hops = 0usize;
    while remaining > 0 && total < MAX_VDS_BLOCKS {
        total += 1;
        remaining -= 1;
        let buf = match read_block(dev, bs, block) {
            Ok(b) => b,
            Err(_) => break,
        };
        let Some(tag) = Tag::parse(&buf) else {
            break; // unrecorded / garbage ends the sequence
        };
        if !tag.crc_ok(&buf) {
            push_warning(
                warnings,
                format!(
                    "descriptor at block {block} (tag {}) fails its CRC; skipped",
                    tag.id
                ),
            );
            block += 1;
            continue;
        }
        if u64::from(tag.location) != block {
            push_warning(
                warnings,
                format!(
                    "descriptor at block {block} (tag {}) records location {}",
                    tag.id, tag.location
                ),
            );
        }
        let vds_num = u32le(&buf, 16);
        match tag.id {
            TAG_PVD => keep_newer(&mut vds.pvd, vds_num, buf),
            TAG_LVD => keep_newer(&mut vds.lvd, vds_num, buf),
            TAG_IUVD => {
                if entity_name(&buf[20..52]) == "*UDF LV Info" {
                    keep_newer(&mut vds.iuvd, vds_num, buf);
                }
            }
            TAG_PD => {
                let num = u16le(&buf, 22);
                let slot = vds.pds.entry(num).or_insert_with(|| (vds_num, buf.clone()));
                if vds_num >= slot.0 {
                    *slot = (vds_num, buf);
                }
            }
            TAG_VDP => {
                hops += 1;
                if hops > MAX_VDP_HOPS {
                    push_warning(warnings, "too many Volume Descriptor Pointers".into());
                    break;
                }
                let next_len = u32le(&buf, 20);
                let next_loc = u32le(&buf, 24);
                block = u64::from(next_loc);
                remaining = (u64::from(next_len) / u64::from(bs)) as usize;
                continue;
            }
            TAG_TD => break,
            TAG_USD => {}
            _ => {}
        }
        block += 1;
    }
    Ok(vds)
}

impl Volume {
    /// Open the UDF volume on `dev`.
    pub fn open(dev: &mut dyn BlockDevice) -> Result<Volume> {
        let mut warnings = Vec::new();
        let mut found = None;
        for bs in [2048u32, 512, 4096, 1024] {
            if let Some((at, avdp)) = find_avdp(dev, bs) {
                found = Some((bs, at, avdp));
                break;
            }
        }
        let (bs, avdp_at, avdp) = found.ok_or_else(|| {
            crate::Error::InvalidImage(
                "udf: no Anchor Volume Descriptor Pointer at block 256, N-256 or N".into(),
            )
        })?;
        let nsr = scan_vrs(dev, u64::from(bs.max(2048))).unwrap_or_else(|| {
            push_warning(
                &mut warnings,
                "no NSR02/NSR03 descriptor in the volume recognition sequence".into(),
            );
            0
        });
        let total_blocks = dev.total_size() / u64::from(bs);
        let _ = avdp_at;

        let main = (u32le(&avdp, 16), u32le(&avdp, 20));
        let reserve = (u32le(&avdp, 24), u32le(&avdp, 28));
        let mut vds = read_vds(dev, bs, main.1, main.0, &mut warnings)?;
        if !vds.usable() {
            push_warning(
                &mut warnings,
                "main volume descriptor sequence incomplete; using the reserve copy".into(),
            );
            vds = read_vds(dev, bs, reserve.1, reserve.0, &mut warnings)?;
        }
        let (_, pvd) = vds.pvd.ok_or_else(|| {
            crate::Error::InvalidImage("udf: no Primary Volume Descriptor".into())
        })?;
        let (_, lvd) = vds.lvd.ok_or_else(|| {
            crate::Error::InvalidImage("udf: no Logical Volume Descriptor".into())
        })?;
        if vds.pds.is_empty() {
            return Err(crate::Error::InvalidImage(
                "udf: no Partition Descriptor".into(),
            ));
        }

        let lvd_bs = u32le(&lvd, 212);
        if lvd_bs != bs {
            return Err(crate::Error::InvalidImage(format!(
                "udf: logical block size {lvd_bs} disagrees with the anchor's sector size {bs}"
            )));
        }
        let domain = &lvd[216..248];
        let udf_revision = if entity_name(domain).starts_with("*OSTA UDF") {
            u16le(domain, 24)
        } else {
            push_warning(
                &mut warnings,
                format!("unexpected LVD domain identifier {:?}", entity_name(domain)),
            );
            0
        };
        let mut info = UdfInfo {
            block_size: bs,
            total_blocks,
            nsr_version: nsr,
            udf_revision,
            volume_id: decode_dstring(&pvd[24..56]),
            volume_set_id: decode_dstring(&pvd[72..200]),
            logical_volume_id: decode_dstring(&lvd[84..212]),
            implementation_id: entity_name(&lvd[272..304]),
            recording_time: decode_timestamp(&pvd[376..388]),
            ..UdfInfo::default()
        };
        if let Some((_, iuvd)) = &vds.iuvd
            && info.logical_volume_id.is_empty()
        {
            info.logical_volume_id = decode_dstring(&iuvd[116..244]);
        }

        // ---- partition maps ----
        let map_len = u32le(&lvd, 264) as usize;
        let n_maps = u32le(&lvd, 268) as usize;
        if n_maps == 0 || n_maps > MAX_PARTITION_MAPS {
            return Err(crate::Error::InvalidImage(format!(
                "udf: {n_maps} partition maps (expected 1..={MAX_PARTITION_MAPS})"
            )));
        }
        if 440 + map_len > lvd.len() {
            return Err(crate::Error::InvalidImage(
                "udf: partition map table runs past the LVD".into(),
            ));
        }
        let table = &lvd[440..440 + map_len];
        enum RawMap {
            T1 {
                number: u16,
            },
            Virtual {
                number: u16,
            },
            Sparable {
                number: u16,
                packet: u16,
                ntables: u8,
                size: u32,
                locs: Vec<u32>,
            },
            Meta {
                number: u16,
                file: u32,
                mirror: u32,
                dup: bool,
            },
        }
        let mut raw = Vec::with_capacity(n_maps);
        let mut off = 0usize;
        for i in 0..n_maps {
            if off + 2 > table.len() {
                return Err(crate::Error::InvalidImage(format!(
                    "udf: partition map {i} runs past the map table"
                )));
            }
            let ty = table[off];
            let len = usize::from(table[off + 1]);
            if len < 2 || off + len > table.len() {
                return Err(crate::Error::InvalidImage(format!(
                    "udf: partition map {i} has a bad length {len}"
                )));
            }
            let m = &table[off..off + len];
            match ty {
                1 if len >= 6 => raw.push(RawMap::T1 {
                    number: u16le(m, 4),
                }),
                2 if len >= 64 => {
                    let ident = entity_name(&m[4..36]);
                    let number = u16le(m, 38);
                    match ident.as_str() {
                        "*UDF Virtual Partition" => raw.push(RawMap::Virtual { number }),
                        "*UDF Sparable Partition" => {
                            let ntables = m[42].min(4);
                            let locs = (0..usize::from(ntables))
                                .map(|k| u32le(m, 48 + 4 * k))
                                .collect();
                            raw.push(RawMap::Sparable {
                                number,
                                packet: u16le(m, 40),
                                ntables,
                                size: u32le(m, 44),
                                locs,
                            });
                        }
                        "*UDF Metadata Partition" => raw.push(RawMap::Meta {
                            number,
                            file: u32le(m, 40),
                            mirror: u32le(m, 44),
                            dup: m[58] & 1 != 0,
                        }),
                        other => {
                            return Err(crate::Error::Unsupported(format!(
                                "udf: partition map type {other:?}"
                            )));
                        }
                    }
                }
                _ => {
                    return Err(crate::Error::InvalidImage(format!(
                        "udf: partition map {i} has unknown type {ty} (length {len})"
                    )));
                }
            }
            off += len;
        }

        let pd_for = |number: u16| -> Result<(u64, u64, u32)> {
            let (_, pd) = vds.pds.get(&number).ok_or_else(|| {
                crate::Error::InvalidImage(format!(
                    "udf: no Partition Descriptor for partition {number}"
                ))
            })?;
            Ok((
                u64::from(u32le(pd, 188)),
                u64::from(u32le(pd, 192)),
                u32le(pd, 184),
            ))
        };

        // First pass: physical and sparable maps.
        let mut maps: Vec<Option<PartMap>> = Vec::with_capacity(raw.len());
        for r in &raw {
            maps.push(match r {
                RawMap::T1 { number } => {
                    let (start, len, _) = pd_for(*number)?;
                    Some(PartMap::Physical {
                        number: *number,
                        start,
                        len,
                    })
                }
                RawMap::Sparable {
                    number,
                    packet,
                    ntables,
                    size,
                    locs,
                } => {
                    let (start, len, _) = pd_for(*number)?;
                    let remap = read_sparing(dev, bs, *size, locs, *ntables, &mut warnings);
                    Some(PartMap::Sparable {
                        number: *number,
                        start,
                        len,
                        packet: u32::from((*packet).max(1)),
                        remap,
                    })
                }
                _ => None,
            });
        }
        let under_of = |maps: &[Option<PartMap>], number: u16| -> Result<usize> {
            maps.iter()
                .position(|m| {
                    matches!(m, Some(PartMap::Physical { number: n, .. })
                        | Some(PartMap::Sparable { number: n, .. }) if *n == number)
                })
                .ok_or_else(|| {
                    crate::Error::InvalidImage(format!(
                        "udf: no physical partition map for partition {number}"
                    ))
                })
        };
        // Second pass: virtual and metadata maps, which sit on a physical one.
        let mut vat_header: Option<VatInfo> = None;
        for (i, r) in raw.iter().enumerate() {
            match r {
                RawMap::Virtual { number } => {
                    let under = under_of(&maps, *number)?;
                    let tmp = placeholder_maps(&maps);
                    let (vat, vinfo) = find_vat(dev, bs, &tmp, under, &mut warnings)?;
                    vat_header = Some(vinfo);
                    maps[i] = Some(PartMap::Virtual {
                        number: *number,
                        under,
                        vat,
                    });
                }
                RawMap::Meta {
                    number,
                    file,
                    mirror,
                    dup,
                } => {
                    let under = under_of(&maps, *number)?;
                    let tmp = placeholder_maps(&maps);
                    let extents = match read_meta_extents(dev, bs, &tmp, under, *file) {
                        Ok(e) => e,
                        Err(e) => {
                            push_warning(
                                &mut warnings,
                                format!("metadata file unusable ({e}); using the mirror"),
                            );
                            read_meta_extents(dev, bs, &tmp, under, *mirror)?
                        }
                    };
                    maps[i] = Some(PartMap::Metadata {
                        number: *number,
                        under,
                        extents,
                        duplicated: *dup,
                    });
                }
                _ => {}
            }
        }
        let maps: Vec<PartMap> = maps
            .into_iter()
            .map(|m| m.expect("every map resolved"))
            .collect();

        for (i, m) in maps.iter().enumerate() {
            let (number, kind, start, length) = match m {
                PartMap::Physical { number, start, len } => {
                    (*number, PartitionMapKind::Physical, *start, *len)
                }
                PartMap::Sparable {
                    number, start, len, ..
                } => (*number, PartitionMapKind::Sparable, *start, *len),
                PartMap::Virtual { number, under, vat } => (
                    *number,
                    PartitionMapKind::Virtual,
                    map_start(&maps[*under]),
                    vat.len() as u64,
                ),
                PartMap::Metadata {
                    number,
                    under,
                    extents,
                    duplicated,
                } => (
                    *number,
                    PartitionMapKind::Metadata {
                        duplicated: *duplicated,
                    },
                    map_start(&maps[*under]),
                    extents.iter().map(|e| e.1).sum(),
                ),
            };
            let access_type = pd_for(number).map(|p| p.2).unwrap_or(0);
            info.partitions.push(PartitionSummary {
                reference: i as u16,
                number,
                kind,
                start,
                length,
                access_type,
            });
        }

        let mut vol = Volume {
            bs,
            maps,
            root: LongAd::default(),
            info,
        };

        // ---- integrity ----
        read_lvid(
            dev,
            &mut vol,
            u32le(&lvd, 432),
            u32le(&lvd, 436),
            &mut warnings,
        );
        if let Some(v) = vat_header {
            if let Some(id) = v.lv_id {
                vol.info.logical_volume_id = id;
            }
            vol.info.num_files = v.files.or(vol.info.num_files);
            vol.info.num_dirs = v.dirs.or(vol.info.num_dirs);
            if let Some(r) = v.min_read {
                vol.info.min_read_revision = Some(r);
            }
            vol.info.integrity_open = false;
        }

        // ---- file set ----
        let fsd_ad = LongAd::parse(&lvd[248..264]);
        let fsd_blocks = (u64::from(fsd_ad.len) / u64::from(bs)).clamp(1, 256);
        let mut fsd: Option<Vec<u8>> = None;
        for k in 0..fsd_blocks {
            let lbn = fsd_ad.loc.lbn.wrapping_add(k as u32);
            let Ok(buf) = vol.read_lb(dev, fsd_ad.loc.part, lbn) else {
                break;
            };
            let Some(t) = Tag::parse(&buf) else { break };
            if t.id == TAG_TD {
                break;
            }
            if t.id != TAG_FSD {
                break;
            }
            if !t.crc_ok(&buf) {
                push_warning(
                    &mut warnings,
                    format!("File Set Descriptor at {lbn} fails its CRC"),
                );
                continue;
            }
            fsd = Some(buf);
        }
        let fsd = fsd.ok_or_else(|| {
            crate::Error::InvalidImage(format!(
                "udf: no File Set Descriptor at partition {} block {}",
                fsd_ad.loc.part, fsd_ad.loc.lbn
            ))
        })?;
        vol.info.file_set_id = decode_dstring(&fsd[304..336]);
        vol.root = LongAd::parse(&fsd[400..416]);
        for w in warnings {
            push_warning(&mut vol.info.warnings, w);
        }
        Ok(vol)
    }

    /// Partition map for a partition reference.
    fn map(&self, part: u16) -> Result<&PartMap> {
        self.maps.get(usize::from(part)).ok_or_else(|| {
            crate::Error::InvalidImage(format!("udf: partition reference {part} out of range"))
        })
    }

    /// Resolve `(part, lbn)` to the physical block and the number of
    /// following blocks (at most `want`) that are physically contiguous.
    pub fn map_run(&self, part: u16, lbn: u32, want: u64) -> Result<(u64, u64)> {
        map_run_in(&self.maps, usize::from(part), lbn, want.max(1), 0)
    }

    /// Read logical block `lbn` of partition `part`.
    pub fn read_lb(&self, dev: &mut dyn BlockDevice, part: u16, lbn: u32) -> Result<Vec<u8>> {
        let _ = self.map(part)?;
        let (abs, _) = self.map_run(part, lbn, 1)?;
        read_block(dev, self.bs, abs)
    }

    /// Decode the ICB at `loc`, following indirect entries (strategy 4096
    /// and stray Indirect Entries) a bounded number of times.
    pub fn read_inode(&self, dev: &mut dyn BlockDevice, loc: LbAddr) -> Result<Inode> {
        let mut loc = loc;
        for _ in 0..MAX_INDIRECT {
            let buf = self.read_lb(dev, loc.part, loc.lbn)?;
            let tag = Tag::parse(&buf).ok_or_else(|| {
                crate::Error::InvalidImage(format!(
                    "udf: no descriptor tag at ICB {}:{}",
                    loc.part, loc.lbn
                ))
            })?;
            if tag.id == TAG_IE {
                if !tag.crc_ok(&buf) {
                    return Err(crate::Error::InvalidImage(format!(
                        "udf: Indirect Entry at {}:{} fails its CRC",
                        loc.part, loc.lbn
                    )));
                }
                let next = LongAd::parse(&buf[36..52]);
                loc = next.loc;
                continue;
            }
            if tag.id != TAG_FE && tag.id != TAG_EFE {
                return Err(crate::Error::InvalidImage(format!(
                    "udf: ICB {}:{} holds tag {}, not a File Entry",
                    loc.part, loc.lbn, tag.id
                )));
            }
            if !tag.crc_ok(&buf) {
                return Err(crate::Error::InvalidImage(format!(
                    "udf: File Entry at {}:{} fails its CRC",
                    loc.part, loc.lbn
                )));
            }
            let strategy = u16le(&buf, 20);
            if strategy == 4096 {
                // Strategy 4096: a newer direct entry may be chained
                // through the Indirect Entry in the next block.
                if let Ok(next) = self.read_lb(dev, loc.part, loc.lbn.wrapping_add(1))
                    && let Some(t) = Tag::parse(&next)
                    && t.id == TAG_IE
                    && t.crc_ok(&next)
                {
                    let ad = LongAd::parse(&next[36..52]);
                    if ad.len > 0 && ad.loc != loc {
                        loc = ad.loc;
                        continue;
                    }
                }
            }
            return self.decode_inode(dev, loc, tag.id == TAG_EFE, &buf);
        }
        Err(crate::Error::InvalidImage(
            "udf: ICB indirection too deep".into(),
        ))
    }

    fn decode_inode(
        &self,
        dev: &mut dyn BlockDevice,
        loc: LbAddr,
        efe: bool,
        b: &[u8],
    ) -> Result<Inode> {
        let base = if efe { 216 } else { 176 };
        let (l_ea_off, times) = if efe {
            (208, [80usize, 92, 116])
        } else {
            (168, [72usize, 84, 96])
        };
        let l_ea = u32le(b, l_ea_off) as usize;
        let l_ad = u32le(b, l_ea_off + 4) as usize;
        if base + l_ea + l_ad > b.len() || l_ea > b.len() || l_ad > b.len() {
            return Err(crate::Error::InvalidImage(format!(
                "udf: File Entry at {}:{} has EA/AD lengths ({l_ea}+{l_ad}) beyond its block",
                loc.part, loc.lbn
            )));
        }
        let icb_flags = u16le(b, 34);
        let ea = b[base..base + l_ea].to_vec();
        let ads = &b[base + l_ea..base + l_ea + l_ad];
        let size = u64le(b, 56);
        let data = match icb_flags & 7 {
            ICB_AD_INLINE => {
                let n = (size as usize).min(ads.len());
                InodeData::Inline(ads[..n].to_vec())
            }
            t => InodeData::Extents(self.parse_ads(dev, ads, t, loc.part)?),
        };
        Ok(Inode {
            loc,
            file_type: b[27],
            icb_flags,
            uid: u32le(b, 36),
            gid: u32le(b, 40),
            perms: u32le(b, 44),
            links: u16le(b, 48),
            size,
            atime: decode_timestamp(&b[times[0]..times[0] + 12]),
            mtime: decode_timestamp(&b[times[1]..times[1] + 12]),
            ctime: decode_timestamp(&b[times[2]..times[2] + 12]),
            ea,
            data,
        })
    }

    /// Decode a list of allocation descriptors of `ad_type`, following
    /// Allocation Extent Descriptors.
    fn parse_ads(
        &self,
        dev: &mut dyn BlockDevice,
        first: &[u8],
        ad_type: u16,
        icb_part: u16,
    ) -> Result<Vec<Extent>> {
        let sz = match ad_type {
            ICB_AD_SHORT => 8,
            ICB_AD_LONG => 16,
            ICB_AD_EXTENDED => 20,
            t => {
                return Err(crate::Error::InvalidImage(format!(
                    "udf: unknown allocation descriptor type {t}"
                )));
            }
        };
        let mut out = Vec::new();
        let mut cur = first.to_vec();
        let mut hops = 0usize;
        'chain: loop {
            let mut off = 0usize;
            while off + sz <= cur.len() {
                let d = &cur[off..off + sz];
                off += sz;
                let (raw, loc) = match ad_type {
                    ICB_AD_SHORT => (
                        u32le(d, 0),
                        LbAddr {
                            lbn: u32le(d, 4),
                            part: icb_part,
                        },
                    ),
                    ICB_AD_LONG => (u32le(d, 0), LbAddr::parse(&d[4..10])),
                    _ => (u32le(d, 0), LbAddr::parse(&d[12..18])),
                };
                let len = raw & 0x3FFF_FFFF;
                let kind = (raw >> 30) as u8;
                if len == 0 {
                    break 'chain;
                }
                if kind == EXT_NEXT {
                    hops += 1;
                    if hops > MAX_AED_CHAIN {
                        return Err(crate::Error::InvalidImage(
                            "udf: allocation extent chain too long".into(),
                        ));
                    }
                    let blk = self.read_lb(dev, loc.part, loc.lbn)?;
                    let t = Tag::parse(&blk).ok_or_else(|| {
                        crate::Error::InvalidImage(
                            "udf: allocation extent has no descriptor tag".into(),
                        )
                    })?;
                    if t.id != TAG_AED || !t.crc_ok(&blk) {
                        return Err(crate::Error::InvalidImage(format!(
                            "udf: bad Allocation Extent Descriptor at {}:{}",
                            loc.part, loc.lbn
                        )));
                    }
                    let l_ad = (u32le(&blk, 20) as usize).min(blk.len() - 24);
                    cur = blk[24..24 + l_ad].to_vec();
                    continue 'chain;
                }
                if out.len() >= MAX_EXTENTS {
                    return Err(crate::Error::InvalidImage(
                        "udf: file has too many extents".into(),
                    ));
                }
                out.push(Extent { kind, len, loc });
            }
            break;
        }
        Ok(out)
    }

    /// Physical runs `(file offset, length, Some(byte offset on the
    /// device) | None for zeros)` covering an inode's extents, merged where
    /// contiguous.
    pub fn runs(&self, extents: &[Extent]) -> Result<Vec<Run>> {
        let bs = u64::from(self.bs);
        let mut runs: Vec<Run> = Vec::new();
        let mut file_off = 0u64;
        // Partition-map lookups allowed for one file. A virtual partition
        // resolves block by block, so without this a crafted extent list
        // could spin for hours without allocating anything.
        let mut budget = 4 * MAX_RUNS;
        for e in extents {
            let len = u64::from(e.len);
            if e.kind == EXT_RECORDED {
                let blocks = len.div_ceil(bs);
                let mut done = 0u64;
                while done < blocks {
                    budget = budget.checked_sub(1).ok_or_else(|| {
                        crate::Error::InvalidImage("udf: file is too fragmented".into())
                    })?;
                    let lbn = e.loc.lbn.checked_add(done as u32).ok_or_else(|| {
                        crate::Error::InvalidImage("udf: extent wraps the block space".into())
                    })?;
                    let (abs, n) = self.map_run(e.loc.part, lbn, blocks - done)?;
                    let n = n.min(blocks - done).max(1);
                    let byte_len = (n * bs).min(len - done * bs);
                    push_run(&mut runs, file_off + done * bs, byte_len, Some(abs * bs))?;
                    done += n;
                }
            } else {
                push_run(&mut runs, file_off, len, None)?;
            }
            file_off += len;
        }
        Ok(runs)
    }

    /// Read a whole (small) inode body into memory, refusing anything
    /// larger than `cap` bytes.
    pub fn read_all(&self, dev: &mut dyn BlockDevice, ino: &Inode, cap: u64) -> Result<Vec<u8>> {
        if ino.size > cap {
            return Err(crate::Error::InvalidImage(format!(
                "udf: object of {} bytes exceeds the {cap}-byte limit",
                ino.size
            )));
        }
        match &ino.data {
            InodeData::Inline(d) => Ok(d.clone()),
            InodeData::Extents(e) => {
                let runs = self.runs(e)?;
                // Size the buffer by what the extents cover, not by the
                // (untrusted) information length alone.
                let covered = runs.last().map_or(0, |r| r.file_off + r.len).min(ino.size);
                let mut out = vec![0u8; covered as usize];
                for r in &runs {
                    if r.file_off >= covered {
                        break;
                    }
                    let n = r.len.min(covered - r.file_off) as usize;
                    if let Some(src) = r.dev_off {
                        let s = r.file_off as usize;
                        dev.read_at(src, &mut out[s..s + n])?;
                    }
                }
                Ok(out)
            }
        }
    }

    /// Read and decode the directory `ino`.
    pub fn read_dir(&self, dev: &mut dyn BlockDevice, ino: &Inode) -> Result<Vec<Fid>> {
        let buf = self.read_all(dev, ino, MAX_DIR_BYTES)?;
        parse_fids(&buf)
    }
}

/// One contiguous piece of a file on the device.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Run {
    pub file_off: u64,
    pub len: u64,
    pub dev_off: Option<u64>,
}

fn push_run(runs: &mut Vec<Run>, file_off: u64, len: u64, dev_off: Option<u64>) -> Result<()> {
    if let Some(last) = runs.last_mut()
        && last.file_off + last.len == file_off
    {
        match (last.dev_off, dev_off) {
            (Some(a), Some(b)) if a + last.len == b => {
                last.len += len;
                return Ok(());
            }
            (None, None) => {
                last.len += len;
                return Ok(());
            }
            _ => {}
        }
    }
    if runs.len() >= MAX_RUNS {
        return Err(crate::Error::InvalidImage(
            "udf: file is too fragmented".into(),
        ));
    }
    runs.push(Run {
        file_off,
        len,
        dev_off,
    });
    Ok(())
}

fn map_start(m: &PartMap) -> u64 {
    match m {
        PartMap::Physical { start, .. } | PartMap::Sparable { start, .. } => *start,
        _ => 0,
    }
}

/// The maps resolved so far, with an empty placeholder standing in for
/// each one still unresolved so partition references keep their index.
fn placeholder_maps(maps: &[Option<PartMap>]) -> Vec<PartMap> {
    maps.iter()
        .map(|m| {
            m.clone().unwrap_or(PartMap::Physical {
                number: u16::MAX,
                start: 0,
                len: 0,
            })
        })
        .collect()
}

fn map_run_in(
    maps: &[PartMap],
    part: usize,
    lbn: u32,
    want: u64,
    depth: u32,
) -> Result<(u64, u64)> {
    if depth > 4 {
        return Err(crate::Error::InvalidImage(
            "udf: partition maps nest too deeply".into(),
        ));
    }
    let m = maps.get(part).ok_or_else(|| {
        crate::Error::InvalidImage(format!("udf: partition reference {part} out of range"))
    })?;
    let lbn64 = u64::from(lbn);
    match m {
        PartMap::Physical { start, len, .. } => {
            if lbn64 >= *len {
                return Err(crate::Error::InvalidImage(format!(
                    "udf: block {lbn} beyond partition length {len}"
                )));
            }
            Ok((start + lbn64, want.min(len - lbn64)))
        }
        PartMap::Sparable {
            start,
            len,
            packet,
            remap,
            ..
        } => {
            if lbn64 >= *len {
                return Err(crate::Error::InvalidImage(format!(
                    "udf: block {lbn} beyond partition length {len}"
                )));
            }
            let p = lbn - lbn % packet;
            let within = lbn - p;
            let left = u64::from(packet - within).min(want);
            match remap.get(&p) {
                Some(mapped) => Ok((mapped + u64::from(within), left)),
                None => Ok((start + lbn64, left)),
            }
        }
        PartMap::Virtual { under, vat, .. } => {
            let first = *vat.get(lbn as usize).ok_or_else(|| {
                crate::Error::InvalidImage(format!("udf: virtual block {lbn} beyond the VAT"))
            })?;
            if first == u32::MAX {
                return Err(crate::Error::InvalidImage(format!(
                    "udf: virtual block {lbn} is unmapped"
                )));
            }
            let (abs, _) = map_run_in(maps, *under, first, 1, depth + 1)?;
            // Extend while the VAT maps consecutive blocks consecutively.
            let mut n = 1u64;
            while n < want
                && let Some(&next) = vat.get(lbn as usize + n as usize)
                && next == first.wrapping_add(n as u32)
            {
                n += 1;
            }
            Ok((abs, n))
        }
        PartMap::Metadata { under, extents, .. } => {
            // Binary search the extent containing lbn.
            let i = extents.partition_point(|e| e.0 + e.1 <= lbn64);
            let e = extents.get(i).filter(|e| e.0 <= lbn64).ok_or_else(|| {
                crate::Error::InvalidImage(format!(
                    "udf: metadata block {lbn} beyond the metadata file"
                ))
            })?;
            let within = lbn64 - e.0;
            let ulbn = u64::from(e.2) + within;
            let ulbn = u32::try_from(ulbn)
                .map_err(|_| crate::Error::InvalidImage("udf: metadata extent overflows".into()))?;
            let left = (e.1 - within).min(want);
            map_run_in(maps, *under, ulbn, left, depth + 1)
        }
    }
}

/// Read the sparing tables; the copy with the highest sequence number
/// wins. Unreadable copies are warned about.
fn read_sparing(
    dev: &mut dyn BlockDevice,
    bs: u32,
    size: u32,
    locs: &[u32],
    ntables: u8,
    warnings: &mut Vec<String>,
) -> BTreeMap<u32, u64> {
    let size = size.clamp(56, MAX_SPARING_BYTES);
    let mut best: Option<(u32, BTreeMap<u32, u64>)> = None;
    for &loc in locs.iter().take(usize::from(ntables)) {
        let mut buf = vec![0u8; round_up(u64::from(size), u64::from(bs)) as usize];
        let off = u64::from(loc) * u64::from(bs);
        if off + buf.len() as u64 > dev.total_size() || dev.read_at(off, &mut buf).is_err() {
            push_warning(warnings, format!("sparing table at {loc} unreadable"));
            continue;
        }
        let Some(t) = Tag::parse(&buf) else {
            push_warning(warnings, format!("sparing table at {loc} has no valid tag"));
            continue;
        };
        if !t.crc_ok(&buf) || entity_name(&buf[16..48]) != "*UDF Sparing Table" {
            push_warning(warnings, format!("sparing table at {loc} is damaged"));
            continue;
        }
        let n = usize::from(u16le(&buf, 48));
        let seq = u32le(&buf, 52);
        let mut map = BTreeMap::new();
        for k in 0..n {
            let o = 56 + 8 * k;
            if o + 8 > buf.len() {
                break;
            }
            let orig = u32le(&buf, o);
            let mapped = u32le(&buf, o + 4);
            if orig < 0xFFFF_FFF0 {
                map.insert(orig, u64::from(mapped));
            }
        }
        if best.as_ref().is_none_or(|(s, _)| seq >= *s) {
            best = Some((seq, map));
        }
    }
    best.map(|(_, m)| m).unwrap_or_default()
}

/// The extents of the metadata (or mirror) file whose FE is at `lbn` of
/// partition map `under` (index into `maps`).
fn read_meta_extents(
    dev: &mut dyn BlockDevice,
    bs: u32,
    maps: &[PartMap],
    under: usize,
    lbn: u32,
) -> Result<Vec<(u64, u64, u32)>> {
    let vol = Volume {
        bs,
        maps: maps.to_vec(),
        root: LongAd::default(),
        info: UdfInfo::default(),
    };
    let ino = vol.read_inode(
        dev,
        LbAddr {
            lbn,
            part: under as u16,
        },
    )?;
    if ino.file_type != FT_META_MAIN && ino.file_type != FT_META_MIRROR {
        return Err(crate::Error::InvalidImage(format!(
            "udf: metadata file has type {}",
            ino.file_type
        )));
    }
    let InodeData::Extents(ext) = ino.data else {
        return Err(crate::Error::InvalidImage(
            "udf: metadata file is embedded".into(),
        ));
    };
    let bsz = u64::from(bs);
    let mut out = Vec::new();
    let mut next = 0u64;
    for e in ext {
        let blocks = u64::from(e.len).div_ceil(bsz);
        if e.kind == EXT_RECORDED || e.kind == EXT_ALLOCATED {
            if usize::from(e.loc.part) != under {
                return Err(crate::Error::InvalidImage(
                    "udf: metadata file extent outside its partition".into(),
                ));
            }
            out.push((next, blocks, e.loc.lbn));
        }
        next += blocks;
    }
    Ok(out)
}

/// What a VAT records besides the table.
#[derive(Default)]
struct VatInfo {
    lv_id: Option<String>,
    files: Option<u32>,
    dirs: Option<u32>,
    min_read: Option<u16>,
}

/// Locate and read the VAT: the last recorded File Entry of the session.
fn find_vat(
    dev: &mut dyn BlockDevice,
    bs: u32,
    maps: &[PartMap],
    under: usize,
    warnings: &mut Vec<String>,
) -> Result<(Vec<u32>, VatInfo)> {
    let (pstart, plen) = match &maps[under] {
        PartMap::Physical { start, len, .. } | PartMap::Sparable { start, len, .. } => {
            (*start, *len)
        }
        _ => unreachable!("VAT sits on a physical partition"),
    };
    let vol = Volume {
        bs,
        maps: maps.to_vec(),
        root: LongAd::default(),
        info: UdfInfo::default(),
    };
    let last = (dev.total_size() / u64::from(bs)).saturating_sub(1);
    let last = last.min(pstart + plen.saturating_sub(1));
    for back in 0..VAT_SEARCH_BLOCKS {
        let Some(abs) = last.checked_sub(back) else {
            break;
        };
        if abs < pstart {
            break;
        }
        let lbn = (abs - pstart) as u32;
        let loc = LbAddr {
            lbn,
            part: under as u16,
        };
        let Ok(ino) = vol.read_inode(dev, loc) else {
            continue;
        };
        if ino.file_type == FT_VAT20 {
            let body = vol.read_all(dev, &ino, MAX_VAT_BYTES)?;
            if body.len() < 152 {
                return Err(crate::Error::InvalidImage(
                    "udf: VAT header truncated".into(),
                ));
            }
            let hdr = usize::from(u16le(&body, 0)).max(152).min(body.len());
            let info = VatInfo {
                lv_id: Some(decode_dstring(&body[4..132])),
                files: Some(u32le(&body, 136)),
                dirs: Some(u32le(&body, 140)),
                min_read: Some(u16le(&body, 144)),
            };
            let vat = body[hdr..]
                .as_chunks::<4>()
                .0
                .iter()
                .map(|c| u32::from_le_bytes(*c))
                .collect();
            return Ok((vat, info));
        }
        if ino.file_type == 0 && ino.size >= 36 {
            let body = vol.read_all(dev, &ino, MAX_VAT_BYTES)?;
            let n = body.len();
            if n >= 36 && entity_name(&body[n - 36..n - 4]) == "*UDF Virtual Alloc Tbl" {
                let vat = body[..n - 36]
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .map(|c| u32::from_le_bytes(*c))
                    .collect();
                return Ok((vat, VatInfo::default()));
            }
        }
    }
    push_warning(warnings, "no VAT found near the end of the medium".into());
    Err(crate::Error::InvalidImage(
        "udf: virtual partition without a readable VAT".into(),
    ))
}

/// Walk the integrity sequence and record the prevailing LVID's contents.
fn read_lvid(
    dev: &mut dyn BlockDevice,
    vol: &mut Volume,
    len: u32,
    loc: u32,
    warnings: &mut Vec<String>,
) {
    let bs = vol.bs;
    let mut block = u64::from(loc);
    let mut remaining = (u64::from(len) / u64::from(bs)) as usize;
    let mut last: Option<Vec<u8>> = None;
    let mut walked = 0usize;
    while remaining > 0 && walked < MAX_LVID_BLOCKS {
        walked += 1;
        remaining -= 1;
        let Ok(buf) = read_block(dev, bs, block) else {
            break;
        };
        let Some(t) = Tag::parse(&buf) else { break };
        if t.id != TAG_LVID {
            break;
        }
        if !t.crc_ok(&buf) {
            push_warning(
                warnings,
                format!("integrity descriptor at {block} fails its CRC"),
            );
            break;
        }
        let next_len = u32le(&buf, 32);
        let next_loc = u32le(&buf, 36);
        last = Some(buf);
        if next_len > 0 {
            block = u64::from(next_loc);
            remaining = (u64::from(next_len) / u64::from(bs)) as usize;
        } else {
            block += 1;
        }
    }
    let Some(b) = last else {
        push_warning(warnings, "no Logical Volume Integrity Descriptor".into());
        return;
    };
    vol.info.integrity_open = u32le(&b, 28) == 0;
    let n_maps = u32le(&b, 72) as usize;
    if n_maps <= MAX_PARTITION_MAPS && 80 + 4 * n_maps <= b.len() {
        let free: u64 = (0..n_maps.min(vol.maps.len()))
            .filter(|&i| {
                matches!(
                    vol.maps[i],
                    PartMap::Physical { .. } | PartMap::Sparable { .. }
                )
            })
            .map(|i| u32le(&b, 80 + 4 * i))
            .filter(|&f| f != u32::MAX)
            .map(u64::from)
            .sum();
        vol.info.free_blocks = Some(free);
    }
    let n = u32le(&b, 72) as usize;
    let l_iu = u32le(&b, 76) as usize;
    let iu = 80usize.saturating_add(n.saturating_mul(8));
    if n <= MAX_PARTITION_MAPS && iu + l_iu.min(b.len()) <= b.len() && l_iu >= 46 {
        vol.info.num_files = Some(u32le(&b, iu + 32));
        vol.info.num_dirs = Some(u32le(&b, iu + 36));
        vol.info.min_read_revision = Some(u16le(&b, iu + 40));
        vol.info.min_write_revision = Some(u16le(&b, iu + 42));
        vol.info.max_write_revision = Some(u16le(&b, iu + 44));
    }
}

/// Decode a directory's File Identifier Descriptors. Deleted entries and
/// the parent entry are dropped.
pub(crate) fn parse_fids(buf: &[u8]) -> Result<Vec<Fid>> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 38 <= buf.len() {
        let d = &buf[off..];
        if d[..16].iter().all(|&b| b == 0) {
            break; // zero padding ends the directory
        }
        let tag = Tag::parse(d).ok_or_else(|| {
            crate::Error::InvalidImage(format!("udf: bad FID tag at directory offset {off}"))
        })?;
        if tag.id != TAG_FID {
            return Err(crate::Error::InvalidImage(format!(
                "udf: tag {} where a File Identifier Descriptor belongs (offset {off})",
                tag.id
            )));
        }
        let chars = d[18];
        let l_fi = usize::from(d[19]);
        let l_iu = usize::from(u16le(d, 36));
        let total = (38 + l_iu + l_fi).div_ceil(4) * 4;
        if 38 + l_iu + l_fi > d.len() {
            return Err(crate::Error::InvalidImage(format!(
                "udf: FID at offset {off} runs past the directory"
            )));
        }
        if !tag.crc_ok(d) {
            return Err(crate::Error::InvalidImage(format!(
                "udf: FID at directory offset {off} fails its CRC"
            )));
        }
        let icb = LongAd::parse(&d[20..36]);
        if chars & (FID_DELETED | FID_PARENT) == 0 {
            let raw = decode_cs0(&d[38 + l_iu..38 + l_iu + l_fi]);
            let name: String = raw
                .chars()
                .map(|c| if c == '/' || c == '\0' { '_' } else { c })
                .collect();
            if !name.is_empty() && name != "." && name != ".." {
                out.push(Fid {
                    name,
                    characteristics: chars,
                    icb,
                });
            }
        }
        off += total.max(4);
    }
    Ok(out)
}

/// Decode a symlink body (ECMA-167 4/14.16 path components).
///
/// `hdiutil makehybrid` records the target as plain UTF-8 instead; a body
/// that is not a valid component sequence but is printable UTF-8 is taken
/// as such (macOS reads those images the same way).
pub(crate) fn decode_symlink(b: &[u8]) -> Result<String> {
    match decode_components(b) {
        Ok(s) => Ok(s),
        Err(e) => match std::str::from_utf8(b) {
            Ok(s) if !s.is_empty() && !s.chars().any(char::is_control) => Ok(s.to_string()),
            _ => Err(e),
        },
    }
}

fn decode_components(b: &[u8]) -> Result<String> {
    let mut parts: Vec<String> = Vec::new();
    let mut absolute = false;
    let mut off = 0usize;
    while off + 4 <= b.len() {
        let ty = b[off];
        let l = usize::from(b[off + 1]);
        if off + 4 + l > b.len() {
            return Err(crate::Error::InvalidImage(
                "udf: symlink path component runs past its body".into(),
            ));
        }
        let ident = &b[off + 4..off + 4 + l];
        match ty {
            1 | 2 => {
                parts.clear();
                absolute = true;
            }
            3 => parts.push("..".into()),
            4 => parts.push(".".into()),
            5 => parts.push(decode_cs0(ident)),
            _ => {
                return Err(crate::Error::InvalidImage(format!(
                    "udf: unknown symlink component type {ty}"
                )));
            }
        }
        off += 4 + l;
    }
    let joined = parts.join("/");
    Ok(if absolute {
        format!("/{joined}")
    } else {
        joined
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symlink_components() {
        // "/usr/bin" and "../a"
        let mut b = vec![2, 0, 0, 0];
        for n in ["usr", "bin"] {
            let e = encode_cs0(n);
            b.extend_from_slice(&[5, e.len() as u8, 0, 0]);
            b.extend_from_slice(&e);
        }
        assert_eq!(decode_symlink(&b).unwrap(), "/usr/bin");
        let mut b = vec![3, 0, 0, 0];
        let e = encode_cs0("a");
        b.extend_from_slice(&[5, e.len() as u8, 0, 0]);
        b.extend_from_slice(&e);
        assert_eq!(decode_symlink(&b).unwrap(), "../a");
        assert!(decode_symlink(&[5, 9, 0, 0, 8]).is_err());
        // hdiutil's raw UTF-8 targets.
        assert_eq!(
            decode_symlink(b"../caf\xc3\xa9.txt").unwrap(),
            "../café.txt"
        );
        assert_eq!(decode_symlink(b"/dir/x").unwrap(), "/dir/x");
    }

    #[test]
    fn fid_parse_rejects_garbage() {
        assert!(parse_fids(&[0xAAu8; 64]).is_err());
        assert!(parse_fids(&[0u8; 64]).unwrap().is_empty());
    }
}
