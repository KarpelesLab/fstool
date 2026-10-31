//! Format options and the standalone ("format a device") writer.
//!
//! The standalone writer is a thin driver over [`super::layout`]: file
//! payloads stream straight onto the device from the partition start as
//! each `create_file` arrives (only their extents are remembered), and
//! `flush` hands the resulting tree to [`UdfImage::build`] with the
//! metadata placed right after the data — the same path an external
//! layout planner takes.

use std::io::Read;

use super::layout::{BlockRange, DataExtent, FileData, UdfImage, UdfPlacement, UdfTree};
use crate::Result;
use crate::block::BlockDevice;
use crate::fs::{DeviceKind, FileMeta};

/// A UDF revision fstool can write. Each is advertised individually,
/// and only once images of that revision pass native validation
/// (`fsck_udf` and a kernel mount on macOS, `udfinfo` / a kernel mount on
/// Linux CI).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[non_exhaustive]
pub enum UdfRevision {
    /// UDF 1.02 (ECMA-167 2nd edition, `NSR02`, File Entries): what
    /// `hdiutil makehybrid -udf-version 1.02` writes; readable by every
    /// UDF implementation.
    V1_02,
    /// UDF 1.50 (`NSR02`, File Entries).
    V1_50,
    /// UDF 2.01 (ECMA-167 3rd edition, `NSR03`, Extended File Entries).
    #[default]
    V2_01,
    /// UDF 2.50 (`NSR03`, Extended File Entries, a metadata partition with
    /// a duplicated mirror file).
    V2_50,
}

impl UdfRevision {
    /// Every revision this build writes, oldest first.
    pub const WRITABLE: &'static [UdfRevision] = &[
        UdfRevision::V1_02,
        UdfRevision::V1_50,
        UdfRevision::V2_01,
        UdfRevision::V2_50,
    ];

    /// The revision as BCD (`0x0201`), as recorded on disc.
    pub const fn bcd(self) -> u16 {
        match self {
            Self::V1_02 => 0x0102,
            Self::V1_50 => 0x0150,
            Self::V2_01 => 0x0201,
            Self::V2_50 => 0x0250,
        }
    }

    /// The `NSR0x` version: 2 below UDF 2.00, 3 from it on.
    pub const fn nsr(self) -> u8 {
        if self.bcd() >= 0x0200 { 3 } else { 2 }
    }

    /// Descriptor tag version (equal to the NSR version).
    pub(crate) const fn tag_version(self) -> u16 {
        self.nsr() as u16
    }

    /// Whether this revision records its metadata in a metadata partition.
    pub const fn uses_metadata_partition(self) -> bool {
        self.bcd() >= 0x0250
    }

    /// Parse `"1.02"`, `"102"`, `"2.50"`, ….
    pub fn parse(s: &str) -> Result<Self> {
        let t = s.trim().trim_start_matches(['v', 'V']).replace('.', "");
        Ok(match t.as_str() {
            "102" => Self::V1_02,
            "150" | "15" => Self::V1_50,
            "201" => Self::V2_01,
            "250" | "25" => Self::V2_50,
            _ => {
                return Err(crate::Error::InvalidArgument(format!(
                    "udf: unsupported revision {s:?} (writable: 1.02, 1.50, 2.01, 2.50)"
                )));
            }
        })
    }
}

impl core::fmt::Display for UdfRevision {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let b = self.bcd();
        write!(f, "{:x}.{:02x}", b >> 8, b & 0xFF)
    }
}

/// Partition access type recorded in the Partition Descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum AccessType {
    /// Read-only (type 1): pressed / distribution media. No space bitmap.
    #[default]
    ReadOnly,
    /// Overwritable (type 4): a hard disk or flash volume another system
    /// can keep writing to. An unallocated-space bitmap is recorded.
    Overwritable,
}

impl AccessType {
    /// The on-disc code.
    pub const fn code(self) -> u32 {
        match self {
            Self::ReadOnly => 1,
            Self::Overwritable => 4,
        }
    }
}

/// UDF format options.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct FormatOpts {
    /// Revision to write.
    pub revision: UdfRevision,
    /// Logical block size: 2048 (optical media, the default), or 512 /
    /// 1024 / 4096 for hard disks.
    pub block_size: u32,
    /// Primary Volume Descriptor volume identifier (≤ 30 Latin-1 or 15
    /// UTF-16 characters).
    pub volume_id: String,
    /// Logical volume identifier — the name macOS, Windows and Linux
    /// show. `None` uses `volume_id`. ≤ 126 Latin-1 / 63 UTF-16.
    pub logical_volume_id: Option<String>,
    /// Volume set identifier. `None` generates the 16 hex digits UDF
    /// 2.2.2.5 asks for.
    pub volume_set_id: Option<String>,
    /// File set identifier. `None` uses the logical volume identifier.
    pub file_set_id: Option<String>,
    /// Application identifier in the PVD (≤ 23 ASCII bytes).
    pub application_id: String,
    /// Recording time stamped on the volume structures (Unix seconds).
    pub recording_time: u32,
    /// Partition access type.
    pub access: AccessType,
    /// Cover the whole device instead of ending the volume right after
    /// its last block (the default, like ISO 9660: the image is truncated
    /// to fit).
    pub fill_device: bool,
    /// Record all-zero 64 KiB runs of a file as unallocated holes.
    pub sparse: bool,
    /// Embed small directories in their File Entry. `None` embeds them
    /// for UDF ≥ 2.00 (as mkudffs does) and gives them their own blocks
    /// below (as `hdiutil makehybrid` does for 1.02 / 1.50).
    pub inline_dirs: Option<bool>,
    /// Extended File Entries (ECMA-167 3rd edition). `None` picks them for
    /// UDF ≥ 2.00.
    pub extended_entries: Option<bool>,
}

impl Default for FormatOpts {
    fn default() -> Self {
        Self {
            revision: UdfRevision::default(),
            block_size: 2048,
            volume_id: "UDF Volume".into(),
            logical_volume_id: None,
            volume_set_id: None,
            file_set_id: None,
            application_id: String::new(),
            recording_time: 0,
            access: AccessType::default(),
            fill_device: false,
            sparse: true,
            inline_dirs: None,
            extended_entries: None,
        }
    }
}

impl FormatOpts {
    /// The logical volume identifier actually recorded.
    pub fn logical_volume_id(&self) -> String {
        self.logical_volume_id
            .clone()
            .unwrap_or_else(|| self.volume_id.clone())
    }

    /// Whether small directories are embedded in their File Entry.
    pub fn uses_inline_dirs(&self) -> bool {
        self.inline_dirs.unwrap_or(self.revision.nsr() >= 3)
    }

    /// Whether Extended File Entries are written.
    pub fn uses_extended_entries(&self) -> bool {
        self.extended_entries.unwrap_or(self.revision.nsr() >= 3)
    }

    /// Check the options for consistency.
    pub fn validate(&self) -> Result<()> {
        if !matches!(self.block_size, 512 | 1024 | 2048 | 4096) {
            return Err(crate::Error::InvalidArgument(format!(
                "udf: block size {} (use 512, 1024, 2048 or 4096)",
                self.block_size
            )));
        }
        if self.extended_entries == Some(true) && self.revision.nsr() < 3 {
            return Err(crate::Error::InvalidArgument(format!(
                "udf: Extended File Entries need UDF 2.00 or later (asked for {})",
                self.revision
            )));
        }
        if !self.application_id.is_ascii() || self.application_id.len() > 23 {
            return Err(crate::Error::InvalidArgument(
                "udf: application_id must be at most 23 ASCII bytes".into(),
            ));
        }
        super::ecma::encode_dstring(&self.volume_id, 32, "volume identifier")?;
        super::ecma::encode_dstring(&self.logical_volume_id(), 128, "logical volume identifier")?;
        if let Some(s) = &self.volume_set_id {
            super::ecma::encode_dstring(s, 128, "volume set identifier")?;
        }
        let fs = self
            .file_set_id
            .clone()
            .unwrap_or_else(|| self.logical_volume_id());
        super::ecma::encode_dstring(&fs, 32, "file set identifier").map_err(|e| match e {
            crate::Error::InvalidArgument(m) => crate::Error::InvalidArgument(format!(
                "{m} (the file set identifier defaults to the volume label; set \
                     file_set_id to something shorter)"
            )),
            e => e,
        })?;
        Ok(())
    }

    /// Apply a generic option bag (CLI `-O key=val` / TOML
    /// `[filesystem.options]`). Unknown keys are left for the caller.
    pub fn apply_options(&mut self, map: &mut crate::format_opts::OptionMap) -> Result<()> {
        for key in ["revision", "udf_revision", "udf_version", "version"] {
            if let Some(s) = map.take_str(key) {
                self.revision = UdfRevision::parse(&s)?;
            }
        }
        if let Some(b) = map.take_u32("block_size")? {
            self.block_size = b;
        }
        for key in ["volume_id", "volume_label", "label"] {
            if let Some(s) = map.take_str(key) {
                self.volume_id = s;
            }
        }
        if let Some(s) = map.take_str("logical_volume_id") {
            self.logical_volume_id = Some(s);
        }
        if let Some(s) = map.take_str("volume_set_id") {
            self.volume_set_id = Some(s);
        }
        if let Some(s) = map.take_str("file_set_id") {
            self.file_set_id = Some(s);
        }
        if let Some(s) = map.take_str("application_id") {
            self.application_id = s;
        }
        for key in ["recording_time", "create_date"] {
            if let Some(t) = map.take_u32(key)? {
                self.recording_time = t;
            }
        }
        if let Some(s) = map.take_str("access") {
            self.access = match s.to_ascii_lowercase().as_str() {
                "ro" | "readonly" | "read-only" => AccessType::ReadOnly,
                "ow" | "rw" | "overwritable" | "overwrite" => AccessType::Overwritable,
                other => {
                    return Err(crate::Error::InvalidArgument(format!(
                        "udf: access {other:?} (use ro or ow)"
                    )));
                }
            };
        }
        if let Some(b) = map.take_bool("fill")? {
            self.fill_device = b;
        }
        if let Some(b) = map.take_bool("sparse")? {
            self.sparse = b;
        }
        if let Some(b) = map.take_bool("inline_dirs")? {
            self.inline_dirs = Some(b);
        }
        if let Some(b) = map.take_bool("extended_entries")? {
            self.extended_entries = Some(b);
        }
        Ok(())
    }
}

/// Metadata the writer could not record. Collected (bounded) rather than
/// silently dropped; see [`super::Udf::unsupported`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UnsupportedMetadata {
    /// Path of the entry.
    pub path: String,
    /// What was not recorded (e.g. `xattr user.comment`).
    pub item: String,
}

/// Blocks reserved before the partition: everything up to and including
/// the anchor at 256.
pub(crate) const PARTITION_START: u64 = 257;

/// Bytes streamed per write.
const CHUNK: usize = 64 * 1024;

/// The standalone writer behind [`super::Udf::format`].
pub(crate) struct UdfWriter {
    pub opts: FormatOpts,
    tree: UdfTree,
    bs: u64,
    /// Next free absolute block in the data area.
    cursor: u64,
    image_len: Option<u64>,
    /// Something changed since the last `flush`.
    dirty: bool,
    pub unsupported: Vec<UnsupportedMetadata>,
}

fn norm(path: &std::path::Path) -> Result<String> {
    let s = path
        .to_str()
        .ok_or_else(|| crate::Error::InvalidArgument("udf: non-UTF-8 path".into()))?;
    Ok(format!("/{}", s.trim_matches('/')))
}

impl UdfWriter {
    pub fn new(dev: &mut dyn BlockDevice, opts: FormatOpts) -> Result<Self> {
        opts.validate()?;
        let bs = u64::from(opts.block_size);
        if opts.fill_device && dev.total_size() / bs < PARTITION_START + 64 {
            return Err(crate::Error::InvalidArgument(format!(
                "udf: device of {} bytes is too small for a UDF volume",
                dev.total_size()
            )));
        }
        Ok(Self {
            bs,
            cursor: PARTITION_START,
            tree: UdfTree::new(),
            opts,
            image_len: None,
            dirty: true,
            unsupported: Vec::new(),
        })
    }

    pub fn image_len(&self) -> Option<u64> {
        self.image_len
    }

    /// The tree being built.
    pub fn tree(&self) -> &UdfTree {
        &self.tree
    }

    /// The tree, for an edit: the next `flush` lays the metadata out again.
    pub fn tree_mut(&mut self) -> &mut UdfTree {
        self.dirty = true;
        &mut self.tree
    }

    /// Stream `reader` onto the device at the data cursor.
    pub fn add_file(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &std::path::Path,
        reader: &mut dyn Read,
        meta: FileMeta,
    ) -> Result<()> {
        let path = norm(path)?;
        let bs = self.bs;
        let mut buf = vec![0u8; CHUNK];
        let mut extents: Vec<DataExtent> = Vec::new();
        let mut total = 0u64;
        loop {
            // Fill the whole chunk (short reads are legal).
            let mut n = 0usize;
            while n < CHUNK {
                let r = reader.read(&mut buf[n..])?;
                if r == 0 {
                    break;
                }
                n += r;
            }
            if n == 0 {
                break;
            }
            let chunk = &buf[..n];
            let len = n as u64;
            if self.opts.sparse && chunk.iter().all(|&b| b == 0) {
                match extents.last_mut() {
                    Some(DataExtent::Hole { len: l }) => *l += len,
                    _ => extents.push(DataExtent::hole(len)),
                }
            } else {
                let at = self.cursor;
                let blocks = len.div_ceil(bs);
                let end = (at + blocks) * bs;
                if !self.opts.fill_device || end <= dev.total_size() {
                    dev.write_at(at * bs, chunk)?;
                    let pad = (blocks * bs - len) as usize;
                    if pad > 0 {
                        dev.write_at(at * bs + len, &vec![0u8; pad])?;
                    }
                } else {
                    return Err(crate::Error::InvalidArgument(format!(
                        "udf: device full while writing {path:?}"
                    )));
                }
                self.cursor += blocks;
                match extents.last_mut() {
                    Some(DataExtent::Recorded { block, len: l })
                        if *block + *l / bs == at && *l % bs == 0 =>
                    {
                        *l += len
                    }
                    _ => extents.push(DataExtent::recorded(at, len)),
                }
            }
            total += len;
            if n < CHUNK {
                break;
            }
        }
        let data = FileData::from_extents(extents);
        debug_assert_eq!(data.len, total);
        self.tree_mut().add_file(&path, data, meta)
    }

    pub fn add_dir(&mut self, path: &std::path::Path, meta: FileMeta) -> Result<()> {
        self.tree_mut().add_dir(&norm(path)?, meta)
    }

    pub fn add_symlink(
        &mut self,
        path: &std::path::Path,
        target: &std::path::Path,
        meta: FileMeta,
    ) -> Result<()> {
        let t = target
            .to_str()
            .ok_or_else(|| crate::Error::InvalidArgument("udf: non-UTF-8 symlink target".into()))?;
        self.tree_mut().add_symlink(&norm(path)?, t, meta)
    }

    pub fn add_device(
        &mut self,
        path: &std::path::Path,
        kind: DeviceKind,
        major: u32,
        minor: u32,
        meta: FileMeta,
    ) -> Result<()> {
        self.tree_mut()
            .add_device(&norm(path)?, kind, major, minor, meta)
    }

    pub fn add_hardlink(&mut self, target: &std::path::Path, new: &std::path::Path) -> Result<()> {
        self.tree_mut().add_hardlink(&norm(new)?, &norm(target)?)
    }

    pub fn remove(&mut self, path: &std::path::Path) -> Result<()> {
        self.tree_mut().remove(&norm(path)?)
    }

    pub fn note_unsupported(&mut self, path: &std::path::Path, item: String) {
        if self.unsupported.len() < 4096 {
            self.unsupported.push(UnsupportedMetadata {
                path: path.display().to_string(),
                item,
            });
        }
    }

    /// Lay out and write the metadata. A no-op when nothing changed since
    /// the last flush; after one, further entries can still be added and
    /// the next flush records a new metadata generation after them (the
    /// old one becomes unreferenced space), so a caller may flush between
    /// edits.
    pub fn flush(&mut self, dev: &mut dyn BlockDevice) -> Result<()> {
        if !self.dirty && self.image_len.is_some() {
            return Ok(());
        }
        let bs = self.bs;
        let dev_blocks = dev.total_size() / bs;
        let start = PARTITION_START;
        let data_end = self.cursor;
        let (volume_blocks, part_len) = if self.opts.fill_device {
            (dev_blocks, dev_blocks - 1 - start)
        } else {
            // Size the partition to data + metadata; the space bitmap (if
            // any) depends on the partition length, so settle it by
            // iteration (it converges in a step or two).
            let mut plen = data_end - start + 64;
            for _ in 0..8 {
                let need = UdfImage::requirements(&self.tree, &self.opts, plen)?;
                let want = data_end - start + need.metadata_blocks;
                if want <= plen {
                    break;
                }
                plen = want;
            }
            let need = UdfImage::requirements(&self.tree, &self.opts, plen)?;
            let plen = (data_end - start + need.metadata_blocks).max(1);
            (start + plen + 1, plen)
        };
        if !self.opts.fill_device && volume_blocks > dev_blocks {
            return Err(crate::Error::InvalidArgument(format!(
                "udf: the volume needs {} bytes but the device holds {}",
                volume_blocks * bs,
                dev.total_size()
            )));
        }
        if data_end > start + part_len {
            return Err(crate::Error::InvalidArgument(
                "udf: the device is full".into(),
            ));
        }
        let partition = BlockRange::new(start, part_len);
        let mut placement = UdfPlacement::new(self.opts.block_size, volume_blocks, partition);
        placement.free = vec![BlockRange::new(data_end, start + part_len - data_end)];
        let image = UdfImage::build(&self.tree, &self.opts, &placement)?;
        // Own the whole pre-partition area: clear stale recognition
        // descriptors or volume structures a previous format left there.
        // The system area (the first 32 KiB) is left alone.
        let zero = vec![0u8; ((start * bs) - 32768) as usize];
        dev.write_at(32768, &zero)?;
        image.write(dev)?;
        self.image_len = Some(volume_blocks * bs);
        self.dirty = false;
        // Later payload goes past everything just written: after the
        // metadata inside a fixed partition, or past the closing anchor of
        // a compact volume (whose partition then grows over it).
        self.cursor = if self.opts.fill_device {
            image
                .used_ranges()
                .iter()
                .filter(|r| r.start >= start && r.start < start + part_len)
                .map(|r| r.start + r.len)
                .max()
                .unwrap_or(data_end)
                .max(data_end)
        } else {
            volume_blocks
        };
        Ok(())
    }
}

/// Upper-bound sizing for [`crate::fs::FilesystemFactory::size_plan`]:
/// every payload block (no hole is assumed), one File Entry per entry,
/// each directory's FID stream rounded to whole blocks, and the volume
/// structures. The writer truncates to its real length after `flush`, so
/// an over-estimate only costs sparse space in the backing file.
pub(crate) struct UdfSizePlan {
    opts: FormatOpts,
    data_blocks: u64,
    entries: u64,
    dir_bytes: std::collections::HashMap<String, u64>,
}

impl UdfSizePlan {
    pub fn new(opts: &FormatOpts) -> Self {
        Self {
            opts: opts.clone(),
            data_blocks: 0,
            entries: 0,
            dir_bytes: std::collections::HashMap::new(),
        }
    }

    fn entry(&mut self, path: &str) {
        let (parent, name) = crate::fs::split_parent_name(path);
        let n = super::ecma::encode_cs0(name).len() as u64;
        *self.dir_bytes.entry(parent.to_string()).or_insert(40) += (38 + n).div_ceil(4) * 4;
        self.entries += 1;
    }
}

impl crate::fs::FsSizePlan for UdfSizePlan {
    fn add_dir(&mut self, path: &str) {
        self.entry(path);
        self.dir_bytes.entry(path.to_string()).or_insert(40);
    }
    fn add_file(&mut self, path: &str, len: u64) {
        self.entry(path);
        let bs = u64::from(self.opts.block_size);
        let blocks = len.div_ceil(bs);
        // Plus one AED block per ~250 maximal extents.
        self.data_blocks += blocks + blocks / (250 * (1 << 30) / bs);
    }
    fn add_symlink(&mut self, path: &str, target: &str) {
        self.entry(path);
        let bs = u64::from(self.opts.block_size);
        self.data_blocks += (target.len() as u64 * 2 + 64).div_ceil(bs);
    }
    fn add_device(&mut self, path: &str) {
        self.entry(path);
    }
    fn total_size(&self) -> u64 {
        let bs = u64::from(self.opts.block_size);
        let dirs: u64 = self.dir_bytes.values().map(|b| b.div_ceil(bs)).sum();
        let mut meta = 1 + (self.entries + 1) + dirs + 1;
        if self.opts.access == AccessType::Overwritable {
            meta += (24 + (self.data_blocks + meta * 2).div_ceil(8)).div_ceil(bs) + 1;
        }
        if self.opts.revision.uses_metadata_partition() {
            meta = 2 * super::ecma::round_up(meta, 32) + 2;
        }
        (PARTITION_START + self.data_blocks + meta + 16) * bs
    }
}
