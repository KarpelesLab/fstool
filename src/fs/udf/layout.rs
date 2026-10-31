//! Planner-driven UDF authoring: record a UDF view over file payloads that
//! are **already placed** on the medium.
//!
//! This is the layer an optical-image layout planner (an ISO 9660 / Joliet
//! / HFS+ / UDF hybrid, say) drives. The planner owns the sector map; UDF
//! only asks for two things:
//!
//! 1. A [`UdfTree`] — directories, symlinks, devices, hard links and
//!    regular files, where every file's payload is a list of
//!    [`DataExtent`]s naming the absolute blocks the planner put it at.
//!    Those blocks can be the very sectors an ISO 9660 directory record or
//!    an HFS+ extent also points at: UDF never moves or copies payload.
//! 2. A [`UdfPlacement`] — where the volume structures go (recognition
//!    sequence, anchors, the two volume descriptor sequences, the
//!    integrity sequence), the partition's block range (which must cover
//!    every payload extent), and the free ranges inside the partition UDF
//!    may fill with its own metadata (File Set Descriptor, File Entries,
//!    directory streams, allocation-extent blocks, the space bitmap, and —
//!    for UDF 2.50 — the metadata file and its mirror).
//!
//! [`UdfImage::requirements`] tells the planner how much metadata space to
//! set aside *before* it has decided where; [`UdfImage::build`] lays the
//! metadata out inside the given free ranges and returns a [`UdfImage`]
//! that knows every block it will write ([`UdfImage::used_ranges`], for
//! overlap checks against the other views) and writes them with
//! [`UdfImage::write`]. Nothing outside those ranges is touched.
//!
//! ```no_run
//! use fstool::fs::FileMeta;
//! use fstool::fs::udf::layout::{BlockRange, DataExtent, FileData, UdfImage, UdfPlacement, UdfTree};
//! use fstool::fs::udf::{FormatOpts, UdfRevision};
//! # fn demo(dev: &mut dyn fstool::block::BlockDevice) -> fstool::Result<()> {
//! // The planner already wrote "readme.txt" (1234 bytes) at block 300 —
//! // the same LBA its ISO 9660 directory record names.
//! let mut tree = UdfTree::new();
//! tree.add_dir("/docs", FileMeta::with_mode(0o755))?;
//! tree.add_file("/docs/readme.txt", FileData::contiguous(300, 1234), FileMeta::with_mode(0o644))?;
//!
//! let mut opts = FormatOpts::default();
//! opts.revision = UdfRevision::V1_02;
//! opts.volume_id = "MYDISC".into();
//!
//! // How many blocks of UDF metadata will this need?
//! let need = UdfImage::requirements(&tree, &opts, 1000)?;
//!
//! // Partition: blocks 257..1257 (covers the payload at 300). UDF may put
//! // its metadata in blocks 1100.. — space the planner kept free.
//! let mut placement = UdfPlacement::new(2048, 1258, BlockRange::new(257, 1000));
//! placement.free = vec![BlockRange::new(1100, need.metadata_blocks)];
//!
//! let image = UdfImage::build(&tree, &opts, &placement)?;
//! for r in image.used_ranges() {
//!     // check r.start .. r.start + r.len against the ISO / HFS+ structures
//!     let _ = (r.start, r.len, r.what);
//! }
//! image.write(dev)?;
//! # Ok(()) }
//! ```

use std::collections::{BTreeMap, VecDeque};

use super::ecma::*;
use super::read::{
    FID_DIR, FID_PARENT, FT_BLOCK, FT_CHAR, FT_DIR, FT_FIFO, FT_FILE, FT_SOCKET, FT_SYMLINK,
};
use super::write::{AccessType, FormatOpts};
use crate::Result;
use crate::block::BlockDevice;
use crate::fs::{DeviceKind, FileMeta};

/// A run of blocks: `start .. start + len`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[non_exhaustive]
pub struct BlockRange {
    /// First block.
    pub start: u64,
    /// Number of blocks.
    pub len: u64,
}

impl BlockRange {
    /// `start .. start + len`.
    pub const fn new(start: u64, len: u64) -> Self {
        Self { start, len }
    }
    /// One past the last block.
    pub const fn end(&self) -> u64 {
        self.start + self.len
    }
    fn overlaps(&self, o: &BlockRange) -> bool {
        self.len > 0 && o.len > 0 && self.start < o.end() && o.start < self.end()
    }
}

/// One piece of a regular file's payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DataExtent {
    /// `len` bytes recorded from absolute block `block` on.
    Recorded {
        /// Absolute block (not partition-relative) where the bytes start.
        block: u64,
        /// Byte length. Every extent but a file's last must be a whole
        /// number of blocks.
        len: u64,
    },
    /// `len` bytes of zeros with nothing recorded (a sparse hole).
    Hole {
        /// Byte length.
        len: u64,
    },
}

impl DataExtent {
    /// A recorded extent.
    pub const fn recorded(block: u64, len: u64) -> Self {
        Self::Recorded { block, len }
    }
    /// A hole.
    pub const fn hole(len: u64) -> Self {
        Self::Hole { len }
    }
    /// Byte length.
    pub const fn len(&self) -> u64 {
        match self {
            Self::Recorded { len, .. } | Self::Hole { len } => *len,
        }
    }
    /// Whether the extent is zero bytes long.
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Where a regular file's bytes are.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct FileData {
    /// File length in bytes — the sum of the extents' lengths.
    pub len: u64,
    /// The payload, in file order.
    pub extents: Vec<DataExtent>,
}

impl FileData {
    /// An empty file.
    pub fn empty() -> Self {
        Self::default()
    }
    /// `len` bytes recorded contiguously from absolute block `block`.
    pub fn contiguous(block: u64, len: u64) -> Self {
        if len == 0 {
            return Self::empty();
        }
        Self {
            len,
            extents: vec![DataExtent::recorded(block, len)],
        }
    }
    /// A file made of `extents`; its length is their sum.
    pub fn from_extents(extents: Vec<DataExtent>) -> Self {
        let len = extents.iter().map(DataExtent::len).sum();
        Self { len, extents }
    }
}

#[derive(Debug, Clone)]
enum TKind {
    Dir,
    File(FileData),
    Symlink(String),
    Device {
        kind: DeviceKind,
        major: u32,
        minor: u32,
    },
}

#[derive(Debug, Clone)]
struct TNode {
    kind: TKind,
    meta: FileMeta,
    /// Every `(parent, name)` this node is linked under. More than one for
    /// a hard-linked file; exactly one for a directory; none once removed.
    names: Vec<(usize, String)>,
    /// Directory children by name.
    children: BTreeMap<String, usize>,
}

/// The tree a UDF view records: directories, regular files (with their
/// already-placed payload), symlinks, device nodes / FIFOs / sockets, and
/// hard links. Paths are `/`-separated and absolute; missing parent
/// directories are created with mode 0755.
#[derive(Debug, Clone)]
pub struct UdfTree {
    nodes: Vec<TNode>,
}

impl Default for UdfTree {
    fn default() -> Self {
        Self::new()
    }
}

/// What an entry in a [`UdfTree`] is, as [`UdfTree::entry`] reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TreeEntry<'a> {
    /// A directory.
    Dir,
    /// A regular file.
    File(&'a FileData),
    /// A symbolic link and its target.
    Symlink(&'a str),
    /// A device node, FIFO or socket.
    Device {
        /// Which kind.
        kind: DeviceKind,
        /// Major number.
        major: u32,
        /// Minor number.
        minor: u32,
    },
}

fn split_path(path: &str) -> Result<Vec<&str>> {
    let comps: Vec<&str> = path
        .split('/')
        .filter(|c| !c.is_empty() && *c != ".")
        .collect();
    if comps.contains(&"..") {
        return Err(crate::Error::InvalidArgument(format!(
            "udf: path {path:?} contains '..'"
        )));
    }
    Ok(comps)
}

impl UdfTree {
    /// An empty tree holding only the root directory.
    pub fn new() -> Self {
        Self {
            nodes: vec![TNode {
                kind: TKind::Dir,
                meta: FileMeta::with_mode(0o755),
                names: Vec::new(),
                children: BTreeMap::new(),
            }],
        }
    }

    /// Node index for `path`, if it exists.
    fn lookup(&self, path: &str) -> Option<usize> {
        let mut cur = 0usize;
        for c in split_path(path).ok()? {
            cur = *self.nodes[cur].children.get(c)?;
        }
        Some(cur)
    }

    /// Directory node for the parent of `path` (created on demand) and the
    /// leaf name.
    fn parent_for<'p>(&mut self, path: &'p str) -> Result<(usize, &'p str)> {
        let comps = split_path(path)?;
        let Some((leaf, dirs)) = comps.split_last() else {
            return Err(crate::Error::InvalidArgument(
                "udf: the root directory cannot be replaced".into(),
            ));
        };
        let mut cur = 0usize;
        for d in dirs {
            cur = match self.nodes[cur].children.get(*d) {
                Some(&i) => {
                    if !matches!(self.nodes[i].kind, TKind::Dir) {
                        return Err(crate::Error::InvalidArgument(format!(
                            "udf: {d:?} in {path:?} is not a directory"
                        )));
                    }
                    i
                }
                None => self.insert(cur, d, TKind::Dir, FileMeta::with_mode(0o755)),
            };
        }
        Ok((cur, leaf))
    }

    fn insert(&mut self, parent: usize, name: &str, kind: TKind, meta: FileMeta) -> usize {
        let idx = self.nodes.len();
        self.nodes.push(TNode {
            kind,
            meta,
            names: vec![(parent, name.to_string())],
            children: BTreeMap::new(),
        });
        self.nodes[parent].children.insert(name.to_string(), idx);
        idx
    }

    fn put(&mut self, path: &str, kind: TKind, meta: FileMeta) -> Result<()> {
        let (parent, leaf) = self.parent_for(path)?;
        if let Some(&old) = self.nodes[parent].children.get(leaf) {
            if matches!(kind, TKind::Dir) && matches!(self.nodes[old].kind, TKind::Dir) {
                self.nodes[old].meta = meta;
                return Ok(());
            }
            self.unlink(parent, leaf);
        }
        self.insert(parent, leaf, kind, meta);
        Ok(())
    }

    /// Add (or update the metadata of) a directory.
    pub fn add_dir(&mut self, path: &str, meta: FileMeta) -> Result<()> {
        if split_path(path)?.is_empty() {
            self.nodes[0].meta = meta;
            return Ok(());
        }
        self.put(path, TKind::Dir, meta)
    }

    /// Add a regular file whose payload is already on the medium at
    /// `data`. Replaces whatever was at `path`.
    pub fn add_file(&mut self, path: &str, data: FileData, meta: FileMeta) -> Result<()> {
        let sum: u64 = data.extents.iter().map(DataExtent::len).sum();
        if sum != data.len {
            return Err(crate::Error::InvalidArgument(format!(
                "udf: {path:?}: extents total {sum} bytes but the file is {} bytes",
                data.len
            )));
        }
        self.put(path, TKind::File(data), meta)
    }

    /// Add a symbolic link to `target`.
    pub fn add_symlink(&mut self, path: &str, target: &str, meta: FileMeta) -> Result<()> {
        if target.is_empty() {
            return Err(crate::Error::InvalidArgument(format!(
                "udf: {path:?}: empty symlink target"
            )));
        }
        self.put(path, TKind::Symlink(target.to_string()), meta)
    }

    /// Add a device node, FIFO or socket.
    pub fn add_device(
        &mut self,
        path: &str,
        kind: DeviceKind,
        major: u32,
        minor: u32,
        meta: FileMeta,
    ) -> Result<()> {
        self.put(path, TKind::Device { kind, major, minor }, meta)
    }

    /// Link `path` to the existing non-directory entry `existing`: both
    /// names then share one File Entry (UDF hard link).
    pub fn add_hardlink(&mut self, path: &str, existing: &str) -> Result<()> {
        let target = self.lookup(existing).ok_or_else(|| {
            crate::Error::InvalidArgument(format!("udf: hard link target {existing:?} not found"))
        })?;
        if matches!(self.nodes[target].kind, TKind::Dir) {
            return Err(crate::Error::InvalidArgument(format!(
                "udf: cannot hard-link the directory {existing:?}"
            )));
        }
        if self.nodes[target].names.len() >= usize::from(u16::MAX) {
            return Err(crate::Error::InvalidArgument(format!(
                "udf: {existing:?} already has the maximum 65535 links"
            )));
        }
        let (parent, leaf) = self.parent_for(path)?;
        if let Some(&old) = self.nodes[parent].children.get(leaf) {
            if old == target {
                return Ok(());
            }
            self.unlink(parent, leaf);
        }
        self.nodes[target].names.push((parent, leaf.to_string()));
        self.nodes[parent].children.insert(leaf.to_string(), target);
        Ok(())
    }

    /// Remove `path` (a directory with everything under it).
    pub fn remove(&mut self, path: &str) -> Result<()> {
        let comps = split_path(path)?;
        if comps.is_empty() {
            return Err(crate::Error::InvalidArgument(
                "udf: cannot remove the root directory".into(),
            ));
        }
        let (parent, leaf) = self.parent_for(path)?;
        if !self.nodes[parent].children.contains_key(leaf) {
            return Err(crate::Error::InvalidArgument(format!(
                "udf: no entry at {path:?}"
            )));
        }
        self.unlink(parent, leaf);
        Ok(())
    }

    fn unlink(&mut self, parent: usize, name: &str) {
        let Some(idx) = self.nodes[parent].children.remove(name) else {
            return;
        };
        self.nodes[idx]
            .names
            .retain(|(p, n)| !(*p == parent && n == name));
        if self.nodes[idx].names.is_empty() {
            // Detach the whole subtree, iteratively.
            let mut stack = vec![idx];
            while let Some(i) = stack.pop() {
                let kids: Vec<(String, usize)> = std::mem::take(&mut self.nodes[i].children)
                    .into_iter()
                    .collect();
                for (n, k) in kids {
                    self.nodes[k].names.retain(|(p, nn)| !(*p == i && *nn == n));
                    if self.nodes[k].names.is_empty() {
                        stack.push(k);
                    }
                }
            }
        }
    }

    /// Replace the metadata of the entry at `path` (the root included).
    pub fn set_meta(&mut self, path: &str, meta: FileMeta) -> Result<()> {
        let i = self
            .lookup(path)
            .ok_or_else(|| crate::Error::InvalidArgument(format!("udf: no entry at {path:?}")))?;
        self.nodes[i].meta = meta;
        Ok(())
    }

    /// What is at `path`, if anything.
    pub fn entry(&self, path: &str) -> Option<(TreeEntry<'_>, FileMeta)> {
        let i = self.lookup(path)?;
        Some((self.entry_of(i), self.nodes[i].meta))
    }

    fn entry_of(&self, i: usize) -> TreeEntry<'_> {
        match &self.nodes[i].kind {
            TKind::Dir => TreeEntry::Dir,
            TKind::File(d) => TreeEntry::File(d),
            TKind::Symlink(t) => TreeEntry::Symlink(t),
            TKind::Device { kind, major, minor } => TreeEntry::Device {
                kind: *kind,
                major: *major,
                minor: *minor,
            },
        }
    }

    /// The names in directory `path`, sorted, with a stable per-node id
    /// (equal for hard links) — `None` when `path` is not a directory.
    pub fn children(&self, path: &str) -> Option<Vec<(String, usize, TreeEntry<'_>)>> {
        let i = self.lookup(path)?;
        if !matches!(self.nodes[i].kind, TKind::Dir) {
            return None;
        }
        Some(
            self.nodes[i]
                .children
                .iter()
                .map(|(n, &k)| (n.clone(), k, self.entry_of(k)))
                .collect(),
        )
    }

    /// Number of names linked to the entry at `path`.
    pub fn link_count(&self, path: &str) -> Option<usize> {
        self.lookup(path).map(|i| self.nodes[i].names.len().max(1))
    }
}

/// Where the volume structures and UDF's metadata go. Block numbers are
/// absolute (in units of [`block_size`](Self::block_size)).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UdfPlacement {
    /// Logical block size: 2048 for optical media; 512 / 1024 / 4096 for
    /// hard disks.
    pub block_size: u32,
    /// Blocks on the medium (`N`). The last anchor conventionally sits at
    /// `N - 1`.
    pub volume_blocks: u64,
    /// Byte offset where the UDF recognition descriptors (BEA01, NSR0x,
    /// TEA01) begin: 32768 on a pure UDF volume; just after an ISO 9660
    /// Volume Descriptor Set Terminator on a bridge disc.
    pub vrs_offset: u64,
    /// Main Volume Descriptor Sequence extent (at least 16 blocks per
    /// ECMA-167; 6 are written, the rest zeroed).
    pub main_vds: BlockRange,
    /// Reserve Volume Descriptor Sequence extent (same size rules).
    pub reserve_vds: BlockRange,
    /// Integrity sequence extent: the LVID and a Terminating Descriptor
    /// (at least 2 blocks).
    pub integrity: BlockRange,
    /// Anchor Volume Descriptor Pointer blocks. ECMA-167 asks for two of
    /// 256, N-256 and N-1; 256 must be one of them.
    pub anchors: Vec<u64>,
    /// The partition: must contain every [`DataExtent::Recorded`] block
    /// and every [`free`](Self::free) range, and none of the volume
    /// structures above.
    pub partition: BlockRange,
    /// Free ranges inside the partition UDF may use for its metadata,
    /// first-fit, in the order given.
    pub free: Vec<BlockRange>,
}

impl UdfPlacement {
    /// The conventional layout for a `volume_blocks`-block medium: the
    /// recognition sequence at byte 32768, the main and reserve VDS and
    /// the integrity sequence between it and block 256 (main VDS at byte
    /// 64 KiB, as mkudffs does), anchors at 256 and `volume_blocks - 1`.
    /// `free` starts empty.
    pub fn new(block_size: u32, volume_blocks: u64, partition: BlockRange) -> Self {
        let bs = u64::from(block_size.max(512));
        let first_free = (32768 + 3 * bs.max(2048)).div_ceil(bs);
        let main = (65536 / bs).max(first_free);
        Self {
            block_size,
            volume_blocks,
            vrs_offset: 32768,
            main_vds: BlockRange::new(main, 16),
            reserve_vds: BlockRange::new(main + 16, 16),
            integrity: BlockRange::new(main + 32, 2),
            anchors: vec![256, volume_blocks.saturating_sub(1)],
            partition,
            free: Vec::new(),
        }
    }
}

/// How much partition space [`UdfImage::build`] will need for metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct UdfRequirements {
    /// Blocks the free ranges must hold in total.
    pub metadata_blocks: u64,
    /// The largest single contiguous run among them (a directory's
    /// stream, or the UDF 2.50 metadata file); some free range must be at
    /// least this long.
    pub largest_run: u64,
}

/// One region [`UdfImage::write`] writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct UsedRange {
    /// First block.
    pub start: u64,
    /// Blocks.
    pub len: u64,
    /// What lives there (`"anchor"`, `"main VDS"`, `"metadata"`, …).
    pub what: &'static str,
}

/// Counters of what a build recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct UdfStats {
    /// Directories, root included.
    pub dirs: u32,
    /// Non-directory File Entries (hard links count once).
    pub files: u32,
    /// Next free UDF unique ID.
    pub next_unique_id: u64,
    /// Blocks of metadata written inside the partition.
    pub metadata_blocks: u64,
}

/// A fully laid-out UDF view, ready to write.
#[derive(Debug, Clone)]
pub struct UdfImage {
    bs: u32,
    /// `(absolute block, bytes)`; bytes are zero-padded to whole blocks
    /// when written.
    writes: Vec<(u64, Vec<u8>)>,
    /// `(byte offset, bytes)` written verbatim (the recognition sequence).
    raw: Vec<(u64, Vec<u8>)>,
    used: Vec<UsedRange>,
    stats: UdfStats,
}

// ---------------------------------------------------------------------------
// Per-node planning.
// ---------------------------------------------------------------------------

/// Allocation descriptors' geometry for one revision.
#[derive(Clone, Copy)]
struct Geo {
    bs: u64,
    fe_base: usize,
    efe: bool,
    tag_ver: u16,
    /// Partition reference of the metadata (FSD, ICBs, directories).
    meta_part: u16,
    /// Whether data extents need long ADs (data in a different partition
    /// from the ICB).
    long_data: bool,
    max_ext: u64,
}

impl Geo {
    fn new(opts: &FormatOpts) -> Self {
        let efe = opts.uses_extended_entries();
        let meta = opts.revision.uses_metadata_partition();
        Geo {
            bs: u64::from(opts.block_size),
            fe_base: if efe { 216 } else { 176 },
            efe,
            tag_ver: opts.revision.tag_version(),
            meta_part: u16::from(meta),
            long_data: meta,
            max_ext: u64::from(max_extent_len(opts.block_size)),
        }
    }
    fn data_ad_size(&self) -> usize {
        if self.long_data { 16 } else { 8 }
    }
}

/// An allocation descriptor to record: `(type, byte length, partition-
/// relative lbn, partition ref)`.
#[derive(Clone, Copy)]
struct Ad {
    kind: u8,
    len: u32,
    lbn: u32,
    part: u16,
}

enum Body {
    /// No body at all (devices, empty files).
    None,
    /// Embedded in the ICB.
    Inline(Vec<u8>),
    /// Recorded in `blocks` metadata blocks (directories, long symlinks).
    Blocks(u64),
    /// File data at caller-placed extents.
    Extents(Vec<Ad>),
}

struct Plan {
    node: usize,
    file_type: u8,
    ea: Vec<u8>,
    body: Body,
    /// Directory: the FID stream length (inline or not).
    size: u64,
    /// AED blocks needed for an over-long AD list.
    aed_blocks: u64,
    /// ADs that fit in the FE itself (the rest go to AEDs).
    fe_ad_slots: usize,
    unique_id: u64,
    // Assigned at allocation time.
    fe_lbn: u32,
    data_lbn: u32,
    aed_lbns: Vec<u32>,
}

fn fid_len(name_bytes: usize) -> usize {
    (38 + name_bytes).div_ceil(4) * 4
}

fn validate_name(name: &str) -> Result<Vec<u8>> {
    if name.contains('\0') {
        return Err(crate::Error::InvalidArgument(format!(
            "udf: file name {name:?} contains NUL"
        )));
    }
    let enc = encode_cs0(name);
    if enc.len() > 255 {
        return Err(crate::Error::InvalidArgument(format!(
            "udf: file name {name:?} is {} bytes as OSTA CS0; UDF allows 255 \
             (254 Latin-1 or 127 UTF-16 characters)",
            enc.len()
        )));
    }
    Ok(enc)
}

/// Encode a symlink target as ECMA-167 path components.
fn encode_symlink(target: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    if target.starts_with('/') {
        out.extend_from_slice(&[1, 0, 0, 0]);
    }
    for c in target.split('/').filter(|c| !c.is_empty()) {
        match c {
            "." => out.extend_from_slice(&[4, 0, 0, 0]),
            ".." => out.extend_from_slice(&[3, 0, 0, 0]),
            n => {
                let e = encode_cs0(n);
                if e.len() > 255 {
                    return Err(crate::Error::InvalidArgument(format!(
                        "udf: symlink component {n:?} is too long ({} bytes encoded)",
                        e.len()
                    )));
                }
                out.extend_from_slice(&[5, e.len() as u8, 0, 0]);
                out.extend_from_slice(&e);
            }
        }
    }
    Ok(out)
}

fn device_ea(major: u32, minor: u32, loc: u32, tag_ver: u16) -> Vec<u8> {
    let mut ea = vec![0u8; 24 + 24];
    // Extended Attribute Header Descriptor: no implementation- or
    // application-use attributes follow (0xFFFFFFFF, as macOS and Linux
    // record it).
    put_u32(&mut ea, 16, u32::MAX);
    put_u32(&mut ea, 20, u32::MAX);
    finish_tag(&mut ea[..24], TAG_EAHD, tag_ver, 1, loc, 8);
    // Device Specification (ECMA-167 4/14.10.7): type 12, subtype 1.
    put_u32(&mut ea, 24, 12);
    ea[28] = 1;
    put_u32(&mut ea, 32, 24);
    put_u32(&mut ea, 36, 0);
    put_u32(&mut ea, 40, major);
    put_u32(&mut ea, 44, minor);
    ea
}

/// Split file extents into ADs no longer than the maximum extent length.
fn data_ads(data: &FileData, geo: &Geo, part: &BlockRange, path: &str) -> Result<Vec<Ad>> {
    let mut ads = Vec::new();
    let n = data.extents.len();
    for (i, e) in data.extents.iter().enumerate() {
        let last = i + 1 == n;
        if !last && e.len() % geo.bs != 0 {
            return Err(crate::Error::InvalidArgument(format!(
                "udf: {path:?}: extent {i} is {} bytes, not a whole number of {}-byte blocks",
                e.len(),
                geo.bs
            )));
        }
        match *e {
            DataExtent::Recorded { block, len } => {
                if len == 0 {
                    continue;
                }
                let blocks = len.div_ceil(geo.bs);
                if block < part.start || block + blocks > part.end() {
                    return Err(crate::Error::InvalidArgument(format!(
                        "udf: {path:?}: payload blocks {block}..{} lie outside the partition \
                         {}..{}",
                        block + blocks,
                        part.start,
                        part.end()
                    )));
                }
                let mut off = 0u64;
                while off < len {
                    let chunk = (len - off).min(geo.max_ext);
                    ads.push(Ad {
                        kind: EXT_RECORDED,
                        len: chunk as u32,
                        lbn: (block - part.start + off / geo.bs) as u32,
                        part: 0,
                    });
                    off += chunk;
                }
            }
            DataExtent::Hole { len } => {
                let mut off = 0u64;
                while off < len {
                    let chunk = (len - off).min(geo.max_ext);
                    ads.push(Ad {
                        kind: EXT_HOLE,
                        len: chunk as u32,
                        lbn: 0,
                        part: 0,
                    });
                    off += chunk;
                }
            }
        }
    }
    // Merge neighbours where the result still fits one AD.
    let mut merged: Vec<Ad> = Vec::with_capacity(ads.len());
    for a in ads {
        if let Some(p) = merged.last_mut()
            && p.kind == a.kind
            && u64::from(p.len) % geo.bs == 0
            && u64::from(p.len) + u64::from(a.len) <= geo.max_ext
            && (a.kind != EXT_RECORDED
                || u64::from(p.lbn) + u64::from(p.len) / geo.bs == u64::from(a.lbn))
        {
            p.len += a.len;
            continue;
        }
        merged.push(a);
    }
    Ok(merged)
}

/// How many ADs fit in the FE and how many AED blocks the rest need.
fn ad_layout(n: usize, ad_sz: usize, fe_room: usize, bs: usize) -> (usize, u64) {
    let fe_cap = fe_room / ad_sz;
    if n <= fe_cap {
        return (n, 0);
    }
    let aed_cap = (bs - 24) / ad_sz;
    // The FE keeps fe_cap - 1 ADs plus the pointer; each AED keeps
    // aed_cap - 1 plus a pointer, the last up to aed_cap.
    let mut rest = n - (fe_cap - 1);
    let mut blocks = 0u64;
    loop {
        blocks += 1;
        if rest <= aed_cap {
            break;
        }
        rest -= aed_cap - 1;
    }
    (fe_cap - 1, blocks)
}

/// Walk the tree breadth-first, children by name; every live node once.
fn bfs(tree: &UdfTree) -> Vec<usize> {
    let mut order = Vec::new();
    let mut seen = vec![false; tree.nodes.len()];
    let mut q = VecDeque::from([0usize]);
    seen[0] = true;
    while let Some(i) = q.pop_front() {
        order.push(i);
        for &k in tree.nodes[i].children.values() {
            if !seen[k] {
                seen[k] = true;
                q.push_back(k);
            }
        }
    }
    order
}

/// Everything about the build that does not depend on where blocks land.
struct Planned {
    plans: Vec<Plan>,
    /// Node → index in `plans`.
    index: Vec<usize>,
    /// Metadata blocks in the metadata space (FSD + ICBs + bodies + AEDs).
    meta_blocks: u64,
    largest: u64,
    bitmap_blocks: u64,
}

fn plan(tree: &UdfTree, opts: &FormatOpts, geo: &Geo, part: &BlockRange) -> Result<Planned> {
    let bs = geo.bs as usize;
    let order = bfs(tree);
    let mut index = vec![usize::MAX; tree.nodes.len()];
    let mut plans = Vec::with_capacity(order.len());
    let mut next_uid = 16u64;
    let mut meta_blocks = 1u64; // the FSD
    let mut largest = 1u64;
    for &i in &order {
        let n = &tree.nodes[i];
        let unique_id = if i == 0 {
            0
        } else {
            let u = next_uid;
            next_uid += 1;
            u
        };
        let (file_type, ea, body, size) = match &n.kind {
            TKind::Dir => {
                let mut size = fid_len(0);
                for name in n.children.keys() {
                    size += fid_len(validate_name(name)?.len());
                }
                (FT_DIR, Vec::new(), Body::None, size as u64)
            }
            TKind::File(d) => {
                let ads = data_ads(d, geo, part, &path_of(tree, i))?;
                let body = if ads.is_empty() {
                    Body::None
                } else {
                    Body::Extents(ads)
                };
                (FT_FILE, Vec::new(), body, d.len)
            }
            TKind::Symlink(t) => {
                let b = encode_symlink(t)?;
                let len = b.len() as u64;
                (FT_SYMLINK, Vec::new(), Body::Inline(b), len)
            }
            TKind::Device { kind, major, minor } => {
                let (ft, ea) = match kind {
                    DeviceKind::Char => (FT_CHAR, device_ea(*major, *minor, 0, geo.tag_ver)),
                    DeviceKind::Block => (FT_BLOCK, device_ea(*major, *minor, 0, geo.tag_ver)),
                    DeviceKind::Fifo => (FT_FIFO, Vec::new()),
                    DeviceKind::Socket => (FT_SOCKET, Vec::new()),
                };
                (ft, ea, Body::None, 0)
            }
        };
        let room = bs - geo.fe_base - ea.len();
        // Directories and symlinks: embed when they fit (and, for
        // directories, when asked), else give them their own blocks.
        let body = match (&n.kind, body) {
            (TKind::Dir, _) => {
                if opts.uses_inline_dirs() && size as usize <= room {
                    Body::Inline(Vec::new())
                } else {
                    Body::Blocks(size.div_ceil(geo.bs))
                }
            }
            (TKind::Symlink(_), Body::Inline(b)) if b.len() > room => {
                if b.len() as u64 > crate::fs::udf::read::MAX_SYMLINK_BYTES {
                    return Err(crate::Error::InvalidArgument(format!(
                        "udf: symlink {:?} target is too long",
                        path_of(tree, i)
                    )));
                }
                Body::Blocks((b.len() as u64).div_ceil(geo.bs))
            }
            (_, b) => b,
        };
        let (fe_ad_slots, aed_blocks) = match &body {
            Body::Extents(ads) => ad_layout(ads.len(), geo.data_ad_size(), room, bs),
            Body::Blocks(blocks) => {
                let n_ads = (blocks * geo.bs).div_ceil(geo.max_ext) as usize;
                ad_layout(n_ads, geo.data_ad_size(), room, bs)
            }
            _ => (0, 0),
        };
        meta_blocks += 1 + aed_blocks;
        if let Body::Blocks(b) = body {
            meta_blocks += b;
            largest = largest.max(b);
        }
        index[i] = plans.len();
        plans.push(Plan {
            node: i,
            file_type,
            ea,
            body,
            size,
            aed_blocks,
            fe_ad_slots,
            unique_id,
            fe_lbn: 0,
            data_lbn: 0,
            aed_lbns: Vec::new(),
        });
    }
    let bitmap_blocks = if opts.access == AccessType::Overwritable {
        (24 + part.len.div_ceil(8)).div_ceil(geo.bs)
    } else {
        0
    };
    Ok(Planned {
        plans,
        index,
        meta_blocks,
        largest,
        bitmap_blocks,
    })
}

fn path_of(tree: &UdfTree, mut i: usize) -> String {
    let mut parts = Vec::new();
    let mut guard = 0;
    while i != 0 && guard < 100_000 {
        guard += 1;
        let Some((p, n)) = tree.nodes[i].names.first() else {
            break;
        };
        parts.push(n.clone());
        i = *p;
    }
    parts.reverse();
    format!("/{}", parts.join("/"))
}

/// Metadata-file allocation unit (blocks) for UDF 2.50.
const META_ALLOC_UNIT: u64 = 32;

/// First-fit allocator over the caller's free ranges.
struct Alloc {
    free: Vec<BlockRange>,
    taken: Vec<BlockRange>,
}

impl Alloc {
    fn take(&mut self, n: u64, what: &str) -> Result<u64> {
        if n == 0 {
            return Ok(0);
        }
        for r in self.free.iter_mut() {
            if r.len >= n {
                let at = r.start;
                r.start += n;
                r.len -= n;
                self.taken.push(BlockRange::new(at, n));
                return Ok(at);
            }
        }
        Err(crate::Error::InvalidArgument(format!(
            "udf: no free run of {n} blocks left for {what}; give the layout more metadata space"
        )))
    }
}

impl UdfImage {
    /// Metadata space a build of `tree` with `opts` needs, for a partition
    /// of `partition_blocks` blocks (the space bitmap of an overwritable
    /// partition scales with it).
    pub fn requirements(
        tree: &UdfTree,
        opts: &FormatOpts,
        partition_blocks: u64,
    ) -> Result<UdfRequirements> {
        opts.validate()?;
        let geo = Geo::new(opts);
        // Payload bounds are checked against a partition covering
        // everything, so this works before the partition is decided.
        let part = BlockRange::new(0, u64::MAX / 4);
        let mut p = plan(tree, opts, &geo, &part)?;
        p.bitmap_blocks = if opts.access == AccessType::Overwritable {
            (24 + partition_blocks.div_ceil(8)).div_ceil(geo.bs)
        } else {
            0
        };
        Ok(if opts.revision.uses_metadata_partition() {
            let m = round_up(p.meta_blocks, META_ALLOC_UNIT);
            UdfRequirements {
                metadata_blocks: 2 * m + 2,
                largest_run: m,
            }
        } else {
            UdfRequirements {
                metadata_blocks: p.meta_blocks + p.bitmap_blocks,
                largest_run: p.largest.max(p.bitmap_blocks),
            }
        })
    }

    /// Lay out `tree` per `placement` and encode every descriptor.
    pub fn build(tree: &UdfTree, opts: &FormatOpts, placement: &UdfPlacement) -> Result<UdfImage> {
        opts.validate()?;
        if placement.block_size != opts.block_size {
            return Err(crate::Error::InvalidArgument(format!(
                "udf: placement block size {} differs from the format's {}",
                placement.block_size, opts.block_size
            )));
        }
        let geo = Geo::new(opts);
        let bs = geo.bs;
        let part = placement.partition;
        check_placement(placement, bs)?;
        let mut planned = plan(tree, opts, &geo, &part)?;
        if opts.access == AccessType::Overwritable && opts.revision.uses_metadata_partition() {
            return Err(crate::Error::Unsupported(
                "udf: an overwritable UDF 2.50 volume needs a metadata bitmap file, which \
                 fstool does not write yet; use access=ro"
                    .into(),
            ));
        }

        // Free ranges, validated and bounded to the partition.
        let mut free = placement.free.clone();
        for r in &free {
            if r.start < part.start || r.end() > part.end() {
                return Err(crate::Error::InvalidArgument(format!(
                    "udf: free range {}..{} lies outside the partition {}..{}",
                    r.start,
                    r.end(),
                    part.start,
                    part.end()
                )));
            }
        }
        free.retain(|r| r.len > 0);
        // No payload block may sit in space handed to UDF for metadata.
        let mut sorted_free = free.clone();
        sorted_free.sort();
        for p in &planned.plans {
            let Body::Extents(ads) = &p.body else {
                continue;
            };
            for a in ads.iter().filter(|a| a.kind == EXT_RECORDED) {
                let r =
                    BlockRange::new(part.start + u64::from(a.lbn), u64::from(a.len).div_ceil(bs));
                let i = sorted_free.partition_point(|f| f.end() <= r.start);
                if let Some(f) = sorted_free.get(i)
                    && f.overlaps(&r)
                {
                    return Err(crate::Error::InvalidArgument(format!(
                        "udf: payload of {:?} (blocks {}..{}) overlaps the free range {}..{}",
                        path_of(tree, p.node),
                        r.start,
                        r.end(),
                        f.start,
                        f.end()
                    )));
                }
            }
        }
        let mut alloc = Alloc {
            free,
            taken: Vec::new(),
        };
        let mut used: Vec<UsedRange> = Vec::new();
        let mut writes: Vec<(u64, Vec<u8>)> = Vec::new();
        let rev = opts.revision.bcd();
        let ts = encode_timestamp(i64::from(opts.recording_time));

        // ---- metadata space ----
        // `meta_abs(lbn)` maps a metadata-space lbn to an absolute block.
        let meta_part_abs: u64; // absolute block of metadata lbn 0
        let mut meta_file: Option<(u32, u32, u32, u64)> = None; // (fe lbn, mirror fe lbn, main start lbn, M)
        let mut mirror_start = 0u64;
        if opts.revision.uses_metadata_partition() {
            let m = round_up(planned.meta_blocks, META_ALLOC_UNIT);
            let main = alloc.take(m, "the metadata file")?;
            let mirror = alloc.take(m, "the metadata mirror file")?;
            let fe = alloc.take(1, "the metadata file entry")?;
            let mfe = alloc.take(1, "the metadata mirror file entry")?;
            meta_part_abs = main;
            mirror_start = mirror;
            meta_file = Some((
                (fe - part.start) as u32,
                (mfe - part.start) as u32,
                (main - part.start) as u32,
                m,
            ));
            used.push(UsedRange {
                start: main,
                len: m,
                what: "metadata file",
            });
            used.push(UsedRange {
                start: mirror,
                len: m,
                what: "metadata mirror file",
            });
            used.push(UsedRange {
                start: fe,
                len: 1,
                what: "metadata file entry",
            });
            used.push(UsedRange {
                start: mfe,
                len: 1,
                what: "metadata mirror file entry",
            });
        } else {
            meta_part_abs = part.start;
        }
        // Metadata-space allocator: in the metadata partition a simple
        // bump pointer over the metadata file; otherwise the free ranges.
        let mut bump = 0u64;
        let meta_cap = meta_file.map(|m| m.3).unwrap_or(0);
        let mut take_meta = |alloc: &mut Alloc, n: u64, what: &str| -> Result<u32> {
            if meta_file.is_some() {
                if bump + n > meta_cap {
                    return Err(crate::Error::InvalidArgument(format!(
                        "udf: metadata file overflow while placing {what}"
                    )));
                }
                let at = bump;
                bump += n;
                Ok(at as u32)
            } else {
                let abs = alloc.take(n, what)?;
                Ok((abs - part.start) as u32)
            }
        };

        let fsd_lbn = take_meta(&mut alloc, 1, "the File Set Descriptor")?;
        let bitmap_lbn = if planned.bitmap_blocks > 0 {
            Some(take_meta(
                &mut alloc,
                planned.bitmap_blocks,
                "the space bitmap",
            )?)
        } else {
            None
        };
        for p in planned.plans.iter_mut() {
            p.fe_lbn = take_meta(&mut alloc, 1, "a File Entry")?;
            if let Body::Blocks(b) = p.body {
                p.data_lbn = take_meta(&mut alloc, b, "a directory")?;
            }
            for _ in 0..p.aed_blocks {
                let l = take_meta(&mut alloc, 1, "an allocation extent")?;
                p.aed_lbns.push(l);
            }
        }
        if meta_file.is_none() {
            for r in &alloc.taken {
                used.push(UsedRange {
                    start: r.start,
                    len: r.len,
                    what: "metadata",
                });
            }
        }
        let meta_lbn_limit: u64 = if meta_file.is_some() {
            meta_cap
        } else {
            part.len
        };
        if u64::from(u32::MAX) < meta_lbn_limit.max(part.len) {
            return Err(crate::Error::InvalidArgument(
                "udf: partition longer than 2^32 blocks".into(),
            ));
        }

        let mut meta_out: Vec<(u32, Vec<u8>)> = Vec::new(); // (metadata lbn, bytes)
        let fe_locs: Vec<LbAddr> = planned
            .plans
            .iter()
            .map(|p| LbAddr {
                lbn: p.fe_lbn,
                part: geo.meta_part,
            })
            .collect();
        let icb_of = |idx: usize| -> LbAddr { fe_locs[idx] };

        // ---- directory streams ----
        let mut dir_streams: Vec<Option<Vec<u8>>> = Vec::with_capacity(planned.plans.len());
        for p in &planned.plans {
            let node = &tree.nodes[p.node];
            if !matches!(node.kind, TKind::Dir) {
                dir_streams.push(None);
                continue;
            }
            let inline = matches!(p.body, Body::Inline(_));
            let mut s = Vec::with_capacity(p.size as usize);
            let tag_lbn = |off: usize| -> u32 {
                if inline {
                    p.fe_lbn
                } else {
                    p.data_lbn + (off as u64 / bs) as u32
                }
            };
            // Parent entry.
            let parent = node.names.first().map(|x| x.0).unwrap_or(0);
            let pidx = planned.index[parent];
            let off = s.len();
            s.extend_from_slice(&fid(
                FID_DIR | FID_PARENT,
                &[],
                icb_of(pidx),
                planned.plans[pidx].unique_id,
                bs,
                geo.tag_ver,
                tag_lbn(off),
            ));
            for (name, &child) in &node.children {
                let cidx = planned.index[child];
                let chars = if matches!(tree.nodes[child].kind, TKind::Dir) {
                    FID_DIR
                } else {
                    0
                };
                let off = s.len();
                s.extend_from_slice(&fid(
                    chars,
                    &encode_cs0(name),
                    icb_of(cidx),
                    planned.plans[cidx].unique_id,
                    bs,
                    geo.tag_ver,
                    tag_lbn(off),
                ));
            }
            debug_assert_eq!(s.len() as u64, p.size);
            dir_streams.push(Some(s));
        }

        // ---- File Entries, bodies, AEDs ----
        let mut n_dirs = 0u32;
        let mut n_files = 0u32;
        for (pi, p) in planned.plans.iter_mut().enumerate() {
            let node = &tree.nodes[p.node];
            let is_dir = matches!(node.kind, TKind::Dir);
            if is_dir {
                n_dirs += 1;
            } else {
                n_files += 1;
            }
            if !p.ea.is_empty() {
                // Re-stamp the EA header tag with the FE's location.
                let mut ea = p.ea.clone();
                let crc_len = 8;
                finish_tag(&mut ea[..24], TAG_EAHD, geo.tag_ver, 1, p.fe_lbn, crc_len);
                p.ea = ea;
            }
            let link_count = if is_dir {
                1 + node
                    .children
                    .values()
                    .filter(|&&c| matches!(tree.nodes[c].kind, TKind::Dir))
                    .count()
            } else {
                node.names.len().max(1)
            };
            // Body → ADs or inline bytes.
            let (ad_type, inline, ads, recorded_blocks): (u16, Option<Vec<u8>>, Vec<Ad>, u64) =
                match &p.body {
                    Body::None => (
                        if geo.long_data {
                            ICB_AD_LONG
                        } else {
                            ICB_AD_SHORT
                        },
                        None,
                        Vec::new(),
                        0,
                    ),
                    Body::Inline(b) => {
                        let bytes = if is_dir {
                            dir_streams[pi].clone().unwrap_or_default()
                        } else {
                            b.clone()
                        };
                        (ICB_AD_INLINE, Some(bytes), Vec::new(), 0)
                    }
                    Body::Blocks(blocks) => {
                        let bytes = if is_dir {
                            dir_streams[pi].clone().unwrap_or_default()
                        } else if let TKind::Symlink(t) = &node.kind {
                            encode_symlink(t)?
                        } else {
                            Vec::new()
                        };
                        let mut ads = Vec::new();
                        let total = bytes.len() as u64;
                        let mut off = 0u64;
                        while off < total {
                            let chunk = (total - off).min(geo.max_ext);
                            ads.push(Ad {
                                kind: EXT_RECORDED,
                                len: chunk as u32,
                                lbn: p.data_lbn + (off / bs) as u32,
                                part: geo.meta_part,
                            });
                            off += chunk;
                        }
                        // The body itself.
                        meta_out.push((p.data_lbn, bytes));
                        (
                            if geo.long_data {
                                ICB_AD_LONG
                            } else {
                                ICB_AD_SHORT
                            },
                            None,
                            ads,
                            *blocks,
                        )
                    }
                    Body::Extents(ads) => {
                        let rb: u64 = ads
                            .iter()
                            .filter(|a| a.kind == EXT_RECORDED)
                            .map(|a| u64::from(a.len).div_ceil(bs))
                            .sum();
                        let t = if geo.long_data {
                            ICB_AD_LONG
                        } else {
                            ICB_AD_SHORT
                        };
                        (t, None, ads.clone(), rb)
                    }
                };
            let ad_sz = if ad_type == ICB_AD_LONG { 16 } else { 8 };
            // Split ADs between the FE and the AED chain.
            let (fe_ads, chain): (Vec<Ad>, Vec<Vec<Ad>>) = if p.aed_lbns.is_empty() {
                (ads, Vec::new())
            } else {
                let aed_cap = (bs as usize - 24) / ad_sz;
                let mut rest = ads;
                let fe_part: Vec<Ad> = rest.drain(..p.fe_ad_slots.min(rest.len())).collect();
                let mut chain = Vec::new();
                for k in 0..p.aed_lbns.len() {
                    let last = k + 1 == p.aed_lbns.len();
                    let take = if last {
                        rest.len()
                    } else {
                        (aed_cap - 1).min(rest.len())
                    };
                    chain.push(rest.drain(..take).collect::<Vec<Ad>>());
                }
                (fe_part, chain)
            };
            let ptr = |lbn: u32| Ad {
                kind: EXT_NEXT,
                len: bs as u32,
                lbn,
                part: geo.meta_part,
            };
            let mut ad_bytes = Vec::new();
            for a in &fe_ads {
                ad_bytes.extend_from_slice(&encode_ad(a, ad_type));
            }
            if let Some(&first) = p.aed_lbns.first() {
                ad_bytes.extend_from_slice(&encode_ad(&ptr(first), ad_type));
            }
            for (k, list) in chain.iter().enumerate() {
                let mut body = Vec::new();
                for a in list {
                    body.extend_from_slice(&encode_ad(a, ad_type));
                }
                if let Some(&next) = p.aed_lbns.get(k + 1) {
                    body.extend_from_slice(&encode_ad(&ptr(next), ad_type));
                }
                let mut aed = vec![0u8; 24 + body.len()];
                put_u32(
                    &mut aed,
                    16,
                    if k == 0 { p.fe_lbn } else { p.aed_lbns[k - 1] },
                );
                put_u32(&mut aed, 20, body.len() as u32);
                aed[24..].copy_from_slice(&body);
                let l = aed.len();
                finish_tag(&mut aed, TAG_AED, geo.tag_ver, 1, p.aed_lbns[k], l - 16);
                meta_out.push((p.aed_lbns[k], aed));
            }
            let alloc_bytes = inline.unwrap_or(ad_bytes);
            let fe = encode_fe(&FeArgs {
                geo: &geo,
                lbn: p.fe_lbn,
                file_type: p.file_type,
                meta: &node.meta,
                link_count: link_count.min(usize::from(u16::MAX)) as u16,
                size: p.size,
                recorded_blocks,
                unique_id: p.unique_id,
                ad_type,
                ea: &p.ea,
                ads: &alloc_bytes,
            });
            meta_out.push((p.fe_lbn, fe));
        }

        // ---- File Set Descriptor ----
        let lv_id = opts.logical_volume_id();
        let fs_id = opts.file_set_id.clone().unwrap_or_else(|| lv_id.clone());
        let root_icb = LongAd {
            len: bs as u32,
            kind: 0,
            loc: icb_of(0),
            imp: [0; 6],
        };
        let mut fsd = vec![0u8; 512];
        fsd[16..28].copy_from_slice(&ts);
        put_u16(&mut fsd, 28, 3);
        put_u16(&mut fsd, 30, 3);
        put_u32(&mut fsd, 32, 1);
        put_u32(&mut fsd, 36, 1);
        fsd[48..112].copy_from_slice(&osta_charspec());
        fsd[112..240].copy_from_slice(&encode_dstring(&lv_id, 128, "logical volume identifier")?);
        fsd[240..304].copy_from_slice(&osta_charspec());
        fsd[304..336].copy_from_slice(&encode_dstring(&fs_id, 32, "file set identifier")?);
        root_icb.write(&mut fsd[400..416]);
        fsd[416..448].copy_from_slice(&entity_id("*OSTA UDF Compliant", domain_suffix(rev)));
        finish_tag(&mut fsd, TAG_FSD, geo.tag_ver, 1, fsd_lbn, 496);
        meta_out.push((fsd_lbn, fsd));

        // ---- space bitmap ----
        let mut free_blocks = 0u64;
        if let Some(bl) = bitmap_lbn {
            let nbits = part.len;
            let nbytes = nbits.div_ceil(8);
            let mut sbd = vec![0u8; 24 + nbytes as usize];
            put_u32(&mut sbd, 16, nbits as u32);
            put_u32(&mut sbd, 20, nbytes as u32);
            // Free = what is left of the caller's free ranges.
            for r in &alloc.free {
                for b in r.start..r.end() {
                    let rel = (b - part.start) as usize;
                    sbd[24 + rel / 8] |= 1 << (rel % 8);
                    free_blocks += 1;
                }
            }
            finish_tag(&mut sbd, TAG_SBD, geo.tag_ver, 1, bl, 8);
            meta_out.push((bl, sbd));
        }

        // Emit metadata-space writes.
        let mut meta_used_end = 0u64;
        for (lbn, bytes) in meta_out {
            let blocks = (bytes.len() as u64).div_ceil(bs).max(1);
            meta_used_end = meta_used_end.max(u64::from(lbn) + blocks);
            writes.push((meta_part_abs + u64::from(lbn), bytes.clone()));
            if meta_file.is_some() {
                writes.push((mirror_start + u64::from(lbn), bytes));
            }
        }
        let _ = meta_lbn_limit;

        // ---- metadata file entries (2.50) ----
        if let Some((fe_lbn, mfe_lbn, main_lbn, m)) = meta_file {
            let mirror_lbn = (mirror_start - part.start) as u32;
            for (lbn, ft, start) in [
                (fe_lbn, super::read::FT_META_MAIN, main_lbn),
                (mfe_lbn, super::read::FT_META_MIRROR, mirror_lbn),
            ] {
                let mut ad = Vec::new();
                let mut off = 0u64;
                while off < m * bs {
                    let chunk = (m * bs - off)
                        .min(geo.max_ext / (META_ALLOC_UNIT * bs) * (META_ALLOC_UNIT * bs));
                    ad.extend_from_slice(&encode_ad(
                        &Ad {
                            kind: EXT_RECORDED,
                            len: chunk as u32,
                            lbn: start + (off / bs) as u32,
                            part: 0,
                        },
                        ICB_AD_SHORT,
                    ));
                    off += chunk;
                }
                let meta = FileMeta {
                    mode: 0,
                    ..FileMeta::default()
                };
                let fe = encode_fe(&FeArgs {
                    geo: &Geo {
                        meta_part: 0,
                        ..geo
                    },
                    lbn,
                    file_type: ft,
                    meta: &meta,
                    link_count: 1,
                    size: m * bs,
                    recorded_blocks: m,
                    unique_id: 0,
                    ad_type: ICB_AD_SHORT,
                    ea: &[],
                    ads: &ad,
                });
                writes.push((part.start + u64::from(lbn), fe));
            }
        }

        // ---- volume structures ----
        let nsr = opts.revision.nsr();
        let mut vrs = vec![0u8; 3 * 2048];
        for (k, id) in [
            &b"BEA01"[..],
            if nsr == 3 { b"NSR03" } else { b"NSR02" },
            b"TEA01",
        ]
        .iter()
        .enumerate()
        {
            vrs[k * 2048 + 1..k * 2048 + 6].copy_from_slice(id);
            vrs[k * 2048 + 6] = 1;
        }
        let mut raw = Vec::new();
        if bs <= 2048 {
            raw.push((placement.vrs_offset, vrs));
        } else {
            for k in 0..3 {
                let mut blk = vec![0u8; bs as usize];
                blk[..2048].copy_from_slice(&vrs[k * 2048..(k + 1) * 2048]);
                raw.push((placement.vrs_offset + k as u64 * bs, blk));
            }
        }
        let vrs_step = bs.max(2048);
        used.push(UsedRange {
            start: placement.vrs_offset / bs,
            len: (3 * vrs_step).div_ceil(bs),
            what: "volume recognition sequence",
        });

        // Partition maps.
        let mut maps = vec![1u8, 6, 1, 0, 0, 0];
        if let Some((fe_lbn, mfe_lbn, _, _)) = meta_file {
            let mut m = vec![0u8; 64];
            m[0] = 2;
            m[1] = 64;
            m[4..36].copy_from_slice(&entity_id("*UDF Metadata Partition", udf_suffix(rev)));
            put_u16(&mut m, 36, 1);
            put_u16(&mut m, 38, 0);
            put_u32(&mut m, 40, fe_lbn);
            put_u32(&mut m, 44, mfe_lbn);
            put_u32(&mut m, 48, u32::MAX);
            put_u32(&mut m, 52, META_ALLOC_UNIT as u32);
            put_u16(&mut m, 56, 1);
            m[58] = 1; // duplicate metadata
            maps.extend_from_slice(&m);
        }
        let n_maps = if meta_file.is_some() { 2u32 } else { 1 };

        let vol_set = opts.volume_set_id.clone().unwrap_or_else(|| {
            // UDF 2.2.2.5: the first 16 characters should be unique.
            let seed = u64::from(opts.recording_time) << 20 ^ crc_itu(lv_id.as_bytes()) as u64;
            format!("{seed:016X}")
        });
        let vds = |base: u64| -> Result<Vec<(u64, Vec<u8>)>> {
            let mut out = Vec::new();
            // PVD
            let mut pvd = vec![0u8; 512];
            put_u32(&mut pvd, 16, 1);
            put_u32(&mut pvd, 20, 0);
            pvd[24..56].copy_from_slice(&encode_dstring(&opts.volume_id, 32, "volume identifier")?);
            put_u16(&mut pvd, 56, 1);
            put_u16(&mut pvd, 58, 1);
            put_u16(&mut pvd, 60, 2);
            put_u16(&mut pvd, 62, 3);
            put_u32(&mut pvd, 64, 1);
            put_u32(&mut pvd, 68, 1);
            pvd[72..200].copy_from_slice(&encode_dstring(&vol_set, 128, "volume set identifier")?);
            pvd[200..264].copy_from_slice(&osta_charspec());
            pvd[264..328].copy_from_slice(&osta_charspec());
            pvd[344..376].copy_from_slice(&entity_id(&opts.application_id, [0; 8]));
            pvd[376..388].copy_from_slice(&ts);
            pvd[388..420].copy_from_slice(&fstool_impl_id());
            finish_tag(&mut pvd, TAG_PVD, geo.tag_ver, 1, base as u32, 496);
            out.push((base, pvd));
            // IUVD
            let mut iuvd = vec![0u8; 512];
            put_u32(&mut iuvd, 16, 2);
            iuvd[20..52].copy_from_slice(&entity_id("*UDF LV Info", udf_suffix(rev)));
            iuvd[52..116].copy_from_slice(&osta_charspec());
            iuvd[116..244].copy_from_slice(&encode_dstring(
                &lv_id,
                128,
                "logical volume identifier",
            )?);
            iuvd[352..384].copy_from_slice(&fstool_impl_id());
            finish_tag(&mut iuvd, TAG_IUVD, geo.tag_ver, 1, (base + 1) as u32, 496);
            out.push((base + 1, iuvd));
            // PD
            let mut pd = vec![0u8; 512];
            put_u32(&mut pd, 16, 3);
            put_u16(&mut pd, 20, 1);
            put_u16(&mut pd, 22, 0);
            pd[24..56].copy_from_slice(&entity_id(
                if nsr == 3 { "+NSR03" } else { "+NSR02" },
                [0; 8],
            ));
            if let Some(bl) = bitmap_lbn {
                // Partition Header Descriptor: unallocated space bitmap.
                let len = 24 + part.len.div_ceil(8);
                put_u32(&mut pd, 56 + 8, len as u32);
                put_u32(&mut pd, 56 + 12, bl);
            }
            put_u32(&mut pd, 184, opts.access.code());
            put_u32(&mut pd, 188, part.start as u32);
            put_u32(&mut pd, 192, part.len as u32);
            pd[196..228].copy_from_slice(&fstool_impl_id());
            finish_tag(&mut pd, TAG_PD, geo.tag_ver, 1, (base + 2) as u32, 496);
            out.push((base + 2, pd));
            // LVD
            let mut lvd = vec![0u8; 440 + maps.len()];
            put_u32(&mut lvd, 16, 4);
            lvd[20..84].copy_from_slice(&osta_charspec());
            lvd[84..212].copy_from_slice(&encode_dstring(
                &lv_id,
                128,
                "logical volume identifier",
            )?);
            put_u32(&mut lvd, 212, bs as u32);
            lvd[216..248].copy_from_slice(&entity_id("*OSTA UDF Compliant", domain_suffix(rev)));
            LongAd {
                len: bs as u32,
                kind: 0,
                loc: LbAddr {
                    lbn: fsd_lbn,
                    part: geo.meta_part,
                },
                imp: [0; 6],
            }
            .write(&mut lvd[248..264]);
            put_u32(&mut lvd, 264, maps.len() as u32);
            put_u32(&mut lvd, 268, n_maps);
            lvd[272..304].copy_from_slice(&fstool_impl_id());
            put_u32(&mut lvd, 432, (placement.integrity.len * bs) as u32);
            put_u32(&mut lvd, 436, placement.integrity.start as u32);
            lvd[440..].copy_from_slice(&maps);
            let l = lvd.len();
            finish_tag(&mut lvd, TAG_LVD, geo.tag_ver, 1, (base + 3) as u32, l - 16);
            out.push((base + 3, lvd));
            // USD
            let mut usd = vec![0u8; 24];
            put_u32(&mut usd, 16, 5);
            finish_tag(&mut usd, TAG_USD, geo.tag_ver, 1, (base + 4) as u32, 8);
            out.push((base + 4, usd));
            // TD
            let mut td = vec![0u8; 512];
            finish_tag(&mut td, TAG_TD, geo.tag_ver, 1, (base + 5) as u32, 496);
            out.push((base + 5, td));
            Ok(out)
        };
        for (r, what) in [
            (placement.main_vds, "main VDS"),
            (placement.reserve_vds, "reserve VDS"),
        ] {
            // Zero the whole extent first, then the descriptors over it.
            writes.push((r.start, vec![0u8; (r.len * bs) as usize]));
            writes.extend(vds(r.start)?);
            used.push(UsedRange {
                start: r.start,
                len: r.len,
                what,
            });
        }

        // LVID + TD.
        let n_parts = n_maps as usize;
        let l_iu = 46usize;
        let mut lvid = vec![0u8; 80 + 8 * n_parts + l_iu];
        lvid[16..28].copy_from_slice(&ts);
        put_u32(&mut lvid, 28, 1); // close
        let next_uid = planned
            .plans
            .iter()
            .map(|p| p.unique_id)
            .max()
            .unwrap_or(0)
            .max(15)
            + 1;
        put_u64(&mut lvid, 40, next_uid);
        put_u32(&mut lvid, 72, n_parts as u32);
        put_u32(&mut lvid, 76, l_iu as u32);
        // Free space and size tables.
        put_u32(&mut lvid, 80, free_blocks as u32);
        put_u32(&mut lvid, 80 + 4 * n_parts, part.len as u32);
        if let Some((_, _, _, m)) = meta_file {
            put_u32(&mut lvid, 84, (m - meta_used_end.min(m)) as u32);
            put_u32(&mut lvid, 84 + 4 * n_parts, m as u32);
        }
        let iu = 80 + 8 * n_parts;
        lvid[iu..iu + 32].copy_from_slice(&fstool_impl_id());
        put_u32(&mut lvid, iu + 32, n_files);
        put_u32(&mut lvid, iu + 36, n_dirs);
        put_u16(&mut lvid, iu + 40, rev);
        put_u16(&mut lvid, iu + 42, rev);
        put_u16(&mut lvid, iu + 44, rev);
        let l = lvid.len();
        let ib = placement.integrity.start;
        finish_tag(&mut lvid, TAG_LVID, geo.tag_ver, 1, ib as u32, l - 16);
        writes.push((ib, vec![0u8; (placement.integrity.len * bs) as usize]));
        writes.push((ib, lvid));
        let mut td = vec![0u8; 512];
        finish_tag(&mut td, TAG_TD, geo.tag_ver, 1, (ib + 1) as u32, 496);
        writes.push((ib + 1, td));
        used.push(UsedRange {
            start: ib,
            len: placement.integrity.len,
            what: "integrity sequence",
        });

        // Anchors.
        for &a in &placement.anchors {
            let mut avdp = vec![0u8; 512];
            put_u32(&mut avdp, 16, (placement.main_vds.len * bs) as u32);
            put_u32(&mut avdp, 20, placement.main_vds.start as u32);
            put_u32(&mut avdp, 24, (placement.reserve_vds.len * bs) as u32);
            put_u32(&mut avdp, 28, placement.reserve_vds.start as u32);
            finish_tag(&mut avdp, TAG_AVDP, geo.tag_ver, 1, a as u32, 496);
            writes.push((a, avdp));
            used.push(UsedRange {
                start: a,
                len: 1,
                what: "anchor",
            });
        }

        let stats = UdfStats {
            dirs: n_dirs,
            files: n_files,
            next_unique_id: next_uid,
            metadata_blocks: alloc.taken.iter().map(|r| r.len).sum(),
        };
        planned.plans.clear();
        Ok(UdfImage {
            bs: bs as u32,
            writes,
            raw,
            used,
            stats,
        })
    }

    /// Every region [`write`](Self::write) touches.
    pub fn used_ranges(&self) -> &[UsedRange] {
        &self.used
    }

    /// One past the highest block written.
    pub fn end_block(&self) -> u64 {
        self.used.iter().map(|r| r.start + r.len).max().unwrap_or(0)
    }

    /// What the build recorded.
    pub fn stats(&self) -> UdfStats {
        self.stats
    }

    /// Write every descriptor to `dev`. Blocks are zero-padded; nothing
    /// outside [`used_ranges`](Self::used_ranges) is written.
    pub fn write(&self, dev: &mut dyn BlockDevice) -> Result<()> {
        let bs = u64::from(self.bs);
        for (off, bytes) in &self.raw {
            dev.write_at(*off, bytes)?;
        }
        for (block, bytes) in &self.writes {
            let padded = round_up(bytes.len().max(1) as u64, bs) as usize;
            if padded == bytes.len() {
                dev.write_at(block * bs, bytes)?;
            } else {
                let mut b = bytes.clone();
                b.resize(padded, 0);
                dev.write_at(block * bs, &b)?;
            }
        }
        Ok(())
    }
}

fn check_placement(p: &UdfPlacement, bs: u64) -> Result<()> {
    let bad = |m: String| {
        Err(crate::Error::InvalidArgument(format!(
            "udf: placement: {m}"
        )))
    };
    if p.partition.len == 0 {
        return bad("empty partition".into());
    }
    if p.partition.end() > p.volume_blocks {
        return bad(format!(
            "partition ends at {} past the {}-block volume",
            p.partition.end(),
            p.volume_blocks
        ));
    }
    if p.partition.start > u64::from(u32::MAX) || p.partition.len > u64::from(u32::MAX) {
        return bad("partition beyond 32-bit block addressing".into());
    }
    if p.main_vds.len < 6 || p.reserve_vds.len < 6 {
        return bad("each volume descriptor sequence extent needs at least 6 blocks".into());
    }
    if p.integrity.len < 2 {
        return bad("the integrity sequence needs at least 2 blocks".into());
    }
    if !p.anchors.contains(&256) || p.anchors.len() < 2 {
        return bad("anchors must include block 256 and one more (N-256 or N-1)".into());
    }
    let mut fixed = vec![
        (p.main_vds, "main VDS"),
        (p.reserve_vds, "reserve VDS"),
        (p.integrity, "integrity sequence"),
        (
            BlockRange::new(p.vrs_offset / bs, (3 * bs.max(2048)).div_ceil(bs)),
            "recognition sequence",
        ),
    ];
    for &a in &p.anchors {
        if a >= p.volume_blocks {
            return bad(format!("anchor {a} beyond the volume"));
        }
        fixed.push((BlockRange::new(a, 1), "anchor"));
    }
    if p.vrs_offset < 32768 || !p.vrs_offset.is_multiple_of(2048) {
        return bad(
            "the recognition sequence must start at or after byte 32768, 2048-aligned".into(),
        );
    }
    for (i, (a, an)) in fixed.iter().enumerate() {
        if a.overlaps(&p.partition) {
            return bad(format!("{an} overlaps the partition"));
        }
        for (b, bn) in &fixed[i + 1..] {
            if a.overlaps(b) {
                return bad(format!("{an} overlaps {bn}"));
            }
        }
    }
    let mut free = p.free.clone();
    free.sort();
    for w in free.windows(2) {
        if w[0].overlaps(&w[1]) {
            return bad("free ranges overlap".into());
        }
    }
    Ok(())
}

fn fid(
    chars: u8,
    name: &[u8],
    icb: LbAddr,
    unique_id: u64,
    bs: u64,
    tag_ver: u16,
    loc: u32,
) -> Vec<u8> {
    let total = fid_len(name.len());
    let mut f = vec![0u8; total];
    put_u16(&mut f, 16, 1);
    f[18] = chars;
    f[19] = name.len() as u8;
    let mut imp = [0u8; 6];
    imp[2..6].copy_from_slice(&(unique_id as u32).to_le_bytes());
    LongAd {
        len: bs as u32,
        kind: 0,
        loc: icb,
        imp,
    }
    .write(&mut f[20..36]);
    put_u16(&mut f, 36, 0);
    f[38..38 + name.len()].copy_from_slice(name);
    finish_tag(&mut f, TAG_FID, tag_ver, 1, loc, total - 16);
    f
}

fn encode_ad(a: &Ad, ad_type: u16) -> Vec<u8> {
    let raw = (a.len & 0x3FFF_FFFF) | (u32::from(a.kind) << 30);
    if ad_type == ICB_AD_LONG {
        let mut b = vec![0u8; 16];
        LongAd {
            len: a.len,
            kind: a.kind,
            loc: LbAddr {
                lbn: a.lbn,
                part: a.part,
            },
            imp: [0; 6],
        }
        .write(&mut b);
        b
    } else {
        let mut b = vec![0u8; 8];
        put_u32(&mut b, 0, raw);
        put_u32(&mut b, 4, a.lbn);
        b
    }
}

struct FeArgs<'a> {
    geo: &'a Geo,
    lbn: u32,
    file_type: u8,
    meta: &'a FileMeta,
    link_count: u16,
    size: u64,
    recorded_blocks: u64,
    unique_id: u64,
    ad_type: u16,
    ea: &'a [u8],
    ads: &'a [u8],
}

/// UDF permission word for POSIX mode bits: other in bits 0–4, group in
/// 5–9, owner in 10–14 (execute, write, read, change-attribute, delete).
/// The owner also gets change-attribute and delete, as mkudffs does.
pub(crate) fn udf_perms(mode: u16) -> u32 {
    let m = u32::from(mode);
    let mut p = (m & 7) | (((m >> 3) & 7) << 5) | (((m >> 6) & 7) << 10);
    p |= (8 | 16) << 10;
    p
}

fn encode_fe(a: &FeArgs<'_>) -> Vec<u8> {
    let g = a.geo;
    let base = g.fe_base;
    let mut b = vec![0u8; base + a.ea.len() + a.ads.len()];
    // ICB tag.
    put_u16(&mut b, 20, 4);
    put_u16(&mut b, 24, 1);
    b[27] = a.file_type;
    let mut flags = a.ad_type;
    if a.meta.mode & 0o4000 != 0 {
        flags |= 1 << 6;
    }
    if a.meta.mode & 0o2000 != 0 {
        flags |= 1 << 7;
    }
    if a.meta.mode & 0o1000 != 0 {
        flags |= 1 << 8;
    }
    put_u16(&mut b, 34, flags);
    put_u32(&mut b, 36, a.meta.uid);
    put_u32(&mut b, 40, a.meta.gid);
    put_u32(&mut b, 44, udf_perms(a.meta.mode));
    put_u16(&mut b, 48, a.link_count);
    put_u64(&mut b, 56, a.size);
    let at = encode_timestamp(i64::from(a.meta.atime));
    let mt = encode_timestamp(i64::from(a.meta.mtime));
    let ct = encode_timestamp(i64::from(a.meta.ctime));
    let (l_ea_off, uid_off, impl_off) = if g.efe {
        put_u64(&mut b, 64, a.size);
        put_u64(&mut b, 72, a.recorded_blocks);
        b[80..92].copy_from_slice(&at);
        b[92..104].copy_from_slice(&mt);
        b[104..116].copy_from_slice(&mt);
        b[116..128].copy_from_slice(&ct);
        put_u32(&mut b, 128, 1);
        (208, 200, 168)
    } else {
        put_u64(&mut b, 64, a.recorded_blocks);
        b[72..84].copy_from_slice(&at);
        b[84..96].copy_from_slice(&mt);
        b[96..108].copy_from_slice(&ct);
        put_u32(&mut b, 108, 1);
        (168, 160, 128)
    };
    b[impl_off..impl_off + 32].copy_from_slice(&fstool_impl_id());
    put_u64(&mut b, uid_off, a.unique_id);
    put_u32(&mut b, l_ea_off, a.ea.len() as u32);
    put_u32(&mut b, l_ea_off + 4, a.ads.len() as u32);
    b[base..base + a.ea.len()].copy_from_slice(a.ea);
    b[base + a.ea.len()..].copy_from_slice(a.ads);
    let l = b.len();
    finish_tag(
        &mut b,
        if g.efe { TAG_EFE } else { TAG_FE },
        g.tag_ver,
        1,
        a.lbn,
        l - 16,
    );
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ad_layout_counts() {
        // 2048-byte block, short ADs, 1872 bytes of room in an FE.
        assert_eq!(ad_layout(10, 8, 1872, 2048), (10, 0));
        let cap = 1872 / 8;
        assert_eq!(ad_layout(cap, 8, 1872, 2048), (cap, 0));
        let (slots, aeds) = ad_layout(cap + 1, 8, 1872, 2048);
        assert_eq!(slots, cap - 1);
        assert_eq!(aeds, 1);
        let aed_cap = (2048 - 24) / 8;
        let (_, aeds) = ad_layout(cap - 1 + aed_cap + 1, 8, 1872, 2048);
        assert_eq!(aeds, 2);
    }

    #[test]
    fn tree_hardlinks_and_remove() {
        let mut t = UdfTree::new();
        t.add_file("/a/b", FileData::empty(), FileMeta::default())
            .unwrap();
        t.add_hardlink("/c", "/a/b").unwrap();
        assert_eq!(t.link_count("/c"), Some(2));
        t.remove("/a").unwrap();
        assert_eq!(t.link_count("/c"), Some(1));
        assert!(t.entry("/a/b").is_none());
        assert!(t.add_hardlink("/d", "/").is_err());
    }

    #[test]
    fn symlink_encoding_round_trips() {
        for t in ["/usr/bin/env", "../x/y", "./a", "rel"] {
            let enc = encode_symlink(t).unwrap();
            let dec = super::super::read::decode_symlink(&enc).unwrap();
            assert_eq!(dec, t);
        }
    }
}
