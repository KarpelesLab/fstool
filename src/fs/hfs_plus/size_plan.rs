//! Content-fit size plan for HFS+ — and the capacity reservation for
//! decorated volumes.
//!
//! Phase 1 models the catalog B-tree the writer builds: every entry contributes
//! a catalog record (folder 88 B / file 248 B body, plus a `8 + 2·name` key) and
//! a thread record (`8` key, `10 + 2·name` body). Records pack into
//! `node_size`-byte leaves (usable = `node_size − 14 − 2`, each record costing
//! `key + body + 2`); index nodes sit above. Files contribute data
//! (allocation) blocks; symlinks a data block for the target. Phase 2
//! (`total_size`) folds in the extents B-tree, the attributes B-tree, the
//! size-dependent allocation bitmap (resolved by a short fixed point), the
//! journal when enabled, and the boot/volume-header blocks.
//!
//! A safe upper bound: the leaf count uses a conservative fill so greedy
//! packing never overflows the computed size (validated `fsck.hfsplus`-clean).
//!
//! ## Reserving capacity for a decorated volume
//!
//! A volume that carries Finder metadata needs room for more than file
//! data: resource forks, the attributes B-tree that holds xattrs (and the
//! extents of large xattr values), catalog growth for every entry — and,
//! when some files are only generated *after* the tree is laid down (a
//! `.DS_Store` that embeds aliases to entries whose CNIDs are known only
//! then), room for those too. The recipe:
//!
//! ```no_run
//! # fn main() -> fstool::Result<()> {
//! use fstool::fs::FsSizePlan;
//! use fstool::fs::hfs_plus::FormatOpts;
//! use fstool::fs::hfs_plus::size_plan::{GeneratedBudget, HfsPlusSizePlan};
//!
//! let mut opts = FormatOpts::default();
//! let mut plan = HfsPlusSizePlan::new(&opts);
//! // 1. The imported tree, entry by entry …
//! plan.add_dir("/App.app");
//! plan.add_file("/App.app/Info.plist", 1_234);
//! plan.add_resource_fork(512);                  // … its resource forks …
//! plan.add_xattr("com.apple.quarantine", 57);   // … and xattrs.
//! // 2. What will be generated after the identities are known.
//! let mut later = GeneratedBudget::default();
//! later.files = 2;               // .DS_Store, .VolumeIcon.icns
//! later.data_bytes = 1 << 20;    // their combined size
//! plan.add_budget(&later);
//! // 3. Pre-size the metadata trees and pick the volume size.
//! plan.apply_to(&mut opts);
//! let bytes = plan.total_size();
//! # let _ = bytes; Ok(()) }
//! ```
//!
//! [`HfsPlusSizePlan::apply_to`] writes the computed catalog and
//! attributes node counts into the [`FormatOpts`], so `format` reserves
//! them up front and nothing has to be carved out of free space later;
//! [`total_size`](crate::fs::FsSizePlan::total_size) then covers metadata
//! *and* data. Names count at their HFS+-normalised length.
//!
//! Generic sizing (`fstool create` / `repack` onto HFS+) drives the same
//! accounting through [`FsSizePlan::add_entry_xattr`](crate::fs::FsSizePlan::add_entry_xattr):
//! every source xattr — a resource fork arrives as `com.apple.ResourceFork`
//! — is charged exactly as [`HfsPlusSizePlan::add_xattr`] charges it.

use super::writer::{DEFAULT_JOURNAL_BUFFER_BLOCKS, FormatOpts, attr_node_size_for};

/// Blocks a B-tree fork of `nodes` nodes occupies (matches the writer's
/// `blocks_for_nodes`).
fn blocks_for_nodes(nodes: u64, node_size: u64, block_size: u64) -> u64 {
    (nodes * node_size).div_ceil(block_size)
}

/// B-tree node descriptor (14) + the trailing free-space offset (2).
const NODE_OVERHEAD: u64 = 16;
/// Folder / file catalog record bodies.
const FOLDER_BODY: u64 = 88;
const FILE_BODY: u64 = 248;
/// Longest catalog name, in UTF-16 units.
const MAX_NAME_UNITS: u64 = 255;
/// Longest attribute name, in UTF-16 units.
const MAX_ATTR_NAME_UNITS: u64 = 127;

/// Things a caller will add to the volume *after* planning — typically
/// files generated once the tree's CNIDs are known (`.DS_Store`,
/// `.VolumeIcon.icns`, `.background/…`). Every count is charged at its
/// worst case (255-unit names, a block of rounding per fork, …), so the
/// budget is safe without knowing the exact names.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct GeneratedBudget {
    /// Regular files (and symlinks) to be created later.
    pub files: u64,
    /// Folders to be created later.
    pub dirs: u64,
    /// Combined data-fork bytes of those files.
    pub data_bytes: u64,
    /// Resource forks to be written later.
    pub resource_forks: u64,
    /// Combined resource-fork bytes.
    pub resource_fork_bytes: u64,
    /// Extended attributes (outside Finder info) to be set later.
    pub xattrs: u64,
    /// Combined value bytes of those attributes.
    pub xattr_bytes: u64,
}

/// Exact-ish (safe upper bound) HFS+ size accumulator.
pub struct HfsPlusSizePlan {
    block_size: u64,
    node_size: u64,
    attr_node_size: u64,
    journaled: bool,
    extents_nodes: u64,
    catalog_nodes_min: u64,
    attributes_nodes_min: u64,
    /// Σ over records of `record_len + 2` (the catalog B-tree leaf payload).
    catalog_bytes: u64,
    /// Allocation blocks for file data + symlink targets + resource forks
    /// + extent-based xattr values.
    data_blocks: u64,
    /// Σ over attribute records of `record_len + 2`.
    attr_bytes: u64,
    /// Number of attribute records (to bound index fan-out).
    attr_records: u64,
}

impl HfsPlusSizePlan {
    #[must_use]
    pub fn new(opts: &FormatOpts) -> Self {
        let mut p = Self {
            block_size: u64::from(opts.block_size),
            node_size: u64::from(opts.node_size),
            attr_node_size: u64::from(attr_node_size_for(opts.node_size)),
            journaled: opts.journaled,
            extents_nodes: u64::from(opts.extents_nodes),
            catalog_nodes_min: u64::from(opts.catalog_nodes),
            attributes_nodes_min: u64::from(opts.attributes_nodes),
            catalog_bytes: 0,
            data_blocks: 0,
            attr_bytes: 0,
            attr_records: 0,
        };
        // The root folder: its folder record + thread record. The volume
        // name is the root's catalog name.
        p.add_catalog_entry(Self::name_units(&opts.volume_name), FOLDER_BODY);
        p
    }

    /// Account for one entry's two catalog records, given its name length (in
    /// UTF-16 code units) and record body size.
    fn add_catalog_entry(&mut self, name_units: u64, body: u64) {
        let name_bytes = 2 * name_units;
        // Catalog record: key (2 keyLength + 4 parentID + 2 nameLength + name)
        // + body, then +2 for the node offset slot.
        let cat = (8 + name_bytes) + body + 2;
        // Thread record: 8-byte key (empty name) + body (10 + name) + 2.
        let thread = 8 + (10 + name_bytes) + 2;
        self.catalog_bytes += cat + thread;
    }

    /// UTF-16 length of `name` as HFS+ stores it (normalised, so a
    /// precomposed `é` counts two units).
    fn name_units(name: &str) -> u64 {
        super::unicode::normalize_name(name).encode_utf16().count() as u64
    }

    fn data_blocks_for(&self, len: u64) -> u64 {
        if len == 0 {
            0
        } else {
            len.div_ceil(self.block_size)
        }
    }

    /// Account for a resource fork of `len` bytes (on a file added with
    /// [`add_file`](crate::fs::FsSizePlan::add_file)).
    pub fn add_resource_fork(&mut self, len: u64) {
        self.data_blocks += self.data_blocks_for(len);
    }

    /// Account for an extended attribute `name` holding `len` bytes.
    /// `com.apple.FinderInfo` is free (it lives in the catalog record) and
    /// `com.apple.ResourceFork` is charged as a resource fork; anything
    /// else costs an attributes-B-tree record, plus its own blocks when
    /// the value is too big to be stored inline.
    pub fn add_xattr(&mut self, name: &str, len: u64) {
        match name {
            super::meta::XATTR_FINDER_INFO => {}
            super::meta::XATTR_RESOURCE_FORK => self.add_resource_fork(len),
            _ => self.add_attr_record(name.encode_utf16().count() as u64, len),
        }
    }

    fn add_attr_record(&mut self, name_units: u64, len: u64) {
        let key = 14 + 2 * name_units;
        let max_inline = super::attributes::max_inline_attr_size(self.attr_node_size as u32) as u64;
        if len <= max_inline {
            let body = 16 + len + (len & 1);
            self.attr_bytes += key + body + 2;
            self.attr_records += 1;
        } else {
            let blocks = self.data_blocks_for(len);
            self.data_blocks += blocks;
            // Fork record (88 B body); one extents record (72 B body) per
            // further eight runs. A fresh volume allocates contiguously, so
            // one run is the norm — charge one extents record anyway.
            self.attr_bytes += (key + 88 + 2) + (key + 72 + 2);
            self.attr_records += 2;
        }
    }

    /// Reserve room for entries and bytes that will only be added after
    /// planning; see [`GeneratedBudget`].
    pub fn add_budget(&mut self, b: &GeneratedBudget) {
        for _ in 0..b.dirs {
            self.add_catalog_entry(MAX_NAME_UNITS, FOLDER_BODY);
        }
        for _ in 0..b.files {
            self.add_catalog_entry(MAX_NAME_UNITS, FILE_BODY);
        }
        // Each fork rounds up to a block: one block of slack per fork.
        self.data_blocks += self.data_blocks_for(b.data_bytes) + b.files;
        self.data_blocks += self.data_blocks_for(b.resource_fork_bytes) + b.resource_forks;
        if b.xattrs > 0 {
            // Charge every attribute as if it might go out of line, and the
            // bytes as if they all sat inline — whichever way each lands,
            // this covers it.
            let per_record = (14 + 2 * MAX_ATTR_NAME_UNITS) * 2 + 88 + 72 + 4;
            self.attr_bytes += b.xattrs * per_record + b.xattr_bytes + b.xattrs;
            self.attr_records += 2 * b.xattrs;
            self.data_blocks += self.data_blocks_for(b.xattr_bytes) + b.xattrs;
        }
    }

    /// Catalog B-tree node count (leaves + a header + index nodes), from the
    /// accumulated leaf payload. Uses a conservative leaf fill so greedy
    /// packing of variable-size records never overflows.
    fn catalog_nodes(&self) -> u64 {
        // Reserve a record's-worth of slack per node for boundary waste.
        let usable = (self.node_size - NODE_OVERHEAD).saturating_sub(768);
        let leaves = self.catalog_bytes.div_ceil(usable).max(1);
        // Index level(s): each index record ~ (key + 4 ptr + 2); fan-out is
        // large, so one index node covers hundreds of leaves. Add a couple of
        // levels' worth of headroom.
        let index = leaves.div_ceil(200).max(1) + 1;
        // + 1 header node, + 1 map node.
        leaves + index + 2
    }

    /// Attributes B-tree node count, `0` when no attribute is planned.
    /// Records can be up to half a node, so greedy packing keeps every
    /// leaf at least half full: `2 · bytes / usable + 1` leaves bound it.
    fn attributes_nodes(&self) -> u64 {
        if self.attr_records == 0 {
            return self.attributes_nodes_min;
        }
        let usable = self.attr_node_size - NODE_OVERHEAD;
        let leaves = (2 * self.attr_bytes).div_ceil(usable) + 1;
        // Index records carry a full key (≤ 270 B) + pointer: ~15 per
        // 4 KiB node at worst.
        let per_index = (usable / (2 * 276)).max(2);
        let mut index = 0;
        let mut level = leaves;
        while level > 1 {
            level = level.div_ceil(per_index);
            index += level;
        }
        (leaves + index + 1).max(self.attributes_nodes_min)
    }

    /// Write the planned catalog and attributes node counts into `opts`
    /// (never shrinking what is already there), so `format` reserves the
    /// metadata trees up front — contiguous, next to the other special
    /// files, and part of the budget rather than carved out of free space
    /// at flush time.
    pub fn apply_to(&mut self, opts: &mut FormatOpts) {
        let cat = u32::try_from(self.catalog_nodes()).unwrap_or(u32::MAX);
        opts.catalog_nodes = opts.catalog_nodes.max(cat);
        let attr = u32::try_from(self.attributes_nodes()).unwrap_or(u32::MAX);
        opts.attributes_nodes = opts.attributes_nodes.max(attr);
        // The plan now describes the reserved layout: no lazy-creation slack.
        self.catalog_nodes_min = u64::from(opts.catalog_nodes);
        self.attributes_nodes_min = u64::from(opts.attributes_nodes);
    }

    fn bitmap_blocks(&self, total_blocks: u64) -> u64 {
        total_blocks.div_ceil(8).div_ceil(self.block_size)
    }
}

impl crate::fs::FsSizePlan for HfsPlusSizePlan {
    fn add_dir(&mut self, path: &str) {
        let name = path.rsplit('/').next().unwrap_or("");
        self.add_catalog_entry(Self::name_units(name), FOLDER_BODY);
    }
    fn add_file(&mut self, path: &str, len: u64) {
        let name = path.rsplit('/').next().unwrap_or("");
        self.add_catalog_entry(Self::name_units(name), FILE_BODY);
        self.data_blocks += self.data_blocks_for(len);
    }
    fn add_symlink(&mut self, path: &str, target: &str) {
        let name = path.rsplit('/').next().unwrap_or("");
        self.add_catalog_entry(Self::name_units(name), FILE_BODY);
        // Symlink target lives in a data fork.
        self.data_blocks += self.data_blocks_for(target.len() as u64).max(1);
    }
    fn add_device(&mut self, path: &str) {
        let name = path.rsplit('/').next().unwrap_or("");
        self.add_catalog_entry(Self::name_units(name), FILE_BODY);
    }
    /// Generic repack / `create` sizing reaches [`Self::add_xattr`] through
    /// this hook, so resource forks and attributes-B-tree records of the
    /// source tree are budgeted without HFS+-specific calls.
    fn add_entry_xattr(&mut self, _path: &str, name: &str, len: u64) {
        self.add_xattr(name, len);
    }

    fn total_size(&self) -> u64 {
        let cat_nodes = self.catalog_nodes().max(self.catalog_nodes_min);
        let catalog_blocks = blocks_for_nodes(cat_nodes, self.node_size, self.block_size);
        let extents_blocks = blocks_for_nodes(self.extents_nodes, self.node_size, self.block_size);
        let attr_nodes = self.attributes_nodes();
        let attr_blocks = blocks_for_nodes(attr_nodes, self.attr_node_size, self.block_size);
        // Created lazily (no format-time reservation), the attributes
        // fork is rounded up to the B-tree clump size — ≤ 1 MiB.
        let attr_lazy_slack = if self.attr_records > 0 && self.attributes_nodes_min == 0 {
            (1024 * 1024u64).div_ceil(self.block_size)
        } else {
            0
        };

        // Journal: info block + buffer sized from the metadata it must cover.
        let journal_blocks = if self.journaled {
            let meta = catalog_blocks + extents_blocks + attr_blocks + 16;
            1 + u64::from(DEFAULT_JOURNAL_BUFFER_BLOCKS).max(meta)
        } else {
            0
        };

        // Fixed: block 0 (boot/VH) + alternate volume header block.
        let fixed = 2u64;
        // Size-independent metadata + data.
        let core = fixed
            + catalog_blocks
            + extents_blocks
            + attr_blocks
            + attr_lazy_slack
            + journal_blocks
            + self.data_blocks;

        // Resolve the allocation-bitmap fixed point (its size depends on the
        // total block count).
        let mut total_blocks = core + self.bitmap_blocks(core + 1);
        for _ in 0..8 {
            let next = core + self.bitmap_blocks(total_blocks);
            if next <= total_blocks {
                break;
            }
            total_blocks = next;
        }
        total_blocks * self.block_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::FsSizePlan;

    #[test]
    fn empty_volume_is_small() {
        let p = HfsPlusSizePlan::new(&FormatOpts::default());
        // Dominated by the 32-node catalog floor + 4-node extents; a few MiB.
        let mib = p.total_size() / (1024 * 1024);
        assert!(mib < 8, "empty HFS+ should be a few MiB, got {mib}");
    }

    #[test]
    fn files_add_data_blocks() {
        let mut p = HfsPlusSizePlan::new(&FormatOpts::default());
        let before = p.data_blocks;
        p.add_file("/big", 1_000_000);
        assert_eq!(p.data_blocks - before, 1_000_000u64.div_ceil(4096));
    }

    #[test]
    fn many_entries_grow_catalog() {
        let mut p = HfsPlusSizePlan::new(&FormatOpts::default());
        let base = p.catalog_nodes();
        for i in 0..5000 {
            p.add_file(&format!("/file_{i:05}.txt"), 0);
        }
        assert!(p.catalog_nodes() > base);
    }

    #[test]
    fn generic_hook_charges_xattrs_and_forks() {
        let opts = FormatOpts::default();
        let mut p: Box<dyn FsSizePlan> = Box::new(HfsPlusSizePlan::new(&opts));
        p.add_file("/a", 10);
        let base = p.total_size();
        p.add_entry_xattr("/a", "com.apple.FinderInfo", 32);
        assert_eq!(p.total_size(), base);
        p.add_entry_xattr("/a", "com.apple.ResourceFork", 40_000);
        assert!(p.total_size() >= base + 40_000);
        let before = p.total_size();
        p.add_entry_xattr("/a", "user.big", 200_000);
        assert!(p.total_size() >= before + 200_000);
    }

    #[test]
    fn metadata_is_charged() {
        let opts = FormatOpts::default();
        let base = HfsPlusSizePlan::new(&opts).total_size();
        let mut p = HfsPlusSizePlan::new(&opts);
        p.add_xattr("com.apple.FinderInfo", 32);
        assert_eq!(p.total_size(), base, "Finder info lives in the catalog");
        p.add_resource_fork(10_000);
        assert!(p.total_size() >= base + 3 * 4096);
        let before = p.total_size();
        p.add_xattr("user.big", 100_000);
        assert!(p.total_size() >= before + 100_000);
        let mut o = opts.clone();
        p.apply_to(&mut o);
        assert!(o.attributes_nodes > 0);
        let b = GeneratedBudget {
            files: 1,
            data_bytes: 50_000,
            ..GeneratedBudget::default()
        };
        let before = p.total_size();
        p.add_budget(&b);
        assert!(p.total_size() >= before + 50_000);
    }
}
