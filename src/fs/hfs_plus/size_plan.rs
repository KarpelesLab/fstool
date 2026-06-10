//! Content-fit size plan for HFS+.
//!
//! Phase 1 models the catalog B-tree the writer builds: every entry contributes
//! a catalog record (folder 88 B / file 248 B body, plus a `8 + 2·name` key) and
//! a thread record (`8` key, `10 + 2·name` body). Records pack into
//! `node_size`-byte leaves (usable = `node_size − 14 − 2`, each record costing
//! `key + body + 2`); index nodes sit above. Files contribute data
//! (allocation) blocks; symlinks a data block for the target. Phase 2
//! ([`total_size`]) folds in the extents B-tree, the size-dependent allocation
//! bitmap (resolved by a short fixed point), the journal when enabled, and the
//! boot/volume-header blocks.
//!
//! A safe upper bound: the leaf count uses a conservative fill so greedy
//! packing never overflows the computed size (validated `fsck.hfsplus`-clean).
//!
//! [`total_size`]: HfsPlusSizePlan::total_size

use super::writer::{DEFAULT_JOURNAL_BUFFER_BLOCKS, FormatOpts};

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

/// Exact-ish (safe upper bound) HFS+ size accumulator.
pub struct HfsPlusSizePlan {
    block_size: u64,
    node_size: u64,
    journaled: bool,
    extents_nodes: u64,
    catalog_nodes_min: u64,
    /// Σ over records of `record_len + 2` (the catalog B-tree leaf payload).
    catalog_bytes: u64,
    /// Allocation blocks for file data + symlink targets.
    data_blocks: u64,
}

impl HfsPlusSizePlan {
    #[must_use]
    pub fn new(opts: &FormatOpts) -> Self {
        let mut p = Self {
            block_size: u64::from(opts.block_size),
            node_size: u64::from(opts.node_size),
            journaled: opts.journaled,
            extents_nodes: u64::from(opts.extents_nodes),
            catalog_nodes_min: u64::from(opts.catalog_nodes),
            catalog_bytes: 0,
            data_blocks: 0,
        };
        // The root folder: its folder record + thread record.
        p.add_catalog_entry(0, FOLDER_BODY);
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

    fn name_units(name: &str) -> u64 {
        name.encode_utf16().count() as u64
    }

    fn data_blocks_for(&self, len: u64) -> u64 {
        if len == 0 {
            0
        } else {
            len.div_ceil(self.block_size)
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

    fn total_size(&self) -> u64 {
        let cat_nodes = self.catalog_nodes().max(self.catalog_nodes_min);
        let catalog_blocks = blocks_for_nodes(cat_nodes, self.node_size, self.block_size);
        let extents_blocks = blocks_for_nodes(self.extents_nodes, self.node_size, self.block_size);

        // Journal: info block + buffer sized from the metadata it must cover.
        let journal_blocks = if self.journaled {
            let meta = catalog_blocks + extents_blocks + 16;
            1 + u64::from(DEFAULT_JOURNAL_BUFFER_BLOCKS).max(meta)
        } else {
            0
        };

        // Fixed: block 0 (boot/VH) + alternate volume header block.
        let fixed = 2u64;
        // Size-independent metadata + data.
        let core = fixed + catalog_blocks + extents_blocks + journal_blocks + self.data_blocks;

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
}
