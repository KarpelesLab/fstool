//! Content-fit size plan for classic **HFS**.
//!
//! Phase 1 models the catalog B-tree the writer builds. Every entry contributes
//! a catalog record — a directory a `dir` record (70-byte body) **and** a
//! thread record (the writer keys threads only for directories); a file a `file`
//! record (102-byte body). Each record's key is `round_up_even(7 + name)` bytes
//! (1 keyLen + 1 reserved + 4 parentID + 1 nameLen + name, padded even), and the
//! whole record is padded even. Records pack into 512-byte B-tree nodes
//! (`DESC` 14-byte descriptor + records + a 2-byte offset per record and one
//! trailing free offset). Files (and symlink targets) contribute data
//! (allocation) blocks at the volume's block size.
//!
//! Phase 2 ([`total_size`]) folds in the extents-overflow B-tree (an empty
//! header node for a tight, contiguous build), the size-dependent volume bitmap,
//! and the fixed overhead (2 boot sectors + the MDB + the alternate MDB +
//! spare). Classic HFS uses 16-bit allocation-block addressing, so the writer
//! scales the block size up to keep the block count bounded; the plan resolves
//! that block size with the same `auto_block_size` rule via a short fixed point.
//!
//! A safe upper bound: the leaf count reserves a max-record's slack per node so
//! greedy packing of variable-size records never overflows the computed size
//! (validated `fsck.hfs`/round-trip-clean).
//!
//! [`total_size`]: HfsClassicSizePlan::total_size

use super::writer::HfsFormatOpts;
use crate::fs::FsSizePlan;

/// B-tree node size (`writer::NODE`).
const NODE: u64 = 512;
/// B-tree node descriptor length (`writer::DESC`).
const DESC: u64 = 14;
/// Directory catalog-record body (`encode_dir`).
const DIR_BODY: u64 = 70;
/// File catalog-record body (`encode_file`).
const FILE_BODY: u64 = 102;
/// Directory-thread catalog-record body (`encode_thread`, fixed 46 bytes).
const THREAD_BODY: u64 = 46;
/// Catalog index key length (`build_btree`'s `key_len_max` for the catalog).
const CAT_KEY_LEN_MAX: u64 = 37;
/// 512-byte bitmap sector holds this many allocation-block bits.
const BITS_PER_VBM_SECTOR: u64 = 4096;

/// `round_up_even(n)`.
fn round_up_even(n: u64) -> u64 {
    n + (n & 1)
}

/// Bytes a leaf record occupies *including* its 2-byte node-offset slot, for a
/// catalog entry with `name_len` name bytes and a `body`-byte record body.
fn record_cost(name_len: u64, body: u64) -> u64 {
    // Key: round_up_even(1 keyLen + (1 reserved + 4 parentID + 1 nameLen) + name)
    // = round_up_even(7 + name). Body appended, whole record padded even.
    let key = round_up_even(7 + name_len);
    round_up_even(key + body) + 2
}

/// Smallest 512-multiple block size keeping the volume's block count bounded —
/// mirrors `writer::auto_block_size`.
fn auto_block_size(total_sectors: u64) -> u64 {
    let mut bs = 512u64;
    while total_sectors / (bs / 512) > 60_000 {
        bs += 512;
    }
    bs
}

/// Exact-ish (safe upper bound) classic-HFS size accumulator.
pub struct HfsClassicSizePlan {
    /// Σ over catalog records of `record_len + 2` (the leaf payload).
    catalog_bytes: u64,
    /// File / symlink-target fork lengths (each rounds up to whole blocks at the
    /// resolved block size).
    file_lens: Vec<u64>,
}

impl HfsClassicSizePlan {
    #[must_use]
    pub fn new(_opts: &HfsFormatOpts) -> Self {
        let mut p = Self {
            catalog_bytes: 0,
            file_lens: Vec::new(),
        };
        // The root directory: its dir record + thread record (the writer seeds
        // these at format time).
        p.add_dir_records(0);
        p
    }

    /// Name length the on-disk key uses: MacRoman bytes, capped at the 31-byte
    /// HFS maximum (UTF-8 length is a safe upper bound for MacRoman length).
    fn key_name_len(name: &str) -> u64 {
        (name.chars().count() as u64).min(31)
    }

    fn leaf_name_of(path: &str) -> u64 {
        Self::key_name_len(path.rsplit('/').next().unwrap_or(""))
    }

    /// A directory's two catalog records (dir record + dir thread).
    fn add_dir_records(&mut self, name_len: u64) {
        self.catalog_bytes += record_cost(name_len, DIR_BODY);
        // The thread record is keyed by the dir's own CNID with an empty name.
        self.catalog_bytes += record_cost(0, THREAD_BODY);
    }

    /// A file's single catalog record.
    fn add_file_record(&mut self, name_len: u64) {
        self.catalog_bytes += record_cost(name_len, FILE_BODY);
    }

    /// Catalog B-tree node count: 1 header + leaves + index nodes.
    fn catalog_nodes(&self) -> u64 {
        // Per-node record budget = NODE − DESC − 2 (one trailing free offset).
        // Reserve a max-record's worth (key 38 + body 102, padded, + 2 ≈ 144)
        // so greedy packing of variable-size records never overflows a node.
        const MAX_RECORD: u64 = 144;
        let usable = NODE - DESC - 2 - MAX_RECORD;
        let leaves = self.catalog_bytes.div_ceil(usable).max(1);
        // Index levels: each index record is 1 + key_len_max + 4 ptr (padded
        // even) + 2 offset ≈ 44 bytes → ~11 per node; use fan-out 10.
        let _ = CAT_KEY_LEN_MAX;
        let mut index = 0u64;
        let mut level = leaves;
        while level > 1 {
            level = level.div_ceil(10);
            index += level;
        }
        1 + leaves + index
    }

    /// Data (allocation) blocks the file/symlink forks need at block size `bs`.
    fn data_blocks(&self, bs: u64) -> u64 {
        self.file_lens.iter().map(|&l| l.div_ceil(bs)).sum()
    }

    /// Total content allocation blocks at block size `bs` (catalog + the empty
    /// extents-overflow header node + data).
    fn content_blocks(&self, bs: u64) -> u64 {
        let cat_blocks = (self.catalog_nodes() * NODE).div_ceil(bs);
        let ext_blocks = NODE.div_ceil(bs); // empty extents tree = 1 header node
        cat_blocks + ext_blocks + self.data_blocks(bs)
    }

    /// Total sectors for a tight volume at block size `bs`.
    fn sectors_at(&self, bs: u64) -> u64 {
        let spab = bs / 512;
        let blocks = self.content_blocks(bs);
        let vbm = blocks.div_ceil(BITS_PER_VBM_SECTOR);
        // boot(2) + MDB(1) + VBM + blocks·spab + alt-MDB + spare(2).
        5 + vbm + blocks * spab
    }
}

impl FsSizePlan for HfsClassicSizePlan {
    fn add_dir(&mut self, path: &str) {
        self.add_dir_records(Self::leaf_name_of(path));
    }

    fn add_file(&mut self, path: &str, len: u64) {
        self.add_file_record(Self::leaf_name_of(path));
        self.file_lens.push(len);
    }

    fn add_symlink(&mut self, path: &str, target: &str) {
        self.add_file_record(Self::leaf_name_of(path));
        // The target lives in a data fork (at least one block).
        self.file_lens.push((target.len() as u64).max(1));
    }

    fn add_device(&mut self, path: &str) {
        // No device nodes in HFS; stored as an empty file.
        self.add_file_record(Self::leaf_name_of(path));
    }

    fn total_size(&self) -> u64 {
        // Resolve the block size: it scales with the volume's sector count, so a
        // short fixed point settles it (and the bitmap size with it).
        let mut bs = 512u64;
        for _ in 0..8 {
            let sectors = self.sectors_at(bs);
            let next = auto_block_size(sectors);
            if next == bs {
                break;
            }
            bs = next;
        }
        self.sectors_at(bs) * 512
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> HfsFormatOpts {
        HfsFormatOpts {
            volume_name: "Test".into(),
            block_size: None,
        }
    }

    #[test]
    fn empty_volume_is_small() {
        let p = HfsClassicSizePlan::new(&opts());
        // Boot + MDB + bitmap + a 2-node catalog (header + one leaf) + extents
        // header — a few KiB.
        let kib = p.total_size() / 1024;
        assert!(kib < 64, "empty HFS should be a few KiB, got {kib} KiB");
    }

    #[test]
    fn files_add_data_blocks() {
        let mut p = HfsClassicSizePlan::new(&opts());
        p.add_file("/big", 100_000);
        // 100_000 bytes at 512-byte blocks.
        assert_eq!(p.data_blocks(512), 100_000u64.div_ceil(512));
    }

    #[test]
    fn empty_files_use_no_data() {
        let mut p = HfsClassicSizePlan::new(&opts());
        for i in 0..10 {
            p.add_file(&format!("/f{i}"), 0);
        }
        assert_eq!(p.data_blocks(512), 0);
    }

    #[test]
    fn many_entries_grow_catalog() {
        let mut p = HfsClassicSizePlan::new(&opts());
        let base = p.catalog_nodes();
        for i in 0..2000 {
            p.add_file(&format!("/file_{i:05}.txt"), 0);
        }
        assert!(p.catalog_nodes() > base);
    }

    #[test]
    fn monotonic_in_size() {
        let small = {
            let mut p = HfsClassicSizePlan::new(&opts());
            p.add_file("/a", 1000);
            p.total_size()
        };
        let big = {
            let mut p = HfsClassicSizePlan::new(&opts());
            p.add_file("/a", 10_000_000);
            p.total_size()
        };
        assert!(big > small);
    }
}
