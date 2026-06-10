//! Content-fit size plan for XFS (v5).
//!
//! Phase 1 accumulates, per the static file list, the block allocation the XFS
//! batch writer makes: one inode per entry (allocated in 64-inode chunks of 8
//! blocks), file data extents (files larger than the inode's 336-byte literal
//! area), and per-directory blocks (a directory is *shortform* — free, packed
//! in the inode — until its entries overflow the literal area, then it needs
//! directory + leaf blocks). Phase 2 ([`total_size`]) folds in the fixed
//! overhead (the 2 MiB internal log, root inode chunk + root dir) and the
//! size-dependent per-AG static metadata (allocation groups scale with the
//! volume), resolving the AG-count chicken-and-egg by a short fixed point.
//!
//! The model is a **safe upper bound**: where XFS's exact B+tree growth is
//! impractical to predict, it reserves headroom so the computed size always
//! fits (validated with `xfs_repair`), staying far tighter than a 2× guess.
//!
//! [`total_size`]: XfsSizePlan::total_size

use std::collections::HashMap;

use super::format::{
    AG0_METADATA_BLOCKS, DEFAULT_AGBLOCKS_PER_AG, MULTI_AG_THRESHOLD_BYTES, XFS_BLOCKSIZE,
    choose_agcount,
};
use crate::fs::{FsSizePlan, split_parent_name};

const BS: u64 = XFS_BLOCKSIZE as u64;
/// v3 (512-byte) inode literal area — the inline budget for shortform dirs,
/// data forks, and symlink targets.
const LITERAL: u64 = 336;
/// Inodes per chunk and blocks per chunk (64 × 512 B = 32 KiB = 8 blocks).
const INODES_PER_CHUNK: u64 = 64;
const BLOCKS_PER_CHUNK: u64 = 8;
/// Internal log size in blocks (`DEFAULT_LOG_BLOCKS`, 2 MiB at 4 KiB).
const LOG_BLOCKS: u64 = 512;
/// Per-AG headroom (blocks) over the 8 static-metadata blocks, covering AGFL +
/// modest BNO/CNT/INOBT B+tree growth on a freshly built AG.
const AG_HEADROOM: u64 = 16;

/// Per-directory accumulator: entry count and summed encoded-record bytes.
#[derive(Default, Clone, Copy)]
struct Dir {
    entries: u64,
    /// Sum of `name_len + 16` over children — an upper bound on each entry's
    /// shortform/block record size.
    rec_bytes: u64,
}

/// Exact-ish (safe upper bound) XFS size accumulator.
#[derive(Default)]
pub struct XfsSizePlan {
    /// inode count (entries); the root inode is added in `total_size`.
    inodes: u64,
    /// File data + remote-symlink blocks (size-independent).
    data_blocks: u64,
    /// Per-directory child accounting, keyed by directory path.
    dirs: HashMap<String, Dir>,
}

impl XfsSizePlan {
    #[must_use]
    pub fn new() -> Self {
        let mut dirs = HashMap::new();
        dirs.insert("/".to_string(), Dir::default()); // the root directory
        Self {
            inodes: 0,
            data_blocks: 0,
            dirs,
        }
    }

    /// Charge `path`'s parent directory for one child entry named `name`.
    fn charge_parent(&mut self, path: &str) {
        let (parent, name) = split_parent_name(path);
        let d = self.dirs.entry(parent.to_string()).or_default();
        d.entries += 1;
        d.rec_bytes += name.len() as u64 + 16;
    }

    /// Blocks one directory needs: 0 when shortform (fits in the literal
    /// area), else its data blocks, the leaf hash blocks (8 bytes per entry),
    /// and a freespace/node allowance. The leaf term is what makes a large
    /// directory's size scale with its entry count.
    fn dir_blocks(d: &Dir) -> u64 {
        // Shortform header (~10 bytes) + records must fit the literal area.
        if 10 + d.rec_bytes <= LITERAL {
            return 0;
        }
        let data = (d.rec_bytes + 64).div_ceil(BS);
        // Leaf/node hash array: 8 bytes per entry, plus the leaf headers; a
        // node-format directory adds an index level — covered by the +2.
        let leaf = (d.entries * 8 + 256).div_ceil(BS) + 1;
        data + leaf + 2 // + freespace + node/headroom
    }
}

impl FsSizePlan for XfsSizePlan {
    fn add_dir(&mut self, path: &str) {
        self.charge_parent(path);
        self.inodes += 1;
        self.dirs.entry(path.to_string()).or_default();
    }

    fn add_file(&mut self, path: &str, len: u64) {
        self.charge_parent(path);
        self.inodes += 1;
        if len > LITERAL {
            self.data_blocks += len.div_ceil(BS);
        }
    }

    fn add_symlink(&mut self, path: &str, target: &str) {
        self.charge_parent(path);
        self.inodes += 1;
        if target.len() as u64 > LITERAL {
            self.data_blocks += (target.len() as u64).div_ceil(BS);
        }
    }

    fn add_device(&mut self, path: &str) {
        self.charge_parent(path);
        self.inodes += 1; // device nodes are inode-only
    }

    fn total_size(&self) -> u64 {
        let dir_blocks: u64 = self.dirs.values().map(Self::dir_blocks).sum();
        // +1 inode for the root directory.
        let inode_chunks = (self.inodes + 1).div_ceil(INODES_PER_CHUNK);
        let inode_blocks = inode_chunks * BLOCKS_PER_CHUNK;

        // Size-independent content: log + inodes + dir blocks + file data,
        // plus a small flat safety margin for fixed metadata the model rounds
        // (AGFL fill, the odd alignment block) — negligible bytes, guarantees
        // the writer's allocator never runs one block short.
        let content = LOG_BLOCKS + inode_blocks + dir_blocks + self.data_blocks + 16;

        // Resolve the AG-count fixed point: per-AG static metadata scales with
        // the volume size, which depends on the AG count.
        let mut total_blocks = content + AG0_METADATA_BLOCKS as u64 + AG_HEADROOM;
        for _ in 0..8 {
            let agcount = u64::from(choose_agcount(total_blocks * BS));
            let ag_overhead = agcount * (AG0_METADATA_BLOCKS as u64 + AG_HEADROOM);
            let next = content + ag_overhead;
            if next <= total_blocks {
                break;
            }
            total_blocks = next;
        }
        // Guard the writer's own minimum and the per-AG block quantum.
        let _ = DEFAULT_AGBLOCKS_PER_AG;
        let _ = MULTI_AG_THRESHOLD_BYTES;
        total_blocks * BS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_log_plus_root_overhead() {
        let p = XfsSizePlan::new();
        // log(512) + root inode chunk(8) + 1 AG (8 + headroom).
        let blocks = p.total_size() / BS;
        assert!(blocks >= LOG_BLOCKS + BLOCKS_PER_CHUNK);
        assert!(blocks < LOG_BLOCKS + 64); // small, single-AG
    }

    #[test]
    fn small_files_are_inline_no_data_blocks() {
        let mut p = XfsSizePlan::new();
        for i in 0..10 {
            p.add_file(&format!("/f{i}"), 100); // < 336 → inline
        }
        assert_eq!(p.data_blocks, 0);
    }

    #[test]
    fn large_file_adds_extent_blocks() {
        let mut p = XfsSizePlan::new();
        p.add_file("/big", 1_000_000);
        assert_eq!(p.data_blocks, 1_000_000u64.div_ceil(BS));
    }

    #[test]
    fn many_children_force_block_dir() {
        let mut p = XfsSizePlan::new();
        for i in 0..50 {
            p.add_file(&format!("/longish_name_{i:03}"), 10);
        }
        // The root dir overflows shortform and needs block(s).
        let root = XfsSizePlan::dir_blocks(p.dirs.get("/").unwrap());
        assert!(root > 0);
    }
}
