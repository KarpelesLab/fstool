//! Content-fit size plan for F2FS.
//!
//! F2FS's metadata region is **fixed** (2 superblocks + checkpoint/SIT/NAT/SSA
//! segments, ~14 MiB), independent of volume size. The size therefore comes
//! from the *main area*: one node (inode) block per entry — plus indirect node
//! blocks for large files — and data blocks for files past the 3672-byte inline
//! limit and directories past 182 inline dentries. The main area is measured in
//! 2 MiB segments and needs at least the 6 active-log segments (hot/warm/cold ×
//! node/data), which is F2FS's practical floor (~27 MiB).
//!
//! Phase 1 accumulates node/data blocks; phase 2 ([`total_size`]) rounds the
//! main area up to whole segments (with headroom for the 6 logs' partial
//! segments) and adds the fixed metadata.
//!
//! [`total_size`]: F2fsSizePlan::total_size

use std::collections::HashMap;

use super::constants::{ADDRS_PER_BLOCK, ADDRS_PER_INODE, NR_DENTRY_IN_BLOCK};
use super::dir::INLINE_DENTRY_NR;
use crate::fs::{FsSizePlan, split_parent_name};

/// 4 KiB F2FS block.
const BLOCK: u64 = 4096;
/// Blocks per 2 MiB segment (`1 << log_blocks_per_seg`, default 9).
const BLOCKS_PER_SEG: u64 = 512;
/// Fixed metadata blocks: 2 superblocks + (ckpt 2 + sit 2 + nat 2 + ssa 1)
/// segments — matches `format::plan_geometry`.
const META_BLOCKS: u64 = 2 + (2 + 2 + 2 + 1) * BLOCKS_PER_SEG;
/// Files larger than this are *not* inline (kept in sync with the writer's
/// `MAX_INLINE_DATA`).
const MAX_INLINE_DATA: u64 = 3672;
/// The six active logs (hot/warm/cold × node/data) each hold a current
/// segment, so the main area never has fewer than this many segments.
const MIN_MAIN_SEGS: u64 = 6;

/// Per-directory accumulator.
#[derive(Default, Clone, Copy)]
struct Dir {
    entries: u64,
    /// Sum of `ceil(name_len / 8)` dentry slots over children.
    slots: u64,
}

/// Exact-ish (safe upper bound) F2FS size accumulator.
#[derive(Default)]
pub struct F2fsSizePlan {
    /// Node blocks: one per entry plus indirect nodes for big files.
    node_blocks: u64,
    /// Data blocks: non-inline file data + directory dentry blocks.
    data_blocks: u64,
    dirs: HashMap<String, Dir>,
}

impl F2fsSizePlan {
    #[must_use]
    pub fn new() -> Self {
        let mut dirs = HashMap::new();
        dirs.insert("/".to_string(), Dir::default());
        Self {
            node_blocks: 1, // the root inode
            data_blocks: 0,
            dirs,
        }
    }

    fn charge_parent(&mut self, path: &str) {
        let (parent, name) = split_parent_name(path);
        let d = self.dirs.entry(parent.to_string()).or_default();
        d.entries += 1;
        d.slots += (name.len() as u64).max(1).div_ceil(8);
    }

    /// Indirect/double-indirect node blocks for a file of `d` data blocks
    /// (the inode itself inlines the first `ADDRS_PER_INODE` pointers).
    fn indirect_nodes(d: u64) -> u64 {
        let inline = ADDRS_PER_INODE as u64;
        if d <= inline {
            return 0;
        }
        let per = ADDRS_PER_BLOCK as u64;
        let direct = (d - inline).div_ceil(per); // direct node blocks
        // Indirect nodes to point at the direct nodes, plus a double-indirect
        // allowance — a safe over-estimate.
        direct + direct.div_ceil(per) + 1
    }

    /// Data (dentry) blocks a directory needs: 0 while inline (≤ 182 entries),
    /// else `ceil(total_slots / 214)`.
    fn dir_data_blocks(d: &Dir) -> u64 {
        if d.entries <= INLINE_DENTRY_NR as u64 {
            return 0;
        }
        d.slots.div_ceil(NR_DENTRY_IN_BLOCK as u64).max(1)
    }
}

impl FsSizePlan for F2fsSizePlan {
    fn add_dir(&mut self, path: &str) {
        self.charge_parent(path);
        self.node_blocks += 1;
        self.dirs.entry(path.to_string()).or_default();
    }

    fn add_file(&mut self, path: &str, len: u64) {
        self.charge_parent(path);
        self.node_blocks += 1;
        if len > MAX_INLINE_DATA {
            let d = len.div_ceil(BLOCK);
            self.data_blocks += d;
            self.node_blocks += Self::indirect_nodes(d);
        }
    }

    fn add_symlink(&mut self, path: &str, target: &str) {
        self.charge_parent(path);
        self.node_blocks += 1;
        // Symlink target stored in one data block when it doesn't fit inline.
        if target.len() as u64 > MAX_INLINE_DATA {
            self.data_blocks += 1;
        }
    }

    fn add_device(&mut self, path: &str) {
        self.charge_parent(path);
        self.node_blocks += 1; // inode-only
    }

    fn total_size(&self) -> u64 {
        let dir_data: u64 = self.dirs.values().map(Self::dir_data_blocks).sum();
        let node_segs = self.node_blocks.div_ceil(BLOCKS_PER_SEG);
        let data_segs = (self.data_blocks + dir_data).div_ceil(BLOCKS_PER_SEG);
        // Node and data live in separate logs; +5 covers the idle logs' current
        // segments (so tiny content lands on exactly the 6-segment floor).
        let main_segs = (node_segs + data_segs + 5).max(MIN_MAIN_SEGS);
        (META_BLOCKS + main_segs * BLOCKS_PER_SEG) * BLOCK
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_meta_plus_floor() {
        let p = F2fsSizePlan::new();
        // ~14 MiB meta + 6..7 main segments → ~27 MiB.
        let mib = p.total_size() / (1024 * 1024);
        assert!((26..=30).contains(&mib), "got {mib} MiB");
    }

    #[test]
    fn small_files_and_dirs_inline() {
        let mut p = F2fsSizePlan::new();
        for i in 0..50 {
            p.add_file(&format!("/f{i}"), 100); // < 3672 → inline
        }
        assert_eq!(p.data_blocks, 0);
        assert_eq!(F2fsSizePlan::dir_data_blocks(p.dirs.get("/").unwrap()), 0);
    }

    #[test]
    fn large_file_adds_data_and_indirect_nodes() {
        let mut p = F2fsSizePlan::new();
        // 8 MiB file → 2048 data blocks > 923 inline → direct node(s).
        p.add_file("/big", 8 * 1024 * 1024);
        assert_eq!(p.data_blocks, (8 * 1024 * 1024u64).div_ceil(BLOCK));
        assert!(p.node_blocks > 2); // root + inode + indirect
    }

    #[test]
    fn big_directory_needs_dentry_blocks() {
        let mut p = F2fsSizePlan::new();
        for i in 0..300 {
            p.add_file(&format!("/file_{i:04}"), 10);
        }
        assert!(F2fsSizePlan::dir_data_blocks(p.dirs.get("/").unwrap()) > 0);
    }
}
