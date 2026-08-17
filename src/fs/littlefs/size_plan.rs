//! Content-fit sizing: how large an image has to be for a given tree.
//!
//! littlefs's footprint is easy to predict because nothing is reserved up
//! front — a volume is exactly the metadata pairs its directories need plus
//! the blocks its out-of-line files occupy. Each directory costs at least
//! one pair (two blocks) and one more pair per metadata block its entries
//! overflow; each file either rides along inline in that metadata or takes
//! a CTZ skip-list of its own.

use std::collections::HashMap;

use crate::fs::{FsSizePlan, split_parent_name};

use super::mdir::Geom;
use super::{LittleFsFormatOpts, ctz};

/// Accumulates the exact block count a tree needs.
pub struct LittleFsSizePlan {
    geom: Geom,
    inline_max: u32,
    /// Metadata bytes per directory, keyed by path.
    dirs: HashMap<String, usize>,
    /// Blocks taken by files too large to inline.
    data_blocks: u64,
}

impl LittleFsSizePlan {
    /// A plan for a volume formatted with `opts`.
    pub fn new(opts: &LittleFsFormatOpts) -> Self {
        let geom = Geom {
            block_size: opts.block_size,
            // Only the block size matters for sizing; the count is what we
            // are computing.
            block_count: u32::MAX,
            prog_size: opts.prog_size.max(1),
            fcrc: opts.disk_version >= super::DISK_VERSION_2_1,
        };
        let inline_max =
            super::pick_inline_max(&geom, opts.inline_max).unwrap_or(opts.block_size / 8);
        let mut dirs = HashMap::new();
        // The root pair also carries the superblock entry: its name tag
        // plus "littlefs", and the inline-struct tag plus 24 bytes of
        // configuration.
        dirs.insert("/".to_string(), (4 + 8) + (4 + 24));
        Self {
            geom,
            inline_max,
            dirs,
            data_blocks: 0,
        }
    }

    /// Charge `bytes` of metadata to the directory containing `path`, and
    /// make sure that directory is on the books.
    fn charge(&mut self, path: &str, bytes: usize) {
        let (parent, _) = split_parent_name(path);
        *self.dirs.entry(parent.to_string()).or_insert(0) += bytes;
    }

    /// Blocks a file of `len` bytes occupies as a CTZ skip-list.
    fn data_blocks_for(&self, len: u64) -> u64 {
        if len == 0 {
            return 0;
        }
        let last = len.min(u32::MAX as u64) as u32 - 1;
        ctz::index_of(&self.geom, last).0 as u64 + 1
    }
}

impl FsSizePlan for LittleFsSizePlan {
    fn add_dir(&mut self, path: &str) {
        let (_, name) = split_parent_name(path);
        // The entry in the parent: a name tag and an 8-byte dir struct.
        self.charge(path, (4 + name.len()) + (4 + 8));
        self.dirs.entry(path.to_string()).or_insert(0);
    }

    fn add_file(&mut self, path: &str, len: u64) {
        let (_, name) = split_parent_name(path);
        let mut bytes = 4 + name.len();
        if len <= self.inline_max as u64 {
            bytes += 4 + len as usize;
        } else {
            bytes += 4 + 8;
            self.data_blocks += self.data_blocks_for(len);
        }
        self.charge(path, bytes);
    }

    fn add_symlink(&mut self, _path: &str, _target: &str) {
        // littlefs has no symbolic links; the writer refuses them and the
        // repack sink skips the entry, so it costs nothing.
    }

    fn add_device(&mut self, _path: &str) {
        // Likewise for device nodes, FIFOs and sockets.
    }

    fn total_size(&self) -> u64 {
        let limit = self.geom.split_limit().max(1);
        let mut blocks: u64 = 0;
        for bytes in self.dirs.values() {
            // One metadata pair per block the directory's entries fill.
            let pairs = (bytes.div_ceil(limit)).max(1) as u64;
            blocks += 2 * pairs;
        }
        blocks += self.data_blocks;
        // Two blocks of slack: littlefs grows the superblock chain by a
        // pair when the root has been rewritten enough times, and a volume
        // with no free block at all cannot be modified afterwards.
        blocks += 2;
        blocks.max(4) * self.geom.block_size as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> LittleFsSizePlan {
        LittleFsSizePlan::new(&LittleFsFormatOpts::default())
    }

    #[test]
    fn empty_tree_is_the_superblock_pair_plus_slack() {
        // Root pair (2 blocks) + 2 blocks of slack, at 4 KiB each.
        assert_eq!(plan().total_size(), 4 * 4096);
    }

    #[test]
    fn inline_files_need_no_data_blocks() {
        let mut p = plan();
        p.add_file("/small.txt", 16);
        assert_eq!(p.total_size(), 4 * 4096);
    }

    #[test]
    fn large_files_are_charged_their_skip_list() {
        let mut p = plan();
        // 4 KiB block: block 0 holds 4096 bytes, block 1 holds 4092.
        p.add_file("/big.bin", 4097);
        assert_eq!(p.data_blocks, 2);
        let mut q = plan();
        q.add_file("/big.bin", 4096);
        assert_eq!(q.data_blocks, 1);
    }

    #[test]
    fn each_directory_costs_a_pair() {
        let mut p = plan();
        p.add_dir("/etc");
        p.add_dir("/etc/ssl");
        // Root + two directories = 3 pairs, plus slack.
        assert_eq!(p.total_size(), (3 * 2 + 2) * 4096);
    }
}
