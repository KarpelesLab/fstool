//! Content-fit size plan for AFFS (Amiga OFS/FFS).
//!
//! Phase 1 of the two-phase builder: as the static file list is walked, this
//! accumulates the exact block allocation `AffsWriter` will make — one header
//! block per inode (file / dir / symlink), the file's data blocks, and its
//! file-extension blocks — mirroring `AffsWriter`'s own
//! `data_block_count` / `ext_block_count`. Phase 2 ([`total_size`]) folds in the
//! size-dependent volume bitmap (chicken-and-egg, resolved by a short
//! fixed-point) and the fixed boot + root blocks to yield the exact image size.
//!
//! [`total_size`]: AffsSizePlan::total_size

use super::{BSIZE, MAX_DATABLK};
use crate::fs::FsSizePlan;

/// Bits of allocation covered by one bitmap block — matches
/// `writer::BM_BITS_PER_BLOCK` (`(BSIZE/4 - 1) × 32`).
const BM_BITS_PER_BLOCK: u64 = (BSIZE as u64 / 4 - 1) * 32;

/// Exact AFFS size accumulator.
#[derive(Debug)]
pub struct AffsSizePlan {
    /// FFS (raw 512-byte data blocks) vs OFS (24-byte data header → 488 bytes).
    ffs: bool,
    /// Size-independent block total: boot (2) + root (1) + every entry's
    /// header / data / extension blocks.
    content_blocks: u64,
}

impl AffsSizePlan {
    /// A fresh plan for an FFS (`ffs = true`) or OFS volume. Seeded with the
    /// two boot blocks and the root block.
    #[must_use]
    pub fn new(ffs: bool) -> Self {
        Self {
            ffs,
            content_blocks: 3,
        }
    }

    /// Bytes of file payload per data block under this variant.
    fn payload(&self) -> u64 {
        if self.ffs {
            BSIZE as u64
        } else {
            BSIZE as u64 - 24
        }
    }

    /// Blocks a regular file of `len` bytes consumes: one file-header block,
    /// the data blocks, and a file-extension block per `MAX_DATABLK` data
    /// pointers beyond the header's first `MAX_DATABLK`.
    fn file_blocks(&self, len: u64) -> u64 {
        let data = len.div_ceil(self.payload());
        let max = MAX_DATABLK as u64;
        let ext = if data <= max {
            0
        } else {
            (data - max).div_ceil(max)
        };
        1 + data + ext
    }
}

impl FsSizePlan for AffsSizePlan {
    fn add_dir(&mut self, _path: &str) {
        // A directory is one header block (its hash table); dir-cache blocks
        // are not used by the default create variant.
        self.content_blocks += 1;
    }

    fn add_file(&mut self, _path: &str, len: u64) {
        self.content_blocks += self.file_blocks(len);
    }

    fn add_symlink(&mut self, _path: &str, _target: &str) {
        // Soft links are a single header block (SLINK), target stored inline.
        self.content_blocks += 1;
    }

    fn add_device(&mut self, _path: &str) {
        // AFFS has no device nodes; reserve a header so the size never
        // under-counts if one is (best-effort) materialised.
        self.content_blocks += 1;
    }

    fn total_size(&self) -> u64 {
        // total = content + bitmap_blocks(total); the bitmap covers blocks
        // 2.. so its size depends on the total. Resolve the fixed point.
        let mut total = self.content_blocks;
        for _ in 0..8 {
            let bitmap = total.saturating_sub(2).div_ceil(BM_BITS_PER_BLOCK);
            let next = self.content_blocks + bitmap;
            if next == total {
                break;
            }
            total = next;
        }
        total * BSIZE as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_volume_is_boot_root_bitmap() {
        let p = AffsSizePlan::new(true);
        // boot(2) + root(1) + 1 bitmap block = 4 blocks.
        assert_eq!(p.total_size(), 4 * 512);
    }

    #[test]
    fn ffs_vs_ofs_data_blocks() {
        let mut ffs = AffsSizePlan::new(true);
        ffs.add_file("/a", 512); // one full 512-byte FFS data block + header
        // header(1) + data(1) added to the seed of 3.
        let mut ofs = AffsSizePlan::new(false);
        ofs.add_file("/a", 512); // 512 / 488 = 2 OFS data blocks + header
        assert!(ofs.total_size() > ffs.total_size());
    }

    #[test]
    fn extension_blocks_past_72_data_blocks() {
        let p = AffsSizePlan::new(true);
        // 73 data blocks (FFS: 73 * 512 bytes) → 1 header + 73 data + 1 ext.
        assert_eq!(p.file_blocks(73 * 512), 1 + 73 + 1);
        // Exactly 72 needs no extension block.
        assert_eq!(p.file_blocks(72 * 512), 1 + 72);
    }

    #[test]
    fn directories_and_symlinks_are_one_block() {
        let mut p = AffsSizePlan::new(true);
        let base = p.total_size();
        p.add_dir("/d");
        p.add_symlink("/l", "target");
        // Two more header blocks → at least 2 × 512 bigger (bitmap unchanged
        // at this scale).
        assert!(p.total_size() >= base + 2 * 512);
    }
}
