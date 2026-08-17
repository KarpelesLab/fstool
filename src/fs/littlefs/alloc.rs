//! Block allocation.
//!
//! littlefs keeps no free list on disk: a block is in use exactly when
//! something reachable from the superblock points at it, and the real
//! implementation rediscovers that by traversing the filesystem into a
//! "lookahead" bitmap whenever it runs dry.
//!
//! We do the same traversal once, when a handle first needs to allocate
//! (see `LittleFs::scan_used`), and then keep the bitmap exact by marking
//! blocks as they are claimed and clearing them as they are released. That
//! costs one pass over the metadata instead of one per allocation, and —
//! because the map is exact rather than a window — "no free block" here
//! really does mean the volume is full.

use crate::{Error, Result};

/// In-use bitmap over the volume's blocks.
#[derive(Debug, Clone)]
pub struct Alloc {
    bits: Vec<u64>,
    count: u32,
    /// Rotating cursor, so successive allocations spread over the device
    /// instead of hammering the low blocks.
    next: u32,
}

impl Alloc {
    /// An empty map for a volume of `count` blocks.
    pub fn new(count: u32) -> Self {
        Self {
            bits: vec![0; (count as usize).div_ceil(64)],
            count,
            next: 0,
        }
    }

    /// Mark `block` in use. Out-of-range blocks are ignored — a corrupt
    /// pointer shouldn't panic a traversal.
    pub fn mark(&mut self, block: u32) {
        if block < self.count {
            self.bits[block as usize / 64] |= 1u64 << (block % 64);
        }
    }

    /// Release `block`. littlefs has no hard links, so nothing else can
    /// still reference a block once its owner is gone.
    pub fn free(&mut self, block: u32) {
        if block < self.count {
            self.bits[block as usize / 64] &= !(1u64 << (block % 64));
        }
    }

    /// Whether `block` is currently claimed.
    pub fn is_used(&self, block: u32) -> bool {
        block < self.count && self.bits[block as usize / 64] & (1u64 << (block % 64)) != 0
    }

    /// Number of blocks in use.
    pub fn used(&self) -> u32 {
        self.bits
            .iter()
            .map(|w| w.count_ones())
            .sum::<u32>()
            .min(self.count)
    }

    /// Claim the next free block.
    pub fn take(&mut self) -> Result<u32> {
        for i in 0..self.count {
            let b = (self.next + i) % self.count;
            if !self.is_used(b) {
                self.mark(b);
                self.next = (b + 1) % self.count;
                return Ok(b);
            }
        }
        Err(Error::InvalidArgument(
            "littlefs: no free blocks left on the volume".into(),
        ))
    }

    /// Claim a metadata pair — two distinct blocks.
    pub fn take_pair(&mut self) -> Result<[u32; 2]> {
        let a = self.take()?;
        let b = self.take().inspect_err(|_| self.free(a))?;
        Ok([a, b])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocations_are_exact_and_reusable() {
        let mut a = Alloc::new(8);
        let p = a.take_pair().unwrap();
        assert_ne!(p[0], p[1]);
        assert_eq!(a.used(), 2);
        a.free(p[0]);
        assert_eq!(a.used(), 1);
        assert!(!a.is_used(p[0]));
    }

    #[test]
    fn a_full_volume_reports_out_of_space() {
        let mut a = Alloc::new(2);
        a.take().unwrap();
        a.take().unwrap();
        assert!(a.take().is_err());
        // The failed pair allocation must not leak the half it did claim.
        let mut b = Alloc::new(3);
        b.take().unwrap();
        b.take().unwrap();
        assert!(b.take_pair().is_err());
        assert_eq!(b.used(), 2);
    }
}
