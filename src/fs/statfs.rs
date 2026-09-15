//! Capacity figures for a mounted filesystem, shaped like POSIX `statfs`.
//!
//! It is plain data — no allocation, no device, no feature — so it is
//! compiled in every configuration and answered by both halves of the
//! crate: the hosted [`Filesystem::statfs`](crate::fs::Filesystem::statfs)
//! and, without a heap, [`Volume::statfs`](crate::fs::volume::Volume::statfs)
//! on the FAT, exFAT and littlefs drivers.

/// Filesystem-level capacity stats.
///
/// Counts are in allocation units of `block_size` bytes — clusters on FAT
/// and exFAT, erase blocks on littlefs, filesystem blocks elsewhere — and
/// are all `u64` so large volumes do not overflow. `name_max` is the longest
/// filename the filesystem accepts. A filesystem with no inode table (FAT,
/// exFAT, littlefs) reports 0 for both inode counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatFs {
    /// Bytes in one allocation unit.
    pub block_size: u32,
    /// Allocation units holding data, in all.
    pub blocks: u64,
    /// Allocation units not in use.
    pub blocks_free: u64,
    /// Allocation units an unprivileged writer may use: `blocks_free` on
    /// filesystems with no reserve.
    pub blocks_avail: u64,
    /// Inodes in all, or 0 when the filesystem has no inode table.
    pub inodes: u64,
    /// Inodes free.
    pub inodes_free: u64,
    /// Longest filename accepted.
    pub name_max: u32,
}

impl StatFs {
    /// Bytes of data the filesystem can hold in all.
    pub fn total_bytes(&self) -> u64 {
        self.blocks.saturating_mul(self.block_size as u64)
    }

    /// Bytes not in use.
    pub fn free_bytes(&self) -> u64 {
        self.blocks_free.saturating_mul(self.block_size as u64)
    }

    /// Bytes an unprivileged writer may still use.
    pub fn avail_bytes(&self) -> u64 {
        self.blocks_avail.saturating_mul(self.block_size as u64)
    }
}

impl Default for StatFs {
    fn default() -> Self {
        // 4 KiB block, no quota, generous name budget — the same
        // numbers the kernel hands out for tmpfs in a fresh mount.
        Self {
            block_size: 4096,
            blocks: 0,
            blocks_free: 0,
            blocks_avail: 0,
            inodes: 0,
            inodes_free: 0,
            name_max: 255,
        }
    }
}
