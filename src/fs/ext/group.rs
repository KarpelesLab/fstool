//! Block group descriptor and bitmap utilities.

use super::constants::GROUP_DESC_SIZE;

/// `bg_flags`: the group's inode bitmap has never been written — treat
/// it as all zero (`EXT4_BG_INODE_UNINIT`). Only meaningful when the
/// filesystem has group-descriptor checksums (`uninit_bg` /
/// `metadata_csum`).
pub const BG_INODE_UNINIT: u16 = 0x0001;
/// `bg_flags`: the group's block bitmap has never been written — it
/// must be synthesised from the group's metadata layout
/// (`EXT4_BG_BLOCK_UNINIT`).
pub const BG_BLOCK_UNINIT: u16 = 0x0002;
/// `bg_flags`: the group's inode table has been zeroed on disk
/// (`EXT4_BG_INODE_ZEROED`). When clear, the kernel's lazy init thread
/// zeroes the table past the used prefix before trusting it.
pub const BG_INODE_ZEROED: u16 = 0x0004;

/// One block group descriptor (32 bytes, classic ext2 layout).
#[derive(Debug, Clone, Copy, Default)]
pub struct GroupDesc {
    /// Block number of this group's block bitmap.
    pub block_bitmap: u32,
    /// Block number of this group's inode bitmap.
    pub inode_bitmap: u32,
    /// Block number of the first block of this group's inode table.
    pub inode_table: u32,
    /// Number of free blocks in this group.
    pub free_blocks_count: u16,
    /// Number of free inodes in this group.
    pub free_inodes_count: u16,
    /// Number of directories allocated in this group.
    pub used_dirs_count: u16,
    /// `bg_flags` (`BG_INODE_UNINIT` / `BG_BLOCK_UNINIT` /
    /// `BG_INODE_ZEROED`). Zero for classic ext2.
    pub flags: u16,
    /// `bg_itable_unused`: number of inode slots at the *end* of this
    /// group's inode table that have never been used. e2fsck and the
    /// kernel's lazy-init skip them; must never claim a live inode.
    pub itable_unused: u16,
}

impl GroupDesc {
    /// Encode into the 32-byte on-disk representation.
    pub fn encode(&self) -> [u8; GROUP_DESC_SIZE] {
        let mut buf = [0u8; GROUP_DESC_SIZE];
        buf[0..4].copy_from_slice(&self.block_bitmap.to_le_bytes());
        buf[4..8].copy_from_slice(&self.inode_bitmap.to_le_bytes());
        buf[8..12].copy_from_slice(&self.inode_table.to_le_bytes());
        buf[12..14].copy_from_slice(&self.free_blocks_count.to_le_bytes());
        buf[14..16].copy_from_slice(&self.free_inodes_count.to_le_bytes());
        buf[16..18].copy_from_slice(&self.used_dirs_count.to_le_bytes());
        buf[18..20].copy_from_slice(&self.flags.to_le_bytes());
        // 20..24: bg_exclude_bitmap_lo, 24..28: bitmap checksums (stamped
        // by the writer), 28..30: bg_itable_unused, 30..32: bg_checksum.
        buf[28..30].copy_from_slice(&self.itable_unused.to_le_bytes());
        buf
    }

    /// Decode from an on-disk descriptor. `buf` must be at least 32 bytes;
    /// only the classic low 32 bytes are read. For a 64-byte
    /// (`INCOMPAT_64BIT`) descriptor the upper half holds the high 32 bits
    /// of the bitmap/table block numbers plus checksums — those are zero
    /// for sub-2³²-block filesystems, which is all genfs writes or opens
    /// today, so ignoring them is correct here.
    pub fn decode(buf: &[u8]) -> Self {
        debug_assert!(buf.len() >= GROUP_DESC_SIZE);
        Self {
            block_bitmap: u32::from_le_bytes(buf[0..4].try_into().unwrap()),
            inode_bitmap: u32::from_le_bytes(buf[4..8].try_into().unwrap()),
            inode_table: u32::from_le_bytes(buf[8..12].try_into().unwrap()),
            free_blocks_count: u16::from_le_bytes(buf[12..14].try_into().unwrap()),
            free_inodes_count: u16::from_le_bytes(buf[14..16].try_into().unwrap()),
            used_dirs_count: u16::from_le_bytes(buf[16..18].try_into().unwrap()),
            flags: u16::from_le_bytes(buf[18..20].try_into().unwrap()),
            itable_unused: u16::from_le_bytes(buf[28..30].try_into().unwrap()),
        }
    }
}

/// Mark bit `index` as set in the bitmap.
#[inline]
pub fn set_bit(bm: &mut [u8], index: u32) {
    let byte = (index / 8) as usize;
    let bit = (index % 8) as u8;
    bm[byte] |= 1 << bit;
}

/// Mark bit `index` as clear in the bitmap.
#[inline]
pub fn clear_bit(bm: &mut [u8], index: u32) {
    let byte = (index / 8) as usize;
    let bit = (index % 8) as u8;
    bm[byte] &= !(1 << bit);
}

/// Test whether bit `index` is set in the bitmap.
#[inline]
pub fn test_bit(bm: &[u8], index: u32) -> bool {
    let byte = (index / 8) as usize;
    let bit = (index % 8) as u8;
    bm[byte] & (1 << bit) != 0
}

/// Set bits `[0, n)` of `bm`. Used to mark the first `n` entries of a bitmap
/// reserved (e.g. the bitmap-and-metadata-block prefix of a group's data
/// area, or the reserved inode range 1..first_ino).
pub fn set_first_n(bm: &mut [u8], n: u32) {
    for i in 0..n {
        set_bit(bm, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_desc_roundtrip() {
        let gd = GroupDesc {
            block_bitmap: 8,
            inode_bitmap: 9,
            inode_table: 10,
            free_blocks_count: 1000,
            free_inodes_count: 500,
            used_dirs_count: 7,
            flags: BG_INODE_ZEROED,
            itable_unused: 123,
        };
        let buf = gd.encode();
        assert_eq!(&buf[28..30], &123u16.to_le_bytes());
        let decoded = GroupDesc::decode(&buf);
        assert_eq!(decoded.block_bitmap, gd.block_bitmap);
        assert_eq!(decoded.inode_bitmap, gd.inode_bitmap);
        assert_eq!(decoded.inode_table, gd.inode_table);
        assert_eq!(decoded.free_blocks_count, gd.free_blocks_count);
        assert_eq!(decoded.free_inodes_count, gd.free_inodes_count);
        assert_eq!(decoded.used_dirs_count, gd.used_dirs_count);
        assert_eq!(decoded.flags, BG_INODE_ZEROED);
        assert_eq!(decoded.itable_unused, 123);
    }

    #[test]
    fn bitmap_set_get() {
        let mut bm = [0u8; 16];
        for i in [0, 1, 7, 8, 9, 15, 16, 64, 127] {
            set_bit(&mut bm, i);
            assert!(test_bit(&bm, i));
        }
        clear_bit(&mut bm, 8);
        assert!(!test_bit(&bm, 8));
        assert!(test_bit(&bm, 7));
    }

    #[test]
    fn set_first_n_marks_prefix() {
        let mut bm = [0u8; 4];
        set_first_n(&mut bm, 10);
        for i in 0..10 {
            assert!(test_bit(&bm, i));
        }
        for i in 10..32 {
            assert!(!test_bit(&bm, i));
        }
    }
}
