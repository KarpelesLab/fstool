//! ext2/3/4 superblock — typed representation + encode/decode.
//!
//! The on-disk superblock is 1024 bytes regardless of `s_inode_size`. We
//! cover the classic ext2 fields plus the dynamic-rev extensions; ext3/4
//! adds more fields (most of the second half of the structure), but the
//! writer only touches what's documented here.
//!
//! ## Unmodelled fields survive a round-trip
//!
//! `Superblock` carries the raw 1024-byte on-disk image it was decoded
//! from (`raw`; all zeros for a freshly-formatted filesystem). `encode`
//! starts from that image and patches only the modelled fields, so
//! every field this module does not model (`s_mmp_block`, quota
//! inodes, `s_jnl_blocks`, `s_last_orphan`, `s_encoding`, ...) is
//! preserved verbatim when an opened image is flushed. Without this an
//! `open` + mutate + `flush` cycle would zero the hash seed, the
//! reserved-GDT count and every other field mke2fs wrote.

use super::constants::{
    EXT2_MAGIC, FIRST_INO_DYNAMIC, FS_VALID, INODE_SIZE_DYNAMIC, OS_LINUX, REV_DYNAMIC,
    SUPERBLOCK_SIZE,
};
use crate::Result;

/// Typed superblock. All fields are in host order; encode/decode handle the
/// little-endian on-disk representation.
#[derive(Debug, Clone)]
pub struct Superblock {
    pub inodes_count: u32,
    pub blocks_count: u32,
    pub r_blocks_count: u32,
    pub free_blocks_count: u32,
    pub free_inodes_count: u32,
    pub first_data_block: u32,
    pub log_block_size: u32, // 0 → 1 KiB, 1 → 2 KiB, 2 → 4 KiB
    pub log_frag_size: u32,
    pub blocks_per_group: u32,
    pub frags_per_group: u32,
    pub inodes_per_group: u32,
    pub mtime: u32,
    pub wtime: u32,
    pub mnt_count: u16,
    pub max_mnt_count: u16,
    pub magic: u16,
    pub state: u16,
    pub errors: u16,
    pub minor_rev_level: u16,
    pub lastcheck: u32,
    pub checkinterval: u32,
    pub creator_os: u32,
    pub rev_level: u32,
    pub def_resuid: u16,
    pub def_resgid: u16,
    // DYNAMIC_REV extensions (only meaningful when rev_level == REV_DYNAMIC):
    pub first_ino: u32,
    pub inode_size: u16,
    pub block_group_nr: u16,
    pub feature_compat: u32,
    pub feature_incompat: u32,
    pub feature_ro_compat: u32,
    pub uuid: [u8; 16],
    pub volume_name: [u8; 16],
    pub last_mounted: [u8; 64],
    pub algorithm_usage_bitmap: u32,
    /// Inode number of the journal (only meaningful with the HAS_JOURNAL
    /// compat feature). 0 for ext2.
    pub journal_inum: u32,
    /// On-disk size of each group descriptor. 0 means the classic 32-byte
    /// form; when `INCOMPAT_64BIT` is set this is 64 (or larger).
    pub desc_size: u16,
    /// `s_log_groups_per_flex` at offset 0x174. Base-2 log of the number
    /// of groups packed into one flex unit when `INCOMPAT_FLEX_BG` is
    /// active. 0 means the classic one-group-at-a-time metadata layout.
    pub log_groups_per_flex: u8,
    /// `s_backup_bgs[2]` at offset 0x24C. The two block-group numbers
    /// that hold SB+GDT backups when the `sparse_super2` compat feature
    /// is set. Zero otherwise.
    pub backup_bgs: [u32; 2],
    /// `s_checksum_seed` at offset 0x270. The filesystem-wide CRC32C seed
    /// when the `metadata_csum_seed` (`INCOMPAT_CSUM_SEED`) feature is
    /// set; ignored otherwise (the seed is then derived from `uuid`).
    pub checksum_seed: u32,
    /// `s_reserved_gdt_blocks` at offset 0xCE: GDT blocks reserved after
    /// the live GDT in every group that carries a superblock backup
    /// (`resize_inode` feature). Zero for images this crate formats.
    pub reserved_gdt_blocks: u16,
    /// `s_hash_seed[4]` at offset 0xEC: the per-filesystem HTree hash
    /// seed. All-zero means "use the algorithm's default IV".
    pub hash_seed: [u8; 16],
    /// `s_def_hash_version` at offset 0xFC.
    pub def_hash_version: u8,
    /// `s_min_extra_isize` / `s_want_extra_isize` at 0x15C / 0x15E: the
    /// `i_extra_isize` every inode must carry / should be grown to when
    /// `RO_COMPAT_EXTRA_ISIZE` is set.
    pub min_extra_isize: u16,
    pub want_extra_isize: u16,
    /// `s_flags` at offset 0x160: `EXT2_FLAGS_SIGNED_HASH` (0x1) /
    /// `EXT2_FLAGS_UNSIGNED_HASH` (0x2) select how HTree hashes treat
    /// bytes >= 0x80; `EXT2_FLAGS_TEST_FILESYS` (0x4).
    pub flags: u32,
    /// The raw on-disk image this superblock was decoded from (all zero
    /// for a freshly-formatted filesystem). `encode` patches the modelled
    /// fields into a copy of it so unmodelled fields round-trip.
    pub raw: [u8; SUPERBLOCK_SIZE],
}

/// `s_flags` bit: HTree hashes treat name bytes as signed chars.
pub const FLAGS_SIGNED_HASH: u32 = 0x0001;
/// `s_flags` bit: HTree hashes treat name bytes as unsigned chars.
pub const FLAGS_UNSIGNED_HASH: u32 = 0x0002;

impl Superblock {
    /// Effective group-descriptor size in bytes: `desc_size` if non-zero,
    /// otherwise the classic 32.
    pub fn group_desc_size(&self) -> usize {
        if self.desc_size == 0 {
            32
        } else {
            self.desc_size as usize
        }
    }
}

impl Superblock {
    /// Build a default superblock suitable for ext2 (no features). Caller
    /// must then fill in counts and sizes.
    pub fn ext2_default() -> Self {
        Self {
            inodes_count: 0,
            blocks_count: 0,
            r_blocks_count: 0,
            free_blocks_count: 0,
            free_inodes_count: 0,
            first_data_block: 0,
            log_block_size: 0,
            log_frag_size: 0,
            blocks_per_group: 0,
            frags_per_group: 0,
            inodes_per_group: 0,
            mtime: 0,
            wtime: 0,
            mnt_count: 0,
            max_mnt_count: 20,
            magic: EXT2_MAGIC,
            state: FS_VALID,
            // genext2fs sets s_errors to 0 ("undefined" in dumpe2fs); the
            // kernel treats it as the default behaviour (continue). We
            // match for byte-exact compatibility.
            errors: 0,
            minor_rev_level: 0,
            lastcheck: 0,
            checkinterval: 0,
            creator_os: OS_LINUX,
            rev_level: REV_DYNAMIC,
            def_resuid: 0,
            def_resgid: 0,
            first_ino: FIRST_INO_DYNAMIC,
            inode_size: INODE_SIZE_DYNAMIC,
            block_group_nr: 0,
            feature_compat: 0,
            feature_incompat: 0,
            feature_ro_compat: 0,
            uuid: [0; 16],
            volume_name: [0; 16],
            last_mounted: [0; 64],
            algorithm_usage_bitmap: 0,
            journal_inum: 0,
            desc_size: 0,
            log_groups_per_flex: 0,
            backup_bgs: [0, 0],
            checksum_seed: 0,
            reserved_gdt_blocks: 0,
            hash_seed: [0; 16],
            def_hash_version: 0,
            min_extra_isize: 0,
            want_extra_isize: 0,
            flags: 0,
            raw: [0; SUPERBLOCK_SIZE],
        }
    }

    /// Block size in bytes derived from `log_block_size`.
    pub fn block_size(&self) -> u32 {
        1024u32 << self.log_block_size
    }

    /// Number of block groups: ceil(blocks_count / blocks_per_group).
    pub fn group_count(&self) -> u32 {
        self.blocks_count.div_ceil(self.blocks_per_group)
    }

    /// Encode into the 1024-byte on-disk representation. Starts from the
    /// raw image this superblock was decoded from (zeros for a fresh
    /// format) and patches only the modelled fields, so unmodelled
    /// fields of an opened image survive a flush.
    pub fn encode(&self) -> [u8; SUPERBLOCK_SIZE] {
        let mut buf = self.raw;
        let p = &mut buf;
        write_u32(p, 0, self.inodes_count);
        write_u32(p, 4, self.blocks_count);
        write_u32(p, 8, self.r_blocks_count);
        write_u32(p, 12, self.free_blocks_count);
        write_u32(p, 16, self.free_inodes_count);
        write_u32(p, 20, self.first_data_block);
        write_u32(p, 24, self.log_block_size);
        write_u32(p, 28, self.log_frag_size);
        write_u32(p, 32, self.blocks_per_group);
        write_u32(p, 36, self.frags_per_group);
        write_u32(p, 40, self.inodes_per_group);
        write_u32(p, 44, self.mtime);
        write_u32(p, 48, self.wtime);
        write_u16(p, 52, self.mnt_count);
        write_u16(p, 54, self.max_mnt_count);
        write_u16(p, 56, self.magic);
        write_u16(p, 58, self.state);
        write_u16(p, 60, self.errors);
        write_u16(p, 62, self.minor_rev_level);
        write_u32(p, 64, self.lastcheck);
        write_u32(p, 68, self.checkinterval);
        write_u32(p, 72, self.creator_os);
        write_u32(p, 76, self.rev_level);
        write_u16(p, 80, self.def_resuid);
        write_u16(p, 82, self.def_resgid);
        write_u32(p, 84, self.first_ino);
        write_u16(p, 88, self.inode_size);
        write_u16(p, 90, self.block_group_nr);
        write_u32(p, 92, self.feature_compat);
        write_u32(p, 96, self.feature_incompat);
        write_u32(p, 100, self.feature_ro_compat);
        p[104..120].copy_from_slice(&self.uuid);
        p[120..136].copy_from_slice(&self.volume_name);
        p[136..200].copy_from_slice(&self.last_mounted);
        write_u32(p, 200, self.algorithm_usage_bitmap);
        // 204: s_prealloc_blocks (u8), 205: s_prealloc_dir_blocks (u8),
        // 206..208: s_reserved_gdt_blocks (u16).
        write_u16(p, 0xCE, self.reserved_gdt_blocks);
        // 208..224: s_journal_uuid — carried from `raw`.
        write_u32(p, 224, self.journal_inum);
        // 228..236: s_journal_dev, s_last_orphan — carried from `raw`.
        p[0xEC..0xFC].copy_from_slice(&self.hash_seed);
        p[0xFC] = self.def_hash_version;
        // 253: s_jnl_backup_type (u8) — carried from `raw`.
        write_u16(p, 254, self.desc_size);
        // 256..0x15C: s_default_mount_opts, s_first_meta_bg, s_mkfs_time,
        // s_jnl_blocks — carried from `raw`.
        write_u16(p, 0x15C, self.min_extra_isize);
        write_u16(p, 0x15E, self.want_extra_isize);
        write_u32(p, 0x160, self.flags);
        // 0x174: s_log_groups_per_flex (u8).
        p[0x174] = self.log_groups_per_flex;
        // 0x175..: s_checksum_type, padding, ... — carried from `raw`.
        // (The metadata-checksum path in mod.rs sets 0x175 directly when
        // needed.)
        // 0x24C..0x254: s_backup_bgs[2] — populated when the
        // `sparse_super2` compat feature is on.
        write_u32(p, 0x24C, self.backup_bgs[0]);
        write_u32(p, 0x250, self.backup_bgs[1]);
        // 0x270: s_checksum_seed — meaningful with `INCOMPAT_CSUM_SEED`.
        write_u32(p, 0x270, self.checksum_seed);
        // 0x3FC: s_checksum — stamped by the caller when metadata_csum
        // is on; zero it here so a stale value from `raw` never leaks
        // into an image whose checksum feature was turned off.
        write_u32(p, 0x3FC, 0);
        buf
    }

    /// Decode from a 1024-byte on-disk representation. Validates the magic.
    pub fn decode(buf: &[u8; SUPERBLOCK_SIZE]) -> Result<Self> {
        let magic = read_u16(buf, 56);
        if magic != EXT2_MAGIC {
            return Err(crate::Error::InvalidImage(format!(
                "ext: bad superblock magic {magic:#06x}, expected {EXT2_MAGIC:#06x}"
            )));
        }
        let rev_level = read_u32(buf, 76);
        let (first_ino, inode_size) = if rev_level == 0 {
            // good_old rev: these fields have implicit values.
            (11, 128)
        } else {
            (read_u32(buf, 84), read_u16(buf, 88))
        };
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&buf[104..120]);
        let mut volume_name = [0u8; 16];
        volume_name.copy_from_slice(&buf[120..136]);
        let mut last_mounted = [0u8; 64];
        last_mounted.copy_from_slice(&buf[136..200]);
        let mut hash_seed = [0u8; 16];
        hash_seed.copy_from_slice(&buf[0xEC..0xFC]);
        Ok(Self {
            inodes_count: read_u32(buf, 0),
            blocks_count: read_u32(buf, 4),
            r_blocks_count: read_u32(buf, 8),
            free_blocks_count: read_u32(buf, 12),
            free_inodes_count: read_u32(buf, 16),
            first_data_block: read_u32(buf, 20),
            log_block_size: read_u32(buf, 24),
            log_frag_size: read_u32(buf, 28),
            blocks_per_group: read_u32(buf, 32),
            frags_per_group: read_u32(buf, 36),
            inodes_per_group: read_u32(buf, 40),
            mtime: read_u32(buf, 44),
            wtime: read_u32(buf, 48),
            mnt_count: read_u16(buf, 52),
            max_mnt_count: read_u16(buf, 54),
            magic,
            state: read_u16(buf, 58),
            errors: read_u16(buf, 60),
            minor_rev_level: read_u16(buf, 62),
            lastcheck: read_u32(buf, 64),
            checkinterval: read_u32(buf, 68),
            creator_os: read_u32(buf, 72),
            rev_level,
            def_resuid: read_u16(buf, 80),
            def_resgid: read_u16(buf, 82),
            first_ino,
            inode_size,
            block_group_nr: read_u16(buf, 90),
            feature_compat: read_u32(buf, 92),
            feature_incompat: read_u32(buf, 96),
            feature_ro_compat: read_u32(buf, 100),
            uuid,
            volume_name,
            last_mounted,
            algorithm_usage_bitmap: read_u32(buf, 200),
            journal_inum: read_u32(buf, 224),
            desc_size: read_u16(buf, 254),
            log_groups_per_flex: buf[0x174],
            backup_bgs: [read_u32(buf, 0x24C), read_u32(buf, 0x250)],
            checksum_seed: read_u32(buf, 0x270),
            reserved_gdt_blocks: read_u16(buf, 0xCE),
            hash_seed,
            def_hash_version: buf[0xFC],
            min_extra_isize: read_u16(buf, 0x15C),
            want_extra_isize: read_u16(buf, 0x15E),
            flags: read_u32(buf, 0x160),
            raw: *buf,
        })
    }
}

#[inline]
fn write_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

#[inline]
fn write_u16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

#[inline]
fn read_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
}

#[inline]
fn read_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(buf[off..off + 2].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_default() {
        let mut sb = Superblock::ext2_default();
        sb.inodes_count = 1024;
        sb.blocks_count = 8192;
        sb.free_blocks_count = 7000;
        sb.free_inodes_count = 1013;
        sb.log_block_size = 0;
        sb.blocks_per_group = 8192;
        sb.frags_per_group = 8192;
        sb.inodes_per_group = 1024;
        sb.first_data_block = 1;
        sb.uuid = [0x42; 16];
        sb.checksum_seed = 0xDEAD_BEEF;
        let buf = sb.encode();
        assert_eq!(&buf[0x270..0x274], &0xDEAD_BEEFu32.to_le_bytes());
        let decoded = Superblock::decode(&buf).unwrap();
        assert_eq!(decoded.inodes_count, sb.inodes_count);
        assert_eq!(decoded.blocks_count, sb.blocks_count);
        assert_eq!(decoded.uuid, sb.uuid);
        assert_eq!(decoded.checksum_seed, 0xDEAD_BEEF);
        assert_eq!(decoded.magic, EXT2_MAGIC);
        assert_eq!(decoded.block_size(), 1024);
    }

    /// Fields this module does not model must survive decode → encode:
    /// an opened mke2fs image carries a hash seed, reserved GDT blocks,
    /// MMP block, quota inodes and more that a flush must not zero.
    #[test]
    fn unmodelled_fields_round_trip_through_raw() {
        let mut sb = Superblock::ext2_default();
        sb.inodes_count = 1024;
        sb.blocks_count = 8192;
        sb.blocks_per_group = 8192;
        sb.inodes_per_group = 1024;
        let mut on_disk = sb.encode();
        // s_hash_seed (modelled), s_mmp_block (0x1D0, unmodelled),
        // s_usr_quota_inum (0x240, unmodelled), s_encoding (0x27C,
        // unmodelled), s_first_meta_bg (0x104, unmodelled).
        on_disk[0xEC..0xFC].copy_from_slice(&[0xA5; 16]);
        on_disk[0x1D0..0x1D8].copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
        on_disk[0x240..0x244].copy_from_slice(&3u32.to_le_bytes());
        on_disk[0x27C..0x27E].copy_from_slice(&1u16.to_le_bytes());
        on_disk[0x104..0x108].copy_from_slice(&7u32.to_le_bytes());
        on_disk[0xCE..0xD0].copy_from_slice(&63u16.to_le_bytes());

        let mut decoded = Superblock::decode(&on_disk).unwrap();
        assert_eq!(decoded.hash_seed, [0xA5; 16]);
        assert_eq!(decoded.reserved_gdt_blocks, 63);
        // Mutate a modelled field the way a flush would.
        decoded.free_blocks_count = 4242;
        let back = decoded.encode();
        assert_eq!(&back[0xEC..0xFC], &[0xA5; 16]);
        assert_eq!(&back[0x1D0..0x1D8], &0x1122_3344_5566_7788u64.to_le_bytes());
        assert_eq!(&back[0x240..0x244], &3u32.to_le_bytes());
        assert_eq!(&back[0x27C..0x27E], &1u16.to_le_bytes());
        assert_eq!(&back[0x104..0x108], &7u32.to_le_bytes());
        assert_eq!(&back[0xCE..0xD0], &63u16.to_le_bytes());
        assert_eq!(&back[12..16], &4242u32.to_le_bytes());
        // A freshly-built superblock still encodes from zeros.
        let fresh = Superblock::ext2_default().encode();
        assert!(fresh[0x1D0..0x1D8].iter().all(|&b| b == 0));
    }

    #[test]
    fn bad_magic_rejected() {
        let mut buf = [0u8; SUPERBLOCK_SIZE];
        // No magic written
        let err = Superblock::decode(&buf).unwrap_err();
        assert!(matches!(err, crate::Error::InvalidImage(_)));
        // Write wrong magic
        buf[56..58].copy_from_slice(&0x1234u16.to_le_bytes());
        let err = Superblock::decode(&buf).unwrap_err();
        assert!(matches!(err, crate::Error::InvalidImage(_)));
    }
}
