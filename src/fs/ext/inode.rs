//! ext inode — typed view + encode/decode.
//!
//! The typed struct models the classic 128-byte layout. When
//! `s_inode_size > 128` the extended area (`i_extra_isize` and what it
//! covers, then in-inode xattrs) is handled as raw bytes by the writer:
//! freshly created inodes get `i_extra_isize = 32` and zeros, inodes
//! staged from disk keep whatever the slot already holds.

use super::constants::{N_BLOCKS, S_IFBLK, S_IFCHR, S_IFDIR, S_IFIFO, S_IFLNK, S_IFREG, S_IFSOCK};

/// Size on disk of the typed-fields portion of an inode (the classic ext2
/// 128-byte layout). Larger inode sizes append an extended area.
pub const INODE_BASE_SIZE: usize = 128;

/// `i_extra_isize` the writer stamps on every inode it creates when
/// `inode_size > 128`: 32 bytes covers `i_checksum_hi`, the
/// nanosecond timestamp extensions, `i_crtime` and `i_projid` — what
/// mke2fs / the kernel use for 256-byte inodes.
pub const EXTRA_ISIZE_DEFAULT: u16 = 32;

/// Offset of `l_i_checksum_lo` (inside `osd2`) in the 128-byte base.
pub const CHECKSUM_LO_OFF: usize = 0x7C;

/// Offset of `i_checksum_hi` in the extended area (`i_extra_isize`
/// must be at least 4 for it to exist).
pub const CHECKSUM_HI_OFF: usize = 0x82;

/// Whether a full on-disk inode slot has room for `i_checksum_hi`: the
/// slot is larger than 128 bytes and its `i_extra_isize` (the first
/// u16 of the extended area) reaches past the field. Mirrors the
/// kernel's `EXT4_FITS_IN_INODE(raw, ei, i_checksum_hi)`.
pub fn extra_isize_covers_checksum_hi(slot: &[u8]) -> bool {
    if slot.len() < CHECKSUM_HI_OFF + 2 {
        return false;
    }
    let extra = u16::from_le_bytes(
        slot[INODE_BASE_SIZE..INODE_BASE_SIZE + 2]
            .try_into()
            .unwrap(),
    );
    INODE_BASE_SIZE + extra as usize >= CHECKSUM_HI_OFF + 2
}

/// Offset of `l_i_uid_high` (inside `osd2`) in the 128-byte base.
const UID_HIGH_OFF: usize = 116 + 4;
/// Offset of `l_i_gid_high` (inside `osd2`) in the 128-byte base.
const GID_HIGH_OFF: usize = 116 + 6;

/// Decoded inode.
#[derive(Debug, Clone, Copy, Default)]
pub struct Inode {
    pub mode: u16,
    /// Owner, all 32 bits: the low half is `i_uid`, the high half
    /// `osd2.l_i_uid_high`, which [`Self::encode`] and [`Self::decode`]
    /// split and join.
    pub uid: u32,
    pub size: u32,
    pub atime: u32,
    pub ctime: u32,
    pub mtime: u32,
    pub dtime: u32,
    /// Group, all 32 bits — `i_gid` plus `osd2.l_i_gid_high`, like `uid`.
    pub gid: u32,
    pub links_count: u16,
    /// Count of 512-byte sectors used. Note: this is NOT the FS block count.
    pub blocks_512: u32,
    pub flags: u32,
    pub osd1: u32,
    /// 15 block pointers: 12 direct + 1 indirect + 1 double + 1 triple.
    pub block: [u32; N_BLOCKS],
    pub generation: u32,
    pub file_acl: u32,
    /// For regular files in DYNAMIC_REV without LARGE_FILE: dir_acl. With
    /// LARGE_FILE it holds size_hi. v1 writer keeps files small (≤4 GiB) and
    /// stores 0 here.
    pub size_hi_or_dir_acl: u32,
    pub faddr: u32,
    pub osd2: [u8; 12],
}

impl Inode {
    /// Build an inode for a regular file with the given size and permissions.
    pub fn regular(size: u32, mode_perms: u16, uid: u32, gid: u32, mtime: u32) -> Self {
        Self {
            mode: S_IFREG | (mode_perms & 0o7777),
            uid,
            size,
            atime: mtime,
            ctime: mtime,
            mtime,
            dtime: 0,
            gid,
            links_count: 1,
            blocks_512: 0,
            flags: 0,
            osd1: 0,
            block: [0; N_BLOCKS],
            generation: 0,
            file_acl: 0,
            size_hi_or_dir_acl: 0,
            faddr: 0,
            osd2: [0; 12],
        }
    }

    /// Build an inode for a directory with the given permissions. The
    /// `size` should be the number of bytes occupied by the directory's
    /// data blocks (one block for a fresh dir).
    pub fn directory(size: u32, mode_perms: u16, uid: u32, gid: u32, mtime: u32) -> Self {
        Self {
            mode: S_IFDIR | (mode_perms & 0o7777),
            uid,
            size,
            atime: mtime,
            ctime: mtime,
            mtime,
            dtime: 0,
            gid,
            // Will be patched as subdirs add their ".." links pointing here.
            links_count: 2,
            blocks_512: 0,
            flags: 0,
            osd1: 0,
            block: [0; N_BLOCKS],
            generation: 0,
            file_acl: 0,
            size_hi_or_dir_acl: 0,
            faddr: 0,
            osd2: [0; 12],
        }
    }

    /// Build an inode for a symlink. If `target.len() < 60` the writer should
    /// store the target inline in the block array and set blocks_512 to 0; for
    /// longer targets it allocates a data block. The caller decides which.
    pub fn symlink(size: u32, mode_perms: u16, uid: u32, gid: u32, mtime: u32) -> Self {
        Self {
            mode: S_IFLNK | (mode_perms & 0o7777),
            uid,
            size,
            atime: mtime,
            ctime: mtime,
            mtime,
            dtime: 0,
            gid,
            links_count: 1,
            blocks_512: 0,
            flags: 0,
            osd1: 0,
            block: [0; N_BLOCKS],
            generation: 0,
            file_acl: 0,
            size_hi_or_dir_acl: 0,
            faddr: 0,
            osd2: [0; 12],
        }
    }

    /// Build an inode for a device / fifo / socket. Major/minor go into
    /// `i_block` the way the kernel lays them out — see
    /// [`device_to_i_block`].
    pub fn special(
        kind: SpecialKind,
        major: u32,
        minor: u32,
        mode_perms: u16,
        uid: u32,
        gid: u32,
        mtime: u32,
    ) -> Self {
        let m = match kind {
            SpecialKind::Char => S_IFCHR,
            SpecialKind::Block => S_IFBLK,
            SpecialKind::Fifo => S_IFIFO,
            SpecialKind::Socket => S_IFSOCK,
        };
        let mut block = [0u32; N_BLOCKS];
        if matches!(kind, SpecialKind::Char | SpecialKind::Block) {
            [block[0], block[1]] = device_to_i_block(major, minor);
        }
        Self {
            mode: m | (mode_perms & 0o7777),
            uid,
            size: 0,
            atime: mtime,
            ctime: mtime,
            mtime,
            dtime: 0,
            gid,
            links_count: 1,
            blocks_512: 0,
            flags: 0,
            osd1: 0,
            block,
            generation: 0,
            file_acl: 0,
            size_hi_or_dir_acl: 0,
            faddr: 0,
            osd2: [0; 12],
        }
    }

    /// Logical file size in bytes, for regular files. Reads
    /// `size_hi_or_dir_acl` as `i_size_high` (per ext2/3's
    /// `RO_COMPAT_LARGE_FILE` layout) and combines it with `size` for
    /// files > 4 GiB. For non-regular inodes the upper half is
    /// `i_dir_acl` and the caller must use `size` directly — this
    /// helper is named accordingly to discourage that misuse.
    pub fn file_size(&self) -> u64 {
        ((self.size_hi_or_dir_acl as u64) << 32) | self.size as u64
    }

    /// Store a 64-bit file size across the low/high halves. The caller
    /// is responsible for setting the `RO_COMPAT_LARGE_FILE` feature
    /// on the superblock when any file ends up with a non-zero
    /// `size_hi`. Only meaningful on regular-file inodes.
    pub fn set_file_size(&mut self, len: u64) {
        self.size = len as u32;
        self.size_hi_or_dir_acl = (len >> 32) as u32;
    }

    /// Encode into the 128-byte on-disk representation.
    pub fn encode(&self) -> [u8; INODE_BASE_SIZE] {
        let mut buf = [0u8; INODE_BASE_SIZE];
        buf[0..2].copy_from_slice(&self.mode.to_le_bytes());
        buf[2..4].copy_from_slice(&(self.uid as u16).to_le_bytes());
        buf[4..8].copy_from_slice(&self.size.to_le_bytes());
        buf[8..12].copy_from_slice(&self.atime.to_le_bytes());
        buf[12..16].copy_from_slice(&self.ctime.to_le_bytes());
        buf[16..20].copy_from_slice(&self.mtime.to_le_bytes());
        buf[20..24].copy_from_slice(&self.dtime.to_le_bytes());
        buf[24..26].copy_from_slice(&(self.gid as u16).to_le_bytes());
        buf[26..28].copy_from_slice(&self.links_count.to_le_bytes());
        buf[28..32].copy_from_slice(&self.blocks_512.to_le_bytes());
        buf[32..36].copy_from_slice(&self.flags.to_le_bytes());
        buf[36..40].copy_from_slice(&self.osd1.to_le_bytes());
        for (i, b) in self.block.iter().enumerate() {
            let off = 40 + i * 4;
            buf[off..off + 4].copy_from_slice(&b.to_le_bytes());
        }
        // i_block is 15 * 4 = 60 bytes, so the next field is at 40+60=100.
        buf[100..104].copy_from_slice(&self.generation.to_le_bytes());
        buf[104..108].copy_from_slice(&self.file_acl.to_le_bytes());
        buf[108..112].copy_from_slice(&self.size_hi_or_dir_acl.to_le_bytes());
        buf[112..116].copy_from_slice(&self.faddr.to_le_bytes());
        buf[116..128].copy_from_slice(&self.osd2);
        // `l_i_uid_high` / `l_i_gid_high` sit inside osd2; the fields
        // above are the source of truth for them.
        buf[UID_HIGH_OFF..UID_HIGH_OFF + 2]
            .copy_from_slice(&((self.uid >> 16) as u16).to_le_bytes());
        buf[GID_HIGH_OFF..GID_HIGH_OFF + 2]
            .copy_from_slice(&((self.gid >> 16) as u16).to_le_bytes());
        buf
    }

    /// Decode from the 128-byte on-disk representation.
    pub fn decode(buf: &[u8; INODE_BASE_SIZE]) -> Self {
        let mut block = [0u32; N_BLOCKS];
        for (i, slot) in block.iter_mut().enumerate() {
            let off = 40 + i * 4;
            *slot = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
        }
        let mut osd2 = [0u8; 12];
        osd2.copy_from_slice(&buf[116..128]);
        Inode {
            mode: u16::from_le_bytes(buf[0..2].try_into().unwrap()),
            uid: u16::from_le_bytes(buf[2..4].try_into().unwrap()) as u32
                | (u16::from_le_bytes(buf[UID_HIGH_OFF..UID_HIGH_OFF + 2].try_into().unwrap())
                    as u32)
                    << 16,
            size: u32::from_le_bytes(buf[4..8].try_into().unwrap()),
            atime: u32::from_le_bytes(buf[8..12].try_into().unwrap()),
            ctime: u32::from_le_bytes(buf[12..16].try_into().unwrap()),
            mtime: u32::from_le_bytes(buf[16..20].try_into().unwrap()),
            dtime: u32::from_le_bytes(buf[20..24].try_into().unwrap()),
            gid: u16::from_le_bytes(buf[24..26].try_into().unwrap()) as u32
                | (u16::from_le_bytes(buf[GID_HIGH_OFF..GID_HIGH_OFF + 2].try_into().unwrap())
                    as u32)
                    << 16,
            links_count: u16::from_le_bytes(buf[26..28].try_into().unwrap()),
            blocks_512: u32::from_le_bytes(buf[28..32].try_into().unwrap()),
            flags: u32::from_le_bytes(buf[32..36].try_into().unwrap()),
            osd1: u32::from_le_bytes(buf[36..40].try_into().unwrap()),
            block,
            generation: u32::from_le_bytes(buf[100..104].try_into().unwrap()),
            file_acl: u32::from_le_bytes(buf[104..108].try_into().unwrap()),
            size_hi_or_dir_acl: u32::from_le_bytes(buf[108..112].try_into().unwrap()),
            faddr: u32::from_le_bytes(buf[112..116].try_into().unwrap()),
            osd2,
        }
    }
}

/// Special-file kinds for [`Inode::special`].
#[derive(Debug, Clone, Copy)]
pub enum SpecialKind {
    Char,
    Block,
    Fifo,
    Socket,
}

pub use crate::fs::devnum::{decode_devnum, encode_devnum};

/// A device number as a char/block inode stores it in `i_block[0..2]`.
///
/// The kernel (`ext4_write_inode`, and ext2 before it) keeps the old
/// 16-bit layout in `i_block[0]` whenever major and minor both fit in a
/// byte, and otherwise zeroes `i_block[0]` and stores the new layout
/// ([`encode_devnum`]) in `i_block[1]`. The reader tells them apart by
/// `i_block[0]` being non-zero, so the new layout can never go there: a
/// number with a minor above 255 in `i_block[0]` reads back as a
/// different device.
pub fn device_to_i_block(major: u32, minor: u32) -> [u32; 2] {
    if major < 256 && minor < 256 {
        [(major << 8) | minor, 0]
    } else {
        [0, encode_devnum(major, minor)]
    }
}

/// Inverse of [`device_to_i_block`]: `(major, minor)` from a char/block
/// inode's `i_block`, as `ext4_iget` reads it.
pub fn device_from_i_block(block: &[u32; N_BLOCKS]) -> (u32, u32) {
    if block[0] != 0 {
        ((block[0] >> 8) & 0xff, block[0] & 0xff)
    } else {
        decode_devnum(block[1])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regular_inode_roundtrip() {
        let ino = Inode::regular(12345, 0o644, 1000, 1000, 0xdeadbeef);
        let buf = ino.encode();
        let decoded = Inode::decode(&buf);
        assert_eq!(decoded.mode, ino.mode);
        assert_eq!(decoded.size, ino.size);
        assert_eq!(decoded.uid, ino.uid);
        assert_eq!(decoded.gid, ino.gid);
        assert_eq!(decoded.mtime, 0xdeadbeef);
        assert_eq!(decoded.links_count, 1);
        assert_eq!(decoded.mode & 0o170000, S_IFREG);
    }

    #[test]
    fn dir_inode_starts_with_two_links() {
        let ino = Inode::directory(1024, 0o755, 0, 0, 0);
        assert_eq!(ino.links_count, 2);
        assert_eq!(ino.mode & 0o170000, S_IFDIR);
    }

    /// Small numbers use the old layout in `i_block[0]`; anything wider
    /// moves to `i_block[1]`, as `ext4_write_inode` does. `/dev/sda1`
    /// (8, 1) is 0x0801 in word 0; (300, 70000) is word 1 only.
    #[test]
    fn device_numbers_use_the_kernels_two_word_layout() {
        assert_eq!(device_to_i_block(8, 1), [0x0801, 0]);
        assert_eq!(device_to_i_block(4, 64), [0x0440, 0]);
        assert_eq!(
            device_to_i_block(300, 70000),
            [0, encode_devnum(300, 70000)]
        );
        assert_eq!(device_to_i_block(8, 256), [0, encode_devnum(8, 256)]);
        for (maj, min) in [
            (0, 0),
            (1, 3),
            (8, 1),
            (255, 255),
            (256, 0),
            (8, 256),
            (300, 70000),
            (0xfff, 0xfffff),
        ] {
            let mut block = [0u32; N_BLOCKS];
            [block[0], block[1]] = device_to_i_block(maj, min);
            assert_eq!(device_from_i_block(&block), (maj, min));
        }
        // What the kernel wrote for mknod(…, makedev(300, 70000)).
        let mut block = [0u32; N_BLOCKS];
        block[1] = (70000 & 0xff) | (300 << 8) | ((70000 & !0xff) << 12);
        assert_eq!(device_from_i_block(&block), (300, 70000));
    }

    #[test]
    fn devnum_encoding_matches_kernel() {
        // null device: major=1, minor=3 → encoded value
        let v = encode_devnum(1, 3);
        // bits 0..7 = 3, bits 8..19 = 1 = 0x100, so v = 0x103
        assert_eq!(v, 0x103);

        // example with high minor bits
        let v = encode_devnum(8, 0x1234);
        // minor low 8 bits = 0x34, major in 8..19 = 8 << 8 = 0x800
        // minor high (0x1234 & 0xfff00) = 0x1200, shifted left 12 = 0x1200_000
        let expected: u32 = 0x34 | 0x800 | 0x0120_0000;
        assert_eq!(v, expected);
    }
}
