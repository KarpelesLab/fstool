//! CRC32C metadata checksums for the ext4 `metadata_csum` feature.
//!
//! When `RO_COMPAT_METADATA_CSUM` is set, every metadata structure carries a
//! CRC32C (Castagnoli) checksum. This module is the pure-function layer: it
//! computes the checksums; the read path validates them and the write path
//! stamps them.
//!
//! ## "Raw" CRC, not the finalised one
//!
//! ext4 chains its checksums with the kernel's `crc32c(crc, data)`, which is
//! the **raw running CRC** — it processes `data` starting from state `crc`
//! and returns the state directly, *without* the final `^ 0xFFFFFFFF` that
//! the standard CRC-32C check value applies. The `crc32c` crate exposes the
//! finalised form, so [`raw_update`] converts: it un-finalises the input,
//! appends, and un-finalises the output.
//!
//! ## Seeding
//!
//! Per-structure checksums chain after a filesystem-wide seed:
//!
//! - with the `metadata_csum_seed` feature → the explicit `s_checksum_seed`
//!   superblock field;
//! - otherwise → `raw_update(0xFFFFFFFF, filesystem_uuid)`.
//!
//! The **superblock** checksum is the exception: it is
//! `raw_update(0xFFFFFFFF, &sb[..1020])` directly — no UUID seed (the UUID
//! is part of the bytes being summed).
//!
//! References: <https://docs.kernel.org/filesystems/ext4/checksums.html>

/// CRC-32C initial / final-XOR constant.
const XOR: u32 = 0xFFFF_FFFF;

/// Raw CRC32C update: process `data` starting from running state `crc`,
/// returning the new running state. This is the kernel's `crc32c(crc, data)`.
///
/// Implemented on top of the `crc32c` crate's *finalised* `crc32c_append`:
/// `crc32c_append(c, d) == raw_update(c ^ XOR, d) ^ XOR`, so un-XOR the
/// input and the output to recover the raw form.
pub fn raw_update(crc: u32, data: &[u8]) -> u32 {
    crate::crc::crc32c_append(crc ^ XOR, data) ^ XOR
}

/// The filesystem-wide checksum seed. `csum_seed` is the explicit
/// `s_checksum_seed` superblock field when the `metadata_csum_seed` feature
/// is present (pass `Some`); otherwise it is derived from the UUID.
pub fn fs_seed(uuid: &[u8; 16], csum_seed: Option<u32>) -> u32 {
    csum_seed.unwrap_or_else(|| raw_update(XOR, uuid))
}

/// Superblock checksum: raw CRC32C over the first 1020 bytes (everything
/// before the 4-byte `s_checksum` field at offset 1020). `sb` must be the
/// full 1024-byte superblock image.
pub fn superblock(sb: &[u8]) -> u32 {
    debug_assert_eq!(sb.len(), 1024);
    raw_update(XOR, &sb[..1020])
}

/// Block- or inode-bitmap checksum: `raw_update(seed, bitmap_bytes)`. The
/// descriptor stores the low 16 bits (and, in a 64-byte descriptor, the
/// high 16 bits) of this value.
pub fn bitmap(seed: u32, bitmap_bytes: &[u8]) -> u32 {
    raw_update(seed, bitmap_bytes)
}

/// Group-descriptor checksum. The 16-bit `bg_checksum` field is computed
/// over the descriptor with that field zeroed, chained after the seed and
/// the little-endian group number.
///
/// `desc` is the descriptor bytes (32 or 64) with the `bg_checksum` field
/// already zeroed. Returns the 16-bit value to store.
pub fn group_desc(seed: u32, group: u32, desc: &[u8]) -> u16 {
    let c = raw_update(seed, &group.to_le_bytes());
    let c = raw_update(c, desc);
    (c & 0xffff) as u16
}

/// CRC-16 as e2fsprogs' `ext2fs_crc16` / the kernel's `crc16()`: the
/// reflected 0x8005 polynomial (table constant 0xA001), no final XOR,
/// running state passed in and returned (callers seed with `!0`).
pub fn crc16(mut crc: u16, data: &[u8]) -> u16 {
    for &b in data {
        crc ^= b as u16;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xA001
            } else {
                crc >> 1
            };
        }
    }
    crc
}

/// Group-descriptor checksum for the `uninit_bg` (`RO_COMPAT_GDT_CSUM`)
/// feature *without* `metadata_csum`: `crc16(~0, uuid)` → the
/// little-endian group number → the descriptor up to `bg_checksum`
/// (offset 0x1E) → for 64-byte descriptors, the bytes after the
/// checksum field (`0x20..desc_size`). Mirrors `ext4_group_desc_csum`.
pub fn group_desc_crc16(uuid: &[u8; 16], group: u32, desc: &[u8]) -> u16 {
    let c = crc16(!0, uuid);
    let c = crc16(c, &group.to_le_bytes());
    let c = crc16(c, &desc[..0x1E]);
    if desc.len() > 0x20 {
        crc16(c, &desc[0x20..])
    } else {
        c
    }
}

/// Inode checksum. Chained: seed → inode number → inode generation → the
/// inode body with both checksum fields zeroed. `inode` is the full on-disk
/// inode (`inode_size` bytes) with `i_checksum_lo` / `i_checksum_hi` zeroed.
/// Returns the full 32-bit value; the caller splits it into lo/hi.
pub fn inode(seed: u32, inode_num: u32, generation: u32, inode: &[u8]) -> u32 {
    let c = raw_update(seed, &inode_num.to_le_bytes());
    let c = raw_update(c, &generation.to_le_bytes());
    raw_update(c, inode)
}

/// Directory-leaf-block checksum. Chained: seed → inode number → inode
/// generation → the directory block bytes *before* the 12-byte checksum
/// dirent at the block tail. Pass `&block[..block_size - 12]`.
pub fn dir_block(seed: u32, dir_inode: u32, dir_generation: u32, block_before_tail: &[u8]) -> u32 {
    let c = raw_update(seed, &dir_inode.to_le_bytes());
    let c = raw_update(c, &dir_generation.to_le_bytes());
    raw_update(c, block_before_tail)
}

/// Extent-tree leaf/index block checksum (`ext4_extent_tail`). Chained:
/// seed → owning inode number → inode generation → the block bytes
/// *before* the trailing 4-byte `et_checksum`. Pass
/// `&block[..block_size - 4]`.
pub fn extent_tail(seed: u32, inode_num: u32, generation: u32, block_before_tail: &[u8]) -> u32 {
    let c = raw_update(seed, &inode_num.to_le_bytes());
    let c = raw_update(c, &generation.to_le_bytes());
    raw_update(c, block_before_tail)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The canonical CRC-32C check value: the *finalised* CRC32C of
    /// "123456789" is 0xE3069283. raw_update(XOR, x) is the un-finalised
    /// form, so it equals 0xE3069283 ^ XOR.
    #[test]
    fn raw_matches_known_check_value() {
        assert_eq!(raw_update(XOR, b"123456789"), 0xE306_9283 ^ XOR);
    }

    #[test]
    fn raw_update_chains() {
        // raw_update(raw_update(s, a), b) == raw_update(s, a ++ b)
        let a = b"hello, ";
        let b = b"world";
        let mut joined = Vec::new();
        joined.extend_from_slice(a);
        joined.extend_from_slice(b);
        assert_eq!(raw_update(raw_update(XOR, a), b), raw_update(XOR, &joined));
    }

    #[test]
    fn fs_seed_prefers_explicit() {
        let uuid = [0x42u8; 16];
        assert_eq!(fs_seed(&uuid, Some(0x1234_5678)), 0x1234_5678);
        assert_eq!(fs_seed(&uuid, None), raw_update(XOR, &uuid));
    }

    #[test]
    fn superblock_excludes_csum_field() {
        let mut sb_a = vec![0u8; 1024];
        let mut sb_b = vec![0u8; 1024];
        sb_a[10] = 0xAB;
        sb_b[10] = 0xAB;
        sb_a[1020..1024].copy_from_slice(&[1, 2, 3, 4]);
        sb_b[1020..1024].copy_from_slice(&[9, 9, 9, 9]);
        assert_eq!(superblock(&sb_a), superblock(&sb_b));
        sb_b[10] = 0xCD;
        assert_ne!(superblock(&sb_a), superblock(&sb_b));
    }

    #[test]
    fn group_desc_depends_on_group_number() {
        let seed = 0x1111_2222;
        let desc = [0u8; 64];
        // Different group numbers yield different descriptor checksums.
        assert_ne!(group_desc(seed, 0, &desc), group_desc(seed, 1, &desc));
    }

    /// CRC-16/MODBUS catalogue check value: reflected 0x8005, init
    /// 0xFFFF, no final XOR — exactly `ext2fs_crc16(~0, "123456789", 9)`.
    #[test]
    fn crc16_matches_catalogue_check_value() {
        assert_eq!(crc16(!0, b"123456789"), 0x4B37);
        // Chaining equals one-shot.
        assert_eq!(crc16(crc16(!0, b"1234"), b"56789"), 0x4B37);
    }

    #[test]
    fn group_desc_crc16_skips_the_checksum_field() {
        let uuid = [0x5Au8; 16];
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        a[0] = 1;
        b[0] = 1;
        a[0x1E] = 0xAA;
        b[0x1E] = 0x55; // differs only in bg_checksum
        assert_eq!(
            group_desc_crc16(&uuid, 3, &a),
            group_desc_crc16(&uuid, 3, &b)
        );
        // The tail past the checksum field IS covered for 64-byte descs.
        b[0x30] = 1;
        assert_ne!(
            group_desc_crc16(&uuid, 3, &a),
            group_desc_crc16(&uuid, 3, &b)
        );
        // And the group number matters.
        assert_ne!(
            group_desc_crc16(&uuid, 3, &a),
            group_desc_crc16(&uuid, 4, &a)
        );
    }

    #[test]
    fn inode_checksum_depends_on_number_and_generation() {
        let seed = 0xABCD_1234;
        let body = [0u8; 256];
        let base = inode(seed, 12, 0, &body);
        assert_ne!(base, inode(seed, 13, 0, &body));
        assert_ne!(base, inode(seed, 12, 1, &body));
    }
}
