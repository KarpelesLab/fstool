//! The exFAT specification's recommended Up-case Table, in its compressed
//! form (Microsoft exFAT specification §7.2.5.1, "Recommended Up-case
//! Table in compressed format").
//!
//! 2 918 little-endian u16 values — 5 836 bytes — whose TableChecksum is
//! `0xE619D30D`. The compression is the spec's: `0xFFFF, n` means "the
//! next `n` code points map to themselves"; any other value is the
//! up-case of the current code point. The final value is a literal
//! `0xFFFF` (U+FFFF maps to itself) with no count after it.
//!
//! This is the table `mkfs.exfat`, `newfs_exfat` and Windows write, so a
//! volume formatted here compares names exactly as one formatted anywhere
//! else. The bytes are pure data (a Unicode simple case mapping published
//! in the specification) and are checked by length and checksum below.
//!
//! Both formatters — the allocation-free [`Volume`](super::Volume) one and
//! the hosted [`Exfat`](super::Exfat) one — write it, so it lives here,
//! available with or without `alloc`.

/// The recommended compressed up-case table.
pub(crate) static UPCASE_TABLE: &[u8; UPCASE_TABLE_LEN] = include_bytes!("upcase_table.bin");

/// Its length in bytes: the up-case directory entry's DataLength.
pub(crate) const UPCASE_TABLE_LEN: usize = 5836;

/// Its TableChecksum, as the up-case directory entry records it.
pub(crate) const UPCASE_TABLE_CHECKSUM: u32 = 0xE619_D30D;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_and_checksum_match_the_specification() {
        assert_eq!(UPCASE_TABLE.len(), 5836);
        assert_eq!(UPCASE_TABLE.len() / 2, 2918);
        assert_eq!(
            super::super::layout::table_checksum(UPCASE_TABLE),
            UPCASE_TABLE_CHECKSUM
        );
        // Ends with a literal 0xFFFF (U+FFFF → U+FFFF), not a run marker.
        assert_eq!(&UPCASE_TABLE[UPCASE_TABLE_LEN - 2..], &[0xFF, 0xFF]);
    }
}
