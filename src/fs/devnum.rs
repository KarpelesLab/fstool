//! Device-number packing shared by every backend that stores an `rdev`.
//!
//! Linux's "new" `dev_t` layout (what `makedev(3)` in glibc produces) is the
//! interchange form: ext stores it verbatim in `i_block[0]`, and tar, HFS+
//! and the in-memory ramfs adopt the same word so a device node survives a
//! round trip between any two backends unchanged.

/// Encode a (major, minor) into the Linux "new" device-number layout used
/// in inode `i_block[0]` for character and block devices.
///
/// Layout (matches `makedev(3)` in glibc):
///   bits  0..7   minor[0..8]
///   bits  8..19  major[0..12]
///   bits 20..31  minor[8..20]
pub fn encode_devnum(major: u32, minor: u32) -> u32 {
    (minor & 0xff) | ((major & 0xfff) << 8) | ((minor & 0xfff00) << 12)
}

/// Inverse of [`encode_devnum`]. Pulls `(major, minor)` out of an
/// ext-style devnum word stored in `inode.block[0]`.
pub fn decode_devnum(raw: u32) -> (u32, u32) {
    let major = (raw >> 8) & 0xfff;
    let minor = (raw & 0xff) | ((raw >> 12) & 0xfff00);
    (major, minor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnum_roundtrip() {
        for (maj, min) in [(1, 3), (8, 0), (0xfff, 0xfffff), (259, 1_000_000 & 0xfffff)] {
            assert_eq!(decode_devnum(encode_devnum(maj, min)), (maj, min));
        }
    }
}
