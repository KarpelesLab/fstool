//! littlefs metadata tags — the 32-bit words that describe every piece of
//! metadata on disk, plus the CRC-32 variant commits are checksummed with.
//!
//! A tag packs four fields into its 32 bits (upstream's `SPEC.md`,
//! "Metadata tags", is the reference for the layout):
//!
//! ```text
//!   bit  31     valid bit — clear on a real tag, set on unwritten storage
//!   bits 30..20 type3: a 3-bit abstract type (type1) then an 8-bit chunk
//!   bits 19..10 id: the file this tag belongs to (0x3ff = none)
//!   bits  9..0  length of the tag's data (0x3ff = deleted, no data)
//! ```
//!
//! Tags are the only thing littlefs stores big-endian (the valid bit has to
//! be the first bit of a commit), and each stored word is XORed with the
//! previous tag so a metadata block can be walked in either direction. The
//! first tag of a block is XORed with `0xffffffff`.

/// Value the running "previous tag" starts at, both when parsing and when
/// building a commit.
pub const PTAG_INIT: u32 = 0xffff_ffff;

/// `id` value used by tags that belong to the metadata block rather than to
/// any single file (tails, global state, commit CRCs).
pub const ID_NONE: u16 = 0x3ff;

/// `size` value marking a deleted attribute — such a tag carries no data.
pub const SIZE_DELETED: u16 = 0x3ff;

/// Largest payload a single tag can carry (the 10-bit size field, minus the
/// reserved "deleted" value).
pub const MAX_SIZE: usize = 0x3fe;

// type3 values. The upper 3 bits are the abstract type (type1), the lower
// 8 the chunk field.
/// Name tag; the chunk field carries the file type (`TYPE_REG` etc.).
pub const TYPE_NAME: u16 = 0x000;
/// Regular file.
pub const TYPE_REG: u16 = 0x001;
/// Directory.
pub const TYPE_DIR: u16 = 0x002;
/// Superblock entry — the name tag whose data is the magic `"littlefs"`.
pub const TYPE_SUPERBLOCK: u16 = 0x0ff;
/// Struct tag: directory (data is the 8-byte metadata pair).
pub const TYPE_DIRSTRUCT: u16 = 0x200;
/// Struct tag: inline data (data is the file contents).
pub const TYPE_INLINESTRUCT: u16 = 0x201;
/// Struct tag: CTZ skip-list (data is head block + file size).
pub const TYPE_CTZSTRUCT: u16 = 0x202;
/// User attribute; the chunk field is the caller-defined attribute type.
pub const TYPE_USERATTR: u16 = 0x300;
/// Splice: create a file id, shifting later ids up.
pub const TYPE_CREATE: u16 = 0x401;
/// Splice: delete a file id, shifting later ids down.
pub const TYPE_DELETE: u16 = 0x4ff;
/// Commit CRC. The low chunk bit selects the valid-bit state the *next*
/// commit's tags must have.
pub const TYPE_CCRC: u16 = 0x500;
/// Forward CRC (lfs2.1): checksum of the erased bytes following this commit.
pub const TYPE_FCRC: u16 = 0x5ff;
/// Soft tail — next metadata pair in the filesystem-wide threaded list.
pub const TYPE_SOFTTAIL: u16 = 0x600;
/// Hard tail — next metadata pair of *this* directory.
pub const TYPE_HARDTAIL: u16 = 0x601;
/// Global-state delta (move state).
pub const TYPE_MOVESTATE: u16 = 0x7ff;

// type1 values, as produced by [`Tag::type1`].
/// type1 of name tags.
pub const T1_NAME: u16 = 0x000;
/// type1 of struct tags.
pub const T1_STRUCT: u16 = 0x200;
/// type1 of user-attribute tags.
pub const T1_USERATTR: u16 = 0x300;
/// type1 of splice (create / delete) tags.
pub const T1_SPLICE: u16 = 0x400;
/// type1 of CRC tags (both commit CRCs and FCRCs).
pub const T1_CRC: u16 = 0x500;
/// type1 of tail tags.
pub const T1_TAIL: u16 = 0x600;
/// type1 of global-state tags.
pub const T1_GSTATE: u16 = 0x700;

/// A decoded metadata tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tag(pub u32);

impl Tag {
    /// Build a tag from its three fields. The valid bit is left clear, which
    /// is what both the parser and the commit builder expect.
    pub fn new(type3: u16, id: u16, size: u16) -> Self {
        Self(((type3 as u32) << 20) | ((id as u32) << 10) | size as u32)
    }

    /// A tag is valid when its high bit is clear. An unwritten (or
    /// power-cut) region decodes to a tag with the bit set, which is how
    /// littlefs finds the end of a metadata log.
    pub fn is_valid(self) -> bool {
        self.0 & 0x8000_0000 == 0
    }

    /// 3-bit abstract type, shifted into the same position `type3` uses so
    /// the two can be compared against the `T1_*` constants directly.
    pub fn type1(self) -> u16 {
        ((self.0 & 0x7000_0000) >> 20) as u16
    }

    /// type1 plus the top bit of the chunk field. Commit CRCs are matched on
    /// this so that FCRC (`0x5ff`) is *not* mistaken for a commit CRC
    /// (`0x50x`) — the distinction lfs2.1 relies on.
    pub fn type2(self) -> u16 {
        ((self.0 & 0x7800_0000) >> 20) as u16
    }

    /// Full 11-bit type.
    pub fn type3(self) -> u16 {
        ((self.0 & 0x7ff0_0000) >> 20) as u16
    }

    /// 8-bit chunk field (file type for names, attribute type for user
    /// attributes, tail flavour for tails, …).
    pub fn chunk(self) -> u8 {
        ((self.0 & 0x0ff0_0000) >> 20) as u8
    }

    /// File id this tag belongs to, or [`ID_NONE`] for block-level tags.
    pub fn id(self) -> u16 {
        ((self.0 & 0x000f_fc00) >> 10) as u16
    }

    /// Length of the tag's data in bytes (meaningless when [`Self::is_delete`]).
    pub fn size(self) -> u16 {
        (self.0 & 0x0000_03ff) as u16
    }

    /// Whether this tag marks the attribute deleted (size field all ones).
    pub fn is_delete(self) -> bool {
        self.size() == SIZE_DELETED
    }

    /// Total on-disk size of the tag: the 4-byte word plus its data. A
    /// deleted tag carries no data.
    pub fn dsize(self) -> usize {
        4 + if self.is_delete() {
            0
        } else {
            self.size() as usize
        }
    }
}

/// littlefs's CRC-32: polynomial `0x04c11db7`, initialised with
/// `0xffffffff`, and — unlike the usual zlib flavour — **no final XOR**, so
/// the running state can be fed straight back in for the next chunk.
///
/// `crc32fast` computes the finalised (XOR-ed) form, so we un-XOR on the way
/// in and re-XOR on the way out. The `crc_matches_reference` test pins this
/// against a commit CRC taken from an image written by the C implementation.
pub fn crc(state: u32, data: &[u8]) -> u32 {
    let mut h = crc32fast::Hasher::new_with_initial(state ^ 0xffff_ffff);
    h.update(data);
    h.finalize() ^ 0xffff_ffff
}

/// Read a big-endian tag word.
pub fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// Read a little-endian word (everything in littlefs except tags).
pub fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// Sequence comparison of two revision counts, tolerant of wraparound:
/// `true` when `a` is newer than `b`.
pub fn rev_newer(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b)) as i32 > 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_fields_round_trip() {
        let t = Tag::new(TYPE_INLINESTRUCT, 3, 24);
        assert_eq!(t.type3(), TYPE_INLINESTRUCT);
        assert_eq!(t.type1(), T1_STRUCT);
        assert_eq!(t.chunk(), 0x01);
        assert_eq!(t.id(), 3);
        assert_eq!(t.size(), 24);
        assert_eq!(t.dsize(), 28);
        assert!(t.is_valid());
        assert!(!t.is_delete());
    }

    #[test]
    fn deleted_tag_carries_no_data() {
        let t = Tag::new(TYPE_USERATTR | 0x42, 1, SIZE_DELETED);
        assert!(t.is_delete());
        assert_eq!(t.dsize(), 4);
    }

    #[test]
    fn fcrc_is_not_a_commit_crc() {
        // lfs2.1 relies on type2 (not type1) to tell an FCRC apart from the
        // commit CRC that ends every commit — get this wrong and every
        // fetch of a modern image stops at the first FCRC.
        assert_eq!(Tag::new(TYPE_CCRC, ID_NONE, 4).type2(), 0x500);
        assert_ne!(Tag::new(TYPE_FCRC, ID_NONE, 8).type2(), 0x500);
        assert_eq!(Tag::new(TYPE_FCRC, ID_NONE, 8).type1(), T1_CRC);
    }

    #[test]
    fn crc_matches_reference() {
        // The first commit of a littlefs image formatted by the C library:
        // revision count, superblock name tag + "littlefs", inline-struct
        // tag + config, FCRC tag, and the commit-CRC tag itself. The stored
        // CRC that follows those bytes is 0xa52fadb2.
        let mut b = Vec::new();
        b.extend_from_slice(&0u32.to_le_bytes()); // rev
        b.extend_from_slice(&[0xf0, 0x0f, 0xff, 0xf7]); // superblock name tag
        b.extend_from_slice(b"littlefs");
        b.extend_from_slice(&[0x2f, 0xe0, 0x00, 0x10]); // inline-struct tag
        b.extend_from_slice(&[
            0x01, 0x00, 0x02, 0x00, // version 2.1
            0x00, 0x10, 0x00, 0x00, // block size 4096
            0x20, 0x00, 0x00, 0x00, // block count 32
            0xff, 0x00, 0x00, 0x00, // name max
            0xff, 0xff, 0xff, 0x7f, // file max
            0xfe, 0x03, 0x00, 0x00, // attr max
        ]);
        b.extend_from_slice(&[0x7f, 0xef, 0xfc, 0x10]); // fcrc tag
        b.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0xde, 0x57, 0x57, 0x01]);
        b.extend_from_slice(&[0x0f, 0xf0, 0x00, 0xcc]); // ccrc tag
        assert_eq!(crc(PTAG_INIT, &b), 0xa52f_adb2);
    }

    #[test]
    fn revision_compare_handles_wraparound() {
        assert!(rev_newer(2, 1));
        assert!(!rev_newer(1, 2));
        assert!(rev_newer(0, u32::MAX));
    }
}
