//! F2FS NAT — Node Address Table.
//!
//! A NAT entry is `{ version: u8, ino: u32, block_addr: u32 }` (9 bytes).
//! 455 entries fit in one 4 KiB NAT page; the entry for nid `N` lives in
//! page `N / 455` at slot `N % 455`. Each logical page has two physical
//! copies for shadow paging, and they are interleaved *per segment*, not
//! split into two halves of the region: the logical page numbered
//! `q * blocks_per_seg + r` lives at offset `2 * q * blocks_per_seg + r`,
//! with its shadow one whole segment further on. Which of the pair is current is a per-page
//! bit in the checkpoint's NAT version bitmap. The function
//! [`current_nat_addr`] implements both rules exactly as the kernel
//! function of the same name does.
//!
//! Lookups consult the checkpoint's in-memory NAT journal first: any
//! `nid` present there is the freshest version regardless of what the
//! on-disk page says.
//!
//! Reference: kernel docs §"NAT" + FAST '15 §2.2.

use crate::Result;
use crate::block::BlockDevice;

use super::checkpoint::Checkpoint;
use super::constants::{F2FS_BLKSIZE, NAT_ENTRY_PER_BLOCK, NAT_ENTRY_SIZE};
use super::superblock::Superblock;

/// Resolved physical block address for a node id.
#[derive(Debug, Clone, Copy)]
pub struct NodeAddr {
    pub block: u32,
    pub version: u8,
    pub ino: u32,
}

/// Look up the on-disk block holding the node `nid`.
///
/// 1. Consult the checkpoint's NAT journal (newest in-memory state).
/// 2. Otherwise read the appropriate NAT page from the active pack and
///    decode the entry at `nid % 455`.
pub fn lookup_node(
    dev: &mut dyn BlockDevice,
    sb: &Superblock,
    cp: &Checkpoint,
    nid: u32,
) -> Result<NodeAddr> {
    if let Some(j) = cp.nat_journal_lookup(nid) {
        if j.block_addr == 0 {
            return Err(crate::Error::InvalidImage(format!(
                "f2fs: nid {nid} unallocated (journal block_addr=0)"
            )));
        }
        return Ok(NodeAddr {
            block: j.block_addr,
            version: j.version,
            ino: j.ino,
        });
    }

    let bs = sb.block_size() as u64;
    let slot = (nid as usize) % NAT_ENTRY_PER_BLOCK;
    let phys_page = current_nat_addr(sb, cp, nid)?;

    let mut page = vec![0u8; F2FS_BLKSIZE];
    dev.read_at(phys_page as u64 * bs, &mut page)?;

    let o = slot * NAT_ENTRY_SIZE;
    if o + NAT_ENTRY_SIZE > page.len() {
        return Err(crate::Error::InvalidImage(
            "f2fs: NAT slot past end of page".into(),
        ));
    }
    let version = page[o];
    let ino = u32::from_le_bytes(page[o + 1..o + 5].try_into().unwrap());
    let block_addr = u32::from_le_bytes(page[o + 5..o + 9].try_into().unwrap());
    if block_addr == 0 {
        return Err(crate::Error::InvalidImage(format!(
            "f2fs: nid {nid} has block_addr=0 (unallocated)"
        )));
    }
    Ok(NodeAddr {
        block: block_addr,
        version,
        ino,
    })
}

/// Test the `block_off`-th bit of an f2fs version bitmap.
///
/// f2fs numbers bits inside a byte MSB-first (`f2fs_test_bit()` in
/// `fs/f2fs/f2fs.h` masks `BIT(7 - (nr & 7))`), which is the opposite of
/// the kernel's generic little-endian bitops. A bit past the end of the
/// bitmap reads as clear, the same as a freshly formatted volume.
fn f2fs_test_bit(block_off: u32, bitmap: &[u8]) -> bool {
    let byte = (block_off >> 3) as usize;
    match bitmap.get(byte) {
        Some(b) => b & (1 << (7 - (block_off & 7))) != 0,
        None => false,
    }
}

/// Physical block holding the current copy of the NAT page that owns
/// `nid` — the kernel's `current_nat_addr()`:
///
/// ```text
/// block_off = nid / NAT_ENTRY_PER_BLOCK
/// addr      = nat_blkaddr + (block_off << 1) - (block_off % blocks_per_seg)
/// if test_bit(block_off, nat_bitmap) { addr += blocks_per_seg }
/// ```
///
/// The subtraction is what makes the two copies interleave a segment at
/// a time instead of splitting the region into halves: logical page
/// `q * blocks_per_seg + r` lands in segment `2q` at offset `r`, its
/// shadow in segment `2q + 1`.
pub fn current_nat_addr(sb: &Superblock, cp: &Checkpoint, nid: u32) -> Result<u32> {
    let blocks_per_seg = sb.blocks_per_seg();
    let block_off = nid / NAT_ENTRY_PER_BLOCK as u32;
    // `segment_count_nat`, `blocks_per_seg` and `nat_blkaddr` are all
    // untrusted; use checked arithmetic so a crafted superblock can't
    // overflow into a bogus (but in-bounds-looking) physical page.
    let nat_total_blocks = sb
        .segment_count_nat
        .checked_mul(blocks_per_seg)
        .ok_or_else(|| crate::Error::InvalidImage("f2fs: NAT geometry overflow".into()))?;
    let mut nat_offset = block_off
        .checked_mul(2)
        .map(|x| x - (block_off & (blocks_per_seg - 1)))
        .ok_or_else(|| crate::Error::InvalidImage("f2fs: NAT page index overflow".into()))?;
    if f2fs_test_bit(block_off, &cp.nat_bitmap) {
        nat_offset = nat_offset
            .checked_add(blocks_per_seg)
            .ok_or_else(|| crate::Error::InvalidImage("f2fs: NAT page index overflow".into()))?;
    }
    if nat_offset >= nat_total_blocks {
        return Err(crate::Error::InvalidImage(format!(
            "f2fs: nid {nid} out of NAT range"
        )));
    }
    sb.nat_blkaddr
        .checked_add(nat_offset)
        .ok_or_else(|| crate::Error::InvalidImage("f2fs: NAT page address overflow".into()))
}

/// Encode a single NAT entry into a page slot. Test helper that mirrors
/// the decoder above so the on-disk layout stays in sync.
#[cfg(test)]
pub(crate) fn encode_nat_entry(page: &mut [u8], slot: usize, version: u8, ino: u32, block: u32) {
    let o = slot * NAT_ENTRY_SIZE;
    page[o] = version;
    page[o + 1..o + 5].copy_from_slice(&ino.to_le_bytes());
    page[o + 5..o + 9].copy_from_slice(&block.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A superblock with just the geometry `current_nat_addr` reads.
    fn sb_with(log_bps: u32, segment_count_nat: u32, nat_blkaddr: u32) -> Superblock {
        Superblock {
            magic: super::super::superblock::F2FS_MAGIC,
            major_ver: 1,
            minor_ver: 15,
            log_sectorsize: 9,
            log_blocksize: 12,
            log_blocks_per_seg: log_bps,
            segs_per_sec: 1,
            secs_per_zone: 1,
            block_count: 1 << 20,
            segment_count: 64,
            segment_count_ckpt: 2,
            segment_count_sit: 2,
            segment_count_nat,
            segment_count_ssa: 1,
            segment_count_main: 16,
            segment0_blkaddr: 2,
            cp_blkaddr: 2,
            sit_blkaddr: 0,
            nat_blkaddr,
            ssa_blkaddr: 0,
            main_blkaddr: 0,
            root_ino: 3,
            node_ino: 1,
            meta_ino: 2,
            cp_payload: 0,
            volume_name: String::new(),
        }
    }

    fn cp_with_bitmap(bitmap: Vec<u8>) -> Checkpoint {
        Checkpoint {
            version: 1,
            user_block_count: 0,
            valid_block_count: 0,
            rsvd_segment_count: 0,
            overprov_segment_count: 0,
            flags: 0,
            cp_pack_start_sum: 1,
            cp_pack_total_block_count: 8,
            cp_payload: 0,
            head_blkaddr: 2,
            nat_ver_bitmap_bytesize: bitmap.len() as u32,
            sit_ver_bitmap_bytesize: 0,
            cur_nat_pack: 0,
            cur_sit_pack: 0,
            nat_bitmap: bitmap,
            nat_journal: Vec::new(),
            cur_node_segno: [0; 3],
            cur_node_blkoff: [0; 3],
            cur_data_segno: [0; 3],
            cur_data_blkoff: [0; 3],
            free_segment_count: 0,
            valid_node_count: 0,
            valid_inode_count: 0,
            next_free_nid: 0,
        }
    }

    /// The two copies of a NAT page interleave one segment at a time.
    /// Splitting the region into halves (what this used to do) agrees
    /// only while the NAT is exactly two segments — at four it puts
    /// every page of the second segment in the wrong place.
    #[test]
    fn nat_pages_interleave_per_segment() {
        let bps = 512u32;
        let sb = sb_with(9, 4, 100);
        let cp = cp_with_bitmap(Vec::new());
        let nid_of = |block_off: u32| block_off * NAT_ENTRY_PER_BLOCK as u32;
        for (block_off, want) in [(0u32, 100u32), (1, 101), (511, 611)] {
            assert_eq!(current_nat_addr(&sb, &cp, nid_of(block_off)).unwrap(), want);
        }
        // Second logical segment: 2 * 512 + r, i.e. a whole segment of
        // shadow pages is skipped over first.
        assert_eq!(current_nat_addr(&sb, &cp, nid_of(512)).unwrap(), 100 + 1024);
        assert_eq!(
            current_nat_addr(&sb, &cp, nid_of(600)).unwrap(),
            100 + 1024 + 88
        );
        // A set bit selects the shadow copy one segment further on.
        let mut bitmap = vec![0u8; 128];
        bitmap[0] = 0x80; // block_off 0, MSB-first
        bitmap[75] = 0x80; // block_off 600
        let cp = cp_with_bitmap(bitmap);
        assert_eq!(current_nat_addr(&sb, &cp, nid_of(0)).unwrap(), 100 + bps);
        assert_eq!(current_nat_addr(&sb, &cp, nid_of(1)).unwrap(), 101);
        assert_eq!(
            current_nat_addr(&sb, &cp, nid_of(600)).unwrap(),
            100 + 1024 + 88 + bps
        );
    }

    /// A nid whose page would fall outside the NAT region is rejected
    /// rather than read from whatever follows it.
    #[test]
    fn nat_page_past_the_region_is_rejected() {
        let sb = sb_with(9, 2, 100);
        let cp = cp_with_bitmap(Vec::new());
        // 2 segments = 1024 blocks; logical page 512 would need 1024.
        let nid = 512 * NAT_ENTRY_PER_BLOCK as u32;
        assert!(current_nat_addr(&sb, &cp, nid).is_err());
    }

    /// f2fs numbers version-bitmap bits MSB-first inside each byte.
    #[test]
    fn version_bitmap_bits_are_msb_first() {
        let bitmap = [0b1000_0001u8, 0b0100_0000];
        assert!(f2fs_test_bit(0, &bitmap));
        assert!(!f2fs_test_bit(1, &bitmap));
        assert!(f2fs_test_bit(7, &bitmap));
        assert!(f2fs_test_bit(9, &bitmap));
        // Past the end reads as clear.
        assert!(!f2fs_test_bit(16, &bitmap));
    }
}
