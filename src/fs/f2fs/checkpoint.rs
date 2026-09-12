//! F2FS checkpoint pack discovery + parsing.
//!
//! F2FS keeps two checkpoint packs (CP0 and CP1), one segment apart.
//! Each pack opens with a `f2fs_checkpoint` block, has zero or more
//! `cp_payload` bitmap pages, then a NAT-journal-bearing summary block
//! (the "cp_pack_start_sum"), some more summary blocks, and a footer
//! that mirrors the header. We pick whichever pack has the higher
//! `checkpoint_ver` AND validates its head-block CRC32.
//!
//! Reference: kernel docs §"Checkpoint" + FAST '15 §2.7.

use crate::Result;
use crate::block::BlockDevice;

use super::constants::{
    CP_CHKSUM_OFFSET, CP_COMPACT_SUM_FLAG, CP_LARGE_NAT_BITMAP_FLAG, CP_MIN_CHKSUM_OFFSET,
    F2FS_BLK_CSUM_OFFSET, F2FS_BLKSIZE, NAT_JOURNAL_ENTRIES, NAT_JOURNAL_ENTRY_SIZE,
    SUM_ENTRY_SIZE,
};
use super::superblock::Superblock;

/// Logical view of a parsed checkpoint pack head.
#[derive(Debug, Clone)]
pub struct Checkpoint {
    /// `checkpoint_ver` — monotonically increasing, used to pick the live pack.
    pub version: u64,
    /// `user_block_count`.
    pub user_block_count: u64,
    /// `valid_block_count`.
    pub valid_block_count: u64,
    /// `rsvd_segment_count` — segments reserved for GC. fsck.f2fs (and
    /// the kernel) refuse a CP that reports zero on a non-RO volume.
    pub rsvd_segment_count: u32,
    /// `overprov_segment_count` — over-provisioned segments. Same
    /// non-zero requirement as `rsvd_segment_count`.
    pub overprov_segment_count: u32,
    /// Bitfield of `CP_*_FLAG` bits.
    pub flags: u32,
    /// First block within this CP pack that holds summary data (where the
    /// NAT journal lives).
    pub cp_pack_start_sum: u32,
    /// `cp_pack_total_block_count` — total length of the pack in blocks.
    pub cp_pack_total_block_count: u32,
    /// CP payload count (overflow bitmap pages between the head block and
    /// the first summary block); typically 0 for small images.
    pub cp_payload: u32,
    /// Absolute block address of the head block we picked.
    pub head_blkaddr: u32,
    /// `nat_ver_bitmap` length in bytes (variable per image — kept so the
    /// NAT bitmap pages can be located if we ever need them).
    pub nat_ver_bitmap_bytesize: u32,
    /// `sit_ver_bitmap` length in bytes.
    pub sit_ver_bitmap_bytesize: u32,
    /// 0 or 1 — which copy of the NAT is current (cleared bits in the
    /// per-block bitmap select the alternate page).
    pub cur_nat_pack: u8,
    /// 0 or 1 — which copy of the SIT is current.
    pub cur_sit_pack: u8,
    /// The NAT version bitmap, one bit per logical NAT page, selecting
    /// which of that page's two physical copies is current. Located per
    /// `__bitmap_ptr(NAT_BITMAP)`; empty when the CP declares no bitmap.
    pub nat_bitmap: Vec<u8>,
    /// Raw NAT journal entries: list of `(nid, ino, block_addr, version)`
    /// pulled from the cp_pack_start_sum block. Newer than the on-disk
    /// NAT pages and must be consulted first.
    pub nat_journal: Vec<NatJournalEntry>,
    /// `cur_node_segno[3]` — main-area segments currently in use for
    /// hot / warm / cold node blocks. Writer leaves the upper 5 slots
    /// (kernel size is `[8]`) zero.
    pub cur_node_segno: [u32; 3],
    /// `cur_node_blkoff[3]` — next free block within each node curseg.
    pub cur_node_blkoff: [u16; 3],
    /// `cur_data_segno[3]` / `cur_data_blkoff[3]` — same for data.
    pub cur_data_segno: [u32; 3],
    pub cur_data_blkoff: [u16; 3],
    /// `free_segment_count` (offset 0x20) — number of main-area segments
    /// with `valid_blocks == 0` that aren't currently a curseg.
    pub free_segment_count: u32,
    /// `valid_node_count` (offset 0x90) — total active NAT entries.
    pub valid_node_count: u32,
    /// `valid_inode_count` (offset 0x94) — number of actual inodes
    /// (= node entries that have S_IFMT set and a footer.ino == nid).
    pub valid_inode_count: u32,
    /// `next_free_nid` (offset 0x98) — first NAT slot not allocated.
    pub next_free_nid: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct NatJournalEntry {
    pub nid: u32,
    pub ino: u32,
    pub block_addr: u32,
    pub version: u8,
}

impl Checkpoint {
    /// Iterate both candidate CP packs, pick the one with the higher
    /// `checkpoint_ver` whose CRC32 validates.
    pub fn load(dev: &mut dyn BlockDevice, sb: &Superblock) -> Result<Self> {
        let bs = sb.block_size() as u64;
        let blocks_per_seg = sb.blocks_per_seg();
        let cp0_blk = sb.cp_blkaddr;
        let cp1_blk = sb
            .cp_blkaddr
            .checked_add(blocks_per_seg)
            .ok_or_else(|| crate::Error::InvalidImage("f2fs: cp_blkaddr overflow".into()))?;

        let mut cp0 = Self::try_load(dev, sb, cp0_blk).ok();
        let mut cp1 = Self::try_load(dev, sb, cp1_blk).ok();

        // `cur_*_pack` flips depending on which CP we ended up using.
        if let Some(c) = cp0.as_mut() {
            c.cur_nat_pack = 0;
            c.cur_sit_pack = 0;
        }
        if let Some(c) = cp1.as_mut() {
            c.cur_nat_pack = 1;
            c.cur_sit_pack = 1;
        }

        let _ = bs; // (silence unused if optimizer skips it on debug)

        match (cp0, cp1) {
            (Some(a), Some(b)) => Ok(if b.version > a.version { b } else { a }),
            (Some(a), None) => Ok(a),
            (None, Some(b)) => Ok(b),
            (None, None) => Err(crate::Error::InvalidImage(
                "f2fs: neither checkpoint pack validates".into(),
            )),
        }
    }

    /// Read + validate a single CP head block + the NAT journal that
    /// follows it.
    fn try_load(dev: &mut dyn BlockDevice, sb: &Superblock, head_blkaddr: u32) -> Result<Self> {
        let bs = sb.block_size() as u64;
        let mut head = vec![0u8; F2FS_BLKSIZE];
        dev.read_at(head_blkaddr as u64 * bs, &mut head)?;
        let cp = decode_cp_head(&head, head_blkaddr)?;

        // The CRC lives at the byte offset given by the on-disk
        // `checksum_offset` field (at +0xA4). `get_checkpoint_version()`
        // rejects anything outside
        // `[CP_MIN_CHKSUM_OFFSET, CP_CHKSUM_OFFSET]`.
        let crc_off = u32::from_le_bytes(head[0xA4..0xA8].try_into().unwrap()) as usize;
        if !(CP_MIN_CHKSUM_OFFSET..=CP_CHKSUM_OFFSET).contains(&crc_off) {
            return Err(crate::Error::InvalidImage(format!(
                "f2fs: cp@{head_blkaddr}: checksum_offset {crc_off} out of range"
            )));
        }
        let want = u32::from_le_bytes(head[crc_off..crc_off + 4].try_into().unwrap());
        let got = cp_chksum(&head, crc_off);
        if got != want {
            return Err(crate::Error::InvalidImage(format!(
                "f2fs: cp@{head_blkaddr}: crc mismatch (want {want:08x}, got {got:08x})"
            )));
        }

        // The NAT journal lives in the pack's first summary block
        // (`cp_pack_start_sum`). With CP_COMPACT_SUM_FLAG that block is
        // a bare pair of journals and the NAT one starts at byte 0
        // (`read_compacted_summaries`); otherwise the block is the
        // HOT_DATA `f2fs_summary_block` and its `journal` member sits
        // after the 512 summary entries, at SUM_ENTRY_SIZE.
        let sum_block = head_blkaddr
            .checked_add(cp.cp_pack_start_sum)
            .ok_or_else(|| crate::Error::InvalidImage("f2fs: cp summary overflow".into()))?;
        let mut sumbuf = vec![0u8; F2FS_BLKSIZE];
        dev.read_at(sum_block as u64 * bs, &mut sumbuf)?;
        let compact = cp.flags & CP_COMPACT_SUM_FLAG != 0;
        let nat_journal = decode_nat_journal(&sumbuf, compact);

        let mut out = cp;
        out.cp_payload = sb.cp_payload;
        out.nat_bitmap = load_nat_bitmap(dev, sb, &head, &out)?;
        out.nat_journal = nat_journal;
        Ok(out)
    }

    /// Convenience: look up the journal-cached NAT entry for `nid`.
    pub fn nat_journal_lookup(&self, nid: u32) -> Option<NatJournalEntry> {
        self.nat_journal.iter().copied().find(|e| e.nid == nid)
    }
}

/// Decode the leading region of a CP head block. The block is 4 KiB.
///
/// Field offsets follow `struct f2fs_checkpoint` in `include/linux/f2fs_fs.h`:
/// ```text
/// 0x00  __le64 checkpoint_ver
/// 0x08  __le64 user_block_count
/// 0x10  __le64 valid_block_count
/// 0x18  __le32 rsvd_segment_count
/// 0x1C  __le32 overprov_segment_count
/// 0x20  __le32 free_segment_count
/// 0x24..0x44  __le32 cur_node_segno[8]
/// 0x44..0x54  __le16 cur_node_blkoff[8]
/// 0x54..0x74  __le32 cur_data_segno[8]
/// 0x74..0x84  __le16 cur_data_blkoff[8]
/// 0x84  __le32 ckpt_flags
/// 0x88  __le32 cp_pack_total_block_count
/// 0x8C  __le32 cp_pack_start_sum
/// 0x90  __le32 valid_node_count
/// 0x94  __le32 valid_inode_count
/// 0x98  __le32 next_free_nid
/// 0x9C  __le32 sit_ver_bitmap_bytesize
/// 0xA0  __le32 nat_ver_bitmap_bytesize
/// 0xA4  __le32 checksum_offset
/// ```
fn decode_cp_head(buf: &[u8], head_blkaddr: u32) -> Result<Checkpoint> {
    if buf.len() < F2FS_BLKSIZE {
        return Err(crate::Error::InvalidImage(
            "f2fs: short read on CP head".into(),
        ));
    }
    let r32 = |o: usize| u32::from_le_bytes(buf[o..o + 4].try_into().unwrap());
    let r64 = |o: usize| u64::from_le_bytes(buf[o..o + 8].try_into().unwrap());

    let version = r64(0x00);
    let user_block_count = r64(0x08);
    let valid_block_count = r64(0x10);
    let rsvd_segment_count = r32(0x18);
    let overprov_segment_count = r32(0x1C);
    let ckpt_flags = r32(0x84);
    let cp_pack_total_block_count = r32(0x88);
    let cp_pack_start_sum = r32(0x8C);
    let sit_ver_bitmap_bytesize = r32(0x9C);
    let nat_ver_bitmap_bytesize = r32(0xA0);
    // 0xA4 checksum_offset — used to locate the CRC at `try_load`.
    let r16 = |o: usize| u16::from_le_bytes(buf[o..o + 2].try_into().unwrap());
    let cur_node_segno = [r32(0x24), r32(0x28), r32(0x2C)];
    let cur_node_blkoff = [r16(0x44), r16(0x46), r16(0x48)];
    let cur_data_segno = [r32(0x54), r32(0x58), r32(0x5C)];
    let cur_data_blkoff = [r16(0x74), r16(0x76), r16(0x78)];
    let free_segment_count = r32(0x20);
    let valid_node_count = r32(0x90);
    let valid_inode_count = r32(0x94);
    let next_free_nid = r32(0x98);

    Ok(Checkpoint {
        version,
        user_block_count,
        valid_block_count,
        rsvd_segment_count,
        overprov_segment_count,
        flags: ckpt_flags,
        cp_pack_start_sum,
        cp_pack_total_block_count,
        // `cp_payload` is a superblock field, not a CP field. The reader
        // gets it from `Superblock::cp_payload` instead.
        cp_payload: 0,
        head_blkaddr,
        nat_ver_bitmap_bytesize,
        sit_ver_bitmap_bytesize,
        cur_nat_pack: 0,
        cur_sit_pack: 0,
        nat_bitmap: Vec::new(),
        nat_journal: Vec::new(),
        cur_node_segno,
        cur_node_blkoff,
        cur_data_segno,
        cur_data_blkoff,
        free_segment_count,
        valid_node_count,
        valid_inode_count,
        next_free_nid,
    })
}

/// Offset of `f2fs_checkpoint::sit_nat_version_bitmap`.
const SIT_NAT_VERSION_BITMAP_OFFSET: usize = 0xC0;

/// Read the NAT version bitmap out of a CP pack, following
/// `__bitmap_ptr(sbi, NAT_BITMAP)`:
///
/// - with `CP_LARGE_NAT_BITMAP_FLAG` the bitmaps are checksum-protected
///   and the NAT one starts one `__le32` past the bitmap area;
/// - with `cp_payload > 0` the NAT bitmap starts at the bitmap area and
///   may run on into the payload blocks that follow the head block;
/// - otherwise the SIT bitmap comes first and the NAT one follows it.
fn load_nat_bitmap(
    dev: &mut dyn BlockDevice,
    sb: &Superblock,
    head: &[u8],
    cp: &Checkpoint,
) -> Result<Vec<u8>> {
    let len = cp.nat_ver_bitmap_bytesize as usize;
    if len == 0 {
        return Ok(Vec::new());
    }
    let large = cp.flags & CP_LARGE_NAT_BITMAP_FLAG != 0;
    let start = if large {
        SIT_NAT_VERSION_BITMAP_OFFSET + 4
    } else if cp.cp_payload > 0 {
        SIT_NAT_VERSION_BITMAP_OFFSET
    } else {
        SIT_NAT_VERSION_BITMAP_OFFSET + cp.sit_ver_bitmap_bytesize as usize
    };
    // The checkpoint is (1 + cp_payload) contiguous blocks; a bitmap
    // that claims to run past them is a malformed image, not a reason
    // to allocate.
    let span = (1 + cp.cp_payload as usize).saturating_mul(F2FS_BLKSIZE);
    if start >= span || len > span - start {
        return Err(crate::Error::InvalidImage(format!(
            "f2fs: cp@{}: NAT bitmap ({len} bytes at {start}) overruns the pack",
            cp.head_blkaddr
        )));
    }
    let mut pack = head.to_vec();
    if start + len > pack.len() {
        let bs = sb.block_size() as u64;
        let extra = (start + len).div_ceil(F2FS_BLKSIZE) - 1;
        for i in 0..extra {
            let blk = cp
                .head_blkaddr
                .checked_add(1 + i as u32)
                .ok_or_else(|| crate::Error::InvalidImage("f2fs: cp payload overflow".into()))?;
            let mut buf = vec![0u8; F2FS_BLKSIZE];
            dev.read_at(blk as u64 * bs, &mut buf)?;
            pack.extend_from_slice(&buf);
        }
    }
    Ok(pack[start..start + len].to_vec())
}

/// Byte offset of the `f2fs_journal` inside the `cp_pack_start_sum`
/// block. A compact summary block opens with the NAT journal; a normal
/// one carries it after the 512 `f2fs_summary` entries.
pub(crate) fn nat_journal_offset(compact: bool) -> usize {
    if compact { 0 } else { SUM_ENTRY_SIZE }
}

/// Compute a CP head block's checksum the way `f2fs_checkpoint_chksum()`
/// does: CRC32 over `[0, crc_off)` and, whenever the CRC does *not* sit
/// in the block's last four bytes, continued over everything after it,
/// `[crc_off + 4, F2FS_BLKSIZE)`. Skipping that tail let an image with a
/// non-default `checksum_offset` pass validation with a corrupt (or
/// forged) second half.
pub(crate) fn cp_chksum(block: &[u8], crc_off: usize) -> u32 {
    let head = super::constants::f2fs_crc32(&block[..crc_off]);
    if crc_off < CP_CHKSUM_OFFSET {
        crate::crc::crc32_ieee_raw(head, &block[crc_off + 4..F2FS_BLKSIZE])
    } else {
        head
    }
}

/// Decode the NAT journal held in the `cp_pack_start_sum` block.
///
/// Layout is `struct f2fs_journal` from `include/linux/f2fs_fs.h`:
///
/// ```text
/// +0      __le16 n_nats
/// +2      struct nat_journal_entry entries[NAT_JOURNAL_ENTRIES]
/// ```
///
/// each entry a packed 13 bytes — `__le32 nid` followed by
/// `struct f2fs_nat_entry { __u8 version; __le32 ino; __le32 block_addr; }`.
/// `compact` selects where the journal starts inside the block; see
/// [`nat_journal_offset`].
fn decode_nat_journal(buf: &[u8], compact: bool) -> Vec<NatJournalEntry> {
    let base = nat_journal_offset(compact);
    if buf.len() < base + 2 {
        return Vec::new();
    }
    let n = u16::from_le_bytes([buf[base], buf[base + 1]]) as usize;
    // Defensive: a crafted image can't push us past the journal area.
    let room = (buf.len() - base - 2) / NAT_JOURNAL_ENTRY_SIZE;
    let n = n.min(NAT_JOURNAL_ENTRIES).min(room);

    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let o = base + 2 + i * NAT_JOURNAL_ENTRY_SIZE;
        let nid = u32::from_le_bytes(buf[o..o + 4].try_into().unwrap());
        let version = buf[o + 4];
        let ino = u32::from_le_bytes(buf[o + 5..o + 9].try_into().unwrap());
        let block_addr = u32::from_le_bytes(buf[o + 9..o + 13].try_into().unwrap());
        out.push(NatJournalEntry {
            nid,
            ino,
            block_addr,
            version,
        });
    }
    out
}

/// Encode a CP head block per `f2fs_fs.h`. Single source of truth for
/// the offsets [`decode_cp_head`] consumes. Used by the live flush path.
pub(crate) fn encode_cp_head_writer(cp: &Checkpoint) -> Vec<u8> {
    let mut buf = vec![0u8; F2FS_BLKSIZE];
    buf[0x00..0x08].copy_from_slice(&cp.version.to_le_bytes());
    buf[0x08..0x10].copy_from_slice(&cp.user_block_count.to_le_bytes());
    buf[0x10..0x18].copy_from_slice(&cp.valid_block_count.to_le_bytes());
    buf[0x18..0x1C].copy_from_slice(&cp.rsvd_segment_count.to_le_bytes());
    buf[0x1C..0x20].copy_from_slice(&cp.overprov_segment_count.to_le_bytes());
    buf[0x20..0x24].copy_from_slice(&cp.free_segment_count.to_le_bytes());
    // 0x24..0x44: cur_node_segno[8]; 0x44..0x54: cur_node_blkoff[8].
    // 0x54..0x74: cur_data_segno[8]; 0x74..0x84: cur_data_blkoff[8].
    for (i, s) in cp.cur_node_segno.iter().enumerate() {
        let o = 0x24 + i * 4;
        buf[o..o + 4].copy_from_slice(&s.to_le_bytes());
    }
    for (i, o16) in cp.cur_node_blkoff.iter().enumerate() {
        let o = 0x44 + i * 2;
        buf[o..o + 2].copy_from_slice(&o16.to_le_bytes());
    }
    for (i, s) in cp.cur_data_segno.iter().enumerate() {
        let o = 0x54 + i * 4;
        buf[o..o + 4].copy_from_slice(&s.to_le_bytes());
    }
    for (i, o16) in cp.cur_data_blkoff.iter().enumerate() {
        let o = 0x74 + i * 2;
        buf[o..o + 2].copy_from_slice(&o16.to_le_bytes());
    }
    buf[0x84..0x88].copy_from_slice(&cp.flags.to_le_bytes());
    buf[0x88..0x8C].copy_from_slice(&cp.cp_pack_total_block_count.to_le_bytes());
    buf[0x8C..0x90].copy_from_slice(&cp.cp_pack_start_sum.to_le_bytes());
    buf[0x90..0x94].copy_from_slice(&cp.valid_node_count.to_le_bytes());
    buf[0x94..0x98].copy_from_slice(&cp.valid_inode_count.to_le_bytes());
    buf[0x98..0x9C].copy_from_slice(&cp.next_free_nid.to_le_bytes());
    buf[0x9C..0xA0].copy_from_slice(&cp.sit_ver_bitmap_bytesize.to_le_bytes());
    buf[0xA0..0xA4].copy_from_slice(&cp.nat_ver_bitmap_bytesize.to_le_bytes());
    // `checksum_offset` = where the CRC32 will go. mkfs.f2fs uses 4092
    // (= F2FS_BLK_CSUM_OFFSET, last 4 bytes of the block).
    let crc_off = F2FS_BLK_CSUM_OFFSET as u32;
    buf[0xA4..0xA8].copy_from_slice(&crc_off.to_le_bytes());
    let crc = cp_chksum(&buf, F2FS_BLK_CSUM_OFFSET);
    buf[F2FS_BLK_CSUM_OFFSET..F2FS_BLK_CSUM_OFFSET + 4].copy_from_slice(&crc.to_le_bytes());
    buf
}

/// Encode an empty NAT-journal summary block — used by the writer when
/// every nid is persisted to the on-disk NAT pages instead of the
/// journal. Currently unused by the live writer (a 2-block CP pack uses
/// a head + duplicate-footer, no separate summary slot) but retained
/// for tests and future expansion to multi-block CP packs.
#[allow(dead_code)]
pub(crate) fn encode_empty_journal_block() -> Vec<u8> {
    encode_nat_journal_block_writer(&[])
}

/// Encode a non-compact `cp_pack_start_sum` block carrying `entries` in
/// its NAT journal. Layout mirrors [`decode_nat_journal`]; entries past
/// `NAT_JOURNAL_ENTRIES` don't fit the journal and are dropped (the
/// kernel spills those to the on-disk NAT pages instead).
#[allow(dead_code)]
pub(crate) fn encode_nat_journal_block_writer(entries: &[NatJournalEntry]) -> Vec<u8> {
    let mut buf = vec![0u8; F2FS_BLKSIZE];
    let base = nat_journal_offset(false);
    let n = entries.len().min(NAT_JOURNAL_ENTRIES);
    buf[base..base + 2].copy_from_slice(&(n as u16).to_le_bytes());
    for (i, e) in entries.iter().take(n).enumerate() {
        let o = base + 2 + i * NAT_JOURNAL_ENTRY_SIZE;
        buf[o..o + 4].copy_from_slice(&e.nid.to_le_bytes());
        buf[o + 4] = e.version;
        buf[o + 5..o + 9].copy_from_slice(&e.ino.to_le_bytes());
        buf[o + 9..o + 13].copy_from_slice(&e.block_addr.to_le_bytes());
    }
    buf
}

/// Test alias for [`encode_cp_head_writer`].
#[cfg(test)]
pub(crate) fn encode_cp_head(cp: &Checkpoint) -> Vec<u8> {
    encode_cp_head_writer(cp)
}

/// Test alias for [`encode_nat_journal_block_writer`].
#[cfg(test)]
pub(crate) fn encode_nat_journal_block(entries: &[NatJournalEntry]) -> Vec<u8> {
    encode_nat_journal_block_writer(entries)
}

#[cfg(test)]
mod tests {
    use super::super::constants::SUM_JOURNAL_SIZE;
    use super::*;

    /// `f2fs_checkpoint_chksum()` keeps CRCing past the checksum field
    /// whenever it isn't the last thing in the block. Ignoring that tail
    /// lets everything after `checksum_offset` be rewritten freely.
    #[test]
    fn cp_checksum_covers_the_tail_after_the_crc() {
        let mut block = vec![0u8; F2FS_BLKSIZE];
        for (i, b) in block.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let off = CP_MIN_CHKSUM_OFFSET;
        let full = cp_chksum(&block, off);
        let head_only = super::super::constants::f2fs_crc32(&block[..off]);
        assert_ne!(full, head_only, "the tail must contribute");
        // Changing a byte after the checksum field changes the result.
        let mut tampered = block.clone();
        tampered[F2FS_BLKSIZE - 1] ^= 0xFF;
        assert_ne!(cp_chksum(&tampered, off), full);
        // Changing the four bytes of the checksum field itself does not.
        let mut restamped = block.clone();
        restamped[off..off + 4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        assert_eq!(cp_chksum(&restamped, off), full);
        // At the canonical offset there is no tail, so it degenerates to
        // a plain CRC of everything before the field.
        assert_eq!(
            cp_chksum(&block, CP_CHKSUM_OFFSET),
            super::super::constants::f2fs_crc32(&block[..CP_CHKSUM_OFFSET])
        );
    }

    /// The journal is `struct f2fs_journal`: `__le16 n_nats` then packed
    /// 13-byte `nat_journal_entry`s, each `nid` followed by a
    /// `f2fs_nat_entry` whose `version` comes *before* ino/block_addr.
    #[test]
    fn nat_journal_matches_the_kernel_layout() {
        assert_eq!(SUM_ENTRY_SIZE, 3584);
        assert_eq!(NAT_JOURNAL_ENTRY_SIZE, 13);
        assert_eq!(NAT_JOURNAL_ENTRIES, 38);

        let entries = vec![
            NatJournalEntry {
                nid: 4,
                ino: 4,
                block_addr: 0x1234,
                version: 7,
            },
            NatJournalEntry {
                nid: 9,
                ino: 3,
                block_addr: 0x5678,
                version: 0,
            },
        ];
        let blk = encode_nat_journal_block_writer(&entries);
        // Bytes land in the summary block's journal member, not at 0.
        let base = SUM_ENTRY_SIZE;
        assert_eq!(&blk[..base], &vec![0u8; base][..]);
        assert_eq!(u16::from_le_bytes([blk[base], blk[base + 1]]), 2);
        assert_eq!(&blk[base + 2..base + 6], &4u32.to_le_bytes());
        assert_eq!(blk[base + 6], 7);
        assert_eq!(&blk[base + 7..base + 11], &4u32.to_le_bytes());
        assert_eq!(&blk[base + 11..base + 15], &0x1234u32.to_le_bytes());

        let back = decode_nat_journal(&blk, false);
        assert_eq!(back.len(), 2);
        assert_eq!((back[0].nid, back[0].ino, back[0].version), (4, 4, 7));
        assert_eq!(back[1].block_addr, 0x5678);
        // Read as a compact block the same bytes decode to nothing: the
        // journal would start at offset 0 there.
        assert!(decode_nat_journal(&blk, true).is_empty());

        // A compact pack carries the journal at offset 0.
        let mut compact = vec![0u8; F2FS_BLKSIZE];
        compact[..SUM_JOURNAL_SIZE].copy_from_slice(&blk[base..base + SUM_JOURNAL_SIZE]);
        let back = decode_nat_journal(&compact, true);
        assert_eq!(back.len(), 2);
        assert_eq!(back[1].nid, 9);
    }

    /// A bogus `n_nats` can't walk us out of the journal area.
    #[test]
    fn nat_journal_entry_count_is_clamped() {
        let mut blk = vec![0u8; F2FS_BLKSIZE];
        blk[SUM_ENTRY_SIZE..SUM_ENTRY_SIZE + 2].copy_from_slice(&u16::MAX.to_le_bytes());
        assert_eq!(decode_nat_journal(&blk, false).len(), NAT_JOURNAL_ENTRIES);
    }
}
