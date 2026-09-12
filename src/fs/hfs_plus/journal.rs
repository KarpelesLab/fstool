//! HFS+ journal — Path A "real transactions".
//!
//! Apple TN1150 specifies a `JournalInfoBlock` pointing at a circular
//! journal buffer whose first sector is a journal header (magic
//! `"JNLx"`). Between `start` and `end` lies a sequence of transactions;
//! each transaction is one or more *block lists*, where a block list
//! consists of a `block_list_header_t` + an array of `block_info_t`
//! entries describing the disk blocks being committed, followed by the
//! block data itself.
//!
//! ## On-disk layout
//!
//! Journal header (`jhdr_size` bytes, of which the first 48 matter):
//!
//! ```text
//! 0   4  magic         0x4a4e4c78 "JNLx"
//! 4   4  endian        0x12345678
//! 8   8  start         ring offset of the first unreplayed transaction
//! 16  8  end           ring offset where free space begins
//! 24  8  size          size of the whole journal buffer in bytes
//! 32  4  blhdr_size    size of each block-list header region
//! 36  4  checksum      calc_checksum over bytes 0..44 with this field 0
//! 40  4  jhdr_size     size of this header (== the volume's sector size)
//! 44  4  sequence_num  sequence number of the most recent transaction
//! ```
//!
//! Block list (`blhdr_size` bytes of header + info array, then data):
//!
//! ```text
//! 0  2  max_blocks            (blhdr_size / 16 - 1)
//! 2  2  num_blocks            (includes the sentinel info[0])
//! 4  4  bytes_used            (blhdr_size + data)
//! 8  4  checksum              (calc_checksum over bytes 0..32, field 0)
//! 12 4  flags                 (1 = per-block checksums, 2 = first header)
//! 16 .. block_info[num_blocks] {
//!         u64 bnum            (sector number, sector = jhdr_size bytes;
//!                              -1 marks a superseded entry to skip)
//!         u32 bsize           (bytes of data; multiple of the sector)
//!         u32 b_cksum         (calc_checksum over the block data)
//!       }
//! ```
//!
//! The first `block_info` slot is a sentinel whose `b_cksum` field
//! carries the transaction's sequence number (`bnum`/`bsize` zero). The
//! concatenated block data starts `blhdr_size` bytes after the block
//! list header. Transactions may straddle the ring's wrap point: bytes
//! past `size` continue at `jhdr_size`.
//!
//! ## Endianness
//!
//! Every multi-byte field is stored in the byte order of the machine
//! that created the journal — a Mac writes little-endian, this writer
//! big-endian. The `endian` field (0x12345678) tells a reader which;
//! [`JournalLog::load`] detects it and every field is decoded and
//! re-encoded with the same swap. Checksums are computed over the raw
//! on-disk bytes, so they are independent of the byte order.
//!
//! ## Checksum
//!
//! xnu's `calc_checksum` (`vfs_journal.c`): `c = (c << 8) ^ (c + byte)`
//! over each byte, result `~c`. Verified against `hdiutil`-created
//! journals — this is *not* a CRC.
//!
//! ## Replay
//!
//! [`replay`] walks the ring from `start` to `end`, copies each
//! described data chunk to its target sector, and then advances
//! `start := end` on disk. Idempotent — replaying a clean journal
//! (start == end) is a no-op.
//!
//! ## Crash safety
//!
//! [`JournalLog::commit`] writes the transaction body + advances `end`
//! BEFORE applying the in-place writes. A crash between those two
//! phases leaves a valid journal entry that the next [`replay`] will
//! re-apply, restoring the file system to the post-commit state.

use std::collections::BTreeMap;

use crate::Result;
use crate::block::BlockDevice;

use super::writer::{JOURNAL_HEADER_ENDIAN, JOURNAL_HEADER_MAGIC, VOL_ATTR_JOURNALED};

/// Size of one block-list-header region (header + info array, before
/// the block data) written by this formatter. 8192 matches what macOS
/// writes; a loaded journal uses whatever its header says.
pub const BLHDR_SIZE: u32 = 8192;

/// Journal-header size in bytes written by this formatter (one 512-byte
/// sector). A loaded journal uses whatever its header says.
pub const JHDR_SIZE: u32 = 512;

/// Number of bytes occupied by one block_info entry on disk.
const BINFO_SIZE: usize = 16;

/// The 16-byte fixed prefix of a `block_list_header_t` (before the
/// `block_info` array).
const BLHDR_FIXED_SIZE: usize = 16;

/// Bytes of the block-list header covered by its checksum: the fixed
/// prefix plus the sentinel `block_info[0]` (xnu `BLHDR_CHECKSUM_SIZE`).
const BLHDR_CKSUM_SIZE: usize = 32;

/// Bytes of the journal header covered by its checksum — everything up
/// to `sequence_num` (xnu `JOURNAL_HEADER_CKSUM_SIZE`).
const JHDR_CKSUM_SIZE: usize = 44;

/// Bytes of the journal header we read: through `sequence_num`.
const JHDR_READ_SIZE: usize = 48;

/// `block_list_header.flags`: every `block_info.b_cksum` is valid and
/// must match the block data.
const BLHDR_CHECK_CHECKSUMS: u32 = 1;
/// `block_list_header.flags`: first block list of its transaction.
const BLHDR_FIRST_HEADER: u32 = 2;

/// `block_info.bnum` value marking an entry whose data is present in
/// the ring but must not be applied (superseded within the transaction).
const BNUM_SKIP: u64 = u64::MAX;

/// xnu `calc_checksum`: the journal's byte-wise checksum, computed over
/// the raw on-disk bytes (so it is byte-order independent).
pub(crate) fn calc_checksum(buf: &[u8]) -> u32 {
    let mut c: u32 = 0;
    for &b in buf {
        c = (c << 8) ^ c.wrapping_add(u32::from(b));
    }
    !c
}

/// Byte-order helper: `true` for big-endian journals (what this writer
/// produces), `false` for little-endian ones (what a Mac produces).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Endian(bool);

impl Endian {
    fn u16(self, b: &[u8]) -> u16 {
        let a: [u8; 2] = b[..2].try_into().unwrap();
        if self.0 {
            u16::from_be_bytes(a)
        } else {
            u16::from_le_bytes(a)
        }
    }
    fn u32(self, b: &[u8]) -> u32 {
        let a: [u8; 4] = b[..4].try_into().unwrap();
        if self.0 {
            u32::from_be_bytes(a)
        } else {
            u32::from_le_bytes(a)
        }
    }
    fn u64(self, b: &[u8]) -> u64 {
        let a: [u8; 8] = b[..8].try_into().unwrap();
        if self.0 {
            u64::from_be_bytes(a)
        } else {
            u64::from_le_bytes(a)
        }
    }
    fn put_u16(self, b: &mut [u8], v: u16) {
        b[..2].copy_from_slice(&if self.0 {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        });
    }
    fn put_u32(self, b: &mut [u8], v: u32) {
        b[..4].copy_from_slice(&if self.0 {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        });
    }
    fn put_u64(self, b: &mut [u8], v: u64) {
        b[..8].copy_from_slice(&if self.0 {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        });
    }
}

/// Per-block pending write. `dev_off` is the byte offset on the
/// underlying volume; `data` is its replacement contents.
#[derive(Debug, Clone)]
pub(crate) struct PendingBlock {
    pub dev_off: u64,
    pub data: Vec<u8>,
}

/// Sink used by the metadata-flush path to route writes either straight
/// through to the device or through the journal as a single transaction.
///
/// * [`FlushSink::Direct`] — writes are applied to `dev` immediately. Used
///   on fresh builds where the volume has no pre-existing journal header
///   yet, so there is no transaction log to thread through.
/// * [`FlushSink::Buffered`] — writes accumulate in memory. The caller is
///   responsible for handing the collected blocks to a [`JournalLog`] and
///   calling [`JournalLog::commit`] so the transaction is journaled
///   atomically before the in-place blocks land.
///
/// The split is necessary because, during a fresh format, the on-disk
/// journal header is itself one of the things `flush` writes — we cannot
/// route that write through a journal that doesn't exist yet.
pub(crate) enum FlushSink<'d> {
    Direct(&'d mut dyn BlockDevice),
    Buffered(Vec<PendingBlock>),
}

impl<'d> FlushSink<'d> {
    /// Apply `data` at `dev_off`. In `Direct` mode this immediately calls
    /// through to `dev.write_at`; in `Buffered` mode the block is recorded
    /// in memory and later committed via the journal. Buffered blocks are
    /// kept in arrival order; [`JournalLog::add_batch`] replays them in
    /// that order so a later write of the same range wins.
    pub fn write_at(&mut self, dev_off: u64, data: &[u8]) -> Result<()> {
        match self {
            FlushSink::Direct(dev) => dev.write_at(dev_off, data),
            FlushSink::Buffered(blocks) => {
                blocks.push(PendingBlock {
                    dev_off,
                    data: data.to_vec(),
                });
                Ok(())
            }
        }
    }
}

/// In-memory journal log. Constructed from the on-disk journal-info
/// block; collects pending writes via [`JournalLog::add`] and emits
/// one or more transactions per [`JournalLog::commit`].
pub(crate) struct JournalLog {
    /// Byte offset of the journal buffer on the volume.
    pub buf_off: u64,
    /// Size of the journal buffer (the circular ring).
    pub buf_size: u64,
    /// Current `start` field from the on-disk header.
    pub start: u64,
    /// Current `end` field from the on-disk header.
    pub end: u64,
    /// `blhdr_size` from the on-disk header.
    pub blhdr_size: u32,
    /// `jhdr_size` from the on-disk header — also the sector size that
    /// `block_info.bnum` counts in.
    pub jhdr_size: u32,
    /// `sequence_num` from the on-disk header: the sequence number of
    /// the most recently written transaction.
    pub sequence_num: u32,
    /// Byte order of the on-disk journal.
    endian: Endian,
    /// Pending writes accumulated since the last commit, keyed by
    /// device byte offset. Entries never overlap: [`Self::add`] trims
    /// or removes whatever an incoming range covers, so the latest
    /// data always wins and lookups are a single `BTreeMap` probe.
    pending: BTreeMap<u64, Vec<u8>>,
}

impl JournalLog {
    /// Read the volume's journal-info block and journal header. Returns
    /// `Ok(None)` if the volume is not journaled (or the JIB pointer
    /// is zero — defensive fallback).
    pub fn load(
        dev: &mut dyn BlockDevice,
        vh: &super::volume_header::VolumeHeader,
    ) -> Result<Option<Self>> {
        if vh.attributes & VOL_ATTR_JOURNALED == 0 {
            return Ok(None);
        }
        let info_block = vh.journal_info_block;
        if info_block == 0 {
            return Ok(None);
        }
        let bs = u64::from(vh.block_size);
        let info_off = u64::from(info_block) * bs;
        let mut info = [0u8; 52];
        dev.read_at(info_off, &mut info)?;
        // The JournalInfoBlock itself is always big-endian (it is an HFS+
        // on-disk structure, not part of the journal proper).
        let buf_off = u64::from_be_bytes(info[36..44].try_into().unwrap());
        let jib_size = u64::from_be_bytes(info[44..52].try_into().unwrap());
        if buf_off == 0 || jib_size == 0 {
            return Ok(None);
        }
        if buf_off.saturating_add(jib_size) > dev.total_size() {
            return Err(crate::Error::InvalidImage(format!(
                "hfs+ journal: buffer [{buf_off}, +{jib_size}) lies past the end of the device"
            )));
        }
        let mut hdr = [0u8; JHDR_READ_SIZE];
        dev.read_at(buf_off, &mut hdr)?;
        let endian = if Endian(true).u32(&hdr[0..4]) == JOURNAL_HEADER_MAGIC
            && Endian(true).u32(&hdr[4..8]) == JOURNAL_HEADER_ENDIAN
        {
            Endian(true)
        } else if Endian(false).u32(&hdr[0..4]) == JOURNAL_HEADER_MAGIC
            && Endian(false).u32(&hdr[4..8]) == JOURNAL_HEADER_ENDIAN
        {
            Endian(false)
        } else {
            let magic = u32::from_be_bytes(hdr[0..4].try_into().unwrap());
            let en = u32::from_be_bytes(hdr[4..8].try_into().unwrap());
            return Err(crate::Error::InvalidImage(format!(
                "hfs+ journal: unrecognised header magic/endian ({magic:#010x}/{en:#010x})"
            )));
        };
        let start = endian.u64(&hdr[8..16]);
        let end = endian.u64(&hdr[16..24]);
        let size = endian.u64(&hdr[24..32]);
        let blhdr_size = endian.u32(&hdr[32..36]);
        let stored_cksum = endian.u32(&hdr[36..40]);
        let jhdr_size = endian.u32(&hdr[40..44]);
        let sequence_num = endian.u32(&hdr[44..48]);

        let mut zeroed = [0u8; JHDR_CKSUM_SIZE];
        zeroed.copy_from_slice(&hdr[..JHDR_CKSUM_SIZE]);
        zeroed[36..40].fill(0);
        let want = calc_checksum(&zeroed);
        if want != stored_cksum {
            return Err(crate::Error::InvalidImage(format!(
                "hfs+ journal: header checksum mismatch (stored {stored_cksum:#010x}, computed {want:#010x})"
            )));
        }

        // The header's own `size` is authoritative for the ring (xnu
        // warns but proceeds on a mismatch with the JIB); it must fit in
        // the region the JIB reserves.
        if size == 0 || size > jib_size {
            return Err(crate::Error::InvalidImage(format!(
                "hfs+ journal: header size {size} does not fit the journal-info size {jib_size}"
            )));
        }
        let buf_size = size;
        // Validate the ring geometry before any code path computes
        // `buf_size - jhdr_size` or walks `[start, end)` in replay. The
        // header must leave room for itself, the block-list header must
        // hold at least the fixed prefix + sentinel and fit in the ring,
        // and both cursors lie within the usable ring `[jhdr_size, size]`.
        let jhdr = u64::from(jhdr_size);
        if jhdr_size < JHDR_READ_SIZE as u32 || jhdr >= buf_size {
            return Err(crate::Error::InvalidImage(format!(
                "hfs+ journal: jhdr_size {jhdr_size} invalid for a {buf_size}-byte buffer"
            )));
        }
        if (blhdr_size as usize) < BLHDR_CKSUM_SIZE
            || u64::from(blhdr_size) > buf_size - jhdr
            || blhdr_size % jhdr_size != 0
        {
            return Err(crate::Error::InvalidImage(format!(
                "hfs+ journal: blhdr_size {blhdr_size} invalid (jhdr_size {jhdr_size}, size {buf_size})"
            )));
        }
        if start < jhdr || start > buf_size || end < jhdr || end > buf_size {
            return Err(crate::Error::InvalidImage(format!(
                "hfs+ journal: start {start} / end {end} outside ring [{jhdr_size}, {buf_size}]"
            )));
        }
        Ok(Some(Self {
            buf_off,
            buf_size,
            start,
            end,
            blhdr_size,
            jhdr_size,
            sequence_num,
            endian,
            pending: BTreeMap::new(),
        }))
    }

    /// True iff there are unreplayed transactions on disk.
    pub fn is_dirty(&self) -> bool {
        self.start != self.end
    }

    /// The sector size `block_info.bnum` counts in, and the granularity
    /// every committed block is padded to.
    pub fn sector(&self) -> u64 {
        u64::from(self.jhdr_size)
    }

    /// Number of pending (uncommitted) blocks.
    #[cfg(test)]
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Queue a pending write. Any previously queued bytes in
    /// `[dev_off, dev_off + data.len())` are superseded. If `data.len()`
    /// is not a multiple of the sector size, the recorded buffer is
    /// padded with zeros to the next sector boundary on commit.
    pub fn add(&mut self, dev_off: u64, data: Vec<u8>) {
        if data.is_empty() {
            return;
        }
        let end = dev_off + data.len() as u64;
        self.remove_range(dev_off, end);
        self.pending.insert(dev_off, data);
    }

    /// Bulk-add a list of pending blocks (as collected by
    /// [`FlushSink::Buffered`]). Equivalent to calling [`Self::add`] in a
    /// loop, but moves the buffers in place so we don't double-copy the
    /// (potentially large) catalog / extents / bitmap payloads.
    pub fn add_batch(&mut self, blocks: Vec<PendingBlock>) {
        for b in blocks {
            self.add(b.dev_off, b.data);
        }
    }

    /// Forget every pending byte in `[lo, hi)`. Entries straddling the
    /// range are trimmed so the parts outside it survive. Used when the
    /// caller writes a range straight to disk (e.g. a zero-fill of a
    /// freshly allocated run) so a stale queued write can't clobber it.
    pub fn remove_range(&mut self, lo: u64, hi: u64) {
        if hi <= lo {
            return;
        }
        // Entries never overlap, so keys and ends are both sorted:
        // walking backwards from the last key below `hi`, the first
        // entry that ends at or before `lo` means none earlier overlap.
        let mut hit: Vec<u64> = Vec::new();
        for (&k, v) in self.pending.range(..hi).rev() {
            if k + v.len() as u64 <= lo {
                break;
            }
            hit.push(k);
        }
        for k in hit {
            let v = self.pending.remove(&k).expect("key came from the map");
            let v_end = k + v.len() as u64;
            if v_end > hi {
                let tail = v[(hi - k) as usize..].to_vec();
                self.pending.insert(hi, tail);
            }
            if k < lo {
                let mut head = v;
                head.truncate((lo - k) as usize);
                self.pending.insert(k, head);
            }
        }
    }

    /// Search pending writes for the byte at `dev_off`. Used by the
    /// file handle to serve reads of bytes we've buffered but not yet
    /// committed. Returns the slice (and its start offset) of the
    /// pending block that contains `dev_off`, if any.
    pub fn lookup(&self, dev_off: u64) -> Option<(u64, &[u8])> {
        let (&k, v) = self.pending.range(..=dev_off).next_back()?;
        if dev_off < k + v.len() as u64 {
            Some((k, v.as_slice()))
        } else {
            None
        }
    }

    /// Device offset of the first pending block starting at or after
    /// `dev_off` (a block *containing* `dev_off` is [`Self::lookup`]'s
    /// job). Lets a reader copy a whole stretch from disk in one go.
    pub fn next_pending_from(&self, dev_off: u64) -> Option<u64> {
        self.pending.range(dev_off..).next().map(|(&k, _)| k)
    }

    /// Commit the pending writes to disk through the journal. Each
    /// transaction:
    ///   1. Rounds each block to a whole number of sectors.
    ///   2. Builds a block-list transaction at offset `end` in the
    ///      circular buffer. Updates on-disk `end` (header rewrite).
    ///   3. Applies each block to its target dev offset.
    ///   4. Advances on-disk `start := end`, header rewrite.
    ///
    /// The order is critical: after step 2 a crash leaves a complete
    /// journal entry that the next [`replay`] will redo. Between steps
    /// 3 and 4 a crash also leaves the journal claiming unreplayed
    /// work — replay is idempotent.
    ///
    /// A pending set larger than one block list can describe (the
    /// `max_blocks` entry limit) or than the ring can hold is split into
    /// several consecutive transactions, each sealed before the next
    /// starts.
    pub fn commit(&mut self, dev: &mut dyn BlockDevice) -> Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        if self.is_dirty() {
            return Err(crate::Error::InvalidImage(
                "hfs+ journal: cannot commit over unreplayed transactions".into(),
            ));
        }
        let sector = self.sector();
        let usable = self.buf_size - u64::from(self.jhdr_size);
        // Data slots per block list: blhdr_size / 16 minus the sentinel
        // and minus one more because xnu's `max_blocks` is itself
        // `blhdr_size / 16 - 1`.
        let max_entries = (self.blhdr_size as usize / BINFO_SIZE).saturating_sub(2);
        if max_entries == 0 {
            return Err(crate::Error::Unsupported(format!(
                "hfs+ journal: blhdr_size {} leaves no room for block entries",
                self.blhdr_size
            )));
        }

        // 1. Pad every block to whole sectors.
        let queue: Vec<(u64, Vec<u8>)> = std::mem::take(&mut self.pending)
            .into_iter()
            .map(|(off, mut data)| {
                let pad_len = (data.len() as u64).div_ceil(sector) * sector;
                data.resize(pad_len as usize, 0);
                (off, data)
            })
            .collect();

        // 2. Chunk into transactions that fit one block list and the ring.
        let mut i = 0;
        while i < queue.len() {
            let mut bytes = u64::from(self.blhdr_size);
            let mut n = 0;
            while i + n < queue.len() && n < max_entries {
                let len = queue[i + n].1.len() as u64;
                if bytes + len > usable {
                    break;
                }
                bytes += len;
                n += 1;
            }
            if n == 0 {
                return Err(crate::Error::Unsupported(format!(
                    "hfs+ journal: a {}-byte block does not fit the {}-byte journal",
                    queue[i].1.len(),
                    self.buf_size
                )));
            }
            self.commit_one(dev, &queue[i..i + n], bytes)?;
            i += n;
        }
        Ok(())
    }

    /// Write and apply one transaction made of `blocks` (already
    /// sector-padded; `bytes_used` = blhdr_size + their total length).
    fn commit_one(
        &mut self,
        dev: &mut dyn BlockDevice,
        blocks: &[(u64, Vec<u8>)],
        bytes_used: u64,
    ) -> Result<()> {
        let e = self.endian;
        let sector = self.sector();
        let bytes_used_u32 = u32::try_from(bytes_used).map_err(|_| {
            crate::Error::Unsupported("hfs+ journal: transaction overflows u32".into())
        })?;
        let num_info = (blocks.len() + 1) as u16;
        let max_blocks = (self.blhdr_size / BINFO_SIZE as u32 - 1) as u16;
        self.sequence_num = self.sequence_num.wrapping_add(1).max(1);

        let mut tx = vec![0u8; bytes_used as usize];
        e.put_u16(&mut tx[0..2], max_blocks);
        e.put_u16(&mut tx[2..4], num_info);
        e.put_u32(&mut tx[4..8], bytes_used_u32);
        // 8..12 checksum (filled at end)
        e.put_u32(&mut tx[12..16], BLHDR_CHECK_CHECKSUMS | BLHDR_FIRST_HEADER);

        // Slot 0 sentinel: bnum/bsize zero, b_cksum = sequence number.
        let info_base = BLHDR_FIXED_SIZE;
        e.put_u32(&mut tx[info_base + 12..info_base + 16], self.sequence_num);

        // Slots 1..num_info describe the data blocks; data follows at
        // blhdr_size.
        let mut cursor = self.blhdr_size as usize;
        for (i, (dev_off, data)) in blocks.iter().enumerate() {
            let slot = info_base + (i + 1) * BINFO_SIZE;
            e.put_u64(&mut tx[slot..slot + 8], dev_off / sector);
            e.put_u32(&mut tx[slot + 8..slot + 12], data.len() as u32);
            e.put_u32(&mut tx[slot + 12..slot + 16], calc_checksum(data));
            tx[cursor..cursor + data.len()].copy_from_slice(data);
            cursor += data.len();
        }

        // Checksum over the 32-byte block_list_header (+ sentinel).
        let csum = calc_checksum(&tx[..BLHDR_CKSUM_SIZE]);
        e.put_u32(&mut tx[8..12], csum);

        // Write the transaction into the ring at `end` (wrapping past the
        // buffer's end back to jhdr_size, as xnu does).
        self.ring_write(dev, self.end, &tx)?;
        let new_end = self.ring_advance(self.end, bytes_used);

        // Persist `end` on disk. From this point on a crash leaves a
        // valid transaction the next replay will apply.
        self.end = new_end;
        self.write_header(dev)?;
        dev.sync()?;

        // Apply the actual block writes in place.
        for (dev_off, data) in blocks {
            dev.write_at(*dev_off, data)?;
        }
        dev.sync()?;

        // Advance `start := end` to mark the transaction replayed.
        self.start = self.end;
        self.write_header(dev)?;
        dev.sync()?;
        Ok(())
    }

    /// Advance a ring offset by `by` bytes, wrapping past the end of the
    /// buffer back to just after the journal header.
    fn ring_advance(&self, off: u64, by: u64) -> u64 {
        let n = off + by;
        if n >= self.buf_size {
            n - self.buf_size + u64::from(self.jhdr_size)
        } else {
            n
        }
    }

    /// Read `buf.len()` bytes of the ring starting at ring offset
    /// `ring_off`, continuing at `jhdr_size` past the end of the buffer.
    fn ring_read(&self, dev: &mut dyn BlockDevice, ring_off: u64, buf: &mut [u8]) -> Result<()> {
        let mut off = ring_off;
        let mut done = 0usize;
        while done < buf.len() {
            let room = (self.buf_size - off) as usize;
            let take = room.min(buf.len() - done);
            dev.read_at(self.buf_off + off, &mut buf[done..done + take])?;
            done += take;
            off = self.ring_advance(off, take as u64);
        }
        Ok(())
    }

    /// Write `data` into the ring starting at ring offset `ring_off`,
    /// continuing at `jhdr_size` past the end of the buffer.
    fn ring_write(&self, dev: &mut dyn BlockDevice, ring_off: u64, data: &[u8]) -> Result<()> {
        let mut off = ring_off;
        let mut done = 0usize;
        while done < data.len() {
            let room = (self.buf_size - off) as usize;
            let take = room.min(data.len() - done);
            dev.write_at(self.buf_off + off, &data[done..done + take])?;
            done += take;
            off = self.ring_advance(off, take as u64);
        }
        Ok(())
    }

    /// Rewrite the on-disk journal header from this log's fields,
    /// preserving the journal's byte order.
    pub fn write_header(&self, dev: &mut dyn BlockDevice) -> Result<()> {
        let b = encode_journal_header(
            self.endian,
            self.start,
            self.end,
            self.buf_size,
            self.blhdr_size,
            self.jhdr_size,
            self.sequence_num,
        );
        dev.write_at(self.buf_off, &b)
    }
}

/// Walk `[start, end)` of the journal buffer and apply every block
/// described by every transaction in that range, then on-disk advance
/// `start := end`. Idempotent when `start == end` (no-op).
pub(crate) fn replay(
    dev: &mut dyn BlockDevice,
    vh: &super::volume_header::VolumeHeader,
) -> Result<()> {
    let Some(mut log) = JournalLog::load(dev, vh)? else {
        return Ok(());
    };
    if !log.is_dirty() {
        return Ok(());
    }
    let e = log.endian;
    let sector = log.sector();
    let blhdr_size = u64::from(log.blhdr_size);
    let max_blocks = (log.blhdr_size as usize / BINFO_SIZE).saturating_sub(1);
    let dev_size = dev.total_size();
    let mut cursor = log.start;
    let end = log.end;
    // Cap the number of transactions we will replay. Every valid
    // transaction is at least blhdr_size bytes, so the usable ring can
    // hold at most `usable / blhdr_size` of them. A hostile `bytes_used`
    // cycle or non-advancing cursor would otherwise loop forever; bound
    // it hard and error past the cap.
    let usable = log.buf_size - u64::from(log.jhdr_size);
    let mut tx_left = (usable / blhdr_size).max(1) + 1;
    let mut info = vec![0u8; log.blhdr_size as usize];
    while cursor != end {
        if tx_left == 0 {
            return Err(crate::Error::InvalidImage(
                "hfs+ journal: transaction count exceeded ring capacity (cycle?)".into(),
            ));
        }
        tx_left -= 1;
        log.ring_read(dev, cursor, &mut info)?;
        let num_blocks = e.u16(&info[2..4]) as usize;
        let bytes_used = u64::from(e.u32(&info[4..8]));
        let stored_cksum = e.u32(&info[8..12]);
        let flags = e.u32(&info[12..16]);
        if num_blocks == 0 || num_blocks > max_blocks || bytes_used < blhdr_size {
            return Err(crate::Error::InvalidImage(format!(
                "hfs+ journal: malformed block list at {cursor} (num={num_blocks}, bytes={bytes_used})"
            )));
        }
        let mut zeroed = [0u8; BLHDR_CKSUM_SIZE];
        zeroed.copy_from_slice(&info[..BLHDR_CKSUM_SIZE]);
        zeroed[8..12].fill(0);
        let want = calc_checksum(&zeroed);
        if want != stored_cksum {
            return Err(crate::Error::InvalidImage(format!(
                "hfs+ journal: block list checksum mismatch at {cursor} \
                 (stored {stored_cksum:#010x}, computed {want:#010x})"
            )));
        }
        // The whole transaction must fit within the usable ring.
        if bytes_used > usable {
            return Err(crate::Error::InvalidImage(format!(
                "hfs+ journal: block list bytes_used {bytes_used} exceeds ring at cursor {cursor}"
            )));
        }
        // The concatenated block data lives in the `bytes_used -
        // blhdr_size` bytes after the header region. Bound the sum of
        // per-block `bsize` to that window so a single oversized entry
        // cannot trigger a huge allocation.
        let mut data_budget = bytes_used - blhdr_size;
        let mut data_cursor = log.ring_advance(cursor, blhdr_size);
        for i in 1..num_blocks {
            let slot = BLHDR_FIXED_SIZE + i * BINFO_SIZE;
            let bnum = e.u64(&info[slot..slot + 8]);
            let bsize = u64::from(e.u32(&info[slot + 8..slot + 12]));
            let b_cksum = e.u32(&info[slot + 12..slot + 16]);
            if bsize > data_budget {
                return Err(crate::Error::InvalidImage(format!(
                    "hfs+ journal: block data {bsize} exceeds remaining transaction bytes {data_budget}"
                )));
            }
            data_budget -= bsize;
            if bnum == BNUM_SKIP {
                data_cursor = log.ring_advance(data_cursor, bsize);
                continue;
            }
            let target = bnum.checked_mul(sector).ok_or_else(|| {
                crate::Error::InvalidImage(format!("hfs+ journal: block number {bnum} overflows"))
            })?;
            if target.saturating_add(bsize) > dev_size {
                return Err(crate::Error::InvalidImage(format!(
                    "hfs+ journal: block {bnum} (+{bsize} bytes) lies past the end of the device"
                )));
            }
            let mut data = vec![0u8; bsize as usize];
            log.ring_read(dev, data_cursor, &mut data)?;
            if flags & BLHDR_CHECK_CHECKSUMS != 0 {
                let got = calc_checksum(&data);
                if got != b_cksum {
                    return Err(crate::Error::InvalidImage(format!(
                        "hfs+ journal: data checksum mismatch for block {bnum} \
                         (stored {b_cksum:#010x}, computed {got:#010x})"
                    )));
                }
            }
            dev.write_at(target, &data)?;
            data_cursor = log.ring_advance(data_cursor, bsize);
        }
        cursor = log.ring_advance(cursor, bytes_used);
    }
    dev.sync()?;
    log.start = end;
    log.write_header(dev)?;
    dev.sync()?;
    Ok(())
}

/// Encode a 512-byte journal header carrying the supplied fields in the
/// requested byte order, with a valid checksum.
fn encode_journal_header(
    endian: Endian,
    start: u64,
    end: u64,
    size: u64,
    blhdr_size: u32,
    jhdr_size: u32,
    sequence_num: u32,
) -> [u8; JHDR_SIZE as usize] {
    let mut b = [0u8; JHDR_SIZE as usize];
    endian.put_u32(&mut b[0..4], JOURNAL_HEADER_MAGIC);
    endian.put_u32(&mut b[4..8], JOURNAL_HEADER_ENDIAN);
    endian.put_u64(&mut b[8..16], start);
    endian.put_u64(&mut b[16..24], end);
    endian.put_u64(&mut b[24..32], size);
    endian.put_u32(&mut b[32..36], blhdr_size);
    endian.put_u32(&mut b[40..44], jhdr_size);
    endian.put_u32(&mut b[44..48], sequence_num);
    let csum = calc_checksum(&b[..JHDR_CKSUM_SIZE]);
    endian.put_u32(&mut b[36..40], csum);
    b
}

/// The journal header a freshly formatted volume gets: an empty ring
/// (`start == end == jhdr_size`), big-endian, sequence number 1, with
/// the `blhdr_size` / `jhdr_size` this module writes.
pub(crate) fn fresh_journal_header(buf_size: u64) -> [u8; JHDR_SIZE as usize] {
    encode_journal_header(
        Endian(true),
        u64::from(JHDR_SIZE),
        u64::from(JHDR_SIZE),
        buf_size,
        BLHDR_SIZE,
        JHDR_SIZE,
        1,
    )
}

/// Write a fresh empty journal header (see [`fresh_journal_header`])
/// for a `buf_size`-byte journal buffer at `buf_off`.
#[cfg(test)]
pub(crate) fn write_journal_header(
    dev: &mut dyn BlockDevice,
    buf_off: u64,
    buf_size: u64,
) -> Result<()> {
    dev.write_at(buf_off, &fresh_journal_header(buf_size))
}

/// Test helper: rewrite the on-disk journal header at `buf_off` with
/// `start` moved to `new_start`, keeping every other field, the byte
/// order and a valid checksum. Simulates a crash before `start` caught
/// up with `end`.
#[cfg(test)]
pub(crate) fn rewind_start_for_test(
    dev: &mut dyn BlockDevice,
    buf_off: u64,
    new_start: u64,
) -> Result<()> {
    let mut hdr = [0u8; JHDR_READ_SIZE];
    dev.read_at(buf_off, &mut hdr)?;
    let endian = if Endian(true).u32(&hdr[0..4]) == JOURNAL_HEADER_MAGIC {
        Endian(true)
    } else {
        Endian(false)
    };
    let b = encode_journal_header(
        endian,
        new_start,
        endian.u64(&hdr[16..24]),
        endian.u64(&hdr[24..32]),
        endian.u32(&hdr[32..36]),
        endian.u32(&hdr[40..44]),
        endian.u32(&hdr[44..48]),
    );
    dev.write_at(buf_off, &b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::MemoryBackend;

    fn fresh_log(buf_off: u64, buf_size: u64) -> JournalLog {
        JournalLog {
            buf_off,
            buf_size,
            start: u64::from(JHDR_SIZE),
            end: u64::from(JHDR_SIZE),
            blhdr_size: BLHDR_SIZE,
            jhdr_size: JHDR_SIZE,
            sequence_num: 1,
            endian: Endian(true),
            pending: BTreeMap::new(),
        }
    }

    /// Minimal volume header + journal-info block so `replay` / `load`
    /// can find the ring at `buf_off`.
    fn stamp_jib(
        dev: &mut MemoryBackend,
        buf_off: u64,
        buf_size: u64,
    ) -> crate::fs::hfs_plus::volume_header::VolumeHeader {
        use crate::fs::hfs_plus::volume_header::{
            ExtentDescriptor, FORK_EXTENT_COUNT, ForkData, VolumeHeader,
        };
        let blank_fork = ForkData {
            logical_size: 0,
            clump_size: 0,
            total_blocks: 0,
            extents: [ExtentDescriptor::default(); FORK_EXTENT_COUNT],
        };
        let vh = VolumeHeader {
            signature: *b"H+",
            version: 4,
            attributes: VOL_ATTR_JOURNALED,
            journal_info_block: 1,
            block_size: 4096,
            total_blocks: 16,
            free_blocks: 0,
            next_catalog_id: 16,
            allocation_file: blank_fork,
            extents_file: blank_fork,
            catalog_file: blank_fork,
            attributes_file: blank_fork,
            startup_file: blank_fork,
        };
        let info_off = u64::from(vh.journal_info_block) * u64::from(vh.block_size);
        let mut info = [0u8; 52];
        info[0..4].copy_from_slice(&2u32.to_be_bytes());
        info[36..44].copy_from_slice(&buf_off.to_be_bytes());
        info[44..52].copy_from_slice(&buf_size.to_be_bytes());
        dev.write_at(info_off, &info).unwrap();
        vh
    }

    /// The checksum pinned against a journal header written by macOS
    /// (`hdiutil create -fs "Journaled HFS+"`): little-endian, start =
    /// end = 17408, size 512 KiB, blhdr 8192, jhdr 512, seq 9948135.
    #[test]
    fn calc_checksum_matches_apple_journal_header() {
        let raw = hex(
            "784c4e4a7856341200440000000000000044000000000000000008000000000000200000dd52e70800020000e7cb9700",
        );
        let mut z = raw.clone();
        z[36..40].fill(0);
        assert_eq!(calc_checksum(&z[..JHDR_CKSUM_SIZE]), 0x08e7_52dd);
        // And the block-list header from the same image: max 511, num 4,
        // bytes_used 16896, flags 3, sentinel b_cksum = seq.
        let bl = hex("ff010400004200006d061c7403000000000000000000000000000000e7cb9700");
        let mut z = bl.clone();
        z[8..12].fill(0);
        assert_eq!(calc_checksum(&z), 0x741c_066d);
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Build a minimal in-memory journal buffer (no surrounding HFS+
    /// volume) and verify a single transaction round-trips: commit
    /// records the data, advances start = end, and the target block
    /// has the expected bytes.
    #[test]
    fn journal_commit_writes_data_and_advances_start() {
        let mut dev = MemoryBackend::new(64 * 1024);
        let buf_off: u64 = 8192;
        let buf_size: u64 = 16 * 1024;
        write_journal_header(&mut dev, buf_off, buf_size).unwrap();
        let mut log = fresh_log(buf_off, buf_size);
        log.add(32 * 1024, vec![0xAB; 512]);
        log.commit(&mut dev).unwrap();
        let mut got = [0u8; 512];
        dev.read_at(32 * 1024, &mut got).unwrap();
        assert!(got.iter().all(|&b| b == 0xAB));
        assert_eq!(log.start, log.end);
        assert_eq!(log.sequence_num, 2);
        // The header on disk reloads with the same geometry.
        let vh = stamp_jib(&mut dev, buf_off, buf_size);
        let back = JournalLog::load(&mut dev, &vh).unwrap().unwrap();
        assert_eq!((back.start, back.end), (log.start, log.end));
        assert_eq!(back.blhdr_size, BLHDR_SIZE);
        assert_eq!(back.sequence_num, 2);
    }

    /// A two-step crash simulation: write a transaction (advancing
    /// `end` and applying the writes) but stop before advancing `start`,
    /// then verify replay re-applies the writes idempotently.
    #[test]
    fn replay_reapplies_pending_transaction() {
        let mut dev = MemoryBackend::new(128 * 1024);
        let buf_off: u64 = 8192;
        let buf_size: u64 = 16 * 1024;
        write_journal_header(&mut dev, buf_off, buf_size).unwrap();
        let mut log = fresh_log(buf_off, buf_size);
        log.add(32 * 1024, vec![0xCD; 512]);
        log.commit(&mut dev).unwrap();
        // Now corrupt the target block so we can verify replay
        // restores it, and rewind `start` so the journal looks dirty.
        dev.write_at(32 * 1024, &[0u8; 512]).unwrap();
        rewind_start_for_test(&mut dev, buf_off, u64::from(JHDR_SIZE)).unwrap();
        let vh = stamp_jib(&mut dev, buf_off, buf_size);
        assert!(JournalLog::load(&mut dev, &vh).unwrap().unwrap().is_dirty());

        replay(&mut dev, &vh).unwrap();
        let mut got = [0u8; 512];
        dev.read_at(32 * 1024, &mut got).unwrap();
        assert!(got.iter().all(|&b| b == 0xCD), "replay restored data");
        assert!(!JournalLog::load(&mut dev, &vh).unwrap().unwrap().is_dirty());
    }

    /// A little-endian journal (what a Mac writes) with a transaction
    /// that straddles the ring's wrap point replays correctly, and the
    /// header we write back stays little-endian.
    #[test]
    fn replay_little_endian_wrapping_transaction() {
        let mut dev = MemoryBackend::new(256 * 1024);
        let buf_off: u64 = 8192;
        let buf_size: u64 = 32 * 1024;
        let vh = stamp_jib(&mut dev, buf_off, buf_size);
        // Start the ring near its end so the transaction wraps.
        let mut log = fresh_log(buf_off, buf_size);
        log.endian = Endian(false);
        log.start = buf_size - 4096;
        log.end = log.start;
        log.write_header(&mut dev).unwrap();
        let pattern: Vec<u8> = (0..8192u32).map(|i| (i % 251) as u8).collect();
        log.add(128 * 1024, pattern.clone());
        log.commit(&mut dev).unwrap();
        assert!(
            log.end < log.start || log.end < buf_size - 4096,
            "ring wrapped"
        );

        dev.write_at(128 * 1024, &vec![0u8; 8192]).unwrap();
        rewind_start_for_test(&mut dev, buf_off, buf_size - 4096).unwrap();
        let loaded = JournalLog::load(&mut dev, &vh).unwrap().unwrap();
        assert_eq!(loaded.endian, Endian(false));
        assert!(loaded.is_dirty());
        replay(&mut dev, &vh).unwrap();
        let mut got = vec![0u8; 8192];
        dev.read_at(128 * 1024, &mut got).unwrap();
        assert_eq!(got, pattern);
        let mut hdr = [0u8; 8];
        dev.read_at(buf_off, &mut hdr).unwrap();
        assert_eq!(&hdr[0..4], b"xLNJ", "byte order preserved");
    }

    /// More pending blocks than a single block list / the ring can hold
    /// are committed as several sealed transactions.
    #[test]
    fn commit_splits_oversized_batches() {
        let mut dev = MemoryBackend::new(2 * 1024 * 1024);
        let buf_off: u64 = 8192;
        let buf_size: u64 = 64 * 1024; // the format-time default stub
        let vh = stamp_jib(&mut dev, buf_off, buf_size);
        write_journal_header(&mut dev, buf_off, buf_size).unwrap();
        let mut log = fresh_log(buf_off, buf_size);
        // 40 x 4 KiB = 160 KiB of data, far more than the 56 KiB a
        // transaction can carry here.
        for i in 0..40u64 {
            log.add(512 * 1024 + i * 4096, vec![i as u8 + 1; 4096]);
        }
        log.commit(&mut dev).unwrap();
        assert!(
            log.sequence_num >= 4,
            "took {} transactions",
            log.sequence_num - 1
        );
        for i in 0..40u64 {
            let mut got = [0u8; 4096];
            dev.read_at(512 * 1024 + i * 4096, &mut got).unwrap();
            assert!(got.iter().all(|&b| b == i as u8 + 1), "block {i}");
        }
        let back = JournalLog::load(&mut dev, &vh).unwrap().unwrap();
        assert!(!back.is_dirty());
        assert_eq!(back.sequence_num, log.sequence_num);
    }

    /// Overlapping adds never leave two entries for the same byte; the
    /// most recent data wins and untouched parts of older entries stay.
    #[test]
    fn add_supersedes_overlapping_ranges() {
        let mut log = fresh_log(0, 64 * 1024);
        log.add(4096, vec![1; 4096]);
        log.add(6144, vec![2; 1024]);
        assert_eq!(log.pending_len(), 3);
        assert_eq!(log.lookup(4096).unwrap().1, &[1u8; 2048][..]);
        assert_eq!(log.lookup(6144).unwrap().1, &[2u8; 1024][..]);
        assert_eq!(log.lookup(7168).unwrap().1, &[1u8; 1024][..]);
        assert_eq!(log.lookup(8192), None);
        assert_eq!(log.next_pending_from(0), Some(4096));
        assert_eq!(log.next_pending_from(6145), Some(7168));
        log.remove_range(0, 1 << 20);
        assert_eq!(log.pending_len(), 0);
    }

    /// A header whose checksum does not match is refused rather than
    /// trusted.
    #[test]
    fn load_rejects_bad_header_checksum() {
        let mut dev = MemoryBackend::new(64 * 1024);
        let buf_off: u64 = 8192;
        let buf_size: u64 = 16 * 1024;
        let vh = stamp_jib(&mut dev, buf_off, buf_size);
        write_journal_header(&mut dev, buf_off, buf_size).unwrap();
        assert!(JournalLog::load(&mut dev, &vh).unwrap().is_some());
        let mut hdr = [0u8; 24];
        dev.read_at(buf_off, &mut hdr).unwrap();
        hdr[8..16].copy_from_slice(&1024u64.to_be_bytes());
        dev.write_at(buf_off, &hdr).unwrap();
        let err = match JournalLog::load(&mut dev, &vh) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("load accepted a header with a bad checksum"),
        };
        assert!(err.contains("checksum"), "{err}");
    }
}
