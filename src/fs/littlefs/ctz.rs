//! CTZ skip-lists — how littlefs stores files too large to inline.
//!
//! A file's blocks form a reversed skip-list: block *n* starts with
//! `ctz(n)+1` pointers, the *x*-th of which points at block *n*-2ˣ, and the
//! rest of the block is file data. Only the *last* block (the "head") and
//! the file size are recorded in the metadata, which is enough to reach any
//! offset in O(log n) reads and — crucially for a copy-on-write filesystem —
//! means rewriting the file from some offset onward leaves every earlier
//! block untouched and still correctly pointed at.
//!
//! ```text
//! .--------.  .--------.  .--------.  .--------.  .--------.  .--------.
//! | A      |<-| D      |<-| G      |<-| J      |<-| M      |<-| P      |
//! | B      |<-| E      |--| H      |<-| K      |--| N      |  | Q      |
//! | C      |<-| F      |--| I      |--| L      |--| O      |  |        |
//! '--------'  '--------'  '--------'  '--------'  '--------'  '--------'
//!   block 0     block 1     block 2     block 3     block 4     block 5
//! ```

use std::io::Read;

use crate::block::BlockDevice;
use crate::{Error, Result};

use super::alloc::Alloc;
use super::mdir::Geom;

/// Number of skip pointers stored at the start of block `index`.
pub fn pointers(index: u32) -> u32 {
    if index == 0 {
        0
    } else {
        index.trailing_zeros() + 1
    }
}

/// Bytes of file data block `index` can hold.
pub fn payload(geom: &Geom, index: u32) -> u32 {
    geom.block_size - 4 * pointers(index)
}

/// `ceil(log2(a))`, littlefs's `lfs_npw2`.
fn npw2(a: u32) -> u32 {
    32 - a.wrapping_sub(1).leading_zeros()
}

/// Map a file offset to `(block index, offset within that block)`. The
/// in-block offset includes the skip pointers, so it is the byte position to
/// read from directly.
///
/// This is `lfs_ctz_index`: the pointer overhead of the preceding blocks is
/// a population count, because block *n* carries `ctz(n)+1` pointers and
/// `Σ ctz(k) = n - popcount(n)`.
pub fn index_of(geom: &Geom, off: u32) -> (u32, u32) {
    let b = geom.block_size - 2 * 4;
    let i = off / b;
    if i == 0 {
        return (0, off);
    }
    let i = off.saturating_sub(4 * ((i - 1).count_ones() + 2)) / b;
    let o = off - b * i - 4 * i.count_ones();
    (i, o)
}

/// Read one skip pointer out of a block.
fn read_pointer(dev: &mut dyn BlockDevice, geom: &Geom, block: u32, slot: u32) -> Result<u32> {
    if block >= geom.block_count {
        return Err(Error::InvalidImage(format!(
            "littlefs: file block {block} beyond block count {}",
            geom.block_count
        )));
    }
    let mut b = [0u8; 4];
    dev.read_at(geom.offset(block) + 4 * slot as u64, &mut b)?;
    Ok(u32::from_le_bytes(b))
}

/// Walk the skip-list to the block holding file offset `pos`, returning it
/// and the byte offset to read from inside it.
pub fn find(
    dev: &mut dyn BlockDevice,
    geom: &Geom,
    head: u32,
    size: u32,
    pos: u32,
) -> Result<(u32, u32)> {
    if size == 0 {
        return Err(Error::InvalidArgument(
            "littlefs: seek inside an empty file".into(),
        ));
    }
    let (mut current, _) = index_of(geom, size - 1);
    let (target, off) = index_of(geom, pos);
    let mut head = head;
    // Each hop follows the largest pointer that doesn't overshoot, so the
    // walk costs O(log n) reads rather than O(n). `current` strictly
    // decreases, so a corrupt pointer can't spin here.
    while current > target {
        let skip = npw2(current - target + 1)
            .saturating_sub(1)
            .min(current.trailing_zeros());
        head = read_pointer(dev, geom, head, skip)?;
        current -= 1 << skip;
    }
    Ok((head, off))
}

/// Call `cb` once for every block of the file, from the head backwards.
pub fn traverse(
    dev: &mut dyn BlockDevice,
    geom: &Geom,
    head: u32,
    size: u32,
    cb: &mut dyn FnMut(u32),
) -> Result<()> {
    if size == 0 {
        return Ok(());
    }
    let (mut index, _) = index_of(geom, size - 1);
    let mut head = head;
    loop {
        cb(head);
        if index == 0 {
            return Ok(());
        }
        // An odd index has its predecessor as its only "new" pointer; an
        // even one lets us pick up two blocks per read.
        let count = 2 - (index & 1);
        let mut heads = [0u32; 2];
        for (i, h) in heads.iter_mut().enumerate().take(count as usize) {
            *h = read_pointer(dev, geom, head, i as u32)?;
        }
        for h in heads.iter().take(count as usize - 1) {
            cb(*h);
        }
        head = heads[count as usize - 1];
        // `count` is 1 for an odd index and 2 for an even one, so it never
        // exceeds `index` here and the walk always terminates at block 0.
        index -= count;
    }
}

/// File offset the data in block `index` starts at.
///
/// The inverse of [`index_of`]: every earlier block contributes a full
/// block minus its own skip pointers, and `Σ ctz(k) = n - popcount(n)`
/// collapses that sum into a population count.
pub fn block_start(geom: &Geom, index: u32) -> u32 {
    if index == 0 {
        return 0;
    }
    index * (geom.block_size - 8) + 8 + 4 * (index - 1).count_ones()
}

/// Where the bytes written into a CTZ block come from.
///
/// Rewriting part of a file has to interleave data the caller supplies with
/// data still living in the old skip-list, and reading the latter needs the
/// same block device the writer is using — hence `dev` is threaded through
/// rather than captured.
pub trait ChunkSource {
    /// Fill `buf` with the file's contents starting at file offset `off`.
    fn fill(&mut self, dev: &mut dyn BlockDevice, off: u64, buf: &mut [u8]) -> Result<()>;
}

/// A source that simply streams from a reader.
pub struct ReaderSource<'r> {
    pub body: &'r mut dyn Read,
}

impl ChunkSource for ReaderSource<'_> {
    fn fill(&mut self, _dev: &mut dyn BlockDevice, _off: u64, buf: &mut [u8]) -> Result<()> {
        self.body.read_exact(buf).map_err(Error::from)
    }
}

/// Write file data as CTZ blocks.
///
/// Blocks are emitted starting at `index`, whose predecessor block is
/// `prev` (`None` only when `index` is 0) and whose first byte is at file
/// offset `file_off`. Returns the new head — the last block written — or
/// `prev` when there is nothing to write.
///
/// Exactly `len` bytes are pulled from `src`; nothing larger than one block
/// is ever held in memory.
#[allow(clippy::too_many_arguments)]
pub fn write_blocks(
    dev: &mut dyn BlockDevice,
    geom: &Geom,
    alloc: &mut Alloc,
    mut index: u32,
    mut prev: Option<u32>,
    mut file_off: u64,
    src: &mut dyn ChunkSource,
    len: u64,
) -> Result<Option<u32>> {
    let bs = geom.block_size as usize;
    let mut remaining = len;
    let mut image = vec![0xffu8; bs];

    while remaining > 0 {
        let block = alloc.take()?;
        let skips = pointers(index);
        image.fill(0xff);

        // Skip pointers: the first is our predecessor, and each subsequent
        // one is found by following the previous pointer's own skip list.
        if skips > 0 {
            let mut p = prev.ok_or_else(|| {
                Error::InvalidArgument("littlefs: skip-list continuation without a head".into())
            })?;
            for j in 0..skips {
                let o = 4 * j as usize;
                image[o..o + 4].copy_from_slice(&p.to_le_bytes());
                if j + 1 < skips {
                    p = read_pointer(dev, geom, p, j)?;
                }
            }
        }

        let cap = payload(geom, index) as u64;
        let n = cap.min(remaining) as usize;
        let start = 4 * skips as usize;
        src.fill(dev, file_off, &mut image[start..start + n])?;
        dev.write_at(geom.offset(block), &image)?;

        prev = Some(block);
        index += 1;
        file_off += n as u64;
        remaining -= n as u64;
    }

    Ok(prev)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn geom(block_size: u32) -> Geom {
        Geom {
            block_size,
            block_count: 1024,
            prog_size: 16,
            fcrc: true,
        }
    }

    #[test]
    fn index_math_agrees_with_block_capacities() {
        // Walking the file offset by offset must land on exactly the block
        // sequence the capacities imply — this is the invariant that keeps
        // reads and writes pointing at the same bytes.
        let g = geom(256);
        let mut off = 0u32;
        for index in 0..40u32 {
            let cap = payload(&g, index);
            for within in 0..cap {
                let (i, o) = index_of(&g, off);
                assert_eq!(i, index, "offset {off} should be in block {index}");
                assert_eq!(o, 4 * pointers(index) + within);
                off += 1;
            }
        }
    }

    #[test]
    fn first_block_holds_a_whole_block() {
        let g = geom(4096);
        assert_eq!(payload(&g, 0), 4096);
        assert_eq!(index_of(&g, 0), (0, 0));
        assert_eq!(index_of(&g, 4095), (0, 4095));
        // Block 1 carries one pointer, so its data starts at byte 4.
        assert_eq!(index_of(&g, 4096), (1, 4));
    }

    #[test]
    fn block_start_inverts_index_of() {
        let g = geom(512);
        for index in 0..64u32 {
            let start = block_start(&g, index);
            assert_eq!(index_of(&g, start), (index, 4 * pointers(index)));
            if index > 0 {
                // The byte before is the last of the previous block.
                assert_eq!(index_of(&g, start - 1).0, index - 1);
            }
        }
    }

    #[test]
    fn pointer_counts_follow_ctz() {
        assert_eq!(pointers(0), 0);
        assert_eq!(pointers(1), 1);
        assert_eq!(pointers(2), 2);
        assert_eq!(pointers(3), 1);
        assert_eq!(pointers(4), 3);
        assert_eq!(pointers(8), 4);
    }

    #[test]
    fn npw2_matches_ceil_log2() {
        assert_eq!(npw2(1), 0);
        assert_eq!(npw2(2), 1);
        assert_eq!(npw2(3), 2);
        assert_eq!(npw2(4), 2);
        assert_eq!(npw2(5), 3);
    }
}
