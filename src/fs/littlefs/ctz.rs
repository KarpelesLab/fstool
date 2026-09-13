//! CTZ skip-lists — how littlefs stores files too large to inline.
//!
//! The arithmetic lives in [`super::index`]; this module is the device
//! I/O built on it: walking a skip-list, traversing one for the allocator,
//! and writing a file's blocks out.

use crate::io::Read;
use alloc::format;
use alloc::vec;

use crate::block::BlockDevice;
use crate::{Error, Result};

use super::alloc::Alloc;
use super::mdir::Geom;

/// Number of skip pointers stored at the start of block `index`.
pub use super::index::pointers;

/// Bytes of file data block `index` can hold.
pub fn payload(geom: &Geom, index: u32) -> u32 {
    super::index::payload(geom.block_size, index)
}

/// Map a file offset to `(block index, offset within that block)` — see
/// [`super::index::index_of`].
pub fn index_of(geom: &Geom, off: u32) -> (u32, u32) {
    super::index::index_of(geom.block_size, off)
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
        let (skip, step) = super::index::hop(current, target);
        head = read_pointer(dev, geom, head, skip)?;
        current -= step;
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

/// File offset the data in block `index` starts at — see
/// [`super::index::block_start`].
pub fn block_start(geom: &Geom, index: u32) -> u32 {
    super::index::block_start(geom.block_size, index)
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
