//! Incremental, on-disk editor for an existing AFFS volume.
//!
//! Unlike the rebuild-on-flush [`super::writer::AffsWriter`] (used to *format*
//! a fresh volume), this edits an existing OFS/FFS image in place: an
//! `add` / `mkdir` / `rm` touches only the blocks it must — the volume bitmap,
//! the parent directory's hash chain, and the new/removed file's header, data,
//! and extension blocks — leaving every other block byte-for-byte unchanged.
//! RAM use is bounded by the bitmap, never by file contents.

use crate::block::BlockDevice;
use crate::{Error, Result};

use super::writer::{
    encode_latin1, fix_checksum, hash_name, put_name, put_ptr_table, put_u32, unix_to_amiga,
};
use super::{
    BSIZE, HT_SIZE, MAX_DATABLK, MAX_NAME_LEN, OFF_BYTE_SIZE, OFF_DAYS, OFF_EXTENSION,
    OFF_HASHTABLE, OFF_HIGH_SEQ, OFF_NEXT_SAME_HASH, OFF_SEC_TYPE, OFF_TYPE, ST_FILE, ST_LINKFILE,
    ST_USERDIR, T_DATA, T_HEADER, T_LIST, Variant, be_i32, be_u32,
};

/// Root-block offsets specific to the bitmap.
const OFF_BM_PAGES: usize = 0x13c; // 25 inline bitmap-page pointers
const OFF_BM_EXT: usize = 0x1a0; // bitmap-extension block chain
/// Parent-pointer offset in a file/dir header.
const OFF_PARENT: usize = 0x1f4;
/// First-data-block pointer in a file header.
const OFF_FIRST_DATA: usize = 0x010;

/// Disk-backed incremental editor over an existing AFFS volume.
pub(super) struct AffsEditor {
    total_blocks: u32,
    variant: Variant,
    /// On-disk block numbers of the bitmap pages, in coverage order.
    bitmap_blocks: Vec<u32>,
    /// Concatenated bitmap data longwords (the per-page checksum word
    /// excluded). Word `w` bit `i` (LSB-first) is free for block `2 + w*32 + i`.
    bitmap: Vec<u32>,
    bitmap_dirty: bool,
    /// Block index to start the next free-block scan from.
    next_free_hint: u32,
}

/// Number of bitmap data longwords per page (`BSIZE/4 - 1`; word 0 is checksum).
const WORDS_PER_PAGE: usize = BSIZE / 4 - 1;

impl AffsEditor {
    /// Load the bitmap pages of an already-parsed volume.
    pub(super) fn open(
        dev: &mut dyn BlockDevice,
        total_blocks: u32,
        variant: Variant,
        root_block: u32,
    ) -> Result<Self> {
        // `root_block` is only needed here to locate the bitmap pages; it is
        // not retained (mutations take the parent block from the caller).
        let mut root = vec![0u8; BSIZE];
        dev.read_at(root_block as u64 * BSIZE as u64, &mut root)?;

        // A volume can have at most one bitmap page per `WORDS_PER_PAGE * 32`
        // blocks; cap the collected page list at that so a malformed
        // extension chain can't make `pages` (and the bitmap built from it)
        // grow without bound.
        let max_pages =
            (total_blocks as usize).div_ceil(WORDS_PER_PAGE * 32).max(1) + 1;
        let mut pages: Vec<u32> = Vec::new();
        let push_page = |pages: &mut Vec<u32>, p: u32| -> Result<()> {
            if p != 0 {
                if (p as u64) >= total_blocks as u64 {
                    return Err(Error::InvalidImage(
                        "affs: bitmap page pointer out of range".into(),
                    ));
                }
                if pages.len() >= max_pages {
                    return Err(Error::InvalidImage(
                        "affs: too many bitmap pages".into(),
                    ));
                }
                pages.push(p);
            }
            Ok(())
        };
        for i in 0..25 {
            let p = be_u32(&root, OFF_BM_PAGES + i * 4);
            push_page(&mut pages, p)?;
        }
        // Follow the bitmap-extension chain (each block is WORDS_PER_PAGE page
        // pointers then a next-ext pointer in the final word). The chain is
        // attacker-controlled: validate every extension pointer against the
        // volume's block count and break on a revisited block so a cyclic
        // `bm_ext` can't loop forever (each pass otherwise pushes up to
        // WORDS_PER_PAGE page pointers → OOM).
        let mut bm_ext = be_u32(&root, OFF_BM_EXT);
        let mut visited = std::collections::HashSet::new();
        let mut ext = vec![0u8; BSIZE];
        while bm_ext != 0 {
            if (bm_ext as u64) >= total_blocks as u64 {
                return Err(Error::InvalidImage(
                    "affs: bitmap extension block out of range".into(),
                ));
            }
            if !visited.insert(bm_ext) {
                return Err(Error::InvalidImage("affs: bitmap extension loop".into()));
            }
            dev.read_at(bm_ext as u64 * BSIZE as u64, &mut ext)?;
            for w in 0..WORDS_PER_PAGE {
                let p = be_u32(&ext, w * 4);
                push_page(&mut pages, p)?;
            }
            bm_ext = be_u32(&ext, WORDS_PER_PAGE * 4);
        }

        let mut bitmap = Vec::with_capacity(pages.len() * WORDS_PER_PAGE);
        let mut page = vec![0u8; BSIZE];
        for &p in &pages {
            dev.read_at(p as u64 * BSIZE as u64, &mut page)?;
            for w in 0..WORDS_PER_PAGE {
                bitmap.push(be_u32(&page, 4 + w * 4));
            }
        }

        Ok(Self {
            total_blocks,
            variant,
            bitmap_blocks: pages,
            bitmap,
            bitmap_dirty: false,
            next_free_hint: 2,
        })
    }

    // ── bitmap allocation (bit set = free) ──

    fn is_free(&self, block: u32) -> bool {
        if block < 2 || block >= self.total_blocks {
            return false;
        }
        let idx = (block - 2) as usize;
        let (w, bit) = (idx / 32, idx % 32);
        self.bitmap
            .get(w)
            .map(|&v| (v >> bit) & 1 == 1)
            .unwrap_or(false)
    }

    /// Allocate one free block, marking it used. Errors when the volume is full.
    fn alloc(&mut self) -> Result<u32> {
        let nblocks = self.total_blocks;
        let mut tried = 0u32;
        let mut b = self.next_free_hint.max(2);
        while tried < nblocks {
            if b >= nblocks {
                b = 2;
            }
            if self.is_free(b) {
                let idx = (b - 2) as usize;
                self.bitmap[idx / 32] &= !(1u32 << (idx % 32));
                self.bitmap_dirty = true;
                self.next_free_hint = b + 1;
                return Ok(b);
            }
            b += 1;
            tried += 1;
        }
        Err(Error::InvalidArgument(
            "affs: no free blocks on volume".into(),
        ))
    }

    fn free(&mut self, block: u32) {
        if block < 2 || block >= self.total_blocks {
            return;
        }
        let idx = (block - 2) as usize;
        let (w, bit) = (idx / 32, idx % 32);
        if w < self.bitmap.len() {
            self.bitmap[w] |= 1u32 << bit;
            self.bitmap_dirty = true;
            if block < self.next_free_hint {
                self.next_free_hint = block;
            }
        }
    }

    // ── helpers ──

    fn read_block(&self, dev: &mut dyn BlockDevice, b: u32) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; BSIZE];
        dev.read_at(b as u64 * BSIZE as u64, &mut buf)?;
        Ok(buf)
    }

    fn write_block(&self, dev: &mut dyn BlockDevice, b: u32, buf: &[u8]) -> Result<()> {
        dev.write_at(b as u64 * BSIZE as u64, buf)
    }

    fn validate_name(name: &str) -> Result<()> {
        let bytes = encode_latin1(name)?;
        if bytes.is_empty() || bytes.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument(format!(
                "affs: name {name:?} must be 1..={MAX_NAME_LEN} Latin-1 bytes"
            )));
        }
        Ok(())
    }

    /// Head-insert a freshly written header `new_block` (whose name hashes to
    /// `slot`) into `parent_block`'s hash table. The new header must already
    /// carry the previous bucket head in its `nextSameHash` field.
    fn link_into_parent(
        &self,
        dev: &mut dyn BlockDevice,
        parent_block: u32,
        slot: usize,
        new_block: u32,
    ) -> Result<()> {
        let mut parent = self.read_block(dev, parent_block)?;
        put_u32(&mut parent, OFF_HASHTABLE + slot * 4, new_block);
        fix_checksum(&mut parent, 0x14);
        self.write_block(dev, parent_block, &parent)
    }

    fn set_dates(buf: &mut [u8], mtime: u32) {
        let (d, m, t) = unix_to_amiga(mtime);
        put_u32(buf, OFF_DAYS, d as u32);
        put_u32(buf, OFF_DAYS + 4, m as u32);
        put_u32(buf, OFF_DAYS + 8, t as u32);
    }

    // ── mutations ──

    /// Create an empty directory under `parent_block`. Returns its block.
    pub(super) fn create_dir(
        &mut self,
        dev: &mut dyn BlockDevice,
        parent_block: u32,
        name: &str,
        mtime: u32,
    ) -> Result<u32> {
        Self::validate_name(name)?;
        let slot = hash_name(name, self.variant.intl);
        let old_head = be_u32(
            &self.read_block(dev, parent_block)?,
            OFF_HASHTABLE + slot * 4,
        );
        let new = self.alloc()?;

        let mut b = vec![0u8; BSIZE];
        put_u32(&mut b, OFF_TYPE, T_HEADER as u32);
        put_u32(&mut b, 0x04, new); // headerKey
        // hashTableSize (@0x0c) stays 0 for user dirs (matches real volumes).
        Self::set_dates(&mut b, mtime);
        put_name(&mut b, name);
        put_u32(&mut b, OFF_NEXT_SAME_HASH, old_head);
        put_u32(&mut b, OFF_PARENT, parent_block);
        put_u32(&mut b, OFF_SEC_TYPE, ST_USERDIR as u32);
        fix_checksum(&mut b, 0x14);
        self.write_block(dev, new, &b)?;

        self.link_into_parent(dev, parent_block, slot, new)?;
        Ok(new)
    }

    /// Create a regular file under `parent_block` with `data`. Returns the
    /// file-header block.
    pub(super) fn create_file(
        &mut self,
        dev: &mut dyn BlockDevice,
        parent_block: u32,
        name: &str,
        data: &[u8],
        mtime: u32,
    ) -> Result<u32> {
        Self::validate_name(name)?;
        let ffs = self.variant.ffs;
        let payload = if ffs { BSIZE } else { BSIZE - 24 };
        let ndata = data.len().div_ceil(payload);
        let next_ext = if ndata > MAX_DATABLK {
            (ndata - MAX_DATABLK).div_ceil(MAX_DATABLK)
        } else {
            0
        };

        // Allocate the header first — its block is the data blocks' headerKey.
        let header = self.alloc()?;
        let mut dblocks = Vec::with_capacity(ndata);
        for _ in 0..ndata {
            dblocks.push(self.alloc()?);
        }
        let mut eblocks = Vec::with_capacity(next_ext);
        for _ in 0..next_ext {
            eblocks.push(self.alloc()?);
        }

        // Data blocks.
        for (i, &db) in dblocks.iter().enumerate() {
            let start = i * payload;
            let end = (start + payload).min(data.len());
            let chunk = &data[start..end];
            let mut blk = vec![0u8; BSIZE];
            if ffs {
                blk[..chunk.len()].copy_from_slice(chunk);
            } else {
                put_u32(&mut blk, OFF_TYPE, T_DATA as u32);
                put_u32(&mut blk, 0x04, header); // headerKey = file header
                put_u32(&mut blk, 0x08, i as u32 + 1); // seqNum (1-based)
                put_u32(&mut blk, 0x0c, chunk.len() as u32); // dataSize
                let next = dblocks.get(i + 1).copied().unwrap_or(0);
                put_u32(&mut blk, 0x10, next); // nextData
                blk[24..24 + chunk.len()].copy_from_slice(chunk);
                fix_checksum(&mut blk, 0x14);
            }
            self.write_block(dev, db, &blk)?;
        }

        // Extension blocks (each lists the next MAX_DATABLK data pointers).
        for (ei, &eb) in eblocks.iter().enumerate() {
            let start = MAX_DATABLK * (ei + 1);
            let end = (start + MAX_DATABLK).min(dblocks.len());
            let chunk = &dblocks[start..end];
            let mut ext = vec![0u8; BSIZE];
            put_u32(&mut ext, OFF_TYPE, T_LIST as u32);
            put_u32(&mut ext, 0x04, eb);
            put_u32(&mut ext, OFF_HIGH_SEQ, chunk.len() as u32);
            put_ptr_table(&mut ext, chunk);
            put_u32(&mut ext, OFF_PARENT, header);
            put_u32(
                &mut ext,
                OFF_EXTENSION,
                eblocks.get(ei + 1).copied().unwrap_or(0),
            );
            put_u32(&mut ext, OFF_SEC_TYPE, ST_FILE as u32);
            fix_checksum(&mut ext, 0x14);
            self.write_block(dev, eb, &ext)?;
        }

        // File header.
        let slot = hash_name(name, self.variant.intl);
        let old_head = be_u32(
            &self.read_block(dev, parent_block)?,
            OFF_HASHTABLE + slot * 4,
        );
        let first_chunk = dblocks.len().min(MAX_DATABLK);
        let mut hdr = vec![0u8; BSIZE];
        put_u32(&mut hdr, OFF_TYPE, T_HEADER as u32);
        put_u32(&mut hdr, 0x04, header);
        put_u32(&mut hdr, OFF_HIGH_SEQ, first_chunk as u32);
        put_u32(
            &mut hdr,
            OFF_FIRST_DATA,
            dblocks.first().copied().unwrap_or(0),
        );
        put_ptr_table(&mut hdr, &dblocks[..first_chunk]);
        put_u32(&mut hdr, OFF_BYTE_SIZE, data.len() as u32);
        Self::set_dates(&mut hdr, mtime);
        put_name(&mut hdr, name);
        put_u32(&mut hdr, OFF_NEXT_SAME_HASH, old_head);
        put_u32(&mut hdr, OFF_PARENT, parent_block);
        put_u32(
            &mut hdr,
            OFF_EXTENSION,
            eblocks.first().copied().unwrap_or(0),
        );
        put_u32(&mut hdr, OFF_SEC_TYPE, ST_FILE as u32);
        fix_checksum(&mut hdr, 0x14);
        self.write_block(dev, header, &hdr)?;

        self.link_into_parent(dev, parent_block, slot, header)?;
        Ok(header)
    }

    /// Remove `entry_block` (named `name`) from `parent_block`: splice it out
    /// of the hash chain and free its blocks. A non-empty directory is refused.
    pub(super) fn remove(
        &mut self,
        dev: &mut dyn BlockDevice,
        parent_block: u32,
        entry_block: u32,
        name: &str,
    ) -> Result<()> {
        let entry = self.read_block(dev, entry_block)?;
        let sectype = be_i32(&entry, OFF_SEC_TYPE);
        let entry_next = be_u32(&entry, OFF_NEXT_SAME_HASH);

        if sectype == ST_USERDIR && (0..HT_SIZE).any(|i| be_u32(&entry, OFF_HASHTABLE + i * 4) != 0)
        {
            return Err(Error::InvalidArgument("affs: directory not empty".into()));
        }

        // Unlink from the parent's hash chain.
        let slot = hash_name(name, self.variant.intl);
        let mut parent = self.read_block(dev, parent_block)?;
        let head = be_u32(&parent, OFF_HASHTABLE + slot * 4);
        if head == entry_block {
            put_u32(&mut parent, OFF_HASHTABLE + slot * 4, entry_next);
            fix_checksum(&mut parent, 0x14);
            self.write_block(dev, parent_block, &parent)?;
        } else {
            let mut cur = head;
            let mut guard = 0u32;
            loop {
                if cur == 0 {
                    return Err(Error::InvalidImage(
                        "affs: entry not found in parent hash chain".into(),
                    ));
                }
                let mut cb = self.read_block(dev, cur)?;
                let next = be_u32(&cb, OFF_NEXT_SAME_HASH);
                if next == entry_block {
                    put_u32(&mut cb, OFF_NEXT_SAME_HASH, entry_next);
                    fix_checksum(&mut cb, 0x14);
                    self.write_block(dev, cur, &cb)?;
                    break;
                }
                cur = next;
                guard += 1;
                if guard > self.total_blocks {
                    return Err(Error::InvalidImage("affs: hash chain loop".into()));
                }
            }
        }

        // Free the data + extension blocks for files; then the header itself.
        if sectype == ST_FILE || sectype == ST_LINKFILE {
            let mut cur = entry_block;
            let mut guard = 0u32;
            while cur != 0 {
                let cb = self.read_block(dev, cur)?;
                let hq = be_i32(&cb, OFF_HIGH_SEQ).clamp(0, MAX_DATABLK as i32) as usize;
                for i in 0..hq {
                    let dptr = be_u32(&cb, OFF_HASHTABLE + (MAX_DATABLK - 1 - i) * 4);
                    if dptr != 0 {
                        self.free(dptr);
                    }
                }
                let ext = be_u32(&cb, OFF_EXTENSION);
                if cur != entry_block {
                    self.free(cur); // an extension block
                }
                cur = ext;
                guard += 1;
                if guard > self.total_blocks {
                    return Err(Error::InvalidImage("affs: file extension loop".into()));
                }
            }
        }
        self.free(entry_block);
        Ok(())
    }

    /// Persist the bitmap (recomputing each touched page's checksum).
    pub(super) fn flush(&mut self, dev: &mut dyn BlockDevice) -> Result<()> {
        if self.bitmap_dirty {
            let mut page = vec![0u8; BSIZE];
            for (p, &blk) in self.bitmap_blocks.iter().enumerate() {
                page.fill(0);
                for w in 0..WORDS_PER_PAGE {
                    let val = self
                        .bitmap
                        .get(p * WORDS_PER_PAGE + w)
                        .copied()
                        .unwrap_or(0);
                    put_u32(&mut page, 4 + w * 4, val);
                }
                fix_checksum(&mut page, 0x00);
                self.write_block(dev, blk, &page)?;
            }
            self.bitmap_dirty = false;
        }
        dev.flush()?;
        Ok(())
    }
}
