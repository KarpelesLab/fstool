//! Incremental, on-disk editor for an existing AFFS volume.
//!
//! Unlike the rebuild-on-flush [`super::writer::AffsWriter`] (used to *format*
//! a fresh volume), this edits an existing OFS/FFS image in place: an
//! `add` / `mkdir` / `rm` touches only the blocks it must — the volume bitmap,
//! the parent directory's hash chain, and the new/removed file's header, data,
//! and extension blocks — leaving every other block byte-for-byte unchanged.
//! RAM use is bounded by the bitmap, never by file contents.
//!
//! On the directory-cache variants (`DOS\4`/`DOS\5`) every mutation also
//! regenerates the affected directory's `T_DIRCACHE` chain from its hash
//! chains. AmigaDOS serves `List`/`ExNext` from that cache, so a file whose
//! header is linked into the hash table but absent from the cache does not
//! exist as far as the Amiga is concerned — see [`AffsEditor::rebuild_dircache`].

use std::io::Read;

use crate::block::BlockDevice;
use crate::{Error, Result};

use super::writer::{
    encode_latin1, fix_checksum, hash_name, put_name, put_ptr_table, put_u32, unix_to_amiga,
};
use super::{
    BSIZE, HT_SIZE, MAX_DATABLK, MAX_NAME_LEN, OFF_BYTE_SIZE, OFF_DAYS, OFF_EXTENSION,
    OFF_HASHTABLE, OFF_HIGH_SEQ, OFF_NAME_LEN, OFF_NEXT_SAME_HASH, OFF_SEC_TYPE, OFF_TYPE, ST_FILE,
    ST_LINKFILE, ST_USERDIR, T_DATA, T_DIRCACHE, T_HEADER, T_LIST, Variant, be_i32, be_u32,
};

/// Root-block offsets specific to the bitmap.
const OFF_BM_PAGES: usize = 0x13c; // 25 inline bitmap-page pointers
const OFF_BM_EXT: usize = 0x1a0; // bitmap-extension block chain
/// Parent-pointer offset in a file/dir header.
const OFF_PARENT: usize = 0x1f4;
/// First-data-block pointer in a file header.
const OFF_FIRST_DATA: usize = 0x010;
/// Header tail: owner UID (word) then GID (word).
const OFF_OWNER: usize = 0x13c;
/// Header tail: protection bits.
const OFF_PROTECT: usize = 0x140;
/// Header tail: BCPL comment (length byte, then up to 79 chars).
const OFF_COMMENT_LEN: usize = 0x148;
const MAX_COMMENT_LEN: usize = 79;

// `T_DIRCACHE` block layout (adflib `bDirCacheBlock`): type, own key,
// then the directory it caches, the record count, the next cache block,
// the checksum at the usual longword 5, and packed records from byte 24.
const OFF_DC_PARENT: usize = 0x08;
const OFF_DC_RECORDS: usize = 0x0c;
const OFF_DC_NEXT: usize = 0x10;
const OFF_DC_RECORDS_START: usize = 0x18;
/// Record bytes available per cache block.
const DC_CAPACITY: usize = BSIZE - OFF_DC_RECORDS_START;

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
        let max_pages = (total_blocks as usize).div_ceil(WORDS_PER_PAGE * 32).max(1) + 1;
        let mut pages: Vec<u32> = Vec::new();
        let push_page = |pages: &mut Vec<u32>, p: u32| -> Result<()> {
            if p != 0 {
                if (p as u64) >= total_blocks as u64 {
                    return Err(Error::InvalidImage(
                        "affs: bitmap page pointer out of range".into(),
                    ));
                }
                if pages.len() >= max_pages {
                    return Err(Error::InvalidImage("affs: too many bitmap pages".into()));
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

    // ── directory cache (DOS\4 / DOS\5) ──

    /// Pack one dircache record for the entry whose header block (`hdr`)
    /// lives at `entry_block`. Layout, after adflib and cross-checked
    /// against xdftool-built `DOS\5` volumes: entry block, size and
    /// protection as longwords; UID and GID as words; the DateStamp as
    /// three *words*; the secondary type as a signed byte; then the BCPL
    /// name and comment — the whole record padded to an even length.
    fn dircache_record(entry_block: u32, hdr: &[u8]) -> Vec<u8> {
        let sectype = be_i32(hdr, OFF_SEC_TYPE);
        let name_len = (hdr[OFF_NAME_LEN] as usize).min(MAX_NAME_LEN);
        let comment_len = (hdr[OFF_COMMENT_LEN] as usize).min(MAX_COMMENT_LEN);
        let raw = 25 + name_len + comment_len;
        let mut r = vec![0u8; raw + (raw & 1)];
        put_u32(&mut r, 0, entry_block);
        // Longword −47 is a byte size only in a file header; in a directory
        // it is spare, and the cache records 0 for it.
        let size = if sectype == ST_FILE || sectype == ST_LINKFILE {
            be_u32(hdr, OFF_BYTE_SIZE)
        } else {
            0
        };
        put_u32(&mut r, 4, size);
        put_u32(&mut r, 8, be_u32(hdr, OFF_PROTECT));
        r[12..16].copy_from_slice(&hdr[OFF_OWNER..OFF_OWNER + 4]);
        for i in 0..3 {
            let v = be_u32(hdr, OFF_DAYS + i * 4) as u16;
            r[16 + i * 2..18 + i * 2].copy_from_slice(&v.to_be_bytes());
        }
        r[22] = sectype as u8; // i8 view of the secondary type (-3 → 0xFD)
        r[23] = name_len as u8;
        let name_at = 24;
        r[name_at..name_at + name_len]
            .copy_from_slice(&hdr[OFF_NAME_LEN + 1..OFF_NAME_LEN + 1 + name_len]);
        let comment_at = name_at + name_len;
        r[comment_at] = comment_len as u8;
        r[comment_at + 1..comment_at + 1 + comment_len]
            .copy_from_slice(&hdr[OFF_COMMENT_LEN + 1..OFF_COMMENT_LEN + 1 + comment_len]);
        r
    }

    /// Free the `T_DIRCACHE` chain starting at `head`. Stops (without
    /// freeing) at the first block that is not a cache block: a stale or
    /// foreign pointer must not cost some other structure its block.
    fn free_dircache_chain(&mut self, dev: &mut dyn BlockDevice, head: u32) -> Result<()> {
        let mut cur = head;
        let mut guard = 0u32;
        while cur != 0 && cur < self.total_blocks {
            let b = self.read_block(dev, cur)?;
            if be_i32(&b, OFF_TYPE) != T_DIRCACHE {
                break;
            }
            let next = be_u32(&b, OFF_DC_NEXT);
            self.free(cur);
            cur = next;
            guard += 1;
            if guard > self.total_blocks {
                return Err(Error::InvalidImage("affs: directory cache loop".into()));
            }
        }
        Ok(())
    }

    /// Regenerate `dir_block`'s directory cache from its hash chains and
    /// point the directory's `extension` longword at the new chain. No-op
    /// on variants without a cache.
    ///
    /// The old chain is released and a fresh one written, one record per
    /// entry in hash-table order, spilling into another block whenever a
    /// record would not fit (a record never straddles blocks). An empty
    /// directory keeps a single zero-record cache block, which is what the
    /// ROM filesystem and adflib create for a new directory.
    fn rebuild_dircache(&mut self, dev: &mut dyn BlockDevice, dir_block: u32) -> Result<()> {
        if !self.variant.dircache {
            return Ok(());
        }
        let mut dir = self.read_block(dev, dir_block)?;
        self.free_dircache_chain(dev, be_u32(&dir, OFF_EXTENSION))?;

        // Pack records into block payloads as we walk the hash table.
        let mut payloads: Vec<(Vec<u8>, u32)> = Vec::new();
        let mut payload: Vec<u8> = Vec::with_capacity(DC_CAPACITY);
        let mut count = 0u32;
        for slot in 0..HT_SIZE {
            let mut cur = be_u32(&dir, OFF_HASHTABLE + slot * 4);
            let mut guard = 0u32;
            while cur != 0 {
                if cur >= self.total_blocks {
                    return Err(Error::InvalidImage(
                        "affs: hash chain pointer out of range".into(),
                    ));
                }
                let hdr = self.read_block(dev, cur)?;
                let rec = Self::dircache_record(cur, &hdr);
                if payload.len() + rec.len() > DC_CAPACITY {
                    payloads.push((std::mem::take(&mut payload), count));
                    count = 0;
                }
                payload.extend_from_slice(&rec);
                count += 1;
                cur = be_u32(&hdr, OFF_NEXT_SAME_HASH);
                guard += 1;
                if guard > self.total_blocks {
                    return Err(Error::InvalidImage("affs: hash chain loop".into()));
                }
            }
        }
        payloads.push((payload, count));

        let blocks = payloads
            .iter()
            .map(|_| self.alloc())
            .collect::<Result<Vec<u32>>>()?;
        // Write back to front so each block can name its successor.
        let mut next = 0u32;
        for (i, (payload, count)) in payloads.iter().enumerate().rev() {
            let mut buf = vec![0u8; BSIZE];
            put_u32(&mut buf, OFF_TYPE, T_DIRCACHE as u32);
            put_u32(&mut buf, 0x04, blocks[i]);
            put_u32(&mut buf, OFF_DC_PARENT, dir_block);
            put_u32(&mut buf, OFF_DC_RECORDS, *count);
            put_u32(&mut buf, OFF_DC_NEXT, next);
            buf[OFF_DC_RECORDS_START..OFF_DC_RECORDS_START + payload.len()]
                .copy_from_slice(payload);
            fix_checksum(&mut buf, 0x14);
            self.write_block(dev, blocks[i], &buf)?;
            next = blocks[i];
        }
        put_u32(&mut dir, OFF_EXTENSION, blocks[0]);
        fix_checksum(&mut dir, 0x14);
        self.write_block(dev, dir_block, &dir)
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
        // A new directory gets its own (empty) cache; the parent's grows.
        self.rebuild_dircache(dev, new)?;
        self.rebuild_dircache(dev, parent_block)?;
        Ok(new)
    }

    /// Create a regular file under `parent_block`, streaming exactly `len`
    /// bytes of contents forward from `body`. Returns the file-header block.
    ///
    /// `body` is read once, in order: every block (header, data, extension) is
    /// allocated up front from `len`, then each data block is filled from the
    /// next payload-sized run of `body` as it arrives — the file contents are
    /// never held in memory in full.
    pub(super) fn create_file(
        &mut self,
        dev: &mut dyn BlockDevice,
        parent_block: u32,
        name: &str,
        body: &mut dyn Read,
        len: u64,
        mtime: u32,
    ) -> Result<u32> {
        Self::validate_name(name)?;
        let ffs = self.variant.ffs;
        let payload = if ffs { BSIZE } else { BSIZE - 24 };
        let len = len as usize;
        let ndata = len.div_ceil(payload);
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

        // Data blocks: pull each payload-sized chunk forward from `body`.
        let mut remaining = len;
        for (i, &db) in dblocks.iter().enumerate() {
            let chunk = payload.min(remaining);
            remaining -= chunk;
            let data_off = if ffs { 0 } else { 24 };
            let mut blk = vec![0u8; BSIZE];
            body.read_exact(&mut blk[data_off..data_off + chunk])?;
            if !ffs {
                put_u32(&mut blk, OFF_TYPE, T_DATA as u32);
                put_u32(&mut blk, 0x04, header); // headerKey = file header
                put_u32(&mut blk, 0x08, i as u32 + 1); // seqNum (1-based)
                put_u32(&mut blk, 0x0c, chunk as u32); // dataSize
                let next = dblocks.get(i + 1).copied().unwrap_or(0);
                put_u32(&mut blk, 0x10, next); // nextData
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
        put_u32(&mut hdr, OFF_BYTE_SIZE, len as u32);
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
        self.rebuild_dircache(dev, parent_block)?;
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

        // An (empty) directory still owns its cache chain on DOS\4/5.
        if sectype == ST_USERDIR && self.variant.dircache {
            self.free_dircache_chain(dev, be_u32(&entry, OFF_EXTENSION))?;
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
        self.rebuild_dircache(dev, parent_block)
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
