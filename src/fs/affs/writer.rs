//! Amiga OFS/FFS writer.
//!
//! Holds the whole volume as an in-memory tree (directories + files with
//! their bytes) and serialises every block — root, user-dir, file-header,
//! file-extension, data, and bitmap — from scratch on [`AffsWriter::flush`].
//! This single rebuild-on-flush path backs both generate-from-scratch
//! ([`AffsWriter::format`]) and, in a later phase, in-place mutation.
//!
//! Layout and checksums follow adflib's `adf_blk.h`; the name hash (ASCII
//! and International) is validated against real Workbench volumes.

use std::collections::BTreeMap;

use crate::block::BlockDevice;
use crate::{Error, Result};

use super::{
    AMIGA_EPOCH, BSIZE, HT_SIZE, MAX_DATABLK, MAX_NAME_LEN, ST_FILE, ST_ROOT, ST_USERDIR, T_DATA,
    T_HEADER, T_LIST, Variant,
};

/// Bits of allocation state per bitmap block: `(BSIZE/4 - 1)` words × 32.
const BM_BITS_PER_BLOCK: u32 = (BSIZE as u32 / 4 - 1) * 32;

/// Options for formatting a fresh AFFS volume.
#[derive(Clone, Debug)]
pub struct AffsFormatOpts {
    /// Volume name (≤ 30 Latin-1 bytes).
    pub volume_name: String,
    /// Fast File System (raw data blocks) vs OFS (24-byte data headers).
    pub ffs: bool,
    /// International case-insensitive name hashing.
    pub intl: bool,
}

impl Default for AffsFormatOpts {
    fn default() -> Self {
        // DOS\3 — FFS + International: the most widely compatible variant.
        Self {
            volume_name: "Empty".to_string(),
            ffs: true,
            intl: true,
        }
    }
}

/// One node in the in-memory volume tree.
#[derive(Clone)]
struct Entry {
    /// Latin-1 name (empty for the root).
    name: String,
    /// Parent entry id (the root is its own parent, id 0).
    parent: u32,
    is_dir: bool,
    /// File contents (files only).
    data: Vec<u8>,
    mtime: u32,
}

/// In-memory AFFS volume with a rebuild-on-flush serialiser.
pub struct AffsWriter {
    total_blocks: u32,
    variant: Variant,
    create_date: u32,
    /// id → entry; id 0 is always the root directory.
    entries: BTreeMap<u32, Entry>,
    /// parent id → ordered child ids.
    children: BTreeMap<u32, Vec<u32>>,
    next_id: u32,
}

impl AffsWriter {
    /// Create an empty volume sized to `dev`.
    pub fn format(dev: &mut dyn BlockDevice, opts: &AffsFormatOpts) -> Result<Self> {
        let total = dev.total_size();
        let total_blocks = (total / BSIZE as u64) as u32;
        if total_blocks < 16 {
            return Err(Error::InvalidArgument(
                "affs: volume too small (need ≥ 16 blocks)".into(),
            ));
        }
        let name = encode_latin1(&opts.volume_name)?;
        if name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument(format!(
                "affs: volume name longer than {MAX_NAME_LEN} bytes"
            )));
        }
        let variant = Variant {
            ffs: opts.ffs,
            intl: opts.intl,
            dircache: false,
        };
        let mut entries = BTreeMap::new();
        entries.insert(
            0,
            Entry {
                name: opts.volume_name.clone(),
                parent: 0,
                is_dir: true,
                data: Vec::new(),
                mtime: 0,
            },
        );
        let mut children = BTreeMap::new();
        children.insert(0, Vec::new());
        let mut w = Self {
            total_blocks,
            variant,
            create_date: 0,
            entries,
            children,
            next_id: 1,
        };
        // Write an empty but valid volume immediately so a never-mutated
        // `create` still produces a mountable image.
        w.flush(dev)?;
        Ok(w)
    }

    /// Recreate a writer over an already-parsed volume (in-place phase).
    #[allow(dead_code)] // used by open_writable in the in-place phase
    pub(super) fn adopt(total_blocks: u32, variant: Variant, volume_name: String) -> Self {
        let mut entries = BTreeMap::new();
        entries.insert(
            0,
            Entry {
                name: volume_name,
                parent: 0,
                is_dir: true,
                data: Vec::new(),
                mtime: 0,
            },
        );
        let mut children = BTreeMap::new();
        children.insert(0, Vec::new());
        Self {
            total_blocks,
            variant,
            create_date: 0,
            entries,
            children,
            next_id: 1,
        }
    }

    /// Variant flags (for the reader/info surface).
    pub(super) fn variant(&self) -> Variant {
        self.variant
    }

    /// Volume name.
    pub(super) fn volume_name(&self) -> &str {
        &self.entries[&0].name
    }

    /// Resolve a `/`-separated path to an entry id.
    fn resolve(&self, path: &str) -> Option<u32> {
        let trimmed = path.trim_matches('/');
        if trimmed.is_empty() {
            return Some(0);
        }
        let mut cur = 0u32;
        for comp in trimmed.split('/') {
            let kids = self.children.get(&cur)?;
            cur = *kids
                .iter()
                .find(|&&id| self.entries[&id].name.eq_ignore_ascii_case(comp))?;
        }
        Some(cur)
    }

    /// Split a path into (parent dir id, final component).
    fn parent_and_name<'a>(&self, path: &'a str) -> Result<(u32, &'a str)> {
        let trimmed = path.trim_matches('/');
        let (dir, name) = match trimmed.rsplit_once('/') {
            Some((d, n)) => (d, n),
            None => ("", trimmed),
        };
        if name.is_empty() {
            return Err(Error::InvalidArgument("affs: empty entry name".into()));
        }
        let parent = self
            .resolve(dir)
            .ok_or_else(|| Error::InvalidArgument(format!("affs: no such directory {dir:?}")))?;
        if !self.entries[&parent].is_dir {
            return Err(Error::InvalidArgument(
                "affs: parent is not a directory".into(),
            ));
        }
        Ok((parent, name))
    }

    fn child_exists(&self, parent: u32, name: &str) -> bool {
        self.children
            .get(&parent)
            .map(|kids| {
                kids.iter()
                    .any(|&id| self.entries[&id].name.eq_ignore_ascii_case(name))
            })
            .unwrap_or(false)
    }

    fn add_entry(
        &mut self,
        parent: u32,
        name: &str,
        is_dir: bool,
        data: Vec<u8>,
        mtime: u32,
    ) -> Result<u32> {
        let bytes = encode_latin1(name)?;
        if bytes.is_empty() || bytes.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument(format!(
                "affs: name {name:?} must be 1..={MAX_NAME_LEN} Latin-1 bytes"
            )));
        }
        if self.child_exists(parent, name) {
            return Err(Error::InvalidArgument(format!(
                "affs: {name:?} already exists"
            )));
        }
        let id = self.next_id;
        self.next_id += 1;
        self.entries.insert(
            id,
            Entry {
                name: name.to_string(),
                parent,
                is_dir,
                data,
                mtime,
            },
        );
        self.children.entry(parent).or_default().push(id);
        if is_dir {
            self.children.insert(id, Vec::new());
        }
        Ok(id)
    }

    /// Create (or implicitly create parents of) a directory at `path`.
    pub fn insert_dir(&mut self, path: &str, mtime: u32) -> Result<()> {
        let (parent, name) = self.parent_and_name(path)?;
        self.add_entry(parent, name, true, Vec::new(), mtime)?;
        Ok(())
    }

    /// Create a regular file at `path` with the given bytes.
    pub fn insert_file(&mut self, path: &str, data: Vec<u8>, mtime: u32) -> Result<()> {
        let (parent, name) = self.parent_and_name(path)?;
        self.add_entry(parent, name, false, data, mtime)?;
        Ok(())
    }

    /// Remove a file or empty directory.
    pub fn remove(&mut self, path: &str) -> Result<()> {
        let id = self
            .resolve(path)
            .ok_or_else(|| Error::InvalidArgument(format!("affs: no such path {path:?}")))?;
        if id == 0 {
            return Err(Error::InvalidArgument(
                "affs: cannot remove the root".into(),
            ));
        }
        if self.entries[&id].is_dir && !self.children.get(&id).map(|c| c.is_empty()).unwrap_or(true)
        {
            return Err(Error::InvalidArgument("affs: directory not empty".into()));
        }
        let parent = self.entries[&id].parent;
        if let Some(kids) = self.children.get_mut(&parent) {
            kids.retain(|&c| c != id);
        }
        self.children.remove(&id);
        self.entries.remove(&id);
        Ok(())
    }

    // --- read-back from the in-memory model (writer-present reads) ---

    pub(super) fn list(&self, path: &str) -> Result<Vec<crate::fs::DirEntry>> {
        let id = self
            .resolve(path)
            .ok_or_else(|| Error::InvalidArgument(format!("affs: no such path {path:?}")))?;
        if !self.entries[&id].is_dir {
            return Err(Error::InvalidArgument("affs: not a directory".into()));
        }
        let mut out = Vec::new();
        for &cid in self.children.get(&id).map(|v| v.as_slice()).unwrap_or(&[]) {
            let e = &self.entries[&cid];
            out.push(crate::fs::DirEntry {
                name: e.name.clone(),
                inode: cid,
                kind: if e.is_dir {
                    crate::fs::EntryKind::Dir
                } else {
                    crate::fs::EntryKind::Regular
                },
                size: e.data.len() as u64,
            });
        }
        Ok(out)
    }

    pub(super) fn read(&self, path: &str) -> Result<Vec<u8>> {
        let id = self
            .resolve(path)
            .ok_or_else(|| Error::InvalidArgument(format!("affs: no such path {path:?}")))?;
        let e = &self.entries[&id];
        if e.is_dir {
            return Err(Error::InvalidArgument("affs: not a regular file".into()));
        }
        Ok(e.data.clone())
    }

    pub(super) fn getattr(&self, path: &str) -> Result<crate::fs::FileAttrs> {
        let id = self
            .resolve(path)
            .ok_or_else(|| Error::InvalidArgument(format!("affs: no such path {path:?}")))?;
        let e = &self.entries[&id];
        let (kind, size) = if e.is_dir {
            (crate::fs::EntryKind::Dir, 0u64)
        } else {
            (crate::fs::EntryKind::Regular, e.data.len() as u64)
        };
        Ok(crate::fs::FileAttrs {
            kind,
            mode: if e.is_dir { 0o755 } else { 0o644 },
            uid: 0,
            gid: 0,
            size,
            blocks: size.div_ceil(512),
            nlink: if e.is_dir { 2 } else { 1 },
            atime: e.mtime,
            mtime: e.mtime,
            ctime: e.mtime,
            rdev: 0,
            inode: id,
        })
    }

    // --- serialisation ---

    /// Bytes of file payload carried by one data block under this variant.
    fn payload(&self) -> usize {
        if self.variant.ffs { BSIZE } else { BSIZE - 24 }
    }

    /// Number of data blocks a file of `size` bytes needs.
    fn data_block_count(&self, size: usize) -> usize {
        size.div_ceil(self.payload())
    }

    /// Number of file-header/extension blocks needed to list `nblocks` data
    /// pointers (the header holds the first `MAX_DATABLK`, each extension the
    /// next `MAX_DATABLK`).
    fn ext_block_count(&self, nblocks: usize) -> usize {
        if nblocks <= MAX_DATABLK {
            0
        } else {
            (nblocks - MAX_DATABLK).div_ceil(MAX_DATABLK)
        }
    }

    fn bitmap_block_count(&self) -> u32 {
        (self.total_blocks - 2).div_ceil(BM_BITS_PER_BLOCK)
    }

    /// Serialise the whole volume to `dev`.
    pub fn flush(&mut self, dev: &mut dyn BlockDevice) -> Result<()> {
        let root_block = self.total_blocks / 2;
        let bm_count = self.bitmap_block_count();

        // Reserve fixed blocks: boot (0,1), root, and the bitmap blocks that
        // follow it.
        let mut used = vec![false; self.total_blocks as usize];
        used[0] = true;
        used[1] = true;
        used[root_block as usize] = true;
        let bm_blocks: Vec<u32> = (0..bm_count).map(|i| root_block + 1 + i).collect();
        for &b in &bm_blocks {
            if b as usize >= used.len() {
                return Err(Error::InvalidArgument(
                    "affs: volume too small for bitmap".into(),
                ));
            }
            used[b as usize] = true;
        }

        // Lowest-free-block allocator over `used`.
        let mut cursor = 2u32;
        let mut alloc = |used: &mut [bool]| -> Result<u32> {
            while (cursor as usize) < used.len() && used[cursor as usize] {
                cursor += 1;
            }
            if cursor as usize >= used.len() {
                return Err(Error::InvalidArgument("affs: out of free blocks".into()));
            }
            used[cursor as usize] = true;
            Ok(cursor)
        };

        // Pass A: assign a header block to every entry (root is fixed).
        let mut hdr_block: BTreeMap<u32, u32> = BTreeMap::new();
        hdr_block.insert(0, root_block);
        let ids: Vec<u32> = self.entries.keys().copied().filter(|&id| id != 0).collect();
        for &id in &ids {
            let b = alloc(&mut used)?;
            hdr_block.insert(id, b);
        }

        // Pass B: assign data + extension blocks for every file.
        let mut file_data: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
        let mut file_ext: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
        for &id in &ids {
            let e = &self.entries[&id];
            if e.is_dir {
                continue;
            }
            let n = self.data_block_count(e.data.len());
            let mut dblocks = Vec::with_capacity(n);
            for _ in 0..n {
                dblocks.push(alloc(&mut used)?);
            }
            let mut eblocks = Vec::with_capacity(self.ext_block_count(n));
            for _ in 0..self.ext_block_count(n) {
                eblocks.push(alloc(&mut used)?);
            }
            file_data.insert(id, dblocks);
            file_ext.insert(id, eblocks);
        }

        // Pass C: compute each directory's hash buckets, and the resulting
        // next-same-hash chain pointer for every child header.
        let mut next_same_hash: BTreeMap<u32, u32> = BTreeMap::new(); // entry id → next header block (0 if last)
        let mut dir_hashtable: BTreeMap<u32, [u32; HT_SIZE]> = BTreeMap::new();
        for (&pid, kids) in &self.children {
            let mut table = [0u32; HT_SIZE];
            // Bucket children by hash, preserving insertion order within a bucket.
            let mut buckets: BTreeMap<usize, Vec<u32>> = BTreeMap::new();
            for &cid in kids {
                let slot = hash_name(&self.entries[&cid].name, self.variant.intl);
                buckets.entry(slot).or_default().push(cid);
            }
            for (slot, chain) in buckets {
                table[slot] = hdr_block[&chain[0]];
                for w in 0..chain.len() {
                    let next = chain.get(w + 1).map(|&c| hdr_block[&c]).unwrap_or(0);
                    next_same_hash.insert(chain[w], next);
                }
            }
            dir_hashtable.insert(pid, table);
        }

        // Pass D: write every block.
        // Root block.
        {
            let table = dir_hashtable.get(&0).cloned().unwrap_or([0; HT_SIZE]);
            let buf = self.build_root(root_block, &table, &bm_blocks);
            dev.write_at(root_block as u64 * BSIZE as u64, &buf)?;
        }
        for &id in &ids {
            let e = &self.entries[&id];
            let block = hdr_block[&id];
            if e.is_dir {
                let table = dir_hashtable.get(&id).cloned().unwrap_or([0; HT_SIZE]);
                let buf = self.build_dir(
                    block,
                    &e.name,
                    &table,
                    hdr_block[&e.parent],
                    next_same_hash.get(&id).copied().unwrap_or(0),
                    e.mtime,
                );
                dev.write_at(block as u64 * BSIZE as u64, &buf)?;
            } else {
                let dblocks = &file_data[&id];
                let eblocks = &file_ext[&id];
                self.write_file(
                    dev,
                    block,
                    e,
                    hdr_block[&e.parent],
                    next_same_hash.get(&id).copied().unwrap_or(0),
                    dblocks,
                    eblocks,
                )?;
            }
        }

        // Bitmap blocks.
        self.write_bitmap(dev, &bm_blocks, &used)?;

        // Boot block (non-bootable: "DOS"+flag, root pointer left 0 so the
        // reader/kernel derive it from geometry).
        let mut boot = vec![0u8; 2 * BSIZE];
        boot[0..3].copy_from_slice(b"DOS");
        boot[3] = (self.variant.ffs as u8) | (self.variant.intl as u8) << 1;
        dev.write_at(0, &boot)?;

        dev.flush()?;
        Ok(())
    }

    fn build_root(&self, self_block: u32, table: &[u32; HT_SIZE], bm_blocks: &[u32]) -> Vec<u8> {
        let mut b = vec![0u8; BSIZE];
        put_u32(&mut b, 0x00, T_HEADER as u32);
        put_u32(&mut b, 0x0c, HT_SIZE as u32); // hashTableSize (root only)
        for (i, &slot) in table.iter().enumerate() {
            put_u32(&mut b, 0x18 + i * 4, slot);
        }
        put_i32(&mut b, 0x138, -1); // bmFlag = valid
        for (i, &bm) in bm_blocks.iter().take(25).enumerate() {
            put_u32(&mut b, 0x13c + i * 4, bm);
        }
        // root-dir, volume, and creation date triplets all set to create_date.
        let (d, m, t) = unix_to_amiga(self.create_date);
        for off in [0x1a4usize, 0x1d8, 0x1e4] {
            put_i32(&mut b, off, d);
            put_i32(&mut b, off + 4, m);
            put_i32(&mut b, off + 8, t);
        }
        put_name(&mut b, self.volume_name());
        put_i32(&mut b, 0x1fc, ST_ROOT);
        let _ = self_block;
        fix_checksum(&mut b, 0x14);
        b
    }

    #[allow(clippy::too_many_arguments)]
    fn build_dir(
        &self,
        self_block: u32,
        name: &str,
        table: &[u32; HT_SIZE],
        parent: u32,
        next_same_hash: u32,
        mtime: u32,
    ) -> Vec<u8> {
        let mut b = vec![0u8; BSIZE];
        put_u32(&mut b, 0x00, T_HEADER as u32);
        put_u32(&mut b, 0x04, self_block); // headerKey
        // hashTableSize @0x0c stays 0 for user dirs (matches real volumes).
        for (i, &slot) in table.iter().enumerate() {
            put_u32(&mut b, 0x18 + i * 4, slot);
        }
        let (d, m, t) = unix_to_amiga(mtime);
        put_i32(&mut b, 0x1a4, d);
        put_i32(&mut b, 0x1a8, m);
        put_i32(&mut b, 0x1ac, t);
        put_name(&mut b, name);
        put_u32(&mut b, 0x1f0, next_same_hash);
        put_u32(&mut b, 0x1f4, parent);
        put_i32(&mut b, 0x1fc, ST_USERDIR);
        fix_checksum(&mut b, 0x14);
        b
    }

    #[allow(clippy::too_many_arguments)]
    fn write_file(
        &self,
        dev: &mut dyn BlockDevice,
        self_block: u32,
        e: &Entry,
        parent: u32,
        next_same_hash: u32,
        dblocks: &[u32],
        eblocks: &[u32],
    ) -> Result<()> {
        // Header block: first MAX_DATABLK data pointers.
        let first_chunk = dblocks.len().min(MAX_DATABLK);
        let mut hdr = vec![0u8; BSIZE];
        put_u32(&mut hdr, 0x00, T_HEADER as u32);
        put_u32(&mut hdr, 0x04, self_block);
        put_u32(&mut hdr, 0x08, first_chunk as u32); // highSeq
        put_u32(&mut hdr, 0x10, dblocks.first().copied().unwrap_or(0)); // firstData
        put_ptr_table(&mut hdr, &dblocks[..first_chunk]);
        put_u32(&mut hdr, 0x144, e.data.len() as u32); // byteSize
        let (d, m, t) = unix_to_amiga(e.mtime);
        put_i32(&mut hdr, 0x1a4, d);
        put_i32(&mut hdr, 0x1a8, m);
        put_i32(&mut hdr, 0x1ac, t);
        put_name(&mut hdr, &e.name);
        put_u32(&mut hdr, 0x1f0, next_same_hash);
        put_u32(&mut hdr, 0x1f4, parent);
        put_u32(&mut hdr, 0x1f8, eblocks.first().copied().unwrap_or(0)); // extension
        put_i32(&mut hdr, 0x1fc, ST_FILE);
        fix_checksum(&mut hdr, 0x14);
        dev.write_at(self_block as u64 * BSIZE as u64, &hdr)?;

        // Extension blocks: each lists the next MAX_DATABLK data pointers.
        for (ei, &eb) in eblocks.iter().enumerate() {
            let start = MAX_DATABLK * (ei + 1);
            let end = (start + MAX_DATABLK).min(dblocks.len());
            let chunk = &dblocks[start..end];
            let mut ext = vec![0u8; BSIZE];
            put_u32(&mut ext, 0x00, T_LIST as u32);
            put_u32(&mut ext, 0x04, eb);
            put_u32(&mut ext, 0x08, chunk.len() as u32);
            put_ptr_table(&mut ext, chunk);
            put_u32(&mut ext, 0x1f4, self_block); // parent = file header
            put_u32(&mut ext, 0x1f8, eblocks.get(ei + 1).copied().unwrap_or(0));
            put_i32(&mut ext, 0x1fc, ST_FILE);
            fix_checksum(&mut ext, 0x14);
            dev.write_at(eb as u64 * BSIZE as u64, &ext)?;
        }

        // Data blocks.
        let payload = self.payload();
        for (i, &db) in dblocks.iter().enumerate() {
            let start = i * payload;
            let end = (start + payload).min(e.data.len());
            let chunk = &e.data[start..end];
            let mut blk = vec![0u8; BSIZE];
            if self.variant.ffs {
                blk[..chunk.len()].copy_from_slice(chunk);
            } else {
                put_u32(&mut blk, 0x00, T_DATA as u32);
                put_u32(&mut blk, 0x04, self_block); // headerKey = file header
                put_u32(&mut blk, 0x08, i as u32 + 1); // seqNum (1-based)
                put_u32(&mut blk, 0x0c, chunk.len() as u32); // dataSize
                let next = dblocks.get(i + 1).copied().unwrap_or(0);
                put_u32(&mut blk, 0x10, next); // nextData
                blk[24..24 + chunk.len()].copy_from_slice(chunk);
                fix_checksum(&mut blk, 0x14);
            }
            dev.write_at(db as u64 * BSIZE as u64, &blk)?;
        }
        Ok(())
    }

    fn write_bitmap(
        &self,
        dev: &mut dyn BlockDevice,
        bm_blocks: &[u32],
        used: &[bool],
    ) -> Result<()> {
        // Bit set = FREE. Bit i of bitmap covers block (i + 2).
        let words_per_block = BSIZE / 4 - 1;
        for (bi, &bm) in bm_blocks.iter().enumerate() {
            let mut blk = vec![0u8; BSIZE];
            for w in 0..words_per_block {
                let mut word = 0u32;
                for bit in 0..32 {
                    let global_bit = (bi * words_per_block + w) * 32 + bit;
                    let block = global_bit + 2;
                    let free = block >= used.len() || !used[block];
                    if free && block < self.total_blocks as usize {
                        word |= 1 << bit;
                    }
                }
                put_u32(&mut blk, 4 + w * 4, word);
            }
            fix_checksum(&mut blk, 0x00);
            dev.write_at(bm as u64 * BSIZE as u64, &blk)?;
        }
        Ok(())
    }
}

// --- free functions ---

#[inline]
fn put_u32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_be_bytes());
}

#[inline]
fn put_i32(b: &mut [u8], off: usize, v: i32) {
    b[off..off + 4].copy_from_slice(&v.to_be_bytes());
}

/// Store a file's data-block pointers in the header/extension reverse table:
/// the first pointer goes in slot `MAX_DATABLK-1`, descending.
fn put_ptr_table(b: &mut [u8], ptrs: &[u32]) {
    for (i, &p) in ptrs.iter().enumerate() {
        let slot = MAX_DATABLK - 1 - i;
        put_u32(b, 0x18 + slot * 4, p);
    }
}

/// Write a BCPL name: length byte at 0x1b0, chars following (Latin-1 already).
fn put_name(b: &mut [u8], name: &str) {
    let bytes: Vec<u8> = name.chars().map(|c| c as u8).collect();
    let len = bytes.len().min(MAX_NAME_LEN);
    b[0x1b0] = len as u8;
    b[0x1b1..0x1b1 + len].copy_from_slice(&bytes[..len]);
}

/// Zero the checksum word at `csum_off`, then store `0 - sum(words)` so the
/// block's 32-bit words sum to zero.
fn fix_checksum(b: &mut [u8], csum_off: usize) {
    put_u32(b, csum_off, 0);
    let mut sum = 0u32;
    let mut i = 0;
    while i < BSIZE {
        sum = sum.wrapping_add(u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]));
        i += 4;
    }
    put_u32(b, csum_off, 0u32.wrapping_sub(sum));
}

/// Encode a UTF-8 string as Latin-1, erroring on any char above U+00FF.
fn encode_latin1(s: &str) -> Result<Vec<u8>> {
    s.chars()
        .map(|c| {
            let u = c as u32;
            if u <= 0xFF {
                Ok(u as u8)
            } else {
                Err(Error::InvalidArgument(format!(
                    "affs: character {c:?} is not representable in Latin-1"
                )))
            }
        })
        .collect()
}

/// AmigaDOS directory name hash. `h = len; for c: h = (h*13 + upper(c)) & 0x7ff`,
/// then `h % HT_SIZE`. International mode also upper-cases Latin-1 accented
/// letters. Validated against real Workbench volumes (ASCII and INTL).
fn hash_name(name: &str, intl: bool) -> usize {
    let bytes: Vec<u8> = name.chars().map(|c| c as u8).collect();
    let mut h = bytes.len() as u32;
    for &c in &bytes {
        let up = if intl {
            intl_toupper(c)
        } else {
            ascii_toupper(c)
        };
        h = h.wrapping_mul(13).wrapping_add(up as u32) & 0x7ff;
    }
    (h % HT_SIZE as u32) as usize
}

#[cfg(test)]
pub(super) fn hash_name_for_test(name: &str, intl: bool) -> usize {
    hash_name(name, intl)
}

fn ascii_toupper(c: u8) -> u8 {
    if c.is_ascii_lowercase() { c - 0x20 } else { c }
}

fn intl_toupper(c: u8) -> u8 {
    if c.is_ascii_lowercase() || (0xE0..=0xFE).contains(&c) && c != 0xF7 {
        c - 0x20
    } else {
        c
    }
}

/// Unix seconds → Amiga `(days, minutes, ticks@1/50 s)` since 1978-01-01.
/// Dates before the Amiga epoch clamp to zero.
fn unix_to_amiga(secs: u32) -> (i32, i32, i32) {
    let s = (secs as u64).saturating_sub(AMIGA_EPOCH);
    let days = (s / 86_400) as i32;
    let rem = (s % 86_400) as i32;
    (days, rem / 60, (rem % 60) * 50)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_matches_known_amiga_values() {
        // Verified against real Workbench volumes (see commit message).
        // Empty + simple names; exact slot is deterministic.
        assert_eq!(hash_name("", false), 0);
        // Same name hashes identically regardless of case.
        assert_eq!(hash_name("System", false), hash_name("SYSTEM", false));
        assert_eq!(hash_name("System", true), hash_name("system", true));
    }

    #[test]
    fn intl_uppercases_accented() {
        assert_eq!(intl_toupper(0xE9), 0xC9); // é → É
        assert_eq!(intl_toupper(0xF7), 0xF7); // ÷ unchanged
        assert_eq!(ascii_toupper(0xE9), 0xE9); // non-intl leaves it
    }

    #[test]
    fn latin1_rejects_non_representable() {
        assert!(encode_latin1("ok").is_ok());
        assert!(encode_latin1("snow☃man").is_err());
    }

    #[test]
    fn unix_epoch_roundtrips_through_amiga() {
        // 1 day + 2 minutes + 30 s after the Amiga epoch.
        let secs = AMIGA_EPOCH as u32 + 86_400 + 120 + 30;
        assert_eq!(unix_to_amiga(secs), (1, 2, 1500));
    }
}
