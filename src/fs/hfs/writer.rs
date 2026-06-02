//! Classic-HFS **writer** — generate-from-scratch and (Phase 3) in-place
//! mutation.
//!
//! Mirrors the HFS+ writer's architecture (`src/fs/hfs_plus/writer.rs`): the
//! catalog is held as an in-memory `BTreeMap<OwnedKey, Vec<u8>>` and the on-disk
//! B-trees are **rebuilt from scratch on every [`HfsWriter::flush`]** by greedily
//! packing the sorted records into 512-byte nodes — no incremental node-splits.
//! `format` (empty catalog) and `open_writable` (catalog loaded from disk) feed
//! the same machinery, so one module covers both create and in-place edit.
//!
//! On-disk facts come from *Inside Macintosh: Files*; field offsets match the
//! reader's decoders in `super` (e.g. `filExtRec` @ +74, `filMdDat` @ +48).

use std::collections::BTreeMap;

use super::{ExtRec, MAC_EPOCH_DELTA, ROOT_CNID, round_up_even};
use crate::block::BlockDevice;
use crate::macroman;
use crate::{Error, Result};

/// Parent of the root directory (the root's catalog record is keyed by this).
const ROOT_PARENT_CNID: u32 = 1;
/// First CNID handed out to user files/dirs (1..=15 are reserved).
const FIRST_USER_CNID: u32 = 16;
/// 512-byte B-tree node.
const NODE: usize = 512;
/// Node-descriptor length (fLink/bLink/type/height/numRecs/reserved).
const DESC: usize = 14;
/// B-tree node kinds (`ndType`).
const ND_LEAF: u8 = 0xFF;
const ND_INDEX: u8 = 0x00;
const ND_HEADER: u8 = 0x01;
/// Catalog record kinds (`cdrType`).
const CDR_DIR: u8 = 1;
const CDR_FILE: u8 = 2;
const CDR_DIR_THREAD: u8 = 3;

fn put_u16(v: &mut [u8], o: usize, x: u16) {
    v[o..o + 2].copy_from_slice(&x.to_be_bytes());
}
fn put_u32(v: &mut [u8], o: usize, x: u32) {
    v[o..o + 4].copy_from_slice(&x.to_be_bytes());
}

/// Unix seconds → classic-Mac local seconds (1904 epoch).
fn mac_time(unix: u32) -> u32 {
    unix.saturating_add(MAC_EPOCH_DELTA)
}

/// Options for formatting a fresh classic-HFS volume (`Hfs::format`).
#[derive(Debug, Clone)]
pub struct HfsFormatOpts {
    /// Volume name (also the root directory's catalog name). ≤ 27 MacRoman
    /// bytes.
    pub volume_name: String,
    /// Allocation-block size in bytes (multiple of 512). `None` = auto-pick the
    /// smallest 512-multiple that keeps the block count ≤ 65535.
    pub block_size: Option<u32>,
}

impl Default for HfsFormatOpts {
    fn default() -> Self {
        Self {
            volume_name: "Untitled".to_string(),
            block_size: None,
        }
    }
}

/// In-memory catalog key: `(parentID, name)` ordered the way the HFS catalog
/// B-tree orders records — parent ID numerically, then the name by the
/// case-insensitive MacRoman collation ([`macroman::cmp_ci`]).
#[derive(Clone, PartialEq, Eq)]
pub(super) struct OwnedKey {
    pub parid: u32,
    /// Name as MacRoman bytes (empty for thread records).
    pub name: Vec<u8>,
}

impl Ord for OwnedKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.parid
            .cmp(&other.parid)
            .then_with(|| macroman::cmp_ci(&self.name, &other.name))
    }
}
impl PartialOrd for OwnedKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// A writable classic-HFS volume's mutable state.
pub(super) struct HfsWriter {
    /// Allocation-block size in bytes (`drAlBlkSiz`).
    pub block_size: u32,
    /// Byte offset of allocation block 0 (`drAlBlSt` × 512).
    pub alloc_base: u64,
    /// First sector of the volume bitmap (`drVBMSt`).
    pub vbm_start: u64,
    /// Number of allocation blocks (`drNmAlBlks`).
    pub total_blocks: u16,
    /// Total device sectors (512-byte).
    pub total_sectors: u64,
    /// Volume bitmap, `ceil(total_blocks/8)` bytes (bit set = used).
    pub bitmap: Vec<u8>,
    /// Bump cursor for the next allocation search.
    pub next_alloc: u16,
    /// Free allocation blocks (`drFreeBks`).
    pub free_blocks: u16,
    /// Next unused CNID (`drNxtCNID`).
    pub next_cnid: u32,
    /// Catalog records, keyed and ordered for the B-tree.
    pub catalog: BTreeMap<OwnedKey, Vec<u8>>,
    /// Extents-overflow records: `(forkType, cnid, startBlock) → 3 extents`.
    pub overflow: BTreeMap<(u8, u32, u16), ExtRec>,
    /// Volume name (`drVN`).
    pub volume_name: String,
    /// Volume creation date (Mac epoch).
    pub create_date: u32,
    /// Catalog file extents (up to 3) + byte size, re-allocated each flush.
    cat_extents: ExtRec,
    cat_size: u32,
    /// Extents-overflow file extents (up to 3) + byte size.
    ext_extents: ExtRec,
    ext_size: u32,
}

impl HfsWriter {
    /// Format a fresh, empty classic-HFS volume on `dev` (boot blocks + MDB +
    /// volume bitmap, an empty root directory and its thread). The caller adds
    /// files via [`Self::insert_file`]/[`Self::insert_dir`] and persists with
    /// [`Self::flush`].
    pub fn format(dev: &mut dyn BlockDevice, opts: &HfsFormatOpts) -> Result<Self> {
        let total_sectors = dev.total_size() / 512;
        if total_sectors < 16 {
            return Err(Error::InvalidArgument(
                "hfs: volume too small to format".into(),
            ));
        }
        let block_size = match opts.block_size {
            Some(b) => {
                if b == 0 || !b.is_multiple_of(512) {
                    return Err(Error::InvalidArgument(
                        "hfs: block_size must be a non-zero multiple of 512".into(),
                    ));
                }
                b
            }
            None => auto_block_size(total_sectors),
        };
        let name_bytes = macroman::encode(&opts.volume_name)?;
        if name_bytes.is_empty() || name_bytes.len() > 27 {
            return Err(Error::InvalidArgument(
                "hfs: volume name must be 1..=27 MacRoman bytes".into(),
            ));
        }

        let geom = Geometry::compute(total_sectors, block_size)?;
        let bitmap = vec![0u8; geom.total_blocks.div_ceil(8) as usize];

        let create = mac_time(0);
        let mut w = HfsWriter {
            block_size,
            alloc_base: geom.al_bl_st * 512,
            vbm_start: geom.vbm_start,
            total_blocks: geom.total_blocks,
            total_sectors,
            bitmap,
            next_alloc: 0,
            free_blocks: geom.total_blocks,
            next_cnid: FIRST_USER_CNID,
            catalog: BTreeMap::new(),
            overflow: BTreeMap::new(),
            volume_name: opts.volume_name.clone(),
            create_date: create,
            cat_extents: [(0, 0); 3],
            cat_size: 0,
            ext_extents: [(0, 0); 3],
            ext_size: 0,
        };

        // Seed the root directory (CNID 2, parent CNID 1, name = volume name)
        // plus its thread record (keyed by CNID 2, empty name).
        w.catalog.insert(
            OwnedKey {
                parid: ROOT_PARENT_CNID,
                name: name_bytes.clone(),
            },
            encode_dir(ROOT_CNID, 0, create),
        );
        w.catalog.insert(
            OwnedKey {
                parid: ROOT_CNID,
                name: Vec::new(),
            },
            encode_thread(ROOT_PARENT_CNID, &name_bytes),
        );
        Ok(w)
    }

    /// Number of entries directly in the root (`drNmFls`).
    fn root_valence(&self) -> u16 {
        self.catalog
            .keys()
            .filter(|k| k.parid == ROOT_CNID && !k.name.is_empty())
            .count() as u16
    }

    /// Volume-wide catalog counts for the MDB: `(total files, total dirs
    /// excluding root, dirs directly in root)`.
    fn counts(&self) -> (u32, u32, u16) {
        let mut files = 0u32;
        let mut dirs = 0u32;
        let mut root_dirs = 0u16;
        for (key, body) in &self.catalog {
            match body.first().copied() {
                Some(CDR_FILE) => files += 1,
                Some(CDR_DIR) => {
                    let cnid = u32::from_be_bytes([body[6], body[7], body[8], body[9]]);
                    if cnid != ROOT_CNID {
                        dirs += 1;
                    }
                    if key.parid == ROOT_CNID {
                        root_dirs += 1;
                    }
                }
                _ => {}
            }
        }
        (files, dirs, root_dirs)
    }

    // ---- allocation -----------------------------------------------------

    fn bit_used(&self, b: u16) -> bool {
        self.bitmap[(b / 8) as usize] & (0x80 >> (b % 8)) != 0
    }
    fn mark(&mut self, start: u16, count: u16, used: bool) {
        for b in start..start + count {
            let (byi, mask) = ((b / 8) as usize, 0x80u8 >> (b % 8));
            if used {
                self.bitmap[byi] |= mask;
            } else {
                self.bitmap[byi] &= !mask;
            }
        }
    }

    /// Allocate `n` blocks as one or more runs (greedy from the bump cursor,
    /// falling back to a first-fit scan). Marks them used.
    fn allocate(&mut self, n: u16) -> Result<Vec<(u16, u16)>> {
        if n == 0 {
            return Ok(Vec::new());
        }
        if self.free_blocks < n {
            return Err(Error::Unsupported("hfs: volume full".into()));
        }
        let mut runs = Vec::new();
        let mut need = n;
        let mut cur = self.next_alloc.min(self.total_blocks);
        while need > 0 {
            // Skip used blocks.
            while cur < self.total_blocks && self.bit_used(cur) {
                cur += 1;
            }
            if cur >= self.total_blocks {
                // Wrap to the start once.
                cur = 0;
                while cur < self.total_blocks && self.bit_used(cur) {
                    cur += 1;
                }
                if cur >= self.total_blocks {
                    return Err(Error::Unsupported("hfs: volume full".into()));
                }
            }
            let start = cur;
            let mut len = 0u16;
            while cur < self.total_blocks && !self.bit_used(cur) && len < need {
                cur += 1;
                len += 1;
            }
            self.mark(start, len, true);
            self.free_blocks -= len;
            need -= len;
            runs.push((start, len));
        }
        self.next_alloc = cur;
        Ok(runs)
    }

    fn free_run(&mut self, start: u16, count: u16) {
        if count == 0 {
            return;
        }
        self.mark(start, count, false);
        self.free_blocks += count;
        if start < self.next_alloc {
            self.next_alloc = start;
        }
    }

    // ---- mutation -------------------------------------------------------

    /// Resolve a `/`-separated **canonical** directory path to its CNID.
    pub fn resolve_dir(&self, path: &str) -> Result<u32> {
        let mut cnid = ROOT_CNID;
        for comp in path.split('/').filter(|c| !c.is_empty()) {
            let name = encode_component(comp)?;
            let body = self
                .catalog
                .get(&OwnedKey { parid: cnid, name })
                .ok_or_else(|| {
                    Error::InvalidArgument(format!("hfs: no such directory component {comp:?}"))
                })?;
            if body.first() != Some(&CDR_DIR) {
                return Err(Error::InvalidArgument(format!(
                    "hfs: path component {comp:?} is not a directory"
                )));
            }
            cnid = u32::from_be_bytes([body[6], body[7], body[8], body[9]]);
        }
        Ok(cnid)
    }

    /// Split a canonical path into `(parent_cnid, leaf_name_bytes)`.
    fn split_parent_leaf(&self, path: &str) -> Result<(u32, Vec<u8>)> {
        let trimmed = path.trim_end_matches('/');
        let (parent_path, leaf) = match trimmed.rsplit_once('/') {
            Some((p, l)) => (p, l),
            None => ("", trimmed),
        };
        if leaf.is_empty() {
            return Err(Error::InvalidArgument(
                "hfs: cannot target the root path".into(),
            ));
        }
        let parent = self.resolve_dir(parent_path)?;
        let name = encode_component(leaf)?;
        if name.len() > 31 {
            return Err(Error::InvalidArgument(
                "hfs: name exceeds 31 MacRoman bytes".into(),
            ));
        }
        Ok((parent, name))
    }

    /// Like [`Self::split_parent_leaf`] but errors if the target already exists.
    fn parent_and_leaf(&self, path: &str) -> Result<(u32, Vec<u8>)> {
        let (parent, name) = self.split_parent_leaf(path)?;
        if self.catalog.contains_key(&OwnedKey {
            parid: parent,
            name: name.clone(),
        }) {
            return Err(Error::InvalidArgument(format!(
                "hfs: {path:?} already exists"
            )));
        }
        Ok((parent, name))
    }

    /// Remove a file or empty directory at canonical `path`, freeing a file's
    /// data-fork blocks (inline + extents-overflow).
    pub fn remove(&mut self, path: &str) -> Result<()> {
        let (parent, name) = self.split_parent_leaf(path)?;
        let key = OwnedKey {
            parid: parent,
            name,
        };
        let body = self
            .catalog
            .get(&key)
            .ok_or_else(|| Error::InvalidArgument(format!("hfs: no such path {path:?}")))?;
        match body.first().copied() {
            Some(CDR_DIR) => {
                let valence = u16::from_be_bytes([body[4], body[5]]);
                if valence != 0 {
                    return Err(Error::InvalidArgument(format!(
                        "hfs: directory {path:?} is not empty"
                    )));
                }
                let cnid = u32::from_be_bytes([body[6], body[7], body[8], body[9]]);
                self.catalog.remove(&key);
                self.catalog.remove(&OwnedKey {
                    parid: cnid,
                    name: Vec::new(),
                });
            }
            Some(CDR_FILE) => {
                let cnid = u32::from_be_bytes([body[20], body[21], body[22], body[23]]);
                let ext = super::ext_rec(body, 74);
                self.catalog.remove(&key);
                for (s, c) in ext {
                    self.free_run(s, c);
                }
                // Free any extents-overflow runs for this file's data fork.
                let keys: Vec<_> = self
                    .overflow
                    .range((0x00u8, cnid, 0u16)..=(0x00u8, cnid, u16::MAX))
                    .map(|(&k, _)| k)
                    .collect();
                for k in keys {
                    if let Some(grp) = self.overflow.remove(&k) {
                        for (s, c) in grp {
                            self.free_run(s, c);
                        }
                    }
                }
            }
            _ => {
                return Err(Error::InvalidArgument(format!(
                    "hfs: {path:?} is not a removable file or directory"
                )));
            }
        }
        self.bump_valence(parent, -1)?;
        Ok(())
    }

    /// Build a writer around an existing volume's loaded state (used by
    /// `Hfs::open_writable`). The catalog/extents files' current extents are
    /// recorded so the first flush re-allocates them cleanly.
    #[allow(clippy::too_many_arguments)]
    pub fn adopt(
        block_size: u32,
        alloc_base: u64,
        vbm_start: u64,
        total_blocks: u16,
        total_sectors: u64,
        bitmap: Vec<u8>,
        free_blocks: u16,
        next_cnid: u32,
        catalog: BTreeMap<OwnedKey, Vec<u8>>,
        overflow: BTreeMap<(u8, u32, u16), ExtRec>,
        volume_name: String,
        create_date: u32,
        cat_extents: ExtRec,
        cat_size: u32,
        ext_extents: ExtRec,
        ext_size: u32,
    ) -> Self {
        HfsWriter {
            block_size,
            alloc_base,
            vbm_start,
            total_blocks,
            total_sectors,
            bitmap,
            next_alloc: 0,
            free_blocks,
            next_cnid,
            catalog,
            overflow,
            volume_name,
            create_date,
            cat_extents,
            cat_size,
            ext_extents,
            ext_size,
        }
    }

    fn bump_valence(&mut self, dir_cnid: u32, delta: i32) -> Result<()> {
        // The directory record is keyed (its-parent, its-name); find it via the
        // thread record (keyed by the dir's own CNID).
        if dir_cnid == ROOT_CNID {
            return Ok(()); // root valence is derived in the MDB write
        }
        let thread = self
            .catalog
            .get(&OwnedKey {
                parid: dir_cnid,
                name: Vec::new(),
            })
            .ok_or_else(|| Error::InvalidImage("hfs: missing directory thread".into()))?;
        let parent = u32::from_be_bytes([thread[10], thread[11], thread[12], thread[13]]);
        let name = thread[15..15 + thread[14] as usize].to_vec();
        let body = self
            .catalog
            .get_mut(&OwnedKey {
                parid: parent,
                name,
            })
            .ok_or_else(|| Error::InvalidImage("hfs: missing directory record".into()))?;
        let val = u16::from_be_bytes([body[4], body[5]]);
        let nv = (val as i32 + delta).clamp(0, u16::MAX as i32) as u16;
        put_u16(body, 4, nv);
        Ok(())
    }

    /// Create an empty directory at canonical `path`; returns its CNID.
    pub fn insert_dir(&mut self, path: &str, mtime: u32) -> Result<u32> {
        let (parent, name) = self.parent_and_leaf(path)?;
        let cnid = self.next_cnid;
        self.next_cnid += 1;
        let t = mac_time(mtime);
        self.catalog.insert(
            OwnedKey {
                parid: parent,
                name: name.clone(),
            },
            encode_dir(cnid, 0, t),
        );
        self.catalog.insert(
            OwnedKey {
                parid: cnid,
                name: Vec::new(),
            },
            encode_thread(parent, &name),
        );
        self.bump_valence(parent, 1)?;
        Ok(cnid)
    }

    /// Create a file at canonical `path` from `src` (`len` bytes); returns its
    /// CNID. Streams the data fork into freshly-allocated blocks.
    pub fn insert_file(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &str,
        src: &mut dyn std::io::Read,
        len: u64,
        mtime: u32,
    ) -> Result<u32> {
        let (parent, name) = self.parent_and_leaf(path)?;
        let cnid = self.next_cnid;
        let (extents, total_blocks) = self.stream_data(dev, src, len, cnid)?;
        self.next_cnid += 1;
        let t = mac_time(mtime);
        self.catalog.insert(
            OwnedKey {
                parid: parent,
                name,
            },
            encode_file(cnid, len, t, &extents, total_blocks, self.block_size),
        );
        self.bump_valence(parent, 1)?;
        Ok(cnid)
    }

    /// Allocate blocks for a `len`-byte fork, stream `src` into them, and return
    /// the (up to 3 inline) extents plus the total block count. Extents beyond 3
    /// spill into the extents-overflow B-tree.
    fn stream_data(
        &mut self,
        dev: &mut dyn BlockDevice,
        src: &mut dyn std::io::Read,
        len: u64,
        cnid: u32,
    ) -> Result<(ExtRec, u16)> {
        let bs = u64::from(self.block_size);
        let total_blocks_u64 = len.div_ceil(bs);
        let total_blocks = u16::try_from(total_blocks_u64).map_err(|_| {
            Error::Unsupported("hfs: file too large for a 16-bit block count".into())
        })?;
        let runs = if total_blocks == 0 {
            Vec::new()
        } else {
            self.allocate(total_blocks)?
        };

        // Stream bytes into the allocated runs.
        let mut buf = vec![0u8; 64 * 1024];
        let mut written = 0u64;
        for &(start, count) in &runs {
            let mut off = self.alloc_base + u64::from(start) * bs;
            let mut run_remaining = u64::from(count) * bs;
            while run_remaining > 0 && written < len {
                let want = (len - written).min(run_remaining).min(buf.len() as u64) as usize;
                let mut filled = 0;
                while filled < want {
                    let n = src.read(&mut buf[filled..want])?;
                    if n == 0 {
                        return Err(Error::InvalidArgument(
                            "hfs: source ended before declared length".into(),
                        ));
                    }
                    filled += n;
                }
                dev.write_at(off, &buf[..filled])?;
                off += filled as u64;
                run_remaining -= filled as u64;
                written += filled as u64;
            }
            // Zero the slack in this run's tail.
            if run_remaining > 0 {
                let zero = vec![0u8; run_remaining as usize];
                dev.write_at(off, &zero)?;
            }
        }

        // Pack into 3 inline extents; the rest into extents-overflow.
        let mut inline: ExtRec = [(0, 0); 3];
        for (slot, run) in inline.iter_mut().zip(runs.iter()) {
            *slot = *run;
        }
        if runs.len() > 3 {
            // Record overflow extents in groups of 3, keyed by start block.
            let mut start_block: u16 = inline.iter().map(|e| e.1).sum();
            let mut rest = &runs[3..];
            while !rest.is_empty() {
                let mut grp: ExtRec = [(0, 0); 3];
                let take = rest.len().min(3);
                for (slot, run) in grp.iter_mut().zip(rest.iter()) {
                    *slot = *run;
                }
                self.overflow.insert((0x00, cnid, start_block), grp);
                start_block += grp.iter().map(|e| e.1).sum::<u16>();
                rest = &rest[take..];
            }
        }
        Ok((inline, total_blocks))
    }

    // ---- flush ----------------------------------------------------------

    /// Rebuild the catalog + extents-overflow B-trees, the volume bitmap, and
    /// the (primary + alternate) MDB, and write everything to `dev`.
    pub fn flush(&mut self, dev: &mut dyn BlockDevice) -> Result<()> {
        // Free the previous B-tree files so a re-flush re-allocates cleanly.
        for (s, c) in std::mem::take(&mut self.cat_extents) {
            self.free_run(s, c);
        }
        for (s, c) in std::mem::take(&mut self.ext_extents) {
            self.free_run(s, c);
        }

        // Build the extents-overflow B-tree (leaf records sorted by key).
        let ext_records: Vec<Vec<u8>> = self
            .overflow
            .iter()
            .map(|(&(fork, cnid, start), ext)| encode_extent_record(fork, cnid, start, ext))
            .collect();
        let ext_nodes = build_btree(&ext_records, 7)?;

        // Build the catalog B-tree.
        let cat_records: Vec<Vec<u8>> = self
            .catalog
            .iter()
            .map(|(k, body)| encode_leaf_record(k, body))
            .collect();
        let cat_nodes = build_btree(&cat_records, 37)?;

        // Allocate blocks (up to 3 extents each — what the MDB can record) for
        // each B-tree file and write the nodes across them.
        let bs = u64::from(self.block_size);
        let ext_blocks = ((ext_nodes.len() * NODE) as u64).div_ceil(bs) as u16;
        let cat_blocks = ((cat_nodes.len() * NODE) as u64).div_ceil(bs) as u16;
        let ext_extents = self.alloc_btree_file(ext_blocks)?;
        let cat_extents = self.alloc_btree_file(cat_blocks)?;
        self.ext_extents = ext_extents;
        self.ext_size = ext_blocks as u32 * self.block_size;
        self.cat_extents = cat_extents;
        self.cat_size = cat_blocks as u32 * self.block_size;

        write_nodes_across(dev, self.alloc_base, bs, &ext_extents, &ext_nodes)?;
        write_nodes_across(dev, self.alloc_base, bs, &cat_extents, &cat_nodes)?;

        // Volume bitmap.
        dev.write_at(self.vbm_start * 512, &self.bitmap)?;

        // MDB (primary at sector 2, alternate at second-to-last sector).
        let mdb = self.encode_mdb();
        dev.write_at(1024, &mdb)?;
        dev.write_at((self.total_sectors - 2) * 512, &mdb)?;
        dev.sync()?;
        Ok(())
    }

    /// Allocate `n` blocks for a B-tree file as at most 3 extents (the MDB's
    /// `drCTExtRec`/`drXTExtRec` hold 3); error if the free space is too
    /// fragmented to fit in 3.
    fn alloc_btree_file(&mut self, n: u16) -> Result<ExtRec> {
        let runs = self.allocate(n)?;
        if runs.len() > 3 {
            return Err(Error::Unsupported(
                "hfs: B-tree file needs more than 3 extents (volume too fragmented)".into(),
            ));
        }
        let mut ext: ExtRec = [(0, 0); 3];
        for (slot, run) in ext.iter_mut().zip(runs) {
            *slot = run;
        }
        Ok(ext)
    }

    fn encode_mdb(&self) -> [u8; 162] {
        let mut m = [0u8; 162];
        m[0..2].copy_from_slice(b"BD"); // drSigWord
        put_u32(&mut m, 2, self.create_date); // drCrDate
        put_u32(&mut m, 6, self.create_date); // drLsMod
        put_u16(&mut m, 10, 1 << 8); // drAtrb: "volume unmounted cleanly"
        put_u16(&mut m, 12, self.root_valence()); // drNmFls
        put_u16(&mut m, 14, self.vbm_start as u16); // drVBMSt
        put_u16(&mut m, 16, self.next_alloc); // drAllocPtr
        put_u16(&mut m, 18, self.total_blocks); // drNmAlBlks
        put_u32(&mut m, 20, self.block_size); // drAlBlkSiz
        put_u32(&mut m, 24, self.block_size); // drClpSiz
        put_u16(&mut m, 28, (self.alloc_base / 512) as u16); // drAlBlSt
        put_u32(&mut m, 30, self.next_cnid); // drNxtCNID
        put_u16(&mut m, 34, self.free_blocks); // drFreeBks
        // Volume-wide counts (validated by fsck): drNmRtDirs @82, drFilCnt @84,
        // drDirCnt @88.
        let (files, dirs, root_dirs) = self.counts();
        put_u16(&mut m, 82, root_dirs);
        put_u32(&mut m, 84, files);
        put_u32(&mut m, 88, dirs);
        // drVN: Str27 at +36.
        let vn = macroman::encode(&self.volume_name).unwrap_or_default();
        m[36] = vn.len() as u8;
        m[37..37 + vn.len()].copy_from_slice(&vn);
        // Extents-overflow file (drXTFlSize @130, drXTExtRec @134).
        put_u32(&mut m, 130, self.ext_size);
        put_ext(&mut m, 134, &self.ext_extents);
        // Catalog file (drCTFlSize @146, drCTExtRec @150).
        put_u32(&mut m, 146, self.cat_size);
        put_ext(&mut m, 150, &self.cat_extents);
        m
    }
}

/// Encode a `/`-separated path **component** to MacRoman catalog bytes,
/// reversing the reader's `/`→`:` canonicalisation (a `:` in the canonical name
/// is a real `/` on disk).
fn encode_component(comp: &str) -> Result<Vec<u8>> {
    macroman::encode(&comp.replace(':', "/"))
}

// ---- record encoders ----------------------------------------------------

fn encode_dir(cnid: u32, valence: u16, mac_time: u32) -> Vec<u8> {
    let mut d = vec![0u8; 70];
    d[0] = CDR_DIR;
    put_u16(&mut d, 4, valence); // dirVal
    put_u32(&mut d, 6, cnid); // dirDirID
    put_u32(&mut d, 10, mac_time); // dirCrDat
    put_u32(&mut d, 14, mac_time); // dirMdDat
    d
}

fn encode_file(
    cnid: u32,
    size: u64,
    mac_time: u32,
    extents: &ExtRec,
    total_blocks: u16,
    block_size: u32,
) -> Vec<u8> {
    let mut d = vec![0u8; 102];
    d[0] = CDR_FILE;
    d[4..8].copy_from_slice(b"????"); // FInfo fdType
    d[8..12].copy_from_slice(b"????"); // FInfo fdCreator
    put_u32(&mut d, 20, cnid); // filFlNum
    put_u16(&mut d, 24, extents[0].0); // filStBlk
    put_u32(&mut d, 26, size as u32); // filLgLen (data fork)
    put_u32(&mut d, 30, u32::from(total_blocks) * block_size); // filPyLen
    put_u32(&mut d, 44, mac_time); // filCrDat
    put_u32(&mut d, 48, mac_time); // filMdDat
    put_ext(&mut d, 74, &[extents[0], extents[1], extents[2]]); // filExtRec
    d
}

fn encode_thread(parent: u32, name: &[u8]) -> Vec<u8> {
    // Fixed 46-byte thread record: cdrType(1) + cdrResrv2(1) + thdResrv(8) +
    // thdParID(4) + thdCName as a full Str31 (1 length byte + 31). Classic HFS
    // pads the name to the full Str31 so every catalog record is even-length and
    // word-aligned — `fsck` requires it.
    let mut t = vec![0u8; 46];
    t[0] = CDR_DIR_THREAD;
    put_u32(&mut t, 10, parent); // thdParID
    let n = name.len().min(31);
    t[14] = n as u8; // thdCName length
    t[15..15 + n].copy_from_slice(&name[..n]);
    t
}

fn put_ext(v: &mut [u8], o: usize, e: &[(u16, u16); 3]) {
    for (i, &(s, c)) in e.iter().enumerate() {
        put_u16(v, o + i * 4, s);
        put_u16(v, o + i * 4 + 2, c);
    }
}

/// Encode a catalog leaf record: keyLen(1) + resrv(1) + parID(4) + Str31 name,
/// padded to even, then the record body. Matches the reader's `leaf_record`.
fn encode_leaf_record(key: &OwnedKey, body: &[u8]) -> Vec<u8> {
    let key_len = 6 + key.name.len();
    let mut r = vec![0u8; round_up_even(1 + key_len)];
    r[0] = key_len as u8;
    put_u32(&mut r, 2, key.parid);
    r[6] = key.name.len() as u8;
    r[7..7 + key.name.len()].copy_from_slice(&key.name);
    r.extend_from_slice(body);
    r
}

/// Encode an extents-overflow leaf record: keyLen(7) + forkType(1) + fileNum(4)
/// + startBlock(2), padded even, then 3 extents (12 bytes).
fn encode_extent_record(fork: u8, cnid: u32, start: u16, ext: &ExtRec) -> Vec<u8> {
    let mut r = vec![0u8; round_up_even(1 + 7)];
    r[0] = 7; // key length
    r[1] = fork; // xkrFkType
    put_u32(&mut r, 2, cnid); // xkrFNum
    put_u16(&mut r, 6, start); // xkrFABN
    let mut body = vec![0u8; 12];
    put_ext(&mut body, 0, ext);
    r.extend_from_slice(&body);
    r
}

// ---- B-tree builder -----------------------------------------------------

/// Build a complete B-tree (header + leaf + index nodes) from sorted leaf
/// `records`. `key_len_max` is the B-tree's `bthKeyLen`. Returns the node images
/// in node-number order (node 0 = header).
fn build_btree(records: &[Vec<u8>], key_len_max: u16) -> Result<Vec<[u8; NODE]>> {
    // Pack the leaves first; their node numbers start at 1 (0 = header).
    let leaves = pack_level(records, ND_LEAF, 1);
    let leaf_count = leaves.len().max(1);

    // A single empty/one-node leaf level needs at least one leaf node.
    let mut levels: Vec<Vec<PackedNode>> = Vec::new();
    if leaves.is_empty() {
        // Empty tree: one empty leaf node.
        levels.push(vec![PackedNode {
            first_key: Vec::new(),
            records: Vec::new(),
            kind: ND_LEAF,
            height: 1,
        }]);
    } else {
        levels.push(leaves);
    }

    // Build index levels until the top level has a single node.
    let mut height = 2u8;
    while levels.last().unwrap().len() > 1 {
        let child_level = levels.last().unwrap();
        // child node numbers: assigned later, but index records need them, so
        // compute the absolute node numbers of this child level now.
        let child_start = 1 + levels[..levels.len() - 1]
            .iter()
            .map(|l| l.len())
            .sum::<usize>() as u32;
        let idx_records: Vec<Vec<u8>> = child_level
            .iter()
            .enumerate()
            .map(|(i, n)| {
                encode_index_record(&n.first_key, child_start + i as u32, key_len_max as usize)
            })
            .collect();
        let idx_nodes = pack_level(&idx_records, ND_INDEX, height);
        levels.push(idx_nodes);
        height += 1;
    }

    // Assign node numbers (header = 0, then each level in order) and emit bytes.
    let total_nodes = 1 + levels.iter().map(|l| l.len()).sum::<usize>();
    let mut nodes: Vec<[u8; NODE]> = Vec::with_capacity(total_nodes);
    nodes.push([0u8; NODE]); // placeholder header

    let mut node_no = 1u32;
    // Record the node number ranges per level for f/b-link chaining.
    let mut level_ranges: Vec<(u32, u32)> = Vec::new();
    for level in &levels {
        let start = node_no;
        for (i, pn) in level.iter().enumerate() {
            let prev = if i == 0 { 0 } else { node_no - 1 };
            let next = if i + 1 == level.len() { 0 } else { node_no + 1 };
            nodes.push(write_node(pn, prev, next));
            node_no += 1;
        }
        level_ranges.push((start, node_no - 1));
    }

    let root = node_no - 1; // last node of the top level
    let depth = levels.len() as u16;
    let first_leaf = level_ranges[0].0;
    let last_leaf = level_ranges[0].1;
    let leaf_records = records.len() as u32;
    nodes[0] = write_header_node(
        depth,
        root,
        leaf_records,
        first_leaf,
        last_leaf,
        total_nodes as u32,
        key_len_max,
    );
    let _ = leaf_count;
    Ok(nodes)
}

struct PackedNode {
    first_key: Vec<u8>,
    records: Vec<Vec<u8>>,
    kind: u8,
    height: u8,
}

/// Greedily pack pre-encoded `records` into 512-byte nodes.
fn pack_level(records: &[Vec<u8>], kind: u8, height: u8) -> Vec<PackedNode> {
    let mut out = Vec::new();
    let mut cur: Vec<Vec<u8>> = Vec::new();
    let mut used = DESC;
    for rec in records {
        // node bytes = DESC + sum(record sizes) + 2*(nrecs+1) offset table.
        let with = used + rec.len() + 2 * (cur.len() + 2);
        if with > NODE && !cur.is_empty() {
            out.push(finish_node(&mut cur, kind, height));
            used = DESC;
        }
        used += rec.len();
        cur.push(rec.clone());
    }
    if !cur.is_empty() {
        out.push(finish_node(&mut cur, kind, height));
    }
    out
}

fn finish_node(cur: &mut Vec<Vec<u8>>, kind: u8, height: u8) -> PackedNode {
    let recs = std::mem::take(cur);
    let first_key = key_of(&recs[0]);
    PackedNode {
        first_key,
        records: recs,
        kind,
        height,
    }
}

/// The key **content** (the bytes after the keyLen byte) of an encoded record.
fn key_of(rec: &[u8]) -> Vec<u8> {
    let kl = rec[0] as usize;
    rec[1..1 + kl].to_vec()
}

/// An HFS index record: a **fixed-length** key (keyLen byte = `key_len`, the
/// B-tree's `bthKeyLen`, with the key content zero-padded to that length)
/// followed by a 4-byte child node pointer. Classic HFS index nodes use
/// max-length keys — `fsck` rejects variable-length ones.
fn encode_index_record(key_content: &[u8], child: u32, key_len: usize) -> Vec<u8> {
    let mut r = vec![0u8; 1 + key_len + 4];
    r[0] = key_len as u8;
    let n = key_content.len().min(key_len);
    r[1..1 + n].copy_from_slice(&key_content[..n]);
    r[1 + key_len..].copy_from_slice(&child.to_be_bytes());
    r
}

fn write_node(pn: &PackedNode, blink: u32, flink: u32) -> [u8; NODE] {
    let mut node = [0u8; NODE];
    put_u32(&mut node, 0, flink); // ndFLink
    put_u32(&mut node, 4, blink); // ndBLink
    node[8] = pn.kind; // ndType
    node[9] = pn.height; // ndNHeight
    put_u16(&mut node, 10, pn.records.len() as u16); // ndNRecs
    let mut off = DESC;
    let mut offsets = vec![DESC as u16];
    for rec in &pn.records {
        node[off..off + rec.len()].copy_from_slice(rec);
        off += rec.len();
        offsets.push(off as u16);
    }
    // Offset table grows downward from the end of the node.
    for (i, &o) in offsets.iter().enumerate() {
        put_u16(&mut node, NODE - 2 * (i + 1), o);
    }
    node
}

#[allow(clippy::too_many_arguments)]
fn write_header_node(
    depth: u16,
    root: u32,
    leaf_records: u32,
    first_leaf: u32,
    last_leaf: u32,
    total_nodes: u32,
    key_len_max: u16,
) -> [u8; NODE] {
    let mut node = [0u8; NODE];
    node[8] = ND_HEADER; // ndType
    put_u16(&mut node, 10, 3); // ndNRecs = header + reserved + bitmap
    // BTHeaderRec at +14.
    let h = DESC;
    put_u16(&mut node, h, depth); // bthDepth
    put_u32(&mut node, h + 2, root); // bthRoot
    put_u32(&mut node, h + 6, leaf_records); // bthNRecs
    put_u32(&mut node, h + 10, first_leaf); // bthFNode
    put_u32(&mut node, h + 14, last_leaf); // bthLNode
    put_u16(&mut node, h + 18, NODE as u16); // bthNodeSize
    put_u16(&mut node, h + 20, key_len_max); // bthKeyLen
    put_u32(&mut node, h + 22, total_nodes); // bthNNodes
    put_u32(&mut node, h + 26, 0); // bthFree (we size files exactly)
    // Node-allocation bitmap at +248: mark the used nodes.
    let bm = 248;
    for n in 0..total_nodes as usize {
        node[bm + n / 8] |= 0x80 >> (n % 8);
    }
    // Offset table: records at 14, 120, 248, free space at 504.
    put_u16(&mut node, NODE - 2, 14);
    put_u16(&mut node, NODE - 4, 120);
    put_u16(&mut node, NODE - 6, 248);
    put_u16(&mut node, NODE - 8, 504);
    node
}

/// Write `nodes` (512-byte each) sequentially across a B-tree file's `extents`
/// (block runs). A node never straddles a run because every run is a whole
/// number of allocation blocks and the block size is a multiple of 512.
fn write_nodes_across(
    dev: &mut dyn BlockDevice,
    alloc_base: u64,
    bs: u64,
    extents: &ExtRec,
    nodes: &[[u8; NODE]],
) -> Result<()> {
    let mut node_i = 0usize;
    for &(start, count) in extents {
        if count == 0 {
            continue;
        }
        let run_off = alloc_base + u64::from(start) * bs;
        let nodes_in_run = (u64::from(count) * bs / NODE as u64) as usize;
        for slot in 0..nodes_in_run {
            if node_i >= nodes.len() {
                return Ok(());
            }
            dev.write_at(run_off + (slot * NODE) as u64, &nodes[node_i])?;
            node_i += 1;
        }
    }
    Ok(())
}

// ---- geometry -----------------------------------------------------------

struct Geometry {
    vbm_start: u64,
    al_bl_st: u64,
    total_blocks: u16,
}

impl Geometry {
    fn compute(total_sectors: u64, block_size: u32) -> Result<Self> {
        let spab = u64::from(block_size) / 512; // sectors per allocation block
        let vbm_start = 3u64; // after boot blocks (0,1) + MDB (2)
        // Reserve 2 trailing sectors (alternate MDB + spare). Iterate to settle
        // the bitmap size, which depends on the block count.
        let usable_end = total_sectors - 2;
        let mut vbm_sectors = 1u64;
        let mut total_blocks;
        loop {
            let al_bl_st = vbm_start + vbm_sectors;
            if al_bl_st >= usable_end {
                return Err(Error::InvalidArgument("hfs: volume too small".into()));
            }
            total_blocks = (usable_end - al_bl_st) / spab;
            if total_blocks == 0 {
                return Err(Error::InvalidArgument("hfs: volume too small".into()));
            }
            let need = total_blocks.div_ceil(4096); // 4096 bits per 512-B sector
            if need <= vbm_sectors {
                let total_blocks = u16::try_from(total_blocks).map_err(|_| {
                    Error::InvalidArgument("hfs: too many allocation blocks".into())
                })?;
                return Ok(Geometry {
                    vbm_start,
                    al_bl_st,
                    total_blocks,
                });
            }
            vbm_sectors = need;
        }
    }
}

/// Smallest 512-multiple allocation-block size that keeps the block count below
/// the 16-bit HFS limit.
fn auto_block_size(total_sectors: u64) -> u32 {
    let mut bs = 512u32;
    while total_sectors / u64::from(bs / 512) > 60_000 {
        bs += 512;
    }
    bs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(parid: u32, name: &str) -> OwnedKey {
        OwnedKey {
            parid,
            name: name.as_bytes().to_vec(),
        }
    }

    /// The B-tree builder must emit a structurally valid, strictly key-ordered
    /// tree with a real index level once there are enough records — exactly what
    /// a real HFS implementation (which binary-searches by key) requires, and
    /// which our scanning reader would not catch.
    #[test]
    fn build_btree_is_ordered_with_an_index_level() {
        // Enough records to overflow several 512-byte leaf nodes.
        let mut entries: Vec<(OwnedKey, Vec<u8>)> = (0..90)
            .map(|i| (key(2, &format!("file{i:03}")), vec![0u8; 40]))
            .collect();
        // Two directory thread records (empty name) under different CNIDs to
        // exercise the empty-name ordering.
        entries.push((key(2, ""), vec![3u8; 20]));
        entries.sort_by(|a, b| a.0.cmp(&b.0));

        let records: Vec<Vec<u8>> = entries
            .iter()
            .map(|(k, b)| encode_leaf_record(k, b))
            .collect();
        let nodes = build_btree(&records, 37).unwrap();

        // Header node consistency.
        assert_eq!(nodes[0][8], ND_HEADER);
        let depth = u16::from_be_bytes([nodes[0][14], nodes[0][15]]);
        let bth_root = u32::from_be_bytes(nodes[0][16..20].try_into().unwrap());
        let bth_fnode = u32::from_be_bytes(nodes[0][24..28].try_into().unwrap());
        let nnodes = u32::from_be_bytes(nodes[0][36..40].try_into().unwrap());
        assert_eq!(nnodes as usize, nodes.len(), "bthNNodes != node count");
        assert!(depth >= 2, "expected an index level (depth {depth})");

        // The root index node must use FIXED-length keys (keyLen == bthKeyLen),
        // as classic HFS requires and `fsck` enforces.
        let root = &nodes[bth_root as usize];
        assert_eq!(root[8], ND_INDEX, "root should be an index node");
        let rnrecs = u16::from_be_bytes([root[10], root[11]]) as usize;
        for r in 0..rnrecs {
            let off = u16::from_be_bytes([root[NODE - 2 * (r + 1)], root[NODE - 2 * (r + 1) + 1]])
                as usize;
            assert_eq!(
                root[off], 37,
                "index record key must be fixed at bthKeyLen=37"
            );
            // Child pointer at off + 1 + keyLen references a real node.
            let child = u32::from_be_bytes(root[off + 38..off + 42].try_into().unwrap());
            assert!((child as usize) < nodes.len(), "index child out of range");
        }

        // Walk the leaf chain via ndFLink, collecting every key in order.
        let mut all: Vec<(u32, Vec<u8>)> = Vec::new();
        let mut idx = bth_fnode;
        let mut leaves = 0;
        while idx != 0 {
            let node = &nodes[idx as usize];
            assert_eq!(node[8], ND_LEAF, "node {idx} not a leaf");
            leaves += 1;
            let nrecs = u16::from_be_bytes([node[10], node[11]]) as usize;
            for r in 0..nrecs {
                let off =
                    u16::from_be_bytes([node[NODE - 2 * (r + 1)], node[NODE - 2 * (r + 1) + 1]])
                        as usize;
                let klen = node[off] as usize;
                let parid = u32::from_be_bytes(node[off + 2..off + 6].try_into().unwrap());
                let nlen = node[off + 6] as usize;
                let name = node[off + 7..off + 7 + nlen].to_vec();
                let _ = klen;
                all.push((parid, name));
            }
            idx = u32::from_be_bytes(node[0..4].try_into().unwrap());
        }
        assert!(leaves > 1, "expected multiple leaf nodes, got {leaves}");
        assert_eq!(all.len(), records.len(), "lost records walking the chain");

        // Strictly increasing by (parID, case-insensitive MacRoman name).
        for w in all.windows(2) {
            let ord = w[0].0.cmp(&w[1].0).then(macroman::cmp_ci(&w[0].1, &w[1].1));
            assert_eq!(ord, std::cmp::Ordering::Less, "keys out of order: {w:?}");
        }
    }
}
