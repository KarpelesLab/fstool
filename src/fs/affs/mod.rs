//! Amiga Fast/Old File System (AFFS) — read + write support.
//!
//! Reads Amiga DOS volumes (`.adf` floppy images and larger hard-file
//! volumes) in both their OFS ("Old File System") and FFS ("Fast File
//! System") variants, including the International and (transparently
//! ignored) directory-cache flavours.
//!
//! ## On-disk format (big-endian, 512-byte blocks)
//!
//! Block 0–1 hold the *boot block*: bytes `"DOS"` then a flag byte whose
//! low three bits select the variant (`DOS\0`..`DOS\7`): bit0 FFS/OFS, bit1
//! International name hashing, bit2 directory cache. The *root block* sits at
//! the middle of the volume and carries an `ADF_HT_SIZE`-entry name hash
//! table plus the volume bitmap pointers and name. Directories are the same
//! shape (a hash table of entries); files chain through a *file header* (and
//! optional *file-extension* blocks) listing their data blocks. Under OFS
//! every data block carries a 24-byte header (and only `512-24` payload
//! bytes); under FFS data blocks are raw.
//!
//! Layout offsets follow adflib's `adf_blk.h` structs; the reader is
//! cross-checked against the Linux kernel `affs` driver.
//!
//! Writing goes through [`writer`]: [`Affs::format`] generates a fresh volume
//! and [`Affs::open_writable`] loads an existing one into an in-memory tree
//! that `add`/`mkdir`/`rm` mutate and `flush` re-serialises block-by-block.
//! A read-only handle ([`Affs::open`]) reports
//! [`MutationCapability::Immutable`]; a writable one reports `Mutable`.

use std::collections::HashMap;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

use crate::block::BlockDevice;
use crate::fs::{DirEntry, EntryKind, Filesystem, MutationCapability};
use crate::{Error, Result};

mod writer;
pub use writer::AffsFormatOpts;

/// Logical block size of a bare Amiga DOS volume.
const BSIZE: usize = 512;
/// Name hash-table entry count for a 512-byte block (`BSIZE/4 - 56`).
const HT_SIZE: usize = 72;
/// Data-block pointer slots in a file header / extension block.
const MAX_DATABLK: usize = 72;
/// Longest Amiga file / directory / volume name.
const MAX_NAME_LEN: usize = 30;

// Primary block types (word @0).
const T_HEADER: i32 = 2;
const T_LIST: i32 = 16;
/// OFS data-block type (used when building/validating OFS data blocks).
const T_DATA: i32 = 8;

// Secondary types (word @ BSIZE-4 = 0x1fc).
const ST_ROOT: i32 = 1;
const ST_USERDIR: i32 = 2;
const ST_SOFTLINK: i32 = 3;
const ST_LINKDIR: i32 = 4;
const ST_FILE: i32 = -3;
const ST_LINKFILE: i32 = -4;

// Field offsets shared by header/dir/file/ext blocks.
const OFF_TYPE: usize = 0x000;
const OFF_HIGH_SEQ: usize = 0x008;
const OFF_HASHTABLE: usize = 0x018;
const OFF_BYTE_SIZE: usize = 0x144; // file header
const OFF_DAYS: usize = 0x1a4; // last-modified date triplet (dir/file)
const OFF_NAME_LEN: usize = 0x1b0;
const OFF_NEXT_SAME_HASH: usize = 0x1f0;
const OFF_EXTENSION: usize = 0x1f8; // file header / ext: next extension block
const OFF_SEC_TYPE: usize = 0x1fc;

/// Seconds between the Unix epoch (1970-01-01) and the Amiga epoch
/// (1978-01-01): 2922 days (8 years incl. leap days 1972, 1976).
const AMIGA_EPOCH: u64 = 2922 * 86_400;

#[inline]
fn be_u32(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

#[inline]
fn be_i32(b: &[u8], off: usize) -> i32 {
    be_u32(b, off) as i32
}

/// An Amiga "normal" block checksum is valid when every 32-bit word
/// (including the stored checksum) sums to zero with wrapping.
fn block_checksum_ok(b: &[u8]) -> bool {
    let mut sum = 0u32;
    let mut i = 0;
    while i < BSIZE {
        sum = sum.wrapping_add(be_u32(b, i));
        i += 4;
    }
    sum == 0
}

/// Amiga `(days, minutes, ticks)` → seconds since the Unix epoch. Ticks run
/// at 1/50 s. Negative/garbage dates clamp to 0.
fn amiga_date_to_unix(days: i32, mins: i32, ticks: i32) -> u32 {
    if days < 0 || mins < 0 || ticks < 0 {
        return 0;
    }
    let secs = AMIGA_EPOCH + days as u64 * 86_400 + mins as u64 * 60 + ticks as u64 / 50;
    secs.try_into().unwrap_or(u32::MAX)
}

/// Decode a BCPL name (length byte at `OFF_NAME_LEN`, chars following) as
/// ISO-8859-1 (Latin-1, the Amiga character set).
fn read_name(block: &[u8]) -> String {
    let len = (block[OFF_NAME_LEN] as usize).min(MAX_NAME_LEN);
    let start = OFF_NAME_LEN + 1;
    block[start..start + len]
        .iter()
        .map(|&b| b as char)
        .collect()
}

/// Variant flags decoded from the boot-block DOS type byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Variant {
    /// Fast File System (raw data blocks) when set; OFS (24-byte data-block
    /// headers) when clear.
    pub ffs: bool,
    /// International case-insensitive name hashing.
    pub intl: bool,
    /// Directory-cache mode (read transparently via the hash table).
    pub dircache: bool,
}

impl Variant {
    fn from_flag(flag: u8) -> Self {
        Self {
            ffs: flag & 1 != 0,
            intl: flag & 2 != 0,
            dircache: flag & 4 != 0,
        }
    }

    /// The `DOS\n` label for this variant.
    pub fn dos_label(&self) -> String {
        let n = (self.ffs as u8) | (self.intl as u8) << 1 | (self.dircache as u8) << 2;
        format!("DOS\\{n}")
    }
}

/// One directory entry resolved into the read index.
#[derive(Clone, Debug)]
struct Node {
    name: String,
    /// Header block number (the file/dir header on disk).
    block: u32,
    kind: EntryKind,
    /// File size in bytes (0 for non-files).
    size: u64,
    /// Symlink target (Latin-1 decoded from the header data area).
    link_target: Option<String>,
    mtime: u32,
}

/// An Amiga OFS/FFS volume, opened read-only.
pub struct Affs {
    block_size: u32,
    root_block: u32,
    variant: Variant,
    /// Volume name (root block BCPL name, Latin-1).
    pub volume_name: String,
    /// Parent header-block → its children. Root's children are keyed by
    /// `root_block`. Used for read-only (writer-absent) access.
    children: HashMap<u32, Vec<Node>>,
    /// Present (and authoritative) when the volume is writable.
    writer: Option<writer::AffsWriter>,
}

impl Affs {
    /// Open and index an Amiga DOS volume.
    pub fn open(dev: &mut dyn BlockDevice) -> Result<Self> {
        let total = dev.total_size();
        let block_size = BSIZE as u32;
        if total < (BSIZE as u64) * 4 {
            return Err(Error::InvalidImage("affs: image too small".into()));
        }

        // Boot block: "DOS" + flag byte.
        let mut boot = [0u8; 12];
        dev.read_at(0, &mut boot)?;
        if &boot[0..3] != b"DOS" || boot[3] > 7 {
            return Err(Error::InvalidImage(
                "affs: missing DOS boot signature".into(),
            ));
        }
        let variant = Variant::from_flag(boot[3]);

        let total_blocks = (total / BSIZE as u64) as u32;
        // Root block is the middle of the volume; trust the boot pointer only
        // when it actually lands on a valid root block.
        let boot_root = be_u32(&boot, 8);
        let candidates = [boot_root, total_blocks / 2, (total_blocks - 1) / 2];
        let mut root_block = 0u32;
        let mut root = vec![0u8; BSIZE];
        for &cand in &candidates {
            if cand == 0 || cand as u64 >= total_blocks as u64 {
                continue;
            }
            dev.read_at(cand as u64 * BSIZE as u64, &mut root)?;
            if be_i32(&root, OFF_TYPE) == T_HEADER
                && be_i32(&root, OFF_SEC_TYPE) == ST_ROOT
                && block_checksum_ok(&root)
            {
                root_block = cand;
                break;
            }
        }
        if root_block == 0 {
            return Err(Error::InvalidImage(
                "affs: no valid root block found".into(),
            ));
        }

        let volume_name = read_name(&root);

        let mut affs = Self {
            block_size,
            root_block,
            variant,
            volume_name,
            children: HashMap::new(),
            writer: None,
        };
        affs.build_index(dev, total_blocks)?;
        Ok(affs)
    }

    /// Format a fresh volume on `dev` and return a writable handle.
    pub fn format(dev: &mut dyn BlockDevice, opts: &AffsFormatOpts) -> Result<Self> {
        let w = writer::AffsWriter::format(dev, opts)?;
        Ok(Self::from_writer(w))
    }

    /// Build a writable `Affs` around an in-memory writer model.
    fn from_writer(w: writer::AffsWriter) -> Self {
        Self {
            block_size: BSIZE as u32,
            root_block: 0,
            variant: w.variant(),
            volume_name: w.volume_name().to_string(),
            children: HashMap::new(),
            writer: Some(w),
        }
    }

    /// Open an existing volume for in-place mutation. The whole tree (every
    /// directory and the bytes of every file) is loaded into the writer
    /// model; subsequent `add`/`mkdir`/`rm` mutate it and `flush` re-lays-out
    /// the entire image from scratch — the same path that backs `format`.
    pub fn open_writable(dev: &mut dyn BlockDevice) -> Result<Self> {
        let ro = Self::open(dev)?;
        let total_blocks = (dev.total_size() / BSIZE as u64) as u32;
        let mut w = writer::AffsWriter::adopt(total_blocks, ro.variant, ro.volume_name.clone());

        // Walk the on-disk tree parent-first, collecting paths so writer
        // inserts (which resolve parents) always see the parent already
        // present.
        let mut ordered: Vec<(String, Node)> = Vec::new();
        let mut stack = vec![(ro.root_block, String::new())];
        while let Some((blk, prefix)) = stack.pop() {
            if let Some(kids) = ro.children.get(&blk) {
                for node in kids {
                    let path = format!("{prefix}/{}", node.name);
                    if node.kind == EntryKind::Dir {
                        stack.push((node.block, path.clone()));
                    }
                    ordered.push((path, node.clone()));
                }
            }
        }
        // Insert dirs before their children: a DFS pre-order already does
        // this for parents, but the stack reverses sibling order — sort by
        // path depth then push, which keeps every parent ahead of its kids.
        ordered.sort_by_key(|(p, _)| p.matches('/').count());
        for (path, node) in ordered {
            match node.kind {
                EntryKind::Dir => w.insert_dir(&path, node.mtime)?,
                EntryKind::Regular => {
                    let content = ro.read_file_content(dev, node.block, node.size)?;
                    w.insert_file(&path, content, node.mtime)?;
                }
                // Symlinks/other types are not yet round-tripped by the writer.
                _ => {}
            }
        }
        Ok(Self::from_writer(w))
    }

    /// Read a file's full contents from its on-disk data blocks.
    fn read_file_content(
        &self,
        dev: &mut dyn BlockDevice,
        header: u32,
        size: u64,
    ) -> Result<Vec<u8>> {
        let blocks = self.data_blocks(dev, header)?;
        let payload = if self.variant.ffs { BSIZE } else { BSIZE - 24 } as u64;
        let data_off = if self.variant.ffs { 0 } else { 24 };
        let mut out = Vec::with_capacity(size as usize);
        let mut remaining = size;
        for b in blocks {
            if remaining == 0 {
                break;
            }
            let take = remaining.min(payload) as usize;
            let mut buf = vec![0u8; take];
            dev.read_at(b as u64 * BSIZE as u64 + data_off, &mut buf)?;
            out.extend_from_slice(&buf);
            remaining -= take as u64;
        }
        Ok(out)
    }

    /// Walk the directory tree from the root, populating `children`.
    fn build_index(&mut self, dev: &mut dyn BlockDevice, total_blocks: u32) -> Result<()> {
        let mut children: HashMap<u32, Vec<Node>> = HashMap::new();
        // Stack of directory header blocks still to expand.
        let mut stack = vec![self.root_block];
        let mut visited = std::collections::HashSet::new();
        while let Some(dir_block) = stack.pop() {
            if !visited.insert(dir_block) {
                continue;
            }
            let mut block = vec![0u8; BSIZE];
            dev.read_at(dir_block as u64 * BSIZE as u64, &mut block)?;
            let entries = self.read_hashtable(dev, &block, total_blocks, &visited)?;
            for node in &entries {
                if node.kind == EntryKind::Dir {
                    stack.push(node.block);
                }
            }
            children.insert(dir_block, entries);
        }
        self.children = children;
        Ok(())
    }

    /// Read every entry hanging off a directory/root block's hash table,
    /// following each bucket's same-hash chain.
    fn read_hashtable(
        &self,
        dev: &mut dyn BlockDevice,
        dir: &[u8],
        total_blocks: u32,
        visited: &std::collections::HashSet<u32>,
    ) -> Result<Vec<Node>> {
        let mut out = Vec::new();
        for i in 0..HT_SIZE {
            let mut entry = be_u32(dir, OFF_HASHTABLE + i * 4);
            let mut guard = 0;
            while entry != 0 && (entry as u64) < total_blocks as u64 {
                if visited.contains(&entry) {
                    break; // already-seen header → avoid cycles
                }
                let mut hb = vec![0u8; BSIZE];
                dev.read_at(entry as u64 * BSIZE as u64, &mut hb)?;
                let sec_type = be_i32(&hb, OFF_SEC_TYPE);
                let kind = match sec_type {
                    ST_USERDIR | ST_LINKDIR => EntryKind::Dir,
                    ST_FILE | ST_LINKFILE => EntryKind::Regular,
                    ST_SOFTLINK => EntryKind::Symlink,
                    _ => EntryKind::Unknown,
                };
                let name = read_name(&hb);
                let size = if kind == EntryKind::Regular {
                    be_u32(&hb, OFF_BYTE_SIZE) as u64
                } else {
                    0
                };
                let link_target = if kind == EntryKind::Symlink {
                    Some(read_softlink_target(&hb))
                } else {
                    None
                };
                let mtime = amiga_date_to_unix(
                    be_i32(&hb, OFF_DAYS),
                    be_i32(&hb, OFF_DAYS + 4),
                    be_i32(&hb, OFF_DAYS + 8),
                );
                if !name.is_empty() && kind != EntryKind::Unknown {
                    out.push(Node {
                        name,
                        block: entry,
                        kind,
                        size,
                        link_target,
                        mtime,
                    });
                }
                entry = be_u32(&hb, OFF_NEXT_SAME_HASH);
                guard += 1;
                if guard > total_blocks {
                    break;
                }
            }
        }
        Ok(out)
    }

    /// Resolve a `/`-separated path to its node (or the root directory).
    fn resolve<'a>(&'a self, path: &str) -> Option<Resolved<'a>> {
        let trimmed = path.trim_matches('/');
        if trimmed.is_empty() {
            return Some(Resolved::Dir(self.root_block));
        }
        let mut cur_dir = self.root_block;
        let mut comps = trimmed.split('/').peekable();
        while let Some(comp) = comps.next() {
            let kids = self.children.get(&cur_dir)?;
            let node = kids.iter().find(|n| n.name.eq_ignore_ascii_case(comp))?;
            let is_last = comps.peek().is_none();
            match node.kind {
                EntryKind::Dir => {
                    if is_last {
                        return Some(Resolved::Dir(node.block));
                    }
                    cur_dir = node.block;
                }
                _ => {
                    if is_last {
                        return Some(Resolved::Node(node));
                    }
                    return None; // path descends into a non-directory
                }
            }
        }
        None
    }

    /// List a directory path. When a writer is attached (a mutable handle),
    /// the in-memory model is authoritative so pending edits are visible.
    pub fn list_path(&self, path: &str) -> Result<Vec<DirEntry>> {
        if let Some(w) = &self.writer {
            return w.list(path);
        }
        let block = match self.resolve(path) {
            Some(Resolved::Dir(b)) => b,
            Some(_) => {
                return Err(Error::InvalidArgument("affs: not a directory".into()));
            }
            None => {
                return Err(Error::InvalidArgument(format!(
                    "affs: no such path {path:?}"
                )));
            }
        };
        let mut out = Vec::new();
        if let Some(kids) = self.children.get(&block) {
            for n in kids {
                out.push(DirEntry {
                    name: n.name.clone(),
                    inode: n.block,
                    kind: n.kind,
                    size: n.size,
                });
            }
        }
        Ok(out)
    }

    /// Build the ordered list of data-block numbers backing a file, walking
    /// the file header plus any extension blocks.
    fn data_blocks(&self, dev: &mut dyn BlockDevice, header: u32) -> Result<Vec<u32>> {
        let mut blocks = Vec::new();
        let mut cur = header;
        let mut guard = 0u64;
        let mut buf = vec![0u8; BSIZE];
        while cur != 0 {
            dev.read_at(cur as u64 * BSIZE as u64, &mut buf)?;
            let high_seq = be_i32(&buf, OFF_HIGH_SEQ).clamp(0, MAX_DATABLK as i32) as usize;
            // Data-block pointers are stored in reverse: the first data block
            // is at slot MAX_DATABLK-1, descending toward slot 0.
            for i in 0..high_seq {
                let slot = MAX_DATABLK - 1 - i;
                let ptr = be_u32(&buf, OFF_HASHTABLE + slot * 4);
                if ptr != 0 {
                    blocks.push(ptr);
                }
            }
            cur = be_u32(&buf, OFF_EXTENSION);
            guard += 1;
            if guard > u32::MAX as u64 / 2 {
                return Err(Error::InvalidImage("affs: file extension loop".into()));
            }
        }
        Ok(blocks)
    }

    /// Open a regular file for streaming reads. The returned reader owns its
    /// resolved block list (or, for a mutable handle, the in-memory bytes), so
    /// it borrows only `dev` (not `self`). When a writer is attached its model
    /// is authoritative, so pending writes are readable before flush.
    pub fn open_file_reader<'a>(
        &self,
        dev: &'a mut dyn BlockDevice,
        path: &str,
    ) -> Result<AffsFileReader<'a>> {
        if let Some(w) = &self.writer {
            let data = w.read(path)?;
            let size = data.len() as u64;
            return Ok(AffsFileReader {
                dev,
                blocks: Vec::new(),
                block_size: self.block_size,
                ofs: false,
                size,
                pos: 0,
                mem: Some(data),
            });
        }
        let (header, size) = match self.resolve(path) {
            Some(Resolved::Node(n)) if n.kind == EntryKind::Regular => (n.block, n.size),
            Some(_) => return Err(Error::InvalidArgument("affs: not a regular file".into())),
            None => {
                return Err(Error::InvalidArgument(format!(
                    "affs: no such path {path:?}"
                )));
            }
        };
        let blocks = self.data_blocks(dev, header)?;
        Ok(AffsFileReader {
            dev,
            blocks,
            block_size: self.block_size,
            ofs: !self.variant.ffs,
            size,
            pos: 0,
            mem: None,
        })
    }

    /// The volume's variant flags.
    pub fn variant(&self) -> Variant {
        self.variant
    }
}

enum Resolved<'a> {
    Dir(u32),
    Node(&'a Node),
}

/// Read the soft-link target stored in a softlink header's data area
/// (`OFF_HASHTABLE` onward, NUL-terminated, Latin-1).
fn read_softlink_target(hb: &[u8]) -> String {
    let start = OFF_HASHTABLE;
    let end = (start..BSIZE).find(|&i| hb[i] == 0).unwrap_or(BSIZE);
    hb[start..end].iter().map(|&b| b as char).collect()
}

/// Streaming reader over a file's data blocks. Honours the OFS 24-byte
/// per-block header (488 payload bytes) vs FFS raw 512-byte blocks; file
/// length bounds the final block.
pub struct AffsFileReader<'a> {
    dev: &'a mut dyn BlockDevice,
    blocks: Vec<u32>,
    block_size: u32,
    ofs: bool,
    size: u64,
    pos: u64,
    /// When `Some`, the file's bytes are served from memory (a writable
    /// handle whose contents aren't yet at a known on-disk location).
    mem: Option<Vec<u8>>,
}

impl AffsFileReader<'_> {
    /// Payload bytes carried by each data block under this variant.
    fn payload(&self) -> u64 {
        if self.ofs {
            self.block_size as u64 - 24
        } else {
            self.block_size as u64
        }
    }
}

impl Read for AffsFileReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.size {
            return Ok(0);
        }
        if let Some(m) = &self.mem {
            let start = self.pos as usize;
            let want = (buf.len()).min(m.len() - start);
            buf[..want].copy_from_slice(&m[start..start + want]);
            self.pos += want as u64;
            return Ok(want);
        }
        let payload = self.payload();
        let blk_idx = (self.pos / payload) as usize;
        let within = self.pos % payload;
        let Some(&blk) = self.blocks.get(blk_idx) else {
            return Ok(0);
        };
        let data_off = if self.ofs { 24 } else { 0 };
        let avail_in_block = (payload - within).min(self.size - self.pos);
        let want = (buf.len() as u64).min(avail_in_block) as usize;
        let off = blk as u64 * self.block_size as u64 + data_off + within;
        self.dev
            .read_at(off, &mut buf[..want])
            .map_err(|e| io::Error::other(e.to_string()))?;
        self.pos += want as u64;
        Ok(want)
    }
}

impl Seek for AffsFileReader<'_> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(n) => n as i64,
            SeekFrom::End(n) => self.size as i64 + n,
            SeekFrom::Current(n) => self.pos as i64 + n,
        };
        if new < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "affs: seek before start",
            ));
        }
        self.pos = new as u64;
        Ok(self.pos)
    }
}

impl crate::fs::FileReadHandle for AffsFileReader<'_> {
    fn len(&self) -> u64 {
        self.size
    }
}

impl crate::fs::FilesystemFactory for Affs {
    type FormatOpts = AffsFormatOpts;

    fn format(dev: &mut dyn BlockDevice, opts: &Self::FormatOpts) -> Result<Self> {
        Affs::format(dev, opts)
    }

    fn open(dev: &mut dyn BlockDevice) -> Result<Self> {
        Affs::open(dev)
    }
}

impl Filesystem for Affs {
    fn streams_immediately(&self) -> bool {
        // create_file reads its source into memory synchronously.
        true
    }

    fn create_file(
        &mut self,
        _dev: &mut dyn BlockDevice,
        path: &Path,
        src: crate::fs::FileSource,
        meta: crate::fs::FileMeta,
    ) -> Result<()> {
        let s = path
            .to_str()
            .ok_or_else(|| Error::InvalidArgument("affs: non-UTF-8 path".into()))?;
        let w = self.writer.as_mut().ok_or(Error::Immutable {
            kind: "affs",
            op: "add",
        })?;
        let (mut reader, len) = src.open()?;
        let mut data = Vec::with_capacity(len as usize);
        std::io::Read::take(&mut reader, len).read_to_end(&mut data)?;
        w.insert_file(s, data, meta.mtime)?;
        Ok(())
    }

    fn create_dir(
        &mut self,
        _dev: &mut dyn BlockDevice,
        path: &Path,
        meta: crate::fs::FileMeta,
    ) -> Result<()> {
        let s = path
            .to_str()
            .ok_or_else(|| Error::InvalidArgument("affs: non-UTF-8 path".into()))?;
        let w = self.writer.as_mut().ok_or(Error::Immutable {
            kind: "affs",
            op: "mkdir",
        })?;
        w.insert_dir(s, meta.mtime)?;
        Ok(())
    }

    fn create_symlink(
        &mut self,
        _dev: &mut dyn BlockDevice,
        _path: &Path,
        _target: &Path,
        _meta: crate::fs::FileMeta,
    ) -> Result<()> {
        // Amiga soft links exist (ST_SOFTLINK) but are deferred; the repack
        // sink treats this as a skippable entry.
        Err(Error::Unsupported(
            "affs: symlink creation not yet implemented".into(),
        ))
    }

    fn create_device(
        &mut self,
        _dev: &mut dyn BlockDevice,
        _path: &Path,
        _kind: crate::fs::DeviceKind,
        _major: u32,
        _minor: u32,
        _meta: crate::fs::FileMeta,
    ) -> Result<()> {
        Err(Error::Immutable {
            kind: "affs",
            op: "mknod",
        })
    }

    fn remove(&mut self, _dev: &mut dyn BlockDevice, path: &Path) -> Result<()> {
        let s = path
            .to_str()
            .ok_or_else(|| Error::InvalidArgument("affs: non-UTF-8 path".into()))?;
        let w = self.writer.as_mut().ok_or(Error::Immutable {
            kind: "affs",
            op: "rm",
        })?;
        w.remove(s)
    }

    fn list(&mut self, _dev: &mut dyn BlockDevice, path: &Path) -> Result<Vec<DirEntry>> {
        let s = path
            .to_str()
            .ok_or_else(|| Error::InvalidArgument("affs: non-UTF-8 path".into()))?;
        self.list_path(s)
    }

    fn getattr(&mut self, _dev: &mut dyn BlockDevice, path: &Path) -> Result<crate::fs::FileAttrs> {
        let s = path
            .to_str()
            .ok_or_else(|| Error::InvalidArgument("affs: non-UTF-8 path".into()))?;
        if let Some(w) = &self.writer {
            return w.getattr(s);
        }
        let (kind, size, mtime, inode) = match self.resolve(s) {
            Some(Resolved::Dir(b)) => (EntryKind::Dir, 0u64, 0u32, b),
            Some(Resolved::Node(n)) => (n.kind, n.size, n.mtime, n.block),
            None => return Err(Error::InvalidArgument(format!("affs: no such path {s:?}"))),
        };
        let mode = match kind {
            EntryKind::Dir => 0o755,
            EntryKind::Symlink => 0o777,
            _ => 0o644,
        };
        Ok(crate::fs::FileAttrs {
            kind,
            mode,
            uid: 0,
            gid: 0,
            size,
            blocks: size.div_ceil(512),
            nlink: if kind == EntryKind::Dir { 2 } else { 1 },
            atime: mtime,
            mtime,
            ctime: mtime,
            rdev: 0,
            inode,
        })
    }

    fn flush(&mut self, dev: &mut dyn BlockDevice) -> Result<()> {
        if let Some(w) = self.writer.as_mut() {
            w.flush(dev)?;
        }
        Ok(())
    }

    fn read_file<'a>(
        &'a mut self,
        dev: &'a mut dyn BlockDevice,
        path: &Path,
    ) -> Result<Box<dyn Read + 'a>> {
        let s = path
            .to_str()
            .ok_or_else(|| Error::InvalidArgument("affs: non-UTF-8 path".into()))?;
        Ok(Box::new(self.open_file_reader(dev, s)?))
    }

    fn open_file_ro<'a>(
        &'a mut self,
        dev: &'a mut dyn BlockDevice,
        path: &Path,
    ) -> Result<Box<dyn crate::fs::FileReadHandle + 'a>> {
        let s = path
            .to_str()
            .ok_or_else(|| Error::InvalidArgument("affs: non-UTF-8 path".into()))?;
        Ok(Box::new(self.open_file_reader(dev, s)?))
    }

    fn read_symlink(
        &mut self,
        _dev: &mut dyn BlockDevice,
        path: &Path,
    ) -> Result<std::path::PathBuf> {
        let s = path
            .to_str()
            .ok_or_else(|| Error::InvalidArgument("affs: non-UTF-8 path".into()))?;
        match self.resolve(s) {
            Some(Resolved::Node(n)) if n.kind == EntryKind::Symlink => Ok(
                std::path::PathBuf::from(n.link_target.clone().unwrap_or_default()),
            ),
            Some(_) => Err(Error::InvalidArgument("affs: not a symlink".into())),
            None => Err(Error::InvalidArgument(format!("affs: no such path {s:?}"))),
        }
    }

    fn mutation_capability(&self) -> MutationCapability {
        if self.writer.is_some() {
            MutationCapability::Mutable
        } else {
            MutationCapability::Immutable
        }
    }
}

#[allow(dead_code)]
const _: () = {
    // Compile-time sanity: the constants line up with a 512-byte block.
    assert!(HT_SIZE == BSIZE / 4 - 56);
    assert!(OFF_SEC_TYPE == BSIZE - 4);
    assert!(OFF_EXTENSION == BSIZE - 8);
    assert!(OFF_NEXT_SAME_HASH == BSIZE - 16);
    assert!(T_LIST == 16 && T_HEADER == 2);
};

#[cfg(test)]
mod tests;
