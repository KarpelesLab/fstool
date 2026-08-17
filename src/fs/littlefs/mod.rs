//! littlefs — read + write support for the little fail-safe filesystem
//! used on microcontroller flash (`lfs2`, disk versions 2.0 and 2.1).
//!
//! ## On-disk format (little-endian, except tags)
//!
//! littlefs has no fixed superblock region, no allocation table and no inode
//! table. Everything is built from two structures:
//!
//! * **Metadata pairs** — two blocks holding a revision count and an
//!   append-only log of commits; the block with the newer revision count that
//!   ends in a valid CRC is the live one. Each commit is a run of 32-bit
//!   *tags* (the `tag` submodule) and their data. A directory is a linked list of
//!   metadata pairs; the pair at blocks `{0, 1}` holds the superblock entry
//!   (the magic `"littlefs"` at offset 8) and doubles as the root directory.
//!   Every pair in the volume is also threaded onto one list through *tail*
//!   pointers, which is what makes a full traversal — and therefore block
//!   allocation — possible without an on-disk free map.
//! * **CTZ skip-lists** — file data too large to inline in a metadata block
//!   (the `ctz` submodule). Files smaller than `inline_max` live directly in their
//!   directory's metadata instead.
//!
//! ## What this backend does
//!
//! [`LittleFs::format`] lays down a fresh volume, and [`LittleFs::open`]
//! mounts an existing one; both return a fully mutable handle. Every
//! mutation is written through immediately as a real littlefs commit —
//! there is no build-once mode and no in-memory image, so `create -t
//! littlefs`, `repack`, `add`/`rm` and `open_file_rw` all drive the same
//! code path and a re-opened image keeps working exactly like a fresh one.
//!
//! Each commit rewrites the whole metadata pair (a *compaction*) into its
//! stale block rather than appending to the live one. That is the same
//! operation littlefs performs whenever a block fills up, so the result is
//! always a volume a stock littlefs can mount and keep appending to — at
//! the cost of writing a block per metadata change, which is the right
//! trade for an image tool.
//!
//! ## Metadata mapping
//!
//! littlefs stores no POSIX metadata at all: no mode, owner, timestamps,
//! symlinks or device nodes. Modes are therefore synthesised on read
//! (`0o755` for directories, `0o644` for files) and dropped on write, and
//! [`Filesystem::create_symlink`] / [`Filesystem::create_device`] report
//! [`Error::Unsupported`] so a `repack` sink skips those entries rather
//! than silently mangling them. littlefs *user attributes* are surfaced as
//! extended attributes named `user.littlefs.<type>`, where `<type>` is the
//! attribute's 8-bit type in decimal.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::io::Read;
use std::path::Path;

use crate::block::BlockDevice;
use crate::fs::{
    DirEntry, EntryKind, FileAttrs, FileMeta, FileSource, Filesystem, MutationCapability, StatFs,
    XattrPair,
};
use crate::{Error, Result};

mod alloc;
mod ctz;
mod mdir;
mod rw;
mod size_plan;
mod tag;
#[cfg(test)]
mod tests;

pub use size_plan::LittleFsSizePlan;

use alloc::Alloc;
use mdir::{Entry, Geom, Mdir, Struct};

/// Disk version 2.0 — understood by every littlefs v2 release. Images
/// pinned to it carry no forward-CRC tags, which releases older than
/// lfs2.1 would mistake for a commit CRC.
pub const DISK_VERSION_2_0: u32 = 0x0002_0000;
/// Disk version 2.1 — the current on-disk version, with forward-CRC tags.
pub const DISK_VERSION_2_1: u32 = 0x0002_0001;

/// The metadata pair every littlefs volume is rooted at.
const SUPERBLOCK_PAIR: [u32; 2] = [0, 1];
/// Magic string carried by the superblock's name tag.
const MAGIC: &[u8; 8] = b"littlefs";
/// Largest value littlefs allows for `file_max`.
const FILE_MAX: u32 = 0x7fff_ffff;

/// Prefix of the extended-attribute names littlefs user attributes are
/// surfaced under; the 8-bit attribute type follows in decimal.
const XATTR_PREFIX: &str = "user.littlefs.";

/// Format-time options for [`LittleFs::format`].
#[derive(Debug, Clone)]
pub struct LittleFsFormatOpts {
    /// Logical block size — the flash erase-block size. littlefs stores it
    /// in the superblock; 4 KiB is the common default.
    pub block_size: u32,
    /// Number of blocks. `None` fills the device.
    pub block_count: Option<u32>,
    /// Program (page) alignment. Commits are padded to it so that a real
    /// littlefs can append in place.
    pub prog_size: u32,
    /// On-disk version to write: [`DISK_VERSION_2_1`] (default) or
    /// [`DISK_VERSION_2_0`] for targets running a pre-2.1 littlefs.
    pub disk_version: u32,
    /// Longest file name the volume accepts.
    pub name_max: u32,
    /// Largest file kept inline in its directory's metadata instead of
    /// being written out as a CTZ skip-list. `None` picks littlefs's own
    /// default of an eighth of a block.
    pub inline_max: Option<u32>,
}

impl Default for LittleFsFormatOpts {
    fn default() -> Self {
        Self {
            block_size: 4096,
            block_count: None,
            prog_size: 256,
            disk_version: DISK_VERSION_2_1,
            name_max: 255,
            inline_max: None,
        }
    }
}

/// A mounted littlefs volume.
pub struct LittleFs {
    geom: Geom,
    version: u32,
    name_max: u32,
    file_max: u32,
    attr_max: u32,
    inline_max: u32,
    root: [u32; 2],
    /// In-use bitmap, built on first allocation and maintained exactly from
    /// then on. `None` until something needs to allocate.
    alloc: Option<Alloc>,
    cache: MdirCache,
}

/// Small LRU over parsed metadata pairs. Directory operations walk the same
/// pairs repeatedly (a lookup, then an insert, then a commit), and every
/// walk would otherwise re-read and re-parse a block.
struct MdirCache {
    map: HashMap<[u32; 2], Mdir>,
    order: VecDeque<[u32; 2]>,
    cap: usize,
}

impl MdirCache {
    fn new(cap: usize) -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
            cap,
        }
    }

    /// Cache key: a pair addresses the same metadata whichever way round it
    /// is written, and a commit swaps the two halves.
    fn key(pair: [u32; 2]) -> [u32; 2] {
        if pair[0] <= pair[1] {
            pair
        } else {
            [pair[1], pair[0]]
        }
    }

    fn get(&self, pair: [u32; 2]) -> Option<&Mdir> {
        self.map.get(&Self::key(pair))
    }

    fn put(&mut self, mdir: Mdir) {
        let k = Self::key(mdir.pair);
        if self.map.insert(k, mdir).is_none() {
            self.order.push_back(k);
            while self.order.len() > self.cap {
                if let Some(old) = self.order.pop_front() {
                    self.map.remove(&old);
                }
            }
        }
    }

    fn remove(&mut self, pair: [u32; 2]) {
        let k = Self::key(pair);
        self.map.remove(&k);
        self.order.retain(|p| *p != k);
    }
}

/// What a path resolved to.
enum Resolved {
    /// The root directory, which has no entry of its own.
    Root,
    /// An entry at `id` in the metadata pair `mdir`.
    Entry { mdir: Mdir, id: usize },
}

impl LittleFs {
    /// Format a fresh volume on `dev`.
    pub fn format(dev: &mut dyn BlockDevice, opts: &LittleFsFormatOpts) -> Result<Self> {
        let block_size = opts.block_size;
        // 128 bytes is the floor at which a CTZ block can still hold its
        // skip pointers (the spec's bound is 104); everything else in
        // littlefs assumes a power-of-two erase block.
        if block_size < 128 || !block_size.is_power_of_two() {
            return Err(Error::InvalidArgument(format!(
                "littlefs: block_size {block_size} must be a power of two and at least 128"
            )));
        }
        let prog_size = opts.prog_size.max(1);
        if !prog_size.is_power_of_two() || prog_size > block_size {
            return Err(Error::InvalidArgument(format!(
                "littlefs: prog_size {prog_size} must be a power of two no larger than the block size"
            )));
        }
        if opts.disk_version != DISK_VERSION_2_0 && opts.disk_version != DISK_VERSION_2_1 {
            return Err(Error::InvalidArgument(format!(
                "littlefs: unsupported disk version {:#010x} (use 2.0 or 2.1)",
                opts.disk_version
            )));
        }

        let avail = (dev.total_size() / block_size as u64).min(u32::MAX as u64) as u32;
        let block_count = opts.block_count.unwrap_or(avail);
        if block_count > avail {
            return Err(Error::InvalidArgument(format!(
                "littlefs: block_count {block_count} exceeds the {avail} blocks the device holds"
            )));
        }
        // The superblock pair plus room for a directory pair and some data.
        if block_count < 4 {
            return Err(Error::InvalidArgument(
                "littlefs: a volume needs at least 4 blocks".into(),
            ));
        }
        if opts.name_max == 0 || opts.name_max > tag::MAX_SIZE as u32 {
            return Err(Error::InvalidArgument(format!(
                "littlefs: name_max {} must be between 1 and {}",
                opts.name_max,
                tag::MAX_SIZE
            )));
        }

        let geom = Geom {
            block_size,
            block_count,
            prog_size,
            fcrc: opts.disk_version >= DISK_VERSION_2_1,
        };
        let attr_max = tag::MAX_SIZE as u32;
        let inline_max = pick_inline_max(&geom, opts.inline_max)?;

        let mut fs = Self {
            geom,
            version: opts.disk_version,
            name_max: opts.name_max,
            file_max: FILE_MAX,
            attr_max,
            inline_max,
            root: SUPERBLOCK_PAIR,
            alloc: None,
            cache: MdirCache::new(32),
        };

        // The root pair is written twice, exactly as `lfs_format` does: the
        // second compaction lands in the other block so that *both* halves
        // of the pair are valid littlefs commits, leaving nothing of an
        // older filesystem behind for a fetch to trip over.
        let mut root = Mdir::empty([SUPERBLOCK_PAIR[1], SUPERBLOCK_PAIR[0]]);
        root.entries.push(Entry {
            kind: tag::TYPE_SUPERBLOCK as u8,
            name: MAGIC.to_vec(),
            data: Some(Struct::Inline(fs.superblock_bytes())),
            attrs: Vec::new(),
        });
        fs.commit(dev, &mut root)?;
        fs.commit(dev, &mut root)?;

        // Claim the superblock pair up front so nothing else can hand it out.
        let mut a = Alloc::new(block_count);
        a.mark(SUPERBLOCK_PAIR[0]);
        a.mark(SUPERBLOCK_PAIR[1]);
        fs.alloc = Some(a);
        Ok(fs)
    }

    /// Mount an existing volume.
    pub fn open(dev: &mut dyn BlockDevice) -> Result<Self> {
        // The superblock's inline struct always sits at a fixed offset in
        // the first commit of block 0 — that's the only way to learn the
        // block size, which everything else needs.
        let mut head = [0u8; 44];
        let n = head.len().min(dev.total_size() as usize);
        dev.read_at(0, &mut head[..n])?;
        if &head[8..16] != MAGIC {
            return Err(Error::InvalidImage(
                "littlefs: no \"littlefs\" magic at offset 8".into(),
            ));
        }
        let version = tag::le32(&head[20..24]);
        let block_size = tag::le32(&head[24..28]);
        let block_count = tag::le32(&head[28..32]);
        if version >> 16 != 2 {
            return Err(Error::Unsupported(format!(
                "littlefs: on-disk version {}.{} (only v2 is supported)",
                version >> 16,
                version & 0xffff
            )));
        }
        if version & 0xffff > 1 {
            return Err(Error::Unsupported(format!(
                "littlefs: on-disk version 2.{} is newer than 2.1",
                version & 0xffff
            )));
        }
        if !(128..=16 * 1024 * 1024).contains(&block_size) || block_count == 0 {
            return Err(Error::InvalidImage(format!(
                "littlefs: implausible geometry ({block_size}-byte blocks × {block_count})"
            )));
        }
        if (block_size as u64).saturating_mul(block_count as u64) > dev.total_size() {
            return Err(Error::InvalidImage(format!(
                "littlefs: volume claims {block_count} × {block_size}-byte blocks but the device holds {} bytes",
                dev.total_size()
            )));
        }

        let geom = Geom {
            block_size,
            block_count,
            prog_size: 1,
            fcrc: version >= DISK_VERSION_2_1,
        };
        let mut fs = Self {
            geom,
            version,
            name_max: tag::le32(&head[32..36]),
            file_max: tag::le32(&head[36..40]),
            attr_max: tag::le32(&head[40..44]),
            inline_max: 0,
            root: SUPERBLOCK_PAIR,
            alloc: None,
            cache: MdirCache::new(32),
        };
        if fs.name_max == 0 || fs.name_max > tag::MAX_SIZE as u32 {
            fs.name_max = 255;
        }
        if fs.file_max == 0 {
            fs.file_max = FILE_MAX;
        }
        if fs.attr_max == 0 || fs.attr_max > tag::MAX_SIZE as u32 {
            fs.attr_max = tag::MAX_SIZE as u32;
        }

        // Walk the superblock chain: the last pair still carrying a
        // superblock entry is the root directory. littlefs grows this chain
        // as the root is rewritten, to spread erase cycles.
        let mut pair = Some(SUPERBLOCK_PAIR);
        let mut hops = 0u32;
        while let Some(p) = pair {
            let m = mdir::fetch(dev, &fs.geom, p)?;
            if m.entries
                .first()
                .is_some_and(|e| e.kind == tag::TYPE_SUPERBLOCK as u8)
            {
                fs.root = m.pair;
                // A commit's forward-CRC records the program size its
                // writer used; reusing it keeps our commits aligned the way
                // the volume's creator intended.
                if let Some(p) = m.fcrc_size
                    && p.is_power_of_two()
                    && p <= block_size
                {
                    fs.geom.prog_size = p;
                }
            }
            pair = m.tail;
            hops += 1;
            if hops > block_count {
                return Err(Error::InvalidImage(
                    "littlefs: cycle in the metadata-pair list".into(),
                ));
            }
        }
        if fs.geom.prog_size == 1 {
            fs.geom.prog_size = 256.min(block_size / 4).max(1);
        }
        fs.inline_max = pick_inline_max(&fs.geom, None)?;
        fs.cache = MdirCache::new(32);
        Ok(fs)
    }

    /// Volume geometry: `(block size, block count)`.
    pub fn geometry(&self) -> (u32, u32) {
        (self.geom.block_size, self.geom.block_count)
    }

    /// On-disk version, as `(major, minor)`.
    pub fn version(&self) -> (u16, u16) {
        ((self.version >> 16) as u16, (self.version & 0xffff) as u16)
    }

    /// Largest file kept inline in metadata rather than written as a CTZ
    /// skip-list.
    pub fn inline_max(&self) -> u32 {
        self.inline_max
    }

    /// Program (page) alignment commits are padded to. Not recorded in
    /// the superblock — it is a property of the target flash — so for an
    /// opened image this is recovered from the forward-CRC of the last
    /// commit, falling back to a sensible default when the image carries
    /// none.
    pub fn program_size(&self) -> u32 {
        self.geom.prog_size
    }

    /// Blocks currently in use.
    pub fn used_blocks(&mut self, dev: &mut dyn BlockDevice) -> Result<u32> {
        Ok(self.allocator(dev)?.used())
    }

    /// The 24-byte superblock configuration record.
    fn superblock_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(24);
        for v in [
            self.version,
            self.geom.block_size,
            self.geom.block_count,
            self.name_max,
            self.file_max,
            self.attr_max,
        ] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        b
    }

    // ---- metadata pairs -------------------------------------------------

    /// Fetch a metadata pair, through the cache.
    fn fetch(&mut self, dev: &mut dyn BlockDevice, pair: [u32; 2]) -> Result<Mdir> {
        if let Some(m) = self.cache.get(pair) {
            return Ok(m.clone());
        }
        let m = mdir::fetch(dev, &self.geom, pair)?;
        self.cache.put(m.clone());
        Ok(m)
    }

    /// Write `mdir` back as a fresh compaction, splitting it across further
    /// pairs first if its contents no longer fit one metadata block.
    fn commit(&mut self, dev: &mut dyn BlockDevice, mdir: &mut Mdir) -> Result<()> {
        while mdir::needs_split(&self.geom, mdir) {
            let at = mdir::split_point(&self.geom, mdir);
            if at == 0 {
                return Err(Error::InvalidArgument(
                    "littlefs: a single entry is too large for a metadata block".into(),
                ));
            }
            let mut tail = self.new_pair(dev)?;
            tail.entries = mdir.entries.split_off(at);
            tail.tail = mdir.tail;
            tail.hard = mdir.hard;
            self.commit(dev, &mut tail)?;
            // The overflow pair becomes the continuation of this directory,
            // which also keeps it threaded on the filesystem-wide list.
            mdir.tail = Some(tail.pair);
            mdir.hard = true;
        }

        mdir.rev = mdir.rev.wrapping_add(1);
        let target = mdir.pair[1];
        mdir::write_compaction(dev, &self.geom, mdir, target, mdir.rev)?;
        // The block we just wrote is now the live half of the pair.
        mdir.pair.swap(0, 1);
        self.cache.put(mdir.clone());
        Ok(())
    }

    /// Allocate a metadata pair that isn't on disk yet.
    ///
    /// The revision count is seeded from the block we will *not* write
    /// first, so that our commit always outranks whatever an earlier
    /// filesystem left in the other half of the pair.
    fn new_pair(&mut self, dev: &mut dyn BlockDevice) -> Result<Mdir> {
        let pair = self.allocator(dev)?.take_pair()?;
        let mut m = Mdir::empty(pair);
        m.rev = mdir::read_rev(dev, &self.geom, pair[0]).unwrap_or(0);
        Ok(m)
    }

    // ---- allocation -----------------------------------------------------

    /// The in-use bitmap, built by traversing the volume the first time
    /// anything needs to allocate.
    fn allocator(&mut self, dev: &mut dyn BlockDevice) -> Result<&mut Alloc> {
        if self.alloc.is_none() {
            let a = self.scan_used(dev)?;
            self.alloc = Some(a);
        }
        Ok(self.alloc.as_mut().expect("just built"))
    }

    /// Walk every metadata pair on the threaded list and every file's
    /// skip-list, marking the blocks they occupy.
    fn scan_used(&mut self, dev: &mut dyn BlockDevice) -> Result<Alloc> {
        let geom = self.geom;
        let mut a = Alloc::new(geom.block_count);
        let mut next = Some(SUPERBLOCK_PAIR);
        let mut hops = 0u32;
        while let Some(pair) = next {
            let m = self.fetch(dev, pair)?;
            a.mark(m.pair[0]);
            a.mark(m.pair[1]);
            for e in &m.entries {
                if let Some(Struct::Ctz { head, size }) = &e.data {
                    ctz::traverse(dev, &geom, *head, *size, &mut |b| a.mark(b))?;
                }
            }
            next = m.tail;
            hops += 1;
            if hops > geom.block_count {
                return Err(Error::InvalidImage(
                    "littlefs: cycle in the metadata-pair list".into(),
                ));
            }
        }
        Ok(a)
    }

    /// Release every block a file's data occupies.
    fn free_data(&mut self, dev: &mut dyn BlockDevice, data: &Struct) -> Result<()> {
        let Struct::Ctz { head, size } = data else {
            return Ok(());
        };
        let geom = self.geom;
        let mut blocks = Vec::new();
        ctz::traverse(dev, &geom, *head, *size, &mut |b| blocks.push(b))?;
        let a = self.allocator(dev)?;
        for b in blocks {
            a.free(b);
        }
        Ok(())
    }

    // ---- path resolution ------------------------------------------------

    /// Resolve a path, erroring when it doesn't exist.
    fn resolve(&mut self, dev: &mut dyn BlockDevice, path: &Path) -> Result<Resolved> {
        self.try_resolve(dev, path)?.ok_or_else(|| {
            Error::InvalidArgument(format!("littlefs: no such path {:?}", path.display()))
        })
    }

    /// Resolve a path, returning `None` when the final component is absent.
    fn try_resolve(&mut self, dev: &mut dyn BlockDevice, path: &Path) -> Result<Option<Resolved>> {
        let comps = components(path)?;
        let mut dir = self.root;
        let mut out = Resolved::Root;
        for (i, name) in comps.iter().enumerate() {
            let Some((mdir, id)) = self.find_in_dir(dev, dir, name.as_bytes())? else {
                return Ok(None);
            };
            if i + 1 < comps.len() {
                dir = match &mdir.entries[id].data {
                    Some(Struct::Dir(p)) => *p,
                    _ => {
                        return Err(Error::InvalidArgument(format!(
                            "littlefs: {name:?} is not a directory"
                        )));
                    }
                };
            }
            out = Resolved::Entry { mdir, id };
        }
        Ok(Some(out))
    }

    /// The metadata pair a directory's entries start at.
    fn dir_head(&self, r: &Resolved) -> Result<[u32; 2]> {
        match r {
            Resolved::Root => Ok(self.root),
            Resolved::Entry { mdir, id } => match &mdir.entries[*id].data {
                Some(Struct::Dir(p)) => Ok(*p),
                _ => Err(Error::InvalidArgument(
                    "littlefs: not a directory".to_string(),
                )),
            },
        }
    }

    /// Resolve `path`'s parent directory to the pair its entries start at.
    fn parent_head(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &Path,
    ) -> Result<([u32; 2], String)> {
        let comps = components(path)?;
        let (name, parents) = comps
            .split_last()
            .ok_or_else(|| Error::InvalidArgument("littlefs: empty path".into()))?;
        let mut dir = self.root;
        for p in parents {
            let Some((mdir, id)) = self.find_in_dir(dev, dir, p.as_bytes())? else {
                return Err(Error::InvalidArgument(format!(
                    "littlefs: no such directory {p:?}"
                )));
            };
            dir = match &mdir.entries[id].data {
                Some(Struct::Dir(pair)) => *pair,
                _ => {
                    return Err(Error::InvalidArgument(format!(
                        "littlefs: {p:?} is not a directory"
                    )));
                }
            };
        }
        Ok((dir, (*name).to_string()))
    }

    /// Find `name` in the directory whose chain starts at `head`.
    fn find_in_dir(
        &mut self,
        dev: &mut dyn BlockDevice,
        head: [u32; 2],
        name: &[u8],
    ) -> Result<Option<(Mdir, usize)>> {
        for m in self.chain(dev, head)? {
            if let Some(id) = m.find(name) {
                return Ok(Some((m, id)));
            }
        }
        Ok(None)
    }

    /// Every metadata pair of one directory, following its hard tails.
    fn chain(&mut self, dev: &mut dyn BlockDevice, head: [u32; 2]) -> Result<Vec<Mdir>> {
        let mut out = Vec::new();
        let mut pair = Some(head);
        while let Some(p) = pair {
            let m = self.fetch(dev, p)?;
            pair = if m.hard { m.tail } else { None };
            out.push(m);
            if out.len() as u32 > self.geom.block_count {
                return Err(Error::InvalidImage(
                    "littlefs: cycle in a directory's metadata chain".into(),
                ));
            }
        }
        Ok(out)
    }

    /// The metadata pair whose tail points at `pair` — its predecessor on
    /// the filesystem-wide threaded list.
    fn find_pred(&mut self, dev: &mut dyn BlockDevice, pair: [u32; 2]) -> Result<Mdir> {
        let key = MdirCache::key(pair);
        let mut next = Some(SUPERBLOCK_PAIR);
        let mut hops = 0u32;
        while let Some(p) = next {
            let m = self.fetch(dev, p)?;
            if m.tail.map(MdirCache::key) == Some(key) {
                return Ok(m);
            }
            next = m.tail;
            hops += 1;
            if hops > self.geom.block_count {
                break;
            }
        }
        Err(Error::InvalidImage(
            "littlefs: metadata pair is not on the threaded list".into(),
        ))
    }

    // ---- mutation -------------------------------------------------------

    /// Insert an entry into a directory, keeping the chain in name order
    /// (littlefs sorts directory entries by their raw bytes).
    fn insert_entry(
        &mut self,
        dev: &mut dyn BlockDevice,
        head: [u32; 2],
        entry: Entry,
    ) -> Result<()> {
        let mut pair = head;
        loop {
            let mut m = self.fetch(dev, pair)?;
            // The superblock shares the root's pair as id 0 and takes no
            // part in the ordering, so entries start after it.
            let start = m.entries.iter().take_while(|e| !e.is_file()).count();
            let pos = m.entries[start..]
                .iter()
                .position(|e| e.name.as_slice() > entry.name.as_slice())
                .map(|p| p + start);
            match pos {
                Some(p) => {
                    m.entries.insert(p, entry);
                    return self.commit(dev, &mut m);
                }
                None => match (m.hard, m.tail) {
                    (true, Some(t)) => pair = t,
                    _ => {
                        m.entries.push(entry);
                        return self.commit(dev, &mut m);
                    }
                },
            }
        }
    }

    /// Shared body of `create_file` / `create_file_streaming`.
    fn write_file(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &Path,
        body: &mut dyn Read,
        len: u64,
    ) -> Result<()> {
        let (head, name) = self.parent_head(dev, path)?;
        self.check_name(&name)?;
        if len > self.file_max as u64 {
            return Err(Error::InvalidArgument(format!(
                "littlefs: {len} bytes exceeds the volume's {}-byte file limit",
                self.file_max
            )));
        }

        let existing = self.find_in_dir(dev, head, name.as_bytes())?;
        if let Some((m, id)) = &existing
            && m.entries[*id].kind == tag::TYPE_DIR as u8
        {
            return Err(Error::InvalidArgument(format!(
                "littlefs: {name:?} already exists as a directory"
            )));
        }

        let data = self.write_data(dev, body, len)?;
        match existing {
            // Replacing a file keeps its id — only the struct changes.
            Some((mut m, id)) => {
                if let Some(old) = m.entries[id].data.clone() {
                    self.free_data(dev, &old)?;
                }
                m.entries[id].data = Some(data);
                self.commit(dev, &mut m)
            }
            None => self.insert_entry(
                dev,
                head,
                Entry {
                    kind: tag::TYPE_REG as u8,
                    name: name.into_bytes(),
                    data: Some(data),
                    attrs: Vec::new(),
                },
            ),
        }
    }

    /// Stream `len` bytes of file data into the volume, inlining it when it
    /// is small enough to live in the directory's metadata.
    fn write_data(
        &mut self,
        dev: &mut dyn BlockDevice,
        body: &mut dyn Read,
        len: u64,
    ) -> Result<Struct> {
        if len <= self.inline_max as u64 {
            let mut buf = vec![0u8; len as usize];
            body.read_exact(&mut buf)?;
            return Ok(Struct::Inline(buf));
        }
        let geom = self.geom;
        let mut src = ctz::ReaderSource { body };
        let alloc = self.allocator(dev)?;
        let head =
            ctz::write_blocks(dev, &geom, alloc, 0, None, 0, &mut src, len)?.ok_or_else(|| {
                Error::InvalidArgument("littlefs: empty skip-list for a non-empty file".into())
            })?;
        Ok(Struct::Ctz {
            head,
            size: len as u32,
        })
    }

    /// Create a directory: a fresh metadata pair, threaded onto the
    /// filesystem-wide list right after its parent's last pair, plus an
    /// entry pointing at it.
    fn make_dir(&mut self, dev: &mut dyn BlockDevice, path: &Path) -> Result<()> {
        let (head, name) = self.parent_head(dev, path)?;
        self.check_name(&name)?;
        if let Some((m, id)) = self.find_in_dir(dev, head, name.as_bytes())? {
            return if m.entries[id].kind == tag::TYPE_DIR as u8 {
                Ok(())
            } else {
                Err(Error::InvalidArgument(format!(
                    "littlefs: {name:?} already exists"
                )))
            };
        }

        let mut dir = self.new_pair(dev)?;
        // Splice the new pair into the threaded list behind the parent's
        // last pair, so a traversal still reaches every metadata block.
        let pred_pair = self
            .chain(dev, head)?
            .last()
            .expect("a directory always has at least one pair")
            .pair;
        let mut pred = self.fetch(dev, pred_pair)?;
        dir.tail = pred.tail;
        dir.hard = false;
        self.commit(dev, &mut dir)?;
        pred.tail = Some(dir.pair);
        pred.hard = false;
        self.commit(dev, &mut pred)?;

        self.insert_entry(
            dev,
            head,
            Entry {
                kind: tag::TYPE_DIR as u8,
                name: name.into_bytes(),
                data: Some(Struct::Dir(dir.pair)),
                attrs: Vec::new(),
            },
        )
    }

    /// Remove a file or an empty directory.
    fn remove_path(&mut self, dev: &mut dyn BlockDevice, path: &Path) -> Result<()> {
        let Resolved::Entry { mdir, id } = self.resolve(dev, path)? else {
            return Err(Error::InvalidArgument(
                "littlefs: cannot remove the root directory".into(),
            ));
        };
        let entry = mdir.entries[id].clone();

        if entry.kind == tag::TYPE_DIR as u8 {
            let head = match &entry.data {
                Some(Struct::Dir(p)) => *p,
                _ => {
                    return Err(Error::InvalidImage(
                        "littlefs: directory entry without a metadata pair".into(),
                    ));
                }
            };
            let chain = self.chain(dev, head)?;
            if chain.iter().any(|m| m.entries.iter().any(Entry::is_file)) {
                return Err(Error::InvalidArgument(format!(
                    "littlefs: directory {:?} is not empty",
                    path.display()
                )));
            }

            // Drop the entry first; the predecessor may well be the very
            // pair we just rewrote, so it has to be re-read afterwards.
            let mut parent = mdir;
            parent.entries.remove(id);
            self.commit(dev, &mut parent)?;

            let last = chain.last().expect("chain is never empty");
            let mut pred = self.find_pred(dev, head)?;
            pred.tail = last.tail;
            pred.hard = last.hard;
            // Global state lives as a per-pair delta whose XOR across the
            // volume is the filesystem's state, so a dropped pair's delta
            // has to be carried over rather than lost.
            for m in &chain {
                if let Some(g) = m.gdelta {
                    let mut acc = pred.gdelta.unwrap_or([0u8; 12]);
                    for (a, b) in acc.iter_mut().zip(g.iter()) {
                        *a ^= *b;
                    }
                    pred.gdelta = if acc == [0u8; 12] { None } else { Some(acc) };
                }
            }
            self.commit(dev, &mut pred)?;

            for m in &chain {
                self.cache.remove(m.pair);
                let a = self.allocator(dev)?;
                a.free(m.pair[0]);
                a.free(m.pair[1]);
            }
            return Ok(());
        }

        if let Some(data) = &entry.data {
            self.free_data(dev, data)?;
        }
        let mut parent = mdir;
        parent.entries.remove(id);
        self.commit(dev, &mut parent)
    }

    /// Reject names littlefs can't store.
    fn check_name(&self, name: &str) -> Result<()> {
        if name.is_empty() {
            return Err(Error::InvalidArgument("littlefs: empty name".into()));
        }
        if name.len() > self.name_max as usize {
            return Err(Error::InvalidArgument(format!(
                "littlefs: name {name:?} is longer than the volume's {}-byte limit",
                self.name_max
            )));
        }
        Ok(())
    }

    /// Directory listing shared by `list` and the FUSE-facing helpers.
    fn list_dir(&mut self, dev: &mut dyn BlockDevice, path: &Path) -> Result<Vec<DirEntry>> {
        let r = self.resolve(dev, path)?;
        let head = self.dir_head(&r)?;
        let mut out = Vec::new();
        for m in self.chain(dev, head)? {
            for (id, e) in m.entries.iter().enumerate().filter(|(_, e)| e.is_file()) {
                out.push(DirEntry {
                    name: String::from_utf8_lossy(&e.name).into_owned(),
                    inode: synthetic_inode(m.pair, id, e),
                    kind: entry_kind(e),
                    size: entry_size(e),
                });
            }
        }
        Ok(out)
    }

    /// Locate a file's contents for reading.
    fn file_source(&mut self, dev: &mut dyn BlockDevice, path: &Path) -> Result<rw::Source> {
        let Resolved::Entry { mdir, id } = self.resolve(dev, path)? else {
            return Err(Error::InvalidArgument(
                "littlefs: the root is not a file".into(),
            ));
        };
        let e = &mdir.entries[id];
        if e.kind != tag::TYPE_REG as u8 {
            return Err(Error::InvalidArgument(format!(
                "littlefs: {:?} is not a regular file",
                path.display()
            )));
        }
        Ok(match &e.data {
            Some(Struct::Inline(d)) => rw::Source::Inline(d.clone()),
            Some(Struct::Ctz { head, size }) => rw::Source::Ctz {
                head: *head,
                size: *size,
            },
            _ => rw::Source::Inline(Vec::new()),
        })
    }
}

/// littlefs's own default: a file is inlined while it fits in an eighth of
/// a metadata block, bounded by what a single tag can carry.
fn pick_inline_max(geom: &Geom, requested: Option<u32>) -> Result<u32> {
    let ceiling = (tag::MAX_SIZE as u32).min(geom.split_limit() as u32 / 2);
    let v = requested.unwrap_or_else(|| (geom.block_size / 8).min(ceiling));
    if v > ceiling {
        return Err(Error::InvalidArgument(format!(
            "littlefs: inline_max {v} exceeds the {ceiling} bytes a {}-byte block can inline",
            geom.block_size
        )));
    }
    Ok(v)
}

/// Split a path into its components, rejecting anything that would escape
/// the volume root.
fn components(path: &Path) -> Result<Vec<&str>> {
    let s = path
        .to_str()
        .ok_or_else(|| Error::InvalidArgument("littlefs: non-UTF-8 path".into()))?;
    let mut out: Vec<&str> = Vec::new();
    for c in s.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                if out.pop().is_none() {
                    return Err(Error::InvalidArgument(
                        "littlefs: path escapes the root".into(),
                    ));
                }
            }
            other => out.push(other),
        }
    }
    Ok(out)
}

fn entry_kind(e: &Entry) -> EntryKind {
    if e.kind == tag::TYPE_DIR as u8 {
        EntryKind::Dir
    } else {
        EntryKind::Regular
    }
}

fn entry_size(e: &Entry) -> u64 {
    match &e.data {
        Some(Struct::Inline(d)) => d.len() as u64,
        Some(Struct::Ctz { size, .. }) => *size as u64,
        _ => 0,
    }
}

/// littlefs has no inode numbers, so we synthesise a stable one: a
/// directory is identified by the first block of its own metadata pair, a
/// file by its id within its parent's pair (ids stop at 0xfe, so eight bits
/// are enough). Callers use these only to tell entries apart — FUSE node
/// ids, and cycle detection in tree walks.
fn synthetic_inode(pair: [u32; 2], id: usize, e: &Entry) -> u32 {
    match &e.data {
        Some(Struct::Dir(p)) => p[0].max(1),
        _ => 0x8000_0000 | (pair[0].wrapping_shl(8) & 0x7fff_ff00) | (id as u32 & 0xff),
    }
}

/// Map a littlefs user-attribute type to its extended-attribute name.
fn xattr_name(kind: u8) -> String {
    format!("{XATTR_PREFIX}{kind}")
}

/// Parse an extended-attribute name back into a littlefs attribute type.
fn xattr_type(name: &str) -> Result<u8> {
    name.strip_prefix(XATTR_PREFIX)
        .and_then(|n| n.parse::<u8>().ok())
        .ok_or_else(|| {
            Error::Unsupported(format!(
                "littlefs: only {XATTR_PREFIX}<0-255> attributes can be stored (got {name:?})"
            ))
        })
}

impl Filesystem for LittleFs {
    fn streams_immediately(&self) -> bool {
        true
    }

    fn create_file(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &Path,
        src: FileSource,
        _meta: FileMeta,
    ) -> Result<()> {
        let (mut reader, len) = src.open()?;
        self.write_file(dev, path, &mut reader, len)
    }

    fn create_file_streaming(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &Path,
        body: &mut dyn Read,
        len: u64,
        _meta: FileMeta,
    ) -> Result<()> {
        self.write_file(dev, path, body, len)
    }

    fn create_dir(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &Path,
        _meta: FileMeta,
    ) -> Result<()> {
        if components(path)?.is_empty() {
            return Ok(()); // the root always exists
        }
        self.make_dir(dev, path)
    }

    fn create_symlink(
        &mut self,
        _dev: &mut dyn BlockDevice,
        _path: &Path,
        _target: &Path,
        _meta: FileMeta,
    ) -> Result<()> {
        Err(Error::Unsupported(
            "littlefs: the format has no symbolic links".into(),
        ))
    }

    fn create_device(
        &mut self,
        _dev: &mut dyn BlockDevice,
        _path: &Path,
        _kind: crate::fs::DeviceKind,
        _major: u32,
        _minor: u32,
        _meta: FileMeta,
    ) -> Result<()> {
        Err(Error::Unsupported(
            "littlefs: the format has no device nodes".into(),
        ))
    }

    fn remove(&mut self, dev: &mut dyn BlockDevice, path: &Path) -> Result<()> {
        self.remove_path(dev, path)
    }

    fn list(&mut self, dev: &mut dyn BlockDevice, path: &Path) -> Result<Vec<DirEntry>> {
        self.list_dir(dev, path)
    }

    fn read_file<'a>(
        &'a mut self,
        dev: &'a mut dyn BlockDevice,
        path: &Path,
    ) -> Result<Box<dyn Read + 'a>> {
        let src = self.file_source(dev, path)?;
        Ok(Box::new(rw::FileReader::new(dev, self.geom, src)))
    }

    fn open_file_ro<'a>(
        &'a mut self,
        dev: &'a mut dyn BlockDevice,
        path: &Path,
    ) -> Result<Box<dyn crate::fs::FileReadHandle + 'a>> {
        let src = self.file_source(dev, path)?;
        Ok(Box::new(rw::FileReader::new(dev, self.geom, src)))
    }

    fn open_file_rw<'a>(
        &'a mut self,
        dev: &'a mut dyn BlockDevice,
        path: &Path,
        flags: crate::fs::OpenFlags,
        meta: Option<FileMeta>,
    ) -> Result<Box<dyn crate::fs::FileHandle + 'a>> {
        rw::open_rw(self, dev, path, flags, meta)
    }

    fn truncate(&mut self, dev: &mut dyn BlockDevice, path: &Path, new_size: u64) -> Result<()> {
        rw::truncate(self, dev, path, new_size)
    }

    fn rename(
        &mut self,
        dev: &mut dyn BlockDevice,
        old_path: &Path,
        new_path: &Path,
    ) -> Result<()> {
        let Resolved::Entry { mdir, id } = self.resolve(dev, old_path)? else {
            return Err(Error::InvalidArgument(
                "littlefs: cannot rename the root directory".into(),
            ));
        };
        let entry = mdir.entries[id].clone();
        let (dst_head, name) = self.parent_head(dev, new_path)?;
        self.check_name(&name)?;
        if self.find_in_dir(dev, dst_head, name.as_bytes())?.is_some() {
            return Err(Error::InvalidArgument(format!(
                "littlefs: {:?} already exists",
                new_path.display()
            )));
        }

        // Drop the old entry first so a name moving within one directory
        // doesn't briefly exist twice — the pair is rewritten either way.
        let mut src = mdir;
        src.entries.remove(id);
        self.commit(dev, &mut src)?;
        self.insert_entry(
            dev,
            dst_head,
            Entry {
                kind: entry.kind,
                name: name.into_bytes(),
                data: entry.data,
                attrs: entry.attrs,
            },
        )
    }

    fn getattr(&mut self, dev: &mut dyn BlockDevice, path: &Path) -> Result<FileAttrs> {
        let r = self.resolve(dev, path)?;
        let (kind, size, inode) = match &r {
            Resolved::Root => (EntryKind::Dir, 0, self.root[0].max(1)),
            Resolved::Entry { mdir, id } => {
                let e = &mdir.entries[*id];
                (
                    entry_kind(e),
                    entry_size(e),
                    synthetic_inode(mdir.pair, *id, e),
                )
            }
        };
        // littlefs stores no permissions, owners or timestamps; these are
        // the values a littlefs FUSE mount reports too.
        Ok(FileAttrs {
            kind,
            mode: if kind == EntryKind::Dir { 0o755 } else { 0o644 },
            uid: 0,
            gid: 0,
            size,
            blocks: size.div_ceil(512),
            nlink: if kind == EntryKind::Dir { 2 } else { 1 },
            atime: 0,
            mtime: 0,
            ctime: 0,
            rdev: 0,
            inode,
        })
    }

    fn list_xattrs(&mut self, dev: &mut dyn BlockDevice, path: &Path) -> Result<Vec<XattrPair>> {
        let Resolved::Entry { mdir, id } = self.resolve(dev, path)? else {
            return Ok(Vec::new());
        };
        Ok(mdir.entries[id]
            .attrs
            .iter()
            .map(|(k, v)| XattrPair {
                name: xattr_name(*k),
                value: v.clone(),
            })
            .collect())
    }

    fn set_xattr(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &Path,
        name: &str,
        value: &[u8],
    ) -> Result<()> {
        let kind = xattr_type(name)?;
        if value.len() > self.attr_max as usize {
            return Err(Error::InvalidArgument(format!(
                "littlefs: attribute value of {} bytes exceeds the volume's {}-byte limit",
                value.len(),
                self.attr_max
            )));
        }
        let Resolved::Entry { mut mdir, id } = self.resolve(dev, path)? else {
            return Err(Error::InvalidArgument(
                "littlefs: the root has no attributes".into(),
            ));
        };
        let attrs = &mut mdir.entries[id].attrs;
        attrs.retain(|(k, _)| *k != kind);
        attrs.push((kind, value.to_vec()));
        attrs.sort_by_key(|(k, _)| *k);
        self.commit(dev, &mut mdir)
    }

    fn remove_xattr(&mut self, dev: &mut dyn BlockDevice, path: &Path, name: &str) -> Result<()> {
        let kind = xattr_type(name)?;
        let Resolved::Entry { mut mdir, id } = self.resolve(dev, path)? else {
            return Err(Error::InvalidArgument(
                "littlefs: the root has no attributes".into(),
            ));
        };
        mdir.entries[id].attrs.retain(|(k, _)| *k != kind);
        self.commit(dev, &mut mdir)
    }

    fn statfs(&mut self, dev: &mut dyn BlockDevice) -> Result<StatFs> {
        let used = self.allocator(dev)?.used() as u64;
        let total = self.geom.block_count as u64;
        Ok(StatFs {
            block_size: self.geom.block_size,
            blocks: total,
            blocks_free: total.saturating_sub(used),
            blocks_avail: total.saturating_sub(used),
            inodes: 0,
            inodes_free: 0,
            name_max: self.name_max,
        })
    }

    fn flush(&mut self, dev: &mut dyn BlockDevice) -> Result<()> {
        // Every mutation is already committed; this just pushes the block
        // device's own buffers out.
        dev.sync()
    }

    fn mutation_capability(&self) -> MutationCapability {
        MutationCapability::Mutable
    }
}

impl crate::fs::FilesystemFactory for LittleFs {
    type FormatOpts = LittleFsFormatOpts;

    fn format(dev: &mut dyn BlockDevice, opts: &Self::FormatOpts) -> Result<Self> {
        LittleFs::format(dev, opts)
    }

    fn open(dev: &mut dyn BlockDevice) -> Result<Self> {
        LittleFs::open(dev)
    }

    fn size_plan(opts: &Self::FormatOpts) -> Option<Box<dyn crate::fs::FsSizePlan>> {
        Some(Box::new(LittleFsSizePlan::new(opts)))
    }
}
