//! UDF — Universal Disk Format (ECMA-167 / OSTA UDF), read and write.
//!
//! ## Read
//!
//! UDF revisions 1.02 through 2.60 on 512-, 1024-, 2048- and 4096-byte
//! blocks: the volume recognition sequence (`BEA01` / `NSR02` / `NSR03` /
//! `TEA01`, also behind an ISO 9660 bridge), anchors at 256, N-256 and N,
//! the main and reserve volume descriptor sequences (PVD, IUVD, PD, LVD,
//! USD, TD, Volume Descriptor Pointers), the integrity sequence, and every
//! partition map UDF defines — type 1, sparable (sparing tables), virtual
//! (the VAT of write-once media, both the 1.50 and the 2.00 layout) and
//! metadata (2.50+, falling back to the mirror file). Files are File
//! Entries or Extended File Entries with ICB strategy 4 or 4096; data is
//! embedded, or in short / long / extended allocation descriptors with
//! Allocation Extent Descriptor chains and unrecorded / unallocated
//! extents (sparse files). Directory entries decode OSTA CS0 in both its
//! 8- and 16-bit forms; symlinks, hard links (link counts, several FIDs to
//! one ICB), device nodes (Device Specification EAs), FIFOs, sockets,
//! permissions, setuid / setgid / sticky, uid / gid and timestamps (with
//! their timezone offset) all surface through the
//! [`Filesystem`](crate::fs::Filesystem) trait. The Macintosh Finder info
//! extended attribute reads as `com.apple.FinderInfo`.
//!
//! Every descriptor's tag checksum and CRC is verified, and every count,
//! length and chain read off the medium is bounded (see `read::MAX_*`):
//! a damaged or hostile image fails with [`crate::Error::InvalidImage`],
//! never a panic or an unbounded allocation. Soft problems are listed in
//! [`UdfInfo::warnings`].
//!
//! ## Write
//!
//! [`Udf::format`] + the `create_*` calls + `flush` build a fresh volume,
//! like the ISO 9660 writer: payloads stream onto the device as they
//! arrive, metadata is laid out at `flush`. Revisions 1.02, 1.50, 2.01 and
//! 2.50 (with a metadata partition and a duplicated mirror) are written,
//! each listed in [`UdfRevision::WRITABLE`] once it passes native
//! validation. Files of any size (extents split at the 2^30 − block limit,
//! Allocation Extent Descriptors when the list outgrows the File Entry),
//! sparse files, Unicode names (CS0 8-bit when possible, 16-bit when not,
//! limits checked on the encoded form), labels, permissions, uid / gid,
//! timestamps, symlinks, hard links, device nodes, FIFOs and sockets are
//! recorded. Extended attributes are not: each one offered is refused with
//! [`crate::Error::Unsupported`] *and* listed in [`Udf::unsupported`].
//!
//! For hybrid images built by an external layout planner, [`layout`]
//! records a UDF view over payload the planner already placed — see its
//! module documentation.

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::Result;
use crate::block::BlockDevice;
use crate::fs::{DirEntry, EntryKind, FileAttrs, FileMeta, FileSource};

mod ecma;
pub mod layout;
mod read;
mod write;

pub use read::{PartitionMapKind, PartitionSummary, UdfInfo, format_rev, probe};
pub use write::{AccessType, FormatOpts, UdfRevision, UnsupportedMetadata};

use ecma::LbAddr;
use read::{
    FID_DIR, FT_BLOCK, FT_CHAR, FT_DIR, FT_FIFO, FT_SOCKET, FT_SYMLINK, Fid, Inode, InodeData, Run,
    Volume,
};
use write::UdfWriter;

/// Directory entries kept in the listing cache before it is cleared.
const CACHE_ENTRIES: usize = 1 << 20;
/// Path components resolved for one lookup.
const MAX_PATH_DEPTH: usize = 4096;

/// A UDF volume: opened from a device (read-only) or being built by
/// [`Udf::format`].
pub struct Udf {
    vol: Option<Volume>,
    writer: Option<Box<UdfWriter>>,
    cache: HashMap<LbAddr, std::sync::Arc<Vec<Fid>>>,
    cached: usize,
}

impl std::fmt::Debug for Udf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Udf")
            .field("info", &self.vol.as_ref().map(|v| &v.info))
            .field("writing", &self.writer.is_some())
            .finish()
    }
}

fn kind_of(file_type: u8) -> EntryKind {
    match file_type {
        FT_DIR => EntryKind::Dir,
        FT_SYMLINK => EntryKind::Symlink,
        FT_BLOCK => EntryKind::Block,
        FT_CHAR => EntryKind::Char,
        FT_FIFO => EntryKind::Fifo,
        FT_SOCKET => EntryKind::Socket,
        _ => EntryKind::Regular,
    }
}

fn path_str(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| crate::Error::InvalidArgument("udf: non-UTF-8 path".into()))
}

fn not_found(path: &str) -> crate::Error {
    crate::Error::Io(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!("udf: no such entry {path:?}"),
    ))
}

impl Udf {
    /// Open the UDF volume on `dev`.
    pub fn open(dev: &mut dyn BlockDevice) -> Result<Self> {
        Ok(Self {
            vol: Some(Volume::open(dev)?),
            writer: None,
            cache: HashMap::new(),
            cached: 0,
        })
    }

    /// Start a fresh volume on `dev`. Entries are added through the
    /// [`Filesystem`](crate::fs::Filesystem) trait; `flush` writes the
    /// metadata.
    pub fn format(dev: &mut dyn BlockDevice, opts: &FormatOpts) -> Result<Self> {
        Ok(Self {
            vol: None,
            writer: Some(Box::new(UdfWriter::new(dev, opts.clone())?)),
            cache: HashMap::new(),
            cached: 0,
        })
    }

    /// What the volume descriptors say, for an opened volume.
    pub fn info(&self) -> Option<&UdfInfo> {
        self.vol.as_ref().map(|v| &v.info)
    }

    /// Metadata offered to the writer that UDF (as fstool writes it)
    /// cannot record. Empty for an opened volume.
    pub fn unsupported(&self) -> &[UnsupportedMetadata] {
        self.writer.as_ref().map_or(&[], |w| &w.unsupported)
    }

    /// The volume label: the logical volume identifier.
    pub fn volume_label(&self) -> String {
        match (&self.vol, &self.writer) {
            (Some(v), _) => v.info.logical_volume_id.clone(),
            (None, Some(w)) => w.opts.logical_volume_id(),
            _ => String::new(),
        }
    }

    fn vol(&self) -> Result<&Volume> {
        self.vol
            .as_ref()
            .ok_or_else(|| crate::Error::Unsupported("udf: the volume is still being built".into()))
    }

    fn writer_mut(&mut self) -> Result<&mut UdfWriter> {
        self.writer.as_deref_mut().ok_or(crate::Error::Immutable {
            kind: "udf",
            op: "write",
        })
    }

    fn inode_number(vol: &Volume, loc: LbAddr) -> u32 {
        vol.map_run(loc.part, loc.lbn, 1)
            .map(|(abs, _)| abs as u32)
            .unwrap_or(loc.lbn)
    }

    fn dir_listing(
        &mut self,
        dev: &mut dyn BlockDevice,
        ino: &Inode,
    ) -> Result<std::sync::Arc<Vec<Fid>>> {
        if let Some(l) = self.cache.get(&ino.loc) {
            return Ok(l.clone());
        }
        let vol = self.vol()?;
        let list = std::sync::Arc::new(vol.read_dir(dev, ino)?);
        if self.cached + list.len() > CACHE_ENTRIES {
            self.cache.clear();
            self.cached = 0;
        }
        self.cached += list.len();
        self.cache.insert(ino.loc, list.clone());
        Ok(list)
    }

    /// Resolve `path` to its File Entry.
    fn resolve(&mut self, dev: &mut dyn BlockDevice, path: &str) -> Result<Inode> {
        let root = self.vol()?.root;
        let mut cur = self.vol()?.read_inode(dev, root.loc)?;
        for (depth, comp) in path.split('/').filter(|c| !c.is_empty()).enumerate() {
            if depth >= MAX_PATH_DEPTH {
                return Err(crate::Error::InvalidArgument("udf: path too deep".into()));
            }
            if !cur.is_dir() {
                return Err(crate::Error::InvalidArgument(format!(
                    "udf: {comp:?} in {path:?} follows a non-directory"
                )));
            }
            let list = self.dir_listing(dev, &cur)?;
            let fid = list
                .iter()
                .find(|f| f.name == comp)
                .ok_or_else(|| not_found(path))?;
            let loc = fid.icb.loc;
            cur = self.vol()?.read_inode(dev, loc)?;
        }
        Ok(cur)
    }

    fn attrs_of(vol: &Volume, ino: &Inode) -> FileAttrs {
        let kind = kind_of(ino.file_type);
        let rdev = ino
            .device_numbers()
            .map(|(ma, mi)| crate::fs::devnum::encode_devnum(ma, mi))
            .unwrap_or(0);
        let fix = |id: u32| if id == u32::MAX { 0 } else { id };
        FileAttrs {
            kind,
            mode: ino.mode(),
            uid: fix(ino.uid),
            gid: fix(ino.gid),
            size: if kind == EntryKind::Dir { 0 } else { ino.size },
            blocks: ino.blocks512(vol.bs),
            nlink: u32::from(ino.links.max(1)),
            atime: ino.atime.clamp(0, i64::from(u32::MAX)) as u32,
            mtime: ino.mtime.clamp(0, i64::from(u32::MAX)) as u32,
            ctime: ino.ctime.clamp(0, i64::from(u32::MAX)) as u32,
            rdev,
            inode: Self::inode_number(vol, ino.loc),
        }
    }

    fn file_handle<'a>(
        &'a self,
        dev: &'a mut dyn BlockDevice,
        ino: &Inode,
    ) -> Result<UdfFileReader<'a>> {
        let vol = self.vol()?;
        let (runs, inline) = match &ino.data {
            InodeData::Inline(d) => (Vec::new(), Some(d.clone())),
            InodeData::Extents(e) => (vol.runs(e)?, None),
        };
        Ok(UdfFileReader {
            dev,
            runs,
            inline,
            len: ino.size,
            pos: 0,
        })
    }

    // ---- writer-mode reads, served from the in-memory tree ----

    fn tree_list(&self, path: &str) -> Result<Vec<DirEntry>> {
        let w = self.writer.as_ref().expect("writer mode");
        let kids = w.tree().children(path).ok_or_else(|| not_found(path))?;
        Ok(kids
            .into_iter()
            .map(|(name, id, e)| {
                let (kind, size) = match e {
                    layout::TreeEntry::Dir => (EntryKind::Dir, 0),
                    layout::TreeEntry::File(d) => (EntryKind::Regular, d.len),
                    layout::TreeEntry::Symlink(_) => (EntryKind::Symlink, 0),
                    layout::TreeEntry::Device { kind, .. } => (
                        match kind {
                            crate::fs::DeviceKind::Char => EntryKind::Char,
                            crate::fs::DeviceKind::Block => EntryKind::Block,
                            crate::fs::DeviceKind::Fifo => EntryKind::Fifo,
                            crate::fs::DeviceKind::Socket => EntryKind::Socket,
                        },
                        0,
                    ),
                };
                DirEntry {
                    name,
                    inode: id as u32 + 1,
                    kind,
                    size,
                }
            })
            .collect())
    }

    fn tree_reader<'a>(
        &'a self,
        dev: &'a mut dyn BlockDevice,
        path: &str,
    ) -> Result<UdfFileReader<'a>> {
        let w = self.writer.as_ref().expect("writer mode");
        let bs = u64::from(w.opts.block_size);
        match w.tree().entry(path) {
            Some((layout::TreeEntry::File(d), _)) => {
                let mut runs = Vec::new();
                let mut off = 0u64;
                for e in &d.extents {
                    let dev_off = match *e {
                        layout::DataExtent::Recorded { block, .. } => Some(block * bs),
                        _ => None,
                    };
                    runs.push(Run {
                        file_off: off,
                        len: e.len(),
                        dev_off,
                    });
                    off += e.len();
                }
                Ok(UdfFileReader {
                    dev,
                    runs,
                    inline: None,
                    len: d.len,
                    pos: 0,
                })
            }
            Some(_) => Err(crate::Error::InvalidArgument(format!(
                "udf: {path:?} is not a regular file"
            ))),
            None => Err(not_found(path)),
        }
    }
}

/// Random-access reader over a UDF file's extents.
pub struct UdfFileReader<'a> {
    dev: &'a mut dyn BlockDevice,
    runs: Vec<Run>,
    inline: Option<Vec<u8>>,
    len: u64,
    pos: u64,
}

impl Read for UdfFileReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() || self.pos >= self.len {
            return Ok(0);
        }
        let want = (buf.len() as u64).min(self.len - self.pos);
        if let Some(d) = &self.inline {
            let p = self.pos as usize;
            let avail = d.len().saturating_sub(p).min(want as usize);
            buf[..avail].copy_from_slice(&d[p..p + avail]);
            // Bytes the size promises but the body lacks read as zeros.
            let n = if avail == 0 { want as usize } else { avail };
            buf[avail..n].fill(0);
            self.pos += n as u64;
            return Ok(n);
        }
        let i = self
            .runs
            .partition_point(|r| r.file_off + r.len <= self.pos);
        let n = match self.runs.get(i) {
            Some(r) if r.file_off <= self.pos => {
                let within = self.pos - r.file_off;
                let n = (r.len - within).min(want) as usize;
                match r.dev_off {
                    Some(d) => self
                        .dev
                        .read_at(d + within, &mut buf[..n])
                        .map_err(|e| std::io::Error::other(e.to_string()))?,
                    None => buf[..n].fill(0),
                }
                n
            }
            // A gap before the next run (or past the last): zeros.
            Some(r) => {
                let n = (r.file_off - self.pos).min(want) as usize;
                buf[..n].fill(0);
                n
            }
            None => {
                let n = want as usize;
                buf[..n].fill(0);
                n
            }
        };
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for UdfFileReader<'_> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let target = match pos {
            SeekFrom::Start(n) => i128::from(n),
            SeekFrom::Current(d) => i128::from(self.pos) + i128::from(d),
            SeekFrom::End(d) => i128::from(self.len) + i128::from(d),
        };
        if target < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "udf: seek before the start of the file",
            ));
        }
        self.pos = (target as u128).min(u128::from(self.len)) as u64;
        Ok(self.pos)
    }
}

impl crate::fs::FileReadHandle for UdfFileReader<'_> {
    fn len(&self) -> u64 {
        self.len
    }
}

impl crate::fs::FilesystemFactory for Udf {
    type FormatOpts = FormatOpts;

    fn format(dev: &mut dyn BlockDevice, opts: &Self::FormatOpts) -> Result<Self> {
        Self::format(dev, opts)
    }

    fn open(dev: &mut dyn BlockDevice) -> Result<Self> {
        Self::open(dev)
    }

    fn size_plan(opts: &Self::FormatOpts) -> Option<Box<dyn crate::fs::FsSizePlan>> {
        Some(Box::new(write::UdfSizePlan::new(opts)))
    }
}

impl crate::fs::Filesystem for Udf {
    fn create_file(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &Path,
        src: FileSource,
        meta: FileMeta,
    ) -> Result<()> {
        let w = self.writer_mut()?;
        let (mut reader, len) = src.open()?;
        let mut take = (&mut reader).take(len);
        w.add_file(dev, path, &mut take, meta)
    }

    fn streams_immediately(&self) -> bool {
        true
    }

    fn create_file_streaming(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &Path,
        body: &mut dyn Read,
        len: u64,
        meta: FileMeta,
    ) -> Result<()> {
        let w = self.writer_mut()?;
        let mut take = body.take(len);
        w.add_file(dev, path, &mut take, meta)
    }

    fn create_dir(
        &mut self,
        _dev: &mut dyn BlockDevice,
        path: &Path,
        meta: FileMeta,
    ) -> Result<()> {
        self.writer_mut()?.add_dir(path, meta)
    }

    fn create_symlink(
        &mut self,
        _dev: &mut dyn BlockDevice,
        path: &Path,
        target: &Path,
        meta: FileMeta,
    ) -> Result<()> {
        self.writer_mut()?.add_symlink(path, target, meta)
    }

    fn create_device(
        &mut self,
        _dev: &mut dyn BlockDevice,
        path: &Path,
        kind: crate::fs::DeviceKind,
        major: u32,
        minor: u32,
        meta: FileMeta,
    ) -> Result<()> {
        self.writer_mut()?
            .add_device(path, kind, major, minor, meta)
    }

    fn hardlink(
        &mut self,
        _dev: &mut dyn BlockDevice,
        target_path: &Path,
        new_path: &Path,
    ) -> Result<()> {
        self.writer_mut()?.add_hardlink(target_path, new_path)
    }

    fn set_attrs(
        &mut self,
        _dev: &mut dyn BlockDevice,
        path: &Path,
        attrs: crate::fs::SetAttrs,
    ) -> Result<()> {
        let p = path_str(path)?.to_string();
        let w = self.writer_mut()?;
        let (_, mut meta) = w.tree().entry(&p).ok_or_else(|| not_found(&p))?;
        if let Some(m) = attrs.mode {
            meta.mode = m;
        }
        if let Some(u) = attrs.uid {
            meta.uid = u;
        }
        if let Some(g) = attrs.gid {
            meta.gid = g;
        }
        if let Some(t) = attrs.atime {
            meta.atime = t;
        }
        if let Some(t) = attrs.mtime {
            meta.mtime = t;
        }
        if let Some(t) = attrs.ctime {
            meta.ctime = t;
        }
        w.tree_mut().set_meta(&p, meta)
    }

    fn remove(&mut self, _dev: &mut dyn BlockDevice, path: &Path) -> Result<()> {
        self.writer_mut()?.remove(path)
    }

    fn set_xattr(
        &mut self,
        _dev: &mut dyn BlockDevice,
        path: &Path,
        name: &str,
        _value: &[u8],
    ) -> Result<()> {
        let w = self.writer_mut()?;
        w.note_unsupported(path, format!("xattr {name}"));
        Err(crate::Error::Unsupported(format!(
            "udf: extended attribute {name:?} on {} is not recorded",
            path.display()
        )))
    }

    fn list(&mut self, dev: &mut dyn BlockDevice, path: &Path) -> Result<Vec<DirEntry>> {
        let p = path_str(path)?;
        if self.vol.is_none() {
            return self.tree_list(p);
        }
        let dir = self.resolve(dev, p)?;
        if !dir.is_dir() {
            return Err(crate::Error::InvalidArgument(format!(
                "udf: {p:?} is not a directory"
            )));
        }
        let list = self.dir_listing(dev, &dir)?;
        let vol = self.vol()?;
        let mut out = Vec::with_capacity(list.len());
        for f in list.iter() {
            let ino = vol.read_inode(dev, f.icb.loc)?;
            let mut kind = kind_of(ino.file_type);
            if f.characteristics & FID_DIR != 0 {
                kind = EntryKind::Dir;
            }
            out.push(DirEntry {
                name: f.name.clone(),
                inode: Self::inode_number(vol, f.icb.loc),
                kind,
                size: if kind == EntryKind::Regular {
                    ino.size
                } else {
                    0
                },
            });
        }
        Ok(out)
    }

    fn read_file<'a>(
        &'a mut self,
        dev: &'a mut dyn BlockDevice,
        path: &Path,
    ) -> Result<Box<dyn Read + 'a>> {
        Ok(Box::new(self.open_file_ro(dev, path)?))
    }

    fn open_file_ro<'a>(
        &'a mut self,
        dev: &'a mut dyn BlockDevice,
        path: &Path,
    ) -> Result<Box<dyn crate::fs::FileReadHandle + 'a>> {
        let p = path_str(path)?;
        if self.vol.is_none() {
            return Ok(Box::new(self.tree_reader(dev, p)?));
        }
        let ino = self.resolve(dev, p)?;
        if ino.is_dir() {
            return Err(crate::Error::InvalidArgument(format!(
                "udf: {p:?} is a directory"
            )));
        }
        Ok(Box::new(self.file_handle(dev, &ino)?))
    }

    fn read_symlink(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &Path,
    ) -> Result<std::path::PathBuf> {
        let p = path_str(path)?;
        if self.vol.is_none() {
            let w = self.writer.as_ref().expect("writer mode");
            return match w.tree().entry(p) {
                Some((layout::TreeEntry::Symlink(t), _)) => Ok(t.into()),
                Some(_) => Err(crate::Error::InvalidArgument(format!(
                    "udf: {p:?} is not a symlink"
                ))),
                None => Err(not_found(p)),
            };
        }
        let ino = self.resolve(dev, p)?;
        if ino.file_type != FT_SYMLINK {
            return Err(crate::Error::InvalidArgument(format!(
                "udf: {p:?} is not a symlink"
            )));
        }
        let body = self.vol()?.read_all(dev, &ino, read::MAX_SYMLINK_BYTES)?;
        Ok(read::decode_symlink(&body)?.into())
    }

    fn getattr(&mut self, dev: &mut dyn BlockDevice, path: &Path) -> Result<FileAttrs> {
        let p = path_str(path)?;
        if self.vol.is_none() {
            let w = self.writer.as_ref().expect("writer mode");
            let (e, meta) = w.tree().entry(p).ok_or_else(|| not_found(p))?;
            let (kind, size, rdev) = match e {
                layout::TreeEntry::Dir => (EntryKind::Dir, 0, 0),
                layout::TreeEntry::File(d) => (EntryKind::Regular, d.len, 0),
                layout::TreeEntry::Symlink(t) => (EntryKind::Symlink, t.len() as u64, 0),
                layout::TreeEntry::Device { kind, major, minor } => (
                    match kind {
                        crate::fs::DeviceKind::Char => EntryKind::Char,
                        crate::fs::DeviceKind::Block => EntryKind::Block,
                        crate::fs::DeviceKind::Fifo => EntryKind::Fifo,
                        crate::fs::DeviceKind::Socket => EntryKind::Socket,
                    },
                    0,
                    crate::fs::devnum::encode_devnum(major, minor),
                ),
            };
            return Ok(FileAttrs {
                kind,
                mode: meta.mode,
                uid: meta.uid,
                gid: meta.gid,
                size,
                blocks: size.div_ceil(512),
                nlink: w.tree().link_count(p).unwrap_or(1) as u32,
                atime: meta.atime,
                mtime: meta.mtime,
                ctime: meta.ctime,
                rdev,
                inode: 0,
            });
        }
        let ino = self.resolve(dev, p)?;
        Ok(Self::attrs_of(self.vol()?, &ino))
    }

    fn list_xattrs(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &Path,
    ) -> Result<Vec<crate::fs::XattrPair>> {
        if self.vol.is_none() {
            return Ok(Vec::new());
        }
        let ino = self.resolve(dev, path_str(path)?)?;
        Ok(ino
            .finder_info()
            .filter(|fi| fi.iter().any(|&b| b != 0))
            .map(|value| crate::fs::XattrPair {
                name: "com.apple.FinderInfo".into(),
                value,
            })
            .into_iter()
            .collect())
    }

    fn statfs(&mut self, _dev: &mut dyn BlockDevice) -> Result<crate::fs::StatFs> {
        let Some(vol) = &self.vol else {
            return Ok(crate::fs::StatFs::default());
        };
        let blocks: u64 = vol
            .info
            .partitions
            .iter()
            .filter(|p| {
                p.kind == PartitionMapKind::Physical || p.kind == PartitionMapKind::Sparable
            })
            .map(|p| p.length)
            .sum();
        Ok(crate::fs::StatFs {
            block_size: vol.bs,
            blocks,
            blocks_free: vol.info.free_blocks.unwrap_or(0),
            blocks_avail: vol.info.free_blocks.unwrap_or(0),
            name_max: 255,
            ..crate::fs::StatFs::default()
        })
    }

    fn image_len(&self) -> Option<u64> {
        self.writer.as_ref().and_then(|w| w.image_len())
    }

    fn flush(&mut self, dev: &mut dyn BlockDevice) -> Result<()> {
        if let Some(w) = self.writer.as_deref_mut() {
            w.flush(dev)?;
        }
        Ok(())
    }

    fn mutation_capability(&self) -> crate::fs::MutationCapability {
        crate::fs::MutationCapability::Immutable
    }
}

#[cfg(test)]
mod tests;
