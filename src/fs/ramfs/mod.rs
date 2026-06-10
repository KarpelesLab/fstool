//! **ramfs** — a purely in-memory [`Filesystem`].
//!
//! Unlike every other backend, ramfs has no on-disk form: it stores its tree
//! in plain Rust collections and **ignores the `dev` argument** of every trait
//! method. Build a tree (files, directories, symlinks, devices, xattrs), work
//! with it through the normal [`Filesystem`] API (including `open_file_rw`,
//! `rename`, `hardlink`, `truncate`), then either drop it or serialise it into
//! a clean image with [`Ramfs::repack_to`].
//!
//! Because the trait still threads a `&mut dyn BlockDevice` everywhere, a
//! standalone library caller passes any throwaway device — e.g.
//! `crate::block::MemoryBackend::new(0)` — and it is never touched.
//!
//! The store is keyed by inode number (`HashMap<u64, Inode>`), so hard links
//! and renames preserve identity. Directories hold a name→inode map; regular
//! files hold a `Vec<u8>`; symlinks hold their target; special files hold a
//! packed `rdev`. The root is inode 1.

mod handle;

use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::path::{Path, PathBuf};

use handle::RamFileHandle;

use crate::block::BlockDevice;
use crate::fs::{
    DeviceKind, DirEntry, EntryKind, FileAttrs, FileHandle, FileMeta, FileReadHandle, FileSource,
    Filesystem, FilesystemFactory, OpenFlags, SetAttrs, StatFs, XattrPair,
};
use crate::{Error, Result};

/// The root directory's inode number.
const ROOT_INO: u64 = 1;

/// Per-inode permission/ownership/timestamp metadata.
#[derive(Debug, Clone, Copy)]
struct InodeMeta {
    mode: u16,
    uid: u32,
    gid: u32,
    atime: u32,
    mtime: u32,
    ctime: u32,
}

impl From<FileMeta> for InodeMeta {
    fn from(m: FileMeta) -> Self {
        Self {
            mode: m.mode,
            uid: m.uid,
            gid: m.gid,
            atime: m.atime,
            mtime: m.mtime,
            ctime: m.ctime,
        }
    }
}

/// The payload of an inode, discriminated by [`EntryKind`].
#[derive(Debug)]
enum Body {
    File(Vec<u8>),
    /// name → child inode.
    Dir(BTreeMap<String, u64>),
    Symlink(PathBuf),
    /// Char/block/fifo/socket; the kind lives on [`Inode::kind`].
    Special {
        rdev: u32,
    },
}

/// One in-memory inode.
#[derive(Debug)]
struct Inode {
    kind: EntryKind,
    meta: InodeMeta,
    nlink: u32,
    xattrs: BTreeMap<String, Vec<u8>>,
    body: Body,
}

/// Format options for [`Ramfs`]. Empty: a ramfs has nothing to configure.
#[derive(Debug, Clone, Default)]
pub struct RamfsFormatOpts {}

/// An in-memory filesystem. See the [module docs](self).
#[derive(Debug)]
pub struct Ramfs {
    inodes: HashMap<u64, Inode>,
    next_ino: u64,
}

impl Default for Ramfs {
    fn default() -> Self {
        Self::new()
    }
}

impl Ramfs {
    /// A fresh ramfs with an empty root directory (mode `0o755`).
    #[must_use]
    pub fn new() -> Self {
        let mut inodes = HashMap::new();
        inodes.insert(
            ROOT_INO,
            Inode {
                kind: EntryKind::Dir,
                meta: InodeMeta {
                    mode: 0o755,
                    uid: 0,
                    gid: 0,
                    atime: 0,
                    mtime: 0,
                    ctime: 0,
                },
                nlink: 2,
                xattrs: BTreeMap::new(),
                body: Body::Dir(BTreeMap::new()),
            },
        );
        Self {
            inodes,
            next_ino: ROOT_INO + 1,
        }
    }

    /// Serialise this ramfs into a fresh image of filesystem `F` on `dst_dev`,
    /// then flush it. The image is built once, from scratch, from the live
    /// tree — the "save when done" path. Entries `F` can't represent (a
    /// symlink/device/xattr on a metadata-poor target) are dropped with a
    /// warning rather than failing the whole save.
    pub fn repack_to<F: FilesystemFactory>(
        &mut self,
        dst_dev: &mut dyn BlockDevice,
        opts: &F::FormatOpts,
    ) -> Result<F> {
        let mut fs = F::format(dst_dev, opts)?;
        {
            // The source (this ramfs) ignores its device, so a zero-byte one
            // suffices for the walk.
            let mut dummy = crate::block::MemoryBackend::new(0);
            let mut sink = crate::repack::FsSink::new(&mut fs, dst_dev).lossy();
            crate::repack::walk_filesystem(self, &mut dummy, &mut sink)?;
        }
        fs.flush(dst_dev)?;
        Ok(fs)
    }

    // ── inode-store accessors used by the file handle ──────────────────────

    /// Immutable bytes of the regular file `ino`. Panics if `ino` isn't a
    /// file (callers only pass file inodes they just validated).
    pub(super) fn file_body(&self, ino: u64) -> &[u8] {
        match &self.inodes.get(&ino).expect("live inode").body {
            Body::File(v) => v,
            _ => unreachable!("file_body on a non-file inode"),
        }
    }

    /// Mutable byte vector of the regular file `ino`.
    pub(super) fn file_body_mut(&mut self, ino: u64) -> &mut Vec<u8> {
        match &mut self.inodes.get_mut(&ino).expect("live inode").body {
            Body::File(v) => v,
            _ => unreachable!("file_body_mut on a non-file inode"),
        }
    }

    // ── path resolution ────────────────────────────────────────────────────

    /// Split an absolute path into `/`-separated components, dropping empty
    /// segments and `.`.
    fn components(path: &Path) -> Vec<String> {
        path.to_string_lossy()
            .split('/')
            .filter(|s| !s.is_empty() && *s != ".")
            .map(str::to_string)
            .collect()
    }

    /// The child map of directory `ino`, or an error if it isn't a directory.
    fn dir_children(&self, ino: u64) -> Result<&BTreeMap<String, u64>> {
        match self.inodes.get(&ino).map(|i| &i.body) {
            Some(Body::Dir(c)) => Ok(c),
            Some(_) => Err(Error::InvalidArgument("ramfs: not a directory".into())),
            None => Err(Error::InvalidArgument("ramfs: dangling inode".into())),
        }
    }

    /// Walk `comps` from the root, honouring `..`. Returns the resolved inode.
    fn resolve_components(&self, comps: &[String], orig: &Path) -> Result<u64> {
        let mut stack = vec![ROOT_INO];
        for comp in comps {
            if comp == ".." {
                if stack.len() > 1 {
                    stack.pop();
                }
                continue;
            }
            let cur = *stack.last().unwrap();
            let ino = *self.dir_children(cur)?.get(comp).ok_or_else(|| {
                Error::InvalidArgument(format!("ramfs: no such path: {}", orig.display()))
            })?;
            stack.push(ino);
        }
        Ok(*stack.last().unwrap())
    }

    /// Resolve `path` to an inode number.
    fn resolve(&self, path: &Path) -> Result<u64> {
        let comps = Self::components(path);
        self.resolve_components(&comps, path)
    }

    /// Resolve `path`'s parent directory and return `(parent_ino, leaf_name)`.
    fn resolve_parent(&self, path: &Path) -> Result<(u64, String)> {
        let comps = Self::components(path);
        let (name, parent) = comps
            .split_last()
            .ok_or_else(|| Error::InvalidArgument("ramfs: cannot operate on the root".into()))?;
        let parent_ino = self.resolve_components(parent, path)?;
        Ok((parent_ino, name.clone()))
    }

    // ── mutation helpers ───────────────────────────────────────────────────

    fn alloc_ino(&mut self) -> u64 {
        let i = self.next_ino;
        self.next_ino += 1;
        i
    }

    /// Error unless `name` can be created in directory `parent` (it is a
    /// directory and has no existing child of that name).
    fn ensure_can_add(&self, parent: u64, name: &str) -> Result<()> {
        if self.dir_children(parent)?.contains_key(name) {
            return Err(Error::InvalidArgument(format!(
                "ramfs: already exists: {name}"
            )));
        }
        Ok(())
    }

    /// Link an already-allocated `child` inode into `parent` under `name`.
    /// The caller must have run [`Self::ensure_can_add`] first.
    fn link_child(&mut self, parent: u64, name: &str, child: u64) {
        if let Body::Dir(c) = &mut self.inodes.get_mut(&parent).expect("live parent").body {
            c.insert(name.to_string(), child);
        }
    }

    /// Create a regular file at `path` with the given bytes and metadata.
    fn insert_regular(&mut self, path: &Path, data: Vec<u8>, meta: FileMeta) -> Result<()> {
        let (parent, name) = self.resolve_parent(path)?;
        self.ensure_can_add(parent, &name)?;
        let ino = self.alloc_ino();
        self.inodes.insert(
            ino,
            Inode {
                kind: EntryKind::Regular,
                meta: meta.into(),
                nlink: 1,
                xattrs: BTreeMap::new(),
                body: Body::File(data),
            },
        );
        self.link_child(parent, &name, ino);
        Ok(())
    }
}

impl FilesystemFactory for Ramfs {
    type FormatOpts = RamfsFormatOpts;

    fn format(_dev: &mut dyn BlockDevice, _opts: &Self::FormatOpts) -> Result<Self> {
        Ok(Self::new())
    }

    fn open(_dev: &mut dyn BlockDevice) -> Result<Self> {
        Err(Error::Unsupported(
            "ramfs has no on-disk form; construct one with Ramfs::new()".into(),
        ))
    }
}

impl Filesystem for Ramfs {
    fn streams_immediately(&self) -> bool {
        // create_file consumes its source synchronously into a Vec.
        true
    }

    fn create_file(
        &mut self,
        _dev: &mut dyn BlockDevice,
        path: &Path,
        src: FileSource,
        meta: FileMeta,
    ) -> Result<()> {
        let (mut reader, len) = src.open()?;
        let mut data = Vec::with_capacity(len as usize);
        reader.by_ref().take(len).read_to_end(&mut data)?;
        self.insert_regular(path, data, meta)
    }

    fn create_file_streaming(
        &mut self,
        _dev: &mut dyn BlockDevice,
        path: &Path,
        body: &mut dyn Read,
        len: u64,
        meta: FileMeta,
    ) -> Result<()> {
        let mut data = Vec::with_capacity(len as usize);
        body.take(len).read_to_end(&mut data)?;
        self.insert_regular(path, data, meta)
    }

    fn create_dir(
        &mut self,
        _dev: &mut dyn BlockDevice,
        path: &Path,
        meta: FileMeta,
    ) -> Result<()> {
        let (parent, name) = self.resolve_parent(path)?;
        self.ensure_can_add(parent, &name)?;
        let ino = self.alloc_ino();
        self.inodes.insert(
            ino,
            Inode {
                kind: EntryKind::Dir,
                meta: meta.into(),
                nlink: 2,
                xattrs: BTreeMap::new(),
                body: Body::Dir(BTreeMap::new()),
            },
        );
        self.link_child(parent, &name, ino);
        Ok(())
    }

    fn create_symlink(
        &mut self,
        _dev: &mut dyn BlockDevice,
        path: &Path,
        target: &Path,
        meta: FileMeta,
    ) -> Result<()> {
        let (parent, name) = self.resolve_parent(path)?;
        self.ensure_can_add(parent, &name)?;
        let ino = self.alloc_ino();
        self.inodes.insert(
            ino,
            Inode {
                kind: EntryKind::Symlink,
                meta: meta.into(),
                nlink: 1,
                xattrs: BTreeMap::new(),
                body: Body::Symlink(target.to_path_buf()),
            },
        );
        self.link_child(parent, &name, ino);
        Ok(())
    }

    fn create_device(
        &mut self,
        _dev: &mut dyn BlockDevice,
        path: &Path,
        kind: DeviceKind,
        major: u32,
        minor: u32,
        meta: FileMeta,
    ) -> Result<()> {
        let (parent, name) = self.resolve_parent(path)?;
        self.ensure_can_add(parent, &name)?;
        let entry_kind = match kind {
            DeviceKind::Char => EntryKind::Char,
            DeviceKind::Block => EntryKind::Block,
            DeviceKind::Fifo => EntryKind::Fifo,
            DeviceKind::Socket => EntryKind::Socket,
        };
        // Pack rdev the same way ext does, so getattr → repack splits it back.
        let rdev = crate::fs::ext::inode::encode_devnum(major, minor);
        let ino = self.alloc_ino();
        self.inodes.insert(
            ino,
            Inode {
                kind: entry_kind,
                meta: meta.into(),
                nlink: 1,
                xattrs: BTreeMap::new(),
                body: Body::Special { rdev },
            },
        );
        self.link_child(parent, &name, ino);
        Ok(())
    }

    fn remove(&mut self, _dev: &mut dyn BlockDevice, path: &Path) -> Result<()> {
        let (parent, name) = self.resolve_parent(path)?;
        let child = *self
            .dir_children(parent)?
            .get(&name)
            .ok_or_else(|| Error::InvalidArgument(format!("ramfs: no such path: {name}")))?;
        if let Body::Dir(c) = &self.inodes.get(&child).expect("live child").body
            && !c.is_empty()
        {
            return Err(Error::InvalidArgument("ramfs: directory not empty".into()));
        }
        // Unlink from the parent.
        if let Body::Dir(c) = &mut self.inodes.get_mut(&parent).expect("live parent").body {
            c.remove(&name);
        }
        // Decrement the link count; free the inode when nothing references it.
        let inode = self.inodes.get_mut(&child).expect("live child");
        inode.nlink = inode.nlink.saturating_sub(1);
        let free = matches!(inode.kind, EntryKind::Dir) || inode.nlink == 0;
        if free {
            self.inodes.remove(&child);
        }
        Ok(())
    }

    fn list(&mut self, _dev: &mut dyn BlockDevice, path: &Path) -> Result<Vec<DirEntry>> {
        let ino = self.resolve(path)?;
        let children = self.dir_children(ino)?;
        let mut out = Vec::with_capacity(children.len());
        for (name, &cino) in children {
            let inode = self.inodes.get(&cino).expect("live child");
            let size = match &inode.body {
                Body::File(v) => v.len() as u64,
                Body::Symlink(t) => t.as_os_str().len() as u64,
                _ => 0,
            };
            out.push(DirEntry {
                name: name.clone(),
                inode: cino as u32,
                kind: inode.kind,
                size,
            });
        }
        Ok(out)
    }

    fn read_file<'a>(
        &'a mut self,
        _dev: &'a mut dyn BlockDevice,
        path: &Path,
    ) -> Result<Box<dyn Read + 'a>> {
        let ino = self.resolve(path)?;
        match &self.inodes.get(&ino).expect("live inode").body {
            Body::File(v) => Ok(Box::new(std::io::Cursor::new(v.as_slice()))),
            _ => Err(Error::InvalidArgument("ramfs: not a regular file".into())),
        }
    }

    fn open_file_ro<'a>(
        &'a mut self,
        _dev: &'a mut dyn BlockDevice,
        path: &Path,
    ) -> Result<Box<dyn FileReadHandle + 'a>> {
        let ino = self.resolve(path)?;
        if !matches!(
            self.inodes.get(&ino).expect("live inode").body,
            Body::File(_)
        ) {
            return Err(Error::InvalidArgument("ramfs: not a regular file".into()));
        }
        Ok(Box::new(RamFileHandle::new(self, ino, 0)))
    }

    fn open_file_rw<'a>(
        &'a mut self,
        _dev: &'a mut dyn BlockDevice,
        path: &Path,
        flags: OpenFlags,
        meta: Option<FileMeta>,
    ) -> Result<Box<dyn FileHandle + 'a>> {
        let ino = match self.resolve(path) {
            Ok(i) => {
                if !matches!(self.inodes.get(&i).expect("live inode").body, Body::File(_)) {
                    return Err(Error::InvalidArgument("ramfs: not a regular file".into()));
                }
                if flags.truncate {
                    self.file_body_mut(i).clear();
                }
                i
            }
            Err(_) if flags.create => {
                let meta = meta.ok_or_else(|| {
                    Error::InvalidArgument("ramfs: open_file_rw with create requires meta".into())
                })?;
                self.insert_regular(path, Vec::new(), meta)?;
                self.resolve(path)?
            }
            Err(e) => return Err(e),
        };
        let pos = if flags.append {
            self.file_body(ino).len() as u64
        } else {
            0
        };
        Ok(Box::new(RamFileHandle::new(self, ino, pos)))
    }

    fn flush(&mut self, _dev: &mut dyn BlockDevice) -> Result<()> {
        Ok(())
    }

    fn read_symlink(&mut self, _dev: &mut dyn BlockDevice, path: &Path) -> Result<PathBuf> {
        let ino = self.resolve(path)?;
        match &self.inodes.get(&ino).expect("live inode").body {
            Body::Symlink(t) => Ok(t.clone()),
            _ => Err(Error::InvalidArgument("ramfs: not a symlink".into())),
        }
    }

    fn getattr(&mut self, _dev: &mut dyn BlockDevice, path: &Path) -> Result<FileAttrs> {
        let ino = self.resolve(path)?;
        let inode = self.inodes.get(&ino).expect("live inode");
        let (size, rdev) = match &inode.body {
            Body::File(v) => (v.len() as u64, 0),
            Body::Symlink(t) => (t.as_os_str().len() as u64, 0),
            Body::Special { rdev } => (0, *rdev),
            Body::Dir(_) => (0, 0),
        };
        // Directory link count = 2 (self + `.`) + one per subdirectory (`..`).
        let nlink = match &inode.body {
            Body::Dir(c) => {
                2 + c
                    .values()
                    .filter(|&&ci| {
                        matches!(self.inodes.get(&ci).map(|i| &i.body), Some(Body::Dir(_)))
                    })
                    .count() as u32
            }
            _ => inode.nlink,
        };
        Ok(FileAttrs {
            kind: inode.kind,
            mode: inode.meta.mode,
            uid: inode.meta.uid,
            gid: inode.meta.gid,
            size,
            blocks: size.div_ceil(512),
            nlink,
            atime: inode.meta.atime,
            mtime: inode.meta.mtime,
            ctime: inode.meta.ctime,
            rdev,
            inode: ino as u32,
        })
    }

    fn set_attrs(
        &mut self,
        _dev: &mut dyn BlockDevice,
        path: &Path,
        attrs: SetAttrs,
    ) -> Result<()> {
        let ino = self.resolve(path)?;
        let inode = self.inodes.get_mut(&ino).expect("live inode");
        if let Some(m) = attrs.mode {
            inode.meta.mode = m;
        }
        if let Some(u) = attrs.uid {
            inode.meta.uid = u;
        }
        if let Some(g) = attrs.gid {
            inode.meta.gid = g;
        }
        if let Some(t) = attrs.atime {
            inode.meta.atime = t;
        }
        if let Some(t) = attrs.mtime {
            inode.meta.mtime = t;
        }
        if let Some(t) = attrs.ctime {
            inode.meta.ctime = t;
        }
        Ok(())
    }

    fn truncate(&mut self, _dev: &mut dyn BlockDevice, path: &Path, new_size: u64) -> Result<()> {
        let ino = self.resolve(path)?;
        match &mut self.inodes.get_mut(&ino).expect("live inode").body {
            Body::File(v) => {
                v.resize(new_size as usize, 0);
                Ok(())
            }
            _ => Err(Error::InvalidArgument("ramfs: not a regular file".into())),
        }
    }

    fn rename(
        &mut self,
        _dev: &mut dyn BlockDevice,
        old_path: &Path,
        new_path: &Path,
    ) -> Result<()> {
        let (old_parent, old_name) = self.resolve_parent(old_path)?;
        let child = *self
            .dir_children(old_parent)?
            .get(&old_name)
            .ok_or_else(|| Error::InvalidArgument(format!("ramfs: no such path: {old_name}")))?;
        let (new_parent, new_name) = self.resolve_parent(new_path)?;
        self.ensure_can_add(new_parent, &new_name)?;
        // Refuse to move a directory into its own subtree (would detach a cycle).
        if matches!(self.inodes.get(&child).map(|i| &i.body), Some(Body::Dir(_)))
            && self.is_ancestor(child, new_parent)
        {
            return Err(Error::InvalidArgument(
                "ramfs: cannot move a directory into itself".into(),
            ));
        }
        if let Body::Dir(c) = &mut self.inodes.get_mut(&old_parent).expect("live parent").body {
            c.remove(&old_name);
        }
        self.link_child(new_parent, &new_name, child);
        Ok(())
    }

    fn hardlink(
        &mut self,
        _dev: &mut dyn BlockDevice,
        target_path: &Path,
        new_path: &Path,
    ) -> Result<()> {
        let target = self.resolve(target_path)?;
        if matches!(
            self.inodes.get(&target).map(|i| &i.body),
            Some(Body::Dir(_))
        ) {
            return Err(Error::InvalidArgument(
                "ramfs: cannot hard-link a directory".into(),
            ));
        }
        let (parent, name) = self.resolve_parent(new_path)?;
        self.ensure_can_add(parent, &name)?;
        self.link_child(parent, &name, target);
        self.inodes.get_mut(&target).expect("live target").nlink += 1;
        Ok(())
    }

    fn list_xattrs(&mut self, _dev: &mut dyn BlockDevice, path: &Path) -> Result<Vec<XattrPair>> {
        let ino = self.resolve(path)?;
        Ok(self
            .inodes
            .get(&ino)
            .expect("live inode")
            .xattrs
            .iter()
            .map(|(name, value)| XattrPair {
                name: name.clone(),
                value: value.clone(),
            })
            .collect())
    }

    fn set_xattr(
        &mut self,
        _dev: &mut dyn BlockDevice,
        path: &Path,
        name: &str,
        value: &[u8],
    ) -> Result<()> {
        let ino = self.resolve(path)?;
        self.inodes
            .get_mut(&ino)
            .expect("live inode")
            .xattrs
            .insert(name.to_string(), value.to_vec());
        Ok(())
    }

    fn remove_xattr(&mut self, _dev: &mut dyn BlockDevice, path: &Path, name: &str) -> Result<()> {
        let ino = self.resolve(path)?;
        if self
            .inodes
            .get_mut(&ino)
            .expect("live inode")
            .xattrs
            .remove(name)
            .is_none()
        {
            return Err(Error::InvalidArgument(format!(
                "ramfs: no such xattr: {name}"
            )));
        }
        Ok(())
    }

    fn statfs(&mut self, _dev: &mut dyn BlockDevice) -> Result<StatFs> {
        let used_bytes: u64 = self
            .inodes
            .values()
            .map(|i| match &i.body {
                Body::File(v) => v.len() as u64,
                _ => 0,
            })
            .sum();
        Ok(StatFs {
            block_size: 4096,
            blocks: used_bytes.div_ceil(4096),
            blocks_free: 0,
            blocks_avail: 0,
            inodes: self.inodes.len() as u64,
            inodes_free: 0,
            name_max: 255,
        })
    }
}

impl Ramfs {
    /// Whether `ancestor` is `node` or one of its (transitive) directory
    /// ancestors-by-containment. Used by `rename` to reject moving a directory
    /// into itself. Walks down from `ancestor`'s subtree looking for `node`.
    fn is_ancestor(&self, ancestor: u64, node: u64) -> bool {
        if ancestor == node {
            return true;
        }
        let mut stack = vec![ancestor];
        while let Some(cur) = stack.pop() {
            if let Some(Body::Dir(c)) = self.inodes.get(&cur).map(|i| &i.body) {
                for &child in c.values() {
                    if child == node {
                        return true;
                    }
                    stack.push(child);
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests;
