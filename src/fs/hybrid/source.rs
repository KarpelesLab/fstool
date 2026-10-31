//! The one source tree every view of a hybrid image is built from.

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::block::BlockDevice;
use crate::fs::{DeviceKind, EntryKind, Filesystem};

use super::error::{HybridError, Result};

/// Index of a node in a [`SourceTree`]. The root is [`SourceTree::ROOT`].
pub type NodeId = usize;

/// Index of a file's content in a [`SourceTree`]. Hard links share one.
pub type ContentId = usize;

/// Where a file's bytes come from when the image is written.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Payload {
    /// A file on the host, opened at write time.
    HostPath(PathBuf),
    /// Bytes held in memory.
    Bytes(Arc<[u8]>),
    /// All zeros.
    Zero,
    /// A path inside a source filesystem, read through a
    /// [`FilesystemPayloads`] opener at write time.
    Filesystem(PathBuf),
    /// Anything else: an opaque key resolved by the caller's
    /// [`PayloadOpener`].
    External(u64),
}

/// Opens payloads at write time. [`HostPayloads`] handles host paths,
/// bytes and zeros; [`FilesystemPayloads`] adds paths in a source
/// filesystem; implement it for anything else ([`Payload::External`]).
pub trait PayloadOpener {
    /// A reader producing the payload's bytes (exactly the length the
    /// tree declares; the writer checks).
    fn open(&mut self, payload: &Payload) -> crate::Result<Box<dyn Read + '_>>;
}

/// Opens [`Payload::HostPath`], [`Payload::Bytes`] and [`Payload::Zero`].
#[derive(Debug, Default, Clone, Copy)]
pub struct HostPayloads;

impl PayloadOpener for HostPayloads {
    fn open(&mut self, payload: &Payload) -> crate::Result<Box<dyn Read + '_>> {
        open_basic(payload)
    }
}

fn open_basic(payload: &Payload) -> crate::Result<Box<dyn Read + 'static>> {
    match payload {
        Payload::HostPath(p) => Ok(Box::new(std::io::BufReader::with_capacity(
            1 << 20,
            std::fs::File::open(p)?,
        ))),
        Payload::Bytes(b) => Ok(Box::new(std::io::Cursor::new(b.clone()))),
        Payload::Zero => Ok(Box::new(std::io::repeat(0))),
        Payload::Filesystem(p) => Err(crate::Error::InvalidArgument(format!(
            "hybrid: payload {} lives in a source filesystem; write with a FilesystemPayloads opener",
            p.display()
        ))),
        Payload::External(k) => Err(crate::Error::InvalidArgument(format!(
            "hybrid: external payload {k} needs the caller's PayloadOpener"
        ))),
    }
}

/// Opens [`Payload::Filesystem`] paths in `fs` (on `dev`), and the
/// [`HostPayloads`] kinds.
pub struct FilesystemPayloads<'a> {
    fs: &'a mut dyn Filesystem,
    dev: &'a mut dyn BlockDevice,
}

impl<'a> FilesystemPayloads<'a> {
    /// An opener reading from `fs` on `dev`.
    pub fn new(fs: &'a mut dyn Filesystem, dev: &'a mut dyn BlockDevice) -> Self {
        Self { fs, dev }
    }
}

impl PayloadOpener for FilesystemPayloads<'_> {
    fn open(&mut self, payload: &Payload) -> crate::Result<Box<dyn Read + '_>> {
        match payload {
            Payload::Filesystem(p) => self.fs.read_file(&mut *self.dev, p),
            other => open_basic(other),
        }
    }
}

/// Permissions, ownership and times of an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct EntryMeta {
    /// Permission bits (`0o7777`), no type bits.
    pub mode: u16,
    /// Owner.
    pub uid: u32,
    /// Group.
    pub gid: u32,
    /// Modification time, seconds since the Unix epoch.
    pub mtime: i64,
    /// Access time.
    pub atime: i64,
    /// Status-change time.
    pub ctime: i64,
}

impl EntryMeta {
    /// Metadata with permission bits `mode`, owned by root, dated 1970.
    pub fn with_mode(mode: u16) -> Self {
        Self {
            mode: mode & 0o7777,
            uid: 0,
            gid: 0,
            mtime: 0,
            atime: 0,
            ctime: 0,
        }
    }

    /// The same metadata with all three times set to `t`.
    pub fn at(mut self, t: i64) -> Self {
        self.mtime = t;
        self.atime = t;
        self.ctime = t;
        self
    }
}

impl Default for EntryMeta {
    fn default() -> Self {
        Self::with_mode(0o644)
    }
}

/// What a node is.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SourceKind {
    /// A directory.
    Dir,
    /// A regular file. Nodes sharing a `content` are hard links.
    File {
        /// The content this name refers to.
        content: ContentId,
    },
    /// A symbolic link.
    Symlink {
        /// Its target, verbatim.
        target: String,
    },
    /// A device node, FIFO or socket.
    Device {
        /// Which.
        kind: DeviceKind,
        /// Major number (char / block devices).
        major: u32,
        /// Minor number.
        minor: u32,
    },
}

/// A file's bytes: how many, and where to get them.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Content {
    /// Length in bytes.
    pub len: u64,
    /// Source of the bytes.
    pub payload: Payload,
}

/// One entry of a [`SourceTree`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SourceNode {
    /// The entry's name (empty for the root).
    pub name: String,
    /// The containing directory (the root is its own parent).
    pub parent: NodeId,
    /// What the entry is.
    pub kind: SourceKind,
    /// Permissions, ownership and times.
    pub meta: EntryMeta,
    /// Extended attributes. On the HFS+ view `com.apple.FinderInfo`
    /// (32 bytes) becomes the catalog record's Finder info and
    /// `com.apple.ResourceFork` the resource fork; other views do not
    /// carry xattrs (the report says so).
    pub xattrs: Vec<crate::fs::xattr::Xattr>,
    children: Vec<NodeId>,
}

/// An in-memory description of the tree to publish: names, kinds,
/// metadata, and for each file where its bytes come from. No payload
/// bytes are held unless given as [`Payload::Bytes`].
///
/// Build it by hand ([`add_dir`](Self::add_dir), [`add_file`](Self::add_file),
/// …), from a host directory ([`from_host_dir`](Self::from_host_dir)) or
/// from any fstool [`Filesystem`] ([`from_filesystem`](Self::from_filesystem)).
#[derive(Debug, Clone)]
pub struct SourceTree {
    nodes: Vec<SourceNode>,
    contents: Vec<Content>,
}

impl Default for SourceTree {
    fn default() -> Self {
        Self::new()
    }
}

impl SourceTree {
    /// The root directory's id.
    pub const ROOT: NodeId = 0;

    /// An empty tree: a root directory with mode `0o755`.
    pub fn new() -> Self {
        Self {
            nodes: vec![SourceNode {
                name: String::new(),
                parent: 0,
                kind: SourceKind::Dir,
                meta: EntryMeta::with_mode(0o755),
                xattrs: Vec::new(),
                children: Vec::new(),
            }],
            contents: Vec::new(),
        }
    }

    /// Number of nodes, root included.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Never true (the root always exists).
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Node `id`.
    pub fn node(&self, id: NodeId) -> &SourceNode {
        &self.nodes[id]
    }

    /// Mutable node `id` (metadata, xattrs).
    pub fn node_mut(&mut self, id: NodeId) -> &mut SourceNode {
        &mut self.nodes[id]
    }

    /// Children of directory `id`, sorted by name.
    pub fn children(&self, id: NodeId) -> &[NodeId] {
        &self.nodes[id].children
    }

    /// Content `id`.
    pub fn content(&self, id: ContentId) -> &Content {
        &self.contents[id]
    }

    /// Number of distinct contents.
    pub fn content_count(&self) -> usize {
        self.contents.len()
    }

    /// The absolute path of node `id` (`"/"` for the root).
    pub fn path_of(&self, id: NodeId) -> String {
        if id == Self::ROOT {
            return "/".into();
        }
        let mut parts = Vec::new();
        let mut cur = id;
        while cur != Self::ROOT {
            parts.push(self.nodes[cur].name.as_str());
            cur = self.nodes[cur].parent;
        }
        parts.reverse();
        format!("/{}", parts.join("/"))
    }

    /// Depth of node `id` (the root is 0, its children 1).
    pub fn depth(&self, id: NodeId) -> usize {
        let mut d = 0;
        let mut cur = id;
        while cur != Self::ROOT {
            d += 1;
            cur = self.nodes[cur].parent;
        }
        d
    }

    /// Resolve an absolute path.
    pub fn lookup(&self, path: &str) -> Option<NodeId> {
        let mut cur = Self::ROOT;
        for comp in path.split('/').filter(|c| !c.is_empty()) {
            let n = &self.nodes[cur];
            if n.kind != SourceKind::Dir {
                return None;
            }
            cur = *n.children.iter().find(|&&c| self.nodes[c].name == comp)?;
        }
        Some(cur)
    }

    /// Every node in pre-order (parents before children, siblings by
    /// name).
    pub fn preorder(&self) -> Vec<NodeId> {
        let mut out = Vec::with_capacity(self.nodes.len());
        let mut stack = vec![Self::ROOT];
        while let Some(n) = stack.pop() {
            out.push(n);
            for &c in self.nodes[n].children.iter().rev() {
                stack.push(c);
            }
        }
        out
    }

    /// Metadata of the root directory.
    pub fn root_meta_mut(&mut self) -> &mut EntryMeta {
        &mut self.nodes[Self::ROOT].meta
    }

    fn insert(&mut self, path: &str, kind: SourceKind, meta: EntryMeta) -> Result<NodeId> {
        let comps: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
        let Some((leaf, dirs)) = comps.split_last() else {
            return Err(HybridError::InvalidTree(
                "the root cannot be added; it always exists".into(),
            ));
        };
        for c in &comps {
            if *c == "." || *c == ".." || c.contains('\0') {
                return Err(HybridError::InvalidTree(format!(
                    "invalid path component {c:?} in {path:?}"
                )));
            }
        }
        let mut cur = Self::ROOT;
        for d in dirs {
            cur = match self.child(cur, d) {
                Some(c) if self.nodes[c].kind == SourceKind::Dir => c,
                Some(_) => {
                    return Err(HybridError::InvalidTree(format!(
                        "{d:?} in {path:?} is not a directory"
                    )));
                }
                None => self.push(cur, d, SourceKind::Dir, EntryMeta::with_mode(0o755)),
            };
        }
        if let Some(existing) = self.child(cur, leaf) {
            if kind == SourceKind::Dir && self.nodes[existing].kind == SourceKind::Dir {
                self.nodes[existing].meta = meta;
                return Ok(existing);
            }
            return Err(HybridError::InvalidTree(format!("{path:?} already exists")));
        }
        Ok(self.push(cur, leaf, kind, meta))
    }

    fn child(&self, dir: NodeId, name: &str) -> Option<NodeId> {
        let kids = &self.nodes[dir].children;
        kids.binary_search_by(|&c| self.nodes[c].name.as_str().cmp(name))
            .ok()
            .map(|i| kids[i])
    }

    fn push(&mut self, parent: NodeId, name: &str, kind: SourceKind, meta: EntryMeta) -> NodeId {
        let id = self.nodes.len();
        self.nodes.push(SourceNode {
            name: name.to_string(),
            parent,
            kind,
            meta,
            xattrs: Vec::new(),
            children: Vec::new(),
        });
        let names: Vec<&str> = self.nodes[parent]
            .children
            .iter()
            .map(|&c| self.nodes[c].name.as_str())
            .collect();
        let at = names.partition_point(|n| *n < name);
        self.nodes[parent].children.insert(at, id);
        id
    }

    /// Add (or update the metadata of) a directory, creating missing
    /// parents with mode `0o755`.
    pub fn add_dir(&mut self, path: &str, meta: EntryMeta) -> Result<NodeId> {
        self.insert(path, SourceKind::Dir, meta)
    }

    /// Add a regular file of `len` bytes read from `payload`.
    pub fn add_file(
        &mut self,
        path: &str,
        payload: Payload,
        len: u64,
        meta: EntryMeta,
    ) -> Result<NodeId> {
        let content = self.contents.len();
        let id = self.insert(path, SourceKind::File { content }, meta)?;
        self.contents.push(Content { len, payload });
        Ok(id)
    }

    /// Add a symbolic link.
    pub fn add_symlink(&mut self, path: &str, target: &str, meta: EntryMeta) -> Result<NodeId> {
        self.insert(
            path,
            SourceKind::Symlink {
                target: target.to_string(),
            },
            meta,
        )
    }

    /// Add a device node, FIFO or socket.
    pub fn add_device(
        &mut self,
        path: &str,
        kind: DeviceKind,
        major: u32,
        minor: u32,
        meta: EntryMeta,
    ) -> Result<NodeId> {
        self.insert(path, SourceKind::Device { kind, major, minor }, meta)
    }

    /// Add `path` as a hard link to the regular file `existing`.
    pub fn add_hardlink(&mut self, path: &str, existing: &str) -> Result<NodeId> {
        let src = self.lookup(existing).ok_or_else(|| {
            HybridError::InvalidTree(format!("hard link target {existing:?} does not exist"))
        })?;
        let SourceKind::File { content } = self.nodes[src].kind else {
            return Err(HybridError::InvalidTree(format!(
                "hard link target {existing:?} is not a regular file"
            )));
        };
        let meta = self.nodes[src].meta;
        self.insert(path, SourceKind::File { content }, meta)
    }

    /// Set extended attribute `name` on `path`.
    pub fn set_xattr(&mut self, path: &str, name: &str, value: Vec<u8>) -> Result<()> {
        let id = self
            .lookup(path)
            .ok_or_else(|| HybridError::InvalidTree(format!("no entry {path:?}")))?;
        let x = &mut self.nodes[id].xattrs;
        x.retain(|a| a.name != name);
        x.push(crate::fs::xattr::Xattr::new(name, value));
        Ok(())
    }

    /// Names (nodes) that refer to content `c`, in pre-order.
    pub(crate) fn links_of(&self) -> Vec<Vec<NodeId>> {
        let mut links = vec![Vec::new(); self.contents.len()];
        for id in self.preorder() {
            if let SourceKind::File { content } = self.nodes[id].kind {
                links[content].push(id);
            }
        }
        links
    }

    /// Import a host directory: every entry below `dir` (not `dir`
    /// itself, whose metadata becomes the root's), symlinks as links,
    /// hard links (same device and inode) as shared content. File bytes
    /// are read when the image is written. Extended attributes are not
    /// read from the host; add them with [`set_xattr`](Self::set_xattr).
    pub fn from_host_dir(dir: &Path) -> Result<Self> {
        let mut tree = Self::new();
        let md = std::fs::metadata(dir)?;
        if !md.is_dir() {
            return Err(HybridError::InvalidOption(format!(
                "{} is not a directory",
                dir.display()
            )));
        }
        tree.nodes[Self::ROOT].meta = host_meta(&md);
        let mut inodes: HashMap<(u64, u64), ContentId> = HashMap::new();
        let mut stack: Vec<(PathBuf, String)> = vec![(dir.to_path_buf(), String::new())];
        while let Some((host, rel)) = stack.pop() {
            let mut names: Vec<(String, PathBuf)> = Vec::new();
            for e in std::fs::read_dir(&host)? {
                let e = e?;
                let name = e.file_name().into_string().map_err(|n| {
                    HybridError::InvalidTree(format!(
                        "non-UTF-8 name {:?} in {}",
                        n,
                        host.display()
                    ))
                })?;
                names.push((name, e.path()));
            }
            names.sort();
            for (name, path) in names {
                let tree_path = format!("{rel}/{name}");
                let md = std::fs::symlink_metadata(&path)?;
                let meta = host_meta(&md);
                let ft = md.file_type();
                if ft.is_dir() {
                    tree.add_dir(&tree_path, meta)?;
                    stack.push((path, tree_path));
                } else if ft.is_symlink() {
                    let t = std::fs::read_link(&path)?;
                    let t = t.to_str().ok_or_else(|| {
                        HybridError::InvalidTree(format!(
                            "non-UTF-8 symlink target in {}",
                            path.display()
                        ))
                    })?;
                    tree.add_symlink(&tree_path, t, meta)?;
                } else if ft.is_file() {
                    match host_inode(&md) {
                        Some(key) if inodes.contains_key(&key) => {
                            let content = inodes[&key];
                            tree.insert(&tree_path, SourceKind::File { content }, meta)?;
                        }
                        key => {
                            let id =
                                tree.add_file(&tree_path, Payload::HostPath(path), md.len(), meta)?;
                            if let (Some(key), SourceKind::File { content }) =
                                (key, &tree.nodes[id].kind)
                            {
                                inodes.insert(key, *content);
                            }
                        }
                    }
                } else if let Some((kind, major, minor)) = host_device(&md) {
                    tree.add_device(&tree_path, kind, major, minor, meta)?;
                }
            }
        }
        Ok(tree)
    }

    /// Import the whole tree of `fs` (on `dev`): directories, files,
    /// symlinks, device nodes, metadata, extended attributes, and hard
    /// links where the filesystem reports a shared inode with a link
    /// count above one. File bytes stay in the source and are read
    /// through [`FilesystemPayloads`] when the image is written.
    pub fn from_filesystem(fs: &mut dyn Filesystem, dev: &mut dyn BlockDevice) -> Result<Self> {
        let mut tree = Self::new();
        if let Ok(a) = fs.getattr(dev, Path::new("/")) {
            tree.nodes[Self::ROOT].meta = attrs_meta(&a);
        }
        tree.nodes[Self::ROOT].xattrs = fs_xattrs(fs, dev, "/");
        let mut inodes: HashMap<u32, ContentId> = HashMap::new();
        let mut stack = vec![String::new()];
        while let Some(rel) = stack.pop() {
            let dir = if rel.is_empty() {
                "/".to_string()
            } else {
                rel.clone()
            };
            let mut entries = fs.list(dev, Path::new(&dir))?;
            entries.sort_by(|a, b| a.name.cmp(&b.name));
            for e in entries {
                if e.name == "." || e.name == ".." {
                    continue;
                }
                let p = format!("{rel}/{}", e.name);
                let attrs = fs.getattr(dev, Path::new(&p)).ok();
                let meta = attrs.as_ref().map(attrs_meta).unwrap_or_default();
                let kind = attrs.as_ref().map(|a| a.kind).unwrap_or(e.kind);
                let id = match kind {
                    EntryKind::Dir => {
                        let id = tree.add_dir(&p, meta)?;
                        stack.push(p.clone());
                        id
                    }
                    EntryKind::Symlink => {
                        let t = fs.read_symlink(dev, Path::new(&p))?;
                        let t = t.to_string_lossy().into_owned();
                        tree.add_symlink(&p, &t, meta)?
                    }
                    EntryKind::Char | EntryKind::Block | EntryKind::Fifo | EntryKind::Socket => {
                        let dk = match kind {
                            EntryKind::Char => DeviceKind::Char,
                            EntryKind::Block => DeviceKind::Block,
                            EntryKind::Fifo => DeviceKind::Fifo,
                            _ => DeviceKind::Socket,
                        };
                        let (major, minor) = attrs
                            .map(|a| crate::fs::devnum::decode_devnum(a.rdev))
                            .unwrap_or((0, 0));
                        tree.add_device(&p, dk, major, minor, meta)?
                    }
                    _ => {
                        let size = attrs.map(|a| a.size).unwrap_or(e.size);
                        let shared = attrs.filter(|a| a.nlink > 1 && a.inode != 0);
                        match shared.and_then(|a| inodes.get(&a.inode).copied()) {
                            Some(content) => tree.insert(&p, SourceKind::File { content }, meta)?,
                            None => {
                                let id = tree.add_file(
                                    &p,
                                    Payload::Filesystem(PathBuf::from(&p)),
                                    size,
                                    meta,
                                )?;
                                if let (Some(a), SourceKind::File { content }) =
                                    (shared, &tree.nodes[id].kind)
                                {
                                    inodes.insert(a.inode, *content);
                                }
                                id
                            }
                        }
                    }
                };
                tree.nodes[id].xattrs = fs_xattrs(fs, dev, &p);
            }
        }
        Ok(tree)
    }
}

fn fs_xattrs(
    fs: &mut dyn Filesystem,
    dev: &mut dyn BlockDevice,
    path: &str,
) -> Vec<crate::fs::xattr::Xattr> {
    fs.list_xattrs(dev, Path::new(path))
        .unwrap_or_default()
        .into_iter()
        .map(|x| crate::fs::xattr::Xattr::new(x.name, x.value))
        .collect()
}

fn attrs_meta(a: &crate::fs::FileAttrs) -> EntryMeta {
    EntryMeta {
        mode: a.mode & 0o7777,
        uid: a.uid,
        gid: a.gid,
        mtime: i64::from(a.mtime),
        atime: i64::from(a.atime),
        ctime: i64::from(a.ctime),
    }
}

#[cfg(unix)]
fn host_meta(md: &std::fs::Metadata) -> EntryMeta {
    use std::os::unix::fs::MetadataExt;
    EntryMeta {
        mode: (md.mode() & 0o7777) as u16,
        uid: md.uid(),
        gid: md.gid(),
        mtime: md.mtime(),
        atime: md.atime(),
        ctime: md.ctime(),
    }
}

#[cfg(not(unix))]
fn host_meta(md: &std::fs::Metadata) -> EntryMeta {
    let mtime = md
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let mode = if md.is_dir() { 0o755 } else { 0o644 };
    EntryMeta::with_mode(mode).at(mtime)
}

#[cfg(unix)]
fn host_inode(md: &std::fs::Metadata) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    (md.nlink() > 1).then(|| (md.dev(), md.ino()))
}

#[cfg(not(unix))]
fn host_inode(_md: &std::fs::Metadata) -> Option<(u64, u64)> {
    None
}

#[cfg(unix)]
fn host_device(md: &std::fs::Metadata) -> Option<(DeviceKind, u32, u32)> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let ft = md.file_type();
    let rdev = md.rdev();
    // BSD / Darwin and Linux spell dev_t differently; both keep the
    // minor number in the low bits for the device numbers seen in
    // practice.
    #[cfg(target_os = "linux")]
    let (major, minor) = (
        (((rdev >> 32) & 0xffff_f000) | ((rdev >> 8) & 0xfff)) as u32,
        (((rdev >> 12) & 0xffff_ff00) | (rdev & 0xff)) as u32,
    );
    #[cfg(not(target_os = "linux"))]
    let (major, minor) = (((rdev >> 24) & 0xff) as u32, (rdev & 0xff_ffff) as u32);
    if ft.is_char_device() {
        Some((DeviceKind::Char, major, minor))
    } else if ft.is_block_device() {
        Some((DeviceKind::Block, major, minor))
    } else if ft.is_fifo() {
        Some((DeviceKind::Fifo, 0, 0))
    } else if ft.is_socket() {
        Some((DeviceKind::Socket, 0, 0))
    } else {
        None
    }
}

#[cfg(not(unix))]
fn host_device(_md: &std::fs::Metadata) -> Option<(DeviceKind, u32, u32)> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_parents_and_links() {
        let mut t = SourceTree::new();
        t.add_file(
            "/a/b/c.txt",
            Payload::Bytes(Arc::from(&b"x"[..])),
            1,
            EntryMeta::default(),
        )
        .unwrap();
        t.add_hardlink("/a/link", "/a/b/c.txt").unwrap();
        t.add_symlink("/s", "a/b", EntryMeta::default()).unwrap();
        assert_eq!(t.path_of(t.lookup("/a/b/c.txt").unwrap()), "/a/b/c.txt");
        assert!(t.add_dir("/a/b/c.txt/x", EntryMeta::default()).is_err());
        assert!(t.add_symlink("/s", "again", EntryMeta::default()).is_err());
        let links = t.links_of();
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].len(), 2);
        let order: Vec<String> = t.preorder().iter().map(|&n| t.path_of(n)).collect();
        assert_eq!(order, ["/", "/a", "/a/b", "/a/b/c.txt", "/a/link", "/s"]);
    }
}
