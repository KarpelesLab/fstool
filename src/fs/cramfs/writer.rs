//! cramfs image builder.
//!
//! cramfs wants all directory data before all file data, and a directory's
//! size isn't known until the whole tree is. So file data is compressed and
//! written to the device as each file arrives, packed from offset 0, and
//! `flush` slides it up into its final place once the directory area's
//! size is known. Files only ever move up, and by a growing amount, so
//! moving them last-first (each one back to front) never overwrites bytes
//! that haven't moved yet. Nothing is spooled in memory beyond the tree and
//! each file's list of compressed block lengths.

use std::collections::BTreeMap;
use std::io::Read;

use super::{
    CRAMFS_MAGIC, CRAMFS_SIGNATURE, FLAG_FSID_VERSION_2, FLAG_HOLES, FLAG_SORTED_DIRS, FormatOpts,
    INODE_SIZE, MAX_FILE_SIZE, MAX_NAME_LEN, MAX_OFFSET, RawInode, SUPER_SIZE,
};
use crate::Result;
use crate::block::BlockDevice;
use crate::compression::Algo;
use crate::fs::{DeviceKind, FileMeta, SetAttrs};

/// File data already compressed onto the device at its provisional spot.
struct Blob {
    /// Provisional offset of the first compressed block.
    prov_start: u64,
    /// Compressed length of each block; 0 is a hole.
    block_lens: Vec<u32>,
    /// Final offset of the block pointer table, set during layout.
    final_start: u64,
}

impl Blob {
    fn data_len(&self) -> u64 {
        self.block_lens.iter().map(|&l| u64::from(l)).sum()
    }
}

enum Body {
    /// Children by name; a `BTreeMap` keeps them in the byte order the
    /// kernel's sorted lookup expects.
    Dir(BTreeMap<Vec<u8>, usize>),
    /// Regular file or symlink: its length and data (None when empty).
    Data { size: u32, blob: Option<usize> },
    /// Device: old-style `major << 8 | minor`.
    Device(u32),
    /// FIFO or socket.
    Special,
}

struct Node {
    /// Full `st_mode`, type bits included.
    mode: u16,
    uid: u32,
    gid: u32,
    body: Body,
}

/// The tree being built.
pub(super) struct WriteState {
    opts: FormatOpts,
    /// Node 0 is the root.
    nodes: Vec<Node>,
    blobs: Vec<Blob>,
    /// Next free provisional offset.
    cursor: u64,
    holes: bool,
}

const S_IFDIR: u16 = 0o040000;
const S_IFREG: u16 = 0o100000;
const S_IFLNK: u16 = 0o120000;
const S_IFCHR: u16 = 0o020000;
const S_IFBLK: u16 = 0o060000;
const S_IFIFO: u16 = 0o010000;
const S_IFSOCK: u16 = 0o140000;

fn pad4(n: u64) -> u64 {
    n.div_ceil(4) * 4
}

/// Split an absolute path into validated name components.
fn components(path: &str) -> Result<Vec<&[u8]>> {
    let mut out = Vec::new();
    for c in path.split('/').filter(|c| !c.is_empty() && *c != ".") {
        if c == ".." {
            return Err(crate::Error::InvalidArgument(format!(
                "cramfs: `..` in path {path:?}"
            )));
        }
        if c.len() > MAX_NAME_LEN {
            return Err(crate::Error::InvalidArgument(format!(
                "cramfs: name {c:?} is longer than {MAX_NAME_LEN} bytes"
            )));
        }
        if c.as_bytes().contains(&0) {
            return Err(crate::Error::InvalidArgument(format!(
                "cramfs: NUL in name {c:?}"
            )));
        }
        out.push(c.as_bytes());
    }
    Ok(out)
}

impl WriteState {
    pub(super) fn new(opts: &FormatOpts) -> Self {
        Self {
            opts: opts.clone(),
            nodes: vec![Node {
                mode: S_IFDIR | 0o755,
                uid: 0,
                gid: 0,
                body: Body::Dir(BTreeMap::new()),
            }],
            blobs: Vec::new(),
            cursor: 0,
            holes: false,
        }
    }

    /// Find the directory that will hold `path`'s last component, creating
    /// missing parents with default metadata. Returns `(dir, name)`.
    fn parent_of<'p>(&mut self, path: &'p str) -> Result<(usize, &'p [u8])> {
        let comps = components(path)?;
        let Some((&name, parents)) = comps.split_last() else {
            return Err(crate::Error::InvalidArgument(
                "cramfs: the root already exists".into(),
            ));
        };
        let mut cur = 0usize;
        for &c in parents {
            let next = match &self.nodes[cur].body {
                Body::Dir(ch) => ch.get(c).copied(),
                _ => {
                    return Err(crate::Error::InvalidArgument(format!(
                        "cramfs: {path:?}: a parent is not a directory"
                    )));
                }
            };
            cur = match next {
                Some(i) => i,
                None => self.insert(
                    cur,
                    c,
                    Node {
                        mode: S_IFDIR | 0o755,
                        uid: 0,
                        gid: 0,
                        body: Body::Dir(BTreeMap::new()),
                    },
                ),
            };
            if !matches!(self.nodes[cur].body, Body::Dir(_)) {
                return Err(crate::Error::InvalidArgument(format!(
                    "cramfs: {path:?}: a parent is not a directory"
                )));
            }
        }
        Ok((cur, name))
    }

    fn insert(&mut self, dir: usize, name: &[u8], node: Node) -> usize {
        let idx = self.nodes.len();
        self.nodes.push(node);
        if let Body::Dir(ch) = &mut self.nodes[dir].body {
            ch.insert(name.to_vec(), idx);
        }
        idx
    }

    /// Add `node` at `path`, refusing to replace an existing entry.
    fn add(&mut self, path: &str, node: Node) -> Result<usize> {
        let (dir, name) = self.parent_of(path)?;
        if let Body::Dir(ch) = &self.nodes[dir].body
            && ch.contains_key(name)
        {
            return Err(crate::Error::InvalidArgument(format!(
                "cramfs: {path:?} already exists"
            )));
        }
        Ok(self.insert(dir, name, node))
    }

    fn lookup(&self, path: &str) -> Result<usize> {
        let mut cur = 0usize;
        for c in components(path)? {
            cur = match &self.nodes[cur].body {
                Body::Dir(ch) => ch.get(c).copied(),
                _ => None,
            }
            .ok_or_else(|| {
                crate::Error::InvalidArgument(format!("cramfs: no such entry: {path:?}"))
            })?;
        }
        Ok(cur)
    }

    pub(super) fn create_dir(&mut self, path: &str, meta: FileMeta) -> Result<()> {
        let mode = S_IFDIR | (meta.mode & 0o7777);
        // An already-implied (or the root) directory just takes the metadata.
        if let Ok(i) = self.lookup(path)
            && matches!(self.nodes[i].body, Body::Dir(_))
        {
            let n = &mut self.nodes[i];
            n.mode = mode;
            n.uid = meta.uid;
            n.gid = meta.gid;
            return Ok(());
        }
        self.add(
            path,
            Node {
                mode,
                uid: meta.uid,
                gid: meta.gid,
                body: Body::Dir(BTreeMap::new()),
            },
        )?;
        Ok(())
    }

    pub(super) fn create_file(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &str,
        body: &mut dyn Read,
        len: u64,
        meta: FileMeta,
    ) -> Result<()> {
        if len > MAX_FILE_SIZE {
            return Err(crate::Error::InvalidArgument(format!(
                "cramfs: {path:?} is {len} bytes; files are limited to 16 MiB - 1"
            )));
        }
        // Validate the path before writing any data.
        self.parent_of(path)?;
        let blob = self.write_blob(dev, body, len)?;
        self.add(
            path,
            Node {
                mode: S_IFREG | (meta.mode & 0o7777),
                uid: meta.uid,
                gid: meta.gid,
                body: Body::Data {
                    size: len as u32,
                    blob,
                },
            },
        )?;
        Ok(())
    }

    pub(super) fn create_symlink(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &str,
        target: &str,
        meta: FileMeta,
    ) -> Result<()> {
        if target.is_empty() || target.len() as u64 > super::MAX_SYMLINK {
            return Err(crate::Error::InvalidArgument(format!(
                "cramfs: symlink {path:?} target must be 1..=64 KiB long"
            )));
        }
        self.parent_of(path)?;
        let len = target.len() as u64;
        let blob = self.write_blob(dev, &mut target.as_bytes(), len)?;
        self.add(
            path,
            Node {
                mode: S_IFLNK | (meta.mode & 0o7777),
                uid: meta.uid,
                gid: meta.gid,
                body: Body::Data {
                    size: len as u32,
                    blob,
                },
            },
        )?;
        Ok(())
    }

    pub(super) fn create_device(
        &mut self,
        path: &str,
        kind: DeviceKind,
        major: u32,
        minor: u32,
        meta: FileMeta,
    ) -> Result<()> {
        let (ty, body) = match kind {
            DeviceKind::Char | DeviceKind::Block => {
                // The size field holds the kernel's old 8:8 encoding.
                if major > 0xFF || minor > 0xFF {
                    return Err(crate::Error::InvalidArgument(format!(
                        "cramfs: device {path:?} ({major}:{minor}) doesn't fit cramfs's 8-bit major/minor"
                    )));
                }
                let ty = if kind == DeviceKind::Char {
                    S_IFCHR
                } else {
                    S_IFBLK
                };
                (ty, Body::Device(major << 8 | minor))
            }
            DeviceKind::Fifo => (S_IFIFO, Body::Special),
            DeviceKind::Socket => (S_IFSOCK, Body::Special),
        };
        self.add(
            path,
            Node {
                mode: ty | (meta.mode & 0o7777),
                uid: meta.uid,
                gid: meta.gid,
                body,
            },
        )?;
        Ok(())
    }

    /// A second name for an existing file: a copy of its inode pointing at
    /// the same data, which is how mkfs.cramfs stores hard links.
    pub(super) fn hardlink(&mut self, target: &str, new_path: &str) -> Result<()> {
        let src = self.lookup(target)?;
        let n = &self.nodes[src];
        let body = match &n.body {
            Body::Dir(_) => {
                return Err(crate::Error::InvalidArgument(format!(
                    "cramfs: can't hard-link directory {target:?}"
                )));
            }
            Body::Data { size, blob } => Body::Data {
                size: *size,
                blob: *blob,
            },
            Body::Device(d) => Body::Device(*d),
            Body::Special => Body::Special,
        };
        let node = Node {
            mode: n.mode,
            uid: n.uid,
            gid: n.gid,
            body,
        };
        self.add(new_path, node)?;
        Ok(())
    }

    pub(super) fn set_attrs(&mut self, path: &str, attrs: SetAttrs) -> Result<()> {
        let i = self.lookup(path)?;
        let n = &mut self.nodes[i];
        if let Some(m) = attrs.mode {
            n.mode = (n.mode & 0o170000) | (m & 0o7777);
        }
        if let Some(u) = attrs.uid {
            n.uid = u;
        }
        if let Some(g) = attrs.gid {
            n.gid = g;
        }
        Ok(())
    }

    /// Compress `len` bytes of `body` a block at a time onto the device at
    /// the provisional cursor. All-zero blocks become holes.
    fn write_blob(
        &mut self,
        dev: &mut dyn BlockDevice,
        body: &mut dyn Read,
        len: u64,
    ) -> Result<Option<usize>> {
        if len == 0 {
            return Ok(None);
        }
        let bs = u64::from(self.opts.block_size);
        let prov_start = self.cursor;
        let mut block_lens = Vec::with_capacity(len.div_ceil(bs) as usize);
        let mut buf = vec![0u8; bs as usize];
        let mut left = len;
        while left > 0 {
            let n = left.min(bs) as usize;
            body.read_exact(&mut buf[..n])?;
            left -= n as u64;
            if buf[..n].iter().all(|&b| b == 0) {
                block_lens.push(0);
                self.holes = true;
                continue;
            }
            let z = crate::compression::compress(Algo::Zlib, &buf[..n])?;
            dev.write_at(self.cursor, &z)?;
            self.cursor += z.len() as u64;
            block_lens.push(z.len() as u32);
        }
        self.blobs.push(Blob {
            prov_start,
            block_lens,
            final_start: 0,
        });
        Ok(Some(self.blobs.len() - 1))
    }

    /// Lay the image out and write it.
    pub(super) fn flush(mut self, dev: &mut dyn BlockDevice) -> Result<()> {
        // 1. Directory area, breadth-first: the root's children right after
        //    the superblock, then each directory's children in turn.
        //    `entry_pos[i]` is where node i's inode header goes;
        //    `dir_data[i]` is (offset, size) of directory i's entries.
        let n = self.nodes.len();
        let mut entry_pos = vec![0u64; n];
        let mut dir_data = vec![(0u64, 0u64); n];
        let mut at = SUPER_SIZE;
        let mut queue = std::collections::VecDeque::from([0usize]);
        while let Some(d) = queue.pop_front() {
            let Body::Dir(children) = &self.nodes[d].body else {
                continue;
            };
            let start = at;
            for (name, &c) in children {
                entry_pos[c] = at;
                at += INODE_SIZE + pad4(name.len() as u64);
                queue.push_back(c);
            }
            let size = at - start;
            if size > MAX_FILE_SIZE {
                return Err(crate::Error::InvalidArgument(
                    "cramfs: a directory's entries exceed 16 MiB".into(),
                ));
            }
            dir_data[d] = if size == 0 { (0, 0) } else { (start, size) };
        }
        let dir_end = at;

        // 2. File data, in the order it was written provisionally.
        let mut data_end = dir_end;
        for b in &mut self.blobs {
            b.final_start = data_end;
            data_end = pad4(data_end + 4 * b.block_lens.len() as u64 + b.data_len());
        }
        let bs = u64::from(self.opts.block_size);
        let image_end = data_end.div_ceil(bs) * bs;
        if self
            .blobs
            .last()
            .is_some_and(|b| b.final_start >= MAX_OFFSET)
            || dir_end > MAX_OFFSET
        {
            return Err(crate::Error::InvalidArgument(
                "cramfs: the image's data starts past 256 MiB, the format's limit".into(),
            ));
        }
        if image_end > u64::from(u32::MAX) {
            return Err(crate::Error::InvalidArgument(
                "cramfs: image would exceed 4 GiB".into(),
            ));
        }
        if image_end > dev.total_size() {
            return Err(crate::Error::OutOfBounds {
                offset: 0,
                len: image_end,
                size: dev.total_size(),
            });
        }

        // 3. Slide the data up, last file first, each back to front.
        let mut chunk = vec![0u8; 1 << 20];
        for b in self.blobs.iter().rev() {
            let dst = b.final_start + 4 * b.block_lens.len() as u64;
            let len = b.data_len();
            if dst == b.prov_start {
                continue;
            }
            let mut left = len;
            while left > 0 {
                let k = left.min(chunk.len() as u64);
                left -= k;
                let buf = &mut chunk[..k as usize];
                dev.read_at(b.prov_start + left, buf)?;
                dev.write_at(dst + left, buf)?;
            }
        }

        // 4. Block pointer tables and the alignment padding after each file.
        let mut total_blocks = 0u32;
        for b in &self.blobs {
            let mut end = b.final_start + 4 * b.block_lens.len() as u64;
            let mut table = Vec::with_capacity(4 * b.block_lens.len());
            for &l in &b.block_lens {
                end += u64::from(l);
                table.extend_from_slice(&(end as u32).to_le_bytes());
            }
            dev.write_at(b.final_start, &table)?;
            let padded = pad4(end);
            if padded > end {
                dev.write_at(end, &[0u8; 4][..(padded - end) as usize])?;
            }
            total_blocks += b.block_lens.len() as u32;
        }
        if image_end > data_end {
            dev.zero_range(data_end, image_end - data_end)?;
        }

        // 5. Inodes.
        let inode_for = |s: &Self, i: usize, name_len: usize| -> Result<RawInode> {
            let node = &s.nodes[i];
            let (size, offset) = match &node.body {
                Body::Dir(_) => (dir_data[i].1, dir_data[i].0),
                Body::Data { size, blob } => {
                    (u64::from(*size), blob.map_or(0, |b| s.blobs[b].final_start))
                }
                Body::Device(d) => (u64::from(*d), 0),
                Body::Special => (0, 0),
            };
            debug_assert_eq!(offset % 4, 0);
            Ok(RawInode {
                mode: node.mode,
                // Wider ids are truncated, as mkfs.cramfs does.
                uid: node.uid as u16,
                size: size as u32,
                gid: node.gid as u8,
                namelen: (pad4(name_len as u64) / 4) as u8,
                offset: (offset >> 2) as u32,
            })
        };
        let mut dir_buf = Vec::with_capacity((dir_end - SUPER_SIZE) as usize);
        let mut queue = std::collections::VecDeque::from([0usize]);
        while let Some(d) = queue.pop_front() {
            let Body::Dir(children) = &self.nodes[d].body else {
                continue;
            };
            for (name, &c) in children {
                debug_assert_eq!(SUPER_SIZE + dir_buf.len() as u64, entry_pos[c]);
                dir_buf.extend_from_slice(&inode_for(&self, c, name.len())?.encode_le());
                dir_buf.extend_from_slice(name);
                dir_buf.resize(pad4(dir_buf.len() as u64) as usize, 0);
                queue.push_back(c);
            }
        }
        dev.write_at(SUPER_SIZE, &dir_buf)?;

        // 6. Superblock, then the CRC over the whole image.
        let mut flags = FLAG_FSID_VERSION_2 | FLAG_SORTED_DIRS;
        if self.holes {
            flags |= FLAG_HOLES;
        }
        let mut sb = [0u8; SUPER_SIZE as usize];
        sb[0..4].copy_from_slice(&CRAMFS_MAGIC.to_le_bytes());
        sb[4..8].copy_from_slice(&(image_end as u32).to_le_bytes());
        sb[8..12].copy_from_slice(&flags.to_le_bytes());
        sb[16..32].copy_from_slice(CRAMFS_SIGNATURE);
        sb[36..40].copy_from_slice(&self.opts.edition.to_le_bytes());
        sb[40..44].copy_from_slice(&total_blocks.to_le_bytes());
        sb[44..48].copy_from_slice(&(n as u32).to_le_bytes());
        let name = self.opts.name.as_bytes();
        sb[48..48 + name.len()].copy_from_slice(name);
        sb[64..76].copy_from_slice(&inode_for(&self, 0, 0)?.encode_le());
        dev.write_at(0, &sb)?;

        let mut crc = 0u32;
        let mut pos = 0u64;
        while pos < image_end {
            let k = (image_end - pos).min(chunk.len() as u64) as usize;
            dev.read_at(pos, &mut chunk[..k])?;
            crc = crate::crc::crc32_append(crc, &chunk[..k]);
            pos += k as u64;
        }
        dev.write_at(32, &crc.to_le_bytes())?;
        Ok(())
    }
}
