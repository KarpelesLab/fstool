//! Paths, directories and the entries in them.
//!
//! A directory is a linked list of metadata pairs, held together by *hard*
//! tails, whose entries are sorted by their raw name bytes. Looking a name
//! up therefore walks that list comparing names in the scratch buffer, and
//! adding one finds the pair the name sorts into and commits it there —
//! splitting the pair in two when it no longer fits, which is what keeps
//! the list growing.
//!
//! Nothing here materialises a name: a lookup compares against the bytes
//! where they lie, and a listing hands out a slice of the scratch buffer,
//! which is why [`DirIter`] is a lending iterator rather than a `for` loop.

use super::super::tag;
use super::mdir::{self, Mdir, Struct, StructOut};
use super::{Error, FlashDriver, Placed, Volume};

/// A directory handle: a `Copy` value naming the metadata pair its entries
/// start at. Obtain one from [`Volume::root`] or [`Volume::open_dir`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dir {
    pub(super) head: [u32; 2],
}

impl Dir {
    /// The metadata pair the directory's entries start at.
    pub fn pair(&self) -> [u32; 2] {
        self.head
    }
}

/// What a file or directory is and how big it is.
///
/// littlefs stores no POSIX metadata at all — no mode, owner or timestamps
/// — so there is nothing else to report. Programs that want timestamps keep
/// them in a user attribute; see [`Volume::attr`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Metadata {
    pub(super) dir: bool,
    pub(super) len: u32,
}

impl Metadata {
    /// Whether this is a directory.
    pub fn is_dir(&self) -> bool {
        self.dir
    }
    /// Whether this is a regular file.
    pub fn is_file(&self) -> bool {
        !self.dir
    }
    /// Size in bytes. Always 0 for a directory.
    pub fn len(&self) -> u32 {
        self.len
    }
    /// Whether the file is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// One entry of a directory listing.
///
/// The name borrows the volume's scratch buffer, so it lives until the next
/// call to [`DirIter::next`].
#[derive(Debug, Clone, Copy)]
pub struct DirEntry<'a> {
    name: &'a [u8],
    dir: bool,
    len: u32,
}

impl<'a> DirEntry<'a> {
    /// The entry's name. littlefs names are byte strings; it is a program's
    /// own business whether it puts UTF-8 in them.
    pub fn name(&self) -> &'a [u8] {
        self.name
    }

    /// The entry's name as UTF-8, or `None` when it is not.
    pub fn name_str(&self) -> Option<&'a str> {
        core::str::from_utf8(self.name).ok()
    }

    /// Whether the entry is a directory.
    pub fn is_dir(&self) -> bool {
        self.dir
    }

    /// Size in bytes, 0 for a directory.
    pub fn len(&self) -> u32 {
        self.len
    }

    /// Whether the file is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The entry's metadata.
    pub fn metadata(&self) -> Metadata {
        Metadata {
            dir: self.dir,
            len: self.len,
        }
    }
}

/// Whether a name tag's kind is a real filesystem entry.
///
/// The superblock shares the root directory's metadata pair as id 0 but is
/// not a file — littlefs filters it out of directory listings by masking the
/// name tag's type, and so do we.
pub(super) fn is_entry(kind: u8) -> bool {
    kind == tag::TYPE_REG as u8 || kind == tag::TYPE_DIR as u8
}

/// Split a path into its components, the way littlefs's own path walk does:
/// leading and repeated separators are skipped, so `"/a/b"`, `"a/b"` and
/// `"//a//b/"` all name the same thing.
pub(super) struct Components<'a> {
    rest: &'a str,
}

impl<'a> Iterator for Components<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<&'a str> {
        let rest = self.rest.trim_start_matches('/');
        if rest.is_empty() {
            self.rest = rest;
            return None;
        }
        let (head, tail) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        self.rest = tail;
        Some(head)
    }
}

/// The components of `path`, checked for the two names littlefs has no
/// entry for.
pub(super) fn components<E>(path: &str) -> Result<Components<'_>, Error<E>> {
    for c in (Components { rest: path }) {
        if c == "." || c == ".." {
            return Err(Error::InvalidPath);
        }
    }
    Ok(Components { rest: path })
}

/// What a path resolved to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Resolved {
    /// The root directory, which has no entry of its own.
    Root,
    /// An entry in a metadata pair.
    Entry {
        /// The pair holding it, live block first.
        pair: [u32; 2],
        /// Its id within that pair.
        id: u16,
        /// Its name tag's kind.
        kind: u8,
    },
}

impl<D: FlashDriver, const BLOCK: usize, const PROG: usize> Volume<D, BLOCK, PROG> {
    /// The root directory.
    pub fn root(&self) -> Dir {
        Dir { head: self.root }
    }

    /// Open a directory.
    pub fn open_dir(&mut self, path: &str) -> Result<Dir, Error<D::Error>> {
        let r = self.resolve(path)?;
        Ok(Dir {
            head: self.dir_head(&r)?,
        })
    }

    /// Whether `path` names anything.
    pub fn exists(&mut self, path: &str) -> Result<bool, Error<D::Error>> {
        Ok(self.try_resolve(path)?.is_some())
    }

    /// What `path` is and how big it is.
    pub fn metadata(&mut self, path: &str) -> Result<Metadata, Error<D::Error>> {
        match self.resolve(path)? {
            Resolved::Root => Ok(Metadata { dir: true, len: 0 }),
            Resolved::Entry { pair, id, kind } => {
                let dir = kind == tag::TYPE_DIR as u8;
                let m = self.fetch(pair)?;
                let bs = self.bs();
                let len = match mdir::struct_of(&self.buf[..bs], &m, id) {
                    Some(Struct::Inline { len, .. }) => len,
                    Some(Struct::Ctz { size, .. }) => size,
                    _ => 0,
                };
                Ok(Metadata {
                    dir,
                    len: if dir { 0 } else { len },
                })
            }
        }
    }

    /// Iterate a directory's entries.
    ///
    /// The names come straight out of the volume's scratch buffer, so each
    /// entry lives until the next call to [`DirIter::next`]:
    ///
    /// ```no_run
    /// # fn demo<D: fstool::device::FlashDriver>(
    /// #     vol: &mut fstool::fs::littlefs::Volume<D>,
    /// # ) -> Result<(), fstool::fs::littlefs::Error<D::Error>> {
    /// let dir = vol.open_dir("/")?;
    /// let mut it = vol.iter_dir(dir);
    /// while let Some(entry) = it.next()? {
    ///     let _ = entry.name();
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn iter_dir(&mut self, dir: Dir) -> DirIter<'_, D, BLOCK, PROG> {
        DirIter {
            vol: self,
            pair: Some(dir.head),
            id: 0,
            hops: 0,
        }
    }

    /// Create a directory. Its parent must exist.
    ///
    /// The new metadata pair is threaded onto the filesystem-wide list right
    /// after its parent's last pair, so a traversal — and therefore
    /// allocation — still reaches every metadata block.
    pub fn create_dir(&mut self, path: &str) -> Result<Dir, Error<D::Error>> {
        let (head, name) = self.parent_of(path)?;
        self.check_name(name)?;
        if self.find_in_dir(head, name.as_bytes())?.is_some() {
            return Err(Error::AlreadyExists);
        }

        let fresh = self.alloc_pair()?;
        self.pending_pair = Some(fresh);
        let result = self.link_dir(head, fresh, name.as_bytes());
        self.pending_pair = None;
        match result {
            Ok(dir) => Ok(dir),
            Err(e) => {
                self.free_block(fresh[0]);
                self.free_block(fresh[1]);
                Err(e)
            }
        }
    }

    /// The body of [`Self::create_dir`], once the pair is claimed.
    fn link_dir(
        &mut self,
        head: [u32; 2],
        fresh: [u32; 2],
        name: &[u8],
    ) -> Result<Dir, Error<D::Error>> {
        // Splice the new pair into the threaded list behind the parent's
        // last pair.
        let pred_pair = self.chain_last(head)?;
        let pred = self.fetch(pred_pair)?;
        let mut dir = Mdir::empty(fresh);
        dir.rev = self.read_rev(fresh[0])?;
        dir.tail = pred.tail;
        dir.hard = false;
        let dir_pair = self.commit(&dir, super::Edit::Nothing)?.pair;

        let mut pred = self.fetch(pred_pair)?;
        pred.tail = Some(dir_pair);
        pred.hard = false;
        self.commit(&pred, super::Edit::Nothing)?;

        self.insert_entry(head, tag::TYPE_DIR as u8, name, StructOut::Dir(dir_pair))?;
        Ok(Dir { head: dir_pair })
    }

    /// Remove an empty directory.
    pub fn remove_dir(&mut self, path: &str) -> Result<(), Error<D::Error>> {
        let Resolved::Entry { pair, id, kind } = self.resolve(path)? else {
            // The root has no entry to remove.
            return Err(Error::InvalidPath);
        };
        if kind != tag::TYPE_DIR as u8 {
            return Err(Error::NotADirectory);
        }
        let m = self.fetch(pair)?;
        let bs = self.bs();
        let Some(Struct::Dir(head)) = mdir::struct_of(&self.buf[..bs], &m, id) else {
            return Err(Error::Corrupt("directory entry without a metadata pair"));
        };

        // Walk the directory's own chain: it has to be empty, and its last
        // pair's tail is what its predecessor inherits. The global state is
        // a per-pair delta whose XOR across the volume is the filesystem's
        // state, so the deltas of the pairs about to disappear are carried
        // over rather than lost.
        let mut chain = Some(head);
        let mut last_tail = None;
        let mut last_hard = false;
        let mut gdelta = [0u8; 12];
        let mut hops = 0u32;
        while let Some(p) = chain {
            let c = self.fetch(p)?;
            let bs = self.bs();
            for cid in 0..c.count {
                if let Some((kind, _, _)) = mdir::name_of(&self.buf[..bs], &c, cid)
                    && is_entry(kind)
                {
                    return Err(Error::DirectoryNotEmpty);
                }
            }
            if let Some(g) = c.gdelta {
                for (a, b) in gdelta.iter_mut().zip(g.iter()) {
                    *a ^= *b;
                }
            }
            last_tail = c.tail;
            last_hard = c.hard;
            chain = if c.hard { c.tail } else { None };
            hops += 1;
            if hops > self.geom.block_count {
                return Err(Error::Corrupt("cycle in a directory's metadata chain"));
            }
        }

        // Drop the entry first; the predecessor may well be the very pair
        // the entry lives in, so it has to be re-read afterwards.
        let m = self.fetch(pair)?;
        self.commit(&m, super::Edit::Delete { id })?;

        let mut pred = self.find_pred(head)?;
        pred.tail = last_tail;
        pred.hard = last_hard;
        if gdelta != [0u8; 12] {
            let mut acc = pred.gdelta.unwrap_or([0u8; 12]);
            for (a, b) in acc.iter_mut().zip(gdelta.iter()) {
                *a ^= *b;
            }
            pred.gdelta = if acc == [0u8; 12] { None } else { Some(acc) };
        }
        self.commit(&pred, super::Edit::Nothing)?;

        // Give the pairs back. Walking the chain again is the price of not
        // holding a list of it.
        let mut chain = Some(head);
        let mut hops = 0u32;
        while let Some(p) = chain {
            let c = self.fetch(p)?;
            self.free_block(c.pair[0]);
            self.free_block(c.pair[1]);
            chain = if c.hard { c.tail } else { None };
            hops += 1;
            if hops > self.geom.block_count {
                break;
            }
        }
        Ok(())
    }

    /// Remove a file.
    pub fn remove_file(&mut self, path: &str) -> Result<(), Error<D::Error>> {
        let Resolved::Entry { pair, id, kind } = self.resolve(path)? else {
            return Err(Error::IsADirectory);
        };
        if kind == tag::TYPE_DIR as u8 {
            return Err(Error::IsADirectory);
        }
        let m = self.fetch(pair)?;
        let bs = self.bs();
        if let Some(Struct::Ctz { head, size }) = mdir::struct_of(&self.buf[..bs], &m, id) {
            self.release_ctz(head, size, 0)?;
        }
        let m = self.fetch(pair)?;
        self.commit(&m, super::Edit::Delete { id })?;
        Ok(())
    }

    // -- user attributes --------------------------------------------------

    /// Read one littlefs user attribute into `out`, returning the
    /// attribute's full length. A buffer shorter than that takes as much as
    /// fits, the way `getxattr` behaves.
    pub fn attr(&mut self, path: &str, key: u8, out: &mut [u8]) -> Result<usize, Error<D::Error>> {
        let Resolved::Entry { pair, id, .. } = self.resolve(path)? else {
            return Err(Error::NotFound);
        };
        let m = self.fetch(pair)?;
        let bs = self.bs();
        let Some((off, len)) = mdir::attr_of(&self.buf[..bs], &m, id, key) else {
            return Err(Error::NotFound);
        };
        let n = out.len().min(len as usize);
        out[..n].copy_from_slice(&self.buf[off as usize..off as usize + n]);
        Ok(len as usize)
    }

    /// Set one littlefs user attribute.
    pub fn set_attr(&mut self, path: &str, key: u8, value: &[u8]) -> Result<(), Error<D::Error>> {
        if value.len() > self.geom.attr_max as usize {
            return Err(Error::AttrTooLarge);
        }
        let Resolved::Entry { pair, id, .. } = self.resolve(path)? else {
            return Err(Error::NotFound);
        };
        let m = self.fetch(pair)?;
        self.commit(
            &m,
            super::Edit::SetAttr {
                id,
                key,
                value: Some(value),
            },
        )?;
        Ok(())
    }

    /// Remove one littlefs user attribute. Removing one that is not there
    /// is not an error.
    pub fn remove_attr(&mut self, path: &str, key: u8) -> Result<(), Error<D::Error>> {
        let Resolved::Entry { pair, id, .. } = self.resolve(path)? else {
            return Err(Error::NotFound);
        };
        let m = self.fetch(pair)?;
        self.commit(
            &m,
            super::Edit::SetAttr {
                id,
                key,
                value: None,
            },
        )?;
        Ok(())
    }

    // -- resolution -------------------------------------------------------

    /// Resolve a path, erroring when it does not exist.
    pub(super) fn resolve(&mut self, path: &str) -> Result<Resolved, Error<D::Error>> {
        self.try_resolve(path)?.ok_or(Error::NotFound)
    }

    /// Resolve a path, returning `None` when the last component is absent.
    pub(super) fn try_resolve(&mut self, path: &str) -> Result<Option<Resolved>, Error<D::Error>> {
        let mut dir = self.root;
        let mut out = Resolved::Root;
        let mut it = components(path)?.peekable();
        while let Some(name) = it.next() {
            let Some((m, id)) = self.find_in_dir(dir, name.as_bytes())? else {
                return Ok(None);
            };
            let bs = self.bs();
            let kind = mdir::name_of(&self.buf[..bs], &m, id).map_or(0, |(k, _, _)| k);
            if it.peek().is_some() {
                let Some(Struct::Dir(p)) = mdir::struct_of(&self.buf[..bs], &m, id) else {
                    return Err(Error::NotADirectory);
                };
                dir = p;
            }
            out = Resolved::Entry {
                pair: m.pair,
                id,
                kind,
            };
        }
        Ok(Some(out))
    }

    /// The metadata pair a resolved directory's entries start at.
    pub(super) fn dir_head(&mut self, r: &Resolved) -> Result<[u32; 2], Error<D::Error>> {
        match r {
            Resolved::Root => Ok(self.root),
            Resolved::Entry { pair, id, kind } => {
                if *kind != tag::TYPE_DIR as u8 {
                    return Err(Error::NotADirectory);
                }
                let m = self.fetch(*pair)?;
                let bs = self.bs();
                match mdir::struct_of(&self.buf[..bs], &m, *id) {
                    Some(Struct::Dir(p)) => Ok(p),
                    _ => Err(Error::Corrupt("directory entry without a metadata pair")),
                }
            }
        }
    }

    /// Resolve a path's parent to the pair its entries start at, and hand
    /// back the final component.
    pub(super) fn parent_of<'p>(
        &mut self,
        path: &'p str,
    ) -> Result<([u32; 2], &'p str), Error<D::Error>> {
        let mut dir = self.root;
        let mut it = components(path)?.peekable();
        let mut last = None;
        while let Some(name) = it.next() {
            if it.peek().is_none() {
                last = Some(name);
                break;
            }
            let Some((m, id)) = self.find_in_dir(dir, name.as_bytes())? else {
                return Err(Error::NotFound);
            };
            let bs = self.bs();
            let Some(Struct::Dir(p)) = mdir::struct_of(&self.buf[..bs], &m, id) else {
                return Err(Error::NotADirectory);
            };
            dir = p;
        }
        Ok((dir, last.ok_or(Error::InvalidPath)?))
    }

    /// Find `name` in the directory whose chain starts at `head`.
    pub(super) fn find_in_dir(
        &mut self,
        head: [u32; 2],
        name: &[u8],
    ) -> Result<Option<(Mdir, u16)>, Error<D::Error>> {
        let mut pair = Some(head);
        let mut hops = 0u32;
        while let Some(p) = pair {
            let m = self.fetch(p)?;
            let bs = self.bs();
            for id in 0..m.count {
                if let Some((kind, off, len)) = mdir::name_of(&self.buf[..bs], &m, id)
                    && is_entry(kind)
                    && self.buf[off as usize..(off + len) as usize] == *name
                {
                    return Ok(Some((m, id)));
                }
            }
            pair = if m.hard { m.tail } else { None };
            hops += 1;
            if hops > self.geom.block_count {
                return Err(Error::Corrupt("cycle in a directory's metadata chain"));
            }
        }
        Ok(None)
    }

    /// The last metadata pair of a directory's chain.
    pub(super) fn chain_last(&mut self, head: [u32; 2]) -> Result<[u32; 2], Error<D::Error>> {
        let mut pair = head;
        let mut hops = 0u32;
        loop {
            let m = self.fetch(pair)?;
            match (m.hard, m.tail) {
                (true, Some(t)) => pair = t,
                _ => return Ok(m.pair),
            }
            hops += 1;
            if hops > self.geom.block_count {
                return Err(Error::Corrupt("cycle in a directory's metadata chain"));
            }
        }
    }

    /// The metadata pair whose tail points at `pair` — its predecessor on
    /// the filesystem-wide threaded list.
    pub(super) fn find_pred(&mut self, pair: [u32; 2]) -> Result<Mdir, Error<D::Error>> {
        let key = |p: [u32; 2]| if p[0] <= p[1] { p } else { [p[1], p[0]] };
        let want = key(pair);
        let mut next = Some(super::SUPERBLOCK_PAIR);
        let mut hops = 0u32;
        while let Some(p) = next {
            let m = self.fetch(p)?;
            if m.tail.map(key) == Some(want) {
                return Ok(m);
            }
            next = m.tail;
            hops += 1;
            if hops > self.geom.block_count {
                break;
            }
        }
        Err(Error::Corrupt("metadata pair is not on the threaded list"))
    }

    /// Insert an entry into a directory, keeping the chain in name order
    /// (littlefs sorts directory entries by their raw bytes).
    pub(super) fn insert_entry(
        &mut self,
        head: [u32; 2],
        kind: u8,
        name: &[u8],
        data: StructOut<'_>,
    ) -> Result<Placed, Error<D::Error>> {
        let mut pair = head;
        let mut hops = 0u32;
        loop {
            let m = self.fetch(pair)?;
            let bs = self.bs();
            // The first id whose name sorts after ours is where it goes.
            // The superblock shares the root's pair as id 0 and takes no
            // part in the ordering, so it is skipped rather than compared.
            let mut at = None;
            for id in 0..m.count {
                let Some((k, off, len)) = mdir::name_of(&self.buf[..bs], &m, id) else {
                    continue;
                };
                if !is_entry(k) {
                    continue;
                }
                if self.buf[off as usize..(off + len) as usize] > *name {
                    at = Some(id);
                    break;
                }
            }
            let at = match at {
                Some(at) => at,
                None => match (m.hard, m.tail) {
                    (true, Some(t)) => {
                        pair = t;
                        hops += 1;
                        if hops > self.geom.block_count {
                            return Err(Error::Corrupt("cycle in a directory's metadata chain"));
                        }
                        continue;
                    }
                    _ => m.count,
                },
            };
            let out = self.commit(
                &m,
                super::Edit::Insert {
                    at,
                    kind,
                    name,
                    data,
                },
            )?;
            return out.placed.ok_or(Error::Corrupt("inserted entry vanished"));
        }
    }

    /// Reject names littlefs cannot store.
    pub(super) fn check_name(&self, name: &str) -> Result<(), Error<D::Error>> {
        if name.is_empty() || name.contains('/') {
            return Err(Error::InvalidName);
        }
        if name.len() > self.geom.name_max as usize {
            return Err(Error::InvalidName);
        }
        Ok(())
    }
}

/// A directory listing in progress.
///
/// Lending iterator: each entry borrows the volume's scratch buffer, so it
/// has to be dropped before the next [`next`](Self::next).
pub struct DirIter<'v, D: FlashDriver, const BLOCK: usize, const PROG: usize> {
    vol: &'v mut Volume<D, BLOCK, PROG>,
    pair: Option<[u32; 2]>,
    id: u16,
    hops: u32,
}

impl<D: FlashDriver, const BLOCK: usize, const PROG: usize> DirIter<'_, D, BLOCK, PROG> {
    /// The next entry, or `None` at the end of the directory.
    #[allow(clippy::should_implement_trait)] // lending: the item borrows self
    pub fn next(&mut self) -> Result<Option<DirEntry<'_>>, Error<D::Error>> {
        loop {
            let Some(pair) = self.pair else {
                return Ok(None);
            };
            let m = self.vol.fetch(pair)?;
            if self.id >= m.count {
                // On to the next pair of this directory's chain.
                self.pair = if m.hard { m.tail } else { None };
                self.id = 0;
                self.hops += 1;
                if self.hops > self.vol.geom.block_count {
                    return Err(Error::Corrupt("cycle in a directory's metadata chain"));
                }
                continue;
            }
            let id = self.id;
            self.id += 1;
            let bs = self.vol.bs();
            let Some((kind, off, len)) = mdir::name_of(&self.vol.buf[..bs], &m, id) else {
                continue;
            };
            if !is_entry(kind) {
                continue;
            }
            let size = match mdir::struct_of(&self.vol.buf[..bs], &m, id) {
                Some(Struct::Inline { len, .. }) => len,
                Some(Struct::Ctz { size, .. }) => size,
                _ => 0,
            };
            let dir = kind == tag::TYPE_DIR as u8;
            return Ok(Some(DirEntry {
                name: &self.vol.buf[off as usize..(off + len) as usize],
                dir,
                len: if dir { 0 } else { size },
            }));
        }
    }
}
