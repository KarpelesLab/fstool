//! Paths, directories and the entries in them.
//!
//! An exFAT directory is a cluster chain of 32-byte slots. A lookup walks
//! it comparing names where they lie (see [`super::entry`]), and adding one
//! finds a run of free slots — deleted or never-used — long enough for the
//! new set, growing the chain when there is none.
//!
//! Nothing here materialises a name until a caller asks for one:
//! [`DirIter`] owns the buffer its entries borrow, which is why it is a
//! lending iterator rather than something a `for` loop drives.

use super::super::layout::{self, ENTRY_SIZE};
use super::entry::{self, EntrySet, SetBuilder};
use super::{Error, SectorDriver, Stream, Timestamp, Volume};

/// UTF-8 bytes a name can need: three per UTF-16 code unit, which covers
/// every code point in the Basic Multilingual Plane plus a replacement
/// character per unpaired surrogate.
const NAME_BYTES: usize = layout::MAX_NAME_UNITS * 3;

/// A directory handle: a `Copy` value naming the stream its entries live in,
/// and where its own entry set is so that a grown chain can be recorded.
/// Obtain one from [`Volume::root`] or [`Volume::open_dir`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dir {
    pub(super) stream: Stream,
    /// The parent's stream and the offset of this directory's entry set in
    /// it. `None` for the root, which has no entry.
    pub(super) entry: Option<(Stream, u64)>,
}

impl Dir {
    /// First cluster of the directory's chain.
    pub fn first_cluster(&self) -> u32 {
        self.stream.first_cluster
    }

    /// Whether this is the root directory.
    pub fn is_root(&self) -> bool {
        self.entry.is_none()
    }
}

/// What a file or directory is, and what exFAT records about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Metadata {
    pub(super) dir: bool,
    pub(super) len: u64,
    pub(super) attrs: u16,
    pub(super) created: u32,
    pub(super) modified: u32,
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
    /// Size in bytes. A directory reports the length of its chain.
    pub fn len(&self) -> u64 {
        self.len
    }
    /// Whether the file is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    /// The raw FileAttributes word.
    pub fn attributes(&self) -> u16 {
        self.attrs
    }
    /// Whether the read-only attribute is set.
    pub fn is_read_only(&self) -> bool {
        self.attrs & layout::ATTR_READ_ONLY != 0
    }
    /// Whether the hidden attribute is set.
    pub fn is_hidden(&self) -> bool {
        self.attrs & layout::ATTR_HIDDEN != 0
    }
    /// Creation time.
    pub fn created(&self) -> Timestamp {
        entry::timestamp_of(self.created, 0)
    }
    /// Last-modification time.
    pub fn modified(&self) -> Timestamp {
        entry::timestamp_of(self.modified, 0)
    }
}

/// One entry of a directory listing.
///
/// The name borrows the iterator's buffer, so it lives until the next call
/// to [`DirIter::next`].
#[derive(Debug, Clone, Copy)]
pub struct DirEntry<'a> {
    name: &'a str,
    meta: Metadata,
}

impl<'a> DirEntry<'a> {
    /// The entry's name, decoded from UTF-16. An unpaired surrogate — which
    /// exFAT does not forbid — becomes U+FFFD.
    pub fn name(&self) -> &'a str {
        self.name
    }

    /// Whether the entry is a directory.
    pub fn is_dir(&self) -> bool {
        self.meta.dir
    }

    /// Size in bytes.
    pub fn len(&self) -> u64 {
        self.meta.len
    }

    /// Whether the file is empty.
    pub fn is_empty(&self) -> bool {
        self.meta.len == 0
    }

    /// The entry's metadata.
    pub fn metadata(&self) -> Metadata {
        self.meta
    }
}

/// Split a path into its components the way the driver walks one: leading
/// and repeated separators are skipped, and both separators are accepted so
/// a Windows-shaped path works.
pub(super) struct Components<'a> {
    rest: &'a str,
}

impl<'a> Iterator for Components<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<&'a str> {
        let rest = self.rest.trim_start_matches(['/', '\\']);
        if rest.is_empty() {
            self.rest = rest;
            return None;
        }
        let (head, tail) = match rest.find(['/', '\\']) {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        self.rest = tail;
        Some(head)
    }
}

/// The components of `path`, refusing the two names a path walk resolves
/// itself.
pub(super) fn components<E>(path: &str) -> Result<Components<'_>, Error<E>> {
    for c in (Components { rest: path }) {
        if c == "." || c == ".." {
            return Err(Error::InvalidPath);
        }
    }
    Ok(Components { rest: path })
}

/// Where a lookup landed: the entry set, and the directory it lives in.
#[derive(Debug, Clone, Copy)]
pub(super) struct Found {
    pub parent: Dir,
    pub set: EntrySet,
}

/// The stream an entry set's data lives in.
///
/// A directory that is *not* contiguous is walked to the end of its chain
/// rather than to its DataLength: exFAT tolerates a length that lags the
/// chain, and a scan that stopped at it would miss entries. A contiguous
/// one has no chain to end, so there its length is the only bound.
pub(super) fn dir_stream_of(set: &EntrySet) -> Stream {
    if set.flags & layout::SECFLAG_NO_FAT_CHAIN != 0 {
        Stream {
            first_cluster: set.first_cluster,
            len: set.data_length,
            contiguous: true,
        }
    } else {
        Stream {
            first_cluster: set.first_cluster,
            len: u64::MAX,
            contiguous: false,
        }
    }
}

impl<D: SectorDriver, const SECTOR: usize> Volume<D, SECTOR> {
    /// The root directory.
    pub fn root(&self) -> Dir {
        Dir {
            stream: Stream::dir(self.geom.root_cluster, u64::MAX),
            entry: None,
        }
    }

    /// Open a directory.
    pub fn open_dir(&mut self, path: &str) -> Result<Dir, Error<D::Error>> {
        match self.find(path)? {
            None => Ok(self.root()),
            Some(found) => {
                if !found.set.is_dir() {
                    return Err(Error::NotADirectory);
                }
                Ok(Dir {
                    stream: dir_stream_of(&found.set),
                    entry: Some((found.parent.stream, found.set.pos)),
                })
            }
        }
    }

    /// Whether `path` names anything.
    pub fn exists(&mut self, path: &str) -> Result<bool, Error<D::Error>> {
        match self.find(path) {
            Ok(_) => Ok(true),
            Err(e) if e.is_not_found() => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// What `path` is and what exFAT records about it.
    pub fn metadata(&mut self, path: &str) -> Result<Metadata, Error<D::Error>> {
        match self.find(path)? {
            None => Ok(Metadata {
                dir: true,
                len: 0,
                attrs: layout::ATTR_DIRECTORY,
                created: 0,
                modified: 0,
            }),
            Some(found) => Ok(meta_of(&found.set)),
        }
    }

    /// Iterate a directory's entries.
    ///
    /// Names are decoded into the iterator's own buffer, so each entry lives
    /// until the next call to [`DirIter::next`]:
    ///
    /// ```no_run
    /// # fn demo<D: fstool::device::SectorDriver>(
    /// #     vol: &mut fstool::fs::exfat::Volume<D>,
    /// # ) -> Result<(), fstool::fs::exfat::Error<D::Error>> {
    /// let dir = vol.open_dir("/")?;
    /// let mut it = vol.iter_dir(dir);
    /// while let Some(entry) = it.next()? {
    ///     let _ = entry.name();
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn iter_dir(&mut self, dir: Dir) -> DirIter<'_, D, SECTOR> {
        DirIter {
            vol: self,
            dir: dir.stream,
            pos: 0,
            units: [0u16; layout::MAX_NAME_UNITS],
            name: [0u8; NAME_BYTES],
            name_len: 0,
        }
    }

    /// Create a directory. Its parent must exist.
    pub fn create_dir(&mut self, path: &str) -> Result<Dir, Error<D::Error>> {
        self.require_bitmap()?;
        let (parent, name) = self.parent_of(path)?;
        self.check_name(name)?;
        if self.find_in_dir(&parent.stream, name)?.is_some() {
            return Err(Error::AlreadyExists);
        }
        // A directory is one zeroed cluster: a zeroed slot is what ends it.
        let cluster = self.alloc_zeroed_cluster(None)?;
        let cb = self.geom.cluster_bytes() as u64;
        let hash = self.name_hash(name)?;
        let set = SetBuilder::new(
            name,
            layout::ATTR_DIRECTORY,
            layout::SECFLAG_ALLOC_POSSIBLE,
            cluster,
            cb,
            cb,
            entry::stamp_of(self.now),
            hash,
        )?;
        match self.insert_set(&parent, &set) {
            Ok(pos) => {
                self.flush_cache()?;
                Ok(Dir {
                    stream: Stream::dir(cluster, u64::MAX),
                    entry: Some((parent.stream, pos)),
                })
            }
            Err(e) => {
                // Give the cluster back rather than leaking it.
                let _ = self.free_chain(cluster);
                Err(e)
            }
        }
    }

    /// Remove an empty directory.
    pub fn remove_dir(&mut self, path: &str) -> Result<(), Error<D::Error>> {
        self.require_bitmap()?;
        let Some(found) = self.find(path)? else {
            // The root has no entry to remove.
            return Err(Error::InvalidPath);
        };
        if !found.set.is_dir() {
            return Err(Error::NotADirectory);
        }
        let dir = dir_stream_of(&found.set);
        if self.first_set(&dir)?.is_some() {
            return Err(Error::DirectoryNotEmpty);
        }
        let parent = found.parent.stream;
        self.clear_set(&parent, &found.set)?;
        self.free_stream(&found.set.stream())?;
        self.flush_cache()
    }

    /// Remove a file.
    pub fn remove_file(&mut self, path: &str) -> Result<(), Error<D::Error>> {
        self.require_bitmap()?;
        let Some(found) = self.find(path)? else {
            return Err(Error::IsADirectory);
        };
        if found.set.is_dir() {
            return Err(Error::IsADirectory);
        }
        let parent = found.parent.stream;
        self.clear_set(&parent, &found.set)?;
        self.free_stream(&found.set.stream())?;
        self.flush_cache()
    }

    // -- lookup -----------------------------------------------------------

    /// Resolve a path. `None` is the root, which has no entry set.
    pub(super) fn find(&mut self, path: &str) -> Result<Option<Found>, Error<D::Error>> {
        let mut parent = self.root();
        let mut out = None;
        let mut it = components(path)?.peekable();
        while let Some(name) = it.next() {
            let Some(set) = self.find_in_dir(&parent.stream, name)? else {
                return Err(Error::NotFound);
            };
            let found = Found { parent, set };
            if it.peek().is_some() {
                // A path continues through directories only.
                if !set.is_dir() {
                    return Err(Error::NotADirectory);
                }
                parent = Dir {
                    stream: dir_stream_of(&set),
                    entry: Some((parent.stream, set.pos)),
                };
            }
            out = Some(found);
        }
        Ok(out)
    }

    /// Find `name` in a directory, comparing case-insensitively through the
    /// volume's up-case table.
    pub(super) fn find_in_dir(
        &mut self,
        dir: &Stream,
        name: &str,
    ) -> Result<Option<EntrySet>, Error<D::Error>> {
        let hash = self.name_hash(name)?;
        let mut pos = 0u64;
        let limit = self.dir_limit();
        while pos < limit {
            let Some(slot) = self.read_slot(dir, pos)? else {
                return Ok(None);
            };
            match slot[0] {
                // A zeroed type byte ends the directory.
                0 => return Ok(None),
                layout::ENTRY_FILE => {
                    let set = self.read_set(dir, pos)?.ok_or(Error::CorruptEntry)?;
                    // The stored hash rejects almost every name without a
                    // comparison; only a candidate is read in full.
                    if set.name_hash == hash && self.name_matches(dir, &set, name)? {
                        return Ok(Some(set));
                    }
                    pos += set.bytes();
                }
                _ => pos += ENTRY_SIZE as u64,
            }
        }
        Ok(None)
    }

    /// The first live file set in a directory, if it has one.
    pub(super) fn first_set(&mut self, dir: &Stream) -> Result<Option<EntrySet>, Error<D::Error>> {
        let mut pos = 0u64;
        let limit = self.dir_limit();
        while pos < limit {
            let Some(slot) = self.read_slot(dir, pos)? else {
                return Ok(None);
            };
            match slot[0] {
                0 => return Ok(None),
                layout::ENTRY_FILE => return self.read_set(dir, pos),
                _ => pos += ENTRY_SIZE as u64,
            }
        }
        Ok(None)
    }

    /// Resolve a path's parent directory and hand back the final component.
    pub(super) fn parent_of<'p>(
        &mut self,
        path: &'p str,
    ) -> Result<(Dir, &'p str), Error<D::Error>> {
        let mut dir = self.root();
        let mut it = components(path)?.peekable();
        let mut last = None;
        while let Some(name) = it.next() {
            if it.peek().is_none() {
                last = Some(name);
                break;
            }
            let Some(set) = self.find_in_dir(&dir.stream, name)? else {
                return Err(Error::NotFound);
            };
            if !set.is_dir() {
                return Err(Error::NotADirectory);
            }
            dir = Dir {
                stream: dir_stream_of(&set),
                entry: Some((dir.stream, set.pos)),
            };
        }
        Ok((dir, last.ok_or(Error::InvalidPath)?))
    }

    /// Refuse a name exFAT cannot store.
    pub(super) fn check_name(&self, name: &str) -> Result<(), Error<D::Error>> {
        if entry::name_is_valid(name) {
            Ok(())
        } else {
            Err(Error::InvalidName)
        }
    }

    /// Upper bound on how far a directory scan may walk, so a cyclic chain
    /// ends the scan rather than the program.
    pub(super) fn dir_limit(&self) -> u64 {
        self.geom.cluster_count as u64 * self.geom.cluster_bytes() as u64
    }

    /// Write a new entry set into a directory, and report where it landed.
    ///
    /// A run of deleted slots is reused when one is long enough — exFAT
    /// leaves those behind on every removal, and a directory that only ever
    /// grew would never give the space back.
    pub(super) fn insert_set(
        &mut self,
        dir: &Dir,
        set: &SetBuilder<'_>,
    ) -> Result<u64, Error<D::Error>> {
        let need = set.count() as u64;
        let mut pos = 0u64;
        let mut run_start = 0u64;
        let mut run = 0u64;
        let limit = self.dir_limit();
        while pos < limit {
            let Some(slot) = self.read_slot(&dir.stream, pos)? else {
                break;
            };
            match slot[0] {
                // Everything from here on is free.
                0 => {
                    let at = if run > 0 { run_start } else { pos };
                    return self.place_set(dir, at, set);
                }
                t if t & layout::ENTRY_INUSE == 0 => {
                    if run == 0 {
                        run_start = pos;
                    }
                    run += 1;
                    pos += ENTRY_SIZE as u64;
                    if run >= need {
                        self.write_set(&dir.stream, run_start, set)?;
                        return Ok(run_start);
                    }
                }
                layout::ENTRY_FILE => {
                    run = 0;
                    let secondary = slot[1] as u64;
                    pos += (1 + secondary) * ENTRY_SIZE as u64;
                }
                _ => {
                    run = 0;
                    pos += ENTRY_SIZE as u64;
                }
            }
        }
        // The chain is full to its last slot: extend it.
        self.place_set(dir, pos, set)
    }

    /// Write a set at `pos`, growing the directory's chain if it does not
    /// reach that far.
    fn place_set(
        &mut self,
        dir: &Dir,
        pos: u64,
        set: &SetBuilder<'_>,
    ) -> Result<u64, Error<D::Error>> {
        let cb = self.geom.cluster_bytes() as u64;
        let end = pos + set.bytes();
        let need_clusters = end.div_ceil(cb);
        let have = self.chain_len(&dir.stream)?;
        let mut stream = dir.stream;
        if need_clusters > have {
            if stream.contiguous {
                // A contiguous directory cannot grow without rewriting the
                // chain its run implies; exFAT's own tools never make one,
                // so this is refused rather than converted.
                return Err(Error::DirectoryFull);
            }
            let mut last = self
                .stream_cluster(&stream, (have - 1) as u32)?
                .ok_or(Error::CorruptChain)?;
            for _ in have..need_clusters {
                last = self.alloc_zeroed_cluster(Some(last))?;
            }
            stream.len = u64::MAX;
            // A directory's own entry set records the length of its chain.
            self.set_dir_length(dir, need_clusters * cb)?;
        }
        self.write_set(&stream, pos, set)?;
        Ok(pos)
    }

    /// Clusters in a stream's chain.
    pub(super) fn chain_len(&mut self, s: &Stream) -> Result<u64, Error<D::Error>> {
        if s.first_cluster < 2 {
            return Ok(0);
        }
        if s.contiguous {
            let cb = self.geom.cluster_bytes() as u64;
            return Ok(s.len.div_ceil(cb).max(1));
        }
        let mut cluster = s.first_cluster;
        let mut n = 1u64;
        while let Some(next) = self.next_cluster(cluster)? {
            cluster = next;
            n += 1;
            if n > self.geom.cluster_count as u64 {
                return Err(Error::CorruptChain);
            }
        }
        Ok(n)
    }

    /// Record a directory's new chain length in its own entry set.
    ///
    /// The root has no entry set, and neither does a directory whose handle
    /// was built without one; exFAT tolerates a DataLength that lags the
    /// chain, since the chain is what a reader follows.
    fn set_dir_length(&mut self, dir: &Dir, bytes: u64) -> Result<(), Error<D::Error>> {
        let Some((parent, pos)) = dir.entry else {
            return Ok(());
        };
        let Some(set) = self.read_set(&parent, pos)? else {
            return Ok(());
        };
        if set.first_cluster != dir.stream.first_cluster || !set.is_dir() {
            return Ok(());
        }
        self.update_set(
            &parent,
            &set,
            set.first_cluster,
            bytes,
            bytes,
            set.flags,
            true,
        )
    }
}

/// The metadata an entry set describes.
pub(super) fn meta_of(set: &EntrySet) -> Metadata {
    Metadata {
        dir: set.is_dir(),
        len: set.data_length,
        attrs: set.attrs,
        created: set.created,
        modified: set.modified,
    }
}

/// A directory listing in progress.
///
/// Lending iterator: each entry's name borrows the buffer inside, so it has
/// to be dropped before the next [`next`](Self::next).
pub struct DirIter<'v, D: SectorDriver, const SECTOR: usize> {
    vol: &'v mut Volume<D, SECTOR>,
    dir: Stream,
    pos: u64,
    units: [u16; layout::MAX_NAME_UNITS],
    name: [u8; NAME_BYTES],
    name_len: usize,
}

impl<D: SectorDriver, const SECTOR: usize> DirIter<'_, D, SECTOR> {
    /// The next entry, or `None` at the end of the directory.
    #[allow(clippy::should_implement_trait)] // lending: the item borrows self
    pub fn next(&mut self) -> Result<Option<DirEntry<'_>>, Error<D::Error>> {
        let limit = self.vol.dir_limit();
        while self.pos < limit {
            let Some(slot) = self.vol.read_slot(&self.dir, self.pos)? else {
                return Ok(None);
            };
            match slot[0] {
                0 => return Ok(None),
                layout::ENTRY_FILE => {
                    let dir = self.dir;
                    let set = self
                        .vol
                        .read_set(&dir, self.pos)?
                        .ok_or(Error::CorruptEntry)?;
                    self.pos += set.bytes();
                    let units = self.vol.copy_name(&dir, &set, &mut self.units)?;
                    // Decoded to UTF-8 in the iterator's own buffer, so the
                    // caller gets a `&str` without an allocation.
                    self.name_len = encode_utf8(&self.units[..units], &mut self.name);
                    let name = core::str::from_utf8(&self.name[..self.name_len])
                        .map_err(|_| Error::CorruptEntry)?;
                    return Ok(Some(DirEntry {
                        name,
                        meta: meta_of(&set),
                    }));
                }
                _ => self.pos += ENTRY_SIZE as u64,
            }
        }
        Ok(None)
    }
}

/// Encode UTF-16 code units as UTF-8 into `out`, returning the length.
/// Unpaired surrogates become U+FFFD, which is what a lossy decode does.
fn encode_utf8(units: &[u16], out: &mut [u8]) -> usize {
    let mut at = 0usize;
    let mut buf = [0u8; 4];
    for ch in char::decode_utf16(units.iter().copied()) {
        let c = ch.unwrap_or(char::REPLACEMENT_CHARACTER);
        let s = c.encode_utf8(&mut buf);
        if at + s.len() > out.len() {
            break;
        }
        out[at..at + s.len()].copy_from_slice(s.as_bytes());
        at += s.len();
    }
    at
}
