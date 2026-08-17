//! File handles — streaming reads, and in-place writes through real
//! littlefs commits.
//!
//! Reads walk the CTZ skip-list (or copy out of the inline data held in the
//! directory's metadata). Writes are gathered into one contiguous dirty
//! region and applied when the handle is synced, dropped, or the caller
//! seeks somewhere the region can't absorb.
//!
//! Applying a write rebuilds the skip-list from the block containing the
//! first changed byte onwards. That is not an optimisation but the shape of
//! the format: every block points *backwards*, so blocks before the change
//! keep their contents and their pointers, while everything after has to be
//! rewritten anyway — which is exactly the copy-on-write littlefs performs
//! itself.

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::block::BlockDevice;
use crate::fs::{FileHandle, FileMeta, FileReadHandle, OpenFlags};
use crate::{Error, Result};

use super::mdir::{Geom, Struct};
use super::{LittleFs, Resolved, ctz, entry_size, tag};

/// Where a file's bytes currently live.
#[derive(Debug, Clone)]
pub enum Source {
    /// Small file, stored in its directory's metadata block.
    Inline(Vec<u8>),
    /// Regular file, stored as a CTZ skip-list.
    Ctz { head: u32, size: u32 },
}

impl Source {
    fn len(&self) -> u64 {
        match self {
            Source::Inline(d) => d.len() as u64,
            Source::Ctz { size, .. } => *size as u64,
        }
    }
}

/// Read up to `buf.len()` bytes of `src` at file offset `pos`. Returns 0 at
/// end of file; a short read means the next call continues from the next
/// block.
fn read_source(
    dev: &mut dyn BlockDevice,
    geom: &Geom,
    src: &Source,
    pos: u64,
    buf: &mut [u8],
) -> Result<usize> {
    if pos >= src.len() || buf.is_empty() {
        return Ok(0);
    }
    match src {
        Source::Inline(d) => {
            let start = pos as usize;
            let n = buf.len().min(d.len() - start);
            buf[..n].copy_from_slice(&d[start..start + n]);
            Ok(n)
        }
        Source::Ctz { head, size } => {
            let (block, off) = ctz::find(dev, geom, *head, *size, pos as u32)?;
            // A read stops at the end of the block it started in — the next
            // call resumes in the next one.
            let in_block = (geom.block_size - off) as u64;
            let n = (buf.len() as u64).min(in_block).min(*size as u64 - pos) as usize;
            dev.read_at(geom.offset(block) + off as u64, &mut buf[..n])?;
            Ok(n)
        }
    }
}

/// Read-only handle over a file.
pub struct FileReader<'a> {
    dev: &'a mut dyn BlockDevice,
    geom: Geom,
    src: Source,
    pos: u64,
}

impl<'a> FileReader<'a> {
    pub(super) fn new(dev: &'a mut dyn BlockDevice, geom: Geom, src: Source) -> Self {
        Self {
            dev,
            geom,
            src,
            pos: 0,
        }
    }
}

impl Read for FileReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = read_source(self.dev, &self.geom, &self.src, self.pos, buf)
            .map_err(|e| io::Error::other(e.to_string()))?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for FileReader<'_> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.pos = resolve_seek(self.pos, self.src.len(), pos)?;
        Ok(self.pos)
    }
}

impl FileReadHandle for FileReader<'_> {
    fn len(&self) -> u64 {
        self.src.len()
    }
}

fn resolve_seek(cur: u64, len: u64, pos: SeekFrom) -> io::Result<u64> {
    let new = match pos {
        SeekFrom::Start(n) => n as i128,
        SeekFrom::End(n) => len as i128 + n as i128,
        SeekFrom::Current(n) => cur as i128 + n as i128,
    };
    if new < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "littlefs: seek before start of file",
        ));
    }
    Ok(new as u64)
}

/// Pending contiguous write.
struct Dirty {
    start: u64,
    buf: Vec<u8>,
}

/// Read + write handle over a file.
pub struct FileWriter<'a> {
    fs: &'a mut LittleFs,
    dev: &'a mut dyn BlockDevice,
    /// The entry is re-resolved by path on every apply: a commit may split
    /// a metadata pair and move the entry to a different one.
    path: PathBuf,
    size: u64,
    pos: u64,
    dirty: Option<Dirty>,
    /// Committed contents, cached between reads and dropped on every write.
    src: Option<Source>,
}

impl FileWriter<'_> {
    /// The file's committed contents, resolved on demand.
    fn source(&mut self) -> Result<Source> {
        if let Some(s) = &self.src {
            return Ok(s.clone());
        }
        let s = self.fs.file_source(self.dev, &self.path)?;
        self.src = Some(s.clone());
        Ok(s)
    }

    /// Write the pending region into the volume and commit the entry.
    fn apply(&mut self) -> Result<()> {
        let Some(d) = self.dirty.take() else {
            return Ok(());
        };
        self.src = None;
        let end = d.start + d.buf.len() as u64;
        let old = self.fs.file_source(self.dev, &self.path)?;
        let old_size = old.len();
        let new_size = old_size.max(end);
        if new_size > self.fs.file_max as u64 {
            return Err(Error::InvalidArgument(format!(
                "littlefs: {new_size} bytes exceeds the volume's {}-byte file limit",
                self.fs.file_max
            )));
        }

        let data = if new_size <= self.fs.inline_max as u64 && matches!(old, Source::Inline(_)) {
            // Still small enough to live in the metadata block.
            let Source::Inline(mut v) = old else {
                unreachable!("checked above")
            };
            v.resize(new_size as usize, 0);
            let s = d.start as usize;
            v[s..s + d.buf.len()].copy_from_slice(&d.buf);
            Struct::Inline(v)
        } else {
            self.rebuild(&old, old_size, new_size, d.start, &d.buf)?
        };

        self.store(data)?;
        self.size = new_size;
        Ok(())
    }

    /// Rewrite the skip-list from the first changed block onwards.
    fn rebuild(
        &mut self,
        old: &Source,
        old_size: u64,
        new_size: u64,
        dirty_start: u64,
        dirty: &[u8],
    ) -> Result<Struct> {
        let geom = self.fs.geom;
        let old_ctz = match old {
            Source::Ctz { head, size } => Some((*head, *size)),
            Source::Inline(_) => None,
        };

        // Blocks before the first changed byte survive untouched — their
        // contents and their back-pointers are still correct.
        let (from_index, prev) = match old_ctz {
            Some((head, size)) => {
                let touch = dirty_start.min(old_size) as u32;
                let (k, _) = ctz::index_of(&geom, touch);
                let prev = if k == 0 {
                    None
                } else {
                    let last_byte = ctz::block_start(&geom, k) - 1;
                    Some(ctz::find(self.dev, &geom, head, size, last_byte)?.0)
                };
                (k, prev)
            }
            // An inline file being outlined is written from scratch.
            None => (0, None),
        };
        let base = ctz::block_start(&geom, from_index) as u64;

        let mut src = RebuildSource {
            geom,
            old: old.clone(),
            old_size,
            dirty_start,
            dirty,
        };
        let head = {
            let alloc = self.fs.allocator(self.dev)?;
            ctz::write_blocks(
                self.dev,
                &geom,
                alloc,
                from_index,
                prev,
                base,
                &mut src,
                new_size - base,
            )?
        }
        .ok_or_else(|| Error::InvalidArgument("littlefs: nothing written to the file".into()))?;

        // Release the blocks the rewrite replaced (everything from
        // `from_index` on); earlier blocks are still part of the file.
        if let Some((old_head, size)) = old_ctz {
            self.free_from(old_head, size, from_index)?;
        }

        Ok(Struct::Ctz {
            head,
            size: new_size as u32,
        })
    }

    /// Free the blocks of `head`/`size` whose index is at least `from`.
    fn free_from(&mut self, head: u32, size: u32, from: u32) -> Result<()> {
        let geom = self.fs.geom;
        let (mut index, _) = ctz::index_of(&geom, size - 1);
        let mut doomed = Vec::new();
        // `traverse` walks the list head-first, i.e. from the highest index
        // down, one index per callback.
        ctz::traverse(self.dev, &geom, head, size, &mut |b| {
            if index >= from {
                doomed.push(b);
            }
            index = index.saturating_sub(1);
        })?;
        let alloc = self.fs.allocator(self.dev)?;
        for b in doomed {
            alloc.free(b);
        }
        Ok(())
    }

    /// Point the file's entry at `data` and commit its metadata pair.
    fn store(&mut self, data: Struct) -> Result<()> {
        let Resolved::Entry { mut mdir, id } = self.fs.resolve(self.dev, &self.path)? else {
            return Err(Error::InvalidArgument(
                "littlefs: file entry vanished".into(),
            ));
        };
        mdir.entries[id].data = Some(data);
        self.fs.commit(self.dev, &mut mdir)
    }
}

/// Feeds a rebuild: the caller's new bytes where they apply, the old
/// contents elsewhere, and zeroes for any gap a write past the end left
/// behind.
struct RebuildSource<'d> {
    geom: Geom,
    old: Source,
    old_size: u64,
    dirty_start: u64,
    dirty: &'d [u8],
}

impl ctz::ChunkSource for RebuildSource<'_> {
    fn fill(&mut self, dev: &mut dyn BlockDevice, off: u64, buf: &mut [u8]) -> Result<()> {
        let dirty_end = self.dirty_start + self.dirty.len() as u64;
        let mut done = 0usize;
        while done < buf.len() {
            let o = off + done as u64;
            let want = buf.len() - done;
            if o >= self.dirty_start && o < dirty_end {
                let s = (o - self.dirty_start) as usize;
                let n = want.min(self.dirty.len() - s);
                buf[done..done + n].copy_from_slice(&self.dirty[s..s + n]);
                done += n;
            } else if o < self.old_size && (o >= dirty_end || o < self.dirty_start) {
                // Old contents, bounded so we never run past the start of
                // the new bytes.
                let limit = if o < self.dirty_start {
                    self.dirty_start.min(self.old_size) - o
                } else {
                    self.old_size - o
                };
                let cap = want.min(limit as usize);
                let n = read_source(dev, &self.geom, &self.old, o, &mut buf[done..done + cap])?;
                if n == 0 {
                    return Err(Error::InvalidImage(
                        "littlefs: short read while rewriting a file".into(),
                    ));
                }
                done += n;
            } else {
                // A gap left by a write past the end of the file.
                let limit = if o < self.dirty_start {
                    (self.dirty_start - o) as usize
                } else {
                    want
                };
                let n = want.min(limit);
                buf[done..done + n].fill(0);
                done += n;
            }
        }
        Ok(())
    }
}

impl Read for FileWriter<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.apply().map_err(|e| io::Error::other(e.to_string()))?;
        let src = self.source().map_err(|e| io::Error::other(e.to_string()))?;
        let n = read_source(self.dev, &self.fs.geom, &src, self.pos, buf)
            .map_err(|e| io::Error::other(e.to_string()))?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Write for FileWriter<'_> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        self.src = None;
        let absorbs = match &self.dirty {
            Some(d) => self.pos >= d.start && self.pos <= d.start + d.buf.len() as u64,
            None => false,
        };
        if !absorbs {
            // The write doesn't touch the pending region — land that one
            // first so the two don't have to be tracked separately.
            self.apply().map_err(|e| io::Error::other(e.to_string()))?;
            self.dirty = Some(Dirty {
                start: self.pos,
                buf: data.to_vec(),
            });
        } else if let Some(d) = &mut self.dirty {
            let off = (self.pos - d.start) as usize;
            if off + data.len() > d.buf.len() {
                d.buf.resize(off + data.len(), 0);
            }
            d.buf[off..off + data.len()].copy_from_slice(data);
        }
        self.pos += data.len() as u64;
        self.size = self.size.max(self.pos);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.apply().map_err(|e| io::Error::other(e.to_string()))
    }
}

impl Seek for FileWriter<'_> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.pos = resolve_seek(self.pos, self.size, pos)?;
        Ok(self.pos)
    }
}

impl FileHandle for FileWriter<'_> {
    fn len(&self) -> u64 {
        self.size
    }

    fn set_len(&mut self, new_len: u64) -> Result<()> {
        self.apply()?;
        if new_len == self.size {
            return Ok(());
        }
        if new_len > self.size {
            // Grow by writing the zero fill through the normal path.
            let gap = new_len - self.size;
            self.dirty = Some(Dirty {
                start: self.size,
                buf: vec![0u8; gap as usize],
            });
            self.pos = new_len;
            return self.apply();
        }

        let old = self.source()?;
        self.src = None;
        let data = match &old {
            Source::Inline(v) => Struct::Inline(v[..new_len as usize].to_vec()),
            Source::Ctz { head, size } => {
                if new_len <= self.fs.inline_max as u64 {
                    // littlefs reverts a shrunken file to inline storage.
                    let mut v = vec![0u8; new_len as usize];
                    let mut done = 0usize;
                    while done < v.len() {
                        let n = read_source(
                            self.dev,
                            &self.fs.geom,
                            &old,
                            done as u64,
                            &mut v[done..],
                        )?;
                        if n == 0 {
                            break;
                        }
                        done += n;
                    }
                    self.free_from(*head, *size, 0)?;
                    Struct::Inline(v)
                } else {
                    let geom = self.fs.geom;
                    // The block holding the last surviving byte becomes the
                    // new head; everything past it is released.
                    let (new_head, _) =
                        ctz::find(self.dev, &geom, *head, *size, new_len as u32 - 1)?;
                    let (keep, _) = ctz::index_of(&geom, new_len as u32 - 1);
                    self.free_from(*head, *size, keep + 1)?;
                    Struct::Ctz {
                        head: new_head,
                        size: new_len as u32,
                    }
                }
            }
        };
        self.store(data)?;
        self.size = new_len;
        self.pos = self.pos.min(new_len);
        Ok(())
    }

    fn sync(&mut self) -> Result<()> {
        self.apply()
    }
}

impl Drop for FileWriter<'_> {
    fn drop(&mut self) {
        if self.dirty.is_some()
            && let Err(e) = self.apply()
        {
            log::warn!("littlefs: dropping a file handle lost pending writes: {e}");
        }
    }
}

/// Open a file for reading and writing, creating it when asked to.
pub(super) fn open_rw<'a>(
    fs: &'a mut LittleFs,
    dev: &'a mut dyn BlockDevice,
    path: &Path,
    flags: OpenFlags,
    meta: Option<FileMeta>,
) -> Result<Box<dyn FileHandle + 'a>> {
    let size = match fs.try_resolve(dev, path)? {
        Some(Resolved::Entry { mdir, id }) => {
            let e = &mdir.entries[id];
            if e.kind != tag::TYPE_REG as u8 {
                return Err(Error::InvalidArgument(format!(
                    "littlefs: {:?} is not a regular file",
                    path.display()
                )));
            }
            entry_size(e)
        }
        Some(Resolved::Root) => {
            return Err(Error::InvalidArgument(
                "littlefs: the root is not a file".into(),
            ));
        }
        None => {
            if !flags.create {
                return Err(Error::InvalidArgument(format!(
                    "littlefs: no such file {:?}",
                    path.display()
                )));
            }
            if meta.is_none() {
                return Err(Error::InvalidArgument(
                    "littlefs: open_file_rw with create needs file metadata".into(),
                ));
            }
            fs.write_file(dev, path, &mut io::empty(), 0)?;
            0
        }
    };

    let mut h = FileWriter {
        fs,
        dev,
        path: path.to_path_buf(),
        size,
        pos: 0,
        dirty: None,
        src: None,
    };
    if flags.truncate {
        h.set_len(0)?;
    }
    if flags.append {
        h.pos = h.size;
    }
    Ok(Box::new(h))
}

/// Resize the file at `path`, the path-flavoured [`FileHandle::set_len`].
pub(super) fn truncate(
    fs: &mut LittleFs,
    dev: &mut dyn BlockDevice,
    path: &Path,
    new_size: u64,
) -> Result<()> {
    let mut h = open_rw(fs, dev, path, OpenFlags::default(), None)?;
    h.set_len(new_size)?;
    h.sync()
}
