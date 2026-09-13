//! File handles: read, write, seek, truncate.
//!
//! A [`File`] is a plain `Copy`-sized value that borrows nothing — it
//! records where its directory entry is, where its bytes are, and where the
//! cursor is. The volume is passed back in on every call, so a program can
//! hold as many handles as it likes without an allocator and without the
//! borrow checker getting in the way.
//!
//! Writes go through immediately: there is no dirty region to hold them in.
//! A write rebuilds the skip-list from the block containing the first
//! changed byte onwards, which is not an optimisation but the shape of the
//! format — every CTZ block points *backwards*, so blocks before the change
//! keep their contents and their pointers, while everything after has to be
//! rewritten anyway. That is exactly the copy-on-write littlefs performs
//! itself. A file small enough to live inline in its directory's metadata is
//! rewritten as part of the commit instead, touching no data block at all.

use super::super::index;
use super::super::tag;
use super::dir::Resolved;
use super::mdir::{self, Data, Struct, StructOut};
use super::{Contents, Error, Fill, FlashDriver, Volume};

/// An open file.
///
/// Every method takes the [`Volume`] the file came from; handing it a
/// different one is a logic error the driver cannot detect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct File {
    /// The metadata pair holding the file's entry, live block first.
    pair: [u32; 2],
    /// Its id in that pair.
    id: u16,
    /// Head block of the skip-list, when the file has one.
    head: u32,
    /// Whether the contents live inline in the metadata pair.
    inline: bool,
    /// Size in bytes.
    size: u32,
    /// The read/write cursor.
    pos: u32,
}

impl File {
    /// Size in bytes.
    pub fn len(&self) -> u32 {
        self.size
    }

    /// Whether the file is empty.
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// The read/write cursor.
    pub fn pos(&self) -> u32 {
        self.pos
    }

    /// Whether the contents currently live inline in the directory's
    /// metadata rather than in a skip-list of their own.
    pub fn is_inline(&self) -> bool {
        self.inline
    }

    /// Move the cursor. Seeking past the end is allowed; writing there fills
    /// the gap with zeros.
    pub fn seek(&mut self, pos: u32) {
        self.pos = pos;
    }

    /// Move the cursor to the end of the file.
    pub fn seek_to_end<D: FlashDriver, const B: usize, const P: usize>(
        &mut self,
        _vol: &mut Volume<D, B, P>,
    ) {
        self.pos = self.size;
    }

    /// Where the file's committed bytes are right now.
    ///
    /// Resolved from the entry on every call: inline contents move whenever
    /// their metadata pair is committed.
    fn contents<D: FlashDriver, const B: usize, const P: usize>(
        &self,
        vol: &mut Volume<D, B, P>,
    ) -> Result<Contents, Error<D::Error>> {
        if !self.inline {
            return Ok(if self.size == 0 {
                Contents::Empty
            } else {
                Contents::Ctz {
                    head: self.head,
                    size: self.size,
                }
            });
        }
        let m = vol.fetch(self.pair)?;
        let bs = vol.bs();
        match mdir::struct_of(&vol.buf[..bs], &m, self.id) {
            Some(Struct::Inline { off, len }) => Ok(Contents::Inline {
                block: m.pair[0],
                off,
                len,
            }),
            Some(Struct::Ctz { head, size }) => Ok(Contents::Ctz { head, size }),
            _ => Ok(Contents::Empty),
        }
    }

    /// Read into `buf`, returning how many bytes were read: fewer than asked
    /// for only at the end of the file.
    pub fn read<D: FlashDriver, const B: usize, const P: usize>(
        &mut self,
        vol: &mut Volume<D, B, P>,
        buf: &mut [u8],
    ) -> Result<usize, Error<D::Error>> {
        let want = buf.len().min(self.size.saturating_sub(self.pos) as usize);
        if want == 0 {
            return Ok(0);
        }
        let src = self.contents(vol)?;
        let mut done = 0usize;
        while done < want {
            let n = vol.read_contents(&src, self.pos, &mut buf[done..want])?;
            if n == 0 {
                break;
            }
            done += n;
            self.pos += n as u32;
        }
        Ok(done)
    }

    /// Read exactly `buf.len()` bytes, or fail with [`Error::InvalidOffset`]
    /// at the end of the file.
    pub fn read_exact<D: FlashDriver, const B: usize, const P: usize>(
        &mut self,
        vol: &mut Volume<D, B, P>,
        buf: &mut [u8],
    ) -> Result<(), Error<D::Error>> {
        if self.read(vol, buf)? == buf.len() {
            Ok(())
        } else {
            Err(Error::InvalidOffset)
        }
    }

    /// Write `buf` at the cursor, extending the file as needed.
    ///
    /// All of `buf` is written or an error is returned; the count comes back
    /// for symmetry with [`read`](Self::read).
    pub fn write<D: FlashDriver, const B: usize, const P: usize>(
        &mut self,
        vol: &mut Volume<D, B, P>,
        buf: &[u8],
    ) -> Result<usize, Error<D::Error>> {
        if buf.is_empty() {
            return Ok(0);
        }
        let len = u32::try_from(buf.len()).map_err(|_| Error::FileTooLarge)?;
        let end = self.pos.checked_add(len).ok_or(Error::FileTooLarge)?;
        let new_size = self.size.max(end);
        self.apply(vol, self.pos, buf, new_size)?;
        self.pos = end;
        Ok(buf.len())
    }

    /// Write all of `buf`.
    pub fn write_all<D: FlashDriver, const B: usize, const P: usize>(
        &mut self,
        vol: &mut Volume<D, B, P>,
        buf: &[u8],
    ) -> Result<(), Error<D::Error>> {
        self.write(vol, buf)?;
        Ok(())
    }

    /// Resize the file. Growing fills with zeros; shrinking frees the blocks
    /// that fall off the end.
    pub fn set_len<D: FlashDriver, const B: usize, const P: usize>(
        &mut self,
        vol: &mut Volume<D, B, P>,
        new_len: u32,
    ) -> Result<(), Error<D::Error>> {
        if new_len == self.size {
            return Ok(());
        }
        if new_len > self.size {
            // The gap reads as zeros, which is what a write past the end of
            // the file already produces.
            let at = self.size;
            self.apply(vol, at, &[], new_len)?;
            self.pos = self.pos.min(new_len);
            return Ok(());
        }

        if new_len > vol.geom.file_max {
            return Err(Error::FileTooLarge);
        }
        let src = self.contents(vol)?;
        match src {
            Contents::Ctz { head, size } if new_len > 0 => {
                // Every CTZ block points backwards, so the block holding the
                // last byte kept *is* the new head: the blocks below it are
                // still correct and still correctly pointed at.
                let (new_head, _) = vol.ctz_find(head, size, new_len - 1)?;
                let (keep, _) = index::index_of(vol.geom.block_size, new_len - 1);
                vol.release_ctz(head, size, keep + 1)?;
                let m = vol.fetch(self.pair)?;
                let out = vol.commit(
                    &m,
                    super::Edit::SetStruct {
                        id: self.id,
                        data: StructOut::Ctz {
                            head: new_head,
                            size: new_len,
                        },
                    },
                )?;
                self.head = new_head;
                self.follow(&out)?;
            }
            Contents::Ctz { head, size } => {
                // Truncated to nothing: the file goes back to being an empty
                // inline one, as a freshly created file is.
                vol.release_ctz(head, size, 0)?;
                let m = vol.fetch(self.pair)?;
                let out = vol.commit(
                    &m,
                    super::Edit::SetStruct {
                        id: self.id,
                        data: StructOut::Inline(Data::Bytes(&[])),
                    },
                )?;
                self.inline = true;
                self.head = 0;
                self.follow(&out)?;
            }
            Contents::Inline { off, len, .. } => {
                let m = vol.fetch(self.pair)?;
                let out = vol.commit(
                    &m,
                    super::Edit::SetStruct {
                        id: self.id,
                        data: StructOut::Inline(Data::Patch {
                            old: (off, len),
                            at: 0,
                            new: &[],
                            len: new_len,
                        }),
                    },
                )?;
                self.follow(&out)?;
            }
            Contents::Empty => {}
        }
        self.size = new_len;
        self.pos = self.pos.min(new_len);
        Ok(())
    }

    /// Flush the driver. Filesystem state is written through as it changes,
    /// so there is nothing of the file's left to write.
    pub fn sync<D: FlashDriver, const B: usize, const P: usize>(
        &mut self,
        vol: &mut Volume<D, B, P>,
    ) -> Result<(), Error<D::Error>> {
        vol.sync()
    }

    /// Apply one change to the file's bytes: `data` lands at `at`, and the
    /// file ends up `new_size` bytes long.
    fn apply<D: FlashDriver, const B: usize, const P: usize>(
        &mut self,
        vol: &mut Volume<D, B, P>,
        at: u32,
        data: &[u8],
        new_size: u32,
    ) -> Result<(), Error<D::Error>> {
        if new_size > vol.geom.file_max {
            return Err(Error::FileTooLarge);
        }
        let src = self.contents(vol)?;

        // Small enough to stay (or become) part of the metadata block: the
        // whole change is one commit, with the new bytes woven into the
        // inline data as it is copied forward.
        if new_size <= vol.geom.inline_max
            && matches!(src, Contents::Inline { .. } | Contents::Empty)
        {
            let old = match src {
                Contents::Inline { off, len, .. } => (off, len),
                _ => (0, 0),
            };
            let m = vol.fetch(self.pair)?;
            let out = vol.commit(
                &m,
                super::Edit::SetStruct {
                    id: self.id,
                    data: StructOut::Inline(Data::Patch {
                        old,
                        at,
                        new: data,
                        len: new_size,
                    }),
                },
            )?;
            self.inline = true;
            self.head = 0;
            self.size = new_size;
            self.follow(&out)?;
            return Ok(());
        }

        // Out of line. Blocks before the first changed byte survive
        // untouched, so the rewrite starts at the block that byte is in.
        let bs = vol.geom.block_size;
        let old_size = src.len();
        let (from_index, prev) = match src {
            Contents::Ctz { head, size } if size > 0 => {
                let touch = at.min(old_size);
                let (k, _) = index::index_of(bs, touch);
                let prev = if k == 0 {
                    None
                } else {
                    let last_byte = index::block_start(bs, k) - 1;
                    Some(vol.ctz_find(head, size, last_byte)?.0)
                };
                (k, prev)
            }
            // An inline file being outlined is written from scratch.
            _ => (0, None),
        };
        let base = index::block_start(bs, from_index);
        let fill = Fill {
            old: src,
            at,
            new: data,
        };
        let head = vol
            .write_ctz(from_index, prev, base, &fill, new_size - base)?
            .ok_or(Error::Corrupt("nothing written to the file"))?;

        // Release the blocks the rewrite replaced; earlier ones are still
        // part of the file.
        if let Contents::Ctz {
            head: old_head,
            size,
        } = src
        {
            vol.release_ctz(old_head, size, from_index)?;
        }

        let m = vol.fetch(self.pair)?;
        let out = vol.commit(
            &m,
            super::Edit::SetStruct {
                id: self.id,
                data: StructOut::Ctz {
                    head,
                    size: new_size,
                },
            },
        )?;
        self.inline = false;
        self.head = head;
        self.size = new_size;
        self.follow(&out)?;
        Ok(())
    }

    /// Follow the entry through a commit, which swaps its pair's halves and
    /// may have moved it to a fresh pair entirely.
    fn follow<E>(&mut self, out: &super::CommitOut) -> Result<(), Error<E>> {
        let placed = out.placed.ok_or(Error::Corrupt("file entry vanished"))?;
        self.pair = placed.pair;
        self.id = placed.id;
        Ok(())
    }
}

impl<D: FlashDriver, const BLOCK: usize, const PROG: usize> Volume<D, BLOCK, PROG> {
    /// Open an existing file.
    pub fn open_file(&mut self, path: &str) -> Result<File, Error<D::Error>> {
        let Resolved::Entry { pair, id, kind } = self.resolve(path)? else {
            return Err(Error::IsADirectory);
        };
        if kind == tag::TYPE_DIR as u8 {
            return Err(Error::IsADirectory);
        }
        self.file_at(pair, id)
    }

    /// Create a file, which must not already exist. Its parent must.
    pub fn create_file(&mut self, path: &str) -> Result<File, Error<D::Error>> {
        let (head, name) = self.parent_of(path)?;
        self.check_name(name)?;
        if self.find_in_dir(head, name.as_bytes())?.is_some() {
            return Err(Error::AlreadyExists);
        }
        // A fresh file is an empty inline one, exactly as littlefs writes it.
        let placed = self.insert_entry(
            head,
            tag::TYPE_REG as u8,
            name.as_bytes(),
            StructOut::Inline(Data::Bytes(&[])),
        )?;
        Ok(File {
            pair: placed.pair,
            id: placed.id,
            head: 0,
            inline: true,
            size: 0,
            pos: 0,
        })
    }

    /// Open a file, creating it if it is not there.
    pub fn open_or_create_file(&mut self, path: &str) -> Result<File, Error<D::Error>> {
        match self.try_resolve(path)? {
            Some(Resolved::Entry { pair, id, kind }) => {
                if kind == tag::TYPE_DIR as u8 {
                    return Err(Error::IsADirectory);
                }
                self.file_at(pair, id)
            }
            Some(Resolved::Root) => Err(Error::IsADirectory),
            None => self.create_file(path),
        }
    }

    /// A handle over the entry at `id` of `pair`.
    fn file_at(&mut self, pair: [u32; 2], id: u16) -> Result<File, Error<D::Error>> {
        let m = self.fetch(pair)?;
        let bs = self.bs();
        let (inline, head, size) = match mdir::struct_of(&self.buf[..bs], &m, id) {
            Some(Struct::Inline { len, .. }) => (true, 0, len),
            Some(Struct::Ctz { head, size }) => (false, head, size),
            Some(Struct::Dir(_)) => return Err(Error::IsADirectory),
            None => (true, 0, 0),
        };
        Ok(File {
            pair: m.pair,
            id,
            head,
            inline,
            size,
            pos: 0,
        })
    }
}
