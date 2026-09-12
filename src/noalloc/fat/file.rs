//! File handles: read, write, seek, truncate.
//!
//! A [`File`] is a plain `Copy`-sized value that borrows nothing — it
//! records where the data is, where the cursor is, and where the directory
//! entry to update lives. The volume is passed back in on every call, so a
//! program can hold as many handles as it likes without an allocator and
//! without the borrow checker getting in the way.
//!
//! The cursor caches which cluster it is in, so reading or writing
//! forwards costs one FAT lookup per cluster boundary rather than a walk
//! from the start. Seeking backwards re-walks the chain.

use super::{EntryLoc, Error, SectorDriver, Volume};

/// FAT records a file's size in 32 bits.
pub const MAX_FILE_LEN: u32 = u32::MAX;

impl<D: SectorDriver, const S: usize> Volume<D, S> {
    /// Read whole sectors straight into the caller's buffer, going around
    /// the one-sector cache (after writing it back if it covers any of
    /// them).
    fn read_sectors_direct(&mut self, first: u32, buf: &mut [u8]) -> Result<(), Error<D::Error>> {
        let count = (buf.len() / self.bps()) as u32;
        self.invalidate(first, count)?;
        let abs = self.abs(first);
        self.dev.read_sectors(abs, buf).map_err(Error::Io)
    }

    /// Write whole sectors straight from the caller's buffer.
    fn write_sectors_direct(&mut self, first: u32, buf: &[u8]) -> Result<(), Error<D::Error>> {
        let count = (buf.len() / self.bps()) as u32;
        self.invalidate(first, count)?;
        let abs = self.abs(first);
        self.dev.write_sectors(abs, buf).map_err(Error::Io)
    }
}

/// An open file.
///
/// Every method takes the [`Volume`] the file came from; handing it a
/// different one is a logic error the driver cannot detect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct File {
    first_cluster: u32,
    len: u32,
    pos: u32,
    /// The cluster holding `cur_index`'s worth of data, when known.
    cur_cluster: u32,
    cur_index: u32,
    loc: EntryLoc,
    /// Size or first cluster changed and the entry needs rewriting.
    dirty: bool,
}

impl File {
    pub(crate) fn new(first_cluster: u32, len: u32, loc: EntryLoc) -> Self {
        Self {
            first_cluster,
            len,
            pos: 0,
            cur_cluster: first_cluster,
            cur_index: 0,
            loc,
            dirty: false,
        }
    }

    /// Size in bytes.
    pub fn len(&self) -> u32 {
        self.len
    }

    /// Whether the file is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The read/write cursor.
    pub fn pos(&self) -> u32 {
        self.pos
    }

    /// Move the cursor. Seeking past the end is allowed; writing there
    /// first fills the gap with zeros.
    pub fn seek<D: SectorDriver, const S: usize>(
        &mut self,
        _vol: &mut Volume<D, S>,
        pos: u32,
    ) -> Result<(), Error<D::Error>> {
        self.pos = pos;
        Ok(())
    }

    /// Move the cursor to the end of the file.
    pub fn seek_to_end<D: SectorDriver, const S: usize>(
        &mut self,
        _vol: &mut Volume<D, S>,
    ) -> Result<(), Error<D::Error>> {
        self.pos = self.len;
        Ok(())
    }

    /// The cluster holding byte offset `index * cluster_bytes`, walking
    /// the chain from wherever the cursor already is.
    fn cluster_at<D: SectorDriver, const S: usize>(
        &mut self,
        vol: &mut Volume<D, S>,
        index: u32,
    ) -> Result<Option<u32>, Error<D::Error>> {
        if self.first_cluster == 0 {
            return Ok(None);
        }
        let (mut cluster, mut at) = if index >= self.cur_index && self.cur_cluster != 0 {
            (self.cur_cluster, self.cur_index)
        } else {
            (self.first_cluster, 0)
        };
        // A chain cannot be longer than the volume has clusters; anything
        // more means it loops back on itself.
        if index > vol.geom.cluster_count {
            return Err(Error::CorruptChain);
        }
        while at < index {
            match vol.next_cluster(cluster)? {
                Some(next) => {
                    cluster = next;
                    at += 1;
                }
                None => return Ok(None),
            }
        }
        self.cur_cluster = cluster;
        self.cur_index = at;
        Ok(Some(cluster))
    }

    /// Like [`Self::cluster_at`], but allocates (and links) clusters up to
    /// `index` when the chain is short.
    ///
    /// `zero_new` fills freshly allocated clusters, which is what keeps a
    /// gap — or the tail of the last cluster — from exposing whatever the
    /// previous owner left there.
    fn cluster_at_or_alloc<D: SectorDriver, const S: usize>(
        &mut self,
        vol: &mut Volume<D, S>,
        index: u32,
        zero_new: bool,
    ) -> Result<u32, Error<D::Error>> {
        if self.first_cluster == 0 {
            let cluster = if zero_new {
                vol.alloc_zeroed_cluster(None)?
            } else {
                vol.alloc_cluster(None)?
            };
            self.first_cluster = cluster;
            self.cur_cluster = cluster;
            self.cur_index = 0;
            self.dirty = true;
        }
        if index > vol.geom.cluster_count {
            return Err(Error::CorruptChain);
        }
        let (mut cluster, mut at) = if index >= self.cur_index && self.cur_cluster != 0 {
            (self.cur_cluster, self.cur_index)
        } else {
            (self.first_cluster, 0)
        };
        while at < index {
            cluster = match vol.next_cluster(cluster)? {
                Some(next) => next,
                None => {
                    if zero_new {
                        vol.alloc_zeroed_cluster(Some(cluster))?
                    } else {
                        vol.alloc_cluster(Some(cluster))?
                    }
                }
            };
            at += 1;
        }
        self.cur_cluster = cluster;
        self.cur_index = at;
        Ok(cluster)
    }

    /// Read into `buf`, returning how many bytes were read: fewer than
    /// asked for only at the end of the file.
    pub fn read<D: SectorDriver, const S: usize>(
        &mut self,
        vol: &mut Volume<D, S>,
        buf: &mut [u8],
    ) -> Result<usize, Error<D::Error>> {
        let want = buf.len().min(self.len.saturating_sub(self.pos) as usize);
        if want == 0 {
            return Ok(0);
        }
        let bps = vol.bps();
        let spc = vol.geom.sectors_per_cluster;
        let cb = vol.geom.cluster_bytes();
        let mut done = 0;

        while done < want {
            let index = self.pos / cb;
            let in_cluster = self.pos % cb;
            let cluster = self
                .cluster_at(vol, index)?
                // The chain ended before the size said it would.
                .ok_or(Error::CorruptChain)?;
            let sector_in_cluster = in_cluster / bps as u32;
            let in_sector = (in_cluster % bps as u32) as usize;
            let first_sector = vol.geom.cluster_first_sector(cluster) + sector_in_cluster;
            let left = want - done;

            if in_sector == 0 && left >= bps {
                // Whole sectors: straight into the caller's buffer, as
                // many as remain in this cluster.
                let max = (spc - sector_in_cluster) as usize;
                let n = (left / bps).min(max);
                let bytes = n * bps;
                vol.read_sectors_direct(first_sector, &mut buf[done..done + bytes])?;
                done += bytes;
                self.pos += bytes as u32;
            } else {
                let n = left.min(bps - in_sector);
                let sector = vol.sector(first_sector)?;
                buf[done..done + n].copy_from_slice(&sector[in_sector..in_sector + n]);
                done += n;
                self.pos += n as u32;
            }
        }
        Ok(done)
    }

    /// Read exactly `buf.len()` bytes, or fail with
    /// [`Error::InvalidOffset`] at the end of the file.
    pub fn read_exact<D: SectorDriver, const S: usize>(
        &mut self,
        vol: &mut Volume<D, S>,
        buf: &mut [u8],
    ) -> Result<(), Error<D::Error>> {
        let n = self.read(vol, buf)?;
        if n == buf.len() {
            Ok(())
        } else {
            Err(Error::InvalidOffset)
        }
    }

    /// Write `buf` at the cursor, extending the file as needed.
    pub fn write<D: SectorDriver, const S: usize>(
        &mut self,
        vol: &mut Volume<D, S>,
        buf: &[u8],
    ) -> Result<usize, Error<D::Error>> {
        if buf.is_empty() {
            return Ok(0);
        }
        // Writing past the end leaves a gap that must read as zeros.
        if self.pos > self.len {
            let gap_to = self.pos;
            self.pos = self.len;
            self.zero_extend(vol, gap_to)?;
            self.pos = gap_to;
        }
        let end = self
            .pos
            .checked_add(buf.len() as u32)
            .ok_or(Error::FileTooLarge)?;

        let bps = vol.bps();
        let spc = vol.geom.sectors_per_cluster;
        let cb = vol.geom.cluster_bytes();
        let mut done = 0usize;

        while done < buf.len() {
            let index = self.pos / cb;
            let in_cluster = self.pos % cb;
            let left = buf.len() - done;
            // A cluster the write covers end to end needs no zeroing.
            let covers_cluster = in_cluster == 0 && left >= cb as usize;
            let cluster = self.cluster_at_or_alloc(vol, index, !covers_cluster)?;
            let sector_in_cluster = in_cluster / bps as u32;
            let in_sector = (in_cluster % bps as u32) as usize;
            let first_sector = vol.geom.cluster_first_sector(cluster) + sector_in_cluster;

            if in_sector == 0 && left >= bps {
                let max = (spc - sector_in_cluster) as usize;
                let n = (left / bps).min(max);
                let bytes = n * bps;
                vol.write_sectors_direct(first_sector, &buf[done..done + bytes])?;
                done += bytes;
                self.pos += bytes as u32;
            } else {
                let n = left.min(bps - in_sector);
                let sector = vol.sector_mut(first_sector)?;
                sector[in_sector..in_sector + n].copy_from_slice(&buf[done..done + n]);
                done += n;
                self.pos += n as u32;
            }
        }

        if end > self.len {
            self.len = end;
        }
        self.dirty = true;
        Ok(done)
    }

    /// Write all of `buf`.
    pub fn write_all<D: SectorDriver, const S: usize>(
        &mut self,
        vol: &mut Volume<D, S>,
        buf: &[u8],
    ) -> Result<(), Error<D::Error>> {
        let n = self.write(vol, buf)?;
        if n == buf.len() {
            Ok(())
        } else {
            Err(Error::NoSpace)
        }
    }

    /// Grow the file to `new_len` with zeros, from the current end.
    fn zero_extend<D: SectorDriver, const S: usize>(
        &mut self,
        vol: &mut Volume<D, S>,
        new_len: u32,
    ) -> Result<(), Error<D::Error>> {
        let cb = vol.geom.cluster_bytes();
        let bps = vol.bps();
        let mut at = self.len;
        while at < new_len {
            let index = at / cb;
            let in_cluster = at % cb;
            let left = new_len - at;
            let covers = in_cluster == 0 && left >= cb;
            // A cluster allocated here is zeroed at allocation; only the
            // tail of an already-allocated one needs clearing.
            let existed = self.cluster_at(vol, index)?.is_some();
            let cluster = self.cluster_at_or_alloc(vol, index, !covers)?;
            let step = left.min(cb - in_cluster);
            if existed {
                let mut off = in_cluster;
                let mut remaining = step;
                while remaining > 0 {
                    let sector_in_cluster = off / bps as u32;
                    let in_sector = (off % bps as u32) as usize;
                    let n = (remaining as usize).min(bps - in_sector);
                    let first = vol.geom.cluster_first_sector(cluster) + sector_in_cluster;
                    let sector = vol.sector_mut(first)?;
                    sector[in_sector..in_sector + n].fill(0);
                    off += n as u32;
                    remaining -= n as u32;
                }
            }
            at += step;
        }
        self.len = self.len.max(new_len);
        self.dirty = true;
        Ok(())
    }

    /// Resize the file. Growing fills with zeros; shrinking frees the
    /// clusters that fall off the end.
    pub fn set_len<D: SectorDriver, const S: usize>(
        &mut self,
        vol: &mut Volume<D, S>,
        new_len: u32,
    ) -> Result<(), Error<D::Error>> {
        if new_len > self.len {
            let keep = self.pos;
            self.zero_extend(vol, new_len)?;
            self.pos = keep;
            return Ok(());
        }
        if new_len == self.len {
            return Ok(());
        }
        let cb = vol.geom.cluster_bytes();
        if new_len == 0 {
            if self.first_cluster != 0 {
                vol.free_chain(self.first_cluster)?;
            }
            self.first_cluster = 0;
            self.cur_cluster = 0;
            self.cur_index = 0;
        } else {
            // The last cluster the file still needs, counted from zero.
            let last_index = (new_len - 1) / cb;
            if let Some(cluster) = self.cluster_at(vol, last_index)? {
                vol.truncate_chain(cluster)?;
            }
        }
        self.len = new_len;
        self.pos = self.pos.min(new_len);
        self.cur_cluster = self.first_cluster;
        self.cur_index = 0;
        self.dirty = true;
        Ok(())
    }

    /// Write the file's size and first cluster back into its directory
    /// entry, then flush the volume's cached sector and the device.
    pub fn flush<D: SectorDriver, const S: usize>(
        &mut self,
        vol: &mut Volume<D, S>,
    ) -> Result<(), Error<D::Error>> {
        if self.dirty {
            vol.update_entry(self.loc, self.first_cluster, self.len)?;
            self.dirty = false;
        }
        vol.flush()
    }

    /// The file's first cluster, or 0 when it has never held data.
    pub fn first_cluster(&self) -> u32 {
        self.first_cluster
    }
}
