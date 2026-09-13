//! File handles: read, write, seek, truncate.
//!
//! A [`File`] is a plain `Copy`-sized value that borrows nothing — it
//! records the stream its bytes live in, where its directory entry set is,
//! and where the cursor is. The volume is passed back in on every call, so a
//! program can hold as many handles as it likes without an allocator and
//! without the borrow checker getting in the way.
//!
//! Two exFAT rules shape this code:
//!
//! * **ValidDataLength** is how much of `DataLength` has actually been
//!   written. Bytes between the two read as zero and are never fetched from
//!   the card — which is what makes [`File::set_len`] cheap when it grows a
//!   file. Any write that leaves a gap closes it by zeroing, because the
//!   rule only holds for a *trailing* region.
//! * **NoFatChain** means a stream's clusters are contiguous and its FAT
//!   entries are not valid. Such a file is read straight out of its run;
//!   growing one writes the chain the run implies and clears the flag,
//!   after which it is an ordinary chained file.

use super::super::layout;
use super::dir::Found;
use super::entry::{self, EntrySet};
use super::{Error, SectorDriver, Stream, Volume};

/// An open file.
///
/// Every method takes the [`Volume`] the file came from; handing it a
/// different one is a logic error the driver cannot detect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct File {
    /// The directory holding the file's entry set, and where in it.
    parent: Stream,
    set_pos: u64,
    /// First cluster of the data stream, 0 when it owns none.
    first_cluster: u32,
    /// DataLength.
    len: u64,
    /// ValidDataLength — everything past this reads as zero.
    valid: u64,
    /// Whether the clusters are a contiguous run with no valid FAT entries.
    contiguous: bool,
    /// GeneralSecondaryFlags, as they will be written back.
    flags: u8,
    /// The read/write cursor.
    pos: u64,
    /// Whether the entry set needs rewriting.
    dirty: bool,
}

impl File {
    pub(super) fn from_found(found: &Found) -> Self {
        let set = &found.set;
        Self {
            parent: found.parent.stream,
            set_pos: set.pos,
            first_cluster: set.first_cluster,
            len: set.data_length,
            valid: set.valid_data_length.min(set.data_length),
            contiguous: set.flags & layout::SECFLAG_NO_FAT_CHAIN != 0,
            flags: set.flags,
            pos: 0,
            dirty: false,
        }
    }

    /// Size in bytes.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether the file is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The read/write cursor.
    pub fn pos(&self) -> u64 {
        self.pos
    }

    /// Whether the file's clusters are a contiguous run whose FAT entries
    /// are not written — exFAT's `NoFatChain`.
    pub fn is_contiguous(&self) -> bool {
        self.contiguous
    }

    /// Move the cursor. Seeking past the end is allowed; writing there fills
    /// the gap with zeros.
    pub fn seek(&mut self, pos: u64) {
        self.pos = pos;
    }

    /// Move the cursor to the end of the file.
    pub fn seek_to_end(&mut self) {
        self.pos = self.len;
    }

    /// The stream the file's bytes live in.
    fn stream(&self) -> Stream {
        Stream {
            first_cluster: self.first_cluster,
            len: self.len,
            contiguous: self.contiguous,
        }
    }

    /// Read into `buf`, returning how many bytes were read: fewer than asked
    /// for only at the end of the file.
    pub fn read<D: SectorDriver, const S: usize>(
        &mut self,
        vol: &mut Volume<D, S>,
        buf: &mut [u8],
    ) -> Result<usize, Error<D::Error>> {
        let want = (buf.len() as u64).min(self.len.saturating_sub(self.pos)) as usize;
        if want == 0 {
            return Ok(0);
        }
        let bps = vol.geom.bytes_per_sector as u64;
        let spc = vol.geom.sectors_per_cluster as u64;
        let cb = bps * spc;
        let stream = self.stream();
        let mut done = 0usize;

        while done < want {
            // Past ValidDataLength there is nothing on the card to read:
            // exFAT says those bytes are zero.
            if self.pos >= self.valid {
                let n = want - done;
                buf[done..done + n].fill(0);
                self.pos += n as u64;
                return Ok(want);
            }
            let in_cluster = self.pos % cb;
            let index = (self.pos / cb) as u32;
            let cluster = vol
                .stream_cluster(&stream, index)?
                // The chain ended before DataLength said it would.
                .ok_or(Error::CorruptChain)?;
            let sector_in_cluster = in_cluster / bps;
            let in_sector = (in_cluster % bps) as usize;
            let first = vol.geom.cluster_first_sector(cluster) + sector_in_cluster;
            // Never read past ValidDataLength, or past what was asked for.
            let left = ((want - done) as u64).min(self.valid - self.pos) as usize;

            if in_sector == 0 && left as u64 >= bps {
                // Whole sectors: straight into the caller's buffer, as many
                // as remain in this cluster.
                let max = (spc - sector_in_cluster) as usize;
                let n = (left / bps as usize).min(max);
                let bytes = n * bps as usize;
                vol.read_sectors_direct(first, &mut buf[done..done + bytes])?;
                done += bytes;
                self.pos += bytes as u64;
            } else {
                let n = left.min(bps as usize - in_sector);
                let sector = vol.sector(first)?;
                buf[done..done + n].copy_from_slice(&sector[in_sector..in_sector + n]);
                done += n;
                self.pos += n as u64;
            }
        }
        Ok(done)
    }

    /// Read exactly `buf.len()` bytes, or fail with [`Error::InvalidOffset`]
    /// at the end of the file.
    pub fn read_exact<D: SectorDriver, const S: usize>(
        &mut self,
        vol: &mut Volume<D, S>,
        buf: &mut [u8],
    ) -> Result<(), Error<D::Error>> {
        if self.read(vol, buf)? == buf.len() {
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
        vol.require_bitmap()?;
        let end = self
            .pos
            .checked_add(buf.len() as u64)
            .ok_or(Error::FileTooLarge)?;
        // Writing past ValidDataLength leaves a gap that has to read as
        // zeros, and the rule only covers a trailing region — so the gap is
        // written out before the bytes that follow it.
        if self.pos > self.valid {
            let gap_to = self.pos;
            self.zero_range(vol, self.valid, gap_to)?;
            self.valid = gap_to;
        }
        self.reserve(vol, end)?;

        let bps = vol.geom.bytes_per_sector as u64;
        let spc = vol.geom.sectors_per_cluster as u64;
        let cb = bps * spc;
        let stream = self.stream();
        let mut done = 0usize;

        while done < buf.len() {
            let in_cluster = self.pos % cb;
            let index = (self.pos / cb) as u32;
            let cluster = vol
                .stream_cluster(&stream, index)?
                .ok_or(Error::CorruptChain)?;
            let sector_in_cluster = in_cluster / bps;
            let in_sector = (in_cluster % bps) as usize;
            let first = vol.geom.cluster_first_sector(cluster) + sector_in_cluster;
            let left = buf.len() - done;

            if in_sector == 0 && left as u64 >= bps {
                let max = (spc - sector_in_cluster) as usize;
                let n = (left / bps as usize).min(max);
                let bytes = n * bps as usize;
                vol.write_sectors_direct(first, &buf[done..done + bytes])?;
                done += bytes;
                self.pos += bytes as u64;
            } else {
                let n = left.min(bps as usize - in_sector);
                let sector = vol.sector_mut(first)?;
                sector[in_sector..in_sector + n].copy_from_slice(&buf[done..done + n]);
                done += n;
                self.pos += n as u64;
            }
        }

        if end > self.len {
            self.len = end;
        }
        self.valid = self.valid.max(end);
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

    /// Resize the file.
    ///
    /// Growing costs nothing but clusters: the new bytes sit past
    /// ValidDataLength, which exFAT already defines to read as zero.
    /// Shrinking frees the clusters that fall off the end.
    pub fn set_len<D: SectorDriver, const S: usize>(
        &mut self,
        vol: &mut Volume<D, S>,
        new_len: u64,
    ) -> Result<(), Error<D::Error>> {
        if new_len == self.len {
            return Ok(());
        }
        vol.require_bitmap()?;
        if new_len > self.len {
            self.reserve(vol, new_len)?;
            self.len = new_len;
            // ValidDataLength stays where it was: the gap reads as zeros.
            self.dirty = true;
            return self.flush(vol);
        }

        let cb = vol.geom.cluster_bytes() as u64;
        let keep = new_len.div_ceil(cb);
        let have = vol.chain_len(&self.stream())?;
        if new_len == 0 {
            if self.first_cluster >= 2 {
                let s = self.stream();
                vol.free_stream(&s)?;
            }
            self.first_cluster = 0;
            self.contiguous = false;
            self.flags = 0;
        } else if keep < have {
            if self.contiguous {
                // The run's tail is simply given back; the surviving part
                // is still a run.
                vol.free_run(self.first_cluster + keep as u32, have - keep)?;
            } else {
                let stream = self.stream();
                let last = vol
                    .stream_cluster(&stream, (keep - 1) as u32)?
                    .ok_or(Error::CorruptChain)?;
                if let Some(rest) = vol.next_cluster(last)? {
                    vol.free_chain(rest)?;
                }
                vol.set_fat_entry(last, layout::FAT_EOC)?;
            }
        }
        self.len = new_len;
        self.valid = self.valid.min(new_len);
        self.pos = self.pos.min(new_len);
        self.dirty = true;
        self.flush(vol)
    }

    /// Write the file's lengths and first cluster back into its directory
    /// entry set, then flush the volume's cached sector and the card.
    pub fn flush<D: SectorDriver, const S: usize>(
        &mut self,
        vol: &mut Volume<D, S>,
    ) -> Result<(), Error<D::Error>> {
        if self.dirty {
            let parent = self.parent;
            let Some(set) = vol.read_set(&parent, self.set_pos)? else {
                return Err(Error::CorruptEntry);
            };
            // A stream with no cluster must say so: exFAT requires
            // FirstCluster == 0 and the allocation flag clear.
            let flags = if self.first_cluster < 2 {
                self.flags & !(layout::SECFLAG_ALLOC_POSSIBLE | layout::SECFLAG_NO_FAT_CHAIN)
            } else {
                self.flags | layout::SECFLAG_ALLOC_POSSIBLE
            };
            vol.update_set(
                &parent,
                &set,
                self.first_cluster,
                self.len,
                self.valid.min(self.len),
                flags,
                true,
            )?;
            self.flags = flags;
            self.dirty = false;
        }
        vol.flush()
    }

    /// Make sure the file owns enough clusters to hold `bytes`.
    ///
    /// Clusters are claimed in runs: one run costs one write to the bitmap
    /// and one to the FAT, where a cluster at a time would cost two each —
    /// the two tables live in different sectors, and there is one sector of
    /// scratch to hold them in.
    fn reserve<D: SectorDriver, const S: usize>(
        &mut self,
        vol: &mut Volume<D, S>,
        bytes: u64,
    ) -> Result<(), Error<D::Error>> {
        let cb = vol.geom.cluster_bytes() as u64;
        let need = bytes.div_ceil(cb);
        if need == 0 {
            return Ok(());
        }
        if self.first_cluster < 2 {
            let (first, count) = vol.alloc_run(None, need)?;
            self.first_cluster = first;
            self.contiguous = false;
            self.flags = layout::SECFLAG_ALLOC_POSSIBLE;
            self.dirty = true;
            if count >= need {
                return Ok(());
            }
        }
        let mut have = vol.chain_len(&self.stream())?;
        if need <= have {
            return Ok(());
        }
        if self.contiguous {
            // Growing means the run can no longer stand on its own: write
            // the chain it implies, then continue as a chained file.
            self.materialise_chain(vol, have)?;
        }
        let stream = self.stream();
        let mut last = vol
            .stream_cluster(&stream, (have - 1) as u32)?
            .ok_or(Error::CorruptChain)?;
        while have < need {
            let (first, count) = vol.alloc_run(Some(last), need - have)?;
            have += count;
            last = first + (count - 1) as u32;
        }
        self.dirty = true;
        Ok(())
    }

    /// Write the FAT chain a `NoFatChain` run implies, and clear the flag.
    fn materialise_chain<D: SectorDriver, const S: usize>(
        &mut self,
        vol: &mut Volume<D, S>,
        clusters: u64,
    ) -> Result<(), Error<D::Error>> {
        for i in 0..clusters {
            let c = self.first_cluster as u64 + i;
            if c > u32::MAX as u64 {
                return Err(Error::CorruptChain);
            }
            let value = if i + 1 == clusters {
                layout::FAT_EOC
            } else {
                (c + 1) as u32
            };
            vol.set_fat_entry(c as u32, value)?;
        }
        self.contiguous = false;
        self.flags &= !layout::SECFLAG_NO_FAT_CHAIN;
        self.dirty = true;
        Ok(())
    }

    /// Zero the bytes in `from..to`, which a write past ValidDataLength
    /// leaves behind.
    fn zero_range<D: SectorDriver, const S: usize>(
        &mut self,
        vol: &mut Volume<D, S>,
        from: u64,
        to: u64,
    ) -> Result<(), Error<D::Error>> {
        if to <= from {
            return Ok(());
        }
        self.reserve(vol, to)?;
        let bps = vol.geom.bytes_per_sector as u64;
        let cb = vol.geom.cluster_bytes() as u64;
        let stream = self.stream();
        let mut at = from;
        while at < to {
            let index = (at / cb) as u32;
            let in_cluster = at % cb;
            let cluster = vol
                .stream_cluster(&stream, index)?
                .ok_or(Error::CorruptChain)?;
            let lba = vol.geom.cluster_first_sector(cluster) + in_cluster / bps;
            let in_sector = (in_cluster % bps) as usize;
            let n = ((to - at) as usize).min(bps as usize - in_sector);
            let sector = vol.sector_mut(lba)?;
            sector[in_sector..in_sector + n].fill(0);
            at += n as u64;
        }
        Ok(())
    }
}

impl<D: SectorDriver, const SECTOR: usize> Volume<D, SECTOR> {
    /// Open an existing file.
    pub fn open_file(&mut self, path: &str) -> Result<File, Error<D::Error>> {
        let Some(found) = self.find(path)? else {
            return Err(Error::IsADirectory);
        };
        if found.set.is_dir() {
            return Err(Error::IsADirectory);
        }
        Ok(File::from_found(&found))
    }

    /// Create a file, which must not already exist. Its parent must.
    pub fn create_file(&mut self, path: &str) -> Result<File, Error<D::Error>> {
        self.require_bitmap()?;
        let (parent, name) = self.parent_of(path)?;
        self.check_name(name)?;
        if self.find_in_dir(&parent.stream, name)?.is_some() {
            return Err(Error::AlreadyExists);
        }
        // An empty file owns no cluster: exFAT wants FirstCluster == 0 and
        // the allocation flag clear until it does.
        let hash = self.name_hash(name)?;
        let set = super::entry::SetBuilder::new(
            name,
            layout::ATTR_ARCHIVE,
            0,
            0,
            0,
            0,
            entry::stamp_of(self.now),
            hash,
        )?;
        let pos = self.insert_set(&parent, &set)?;
        self.flush_cache()?;
        Ok(File {
            parent: parent.stream,
            set_pos: pos,
            first_cluster: 0,
            len: 0,
            valid: 0,
            contiguous: false,
            flags: 0,
            pos: 0,
            dirty: false,
        })
    }

    /// Open a file, creating it if it is not there.
    pub fn open_or_create_file(&mut self, path: &str) -> Result<File, Error<D::Error>> {
        match self.find(path) {
            Ok(Some(found)) => {
                if found.set.is_dir() {
                    return Err(Error::IsADirectory);
                }
                Ok(File::from_found(&found))
            }
            Ok(None) => Err(Error::IsADirectory),
            Err(e) if e.is_not_found() => self.create_file(path),
            Err(e) => Err(e),
        }
    }

    /// The entry set a [`File`] was opened from, re-read from the card.
    #[allow(dead_code)]
    pub(super) fn set_of(&mut self, file: &File) -> Result<EntrySet, Error<D::Error>> {
        let parent = file.parent;
        self.read_set(&parent, file.set_pos)?
            .ok_or(Error::CorruptEntry)
    }
}
