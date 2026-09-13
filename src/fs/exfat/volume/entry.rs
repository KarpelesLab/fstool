//! Directory entry sets, read and written in place.
//!
//! A file or directory is described by a *set* of consecutive 32-byte
//! entries: the file entry (`0x85`), a stream extension (`0xC0`) holding
//! the cluster and the two lengths, and one name entry (`0xC1`) per 15
//! UTF-16 code units. A 16-bit checksum over the whole set protects it, so
//! changing one field means recomputing the checksum over every entry.
//!
//! The hosted half reads a directory into a `Vec<u8>` and slices sets out
//! of it. With no heap there is nowhere to put that, so everything here
//! works a slot at a time through the volume's single-sector cache: a set
//! is *summarised* into the fixed-size [`EntrySet`] below, its name is
//! compared or copied out one entry at a time, and a new set is written by
//! generating each entry twice — once to accumulate the checksum, once to
//! program it.

use super::super::layout::{self, ENTRY_SIZE};
use super::{Error, SectorDriver, Stream, Timestamp, Volume};

/// A file entry set, as much of it as fits in fixed-size fields.
///
/// The name is left on the card: [`Volume::name_matches`] compares it where
/// it lies and [`Volume::copy_name`] pulls it into a caller's buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct EntrySet {
    /// Byte offset of the primary entry within its directory's stream.
    pub pos: u64,
    /// Entries in the set, primary included.
    pub count: u8,
    /// FileAttributes.
    pub attrs: u16,
    /// GeneralSecondaryFlags from the stream extension.
    pub flags: u8,
    /// Name length in UTF-16 code units.
    pub name_len: u8,
    /// The NameHash the volume stored.
    pub name_hash: u16,
    /// First cluster of the data stream, or 0 when it owns none.
    pub first_cluster: u32,
    /// DataLength.
    pub data_length: u64,
    /// ValidDataLength — how much of `data_length` has been written.
    pub valid_data_length: u64,
    /// Create / modify / access timestamps, as stored.
    pub created: u32,
    pub modified: u32,
    pub accessed: u32,
}

impl EntrySet {
    /// Whether the set describes a directory.
    pub fn is_dir(&self) -> bool {
        self.attrs & layout::ATTR_DIRECTORY != 0
    }

    /// The data stream the set points at.
    pub fn stream(&self) -> Stream {
        Stream {
            first_cluster: self.first_cluster,
            len: self.data_length,
            contiguous: self.flags & layout::SECFLAG_NO_FAT_CHAIN != 0,
        }
    }

    /// Total bytes the set occupies in its directory.
    pub fn bytes(&self) -> u64 {
        self.count as u64 * ENTRY_SIZE as u64
    }
}

/// A set about to be written: every entry is generated from these fields,
/// so nothing has to be buffered.
#[derive(Debug, Clone, Copy)]
pub(super) struct SetBuilder<'a> {
    name: &'a str,
    /// UTF-16 code units in `name`.
    name_units: u8,
    /// Name entries the set needs.
    name_entries: u8,
    attrs: u16,
    flags: u8,
    first_cluster: u32,
    data_length: u64,
    valid_data_length: u64,
    /// Timestamp word and its 10ms increment.
    stamp: (u32, u8),
    name_hash: u16,
}

impl<'a> SetBuilder<'a> {
    /// Validate a name and describe the set that will hold it.
    #[allow(clippy::too_many_arguments)]
    pub fn new<E>(
        name: &'a str,
        attrs: u16,
        flags: u8,
        first_cluster: u32,
        data_length: u64,
        valid_data_length: u64,
        stamp: (u32, u8),
        name_hash: u16,
    ) -> Result<Self, Error<E>> {
        let units = name.encode_utf16().count();
        if units == 0 || units > layout::MAX_NAME_UNITS {
            return Err(Error::InvalidName);
        }
        Ok(Self {
            name,
            name_units: units as u8,
            name_entries: units.div_ceil(layout::NAME_UNITS_PER_ENTRY) as u8,
            attrs,
            flags,
            first_cluster,
            data_length,
            valid_data_length,
            stamp,
            name_hash,
        })
    }

    /// Entries in the set, primary included.
    pub fn count(&self) -> u8 {
        2 + self.name_entries
    }

    /// Bytes the set occupies.
    pub fn bytes(&self) -> u64 {
        self.count() as u64 * ENTRY_SIZE as u64
    }

    /// Generate entry `index` of the set. The primary's checksum field is
    /// left zero; [`Self::checksum`] computes what belongs there, and the
    /// writer patches it in.
    pub fn entry(&self, index: usize) -> [u8; ENTRY_SIZE] {
        let mut e = [0u8; ENTRY_SIZE];
        match index {
            0 => {
                e[0] = layout::ENTRY_FILE;
                e[1] = self.count() - 1;
                // 2..4 is the set checksum, filled in by the writer.
                e[4..6].copy_from_slice(&self.attrs.to_le_bytes());
                e[8..12].copy_from_slice(&self.stamp.0.to_le_bytes());
                e[12..16].copy_from_slice(&self.stamp.0.to_le_bytes());
                e[16..20].copy_from_slice(&self.stamp.0.to_le_bytes());
                e[20] = self.stamp.1;
                e[21] = self.stamp.1;
            }
            1 => {
                e[0] = layout::ENTRY_STREAM_EXTENSION;
                e[1] = self.flags;
                e[3] = self.name_units;
                e[4..6].copy_from_slice(&self.name_hash.to_le_bytes());
                e[8..16].copy_from_slice(&self.valid_data_length.to_le_bytes());
                e[20..24].copy_from_slice(&self.first_cluster.to_le_bytes());
                e[24..32].copy_from_slice(&self.data_length.to_le_bytes());
            }
            n => {
                e[0] = layout::ENTRY_FILE_NAME;
                let skip = (n - 2) * layout::NAME_UNITS_PER_ENTRY;
                for (i, unit) in self
                    .name
                    .encode_utf16()
                    .skip(skip)
                    .take(layout::NAME_UNITS_PER_ENTRY)
                    .enumerate()
                {
                    let at = 2 + i * 2;
                    e[at..at + 2].copy_from_slice(&unit.to_le_bytes());
                }
            }
        }
        e
    }

    /// The set checksum over every entry, which is what the primary
    /// carries.
    pub fn checksum(&self) -> u16 {
        let mut sum = 0u16;
        for i in 0..self.count() as usize {
            sum = layout::set_checksum_step(sum, i, &self.entry(i));
        }
        sum
    }
}

/// Split an exFAT timestamp word and its 10ms increment out of a
/// [`Timestamp`].
pub(super) fn stamp_of(t: Timestamp) -> (u32, u8) {
    ((t.date as u32) << 16 | t.time as u32, t.tenths)
}

/// The [`Timestamp`] an exFAT timestamp word describes.
pub(super) fn timestamp_of(word: u32, tenths: u8) -> Timestamp {
    Timestamp {
        date: (word >> 16) as u16,
        time: (word & 0xffff) as u16,
        tenths,
    }
}

/// Names exFAT refuses: the characters FAT reserves, plus the two names a
/// path walk resolves itself.
pub(super) fn name_is_valid(name: &str) -> bool {
    if name.is_empty() || name == "." || name == ".." {
        return false;
    }
    let units = name.encode_utf16().count();
    if units > layout::MAX_NAME_UNITS {
        return false;
    }
    // Every code point below 0x20 is illegal, as are these.
    !name.chars().any(|c| {
        (c as u32) < 0x20 || matches!(c, '"' | '*' | '/' | ':' | '<' | '>' | '?' | '\\' | '|')
    })
}

impl<D: SectorDriver, const SECTOR: usize> Volume<D, SECTOR> {
    /// Read the set that starts at byte `pos` of a directory stream.
    ///
    /// Returns `None` when the slot ends the directory or holds something
    /// that is not a file set. The set's checksum is verified here, so a
    /// caller that gets an `EntrySet` back has one the volume vouches for.
    pub(super) fn read_set(
        &mut self,
        dir: &Stream,
        pos: u64,
    ) -> Result<Option<EntrySet>, Error<D::Error>> {
        let Some(primary) = self.read_slot(dir, pos)? else {
            return Ok(None);
        };
        if primary[0] != layout::ENTRY_FILE {
            return Ok(None);
        }
        let secondary = primary[1] as usize;
        // A set is the primary, a stream extension and up to 17 name
        // entries; anything else is not one.
        if secondary < 2
            || secondary > 1 + layout::MAX_NAME_UNITS.div_ceil(layout::NAME_UNITS_PER_ENTRY)
        {
            return Err(Error::CorruptEntry);
        }
        let Some(stream) = self.read_slot(dir, pos + ENTRY_SIZE as u64)? else {
            return Err(Error::CorruptEntry);
        };
        if stream[0] != layout::ENTRY_STREAM_EXTENSION {
            return Err(Error::CorruptEntry);
        }

        let count = (1 + secondary) as u8;
        let on_disk = layout::le16(&primary, 2);
        let mut sum = layout::set_checksum_step(0, 0, &primary);
        sum = layout::set_checksum_step(sum, 1, &stream);
        for i in 2..count as usize {
            let Some(slot) = self.read_slot(dir, pos + (i * ENTRY_SIZE) as u64)? else {
                return Err(Error::CorruptEntry);
            };
            if slot[0] != layout::ENTRY_FILE_NAME {
                return Err(Error::CorruptEntry);
            }
            sum = layout::set_checksum_step(sum, i, &slot);
        }
        if sum != on_disk {
            return Err(Error::CorruptEntry);
        }

        let name_len = stream[3];
        if name_len == 0 || name_len as usize > (count as usize - 2) * layout::NAME_UNITS_PER_ENTRY
        {
            return Err(Error::CorruptEntry);
        }
        Ok(Some(EntrySet {
            pos,
            count,
            attrs: layout::le16(&primary, 4),
            flags: stream[1],
            name_len,
            name_hash: layout::le16(&stream, 4),
            first_cluster: layout::le32(&stream, 20),
            data_length: layout::le64(&stream, 24),
            valid_data_length: layout::le64(&stream, 8),
            created: layout::le32(&primary, 8),
            modified: layout::le32(&primary, 12),
            accessed: layout::le32(&primary, 16),
        }))
    }

    /// Whether a set's name equals `query`, compared the way exFAT does:
    /// code unit by code unit through the volume's up-case table.
    ///
    /// The table is only consulted where the two actually differ, which for
    /// ASCII names is nowhere at all.
    pub(super) fn name_matches(
        &mut self,
        dir: &Stream,
        set: &EntrySet,
        query: &str,
    ) -> Result<bool, Error<D::Error>> {
        if query.encode_utf16().count() != set.name_len as usize {
            return Ok(false);
        }
        let mut want = query.encode_utf16();
        let mut left = set.name_len as usize;
        for i in 2..set.count as usize {
            let Some(slot) = self.read_slot(dir, set.pos + (i * ENTRY_SIZE) as u64)? else {
                return Err(Error::CorruptEntry);
            };
            // Copied out before comparing: an up-case lookup reads the card
            // through the same cache this slot came from.
            let n = left.min(layout::NAME_UNITS_PER_ENTRY);
            let mut units = [0u16; layout::NAME_UNITS_PER_ENTRY];
            for (j, unit) in units[..n].iter_mut().enumerate() {
                *unit = layout::le16(&slot, 2 + j * 2);
            }
            for &on_disk in &units[..n] {
                let Some(q) = want.next() else {
                    return Ok(false);
                };
                if on_disk != q && self.up(on_disk)? != self.up(q)? {
                    return Ok(false);
                }
            }
            left -= n;
            if left == 0 {
                break;
            }
        }
        Ok(left == 0 && want.next().is_none())
    }

    /// Copy a set's name into `units`, returning how many code units it
    /// holds.
    pub(super) fn copy_name(
        &mut self,
        dir: &Stream,
        set: &EntrySet,
        units: &mut [u16],
    ) -> Result<usize, Error<D::Error>> {
        let total = (set.name_len as usize).min(units.len());
        let mut done = 0usize;
        for i in 2..set.count as usize {
            if done >= total {
                break;
            }
            let Some(slot) = self.read_slot(dir, set.pos + (i * ENTRY_SIZE) as u64)? else {
                return Err(Error::CorruptEntry);
            };
            let n = (total - done).min(layout::NAME_UNITS_PER_ENTRY);
            for (j, slot_unit) in units[done..done + n].iter_mut().enumerate() {
                *slot_unit = layout::le16(&slot, 2 + j * 2);
            }
            done += n;
        }
        Ok(done)
    }

    /// Write a fresh set at byte `pos` of a directory stream.
    pub(super) fn write_set(
        &mut self,
        dir: &Stream,
        pos: u64,
        set: &SetBuilder<'_>,
    ) -> Result<(), Error<D::Error>> {
        let checksum = set.checksum();
        for i in 0..set.count() as usize {
            let mut e = set.entry(i);
            if i == 0 {
                e[2..4].copy_from_slice(&checksum.to_le_bytes());
            }
            self.write_slot(dir, pos + (i * ENTRY_SIZE) as u64, &e)?;
        }
        Ok(())
    }

    /// Rewrite the stream extension of an existing set — the cluster, the
    /// two lengths and the flags — and the modification timestamp with it.
    ///
    /// The set checksum covers every entry, so it is recomputed by reading
    /// the name entries back; only the two entries that changed are
    /// written.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn update_set(
        &mut self,
        dir: &Stream,
        set: &EntrySet,
        first_cluster: u32,
        data_length: u64,
        valid_data_length: u64,
        flags: u8,
        touch: bool,
    ) -> Result<(), Error<D::Error>> {
        let Some(mut primary) = self.read_slot(dir, set.pos)? else {
            return Err(Error::CorruptEntry);
        };
        let Some(mut stream) = self.read_slot(dir, set.pos + ENTRY_SIZE as u64)? else {
            return Err(Error::CorruptEntry);
        };
        stream[1] = flags;
        stream[8..16].copy_from_slice(&valid_data_length.to_le_bytes());
        stream[20..24].copy_from_slice(&first_cluster.to_le_bytes());
        stream[24..32].copy_from_slice(&data_length.to_le_bytes());
        if touch {
            let (word, tenths) = stamp_of(self.now);
            primary[12..16].copy_from_slice(&word.to_le_bytes());
            primary[16..20].copy_from_slice(&word.to_le_bytes());
            primary[21] = tenths;
        }
        // The checksum skips its own field, so zeroing it first is not
        // needed — but every other byte of every entry counts.
        let mut sum = layout::set_checksum_step(0, 0, &primary);
        sum = layout::set_checksum_step(sum, 1, &stream);
        for i in 2..set.count as usize {
            let Some(slot) = self.read_slot(dir, set.pos + (i * ENTRY_SIZE) as u64)? else {
                return Err(Error::CorruptEntry);
            };
            sum = layout::set_checksum_step(sum, i, &slot);
        }
        primary[2..4].copy_from_slice(&sum.to_le_bytes());
        self.write_slot(dir, set.pos, &primary)?;
        self.write_slot(dir, set.pos + ENTRY_SIZE as u64, &stream)?;
        Ok(())
    }

    /// Mark every entry of a set deleted, by clearing the in-use bit of its
    /// type byte — which is exactly what exFAT calls a removed entry.
    pub(super) fn clear_set(
        &mut self,
        dir: &Stream,
        set: &EntrySet,
    ) -> Result<(), Error<D::Error>> {
        for i in 0..set.count as usize {
            let off = set.pos + (i * ENTRY_SIZE) as u64;
            let Some(mut slot) = self.read_slot(dir, off)? else {
                break;
            };
            slot[0] &= !layout::ENTRY_INUSE;
            self.write_slot(dir, off, &slot)?;
        }
        Ok(())
    }
}
