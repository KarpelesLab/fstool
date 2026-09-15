//! exFAT with no allocator.
//!
//! This is a second, independent exFAT driver. [`super::hosted`] is the
//! hosted one: it reads the whole FAT, the whole allocation bitmap and the
//! whole up-case table into memory, hands back `String` names, and speaks
//! the crate's [`Filesystem`](crate::fs::Filesystem) trait. That design is
//! right for building images on a machine with a heap and wrong for a
//! microcontroller, so none of it is reused here. Instead:
//!
//! * **No allocation, anywhere.** Every buffer is a fixed-size array or
//!   comes from the caller. With `default-features = false, features =
//!   ["exfat"]` the crate compiles and links on a target with no global
//!   allocator at all; the hosted driver appears only when `alloc` is also
//!   on.
//! * **Everything stays on the card.** The FAT and the allocation bitmap
//!   are read — and written — one sector at a time through a single-sector
//!   write-back cache, so mounting a 256 GB card costs one sector of RAM
//!   rather than the megabytes its tables occupy.
//! * **The up-case table is consulted on disk.** Its first 128 entries are
//!   read once at mount, which covers every ASCII comparison; beyond that
//!   the table is walked on the card, and only when two names actually
//!   differ at a non-ASCII position. With `alloc` the whole table is
//!   decoded into memory on first need instead.
//! * **The same device trait as FAT.** [`SectorDriver`](crate::device::SectorDriver) comes from
//!   [`crate::device`], the layer below the filesystems, so one
//!   implementation over your SD/eMMC peripheral mounts either filesystem —
//!   which is what a card reader wants, since an SDXC card arrives formatted
//!   exFAT and an SDHC one FAT32.
//!
//! Reads and writes are both supported: mount (whole card or an MBR
//! partition), open, read, seek, append, extend, truncate, create and
//! remove files, create and remove directories, and list directories.
//!
//! # Shape of the API
//!
//! There is no interior mutability and no heap, so the volume owns the
//! driver and every handle is a plain `Copy` value that borrows nothing.
//! Operations on a handle therefore take the volume back:
//!
//! ```
//! # use fstool::device::SectorDriver;
//! # use fstool::fs::exfat::{Error, Volume};
//! # struct Card([u8; 0]);
//! # impl SectorDriver for Card {
//! #     type Error = core::convert::Infallible;
//! #     fn sector_size(&self) -> u32 { 512 }
//! #     fn sector_count(&self) -> u64 { 0 }
//! #     fn read_sectors(&mut self, _: u64, _: &mut [u8]) -> Result<(), Self::Error> { Ok(()) }
//! #     fn write_sectors(&mut self, _: u64, _: &[u8]) -> Result<(), Self::Error> { Ok(()) }
//! # }
//! # fn demo(card: Card) -> Result<(), Error<core::convert::Infallible>> {
//! let mut vol = Volume::<_, 512>::mount_auto(card)?;
//!
//! // Read a config file into a fixed buffer.
//! let mut file = vol.open_file("/config/wifi.txt")?;
//! let mut buf = [0u8; 256];
//! let n = file.read(&mut vol, &mut buf)?;
//!
//! // Append a line to a log, creating it if needed.
//! let mut log = vol.open_or_create_file("/log.txt")?;
//! log.seek_to_end();
//! log.write_all(&mut vol, b"booted\n")?;
//! log.flush(&mut vol)?;
//!
//! // List a directory. Names borrow the iterator's buffer, so this is a
//! // `while let`, not a `for`.
//! let dir = vol.open_dir("/")?;
//! let mut it = vol.iter_dir(dir);
//! while let Some(entry) = it.next()? {
//!     let _ = (entry.name(), entry.len(), entry.is_dir());
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Limits
//!
//! * `SECTOR`, the const parameter, is the scratch buffer's size and must
//!   be at least the volume's sector size. Use `Volume::<_, 512>` unless
//!   you have 4 KiB-sector media.
//! * The volume's declared sector size must equal the driver's; a mismatch
//!   is [`Error::SectorSizeMismatch`] rather than a bounce-buffer layer.
//! * [`Volume::format`] / [`Volume::format_at`] create volumes, with the
//!   specification's recommended up-case table, one FAT, and no volume GUID
//!   entry; TexFAT's second FAT and bitmap are never laid down.
//! * Every write path needs the allocation bitmap, since it is the only
//!   record of which clusters a `NoFatChain` file owns; a volume without a
//!   readable one is read-only ([`Error::NoAllocationBitmap`]).
//! * A file this driver creates is a FAT chain, never a `NoFatChain` run —
//!   the bit is honoured on read, and a contiguous file that grows is
//!   converted by writing the chain its run implies.
//! * Names are compared through the volume's own up-case table, so
//!   behaviour matches whatever formatted the card. A name outside the
//!   Basic Multilingual Plane (a surrogate pair) is compared code unit by
//!   code unit, which is what the table itself covers.
//! * A handle caches where its directory entry set lives, so removing or
//!   re-creating a path while a handle to it is open is a bug the driver
//!   cannot detect.
//! * The boot sector's `VolumeFlags` dirty bit is left alone, as it is by
//!   the hosted half: a volume this driver wrote is consistent on every
//!   [`flush`](Volume::flush), so there is no window the flag would be
//!   warning a later mount about. `PercentInUse` is advisory and likewise
//!   untouched — [`free_clusters`](Volume::free_clusters) counts the bitmap
//!   instead.

mod dir;
mod entry;
mod file;
mod format;
#[cfg(test)]
pub(crate) mod tests;

pub use dir::{Dir, DirEntry, DirIter, Metadata};
pub use file::File;
pub use format::VolumeFormatOpts;

use super::layout::{self, Boot, FatEntry};

// The storage the driver is written against, and the partition table it may
// find a volume inside, both live one layer down in `crate::device` — the
// module a consumer implements against. Neither is re-exported here: there
// is one canonical path for each.
use crate::device::{SectorDriver, gpt, mbr};
/// The timestamp stamped on entries this driver creates or modifies. exFAT
/// stores the same date and time words FAT does, plus a 10ms increment, so
/// this is [`fat`](crate::fs::fat)'s type.
pub use crate::fs::fat::Timestamp;

/// UTF-16 code units an exFAT name can hold.
pub const MAX_NAME_LEN: usize = layout::MAX_NAME_UNITS;

/// Up-case entries cached in the volume: enough for every ASCII code unit,
/// read from the volume's own table at mount.
const UP_ASCII: usize = 128;

/// Everything that can go wrong, parameterised by the driver's own error.
///
/// No variant owns a heap allocation; the ones that carry detail carry it
/// as numbers or a `&'static str`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error<E> {
    /// The driver failed.
    Io(E),
    /// No exFAT volume here: bad signature, or a boot sector whose fields
    /// contradict each other.
    NotExfat,
    /// The volume's filesystem revision is not one this driver reads.
    UnsupportedVersion {
        /// Major revision from the boot sector.
        major: u8,
        /// Minor revision from the boot sector.
        minor: u8,
    },
    /// The volume declares a sector size the driver does not use.
    SectorSizeMismatch {
        /// What the boot sector says.
        volume: u32,
        /// What the driver reports.
        driver: u32,
    },
    /// `SECTOR` is smaller than the driver's sector size.
    ScratchTooSmall {
        /// The driver's sector size.
        needed: usize,
        /// The const parameter the volume was instantiated with.
        got: usize,
    },
    /// The volume extends past the end of the medium.
    VolumeExceedsDevice,
    /// The boot sector describes a geometry exFAT cannot use.
    BadGeometry,
    /// No MBR, or no such partition slot.
    NoSuchPartition,
    /// The volume has no readable allocation bitmap, which every write
    /// path needs: it is the only record of which clusters a `NoFatChain`
    /// file owns.
    NoAllocationBitmap,
    /// A path component does not exist.
    NotFound,
    /// A path component that must be a directory is not one.
    NotADirectory,
    /// The target is a directory and the operation needs a file.
    IsADirectory,
    /// Creating something whose name is already taken.
    AlreadyExists,
    /// `remove_dir` on a directory that still has entries.
    DirectoryNotEmpty,
    /// The name is empty, longer than [`MAX_NAME_LEN`] UTF-16 units, or
    /// contains a character exFAT reserves.
    InvalidName,
    /// A path is malformed: a component is `.` or `..`, or it is empty
    /// where a name is required.
    InvalidPath,
    /// The directory cannot be extended to hold another entry set.
    DirectoryFull,
    /// The volume has no free cluster left.
    NoSpace,
    /// A cluster chain is free, reserved or out of range — the volume
    /// needs `fsck`.
    CorruptChain,
    /// A directory entry set failed its checksum or its layout.
    CorruptEntry,
    /// The operation would take the file past what exFAT can address.
    FileTooLarge,
    /// A seek or read outside the file.
    InvalidOffset,
    /// Recognised on-disk structure this driver does not implement.
    Unsupported(&'static str),
}

impl<E> Error<E> {
    /// True for [`Error::NotFound`] — the check callers write most.
    pub fn is_not_found(&self) -> bool {
        matches!(self, Error::NotFound)
    }
}

impl<E: core::fmt::Display> core::fmt::Display for Error<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "device error: {e}"),
            Error::NotExfat => f.write_str("not an exFAT volume"),
            Error::UnsupportedVersion { major, minor } => {
                write!(f, "unsupported exFAT revision {major}.{minor}")
            }
            Error::SectorSizeMismatch { volume, driver } => write!(
                f,
                "volume declares {volume}-byte sectors, driver uses {driver}"
            ),
            Error::ScratchTooSmall { needed, got } => {
                write!(f, "scratch buffer is {got} bytes, need {needed}")
            }
            Error::VolumeExceedsDevice => f.write_str("volume runs past the end of the device"),
            Error::BadGeometry => f.write_str("geometry exFAT cannot use"),
            Error::NoSuchPartition => f.write_str("no such partition"),
            Error::NoAllocationBitmap => f.write_str("volume has no allocation bitmap"),
            Error::NotFound => f.write_str("no such file or directory"),
            Error::NotADirectory => f.write_str("not a directory"),
            Error::IsADirectory => f.write_str("is a directory"),
            Error::AlreadyExists => f.write_str("already exists"),
            Error::DirectoryNotEmpty => f.write_str("directory not empty"),
            Error::InvalidName => f.write_str("invalid name"),
            Error::InvalidPath => f.write_str("invalid path"),
            Error::DirectoryFull => f.write_str("directory full"),
            Error::NoSpace => f.write_str("no space left on volume"),
            Error::CorruptChain => f.write_str("corrupt cluster chain"),
            Error::CorruptEntry => f.write_str("corrupt directory entry set"),
            Error::FileTooLarge => f.write_str("file too large"),
            Error::InvalidOffset => f.write_str("offset out of range"),
            Error::Unsupported(what) => write!(f, "unsupported: {what}"),
        }
    }
}

#[cfg(feature = "std")]
impl<E: core::fmt::Debug + core::fmt::Display> std::error::Error for Error<E> {}

/// A volume's validated layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Geometry {
    /// Absolute LBA the volume starts at (0 for an unpartitioned card).
    pub part_start: u64,
    /// Sectors the volume spans.
    pub volume_sectors: u64,
    /// Bytes per sector, which must match the driver's.
    pub bytes_per_sector: u32,
    /// Sectors per cluster — the allocation granularity.
    pub sectors_per_cluster: u32,
    /// Data clusters, numbered 2..cluster_count + 2.
    pub cluster_count: u32,
    /// First cluster of the root directory.
    pub root_cluster: u32,
    /// Filesystem revision, as `(major, minor)`.
    pub revision: (u8, u8),
    /// VolumeSerialNumber.
    pub serial: u32,
    /// Volume-relative sector of the first FAT.
    fat_start: u32,
    /// Sectors in one FAT.
    fat_sectors: u32,
    /// Which FAT copy is active (VolumeFlags bit 0).
    active_fat: u8,
    /// Volume-relative sector where cluster 2 starts.
    heap_start: u32,
}

impl Geometry {
    /// Bytes in one cluster.
    pub fn cluster_bytes(&self) -> u32 {
        self.bytes_per_sector * self.sectors_per_cluster
    }

    /// Capacity of the data region in bytes.
    pub fn total_bytes(&self) -> u64 {
        self.cluster_count as u64 * self.cluster_bytes() as u64
    }

    /// Whether `cluster` names a data cluster.
    pub fn is_data_cluster(&self, cluster: u32) -> bool {
        cluster >= 2 && cluster < self.cluster_count + 2
    }

    /// Absolute LBA of `cluster`'s first sector.
    fn cluster_first_sector(&self, cluster: u32) -> u64 {
        self.part_start
            + self.heap_start as u64
            + (cluster as u64 - 2) * self.sectors_per_cluster as u64
    }

    /// Absolute LBA of the active FAT's first sector.
    fn fat_first_sector(&self) -> u64 {
        self.part_start + self.fat_start as u64 + self.active_fat as u64 * self.fat_sectors as u64
    }
}

/// A byte stream on the volume: a file's data, a directory's entries, or
/// one of the volume's own metadata streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Stream {
    /// First cluster, or 0 for an empty stream.
    pub first_cluster: u32,
    /// Length in bytes (`DataLength`).
    pub len: u64,
    /// `NoFatChain`: the clusters are contiguous and the FAT entries for
    /// them are not valid.
    pub contiguous: bool,
}

impl Stream {
    /// A directory's stream: exFAT gives directories a DataLength, and the
    /// root's is however far its chain reaches.
    pub(super) fn dir(first_cluster: u32, len: u64) -> Self {
        Self {
            first_cluster,
            len,
            contiguous: false,
        }
    }
}

/// A mounted exFAT volume that owns its card.
///
/// `SECTOR` is the size of the single sector of scratch RAM the volume
/// keeps; it must be at least the volume's sector size. 512 is right for
/// SD cards.
#[derive(Debug)]
pub struct Volume<D: SectorDriver, const SECTOR: usize = 512> {
    dev: D,
    geom: Geometry,
    /// One sector of scratch, plus which absolute LBA it holds and whether
    /// it has been modified: a write-back cache of exactly one sector.
    buf: [u8; SECTOR],
    cache_lba: Option<u64>,
    cache_dirty: bool,
    /// The allocation bitmap's stream, when the volume has a readable one.
    bitmap: Option<Stream>,
    /// The up-case table's stream.
    upcase: Option<Stream>,
    /// The table's first [`UP_ASCII`] entries, read at mount: every
    /// comparison of ASCII names is then free, which is almost all of them.
    up_ascii: [u16; UP_ASCII],
    /// Cursor into the last chain walked — `(first cluster, index,
    /// cluster)` — so a sequential scan does not re-walk from the start.
    walk: Option<(u32, u32, u32)>,
    /// Where to start looking for a free cluster.
    next_free: u32,
    /// What to stamp on entries this volume creates or modifies.
    now: Timestamp,
    /// The up-case table, decoded, when there is a heap to hold it in.
    /// Pure optimisation: the same calls give the same answers without it,
    /// just a walk on the card per non-ASCII comparison instead of none.
    #[cfg(feature = "alloc")]
    up_cache: Option<::alloc::vec::Vec<u16>>,
}

impl<D: SectorDriver, const SECTOR: usize> Volume<D, SECTOR> {
    // -- mounting ---------------------------------------------------------

    /// Mount the volume that starts at sector 0 of the card.
    pub fn mount(dev: D) -> Result<Self, Error<D::Error>> {
        Self::mount_at(dev, 0)
    }

    /// Mount the volume in 1-based MBR partition `index`.
    pub fn mount_partition(mut dev: D, index: u8) -> Result<Self, Error<D::Error>> {
        let part = Self::partition(&mut dev, index)?;
        Self::mount_at(dev, part.start_lba)
    }

    /// Mount whatever looks like an exFAT volume: the whole card if sector 0
    /// is an exFAT boot sector, otherwise the first partition that mounts —
    /// from a GPT if the card has one, from the MBR if not.
    ///
    /// This is what an SDXC card wants — the ones the SD Association's own
    /// formatter produces are partitioned, most cameras' are too, and a card
    /// that has been through a PC may well carry a GPT.
    pub fn mount_auto(mut dev: D) -> Result<Self, Error<D::Error>> {
        match Self::probe(&mut dev)? {
            Some(lba) => Self::mount_at(dev, lba),
            None => Err(Error::NotExfat),
        }
    }

    /// Where on the card an exFAT volume starts, if one does — without
    /// taking the card.
    ///
    /// This is what [`mount_auto`](Self::mount_auto) asks, split out because
    /// a card reader does not know which filesystem it has been handed and
    /// a failed mount would have swallowed the driver:
    ///
    /// ```no_run
    /// # use fstool::fs::exfat::Volume as Exfat;
    /// # use fstool::fs::fat::Volume as Fat;
    /// # fn demo<D: fstool::device::SectorDriver>(mut card: D)
    /// #     -> Result<(), fstool::fs::exfat::Error<D::Error>> {
    /// if let Some(lba) = Exfat::<_, 512>::probe(&mut card)? {
    ///     let _vol = Exfat::<_, 512>::mount_at(card, lba)?;
    /// } else {
    ///     let _vol = Fat::<_, 512>::mount_auto(card);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn probe(dev: &mut D) -> Result<Option<u64>, Error<D::Error>> {
        Self::check_scratch(dev)?;
        let ss = dev.sector_size() as usize;
        let mut first = [0u8; SECTOR];
        Self::read_raw(dev, 0, &mut first[..ss])?;

        if Boot::decode(&first[..ss]).is_ok() {
            return Ok(Some(0));
        }

        // GPT before MBR: a GPT disk carries a protective MBR whose one entry
        // describes the table, not a volume, so walking that first would just
        // waste a read.
        if let Some(table) = gpt::Table::read(dev, &mut first[..ss]).map_err(Error::Io)? {
            // Likely type GUIDs first, then anything else that parses: the
            // GUID is a hint, never the decision.
            for pass in 0..2 {
                for i in 0..table.entries() {
                    let Some(part) = table.entry(dev, &mut first[..ss], i).map_err(Error::Io)?
                    else {
                        continue;
                    };
                    if (pass == 0) != part.looks_like_fat_family() {
                        continue;
                    }
                    if Self::read_raw(dev, part.start_lba, &mut first[..ss]).is_ok()
                        && Boot::decode(&first[..ss]).is_ok()
                    {
                        return Ok(Some(part.start_lba));
                    }
                }
            }
            return Ok(None);
        }

        Self::read_raw(dev, 0, &mut first[..ss])?;
        if let Some(table) = mbr::parse(&first[..ss]) {
            // exFAT-typed slots first, then anything else that parses: the
            // type byte is a hint, never the decision.
            for pass in 0..2 {
                for slot in table.iter().flatten() {
                    if (pass == 0) != slot.looks_like_exfat() {
                        continue;
                    }
                    if Self::read_raw(dev, slot.start_lba, &mut first[..ss]).is_ok()
                        && Boot::decode(&first[..ss]).is_ok()
                    {
                        return Ok(Some(slot.start_lba));
                    }
                }
            }
        }
        Ok(None)
    }

    /// Mount the volume whose boot sector is at `start_lba`.
    pub fn mount_at(mut dev: D, start_lba: u64) -> Result<Self, Error<D::Error>> {
        Self::check_scratch(&dev)?;
        let ss = dev.sector_size();
        let mut sector = [0u8; SECTOR];
        Self::read_raw(&mut dev, start_lba, &mut sector[..ss as usize])?;
        let boot = Boot::decode(&sector[..ss as usize]).map_err(|_| Error::NotExfat)?;

        if boot.bytes_per_sector() != ss {
            return Err(Error::SectorSizeMismatch {
                volume: boot.bytes_per_sector(),
                driver: ss,
            });
        }
        // Revision 1.x is what every exFAT volume in the wild is; a future
        // major would change the structures this driver reads.
        if boot.fs_revision_major != 1 {
            return Err(Error::UnsupportedVersion {
                major: boot.fs_revision_major,
                minor: boot.fs_revision_minor,
            });
        }
        let geom = Self::geometry_from(&boot, start_lba, &dev)?;

        let mut vol = Self {
            dev,
            geom,
            buf: [0u8; SECTOR],
            cache_lba: None,
            cache_dirty: false,
            bitmap: None,
            upcase: None,
            up_ascii: [0u16; UP_ASCII],
            walk: None,
            next_free: 2,
            now: Timestamp::EPOCH,
            #[cfg(feature = "alloc")]
            up_cache: None,
        };
        // Identity until the volume's own table says otherwise, so that a
        // volume with no readable table still compares names sanely.
        for (i, slot) in vol.up_ascii.iter_mut().enumerate() {
            *slot = i as u16;
        }
        vol.scan_root_metadata()?;
        vol.load_upcase_ascii()?;
        Ok(vol)
    }

    /// Look up a 1-based MBR partition without mounting it.
    pub fn partition(dev: &mut D, index: u8) -> Result<mbr::Partition, Error<D::Error>> {
        if index == 0 || index > 4 {
            return Err(Error::NoSuchPartition);
        }
        Self::check_scratch(dev)?;
        let ss = dev.sector_size() as usize;
        let mut sector = [0u8; SECTOR];
        Self::read_raw(dev, 0, &mut sector[..ss])?;
        mbr::parse(&sector[..ss])
            .and_then(|t| t[index as usize - 1])
            .ok_or(Error::NoSuchPartition)
    }

    /// Validate the boot sector's layout against the medium.
    fn geometry_from(boot: &Boot, part_start: u64, dev: &D) -> Result<Geometry, Error<D::Error>> {
        let bps = boot.bytes_per_sector();
        let spc = boot.sectors_per_cluster();
        if boot.cluster_count == 0 || boot.fat_length == 0 || spc == 0 {
            return Err(Error::BadGeometry);
        }
        // The volume has to fit the medium, with room for the partition
        // offset the caller mounted at.
        let end = part_start
            .checked_add(boot.volume_length)
            .ok_or(Error::BadGeometry)?;
        if boot.volume_length == 0 || end > dev.sector_count() {
            return Err(Error::VolumeExceedsDevice);
        }
        // The FAT must lie inside the volume and be large enough to map
        // every cluster: (cluster_count + 2) 32-bit entries.
        let fat_end = (boot.fat_offset as u64)
            .checked_add(boot.fat_length as u64 * boot.number_of_fats as u64)
            .ok_or(Error::BadGeometry)?;
        if fat_end > boot.volume_length {
            return Err(Error::BadGeometry);
        }
        let need_entries = boot.cluster_count as u64 + 2;
        if boot.fat_length as u64 * bps as u64 / 4 < need_entries {
            return Err(Error::BadGeometry);
        }
        // The cluster heap must lie inside the volume too.
        let heap_sectors = boot.cluster_count as u64 * spc as u64;
        let heap_end = (boot.cluster_heap_offset as u64)
            .checked_add(heap_sectors)
            .ok_or(Error::BadGeometry)?;
        if (boot.cluster_heap_offset as u64) < fat_end || heap_end > boot.volume_length {
            return Err(Error::BadGeometry);
        }
        let root = boot.first_cluster_of_root_directory;
        if root < 2 || root >= boot.cluster_count + 2 {
            return Err(Error::BadGeometry);
        }
        Ok(Geometry {
            part_start,
            volume_sectors: boot.volume_length,
            bytes_per_sector: bps,
            sectors_per_cluster: spc,
            cluster_count: boot.cluster_count,
            root_cluster: root,
            revision: (boot.fs_revision_major, boot.fs_revision_minor),
            serial: boot.volume_serial_number,
            fat_start: boot.fat_offset,
            fat_sectors: boot.fat_length,
            // VolumeFlags bit 0 selects the FAT in use; a volume with one
            // FAT always uses the first.
            active_fat: if boot.number_of_fats > 1 {
                (boot.volume_flags & 1) as u8
            } else {
                0
            },
            heap_start: boot.cluster_heap_offset,
        })
    }

    fn check_scratch(dev: &D) -> Result<(), Error<D::Error>> {
        let ss = dev.sector_size() as usize;
        if !(512..=4096).contains(&ss) || !ss.is_power_of_two() {
            return Err(Error::NotExfat);
        }
        if SECTOR < ss {
            return Err(Error::ScratchTooSmall {
                needed: ss,
                got: SECTOR,
            });
        }
        Ok(())
    }

    fn read_raw(dev: &mut D, lba: u64, buf: &mut [u8]) -> Result<(), Error<D::Error>> {
        let ss = dev.sector_size() as u64;
        if lba.saturating_add(buf.len() as u64 / ss) > dev.sector_count() {
            return Err(Error::VolumeExceedsDevice);
        }
        dev.read_sectors(lba, buf).map_err(Error::Io)
    }

    /// Walk the root directory for the volume's own metadata entries: the
    /// allocation bitmap and the up-case table.
    ///
    /// Both are ordinary streams described by ordinary directory entries,
    /// which is why this is the first thing a mount does.
    fn scan_root_metadata(&mut self) -> Result<(), Error<D::Error>> {
        let root = Stream::dir(self.geom.root_cluster, u64::MAX);
        let mut pos = 0u64;
        let mut slots = 0u64;
        // A directory cannot be longer than the volume; the bound stops a
        // cyclic chain rather than trusting one.
        let max_slots = self.geom.cluster_count as u64
            * (self.geom.cluster_bytes() as u64 / layout::ENTRY_SIZE as u64);
        while slots <= max_slots {
            let Some(slot) = self.read_slot(&root, pos)? else {
                break;
            };
            match slot[0] {
                0 => break,
                layout::ENTRY_ALLOCATION_BITMAP => {
                    // Bit 0 of the flags byte selects which of a TexFAT
                    // volume's two bitmaps this is; take the active one.
                    let which = slot[1] & 1;
                    if which == self.geom.active_fat && self.bitmap.is_none() {
                        let first = layout::le32(&slot, 20);
                        let len = layout::le64(&slot, 24);
                        if self.geom.is_data_cluster(first) {
                            self.bitmap = Some(Stream {
                                first_cluster: first,
                                len,
                                contiguous: slot[1] & layout::SECFLAG_NO_FAT_CHAIN != 0,
                            });
                        }
                    }
                }
                layout::ENTRY_UPCASE_TABLE => {
                    if self.upcase.is_none() {
                        let first = layout::le32(&slot, 20);
                        let len = layout::le64(&slot, 24);
                        if self.geom.is_data_cluster(first) {
                            self.upcase = Some(Stream {
                                first_cluster: first,
                                len,
                                contiguous: slot[1] & layout::SECFLAG_NO_FAT_CHAIN != 0,
                            });
                        }
                    }
                }
                // Skip a file set's secondary entries in one step so their
                // bytes are never mistaken for a metadata entry.
                layout::ENTRY_FILE => {
                    pos += slot[1] as u64 * layout::ENTRY_SIZE as u64;
                    slots += slot[1] as u64;
                }
                _ => {}
            }
            pos += layout::ENTRY_SIZE as u64;
            slots += 1;
        }
        // The bitmap's length has to cover every cluster, or the allocator
        // would read outside it.
        if let Some(b) = self.bitmap
            && b.len < (self.geom.cluster_count as u64).div_ceil(8)
        {
            self.bitmap = None;
        }
        Ok(())
    }

    /// Read the up-case table's ASCII range into the volume.
    fn load_upcase_ascii(&mut self) -> Result<(), Error<D::Error>> {
        let Some(table) = self.upcase else {
            return Ok(());
        };
        let mut index = 0usize;
        let mut off = 0u64;
        // The table is a u16 stream in which 0xFFFF introduces an identity
        // run; decoding stops as soon as the ASCII range is covered.
        while index < UP_ASCII && off + 2 <= table.len {
            let v = self.stream_u16(&table, off)?;
            off += 2;
            if v == 0xFFFF {
                if off + 2 > table.len {
                    break;
                }
                let count = self.stream_u16(&table, off)? as usize;
                off += 2;
                for _ in 0..count {
                    if index >= UP_ASCII {
                        break;
                    }
                    self.up_ascii[index] = index as u16;
                    index += 1;
                }
            } else {
                self.up_ascii[index] = v;
                index += 1;
            }
        }
        Ok(())
    }

    // -- accessors --------------------------------------------------------

    /// The validated layout.
    pub fn geometry(&self) -> &Geometry {
        &self.geom
    }

    /// Bytes in one cluster — the volume's allocation granularity.
    pub fn cluster_bytes(&self) -> u32 {
        self.geom.cluster_bytes()
    }

    /// Total capacity of the data region in bytes.
    pub fn total_bytes(&self) -> u64 {
        self.geom.total_bytes()
    }

    /// Whether the volume can be written: every write path needs the
    /// allocation bitmap.
    pub fn is_writable(&self) -> bool {
        self.bitmap.is_some()
    }

    /// Borrow the driver.
    pub fn driver(&self) -> &D {
        &self.dev
    }

    /// Mutably borrow the driver.
    pub fn driver_mut(&mut self) -> &mut D {
        &mut self.dev
    }

    /// Set the timestamp stamped on entries created or modified from here
    /// on. The driver has no clock of its own.
    pub fn set_time(&mut self, now: Timestamp) {
        self.now = now;
    }

    /// The timestamp currently being stamped.
    pub fn time(&self) -> Timestamp {
        self.now
    }

    /// Bytes of up-case table currently held in memory.
    ///
    /// Always `0` in a build without `alloc`, where a comparison of two
    /// names that differ outside ASCII walks the table on the card. With a
    /// heap the table is decoded once and kept, which is the only
    /// difference the feature makes to this driver: the same calls give the
    /// same answers, with far fewer reads.
    pub fn upcase_cache_bytes(&self) -> usize {
        #[cfg(feature = "alloc")]
        {
            self.up_cache.as_ref().map_or(0, |t| t.len() * 2)
        }
        #[cfg(not(feature = "alloc"))]
        {
            0
        }
    }

    /// Write back the cached sector and the driver's own cache.
    pub fn flush(&mut self) -> Result<(), Error<D::Error>> {
        self.flush_cache()?;
        self.dev.flush().map_err(Error::Io)
    }

    /// Flush and give the card back.
    pub fn unmount(mut self) -> Result<D, Error<D::Error>> {
        self.flush()?;
        // The volume has no destructor of its own, so the driver moves out
        // by destructuring — which drops what is left rather than leaking
        // it.
        let Self { dev, .. } = self;
        Ok(dev)
    }

    // -- the single-sector cache ------------------------------------------

    fn bps(&self) -> usize {
        self.geom.bytes_per_sector as usize
    }

    /// Refuse an LBA outside the volume.
    fn check_lba(&self, lba: u64) -> Result<(), Error<D::Error>> {
        let end = self.geom.part_start + self.geom.volume_sectors;
        if lba < self.geom.part_start || lba >= end {
            return Err(Error::CorruptChain);
        }
        Ok(())
    }

    /// Load absolute `lba` into the scratch buffer.
    fn load(&mut self, lba: u64) -> Result<(), Error<D::Error>> {
        self.check_lba(lba)?;
        if self.cache_lba == Some(lba) {
            return Ok(());
        }
        self.flush_cache()?;
        let n = self.bps();
        self.dev
            .read_sectors(lba, &mut self.buf[..n])
            .map_err(Error::Io)?;
        self.cache_lba = Some(lba);
        Ok(())
    }

    /// The cached copy of `lba`, for reading.
    fn sector(&mut self, lba: u64) -> Result<&[u8], Error<D::Error>> {
        self.load(lba)?;
        let n = self.bps();
        Ok(&self.buf[..n])
    }

    /// The cached copy of `lba`, marked dirty.
    fn sector_mut(&mut self, lba: u64) -> Result<&mut [u8], Error<D::Error>> {
        self.load(lba)?;
        self.cache_dirty = true;
        let n = self.bps();
        Ok(&mut self.buf[..n])
    }

    fn flush_cache(&mut self) -> Result<(), Error<D::Error>> {
        if self.cache_dirty {
            if let Some(lba) = self.cache_lba {
                let n = self.bps();
                self.dev
                    .write_sectors(lba, &self.buf[..n])
                    .map_err(Error::Io)?;
            }
            self.cache_dirty = false;
        }
        Ok(())
    }

    /// Drop the cached sector after writing it back — used before
    /// bypassing the cache for a bulk transfer that may cover it.
    fn invalidate(&mut self, first: u64, count: u64) -> Result<(), Error<D::Error>> {
        if let Some(lba) = self.cache_lba
            && lba >= first
            && lba < first + count
        {
            self.flush_cache()?;
            self.cache_lba = None;
        }
        Ok(())
    }

    /// Read whole sectors straight into the caller's buffer, going around
    /// the one-sector cache.
    fn read_sectors_direct(&mut self, first: u64, buf: &mut [u8]) -> Result<(), Error<D::Error>> {
        let count = (buf.len() / self.bps()) as u64;
        self.check_lba(first)?;
        self.check_lba(first + count - 1)?;
        self.invalidate(first, count)?;
        self.dev.read_sectors(first, buf).map_err(Error::Io)
    }

    /// Write whole sectors straight from the caller's buffer.
    fn write_sectors_direct(&mut self, first: u64, buf: &[u8]) -> Result<(), Error<D::Error>> {
        let count = (buf.len() / self.bps()) as u64;
        self.check_lba(first)?;
        self.check_lba(first + count - 1)?;
        self.invalidate(first, count)?;
        self.dev.write_sectors(first, buf).map_err(Error::Io)
    }

    // -- the FAT ----------------------------------------------------------

    /// Read `cluster`'s FAT entry.
    fn fat_entry(&mut self, cluster: u32) -> Result<u32, Error<D::Error>> {
        if !self.geom.is_data_cluster(cluster) {
            return Err(Error::CorruptChain);
        }
        let bps = self.bps() as u64;
        let off = cluster as u64 * 4;
        if off / bps >= self.geom.fat_sectors as u64 {
            return Err(Error::CorruptChain);
        }
        let lba = self.geom.fat_first_sector() + off / bps;
        let at = (off % bps) as usize;
        let s = self.sector(lba)?;
        Ok(layout::le32(s, at))
    }

    /// Set `cluster`'s FAT entry.
    fn set_fat_entry(&mut self, cluster: u32, value: u32) -> Result<(), Error<D::Error>> {
        if !self.geom.is_data_cluster(cluster) {
            return Err(Error::CorruptChain);
        }
        let bps = self.bps() as u64;
        let off = cluster as u64 * 4;
        if off / bps >= self.geom.fat_sectors as u64 {
            return Err(Error::CorruptChain);
        }
        let lba = self.geom.fat_first_sector() + off / bps;
        let at = (off % bps) as usize;
        let s = self.sector_mut(lba)?;
        s[at..at + 4].copy_from_slice(&value.to_le_bytes());
        // Any chain the cursor remembered may have just changed shape.
        self.walk = None;
        Ok(())
    }

    /// The cluster after `cluster` in its chain, or `None` at the end.
    fn next_cluster(&mut self, cluster: u32) -> Result<Option<u32>, Error<D::Error>> {
        match layout::classify(self.fat_entry(cluster)?) {
            FatEntry::Eoc => Ok(None),
            FatEntry::Next(next) if self.geom.is_data_cluster(next) => Ok(Some(next)),
            // Free, bad, or out of range: the chain is broken.
            _ => Err(Error::CorruptChain),
        }
    }

    // -- streams ----------------------------------------------------------

    /// The cluster holding a stream's cluster-sized block `index`.
    fn stream_cluster(&mut self, s: &Stream, index: u32) -> Result<Option<u32>, Error<D::Error>> {
        if s.first_cluster < 2 {
            return Ok(None);
        }
        if s.contiguous {
            let c = s
                .first_cluster
                .checked_add(index)
                .ok_or(Error::CorruptChain)?;
            return if self.geom.is_data_cluster(c) {
                Ok(Some(c))
            } else {
                Err(Error::CorruptChain)
            };
        }
        // Continue from the cursor when it is already part-way there.
        let (mut cluster, mut at) = match self.walk {
            Some((first, i, c)) if first == s.first_cluster && i <= index => (c, i),
            _ => (s.first_cluster, 0),
        };
        if !self.geom.is_data_cluster(cluster) {
            return Err(Error::CorruptChain);
        }
        while at < index {
            match self.next_cluster(cluster)? {
                Some(next) => {
                    cluster = next;
                    at += 1;
                }
                None => return Ok(None),
            }
            // A chain cannot be longer than the volume has clusters.
            if at > self.geom.cluster_count {
                return Err(Error::CorruptChain);
            }
        }
        self.walk = Some((s.first_cluster, at, cluster));
        Ok(Some(cluster))
    }

    /// Absolute LBA and in-sector offset of byte `off` of a stream.
    fn stream_pos(&mut self, s: &Stream, off: u64) -> Result<(u64, usize), Error<D::Error>> {
        let cb = self.geom.cluster_bytes() as u64;
        let index = (off / cb) as u32;
        let in_cluster = off % cb;
        let cluster = self.stream_cluster(s, index)?.ok_or(Error::CorruptChain)?;
        let bps = self.bps() as u64;
        let lba = self.geom.cluster_first_sector(cluster) + in_cluster / bps;
        Ok((lba, (in_cluster % bps) as usize))
    }

    /// Read a little-endian `u16` out of a stream.
    fn stream_u16(&mut self, s: &Stream, off: u64) -> Result<u16, Error<D::Error>> {
        let (lba, at) = self.stream_pos(s, off)?;
        let bps = self.bps();
        if at + 2 <= bps {
            let sec = self.sector(lba)?;
            return Ok(layout::le16(sec, at));
        }
        // Straddles two sectors, which a table whose length is odd can do.
        let lo = self.sector(lba)?[at];
        let (lba2, at2) = self.stream_pos(s, off + 1)?;
        let hi = self.sector(lba2)?[at2];
        Ok(u16::from_le_bytes([lo, hi]))
    }

    /// Read one 32-byte directory slot at byte `off` of a directory stream,
    /// or `None` past its end.
    ///
    /// Entries are 32 bytes and sectors are a multiple of that, so a slot
    /// never straddles two sectors.
    fn read_slot(
        &mut self,
        dir: &Stream,
        off: u64,
    ) -> Result<Option<[u8; layout::ENTRY_SIZE]>, Error<D::Error>> {
        if dir.len != u64::MAX && off + layout::ENTRY_SIZE as u64 > dir.len {
            return Ok(None);
        }
        let cb = self.geom.cluster_bytes() as u64;
        let index = (off / cb) as u32;
        if self.stream_cluster(dir, index)?.is_none() {
            return Ok(None);
        }
        let (lba, at) = self.stream_pos(dir, off)?;
        let sec = self.sector(lba)?;
        let mut out = [0u8; layout::ENTRY_SIZE];
        out.copy_from_slice(&sec[at..at + layout::ENTRY_SIZE]);
        Ok(Some(out))
    }

    /// Write one 32-byte directory slot.
    fn write_slot(
        &mut self,
        dir: &Stream,
        off: u64,
        slot: &[u8; layout::ENTRY_SIZE],
    ) -> Result<(), Error<D::Error>> {
        let (lba, at) = self.stream_pos(dir, off)?;
        let sec = self.sector_mut(lba)?;
        sec[at..at + layout::ENTRY_SIZE].copy_from_slice(slot);
        Ok(())
    }

    // -- the allocation bitmap --------------------------------------------

    /// The bitmap stream, or an error when the volume has none.
    fn bitmap(&self) -> Result<Stream, Error<D::Error>> {
        self.bitmap.ok_or(Error::NoAllocationBitmap)
    }

    /// Error unless the volume has a readable allocation bitmap.
    ///
    /// Every write path starts here: the bitmap is the only record of which
    /// clusters a `NoFatChain` file owns, so without one the allocator
    /// cannot tell free space from live data — and a volume that cannot be
    /// allocated on cannot be modified at all.
    pub(super) fn require_bitmap(&self) -> Result<(), Error<D::Error>> {
        if self.bitmap.is_some() {
            Ok(())
        } else {
            Err(Error::NoAllocationBitmap)
        }
    }

    /// Claim one free cluster, marking it allocated in the bitmap and ending
    /// its chain in the FAT. Linked after `prev` when given.
    ///
    /// The cluster's contents are left as they were.
    fn alloc_cluster(&mut self, prev: Option<u32>) -> Result<u32, Error<D::Error>> {
        let (first, _) = self.alloc_run(prev, 1)?;
        Ok(first)
    }

    /// Claim up to `want` *consecutive* free clusters in one go, and return
    /// the first and how many were taken.
    ///
    /// Runs matter for more than fragmentation: with a single sector of
    /// scratch, marking one cluster at a time would evict the bitmap sector
    /// for the FAT sector and back on every cluster — two writes each — so
    /// a 200 KB file would cost a hundred. A run touches each of the two
    /// once.
    fn alloc_run(&mut self, prev: Option<u32>, want: u64) -> Result<(u32, u64), Error<D::Error>> {
        let bm = self.bitmap()?;
        let last_cluster = self.geom.cluster_count + 1;
        let mut cursor = self.next_free.clamp(2, last_cluster);
        let mut scanned = 0u32;

        while scanned <= self.geom.cluster_count {
            // Find the next cluster the bitmap says is free, a byte at a
            // time: a byte of 0xff is eight clusters skipped at once.
            let bit = (cursor - 2) as u64;
            let (lba, at) = self.stream_pos(&bm, bit / 8)?;
            let byte = self.sector(lba)?[at];
            if byte == 0xff {
                let step = 8 - (bit % 8) as u32;
                cursor = cursor.saturating_add(step);
                scanned += step;
            } else if byte & (1u8 << (bit % 8)) != 0 {
                cursor += 1;
                scanned += 1;
            } else {
                // Extend the run while the bitmap keeps saying free.
                let mut count = 1u64;
                while count < want {
                    let next = cursor as u64 + count;
                    if next > last_cluster as u64 {
                        break;
                    }
                    let nbit = next - 2;
                    let (lba, at) = self.stream_pos(&bm, nbit / 8)?;
                    if self.sector(lba)?[at] & (1u8 << (nbit % 8)) != 0 {
                        break;
                    }
                    count += 1;
                }
                // The FAT has the last word on whether those clusters are
                // really free: a stale bitmap must not hand out live data.
                // Its entries are consecutive, so this is one cached
                // sector's worth of reads per 128 clusters.
                let mut usable = 0u64;
                while usable < count {
                    let c = cursor + usable as u32;
                    if self.fat_entry(c)? != layout::FAT_FREE {
                        break;
                    }
                    usable += 1;
                }
                if usable == 0 {
                    // The bitmap and the FAT disagree here; step over it.
                    cursor += 1;
                    scanned += 1;
                    continue;
                }
                let first = cursor;
                // Link the run in the FAT — every entry in one place — then
                // mark the bitmap, which is a different sector entirely.
                for i in 0..usable {
                    let c = first + i as u32;
                    let value = if i + 1 == usable {
                        layout::FAT_EOC
                    } else {
                        c + 1
                    };
                    self.set_fat_entry(c, value)?;
                }
                if let Some(prev) = prev {
                    self.set_fat_entry(prev, first)?;
                }
                self.mark_run(first, usable, true)?;
                self.next_free = if first as u64 + usable > last_cluster as u64 {
                    2
                } else {
                    first + usable as u32
                };
                return Ok((first, usable));
            }
            if cursor > last_cluster {
                cursor = 2;
            }
        }
        Err(Error::NoSpace)
    }

    /// Set or clear the bitmap bits of a run of clusters, whole bytes at a
    /// time where the run covers them.
    fn mark_run(&mut self, first: u32, count: u64, used: bool) -> Result<(), Error<D::Error>> {
        let bm = self.bitmap()?;
        let mut done = 0u64;
        while done < count {
            let cluster = first as u64 + done;
            if cluster > self.geom.cluster_count as u64 + 1 {
                return Err(Error::CorruptChain);
            }
            let bit = cluster - 2;
            let (lba, at) = self.stream_pos(&bm, bit / 8)?;
            let in_byte = (bit % 8) as u32;
            let bits = (8 - in_byte as u64).min(count - done);
            let mask = if bits == 8 {
                0xffu8
            } else {
                (((1u16 << bits) - 1) as u8) << in_byte
            };
            let sec = self.sector_mut(lba)?;
            if used {
                sec[at] |= mask;
            } else {
                sec[at] &= !mask;
            }
            done += bits;
        }
        if !used {
            self.next_free = self.next_free.min(first);
        }
        Ok(())
    }

    /// Allocate a cluster and zero every byte of it — what a new directory
    /// needs, since a directory's end is marked by a zeroed entry.
    fn alloc_zeroed_cluster(&mut self, prev: Option<u32>) -> Result<u32, Error<D::Error>> {
        let cluster = self.alloc_cluster(prev)?;
        self.zero_cluster(cluster)?;
        Ok(cluster)
    }

    /// Zero a whole cluster, through the sector cache.
    fn zero_cluster(&mut self, cluster: u32) -> Result<(), Error<D::Error>> {
        let first = self.geom.cluster_first_sector(cluster);
        for i in 0..self.geom.sectors_per_cluster as u64 {
            let sec = self.sector_mut(first + i)?;
            sec.fill(0);
        }
        Ok(())
    }

    /// Free `cluster` and every cluster after it in its FAT chain.
    ///
    /// The bitmap bits are cleared a *run* at a time: a chain is usually
    /// consecutive, and with one sector of scratch, clearing one bit per
    /// cluster would evict the FAT sector for the bitmap sector and back on
    /// every step.
    fn free_chain(&mut self, cluster: u32) -> Result<(), Error<D::Error>> {
        let mut cur = cluster;
        let mut run_start = cluster;
        let mut run = 0u64;
        let mut freed = 0u32;
        loop {
            if !self.geom.is_data_cluster(cur) {
                return Err(Error::CorruptChain);
            }
            let entry = self.fat_entry(cur)?;
            self.set_fat_entry(cur, layout::FAT_FREE)?;
            if cur as u64 == run_start as u64 + run {
                run += 1;
            } else {
                self.mark_run(run_start, run, false)?;
                run_start = cur;
                run = 1;
            }
            freed += 1;
            if freed > self.geom.cluster_count {
                return Err(Error::CorruptChain);
            }
            match layout::classify(entry) {
                FatEntry::Next(next) if self.geom.is_data_cluster(next) => cur = next,
                FatEntry::Eoc | FatEntry::Free => break,
                _ => return Err(Error::CorruptChain),
            }
        }
        self.mark_run(run_start, run, false)
    }

    /// Free `count` contiguous clusters starting at `first` — what a
    /// `NoFatChain` stream owns.
    fn free_run(&mut self, first: u32, count: u64) -> Result<(), Error<D::Error>> {
        if count == 0 {
            return Ok(());
        }
        let last = first as u64 + count - 1;
        if last > u32::MAX as u64 || !self.geom.is_data_cluster(last as u32) {
            return Err(Error::CorruptChain);
        }
        self.mark_run(first, count, false)
    }

    /// Release whatever a stream owns, chained or contiguous.
    fn free_stream(&mut self, s: &Stream) -> Result<(), Error<D::Error>> {
        if s.first_cluster < 2 {
            return Ok(());
        }
        if s.contiguous {
            let cb = self.geom.cluster_bytes() as u64;
            let clusters = s.len.div_ceil(cb).max(1);
            self.free_run(s.first_cluster, clusters)
        } else {
            self.free_chain(s.first_cluster)
        }
    }

    /// Clusters currently allocated, counted out of the bitmap.
    pub fn used_clusters(&mut self) -> Result<u32, Error<D::Error>> {
        let bm = self.bitmap()?;
        let count = self.geom.cluster_count;
        let bytes = (count as u64).div_ceil(8);
        let mut used = 0u32;
        let mut off = 0u64;
        while off < bytes {
            let (lba, at) = self.stream_pos(&bm, off)?;
            let bps = self.bps();
            let sec = self.sector(lba)?;
            // Count whole sectors of the bitmap at a time.
            let n = ((bytes - off) as usize).min(bps - at);
            for &b in &sec[at..at + n] {
                used += b.count_ones();
            }
            off += n as u64;
        }
        // The last byte may cover clusters past the end of the volume.
        Ok(used.min(count))
    }

    /// Clusters the volume has left.
    pub fn free_clusters(&mut self) -> Result<u32, Error<D::Error>> {
        Ok(self.geom.cluster_count - self.used_clusters()?)
    }

    /// Capacity figures in `statfs` shape: clusters as the allocation unit,
    /// free clusters counted from the allocation bitmap (so the same cost as
    /// [`Self::free_clusters`]), no inodes, and [`MAX_NAME_LEN`] as
    /// `name_max`.
    pub fn statfs(&mut self) -> Result<crate::fs::StatFs, Error<D::Error>> {
        let free = self.free_clusters()? as u64;
        Ok(crate::fs::StatFs {
            block_size: self.geom.cluster_bytes(),
            blocks: self.geom.cluster_count as u64,
            blocks_free: free,
            blocks_avail: free,
            inodes: 0,
            inodes_free: 0,
            name_max: MAX_NAME_LEN as u32,
        })
    }

    /// Free space in bytes.
    pub fn free_bytes(&mut self) -> Result<u64, Error<D::Error>> {
        Ok(self.free_clusters()? as u64 * self.geom.cluster_bytes() as u64)
    }

    // -- the up-case table ------------------------------------------------

    /// Up-case one code unit through the volume's own table.
    fn up(&mut self, ch: u16) -> Result<u16, Error<D::Error>> {
        if (ch as usize) < UP_ASCII {
            return Ok(self.up_ascii[ch as usize]);
        }
        #[cfg(feature = "alloc")]
        {
            if self.up_cache.is_none() {
                self.build_up_cache()?;
            }
            if let Some(t) = &self.up_cache {
                return Ok(t.get(ch as usize).copied().unwrap_or(ch));
            }
        }
        self.up_on_disk(ch)
    }

    /// Walk the table on the card to up-case one code unit.
    ///
    /// The table may be run-length compressed, so there is no way to index
    /// it: reaching entry `ch` means decoding everything before it. Only
    /// names that differ outside ASCII get here.
    fn up_on_disk(&mut self, ch: u16) -> Result<u16, Error<D::Error>> {
        let Some(table) = self.upcase else {
            return Ok(ch);
        };
        let want = ch as usize;
        let mut index = 0usize;
        let mut off = 0u64;
        while off + 2 <= table.len {
            let v = self.stream_u16(&table, off)?;
            off += 2;
            if v == 0xFFFF {
                if off + 2 > table.len {
                    break;
                }
                let count = self.stream_u16(&table, off)? as usize;
                off += 2;
                // An identity run: every unit in it maps to itself.
                if want < index + count {
                    return Ok(ch);
                }
                index += count;
            } else {
                if index == want {
                    return Ok(v);
                }
                index += 1;
            }
            if index > want {
                break;
            }
        }
        // Past the end of the table, a unit maps to itself.
        Ok(ch)
    }

    /// Decode the whole table into memory, which turns every later lookup
    /// into an index.
    #[cfg(feature = "alloc")]
    fn build_up_cache(&mut self) -> Result<(), Error<D::Error>> {
        let Some(table) = self.upcase else {
            self.up_cache = Some(::alloc::vec::Vec::new());
            return Ok(());
        };
        let mut out: ::alloc::vec::Vec<u16> = ::alloc::vec::Vec::new();
        // A table covers at most the BMP; the cap bounds a malformed one.
        if out
            .try_reserve_exact((table.len as usize / 2).min(0x1_0000))
            .is_err()
        {
            // No memory for the cache: the on-disk walk still works.
            return Ok(());
        }
        let mut off = 0u64;
        while off + 2 <= table.len && out.len() < 0x1_0000 {
            let v = self.stream_u16(&table, off)?;
            off += 2;
            if v == 0xFFFF {
                if off + 2 > table.len {
                    break;
                }
                let count = self.stream_u16(&table, off)? as usize;
                off += 2;
                for _ in 0..count {
                    if out.len() >= 0x1_0000 {
                        break;
                    }
                    let identity = out.len() as u16;
                    out.push(identity);
                }
            } else {
                out.push(v);
            }
        }
        self.up_cache = Some(out);
        Ok(())
    }

    /// The NameHash exFAT stores for a name: the rolling checksum of its
    /// up-cased code units.
    fn name_hash(&mut self, name: &str) -> Result<u16, Error<D::Error>> {
        let mut hash = 0u16;
        for unit in name.encode_utf16() {
            hash = layout::name_hash_step(hash, self.up(unit)?);
        }
        Ok(hash)
    }
}
