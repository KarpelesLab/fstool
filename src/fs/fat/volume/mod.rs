//! FAT12 / FAT16 / FAT32 with no allocator.
//!
//! This is a second, independent FAT driver. [`crate::fs::fat`] is the
//! hosted one: it holds the whole allocation table in a `Vec`, stages
//! writes in memory, hands back `String` names, and speaks the crate's
//! [`Filesystem`](crate::fs::Filesystem) trait. That design is right for
//! building images on a machine with a heap and wrong for a
//! microcontroller, so none of it is reused here. Instead:
//!
//! * **No allocation, anywhere.** Every buffer is a fixed-size array or
//!   comes from the caller. With `default-features = false, features =
//!   ["fat"]` the crate compiles and links on a target with no global
//!   allocator at all; the hosted driver appears only when `alloc` is
//!   also on.
//! * **The FAT stays on the card.** Entries are read (and written) one
//!   sector at a time through a single-sector write-back cache, so mounting
//!   a 32 GB volume costs one sector of RAM, not the four megabytes its
//!   table would occupy.
//! * **A driver, not a block device.** [`SectorDriver`] — from
//!   [`crate::device`], the layer below the filesystems, and shared with
//!   [`fs::exfat`](crate::fs::exfat) — is what you implement over your
//!   SD/eMMC peripheral. It carries an associated error type, unlike
//!   [`crate::block::SectorIo`], whose signatures return a `crate::Error`
//!   that owns a `String`.
//!
//! Reads and writes are both supported: open, read, seek, append, extend,
//! truncate, create and remove files, create and remove directories, and
//! list directories with long names. Volumes are mounted whole or from an
//! MBR partition.
//!
//! # Shape of the API
//!
//! There is no interior mutability and no heap, so the volume owns the
//! device and every handle is a plain `Copy` value that borrows nothing.
//! Operations on a handle therefore take the volume back:
//!
//! ```
//! # use fstool::device::SectorDriver;
//! # use fstool::fs::fat::{Error, Volume};
//! # struct RamCard([u8; 0]);
//! # impl SectorDriver for RamCard {
//! #     type Error = core::convert::Infallible;
//! #     fn sector_size(&self) -> u32 { 512 }
//! #     fn sector_count(&self) -> u64 { 0 }
//! #     fn read_sectors(&mut self, _: u64, _: &mut [u8]) -> Result<(), Self::Error> { Ok(()) }
//! #     fn write_sectors(&mut self, _: u64, _: &[u8]) -> Result<(), Self::Error> { Ok(()) }
//! # }
//! # fn demo(card: RamCard) -> Result<(), Error<core::convert::Infallible>> {
//! let mut vol = Volume::<_, 512>::mount_auto(card)?;
//!
//! // Read a config file into a fixed buffer.
//! let mut file = vol.open_file("/config/wifi.txt")?;
//! let mut buf = [0u8; 256];
//! let n = file.read(&mut vol, &mut buf)?;
//!
//! // Append a line to a log, creating it if needed.
//! let mut log = vol.open_or_create_file("/log.txt")?;
//! log.seek_to_end(&mut vol)?;
//! log.write_all(&mut vol, b"booted\n")?;
//! log.flush(&mut vol)?;          // metadata + cached sector + device
//!
//! // List a directory. The iterator owns the name buffer, so entries
//! // borrow from it and this is a `while let`, not a `for`.
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
//! * The volume's declared sector size must equal the driver's; a
//!   mismatch is [`Error::SectorSizeMismatch`] rather than a bounce-buffer
//!   layer. Both are 512 on every SD card.
//! * `SECTOR`, the const parameter, is the scratch buffer's size and must
//!   be at least the sector size. Use `Volume::<_, 512>` unless you have
//!   4 KiB-sector media.
//! * Names are matched case-insensitively over ASCII only, like the hosted
//!   driver: a volume whose names differ only in the case of a non-ASCII
//!   letter can hold both.
//! * A [`File`] caches the location of its directory entry, so removing or
//!   re-creating a path while a handle to it is open is a bug the driver
//!   cannot detect.
//! * Extended MBR containers are not walked; only the four primary slots.

mod boot;
mod dir;
mod file;
mod format;

pub use boot::{Geometry, MAX_SECTOR_SIZE, MIN_SECTOR_SIZE};
pub use dir::{DirEntry, DirIter};
pub use file::{File, MAX_FILE_LEN};
pub use format::FormatOpts;

/// The storage this driver is written against.
///
/// It lives in [`crate::device`], which is where a consumer implementing it
/// should look: the same trait serves [`fs::exfat`](crate::fs::exfat), so one
/// card driver mounts either filesystem. This re-export is kept because the
/// trait was published here first — rustc ignores `#[deprecated]` on a
/// re-export, so there is no warning to be had, only this note.
pub use crate::device::SectorDriver;

use crate::device::{gpt, mbr};

/// Everything that can go wrong, parameterised by the driver's own error.
///
/// No variant owns a heap allocation; the ones that carry detail carry it
/// as numbers or a `&'static str`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error<E> {
    /// The driver failed.
    Io(E),
    /// No FAT volume here: bad signature, or a BPB whose fields contradict
    /// each other.
    NotFat,
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
    /// No MBR, or no such partition slot.
    NoSuchPartition,
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
    /// The name is empty, too long for a long-name entry (255 UTF-16
    /// units), or contains a character FAT reserves.
    InvalidName,
    /// A path is malformed: not absolute, or a component is `.`/`..` where
    /// the driver does not accept one.
    InvalidPath,
    /// The directory is full and cannot be extended (the FAT12/FAT16 fixed
    /// root), or a generated short name could not be made unique.
    DirectoryFull,
    /// The volume has no free cluster left.
    NoSpace,
    /// A FAT entry in a chain is free, reserved, or out of range — the
    /// volume needs `fsck`.
    CorruptChain,
    /// FAT stores sizes in 32 bits; this operation would exceed 4 GiB - 1.
    FileTooLarge,
    /// A seek or write past the 4 GiB file-size ceiling.
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
            Error::NotFat => f.write_str("not a FAT volume"),
            Error::SectorSizeMismatch { volume, driver } => write!(
                f,
                "volume declares {volume}-byte sectors, driver uses {driver}"
            ),
            Error::ScratchTooSmall { needed, got } => {
                write!(f, "scratch buffer is {got} bytes, need {needed}")
            }
            Error::VolumeExceedsDevice => f.write_str("volume runs past the end of the device"),
            Error::NoSuchPartition => f.write_str("no such partition"),
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
            Error::FileTooLarge => f.write_str("file would exceed 4 GiB"),
            Error::InvalidOffset => f.write_str("offset out of range"),
            Error::Unsupported(what) => write!(f, "unsupported: {what}"),
        }
    }
}

#[cfg(feature = "std")]
impl<E: core::fmt::Debug + core::fmt::Display> std::error::Error for Error<E> {}

/// FAT entry width, decided by the volume's data-cluster count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FatKind {
    Fat12,
    Fat16,
    Fat32,
}

impl FatKind {
    /// End-of-chain threshold: an entry at or above this ends the chain.
    fn eoc_floor(&self) -> u32 {
        self.eoc_min()
    }

    /// Value written to terminate a chain.
    fn eoc_mark(&self) -> u32 {
        self.eoc()
    }

    /// Entry width in bits.
    pub fn bits(self) -> u32 {
        match self {
            FatKind::Fat12 => 12,
            FatKind::Fat16 => 16,
            FatKind::Fat32 => 32,
        }
    }

    /// The meaningful bits of one entry — 28 for FAT32, the full width
    /// otherwise.
    pub fn entry_mask(self) -> u32 {
        match self {
            FatKind::Fat12 => 0x0000_0FFF,
            FatKind::Fat16 => 0x0000_FFFF,
            FatKind::Fat32 => 0x0FFF_FFFF,
        }
    }

    /// The end-of-chain value this writer stores (all meaningful bits set).
    pub fn eoc(self) -> u32 {
        self.entry_mask()
    }

    /// Minimum value that counts as an end-of-chain marker.
    pub fn eoc_min(self) -> u32 {
        self.entry_mask() & !0x7
    }

    /// Whether `value` marks the end of a cluster chain.
    pub fn is_eoc(self, value: u32) -> bool {
        value >= self.eoc_min()
    }

    /// The "bad cluster" marker (one below the end-of-chain range).
    pub fn bad_cluster(self) -> u32 {
        self.eoc_min() - 1
    }

    /// Smallest data-cluster count that makes a volume this flavour.
    pub fn min_clusters(self) -> u32 {
        match self {
            FatKind::Fat12 => 1,
            FatKind::Fat16 => 4085,
            FatKind::Fat32 => 65525,
        }
    }

    /// Largest data-cluster count this flavour can address. The cap is one
    /// below the first reserved/bad-cluster value.
    pub fn max_clusters(self) -> u32 {
        match self {
            FatKind::Fat12 => 4084,
            FatKind::Fat16 => 65524,
            FatKind::Fat32 => 0x0FFF_FFF4,
        }
    }

    /// Classify a volume by its data-cluster count, per the FAT
    /// specification's one true rule.
    pub fn from_cluster_count(clusters: u32) -> FatKind {
        if clusters < FatKind::Fat16.min_clusters() {
            FatKind::Fat12
        } else if clusters < FatKind::Fat32.min_clusters() {
            FatKind::Fat16
        } else {
            FatKind::Fat32
        }
    }

    /// Bytes needed on disk to hold `entries` entries (before rounding up
    /// to a whole number of sectors).
    pub fn fat_bytes(self, entries: u64) -> u64 {
        match self {
            // Two entries per three bytes; an odd count still needs the
            // whole trailing pair's second byte.
            FatKind::Fat12 => (entries * 3).div_ceil(2),
            FatKind::Fat16 => entries * 2,
            FatKind::Fat32 => entries * 4,
        }
    }

    /// How many whole entries fit in `bytes` bytes of on-disk FAT.
    pub fn entries_in(self, bytes: usize) -> usize {
        match self {
            FatKind::Fat12 => bytes * 2 / 3,
            FatKind::Fat16 => bytes / 2,
            FatKind::Fat32 => bytes / 4,
        }
    }

    /// The 8-byte `fs_type` string conventionally stored in the BPB. It is
    /// informational only — never used to identify a volume.
    pub fn fs_type_label(self) -> &'static [u8; 8] {
        match self {
            FatKind::Fat12 => b"FAT12   ",
            FatKind::Fat16 => b"FAT16   ",
            FatKind::Fat32 => b"FAT32   ",
        }
    }

    /// Lower-case name used in CLI arguments and diagnostics.
    pub fn as_str(self) -> &'static str {
        match self {
            FatKind::Fat12 => "fat12",
            FatKind::Fat16 => "fat16",
            FatKind::Fat32 => "fat32",
        }
    }
}

/// A FAT timestamp, stored as the on-disk date and time words.
///
/// The driver has no clock. Whatever you hand [`Volume::set_time`] is
/// stamped on entries it creates and files it modifies; the default is the
/// FAT epoch, 1980-01-01 00:00:00.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Timestamp {
    /// Bits 15..9 year since 1980, 8..5 month, 4..0 day.
    pub date: u16,
    /// Bits 15..11 hour, 10..5 minute, 4..0 seconds / 2.
    pub time: u16,
    /// Hundredths of a second, 0..=199 (the odd second plus hundredths).
    pub tenths: u8,
}

impl Timestamp {
    /// The FAT epoch: 1980-01-01 00:00:00.
    pub const EPOCH: Self = Self {
        date: 0x0021,
        time: 0,
        tenths: 0,
    };

    /// Build a timestamp from civil time. Values outside FAT's range are
    /// clamped into it (1980..=2107).
    pub fn from_ymd_hms(year: u16, month: u8, day: u8, hour: u8, min: u8, sec: u8) -> Self {
        let y = year.clamp(1980, 2107) - 1980;
        let mo = month.clamp(1, 12) as u16;
        let d = day.clamp(1, 31) as u16;
        let h = hour.min(23) as u16;
        let mi = min.min(59) as u16;
        let s = sec.min(59) as u16;
        Self {
            date: (y << 9) | (mo << 5) | d,
            time: (h << 11) | (mi << 5) | (s / 2),
            tenths: if s % 2 == 1 { 100 } else { 0 },
        }
    }

    /// Calendar year.
    pub fn year(&self) -> u16 {
        1980 + (self.date >> 9)
    }
    /// Month, 1..=12.
    pub fn month(&self) -> u8 {
        ((self.date >> 5) & 0x0F) as u8
    }
    /// Day of month, 1..=31.
    pub fn day(&self) -> u8 {
        (self.date & 0x1F) as u8
    }
    /// Hour, 0..=23.
    pub fn hour(&self) -> u8 {
        (self.time >> 11) as u8
    }
    /// Minute, 0..=59.
    pub fn minute(&self) -> u8 {
        ((self.time >> 5) & 0x3F) as u8
    }
    /// Second, 0..=59 (two-second resolution plus the `tenths` carry).
    pub fn second(&self) -> u8 {
        ((self.time & 0x1F) * 2) as u8 + u8::from(self.tenths >= 100)
    }
}

/// FAT attribute bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attributes(pub u8);

impl Attributes {
    pub const READ_ONLY: u8 = 0x01;
    pub const HIDDEN: u8 = 0x02;
    pub const SYSTEM: u8 = 0x04;
    pub const VOLUME_ID: u8 = 0x08;
    pub const DIRECTORY: u8 = 0x10;
    pub const ARCHIVE: u8 = 0x20;
    /// The combination that marks a long-name entry rather than a file.
    pub const LONG_NAME: u8 = 0x0F;

    pub fn is_read_only(&self) -> bool {
        self.0 & Self::READ_ONLY != 0
    }
    pub fn is_hidden(&self) -> bool {
        self.0 & Self::HIDDEN != 0
    }
    pub fn is_system(&self) -> bool {
        self.0 & Self::SYSTEM != 0
    }
    pub fn is_volume_id(&self) -> bool {
        self.0 & Self::VOLUME_ID != 0
    }
    pub fn is_dir(&self) -> bool {
        self.0 & Self::DIRECTORY != 0
    }
    pub fn is_archive(&self) -> bool {
        self.0 & Self::ARCHIVE != 0
    }
}

/// Where a 32-byte directory entry lives, so a handle can write its size
/// and first cluster back without searching for it again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EntryLoc {
    /// Volume-relative sector. `0` never holds entries (it is the boot
    /// sector), so it doubles as "no entry" for the root directory.
    pub(crate) sector: u32,
    pub(crate) offset: u16,
}

impl EntryLoc {
    pub(crate) const NONE: Self = Self {
        sector: 0,
        offset: 0,
    };

    pub(crate) fn is_none(&self) -> bool {
        self.sector == 0
    }
}

/// A file or directory's metadata, as recorded in its directory entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Metadata {
    /// Attribute bits.
    pub attrs: Attributes,
    /// Size in bytes. Always 0 for a directory, as FAT stores it.
    pub len: u32,
    /// Creation time.
    pub created: Timestamp,
    /// Last-modification time.
    pub modified: Timestamp,
    pub(crate) first_cluster: u32,
    pub(crate) loc: EntryLoc,
}

impl Metadata {
    /// Whether this is a directory.
    pub fn is_dir(&self) -> bool {
        self.attrs.is_dir()
    }
    /// Whether this is a regular file.
    pub fn is_file(&self) -> bool {
        !self.attrs.is_dir() && !self.attrs.is_volume_id()
    }
    /// Size in bytes.
    pub fn len(&self) -> u32 {
        self.len
    }
    /// Whether the file is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// A directory handle: a `Copy` value naming where the directory's entries
/// live. Obtain one from [`Volume::root`] or [`Volume::open_dir`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dir {
    /// First cluster of the chain, or 0 for the FAT12/16 fixed root.
    pub(crate) first_cluster: u32,
    /// True for the FAT12/FAT16 root, which is a fixed sector range
    /// outside the data area and cannot grow.
    pub(crate) fixed_root: bool,
    /// The directory's own entry, so `create_*` can stamp its mtime. None
    /// for a root.
    pub(crate) loc: EntryLoc,
}

/// A mounted FAT volume that owns its device.
///
/// `SECTOR` is the size of the single sector of scratch RAM the volume
/// keeps; it must be at least the driver's sector size. 512 is right for
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
    /// FSInfo's free-cluster count when the volume had a usable one.
    free_count: Option<u32>,
    /// Where to start looking for a free cluster.
    next_free: u32,
    /// The allocation table, held in memory when there is a heap to hold
    /// it in. Pure optimisation: the same calls give the same answers
    /// without it, just one device transfer per lookup instead of none.
    #[cfg(feature = "alloc")]
    fat_cache: FatCache,
    /// Whether `free_count` / `next_free` have moved since mount.
    fsinfo_dirty: bool,
    /// What to stamp on entries this volume creates or modifies.
    now: Timestamp,
}

impl<D: SectorDriver, const SECTOR: usize> Volume<D, SECTOR> {
    /// Mount the volume that starts at sector 0 of the device.
    pub fn mount(dev: D) -> Result<Self, Error<D::Error>> {
        Self::mount_at(dev, 0)
    }

    /// Mount the volume in 1-based MBR partition `index`.
    pub fn mount_partition(mut dev: D, index: u8) -> Result<Self, Error<D::Error>> {
        let part = Self::partition(&mut dev, index)?;
        Self::mount_at(dev, part.start_lba)
    }

    /// Mount whatever looks like a FAT volume: the whole device if sector 0
    /// is a boot sector, otherwise the first partition that mounts — from a
    /// GPT if the medium has one, from the MBR if not.
    ///
    /// This is what an SD card wants — some are formatted whole, most are
    /// partitioned, and a card that has been through a PC may well carry a
    /// GPT.
    pub fn mount_auto(mut dev: D) -> Result<Self, Error<D::Error>> {
        Self::check_scratch(&dev)?;
        // `SECTOR` is already known to be at least the driver's sector
        // size, so sizing the scratch by it keeps a 512-byte-sector build
        // off a 4 KiB stack frame.
        let mut first = [0u8; SECTOR];
        let ss = dev.sector_size() as usize;
        Self::read_raw(&mut dev, 0, &mut first[..ss])?;

        let device_bytes = Self::device_bytes(&dev);
        if Geometry::parse::<D::Error>(&first[..ss], 0, device_bytes).is_ok() {
            return Self::mount_at(dev, 0);
        }
        // GPT before MBR: a GPT disk carries a protective MBR whose one entry
        // describes the table, not a volume, so walking that first would just
        // waste a read.
        if let Some(table) = gpt::Table::read(&mut dev, &mut first[..ss]).map_err(Error::Io)? {
            // Likely type GUIDs first, then anything else that parses: the
            // GUID is a hint, never the decision.
            for pass in 0..2 {
                for i in 0..table.entries() {
                    let Some(part) = table
                        .entry(&mut dev, &mut first[..ss], i)
                        .map_err(Error::Io)?
                    else {
                        continue;
                    };
                    if (pass == 0) != part.looks_like_fat_family() {
                        continue;
                    }
                    if Self::probe_at(&mut dev, part.start_lba, &mut first[..ss]).is_ok() {
                        return Self::mount_at(dev, part.start_lba);
                    }
                }
            }
            return Err(Error::NotFat);
        }

        Self::read_raw(&mut dev, 0, &mut first[..ss])?;
        if let Some(table) = boot::parse_mbr(&first[..ss]) {
            // FAT-typed slots first, then anything else that parses: the
            // type byte is a hint, never the decision.
            for pass in 0..2 {
                for slot in table.iter().flatten() {
                    if (pass == 0) != slot.looks_like_fat() {
                        continue;
                    }
                    if Self::probe_at(&mut dev, slot.start_lba, &mut first[..ss]).is_ok() {
                        return Self::mount_at(dev, slot.start_lba);
                    }
                }
            }
        }
        Err(Error::NotFat)
    }

    /// Mount the volume whose boot sector is at `start_lba`.
    pub fn mount_at(mut dev: D, start_lba: u64) -> Result<Self, Error<D::Error>> {
        Self::check_scratch(&dev)?;
        let ss = dev.sector_size() as usize;
        let mut sector = [0u8; SECTOR];
        Self::read_raw(&mut dev, start_lba, &mut sector[..ss])?;

        let device_bytes = Self::device_bytes(&dev);
        let geom = Geometry::parse::<D::Error>(&sector[..ss], start_lba, device_bytes)?;
        if geom.bytes_per_sector != dev.sector_size() {
            return Err(Error::SectorSizeMismatch {
                volume: geom.bytes_per_sector,
                driver: dev.sector_size(),
            });
        }

        let mut vol = Self {
            dev,
            geom,
            buf: [0u8; SECTOR],
            cache_lba: None,
            cache_dirty: false,
            free_count: None,
            #[cfg(feature = "alloc")]
            fat_cache: FatCache::default(),
            next_free: 2,
            fsinfo_dirty: false,
            now: Timestamp::EPOCH,
        };
        vol.load_fsinfo()?;
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
        boot::parse_mbr(&sector[..ss])
            .and_then(|t| t[index as usize - 1])
            .ok_or(Error::NoSuchPartition)
    }

    fn probe_at(dev: &mut D, lba: u64, scratch: &mut [u8]) -> Result<Geometry, Error<D::Error>> {
        Self::read_raw(dev, lba, scratch)?;
        let device_bytes = Self::device_bytes(dev);
        Geometry::parse::<D::Error>(scratch, lba, device_bytes)
    }

    fn check_scratch(dev: &D) -> Result<(), Error<D::Error>> {
        let ss = dev.sector_size() as usize;
        if !(MIN_SECTOR_SIZE..=MAX_SECTOR_SIZE).contains(&ss) || !ss.is_power_of_two() {
            return Err(Error::NotFat);
        }
        if SECTOR < ss {
            return Err(Error::ScratchTooSmall {
                needed: ss,
                got: SECTOR,
            });
        }
        Ok(())
    }

    fn device_bytes(dev: &D) -> u64 {
        dev.sector_count().saturating_mul(dev.sector_size() as u64)
    }

    fn read_raw(dev: &mut D, lba: u64, buf: &mut [u8]) -> Result<(), Error<D::Error>> {
        let ss = dev.sector_size() as u64;
        if lba.saturating_add(buf.len() as u64 / ss) > dev.sector_count() {
            return Err(Error::VolumeExceedsDevice);
        }
        dev.read_sectors(lba, buf).map_err(Error::Io)
    }

    // -- accessors ---------------------------------------------------------

    /// The validated layout.
    pub fn geometry(&self) -> &Geometry {
        &self.geom
    }

    /// FAT12, FAT16 or FAT32.
    pub fn kind(&self) -> FatKind {
        self.geom.kind
    }

    /// Bytes in one cluster — the volume's allocation granularity.
    pub fn cluster_bytes(&self) -> u32 {
        self.geom.cluster_bytes()
    }

    /// Total capacity of the data region in bytes.
    pub fn total_bytes(&self) -> u64 {
        self.geom.cluster_count as u64 * self.geom.cluster_bytes() as u64
    }

    /// Borrow the driver.
    pub fn driver(&self) -> &D {
        &self.dev
    }

    /// Mutably borrow the driver.
    pub fn driver_mut(&mut self) -> &mut D {
        &mut self.dev
    }

    /// Flush and give the device back.
    pub fn unmount(mut self) -> Result<D, Error<D::Error>> {
        // Flush first, so a failure is reported rather than swallowed by
        // the `Drop` below; on that path `self` drops normally.
        self.flush()?;

        // Handing the device back means moving it out of a type that
        // implements `Drop`, which only `ManuallyDrop` allows — and that
        // suppresses the drop glue of *every* field, not just the device's.
        // So anything that owns memory has to leave the volume here, by
        // hand, or it is leaked.
        //
        // The pattern below is what keeps that honest: it is exhaustive (no
        // `..`) and binds by reference, which a `Drop` type permits. Add a
        // field and this stops compiling until someone has decided whether
        // it needs releasing above.
        #[cfg(feature = "alloc")]
        drop(core::mem::take(&mut self.fat_cache));
        let Self {
            dev: _,
            geom: _,
            buf: _,
            cache_lba: _,
            cache_dirty: _,
            free_count: _,
            next_free: _,
            #[cfg(feature = "alloc")]
                fat_cache: _,
            fsinfo_dirty: _,
            now: _,
        } = &self;

        let me = core::mem::ManuallyDrop::new(self);
        // SAFETY: `me` is a `ManuallyDrop`, so its destructor never runs
        // and the device is not dropped twice. Nothing reads `me` after
        // this, and every field that owned memory was released above.
        Ok(unsafe { core::ptr::read(&me.dev) })
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

    /// Bytes of allocation table currently held in memory.
    ///
    /// Always `0` in a build without `alloc`, where every lookup reads a
    /// sector from the device. With a heap the table is kept as it is
    /// touched, which is the whole of the difference the feature makes to
    /// this driver: no call changes, no result changes, fewer transfers.
    pub fn fat_cache_bytes(&self) -> usize {
        #[cfg(feature = "alloc")]
        {
            self.fat_cache.bytes_held()
        }
        #[cfg(not(feature = "alloc"))]
        {
            0
        }
    }

    /// The root directory.
    pub fn root(&self) -> Dir {
        Dir {
            first_cluster: if self.geom.kind == FatKind::Fat32 {
                self.geom.root_cluster
            } else {
                0
            },
            fixed_root: self.geom.kind != FatKind::Fat32,
            loc: EntryLoc::NONE,
        }
    }

    // -- the single-sector cache ------------------------------------------

    fn bps(&self) -> usize {
        self.geom.bytes_per_sector as usize
    }

    fn abs(&self, rel_sector: u32) -> u64 {
        self.geom.part_start + rel_sector as u64
    }

    /// Load volume-relative `sector` into the scratch buffer.
    fn load(&mut self, sector: u32) -> Result<(), Error<D::Error>> {
        if sector >= self.geom.total_sectors {
            return Err(Error::CorruptChain);
        }
        let abs = self.abs(sector);
        if self.cache_lba == Some(abs) {
            return Ok(());
        }
        self.flush_cache()?;
        let n = self.bps();
        self.dev
            .read_sectors(abs, &mut self.buf[..n])
            .map_err(Error::Io)?;
        self.cache_lba = Some(abs);
        Ok(())
    }

    /// The cached copy of volume-relative `sector`, for reading.
    fn sector(&mut self, sector: u32) -> Result<&[u8], Error<D::Error>> {
        self.load(sector)?;
        let n = self.bps();
        Ok(&self.buf[..n])
    }

    /// The cached copy of volume-relative `sector`, marked dirty.
    fn sector_mut(&mut self, sector: u32) -> Result<&mut [u8], Error<D::Error>> {
        self.load(sector)?;
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

    /// Refuse a transfer that would run past the end of the volume.
    pub(crate) fn check_range(&self, first: u32, count: u32) -> Result<(), Error<D::Error>> {
        let end = first as u64 + count as u64;
        if end > self.geom.total_sectors as u64 {
            return Err(Error::CorruptChain);
        }
        Ok(())
    }

    /// Drop the cached sector after writing it back — used before bypassing
    /// the cache for a bulk transfer that may cover it.
    fn invalidate(&mut self, first: u32, count: u32) -> Result<(), Error<D::Error>> {
        if let Some(lba) = self.cache_lba {
            let first_abs = self.abs(first);
            if lba >= first_abs && lba < first_abs + count as u64 {
                self.flush_cache()?;
                self.cache_lba = None;
            }
        }
        Ok(())
    }

    /// Write back everything: the cached sector, FSInfo, and the driver.
    pub fn flush(&mut self) -> Result<(), Error<D::Error>> {
        self.flush_cache()?;
        self.store_fsinfo()?;
        self.flush_cache()?;
        self.dev.flush().map_err(Error::Io)
    }

    // -- FAT entries -------------------------------------------------------

    /// Byte offset of `cluster`'s entry within a FAT copy.
    fn fat_offset(&self, cluster: u32) -> u64 {
        match self.geom.kind {
            FatKind::Fat12 => cluster as u64 + (cluster as u64 / 2),
            FatKind::Fat16 => cluster as u64 * 2,
            FatKind::Fat32 => cluster as u64 * 4,
        }
    }

    /// First sector of FAT copy `n`.
    fn fat_start(&self, n: u32) -> u32 {
        self.geom.reserved_sectors + n * self.geom.fat_sectors
    }

    /// One byte of the active FAT.
    fn fat_byte(&mut self, off: u64) -> Result<u8, Error<D::Error>> {
        let bps = self.bps() as u64;
        let sector = self.fat_start(self.geom.active_fat) + (off / bps) as u32;
        let at = (off % bps) as usize;
        #[cfg(feature = "alloc")]
        {
            let rel = (off / bps) as u32;
            if let Some(byte) = self.cached_fat_byte(rel, at)? {
                return Ok(byte);
            }
        }
        Ok(self.sector(sector)?[at])
    }

    /// One byte of the active FAT from the in-memory copy, filling it from
    /// the device on first touch. `None` when this build has no heap.
    #[cfg(feature = "alloc")]
    fn cached_fat_byte(&mut self, rel: u32, at: usize) -> Result<Option<u8>, Error<D::Error>> {
        let bps = self.bps();
        if rel >= self.geom.fat_sectors {
            return Ok(None);
        }
        if !self.fat_cache.holds(rel) {
            // Read it through the sector cache so a pending write to this
            // very sector is seen, then keep the copy.
            let sector = self.fat_start(self.geom.active_fat) + rel;
            let mut tmp = [0u8; SECTOR];
            tmp[..bps].copy_from_slice(self.sector(sector)?);
            self.fat_cache
                .store(rel, &tmp[..bps], self.geom.fat_sectors);
        }
        Ok(self.fat_cache.byte(rel, at, bps))
    }

    /// Read `cluster`'s FAT entry, normalised to its defined bits.
    fn fat_entry(&mut self, cluster: u32) -> Result<u32, Error<D::Error>> {
        if cluster > self.geom.cluster_count + 1 {
            return Err(Error::CorruptChain);
        }
        let off = self.fat_offset(cluster);
        match self.geom.kind {
            FatKind::Fat12 => {
                // A 12-bit entry straddles two bytes, and those two bytes
                // can straddle two sectors.
                let lo = self.fat_byte(off)? as u32;
                let hi = self.fat_byte(off + 1)? as u32;
                let raw = lo | (hi << 8);
                Ok(if cluster & 1 == 0 {
                    raw & 0x0FFF
                } else {
                    raw >> 4
                })
            }
            FatKind::Fat16 => {
                let lo = self.fat_byte(off)? as u32;
                let hi = self.fat_byte(off + 1)? as u32;
                Ok(lo | (hi << 8))
            }
            FatKind::Fat32 => {
                let mut b = [0u8; 4];
                for (i, slot) in b.iter_mut().enumerate() {
                    *slot = self.fat_byte(off + i as u64)?;
                }
                Ok(u32::from_le_bytes(b) & 0x0FFF_FFFF)
            }
        }
    }

    /// Set `cluster`'s FAT entry to `value`.
    ///
    /// The bytes of one entry share a sector (except at a FAT12 straddle),
    /// and a mirrored volume keeps every FAT copy identical. Walking the
    /// copies *outside* the bytes is what keeps that to one cached sector
    /// per copy: the other way round, each byte alternates between copies,
    /// evicting and reloading the single-sector cache every time — eight
    /// sector writes per FAT32 entry instead of one.
    fn set_fat_entry(&mut self, cluster: u32, value: u32) -> Result<(), Error<D::Error>> {
        if !self.geom.is_data_cluster(cluster) {
            return Err(Error::CorruptChain);
        }
        let off = self.fat_offset(cluster);
        // (byte offset, bits kept from the old byte, bits to set).
        let mut edits = [(0u64, 0u8, 0u8); 4];
        let n = match self.geom.kind {
            FatKind::Fat12 => {
                let v = value & 0x0FFF;
                if cluster & 1 == 0 {
                    edits[0] = (off, 0x00, (v & 0xFF) as u8);
                    edits[1] = (off + 1, 0xF0, (v >> 8) as u8 & 0x0F);
                } else {
                    edits[0] = (off, 0x0F, ((v & 0x0F) as u8) << 4);
                    edits[1] = (off + 1, 0x00, (v >> 4) as u8);
                }
                2
            }
            FatKind::Fat16 => {
                let b = ((value & 0xFFFF) as u16).to_le_bytes();
                edits[0] = (off, 0, b[0]);
                edits[1] = (off + 1, 0, b[1]);
                2
            }
            FatKind::Fat32 => {
                // The top four bits are reserved; the spec says preserve
                // them rather than zero them.
                let b = (value & 0x0FFF_FFFF).to_le_bytes();
                edits[0] = (off, 0, b[0]);
                edits[1] = (off + 1, 0, b[1]);
                edits[2] = (off + 2, 0, b[2]);
                edits[3] = (off + 3, 0xF0, b[3] & 0x0F);
                4
            }
        };

        let bps = self.bps() as u64;
        let copies = if self.geom.mirrored {
            0..self.geom.num_fats
        } else {
            self.geom.active_fat..self.geom.active_fat + 1
        };
        for copy in copies {
            for &(at_off, keep, set) in &edits[..n] {
                let sector = self.fat_start(copy) + (at_off / bps) as u32;
                let at = (at_off % bps) as usize;
                let buf = self.sector_mut(sector)?;
                buf[at] = (buf[at] & keep) | set;
            }
        }
        // Keep the in-memory copy in step rather than dropping it: an
        // allocation walk writes and re-reads the same entries constantly.
        #[cfg(feature = "alloc")]
        {
            let bps = self.bps();
            for &(at_off, keep, set) in &edits[..n] {
                let rel = (at_off / bps as u64) as u32;
                let at = (at_off % bps as u64) as usize;
                self.fat_cache.patch(rel, at, keep, set, bps);
            }
        }
        Ok(())
    }

    /// The cluster after `cluster` in its chain, or `None` at the end.
    pub(crate) fn next_cluster(&mut self, cluster: u32) -> Result<Option<u32>, Error<D::Error>> {
        let entry = self.fat_entry(cluster)?;
        if entry >= self.geom.kind.eoc_floor() {
            return Ok(None);
        }
        if !self.geom.is_data_cluster(entry) {
            // 0 (free), 1 (reserved), the bad-cluster mark, or past the
            // end of the volume: the chain is broken.
            return Err(Error::CorruptChain);
        }
        Ok(Some(entry))
    }

    /// Allocate one free cluster, terminate it, and link it after `prev`
    /// when given. The cluster's contents are left as they were.
    pub(crate) fn alloc_cluster(&mut self, prev: Option<u32>) -> Result<u32, Error<D::Error>> {
        let last = self.geom.cluster_count + 1;
        let start = self.next_free.clamp(2, last);
        // One pass from the hint to the end, then from 2 back to the hint.
        let mut found = None;
        for cluster in start..=last {
            if self.fat_entry(cluster)? == 0 {
                found = Some(cluster);
                break;
            }
        }
        if found.is_none() {
            for cluster in 2..start {
                if self.fat_entry(cluster)? == 0 {
                    found = Some(cluster);
                    break;
                }
            }
        }
        let cluster = found.ok_or(Error::NoSpace)?;

        let eoc = self.geom.kind.eoc_mark();
        self.set_fat_entry(cluster, eoc)?;
        if let Some(prev) = prev {
            self.set_fat_entry(prev, cluster)?;
        }
        self.next_free = if cluster >= last { 2 } else { cluster + 1 };
        if let Some(free) = self.free_count.as_mut() {
            *free = free.saturating_sub(1);
        }
        self.fsinfo_dirty = true;
        Ok(cluster)
    }

    /// Allocate a cluster and zero every byte of it — what a new directory
    /// needs, since a directory's end is marked by a zero entry.
    pub(crate) fn alloc_zeroed_cluster(
        &mut self,
        prev: Option<u32>,
    ) -> Result<u32, Error<D::Error>> {
        let cluster = self.alloc_cluster(prev)?;
        let first = self.geom.cluster_first_sector(cluster);
        for i in 0..self.geom.sectors_per_cluster {
            let buf = self.sector_mut(first + i)?;
            buf.fill(0);
        }
        Ok(cluster)
    }

    /// Free `cluster` and everything after it in its chain.
    pub(crate) fn free_chain(&mut self, cluster: u32) -> Result<(), Error<D::Error>> {
        let mut cur = cluster;
        loop {
            if !self.geom.is_data_cluster(cur) {
                return Err(Error::CorruptChain);
            }
            let entry = self.fat_entry(cur)?;
            self.set_fat_entry(cur, 0)?;
            if let Some(free) = self.free_count.as_mut() {
                *free = free.saturating_add(1);
            }
            self.next_free = self.next_free.min(cur);
            self.fsinfo_dirty = true;
            if entry >= self.geom.kind.eoc_floor() {
                return Ok(());
            }
            if !self.geom.is_data_cluster(entry) {
                return Err(Error::CorruptChain);
            }
            cur = entry;
        }
    }

    /// Truncate a chain after `cluster`, freeing the rest.
    pub(crate) fn truncate_chain(&mut self, cluster: u32) -> Result<(), Error<D::Error>> {
        let rest = self.next_cluster(cluster)?;
        let eoc = self.geom.kind.eoc_mark();
        self.set_fat_entry(cluster, eoc)?;
        if let Some(next) = rest {
            self.free_chain(next)?;
        }
        Ok(())
    }

    /// Count the free clusters.
    ///
    /// FAT32 volumes usually record this in FSInfo and it is returned from
    /// there; otherwise the whole FAT is scanned, which on a large volume
    /// is thousands of sector reads.
    pub fn free_clusters(&mut self) -> Result<u32, Error<D::Error>> {
        if let Some(free) = self.free_count {
            return Ok(free);
        }
        let mut free = 0;
        for cluster in 2..=self.geom.cluster_count + 1 {
            if self.fat_entry(cluster)? == 0 {
                free += 1;
            }
        }
        self.free_count = Some(free);
        Ok(free)
    }

    /// Capacity figures in `statfs` shape: clusters as the allocation unit,
    /// free clusters from [`Self::free_clusters`] (so the same cost), no
    /// inodes, and long-name entries' 255-unit limit as `name_max`.
    pub fn statfs(&mut self) -> Result<crate::fs::StatFs, Error<D::Error>> {
        let free = self.free_clusters()? as u64;
        Ok(crate::fs::StatFs {
            block_size: self.cluster_bytes(),
            blocks: self.geom.cluster_count as u64,
            blocks_free: free,
            blocks_avail: free,
            inodes: 0,
            inodes_free: 0,
            name_max: 255,
        })
    }

    /// Free space in bytes, from [`Self::free_clusters`].
    pub fn free_bytes(&mut self) -> Result<u64, Error<D::Error>> {
        Ok(self.free_clusters()? as u64 * self.geom.cluster_bytes() as u64)
    }

    // -- FSInfo ------------------------------------------------------------

    fn load_fsinfo(&mut self) -> Result<(), Error<D::Error>> {
        if self.geom.kind != FatKind::Fat32 || self.geom.fs_info_sector == 0 {
            return Ok(());
        }
        let sector = self.geom.fs_info_sector;
        let buf = self.sector(sector)?;
        let lead = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let struc = u32::from_le_bytes([buf[484], buf[485], buf[486], buf[487]]);
        let trail = u32::from_le_bytes([buf[508], buf[509], buf[510], buf[511]]);
        if lead != 0x4161_5252 || struc != 0x6141_7272 || trail != 0xAA55_0000 {
            return Ok(());
        }
        let free = u32::from_le_bytes([buf[488], buf[489], buf[490], buf[491]]);
        let next = u32::from_le_bytes([buf[492], buf[493], buf[494], buf[495]]);
        // 0xFFFFFFFF means "unknown"; anything past the end of the volume
        // is not to be trusted either.
        let last = self.geom.cluster_count + 1;
        if free != u32::MAX && free <= self.geom.cluster_count {
            self.free_count = Some(free);
        }
        self.next_free = if next >= 2 && next <= last { next } else { 2 };
        Ok(())
    }

    fn store_fsinfo(&mut self) -> Result<(), Error<D::Error>> {
        if !self.fsinfo_dirty || self.geom.kind != FatKind::Fat32 || self.geom.fs_info_sector == 0 {
            return Ok(());
        }
        let free = self.free_count.unwrap_or(u32::MAX);
        let next = self.next_free;
        let sector = self.geom.fs_info_sector;
        let buf = self.sector_mut(sector)?;
        // Only rewrite the two counters, and only if the signatures are
        // there: an unrecognised FSInfo is left exactly as found.
        let lead = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let struc = u32::from_le_bytes([buf[484], buf[485], buf[486], buf[487]]);
        if lead == 0x4161_5252 && struc == 0x6141_7272 {
            buf[488..492].copy_from_slice(&free.to_le_bytes());
            buf[492..496].copy_from_slice(&next.to_le_bytes());
        }
        self.fsinfo_dirty = false;
        Ok(())
    }
}

/// The active FAT, held in memory a sector at a time.
///
/// Only ever a cache of what is on the device: every write goes to the
/// device through the sector cache first and is mirrored here, so dropping
/// this wholesale would cost speed and nothing else.
#[cfg(feature = "alloc")]
#[derive(Debug, Default)]
struct FatCache {
    /// The FAT's sectors, laid out end to end; empty until first use.
    bytes: alloc::vec::Vec<u8>,
    /// Which of them have been read in.
    present: alloc::vec::Vec<bool>,
}

#[cfg(feature = "alloc")]
impl FatCache {
    fn holds(&self, rel: u32) -> bool {
        self.present.get(rel as usize).copied().unwrap_or(false)
    }

    /// Take a copy of one FAT sector, allocating the table on first use.
    ///
    /// A FAT is 4 MiB for a 32 GB card, which is why this fills lazily:
    /// a volume that only ever reads one file touches a handful of
    /// sectors, and pays for a handful.
    fn store(&mut self, rel: u32, sector: &[u8], fat_sectors: u32) {
        if self.bytes.is_empty() {
            let total = fat_sectors as usize * sector.len();
            // A card whose FAT will not fit stays uncached rather than
            // failing: correctness never depends on this.
            if total == 0 || self.bytes.try_reserve_exact(total).is_err() {
                return;
            }
            self.bytes.resize(total, 0);
            self.present.resize(fat_sectors as usize, false);
        }
        let at = rel as usize * sector.len();
        if at + sector.len() <= self.bytes.len() {
            self.bytes[at..at + sector.len()].copy_from_slice(sector);
            self.present[rel as usize] = true;
        }
    }

    fn byte(&self, rel: u32, at: usize, bps: usize) -> Option<u8> {
        if !self.holds(rel) {
            return None;
        }
        self.bytes.get(rel as usize * bps + at).copied()
    }

    /// Apply the same edit the device just took.
    fn patch(&mut self, rel: u32, at: usize, keep: u8, set: u8, bps: usize) {
        if !self.holds(rel) {
            return;
        }
        if let Some(b) = self.bytes.get_mut(rel as usize * bps + at) {
            *b = (*b & keep) | set;
        }
    }

    fn bytes_held(&self) -> usize {
        self.bytes.len()
    }
}

impl<D: SectorDriver, const SECTOR: usize> Drop for Volume<D, SECTOR> {
    /// Write back the cached sector and FSInfo.
    ///
    /// Best effort: a caller who needs to know whether it worked calls
    /// [`Volume::flush`] or [`Volume::unmount`], which report it. Losing
    /// the last write of a session because nobody remembered to flush
    /// would be a worse default than an ignored error here.
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

#[cfg(test)]
pub(crate) mod tests;
