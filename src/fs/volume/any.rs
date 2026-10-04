//! Finding out which filesystem a medium holds, and mounting it as one type.

#[cfg(feature = "exfat")]
use super::exfat::ExfatDirIter;
#[cfg(feature = "fat")]
use super::fat::FatDirIter;
#[cfg(feature = "littlefs")]
use super::littlefs::LittleFsDirIter;
use super::{Entry, ErrorKind, FsType, Metadata, Volume, VolumeDirIter, VolumeError, VolumeFile};
#[cfg(feature = "littlefs")]
use crate::device::SectorFlash;
use crate::device::{SectorDriver, gpt, mbr};
#[cfg(feature = "exfat")]
use crate::fs::exfat;
#[cfg(feature = "fat")]
use crate::fs::fat;
#[cfg(feature = "littlefs")]
use crate::fs::littlefs;

/// A volume [`probe`] recognised, and where.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Found {
    /// Which filesystem.
    pub fs: FsType,
    /// The sector it starts at: 0 for a whole medium, the partition's first
    /// sector otherwise.
    pub start_lba: u64,
    /// Sectors from `start_lba` the volume may occupy: the partition's
    /// length, or the rest of the medium.
    pub sectors: u64,
    /// For littlefs, the block size its superblock records — the one thing
    /// a flash filesystem cannot be mounted without. The sector size for
    /// the others.
    pub block_size: u32,
}

/// Everything [`mount`] and an [`AnyVolume`] can fail with.
///
/// Once a volume is mounted, its driver's own error is carried whole, so no
/// detail is lost to the generic layer: match on the variant, or ask
/// [`VolumeError::kind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AnyError<E> {
    /// The device failed while probing.
    Io(E),
    /// Neither the medium nor any partition on it holds a filesystem this
    /// build can mount.
    NotRecognised,
    /// `SECTOR` is smaller than the device's sector size, or the device's
    /// sector size is not one any driver uses.
    ScratchTooSmall {
        /// The device's sector size.
        needed: usize,
        /// The const parameter the call was instantiated with.
        got: usize,
    },
    /// A littlefs superblock records a block size the medium or `BLOCK`
    /// cannot serve: not a multiple of the sector size, or larger than
    /// the partition.
    BlockSize(u32),
    /// A file or directory handle was used with a volume it did not come
    /// from.
    WrongVolume,
    /// The FAT driver's error.
    #[cfg(feature = "fat")]
    Fat(fat::Error<E>),
    /// The exFAT driver's error.
    #[cfg(feature = "exfat")]
    Exfat(exfat::Error<E>),
    /// The littlefs driver's error.
    #[cfg(feature = "littlefs")]
    LittleFs(littlefs::Error<E>),
}

impl<E> VolumeError for AnyError<E> {
    fn kind(&self) -> ErrorKind {
        match self {
            AnyError::Io(_) => ErrorKind::Io,
            AnyError::NotRecognised => ErrorKind::NotRecognised,
            AnyError::ScratchTooSmall { .. } | AnyError::BlockSize(_) => ErrorKind::Geometry,
            AnyError::WrongVolume => ErrorKind::WrongVolume,
            #[cfg(feature = "fat")]
            AnyError::Fat(e) => e.kind(),
            #[cfg(feature = "exfat")]
            AnyError::Exfat(e) => e.kind(),
            #[cfg(feature = "littlefs")]
            AnyError::LittleFs(e) => e.kind(),
        }
    }
}

impl<E: core::fmt::Display> core::fmt::Display for AnyError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AnyError::Io(e) => write!(f, "device error: {e}"),
            AnyError::NotRecognised => f.write_str("no filesystem recognised"),
            AnyError::ScratchTooSmall { needed, got } => {
                write!(f, "scratch buffer is {got} bytes, need {needed}")
            }
            AnyError::BlockSize(bs) => {
                write!(f, "littlefs block size {bs} does not fit the medium")
            }
            AnyError::WrongVolume => f.write_str("handle belongs to a different volume"),
            #[cfg(feature = "fat")]
            AnyError::Fat(e) => write!(f, "fat: {e}"),
            #[cfg(feature = "exfat")]
            AnyError::Exfat(e) => write!(f, "exfat: {e}"),
            #[cfg(feature = "littlefs")]
            AnyError::LittleFs(e) => write!(f, "littlefs: {e}"),
        }
    }
}

#[cfg(feature = "std")]
impl<E: core::fmt::Debug + core::fmt::Display> std::error::Error for AnyError<E> {}

/// Find the first volume on `dev` that this build can mount, without taking
/// the device.
///
/// The whole medium is tried first — cards are often formatted without a
/// partition table — then each GPT entry in order if there is a GPT, or
/// each MBR slot in order if not. At every candidate start the filesystems
/// compiled in are recognised by their own signatures: the exFAT boot
/// sector, a FAT BPB that validates, a littlefs superblock. A partition's
/// type is never consulted; what is on it decides.
///
/// Probing only reads, one sector at a time through `SECTOR` bytes of
/// stack. A recognised volume can still fail to mount if it is damaged;
/// [`mount_found`] reports that.
pub fn probe<D: SectorDriver, const SECTOR: usize>(
    dev: &mut D,
) -> Result<Option<Found>, AnyError<D::Error>> {
    let ss = dev.sector_size() as usize;
    if SECTOR < ss || !(512..=4096).contains(&ss) || !ss.is_power_of_two() {
        return Err(AnyError::ScratchTooSmall {
            needed: ss,
            got: SECTOR,
        });
    }
    let mut buf = [0u8; SECTOR];
    let sector = &mut buf[..ss];
    let count = dev.sector_count();

    if let Some(found) = detect_at(dev, 0, count, sector)? {
        return Ok(Some(found));
    }

    if let Some(table) = gpt::Table::read(dev, sector).map_err(AnyError::Io)? {
        for i in 0..table.entries() {
            let Some(part) = table.entry(dev, sector, i).map_err(AnyError::Io)? else {
                continue;
            };
            if let Some(found) = detect_at(dev, part.start_lba, part.sectors(), sector)? {
                return Ok(Some(found));
            }
        }
        // A GPT medium's MBR is the protective stub; there is nothing
        // further to look at.
        return Ok(None);
    }

    dev.read_sectors(0, sector).map_err(AnyError::Io)?;
    if let Some(table) = mbr::parse(sector) {
        for slot in table.iter().flatten() {
            if let Some(found) = detect_at(dev, slot.start_lba, slot.sectors, sector)? {
                return Ok(Some(found));
            }
        }
    }
    Ok(None)
}

/// Recognise the volume, if any, whose first sector is `lba`.
fn detect_at<D: SectorDriver>(
    dev: &mut D,
    lba: u64,
    sectors: u64,
    sector: &mut [u8],
) -> Result<Option<Found>, AnyError<D::Error>> {
    let count = dev.sector_count();
    if lba >= count {
        return Ok(None);
    }
    let sectors = sectors.min(count - lba);
    let ss = sector.len() as u32;
    dev.read_sectors(lba, sector).map_err(AnyError::Io)?;
    let found = |fs, block_size| {
        Some(Found {
            fs,
            start_lba: lba,
            sectors,
            block_size,
        })
    };

    #[cfg(feature = "exfat")]
    if exfat::layout::Boot::decode(sector).is_ok() {
        return Ok(found(FsType::Exfat, ss));
    }
    #[cfg(feature = "fat")]
    if fat::Geometry::parse::<()>(sector, lba, count.saturating_mul(ss as u64)).is_ok() {
        return Ok(found(FsType::Fat, ss));
    }
    #[cfg(feature = "littlefs")]
    if let Some(block_size) = littlefs_block_size(sector) {
        return Ok(found(FsType::LittleFs, block_size));
    }
    let _ = (found, ss);
    Ok(None)
}

/// The block size a littlefs superblock at the start of `block` records.
///
/// A metadata block opens with a 4-byte revision count and then its log of
/// tags, each XORed with the one before; the superblock's first commit
/// carries the `"littlefs"` name entry and its inline configuration record
/// — version, block size, block count — well within the first sector.
/// This walks that first commit. It is recognition, not validation: the
/// mount that follows reads the superblock through its metadata pair and
/// checks everything.
#[cfg(feature = "littlefs")]
fn littlefs_block_size(sector: &[u8]) -> Option<u32> {
    use crate::fs::littlefs::tag::{self, Tag};

    let mut off = 4;
    let mut prev = tag::PTAG_INIT;
    let mut magic = false;
    let mut block_size = None;
    while off + 4 <= sector.len() {
        let t = Tag(tag::be32(&sector[off..off + 4]) ^ prev);
        if !t.is_valid() {
            break;
        }
        prev = t.0;
        let data = off + 4;
        let len = if t.is_delete() { 0 } else { t.size() as usize };
        if t.type1() == tag::T1_CRC && t.type3() != tag::TYPE_FCRC {
            // End of the first commit.
            break;
        }
        if data + len > sector.len() {
            break;
        }
        match t.type3() {
            tag::TYPE_SUPERBLOCK if t.id() == 0 => {
                magic = &sector[data..data + len] == crate::fs::littlefs::MAGIC;
            }
            tag::TYPE_INLINESTRUCT if t.id() == 0 && len >= 12 => {
                block_size = Some(tag::le32(&sector[data + 4..data + 8]));
            }
            _ => {}
        }
        off = data + len;
    }
    block_size.filter(|&bs| magic && bs.is_power_of_two())
}

/// Probe `dev` and mount the first volume found.
///
/// `SECTOR` is the scratch every sector-based driver keeps (512 for SD
/// cards); `BLOCK` is the block of scratch a littlefs volume keeps, and
/// bounds the littlefs block size that can be mounted. With littlefs
/// compiled out, `BLOCK` is unused.
///
/// The device is consumed. To keep it when nothing is found — to format
/// the card, say — call [`probe`] first and [`mount_found`] on its answer.
pub fn mount<D: SectorDriver, const SECTOR: usize, const BLOCK: usize>(
    mut dev: D,
) -> Result<AnyVolume<D, SECTOR, BLOCK>, AnyError<D::Error>> {
    match probe::<D, SECTOR>(&mut dev)? {
        Some(found) => mount_found(dev, found),
        None => Err(AnyError::NotRecognised),
    }
}

/// Mount the volume [`probe`] found.
pub fn mount_found<D: SectorDriver, const SECTOR: usize, const BLOCK: usize>(
    dev: D,
    found: Found,
) -> Result<AnyVolume<D, SECTOR, BLOCK>, AnyError<D::Error>> {
    match found.fs {
        #[cfg(feature = "fat")]
        FsType::Fat => fat::Volume::mount_at(dev, found.start_lba)
            .map(AnyVolume::Fat)
            .map_err(AnyError::Fat),
        #[cfg(feature = "exfat")]
        FsType::Exfat => exfat::Volume::mount_at(dev, found.start_lba)
            .map(AnyVolume::Exfat)
            .map_err(AnyError::Exfat),
        #[cfg(feature = "littlefs")]
        FsType::LittleFs => {
            if found.block_size as usize > BLOCK {
                return Err(AnyError::BlockSize(found.block_size));
            }
            let flash = SectorFlash::new(dev, found.start_lba, found.sectors, found.block_size)
                .map_err(|_| AnyError::BlockSize(found.block_size))?;
            littlefs::Volume::mount(flash)
                .map(AnyVolume::LittleFs)
                .map_err(AnyError::LittleFs)
        }
        #[allow(unreachable_patterns)] // every variant compiled in
        _ => {
            let _ = dev;
            Err(AnyError::NotRecognised)
        }
    }
}

/// Which filesystem [`format`](fn@format) lays down, and how.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FormatAs<'a> {
    /// FAT12/16/32 — the flavour chosen by size unless the options name one.
    #[cfg(feature = "fat")]
    Fat(fat::FormatOpts),
    /// exFAT.
    #[cfg(feature = "exfat")]
    Exfat(exfat::VolumeFormatOpts<'a>),
    /// littlefs on the card, in `block_size`-byte blocks of sectors.
    #[cfg(feature = "littlefs")]
    LittleFs {
        /// The littlefs block: a power-of-two multiple of the sector size,
        /// no larger than `BLOCK`.
        block_size: u32,
        /// littlefs's own format options.
        opts: littlefs::FormatOpts,
    },
    #[doc(hidden)]
    _Lifetime(core::marker::PhantomData<&'a ()>),
}

#[cfg(all(feature = "fat", feature = "exfat"))]
impl FormatAs<'_> {
    /// What the SD Association's specification puts on a card of
    /// `sectors` sectors of `sector_size` bytes: FAT (FAT32 from 512 MiB,
    /// smaller flavours below) up to 32 GiB — SDSC and SDHC — and exFAT above
    /// it, SDXC and SDUC. Every card reader and camera expects exactly that.
    pub fn sd_card(sectors: u64, sector_size: u32) -> Self {
        if sectors.saturating_mul(sector_size as u64) <= 32 << 30 {
            FormatAs::Fat(fat::FormatOpts::default())
        } else {
            FormatAs::Exfat(exfat::VolumeFormatOpts::default())
        }
    }
}

/// Format `sectors` sectors of `dev` from `start_lba` — a whole card from 0,
/// or a partition's extent — as `how` says, and mount the result.
///
/// It is each driver's own formatter underneath
/// ([`fat::Volume::format_at`](crate::fs::fat::Volume::format_at),
/// [`exfat::Volume::format_at`](crate::fs::exfat::Volume::format_at),
/// [`littlefs::Volume::format_with`](crate::fs::littlefs::Volume::format_with)
/// through [`SectorFlash`](crate::device::SectorFlash)), so it needs no
/// allocator either. Partitioning first is [`device::mbr`](crate::device::mbr)'s
/// or [`device::gpt`](crate::device::gpt)'s business:
///
/// ```no_run
/// # use fstool::device::{SectorDriver, mbr};
/// # use fstool::fs::volume::{self, AnyError, FormatAs};
/// # fn demo<D: SectorDriver>(mut card: D) -> Result<(), AnyError<D::Error>> {
/// // A blank card, prepared the way the SD specification says.
/// let sectors = card.sector_count() - mbr::FIRST_LBA as u64;
/// let how = FormatAs::sd_card(sectors, card.sector_size());
/// let kind = if matches!(how, FormatAs::Exfat(_)) { mbr::EXFAT } else { mbr::FAT32_LBA };
/// let part = mbr::Entry::new(kind, mbr::FIRST_LBA, sectors as u32);
/// let mut scratch = [0u8; 512];
/// mbr::write(&mut card, &mut scratch, &[Some(part), None, None, None], 0x5D_CA_4D)
///     .map_err(|_| AnyError::NotRecognised)?;
/// let vol = volume::format::<_, 512, 4096>(card, mbr::FIRST_LBA as u64, sectors, how)?;
/// # let _ = vol;
/// # Ok(())
/// # }
/// ```
pub fn format<D: SectorDriver, const SECTOR: usize, const BLOCK: usize>(
    dev: D,
    start_lba: u64,
    sectors: u64,
    how: FormatAs<'_>,
) -> Result<AnyVolume<D, SECTOR, BLOCK>, AnyError<D::Error>> {
    match how {
        #[cfg(feature = "fat")]
        FormatAs::Fat(opts) => fat::Volume::format_at(dev, start_lba, sectors, &opts)
            .map(AnyVolume::Fat)
            .map_err(AnyError::Fat),
        #[cfg(feature = "exfat")]
        FormatAs::Exfat(opts) => exfat::Volume::format_at(dev, start_lba, sectors, &opts)
            .map(AnyVolume::Exfat)
            .map_err(AnyError::Exfat),
        #[cfg(feature = "littlefs")]
        FormatAs::LittleFs { block_size, opts } => {
            if block_size as usize > BLOCK {
                return Err(AnyError::BlockSize(block_size));
            }
            let flash = SectorFlash::new(dev, start_lba, sectors, block_size)
                .map_err(|_| AnyError::BlockSize(block_size))?;
            littlefs::Volume::format_with(flash, &opts)
                .map(AnyVolume::LittleFs)
                .map_err(AnyError::LittleFs)
        }
        FormatAs::_Lifetime(_) => {
            let _ = (dev, start_lba, sectors);
            Err(AnyError::NotRecognised)
        }
    }
}

/// Whichever volume [`mount`] found.
///
/// The variants that exist are the filesystems compiled in. It is as large
/// as its largest variant — with littlefs on, that includes `BLOCK` bytes of
/// scratch — since without a heap there is nowhere else for a volume to
/// live.
///
/// littlefs on a card sits on [`SectorFlash`](crate::device::SectorFlash),
/// one littlefs block per run of sectors, programmed a sector at a time.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)] // no heap to box the big one into
#[non_exhaustive]
pub enum AnyVolume<D: SectorDriver, const SECTOR: usize = 512, const BLOCK: usize = 4096> {
    /// A FAT12/16/32 volume.
    #[cfg(feature = "fat")]
    Fat(fat::Volume<D, SECTOR>),
    /// An exFAT volume.
    #[cfg(feature = "exfat")]
    Exfat(exfat::Volume<D, SECTOR>),
    /// A littlefs volume on the card.
    #[cfg(feature = "littlefs")]
    LittleFs(littlefs::Volume<SectorFlash<D, SECTOR>, BLOCK, SECTOR>),
}

/// A file open on an [`AnyVolume`].
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum AnyFile {
    /// On a FAT volume.
    #[cfg(feature = "fat")]
    Fat(fat::File),
    /// On an exFAT volume.
    #[cfg(feature = "exfat")]
    Exfat(exfat::File),
    /// On a littlefs volume.
    #[cfg(feature = "littlefs")]
    LittleFs(littlefs::File),
}

/// A directory on an [`AnyVolume`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AnyDir {
    /// On a FAT volume.
    #[cfg(feature = "fat")]
    Fat(fat::Dir),
    /// On an exFAT volume.
    #[cfg(feature = "exfat")]
    Exfat(exfat::Dir),
    /// On a littlefs volume.
    #[cfg(feature = "littlefs")]
    LittleFs(littlefs::Dir),
}

/// A listing of a directory on an [`AnyVolume`].
#[allow(clippy::large_enum_variant)] // the name buffers live in the iterator, and no heap
#[non_exhaustive]
pub enum AnyDirIter<'a, D: SectorDriver, const SECTOR: usize, const BLOCK: usize> {
    /// On a FAT volume.
    #[cfg(feature = "fat")]
    Fat(FatDirIter<'a, D, SECTOR>),
    /// On an exFAT volume.
    #[cfg(feature = "exfat")]
    Exfat(ExfatDirIter<'a, D, SECTOR>),
    /// On a littlefs volume.
    #[cfg(feature = "littlefs")]
    LittleFs(LittleFsDirIter<'a, SectorFlash<D, SECTOR>, BLOCK, SECTOR>),
    /// A handle from another volume was listed. Yields
    /// [`AnyError::WrongVolume`].
    Mismatch,
}

/// Run `$body` against whichever volume `$vol` is, wrapping its error — and,
/// given `$wrap`, its success value — in the matching variant.
macro_rules! each {
    ($vol:expr, |$v:ident| $body:expr) => {
        match $vol {
            #[cfg(feature = "fat")]
            AnyVolume::Fat($v) => $body.map_err(AnyError::Fat),
            #[cfg(feature = "exfat")]
            AnyVolume::Exfat($v) => $body.map_err(AnyError::Exfat),
            #[cfg(feature = "littlefs")]
            AnyVolume::LittleFs($v) => $body.map_err(AnyError::LittleFs),
        }
    };
    ($vol:expr, |$v:ident| $body:expr, $wrap:ident) => {
        match $vol {
            #[cfg(feature = "fat")]
            AnyVolume::Fat($v) => $body.map($wrap::Fat).map_err(AnyError::Fat),
            #[cfg(feature = "exfat")]
            AnyVolume::Exfat($v) => $body.map($wrap::Exfat).map_err(AnyError::Exfat),
            #[cfg(feature = "littlefs")]
            AnyVolume::LittleFs($v) => $body.map($wrap::LittleFs).map_err(AnyError::LittleFs),
        }
    };
}

/// Run `$body` against a file (or directory) handle and the volume it must
/// belong to; a handle from a different kind of volume is
/// [`AnyError::WrongVolume`].
macro_rules! paired {
    ($handle:expr, $vol:expr, $Handle:ident, |$h:ident, $v:ident| $body:expr) => {
        #[allow(unreachable_patterns)] // a single filesystem compiled in
        match ($handle, $vol) {
            #[cfg(feature = "fat")]
            ($Handle::Fat($h), AnyVolume::Fat($v)) => $body.map_err(AnyError::Fat),
            #[cfg(feature = "exfat")]
            ($Handle::Exfat($h), AnyVolume::Exfat($v)) => $body.map_err(AnyError::Exfat),
            #[cfg(feature = "littlefs")]
            ($Handle::LittleFs($h), AnyVolume::LittleFs($v)) => $body.map_err(AnyError::LittleFs),
            _ => Err(AnyError::WrongVolume),
        }
    };
}

impl<D: SectorDriver, const SECTOR: usize, const BLOCK: usize> Volume
    for AnyVolume<D, SECTOR, BLOCK>
{
    type Error = AnyError<D::Error>;
    type Device = D;
    type File = AnyFile;
    type Dir = AnyDir;
    type DirIter<'a>
        = AnyDirIter<'a, D, SECTOR, BLOCK>
    where
        Self: 'a;

    fn fs_type(&self) -> FsType {
        match self {
            #[cfg(feature = "fat")]
            AnyVolume::Fat(v) => v.fs_type(),
            #[cfg(feature = "exfat")]
            AnyVolume::Exfat(v) => v.fs_type(),
            #[cfg(feature = "littlefs")]
            AnyVolume::LittleFs(v) => v.fs_type(),
        }
    }

    fn root(&self) -> AnyDir {
        match self {
            #[cfg(feature = "fat")]
            AnyVolume::Fat(v) => AnyDir::Fat(v.root()),
            #[cfg(feature = "exfat")]
            AnyVolume::Exfat(v) => AnyDir::Exfat(v.root()),
            #[cfg(feature = "littlefs")]
            AnyVolume::LittleFs(v) => AnyDir::LittleFs(v.root()),
        }
    }

    fn open_dir(&mut self, path: &str) -> Result<AnyDir, Self::Error> {
        each!(self, |v| Volume::open_dir(v, path), AnyDir)
    }

    fn iter_dir(&mut self, dir: AnyDir) -> Self::DirIter<'_> {
        #[allow(unreachable_patterns)] // a single filesystem compiled in
        match (dir, self) {
            #[cfg(feature = "fat")]
            (AnyDir::Fat(d), AnyVolume::Fat(v)) => AnyDirIter::Fat(Volume::iter_dir(v, d)),
            #[cfg(feature = "exfat")]
            (AnyDir::Exfat(d), AnyVolume::Exfat(v)) => AnyDirIter::Exfat(Volume::iter_dir(v, d)),
            #[cfg(feature = "littlefs")]
            (AnyDir::LittleFs(d), AnyVolume::LittleFs(v)) => {
                AnyDirIter::LittleFs(Volume::iter_dir(v, d))
            }
            _ => AnyDirIter::Mismatch,
        }
    }

    fn metadata(&mut self, path: &str) -> Result<Metadata, Self::Error> {
        each!(self, |v| Volume::metadata(v, path))
    }

    fn exists(&mut self, path: &str) -> Result<bool, Self::Error> {
        each!(self, |v| Volume::exists(v, path))
    }

    fn create_dir(&mut self, path: &str) -> Result<AnyDir, Self::Error> {
        each!(self, |v| Volume::create_dir(v, path), AnyDir)
    }

    fn remove_dir(&mut self, path: &str) -> Result<(), Self::Error> {
        each!(self, |v| Volume::remove_dir(v, path))
    }

    fn remove_file(&mut self, path: &str) -> Result<(), Self::Error> {
        each!(self, |v| Volume::remove_file(v, path))
    }

    fn open_file(&mut self, path: &str) -> Result<AnyFile, Self::Error> {
        each!(self, |v| Volume::open_file(v, path), AnyFile)
    }

    fn create_file(&mut self, path: &str) -> Result<AnyFile, Self::Error> {
        each!(self, |v| Volume::create_file(v, path), AnyFile)
    }

    fn open_or_create_file(&mut self, path: &str) -> Result<AnyFile, Self::Error> {
        each!(self, |v| Volume::open_or_create_file(v, path), AnyFile)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        each!(self, |v| Volume::flush(v))
    }

    fn total_bytes(&self) -> u64 {
        match self {
            #[cfg(feature = "fat")]
            AnyVolume::Fat(v) => Volume::total_bytes(v),
            #[cfg(feature = "exfat")]
            AnyVolume::Exfat(v) => Volume::total_bytes(v),
            #[cfg(feature = "littlefs")]
            AnyVolume::LittleFs(v) => Volume::total_bytes(v),
        }
    }

    fn free_bytes(&mut self) -> Result<u64, Self::Error> {
        each!(self, |v| Volume::free_bytes(v))
    }

    fn statfs(&mut self) -> Result<crate::fs::StatFs, Self::Error> {
        each!(self, |v| Volume::statfs(v))
    }

    fn unmount(self) -> Result<D, Self::Error> {
        match self {
            #[cfg(feature = "fat")]
            AnyVolume::Fat(v) => Volume::unmount(v).map_err(AnyError::Fat),
            #[cfg(feature = "exfat")]
            AnyVolume::Exfat(v) => Volume::unmount(v).map_err(AnyError::Exfat),
            #[cfg(feature = "littlefs")]
            AnyVolume::LittleFs(v) => Volume::unmount(v)
                .map(SectorFlash::into_inner)
                .map_err(AnyError::LittleFs),
        }
    }
}

impl<D: SectorDriver, const SECTOR: usize, const BLOCK: usize>
    VolumeFile<AnyVolume<D, SECTOR, BLOCK>> for AnyFile
{
    fn len(&self) -> u64 {
        match self {
            #[cfg(feature = "fat")]
            AnyFile::Fat(f) => f.len() as u64,
            #[cfg(feature = "exfat")]
            AnyFile::Exfat(f) => f.len(),
            #[cfg(feature = "littlefs")]
            AnyFile::LittleFs(f) => f.len() as u64,
        }
    }

    fn pos(&self) -> u64 {
        match self {
            #[cfg(feature = "fat")]
            AnyFile::Fat(f) => f.pos() as u64,
            #[cfg(feature = "exfat")]
            AnyFile::Exfat(f) => f.pos(),
            #[cfg(feature = "littlefs")]
            AnyFile::LittleFs(f) => f.pos() as u64,
        }
    }

    fn seek(
        &mut self,
        vol: &mut AnyVolume<D, SECTOR, BLOCK>,
        pos: u64,
    ) -> Result<(), AnyError<D::Error>> {
        paired!(self, vol, AnyFile, |f, v| VolumeFile::seek(f, v, pos))
    }

    fn read(
        &mut self,
        vol: &mut AnyVolume<D, SECTOR, BLOCK>,
        buf: &mut [u8],
    ) -> Result<usize, AnyError<D::Error>> {
        paired!(self, vol, AnyFile, |f, v| VolumeFile::read(f, v, buf))
    }

    fn read_exact(
        &mut self,
        vol: &mut AnyVolume<D, SECTOR, BLOCK>,
        buf: &mut [u8],
    ) -> Result<(), AnyError<D::Error>> {
        paired!(self, vol, AnyFile, |f, v| VolumeFile::read_exact(f, v, buf))
    }

    fn write(
        &mut self,
        vol: &mut AnyVolume<D, SECTOR, BLOCK>,
        buf: &[u8],
    ) -> Result<usize, AnyError<D::Error>> {
        paired!(self, vol, AnyFile, |f, v| VolumeFile::write(f, v, buf))
    }

    fn write_all(
        &mut self,
        vol: &mut AnyVolume<D, SECTOR, BLOCK>,
        buf: &[u8],
    ) -> Result<(), AnyError<D::Error>> {
        paired!(self, vol, AnyFile, |f, v| VolumeFile::write_all(f, v, buf))
    }

    fn set_len(
        &mut self,
        vol: &mut AnyVolume<D, SECTOR, BLOCK>,
        len: u64,
    ) -> Result<(), AnyError<D::Error>> {
        paired!(self, vol, AnyFile, |f, v| VolumeFile::set_len(f, v, len))
    }

    fn flush(&mut self, vol: &mut AnyVolume<D, SECTOR, BLOCK>) -> Result<(), AnyError<D::Error>> {
        paired!(self, vol, AnyFile, |f, v| VolumeFile::flush(f, v))
    }
}

impl<D: SectorDriver, const SECTOR: usize, const BLOCK: usize> VolumeDirIter
    for AnyDirIter<'_, D, SECTOR, BLOCK>
{
    type Error = AnyError<D::Error>;

    fn next(&mut self) -> Result<Option<Entry<'_>>, Self::Error> {
        match self {
            #[cfg(feature = "fat")]
            AnyDirIter::Fat(it) => it.next().map_err(AnyError::Fat),
            #[cfg(feature = "exfat")]
            AnyDirIter::Exfat(it) => it.next().map_err(AnyError::Exfat),
            #[cfg(feature = "littlefs")]
            AnyDirIter::LittleFs(it) => it.next().map_err(AnyError::LittleFs),
            AnyDirIter::Mismatch => Err(AnyError::WrongVolume),
        }
    }
}
