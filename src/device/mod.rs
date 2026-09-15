//! The storage a driver talks to — the bottom of the allocator-free stack.
//!
//! This is the layer beneath the filesystems: two traits describing the two
//! shapes storage comes in. Nothing here allocates, touches `std`, or knows
//! which filesystem is above it, so a program implements one of these traits
//! over its peripheral and then mounts whatever the medium turns out to
//! hold.
//!
//! * [`SectorDriver`] — media addressed in fixed-size sectors that can be
//!   rewritten in place: SD, eMMC, USB mass storage, a file. This is what
//!   [`fs::fat`](crate::fs::fat)'s and [`fs::exfat`](crate::fs::exfat)'s
//!   drivers are written against, so one implementation serves both — which
//!   is what a card reader needs, since an SDXC card arrives formatted exFAT
//!   and an SDHC one FAT32.
//! * [`FlashDriver`] — media that must be erased before it is programmed,
//!   and only a whole block at a time: raw NOR and NAND. This is what
//!   [`fs::littlefs`](crate::fs::littlefs)'s driver is written against, and
//!   it mirrors littlefs's own `lfs_config`. [`SectorFlash`] presents a
//!   [`SectorDriver`] as one, which is how littlefs lives on a card.
//!
//! Those two traits are the whole contract: what a consumer *implements*.
//! Everything a driver hands back about the medium is data, and lives beside
//! them rather than among them — the partition tables that say where on a
//! medium a volume begins:
//!
//! * [`mbr`] — the master boot record's four primary slots.
//! * [`gpt`] — the EFI GUID Partition Table, header CRC checked, with the
//!   backup at the end of the medium used when the primary does not.
//!
//! They are here rather than in [`part`](crate::part) because the hosted
//! partition layer builds owned tables and needs a heap, while a driver
//! mounting a volume needs a handful of numbers and no allocator.
//!
//! With `alloc` on, [`block`](crate::block) re-exports the two traits beside
//! its own [`SectorIo`](crate::block::SectorIo) — which is the trait to
//! implement when you want a *byte-addressed* device for the hosted
//! filesystems, rather than a driver for the allocator-free ones.

pub mod gpt;
pub mod mbr;
mod sector_flash;

pub use sector_flash::SectorFlash;

/// A driver for sector-addressed storage: the one trait an embedded consumer
/// implements for a card.
///
/// The volume checks every request before making it, so an implementation
/// need not: `buf` is always a non-zero multiple of
/// [`sector_size`](Self::sector_size) bytes long, and `lba + buf.len() /
/// sector_size` never exceeds [`sector_count`](Self::sector_count).
pub trait SectorDriver {
    /// Whatever your driver fails with. Each filesystem's error type carries
    /// it in its own `Io` variant.
    type Error;

    /// Bytes per sector. Must be a power of two between 512 and 4096;
    /// 512 for every SD card.
    fn sector_size(&self) -> u32;

    /// Number of sectors on the medium.
    fn sector_count(&self) -> u64;

    /// Read `buf.len() / sector_size()` sectors starting at `lba`.
    fn read_sectors(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), Self::Error>;

    /// Write `buf.len() / sector_size()` sectors starting at `lba`.
    fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> Result<(), Self::Error>;

    /// Push any write-back cache through to the medium. Default: nothing
    /// to do.
    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// A driver for erase-block storage: raw flash, which must be erased before
/// it can be programmed.
///
/// It mirrors littlefs's own `lfs_config`. The volume checks every request
/// before making it, so an implementation need not: `block` is always below
/// [`block_count`](Self::block_count), and `off + buf.len()` never exceeds
/// [`block_size`](Self::block_size).
///
/// The usual flash contract applies and a filesystem relies on it: a block
/// reads as `0xff` after [`erase`](Self::erase), and [`prog`](Self::prog) is
/// only ever called on erased storage, at offsets and lengths that are
/// multiples of [`prog_size`](Self::prog_size).
pub trait FlashDriver {
    /// Whatever your driver fails with. Each filesystem's error type carries
    /// it in its own `Io` variant.
    type Error;

    /// Bytes per erase block.
    fn block_size(&self) -> u32;

    /// Number of erase blocks available to the filesystem.
    fn block_count(&self) -> u32;

    /// Program granularity — the page size. Must be a power of two no
    /// larger than the block size. The default, 1, suits byte-addressable
    /// storage such as RAM or a file.
    fn prog_size(&self) -> u32 {
        1
    }

    /// Read `buf.len()` bytes from `block` starting at `off`.
    fn read(&mut self, block: u32, off: u32, buf: &mut [u8]) -> Result<(), Self::Error>;

    /// Program `data` into `block` at `off`, which is erased storage.
    fn prog(&mut self, block: u32, off: u32, data: &[u8]) -> Result<(), Self::Error>;

    /// Erase `block`, after which it reads as `0xff`.
    fn erase(&mut self, block: u32) -> Result<(), Self::Error>;

    /// Push any write-back cache through to the medium. Default: nothing
    /// to do.
    fn sync(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}
