//! Erase-block storage on top of sector storage, so a flash filesystem can
//! live on a card.
//!
//! littlefs is written for raw flash, but it is also a sound choice on an SD
//! card or eMMC part where power can vanish mid-write: it never overwrites
//! live metadata in place. Its driver speaks [`FlashDriver`], a card driver
//! speaks [`SectorDriver`], and this adapter is the bridge — a littlefs block
//! is a run of whole sectors, starting wherever the volume does.
//!
//! ```text
//!   start_lba                     one littlefs block = block_size / sector_size sectors
//!   │ block 0 │ block 1 │ block 2 │ …
//! ```
//!
//! The flash contract says a block reads as `0xff` once erased, and the
//! littlefs driver is entitled to rely on that, so [`FlashDriver::erase`]
//! really writes `0xff` across the block. A card has no erase of its own that
//! would guarantee it, and "erase is a no-op" — which some littlefs ports
//! choose on block devices — is only safe for a driver that never looks at
//! erased space.

use super::{FlashDriver, SectorDriver};

/// A [`SectorDriver`] presented as a [`FlashDriver`].
///
/// `SECTOR` is the size of the one sector of scratch RAM the adapter keeps,
/// for reads and programs that cover part of a sector; it must be at least
/// the card's sector size. [`new`](Self::new) checks.
#[derive(Debug)]
pub struct SectorFlash<D, const SECTOR: usize = 512> {
    dev: D,
    start_lba: u64,
    sector_size: u32,
    sectors_per_block: u32,
    block_count: u32,
    scratch: [u8; SECTOR],
}

impl<D: SectorDriver, const SECTOR: usize> SectorFlash<D, SECTOR> {
    /// Present `sectors` sectors of `dev`, starting at `start_lba`, as
    /// `block_size`-byte erase blocks.
    ///
    /// Returns the driver back when the shape cannot work: a block size that
    /// is not a power-of-two multiple of the sector size, a `SECTOR` smaller
    /// than the sector size, a range that runs off the medium, or one too
    /// small to hold a single block.
    pub fn new(dev: D, start_lba: u64, sectors: u64, block_size: u32) -> Result<Self, D> {
        let ss = dev.sector_size();
        let fits = start_lba
            .checked_add(sectors)
            .is_some_and(|end| end <= dev.sector_count());
        if ss == 0
            || (ss as usize) > SECTOR
            || !block_size.is_power_of_two()
            || block_size < ss
            || !fits
        {
            return Err(dev);
        }
        let sectors_per_block = block_size / ss;
        let block_count = (sectors / sectors_per_block as u64).min(u32::MAX as u64) as u32;
        if block_count == 0 {
            return Err(dev);
        }
        Ok(Self {
            dev,
            start_lba,
            sector_size: ss,
            sectors_per_block,
            block_count,
            scratch: [0u8; SECTOR],
        })
    }

    /// Present the whole medium as `block_size`-byte erase blocks.
    pub fn whole(dev: D, block_size: u32) -> Result<Self, D> {
        let sectors = dev.sector_count();
        Self::new(dev, 0, sectors, block_size)
    }

    /// The first sector of block 0.
    pub fn start_lba(&self) -> u64 {
        self.start_lba
    }

    /// Borrow the card driver.
    pub fn get_ref(&self) -> &D {
        &self.dev
    }

    /// Borrow the card driver mutably. Writing behind the filesystem's back
    /// is the caller's own business.
    pub fn get_mut(&mut self) -> &mut D {
        &mut self.dev
    }

    /// Hand the card driver back.
    pub fn into_inner(self) -> D {
        self.dev
    }

    /// Where byte `off` of `block` lies: the sector's LBA, and the offset
    /// inside it.
    fn locate(&self, block: u32, off: u32) -> (u64, usize) {
        let ss = self.sector_size as u64;
        let byte = block as u64 * self.sectors_per_block as u64 * ss + off as u64;
        (self.start_lba + byte / ss, (byte % ss) as usize)
    }
}

impl<D: SectorDriver, const SECTOR: usize> FlashDriver for SectorFlash<D, SECTOR> {
    type Error = D::Error;

    fn block_size(&self) -> u32 {
        self.sectors_per_block * self.sector_size
    }

    fn block_count(&self) -> u32 {
        self.block_count
    }

    /// A program lands on whole sectors, so a sector is the page.
    fn prog_size(&self) -> u32 {
        self.sector_size
    }

    fn read(&mut self, block: u32, off: u32, buf: &mut [u8]) -> Result<(), Self::Error> {
        let ss = self.sector_size as usize;
        let (mut lba, mut at) = self.locate(block, off);
        let mut done = 0;
        while done < buf.len() {
            let rest = &mut buf[done..];
            if at == 0 && rest.len() >= ss {
                // Whole sectors go straight into the caller's buffer.
                let whole = rest.len() / ss * ss;
                self.dev.read_sectors(lba, &mut rest[..whole])?;
                lba += (whole / ss) as u64;
                done += whole;
            } else {
                self.dev.read_sectors(lba, &mut self.scratch[..ss])?;
                let n = (ss - at).min(rest.len());
                rest[..n].copy_from_slice(&self.scratch[at..at + n]);
                lba += 1;
                at = 0;
                done += n;
            }
        }
        Ok(())
    }

    fn prog(&mut self, block: u32, off: u32, data: &[u8]) -> Result<(), Self::Error> {
        let ss = self.sector_size as usize;
        let (mut lba, mut at) = self.locate(block, off);
        let mut done = 0;
        while done < data.len() {
            let rest = &data[done..];
            if at == 0 && rest.len() >= ss {
                let whole = rest.len() / ss * ss;
                self.dev.write_sectors(lba, &rest[..whole])?;
                lba += (whole / ss) as u64;
                done += whole;
            } else {
                // The contract keeps programs page-aligned, so this is only
                // reached by a driver that breaks it; read-modify-write keeps
                // it correct anyway.
                self.dev.read_sectors(lba, &mut self.scratch[..ss])?;
                let n = (ss - at).min(rest.len());
                self.scratch[at..at + n].copy_from_slice(&rest[..n]);
                self.dev.write_sectors(lba, &self.scratch[..ss])?;
                lba += 1;
                at = 0;
                done += n;
            }
        }
        Ok(())
    }

    fn erase(&mut self, block: u32) -> Result<(), Self::Error> {
        let ss = self.sector_size as usize;
        let (first, _) = self.locate(block, 0);
        self.scratch[..ss].fill(0xff);
        for i in 0..self.sectors_per_block as u64 {
            self.dev.write_sectors(first + i, &self.scratch[..ss])?;
        }
        Ok(())
    }

    fn sync(&mut self) -> Result<(), Self::Error> {
        self.dev.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 64 sectors of RAM.
    #[derive(Debug)]
    struct Card {
        bytes: [u8; 64 * 512],
    }

    impl SectorDriver for Card {
        type Error = core::convert::Infallible;
        fn sector_size(&self) -> u32 {
            512
        }
        fn sector_count(&self) -> u64 {
            64
        }
        fn read_sectors(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), Self::Error> {
            let at = lba as usize * 512;
            buf.copy_from_slice(&self.bytes[at..at + buf.len()]);
            Ok(())
        }
        fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> Result<(), Self::Error> {
            let at = lba as usize * 512;
            self.bytes[at..at + buf.len()].copy_from_slice(buf);
            Ok(())
        }
    }

    fn card() -> Card {
        Card {
            bytes: [0u8; 64 * 512],
        }
    }

    #[test]
    fn blocks_are_runs_of_sectors_from_the_start_lba() {
        let mut f = SectorFlash::<_, 512>::new(card(), 8, 40, 1024).unwrap();
        assert_eq!(
            (f.block_size(), f.block_count(), f.prog_size()),
            (1024, 20, 512)
        );
        f.erase(1).unwrap();
        f.prog(1, 512, &[7u8; 512]).unwrap();
        let card = f.into_inner();
        // Block 1 is sectors 10 and 11: the first erased, the second programmed.
        assert!(card.bytes[10 * 512..11 * 512].iter().all(|&b| b == 0xff));
        assert!(card.bytes[11 * 512..12 * 512].iter().all(|&b| b == 7));
        // Nothing before the start LBA or after the block was touched.
        assert!(card.bytes[..10 * 512].iter().all(|&b| b == 0));
        assert!(card.bytes[12 * 512..].iter().all(|&b| b == 0));
    }

    #[test]
    fn reads_and_programs_that_straddle_sectors_land_exactly() {
        let mut f = SectorFlash::<_, 512>::whole(card(), 2048).unwrap();
        f.erase(0).unwrap();
        let pattern: [u8; 1100] = core::array::from_fn(|i| i as u8);
        f.prog(0, 300, &pattern).unwrap();
        let mut back = [0u8; 1100];
        f.read(0, 300, &mut back).unwrap();
        assert_eq!(back, pattern);
        let mut edge = [0u8; 4];
        f.read(0, 298, &mut edge).unwrap();
        assert_eq!(edge, [0xff, 0xff, 0, 1]);
    }

    #[test]
    fn refuses_shapes_that_cannot_work() {
        // Not a power of two, smaller than a sector, off the end, too small.
        assert!(SectorFlash::<_, 512>::whole(card(), 1536).is_err());
        assert!(SectorFlash::<_, 512>::whole(card(), 256).is_err());
        assert!(SectorFlash::<_, 512>::new(card(), 60, 8, 512).is_err());
        assert!(SectorFlash::<_, 512>::new(card(), 0, 3, 2048).is_err());
        // Scratch smaller than a sector.
        assert!(SectorFlash::<_, 256>::whole(card(), 512).is_err());
    }
}
