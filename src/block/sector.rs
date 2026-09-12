//! A sector-addressed driver as a [`BlockDevice`].
//!
//! Storage hardware — an SD card over SPI or SDIO, eMMC, a raw NAND/NOR
//! translation layer — moves whole sectors, not bytes. [`SectorIo`] is
//! that contract: a sector size, a sector count, and aligned multi-sector
//! reads and writes. [`SectorDevice`] wraps any `SectorIo` as a full
//! byte-addressed [`BlockDevice`], bouncing the unaligned head and tail of
//! each request through a single-sector buffer and passing the aligned
//! middle straight to the driver, so a filesystem's cluster-sized
//! transfers cost one driver call each.
//!
//! This is the adapter an embedded build implements: write the four
//! `SectorIo` methods against your card driver, and `Fat32::open` (or any
//! other backend) mounts it.
//!
//! ```
//! use fstool::block::{BlockDevice, SectorDevice, SectorIo};
//!
//! /// A 1 MiB "card" of 512-byte sectors, in RAM for the example.
//! struct RamCard(Vec<u8>);
//!
//! impl SectorIo for RamCard {
//!     fn sector_size(&self) -> u32 { 512 }
//!     fn sector_count(&self) -> u64 { self.0.len() as u64 / 512 }
//!     fn read_sectors(&mut self, lba: u64, buf: &mut [u8]) -> fstool::Result<()> {
//!         let at = lba as usize * 512;
//!         buf.copy_from_slice(&self.0[at..at + buf.len()]);
//!         Ok(())
//!     }
//!     fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> fstool::Result<()> {
//!         let at = lba as usize * 512;
//!         self.0[at..at + buf.len()].copy_from_slice(buf);
//!         Ok(())
//!     }
//! }
//!
//! let mut dev = SectorDevice::new(RamCard(vec![0; 1 << 20]));
//! assert_eq!(dev.total_size(), 1 << 20);
//! dev.write_at(700, b"unaligned").unwrap();   // spans sectors 1 and 2
//! let mut back = [0u8; 9];
//! dev.read_at(700, &mut back).unwrap();
//! assert_eq!(&back, b"unaligned");
//! ```

use alloc::vec;
use alloc::vec::Vec;

use super::BlockDevice;
use crate::Result;
use crate::io::{self, Read, Seek, SeekFrom, Write};

/// A driver that moves whole sectors.
///
/// `buf` in [`read_sectors`](Self::read_sectors) and
/// [`write_sectors`](Self::write_sectors) is always a non-zero multiple of
/// [`sector_size`](Self::sector_size) bytes long, and `lba + buf.len() /
/// sector_size` never exceeds [`sector_count`](Self::sector_count) — the
/// adapter checks both before calling, so a driver need not.
pub trait SectorIo {
    /// Bytes per sector. Must be a power of two; 512 for every SD card.
    fn sector_size(&self) -> u32;

    /// Number of sectors on the medium.
    fn sector_count(&self) -> u64;

    /// Read `buf.len() / sector_size()` sectors starting at `lba`.
    fn read_sectors(&mut self, lba: u64, buf: &mut [u8]) -> Result<()>;

    /// Write `buf.len() / sector_size()` sectors starting at `lba`.
    fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> Result<()>;

    /// Push any write-back cache through to the medium. Default: nothing
    /// to do.
    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

/// [`SectorIo`] adapted to the byte-addressed [`BlockDevice`] contract.
///
/// See the [module docs](self) for what it does with unaligned requests.
/// The streaming `Read` / `Write` / `Seek` side keeps a cursor and
/// short-reads at the end of the medium, like a file.
#[derive(Debug)]
pub struct SectorDevice<D: SectorIo> {
    drv: D,
    cursor: u64,
    /// One sector, for the unaligned head and tail of a request.
    bounce: Vec<u8>,
}

impl<D: SectorIo> SectorDevice<D> {
    /// Wrap `drv`. Panics if its sector size is not a power of two.
    pub fn new(drv: D) -> Self {
        let ss = drv.sector_size();
        assert!(
            ss.is_power_of_two() && ss > 0,
            "sector size must be a power of two"
        );
        Self {
            drv,
            cursor: 0,
            bounce: vec![0u8; ss as usize],
        }
    }

    /// Borrow the driver.
    pub fn driver(&self) -> &D {
        &self.drv
    }

    /// Mutably borrow the driver.
    pub fn driver_mut(&mut self) -> &mut D {
        &mut self.drv
    }

    /// Unwrap the driver.
    pub fn into_driver(self) -> D {
        self.drv
    }

    fn sector_size(&self) -> u64 {
        u64::from(self.drv.sector_size())
    }

    /// Bytes on the medium.
    fn capacity(&self) -> u64 {
        self.drv.sector_count().saturating_mul(self.sector_size())
    }

    /// Reject a request outside the medium.
    fn check(&self, offset: u64, len: u64) -> Result<()> {
        let size = self.capacity();
        match offset.checked_add(len) {
            Some(end) if end <= size => Ok(()),
            _ => Err(crate::Error::OutOfBounds { offset, len, size }),
        }
    }
}

impl<D: SectorIo + Send> BlockDevice for SectorDevice<D> {
    fn block_size(&self) -> u32 {
        self.drv.sector_size()
    }

    fn total_size(&self) -> u64 {
        self.capacity()
    }

    fn sync(&mut self) -> Result<()> {
        self.drv.flush()
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.check(offset, buf.len() as u64)?;
        let ss = self.sector_size();
        let mut pos = offset;
        let mut buf = buf;
        // Unaligned head: the part of the first sector we want.
        let head = (pos % ss) as usize;
        if head != 0 {
            let n = buf.len().min(ss as usize - head);
            self.drv.read_sectors(pos / ss, &mut self.bounce)?;
            buf[..n].copy_from_slice(&self.bounce[head..head + n]);
            buf = &mut buf[n..];
            pos += n as u64;
        }
        // Aligned middle, straight through.
        let whole = buf.len() - buf.len() % ss as usize;
        if whole != 0 {
            self.drv.read_sectors(pos / ss, &mut buf[..whole])?;
            buf = &mut buf[whole..];
            pos += whole as u64;
        }
        // Unaligned tail: the start of the last sector.
        if !buf.is_empty() {
            self.drv.read_sectors(pos / ss, &mut self.bounce)?;
            let n = buf.len();
            buf.copy_from_slice(&self.bounce[..n]);
        }
        Ok(())
    }

    fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        self.check(offset, buf.len() as u64)?;
        let ss = self.sector_size();
        let mut pos = offset;
        let mut buf = buf;
        // Partial first sector: read-modify-write.
        let head = (pos % ss) as usize;
        if head != 0 {
            let n = buf.len().min(ss as usize - head);
            self.drv.read_sectors(pos / ss, &mut self.bounce)?;
            self.bounce[head..head + n].copy_from_slice(&buf[..n]);
            self.drv.write_sectors(pos / ss, &self.bounce)?;
            buf = &buf[n..];
            pos += n as u64;
        }
        let whole = buf.len() - buf.len() % ss as usize;
        if whole != 0 {
            self.drv.write_sectors(pos / ss, &buf[..whole])?;
            buf = &buf[whole..];
            pos += whole as u64;
        }
        if !buf.is_empty() {
            self.drv.read_sectors(pos / ss, &mut self.bounce)?;
            self.bounce[..buf.len()].copy_from_slice(buf);
            self.drv.write_sectors(pos / ss, &self.bounce)?;
        }
        Ok(())
    }
}

impl<D: SectorIo + Send> Read for SectorDevice<D> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let size = self.total_size();
        if self.cursor >= size {
            return Ok(0);
        }
        let n = (size - self.cursor).min(buf.len() as u64) as usize;
        self.read_at(self.cursor, &mut buf[..n])
            .map_err(io::Error::other)?;
        self.cursor += n as u64;
        Ok(n)
    }
}

impl<D: SectorIo + Send> Write for SectorDevice<D> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let size = self.total_size();
        if self.cursor >= size {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "write past end of SectorDevice",
            ));
        }
        let n = (size - self.cursor).min(buf.len() as u64) as usize;
        self.write_at(self.cursor, &buf[..n])
            .map_err(io::Error::other)?;
        self.cursor += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.drv.flush().map_err(io::Error::other)
    }
}

impl<D: SectorIo> Seek for SectorDevice<D> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let total = self.capacity();
        let new = match pos {
            SeekFrom::Start(n) => n as i128,
            SeekFrom::End(d) => total as i128 + d as i128,
            SeekFrom::Current(d) => self.cursor as i128 + d as i128,
        };
        if new < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before start",
            ));
        }
        self.cursor = new as u64;
        Ok(self.cursor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::MemoryBackend;

    /// A RAM "card" that counts driver calls and insists on alignment.
    struct Card {
        data: Vec<u8>,
        calls: usize,
    }

    impl SectorIo for Card {
        fn sector_size(&self) -> u32 {
            512
        }
        fn sector_count(&self) -> u64 {
            self.data.len() as u64 / 512
        }
        fn read_sectors(&mut self, lba: u64, buf: &mut [u8]) -> Result<()> {
            assert!(
                !buf.is_empty() && buf.len().is_multiple_of(512),
                "unaligned read"
            );
            self.calls += 1;
            let at = lba as usize * 512;
            buf.copy_from_slice(&self.data[at..at + buf.len()]);
            Ok(())
        }
        fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> Result<()> {
            assert!(
                !buf.is_empty() && buf.len().is_multiple_of(512),
                "unaligned write"
            );
            self.calls += 1;
            let at = lba as usize * 512;
            self.data[at..at + buf.len()].copy_from_slice(buf);
            Ok(())
        }
    }

    fn card(sectors: usize) -> SectorDevice<Card> {
        SectorDevice::new(Card {
            data: vec![0; sectors * 512],
            calls: 0,
        })
    }

    #[test]
    fn unaligned_io_matches_memory_backend() {
        let mut dev = card(16);
        let mut reference = MemoryBackend::new(16 * 512);
        let pattern: Vec<u8> = (0..3000u32).map(|i| (i * 7 % 251) as u8).collect();
        // Head + middle + tail, head only, tail only, inside one sector.
        for (off, len) in [(700u64, 2000usize), (100, 50), (1024, 300), (1500, 12)] {
            dev.write_at(off, &pattern[..len]).unwrap();
            reference.write_at(off, &pattern[..len]).unwrap();
        }
        let mut a = vec![0u8; 16 * 512];
        let mut b = vec![0u8; 16 * 512];
        dev.read_at(0, &mut a).unwrap();
        reference.read_at(0, &mut b).unwrap();
        assert_eq!(a, b);
        let mut got = vec![0u8; 777];
        dev.read_at(333, &mut got).unwrap();
        assert_eq!(got, &b[333..333 + 777]);
    }

    #[test]
    fn aligned_request_is_one_driver_call() {
        let mut dev = card(64);
        dev.driver_mut().calls = 0;
        dev.write_at(4096, &[0xab; 8192]).unwrap();
        assert_eq!(dev.driver().calls, 1);
        let mut buf = [0u8; 8192];
        dev.read_at(4096, &mut buf).unwrap();
        assert_eq!(dev.driver().calls, 2);
    }

    #[test]
    fn out_of_bounds_rejected() {
        let mut dev = card(4);
        assert!(matches!(
            dev.write_at(2000, &[0; 100]).unwrap_err(),
            crate::Error::OutOfBounds { .. }
        ));
        let mut buf = [0u8; 8];
        assert!(dev.read_at(u64::MAX - 2, &mut buf).is_err());
    }

    #[test]
    fn streaming_cursor_short_reads_at_end() {
        let mut dev = card(2);
        dev.seek(SeekFrom::Start(1000)).unwrap();
        dev.write_all(&[1, 2, 3, 4]).unwrap();
        dev.seek(SeekFrom::End(-10)).unwrap();
        let mut buf = [0u8; 64];
        assert_eq!(dev.read(&mut buf).unwrap(), 10);
        assert_eq!(&buf[..4], &[0, 0, 0, 0]);
        let mut at = [0u8; 4];
        dev.read_at(1000, &mut at).unwrap();
        assert_eq!(at, [1, 2, 3, 4]);
    }

    #[cfg(feature = "fat")]
    #[test]
    fn fat_volume_on_a_sector_device() {
        use crate::fs::fat::{Fat32, FatFormatOpts, FatKind};
        use crate::fs::{FileMeta, FileSource, Filesystem};
        use crate::path::Path;

        let mut dev = card(2048);
        let opts = FatFormatOpts {
            kind: FatKind::Fat12,
            total_sectors: 2048,
            ..Default::default()
        };
        let mut fs = Fat32::format(&mut dev, &opts).unwrap();
        fs.create_file(
            &mut dev,
            Path::new("/hello.txt"),
            FileSource::Reader {
                reader: alloc::boxed::Box::new(io::Cursor::new(b"hi there".to_vec())),
                len: 8,
            },
            FileMeta::default(),
        )
        .unwrap();
        fs.flush(&mut dev).unwrap();
        let mut fs = Fat32::open(&mut dev).unwrap();
        let names: Vec<_> = fs
            .list(&mut dev, Path::new("/"))
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(names, ["hello.txt"]);
        let mut body = Vec::new();
        fs.read_file(&mut dev, Path::new("/hello.txt"))
            .unwrap()
            .read_to_end(&mut body)
            .unwrap();
        assert_eq!(body, b"hi there");
    }
}
