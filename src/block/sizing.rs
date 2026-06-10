//! A sparse, write-discarding [`BlockDevice`] used to let a filesystem
//! **writer determine its own minimal image size** by a dry run.
//!
//! The content-fit sizing path formats and populates a real filesystem writer
//! against one of these devices at a candidate size: the writer assigns
//! inodes / CNIDs, encodes names, builds its B-trees and directory blocks, and
//! allocates blocks exactly as it would for a real build — but file *data* is
//! written as zeros (via [`crate::fs::FileSource::Zero`]) and never stored, so
//! the dry run costs only the metadata's worth of RAM. Whether the writer's
//! own allocator runs out of space at a given size is the authoritative answer
//! to "does it fit?", with no second size model to drift out of sync.
//!
//! Pages are stored only when written non-zero, so the all-zero file data the
//! sizing pass emits allocates nothing while metadata reads back correctly
//! (writers that re-read structures they wrote during the build still work).

use std::collections::HashMap;
use std::io::{self, Read, Seek, SeekFrom, Write};

use super::BlockDevice;
use crate::Result;

/// 4 KiB sparse page.
const PAGE: usize = 4096;

/// A fixed-capacity device that stores only non-zero pages in memory and
/// reads unwritten regions as zero. Writes never fail for being non-durable;
/// the *capacity* is enforced via [`BlockDevice::read_at`]/`write_at`'s bounds
/// checks, so a writer that allocates past `total_size` gets the same
/// out-of-bounds error it would from a real device of that size.
pub struct SizingDevice {
    total: u64,
    cursor: u64,
    pages: HashMap<u64, Box<[u8; PAGE]>>,
}

impl SizingDevice {
    /// A device that presents `total` bytes of capacity.
    #[must_use]
    pub fn new(total: u64) -> Self {
        Self {
            total,
            cursor: 0,
            pages: HashMap::new(),
        }
    }
}

impl Read for SizingDevice {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let remaining = self.total.saturating_sub(self.cursor);
        let n = (buf.len() as u64).min(remaining) as usize;
        let mut off = self.cursor;
        let mut out = &mut buf[..n];
        // Fill page-chunk at a time: copy from a stored page, else zero-fill.
        while !out.is_empty() {
            let page = off / PAGE as u64;
            let within = (off % PAGE as u64) as usize;
            let take = (PAGE - within).min(out.len());
            let (head, tail) = out.split_at_mut(take);
            match self.pages.get(&page) {
                Some(p) => head.copy_from_slice(&p[within..within + take]),
                None => head.fill(0),
            }
            off += take as u64;
            out = tail;
        }
        self.cursor += n as u64;
        Ok(n)
    }
}

impl Write for SizingDevice {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let start = self.cursor;
        if start + buf.len() as u64 > self.total {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "sizing device: write past capacity",
            ));
        }
        // Page-chunked: an all-zero chunk to a not-yet-stored page costs
        // nothing (so the zero "file data" the sizing pass emits is free),
        // while any non-zero byte materialises the page.
        let mut off = start;
        let mut rest = buf;
        while !rest.is_empty() {
            let page = off / PAGE as u64;
            let within = (off % PAGE as u64) as usize;
            let take = (PAGE - within).min(rest.len());
            let chunk = &rest[..take];
            if let Some(p) = self.pages.get_mut(&page) {
                p[within..within + take].copy_from_slice(chunk);
            } else if chunk.iter().any(|&b| b != 0) {
                let mut p = Box::new([0u8; PAGE]);
                p[within..within + take].copy_from_slice(chunk);
                self.pages.insert(page, p);
            }
            off += take as u64;
            rest = &rest[take..];
        }
        self.cursor += buf.len() as u64;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Seek for SizingDevice {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let n = match pos {
            SeekFrom::Start(p) => p,
            SeekFrom::End(d) => (self.total as i64 + d) as u64,
            SeekFrom::Current(d) => (self.cursor as i64 + d) as u64,
        };
        self.cursor = n;
        Ok(n)
    }
}

impl BlockDevice for SizingDevice {
    fn block_size(&self) -> u32 {
        512
    }
    fn total_size(&self) -> u64 {
        self.total
    }
    fn sync(&mut self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_non_zero_reads_back_zeros_elsewhere() {
        let mut d = SizingDevice::new(1 << 20);
        d.write_at(8192, b"hello").unwrap();
        let mut buf = [0u8; 5];
        d.read_at(8192, &mut buf).unwrap();
        assert_eq!(&buf, b"hello");
        // Unwritten region reads as zero.
        let mut z = [9u8; 16];
        d.read_at(0, &mut z).unwrap();
        assert_eq!(z, [0u8; 16]);
    }

    #[test]
    fn all_zero_writes_allocate_no_pages() {
        let mut d = SizingDevice::new(64 << 20);
        // 16 MiB of zeros — the kind of "file data" the sizing pass emits.
        let zeros = vec![0u8; 16 << 20];
        d.write_at(0, &zeros).unwrap();
        assert!(d.pages.is_empty(), "zero writes must not allocate pages");
    }

    #[test]
    fn write_past_capacity_errors() {
        let mut d = SizingDevice::new(4096);
        assert!(d.write_at(4000, &[1u8; 200]).is_err());
    }
}
