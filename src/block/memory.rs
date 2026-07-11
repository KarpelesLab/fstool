//! In-memory [`BlockDevice`] backed by a `Vec<u8>`.
//!
//! `MemoryBackend` is a first-class production backend, not just a test
//! fixture. It is what makes fstool usable where there is no host
//! filesystem — most importantly the browser/WebAssembly build, where an
//! uploaded file is converted to another format entirely in RAM (see
//! [`crate::memconv`]).
//!
//! Two shapes:
//!
//! - **Fixed-capacity** ([`MemoryBackend::new`] / [`from_bytes`]) — a
//!   device of a known size, exactly like a raw file of that length. Writes
//!   past the end are rejected. Use this to wrap an existing image's bytes
//!   or to hold an image whose final size was computed up front.
//! - **Growable** ([`MemoryBackend::growable`]) — starts empty and extends
//!   on demand as higher layers write past the current end (zero-filling any
//!   gap). Use this as the sink for a streaming writer (tar / zip / an FS
//!   whose final size isn't known in advance).
//!
//! [`from_bytes`]: MemoryBackend::from_bytes

use std::io::{self, Read, Seek, SeekFrom, Write};

use super::BlockDevice;
use crate::Result;

/// A [`BlockDevice`] backed by a `Vec<u8>`. Bytes default to zero.
///
/// See the [module docs](self) for the fixed-capacity vs. growable
/// distinction.
#[derive(Debug, Clone)]
pub struct MemoryBackend {
    buf: Vec<u8>,
    cursor: u64,
    block_size: u32,
    /// When true, writes / positional writes / `zero_range` past the current
    /// end extend the buffer (zero-filling any gap) instead of being
    /// rejected. Fixed-capacity backends set this to false.
    growable: bool,
}

impl MemoryBackend {
    /// Create a fixed-capacity backend of exactly `size` bytes, all zero.
    pub fn new(size: u64) -> Self {
        Self::with_block_size(size, 512)
    }

    /// Create a fixed-capacity backend of exactly `size` bytes with a custom
    /// advisory sector size.
    pub fn with_block_size(size: u64, block_size: u32) -> Self {
        assert!(
            block_size.is_power_of_two(),
            "block_size must be a power of two"
        );
        Self {
            buf: vec![0; size as usize],
            cursor: 0,
            block_size,
            growable: false,
        }
    }

    /// Create a fixed-capacity backend that owns `bytes` as its initial
    /// contents. Capacity equals `bytes.len()`; the device behaves exactly
    /// like a raw file of that image. This is the entry point for inspecting
    /// or converting an uploaded file in memory.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            buf: bytes,
            cursor: 0,
            block_size: 512,
            growable: false,
        }
    }

    /// Create an empty growable backend. It reports `total_size() == 0`
    /// initially and extends as higher layers write past the end. Ideal as
    /// the sink for a streaming writer whose final size isn't known up front.
    pub fn growable() -> Self {
        Self::growable_with_block_size(512)
    }

    /// Like [`growable`](Self::growable) with a custom advisory sector size.
    pub fn growable_with_block_size(block_size: u32) -> Self {
        assert!(
            block_size.is_power_of_two(),
            "block_size must be a power of two"
        );
        Self {
            buf: Vec::new(),
            cursor: 0,
            block_size,
            growable: true,
        }
    }

    /// Borrow the underlying byte buffer.
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    /// Consume the backend and return its byte buffer — the finished image.
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// True if this backend grows on out-of-bounds writes.
    pub fn is_growable(&self) -> bool {
        self.growable
    }

    /// Ensure the buffer is at least `end` bytes long, zero-filling any new
    /// space. Only meaningful for growable backends.
    fn grow_to(&mut self, end: u64) {
        if end > self.buf.len() as u64 {
            self.buf.resize(end as usize, 0);
        }
    }
}

impl Read for MemoryBackend {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.cursor >= self.buf.len() as u64 {
            return Ok(0);
        }
        let start = self.cursor as usize;
        let available = self.buf.len() - start;
        let n = available.min(out.len());
        out[..n].copy_from_slice(&self.buf[start..start + n]);
        self.cursor += n as u64;
        Ok(n)
    }
}

impl Write for MemoryBackend {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.growable {
            // Extend to cover the whole write, zero-filling any gap between
            // the current end and the (possibly seeked-past-end) cursor.
            let end = self.cursor.saturating_add(data.len() as u64);
            self.grow_to(end);
            let start = self.cursor as usize;
            self.buf[start..start + data.len()].copy_from_slice(data);
            self.cursor += data.len() as u64;
            return Ok(data.len());
        }
        if self.cursor >= self.buf.len() as u64 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "write past end of MemoryBackend",
            ));
        }
        let start = self.cursor as usize;
        let available = self.buf.len() - start;
        let n = available.min(data.len());
        self.buf[start..start + n].copy_from_slice(&data[..n]);
        self.cursor += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Seek for MemoryBackend {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let total = self.buf.len() as u64;
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

impl BlockDevice for MemoryBackend {
    fn block_size(&self) -> u32 {
        self.block_size
    }

    fn total_size(&self) -> u64 {
        self.buf.len() as u64
    }

    fn zero_range(&mut self, offset: u64, len: u64) -> Result<()> {
        let size = self.total_size();
        let end = offset
            .checked_add(len)
            .ok_or(crate::Error::OutOfBounds { offset, len, size })?;
        if end > size {
            if !self.growable {
                return Err(crate::Error::OutOfBounds { offset, len, size });
            }
            self.grow_to(end);
        }
        // Newly grown bytes are already zero; only an explicit fill of the
        // pre-existing range is needed.
        self.buf[offset as usize..end as usize].fill(0);
        Ok(())
    }

    fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        if self.growable {
            let end = offset.checked_add(buf.len() as u64).ok_or({
                crate::Error::OutOfBounds {
                    offset,
                    len: buf.len() as u64,
                    size: self.total_size(),
                }
            })?;
            self.grow_to(end);
            self.buf[offset as usize..end as usize].copy_from_slice(buf);
            self.cursor = end;
            return Ok(());
        }
        // Fixed-capacity: fall back to the trait default (bounds-checked).
        let size = self.total_size();
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or(crate::Error::OutOfBounds {
                offset,
                len: buf.len() as u64,
                size,
            })?;
        if end > size {
            return Err(crate::Error::OutOfBounds {
                offset,
                len: buf.len() as u64,
                size,
            });
        }
        self.buf[offset as usize..end as usize].copy_from_slice(buf);
        self.cursor = end;
        Ok(())
    }

    fn sync(&mut self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_zero_initialised() {
        let mut dev = MemoryBackend::new(64);
        let mut buf = [0xffu8; 32];
        dev.read_at(0, &mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn write_then_read_at_roundtrip() {
        let mut dev = MemoryBackend::new(1024);
        let payload: Vec<u8> = (0..256u16).map(|i| i as u8).collect();
        dev.write_at(100, &payload).unwrap();
        let mut got = vec![0u8; 256];
        dev.read_at(100, &mut got).unwrap();
        assert_eq!(payload, got);
    }

    #[test]
    fn write_at_past_end_rejected() {
        let mut dev = MemoryBackend::new(64);
        let err = dev.write_at(50, &[0u8; 32]).unwrap_err();
        match err {
            crate::Error::OutOfBounds { offset, len, size } => {
                assert_eq!((offset, len, size), (50, 32, 64));
            }
            _ => panic!("expected OutOfBounds, got {err:?}"),
        }
    }

    #[test]
    fn zero_range_clears_existing_data() {
        let mut dev = MemoryBackend::new(128);
        dev.write_at(0, &[0xaa; 128]).unwrap();
        dev.zero_range(32, 32).unwrap();
        let mut buf = [0u8; 128];
        dev.read_at(0, &mut buf).unwrap();
        assert!(buf[..32].iter().all(|&b| b == 0xaa));
        assert!(buf[32..64].iter().all(|&b| b == 0x00));
        assert!(buf[64..].iter().all(|&b| b == 0xaa));
    }

    #[test]
    fn growable_extends_on_write_past_end() {
        let mut dev = MemoryBackend::growable();
        assert_eq!(dev.total_size(), 0);
        dev.write_at(10, &[0xab; 4]).unwrap();
        assert_eq!(dev.total_size(), 14);
        let mut buf = [0xffu8; 14];
        dev.read_at(0, &mut buf).unwrap();
        assert!(buf[..10].iter().all(|&b| b == 0)); // gap zero-filled
        assert!(buf[10..].iter().all(|&b| b == 0xab));
    }

    #[test]
    fn growable_streaming_write_grows() {
        let mut dev = MemoryBackend::growable();
        dev.write_all(&[1, 2, 3]).unwrap();
        dev.write_all(&[4, 5]).unwrap();
        assert_eq!(dev.total_size(), 5);
        assert_eq!(dev.as_slice(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn from_bytes_is_fixed_capacity() {
        let mut dev = MemoryBackend::from_bytes(vec![9u8; 8]);
        assert_eq!(dev.total_size(), 8);
        assert!(!dev.is_growable());
        assert!(dev.write_at(4, &[0u8; 8]).is_err()); // past end rejected
        assert_eq!(dev.into_bytes(), vec![9u8; 8]);
    }

    #[test]
    fn growable_zero_range_extends() {
        let mut dev = MemoryBackend::growable();
        dev.zero_range(0, 16).unwrap();
        assert_eq!(dev.total_size(), 16);
        assert!(dev.as_slice().iter().all(|&b| b == 0));
    }

    #[test]
    fn seek_modes_consistent() {
        let mut dev = MemoryBackend::new(100);
        assert_eq!(dev.seek(SeekFrom::Start(10)).unwrap(), 10);
        assert_eq!(dev.seek(SeekFrom::Current(5)).unwrap(), 15);
        assert_eq!(dev.seek(SeekFrom::End(-1)).unwrap(), 99);
        assert!(dev.seek(SeekFrom::End(-101)).is_err());
    }
}
