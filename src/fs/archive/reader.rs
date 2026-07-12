//! Per-entry readers for the archive core: a bounded view over the
//! device's compressed byte range, plus codec dispatch.

use std::io::{self, Read, Seek, SeekFrom};

use super::{DataLocator, Method};
use crate::Result;
use crate::block::BlockDevice;
use crate::fs::FileReadHandle;

/// Reads exactly `remaining` bytes from `dev` starting at `offset`,
/// through `read_at` — nothing is buffered beyond the caller's slice.
/// Same shape as tar's `TarFileReader`.
pub struct BoundedDevReader<'a> {
    dev: &'a mut dyn BlockDevice,
    offset: u64,
    remaining: u64,
}

impl<'a> BoundedDevReader<'a> {
    pub fn new(dev: &'a mut dyn BlockDevice, offset: u64, len: u64) -> Self {
        Self {
            dev,
            offset,
            remaining: len,
        }
    }
}

impl<'a> Read for BoundedDevReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Ok(0);
        }
        let want = (buf.len() as u64).min(self.remaining) as usize;
        self.dev
            .read_at(self.offset, &mut buf[..want])
            .map_err(io::Error::other)?;
        self.offset += want as u64;
        self.remaining -= want as u64;
        Ok(want)
    }
}

/// Open a streaming reader over one entry's body, decoding per
/// `loc.method`. The returned reader borrows only `dev`.
pub fn open<'a>(dev: &'a mut dyn BlockDevice, loc: DataLocator) -> Result<Box<dyn Read + 'a>> {
    let bounded = BoundedDevReader::new(dev, loc.offset, loc.compressed_len);
    match loc.method {
        Method::Stored => Ok(Box::new(bounded)),
        Method::Deflate => deflate_reader(bounded),
        Method::Codec(algo) => crate::compression::make_reader(algo, bounded),
        Method::Unsupported(id) => Err(unsupported_method(id)),
    }
}

#[cfg(feature = "gzip")]
fn deflate_reader<'a, R: Read + 'a>(r: R) -> Result<Box<dyn Read + 'a>> {
    use compcol::Algorithm;
    Ok(Box::new(compcol::io::DecoderReader::new(
        r,
        compcol::deflate::Deflate::decoder(),
    )))
}

#[cfg(not(feature = "gzip"))]
fn deflate_reader<'a, R: Read + 'a>(_r: R) -> Result<Box<dyn Read + 'a>> {
    Err(crate::Error::Unsupported(
        "deflate support is disabled — rebuild with `--features gzip` (or `zip`)".into(),
    ))
}

fn unsupported_method(id: u16) -> crate::Error {
    crate::Error::Unsupported(format!(
        "archive: compression method {id} is recognised but not supported"
    ))
}

/// Open a random-access (`Read + Seek`) handle over one entry. Only
/// `Stored` members are genuinely seekable — they map to a cheap
/// bounded view over the device.
///
/// A compressed member (Deflate / any codec) is whole-member
/// compressed and can only be read forward from the start, so its
/// seekability would have to be faked by inflating the entire body
/// into RAM. That's dishonest, so we refuse: callers wanting the bytes
/// must stream them forward through [`open`] (`read_file`).
pub fn open_ro<'a>(
    dev: &'a mut dyn BlockDevice,
    loc: DataLocator,
) -> Result<Box<dyn FileReadHandle + 'a>> {
    match loc.method {
        Method::Stored => Ok(Box::new(StoredHandle {
            dev,
            start: loc.offset,
            len: loc.compressed_len,
            pos: 0,
        })),
        Method::Unsupported(id) => Err(unsupported_method(id)),
        _ => Err(crate::Error::Unsupported(
            "archive: member is compressed; only forward reads are supported \
             (use read_file / open_file_reader)"
                .into(),
        )),
    }
}

/// Seekable view over a `Stored` byte range of the device.
struct StoredHandle<'a> {
    dev: &'a mut dyn BlockDevice,
    start: u64,
    len: u64,
    pos: u64,
}

impl<'a> Read for StoredHandle<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.len {
            return Ok(0);
        }
        let want = (buf.len() as u64).min(self.len - self.pos) as usize;
        self.dev
            .read_at(self.start + self.pos, &mut buf[..want])
            .map_err(io::Error::other)?;
        self.pos += want as u64;
        Ok(want)
    }
}

impl<'a> Seek for StoredHandle<'a> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(n) => n as i64,
            SeekFrom::End(n) => self.len as i64 + n,
            SeekFrom::Current(n) => self.pos as i64 + n,
        };
        if new < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "archive: seek before start",
            ));
        }
        // Cap at len so seeking past EOF then reading yields 0 bytes.
        self.pos = (new as u64).min(self.len);
        Ok(self.pos)
    }
}

impl<'a> FileReadHandle for StoredHandle<'a> {
    fn len(&self) -> u64 {
        self.len
    }
}
