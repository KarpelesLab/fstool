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
///
/// Methods whose codec was compiled out return `Unsupported` naming the
/// feature to enable. The zip-specific methods that carry their
/// parameters out of band (in the central directory rather than the
/// stream) are re-framed here into the self-describing header the
/// compcol codec expects.
pub fn open<'a>(dev: &'a mut dyn BlockDevice, loc: DataLocator) -> Result<Box<dyn Read + 'a>> {
    match loc.method {
        Method::Stored => Ok(Box::new(BoundedDevReader::new(
            dev,
            loc.offset,
            loc.compressed_len,
        ))),
        Method::Deflate => {
            deflate_reader(BoundedDevReader::new(dev, loc.offset, loc.compressed_len))
        }
        Method::Deflate64 => {
            deflate64_reader(BoundedDevReader::new(dev, loc.offset, loc.compressed_len))
        }
        Method::Codec(algo) => crate::compression::make_reader(
            algo,
            BoundedDevReader::new(dev, loc.offset, loc.compressed_len),
        ),
        Method::ZipLzma { eos } => zip_lzma_reader(dev, &loc, eos),
        Method::ZipPpmd => Err(zip_ppmd_unsupported()),
        Method::ZipShrink => {
            let hdr = legacy_len(&loc)?.to_le_bytes().to_vec();
            zip_shrink_reader(prefixed(dev, &loc, 0, hdr))
        }
        Method::ZipReduce(factor) => {
            let mut hdr = vec![factor];
            hdr.extend_from_slice(&legacy_len(&loc)?.to_le_bytes());
            zip_reduce_reader(prefixed(dev, &loc, 0, hdr))
        }
        Method::ZipImplode {
            large_window,
            lit_tree,
        } => {
            let mut hdr = vec![(large_window as u8) | ((lit_tree as u8) << 1)];
            hdr.extend_from_slice(&legacy_len(&loc)?.to_le_bytes());
            zip_implode_reader(prefixed(dev, &loc, 0, hdr))
        }
        Method::Unsupported(id) => Err(unsupported_method(id)),
        Method::Encrypted => Err(encrypted_method()),
    }
}

/// The PKZIP 1.x codecs carry a 32-bit length; a member that large was
/// never written by PKZIP 1.x, so refuse rather than truncate.
fn legacy_len(loc: &DataLocator) -> Result<u32> {
    u32::try_from(loc.uncompressed_len).map_err(|_| {
        crate::Error::InvalidImage(format!(
            "archive: {}-byte member is too large for a PKZIP 1.x method",
            loc.uncompressed_len
        ))
    })
}

/// A bounded view over the body starting `skip` bytes in, with `header`
/// served first — the shape every re-framed codec needs.
fn prefixed<'a>(
    dev: &'a mut dyn BlockDevice,
    loc: &DataLocator,
    skip: u64,
    header: Vec<u8>,
) -> io::Chain<io::Cursor<Vec<u8>>, BoundedDevReader<'a>> {
    io::Cursor::new(header).chain(BoundedDevReader::new(
        dev,
        loc.offset + skip,
        loc.compressed_len.saturating_sub(skip),
    ))
}

/// Read the first `n` bytes of a body (a method's parameter block).
#[cfg(feature = "lzma")]
fn body_prefix(dev: &mut dyn BlockDevice, loc: &DataLocator, n: usize) -> Result<Vec<u8>> {
    if loc.compressed_len < n as u64 {
        return Err(crate::Error::InvalidImage(format!(
            "archive: compressed body ({} bytes) is shorter than its {n}-byte method header",
            loc.compressed_len
        )));
    }
    let mut buf = vec![0u8; n];
    dev.read_at(loc.offset, &mut buf)?;
    Ok(buf)
}

/// Only reachable in a build with some codec feature off.
#[allow(dead_code)]
fn disabled(what: &str, feature: &str) -> crate::Error {
    crate::Error::Unsupported(format!(
        "{what} support is disabled — rebuild with `--features {feature}`"
    ))
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
    Err(disabled("deflate", "gzip"))
}

#[cfg(feature = "deflate64")]
fn deflate64_reader<'a, R: Read + 'a>(r: R) -> Result<Box<dyn Read + 'a>> {
    use compcol::Algorithm;
    Ok(Box::new(compcol::io::DecoderReader::new(
        r,
        compcol::deflate64::Deflate64::decoder(),
    )))
}

#[cfg(not(feature = "deflate64"))]
fn deflate64_reader<'a, R: Read + 'a>(_r: R) -> Result<Box<dyn Read + 'a>> {
    Err(disabled("deflate64", "deflate64"))
}

/// zip method 14 → compcol's `.lzma` "alone" framing: the 5 property
/// bytes the zip header carries, then an 8-byte size — the declared
/// length, or the "unknown" sentinel when the stream ends with an EOS
/// marker, so the decoder stops on the marker rather than running past
/// it into the next member's bytes.
#[cfg(feature = "lzma")]
fn zip_lzma_reader<'a>(
    dev: &'a mut dyn BlockDevice,
    loc: &DataLocator,
    eos: bool,
) -> Result<Box<dyn Read + 'a>> {
    use compcol::Algorithm;
    let zh = body_prefix(dev, loc, 4)?;
    let props_len = u16::from_le_bytes([zh[2], zh[3]]) as usize;
    if props_len != 5 {
        return Err(crate::Error::InvalidImage(format!(
            "zip: LZMA member declares a {props_len}-byte properties block (expected 5)"
        )));
    }
    let props = body_prefix(dev, loc, 9)?;
    let mut hdr = props[4..9].to_vec();
    let size = if eos { u64::MAX } else { loc.uncompressed_len };
    hdr.extend_from_slice(&size.to_le_bytes());
    Ok(Box::new(compcol::io::DecoderReader::new(
        prefixed(dev, loc, 9, hdr),
        compcol::lzma::Lzma::decoder(),
    )))
}

#[cfg(not(feature = "lzma"))]
fn zip_lzma_reader<'a>(
    _dev: &'a mut dyn BlockDevice,
    _loc: &DataLocator,
    _eos: bool,
) -> Result<Box<dyn Read + 'a>> {
    Err(disabled("lzma", "lzma"))
}

/// zip method 98 is PPMd *variant I* (APPNOTE: "PPMd version I, Rev 1",
/// 7-Zip's `Ppmd8`), whose model and carry-less range coder differ from
/// the variant H that compcol's `ppmd` module decodes. Until compcol
/// gains Ppmd8 the member is indexed and refused here.
fn zip_ppmd_unsupported() -> crate::Error {
    crate::Error::Unsupported(
        "zip: PPMd (method 98) members cannot be decoded — compcol has no PPMd variant I codec"
            .into(),
    )
}

#[cfg(feature = "zip-legacy")]
fn zip_shrink_reader<'a, R: Read + 'a>(r: R) -> Result<Box<dyn Read + 'a>> {
    use compcol::Algorithm;
    Ok(Box::new(compcol::io::DecoderReader::new(
        r,
        compcol::zip_shrink::ZipShrink::decoder(),
    )))
}

#[cfg(feature = "zip-legacy")]
fn zip_reduce_reader<'a, R: Read + 'a>(r: R) -> Result<Box<dyn Read + 'a>> {
    use compcol::Algorithm;
    Ok(Box::new(compcol::io::DecoderReader::new(
        r,
        compcol::zip_reduce::ZipReduce::decoder(),
    )))
}

#[cfg(feature = "zip-legacy")]
fn zip_implode_reader<'a, R: Read + 'a>(r: R) -> Result<Box<dyn Read + 'a>> {
    use compcol::Algorithm;
    Ok(Box::new(compcol::io::DecoderReader::new(
        r,
        compcol::zip_implode::ZipImplode::decoder(),
    )))
}

#[cfg(not(feature = "zip-legacy"))]
fn zip_shrink_reader<'a, R: Read + 'a>(_r: R) -> Result<Box<dyn Read + 'a>> {
    Err(disabled("zip shrink", "zip-legacy"))
}

#[cfg(not(feature = "zip-legacy"))]
fn zip_reduce_reader<'a, R: Read + 'a>(_r: R) -> Result<Box<dyn Read + 'a>> {
    Err(disabled("zip reduce", "zip-legacy"))
}

#[cfg(not(feature = "zip-legacy"))]
fn zip_implode_reader<'a, R: Read + 'a>(_r: R) -> Result<Box<dyn Read + 'a>> {
    Err(disabled("zip implode", "zip-legacy"))
}

fn unsupported_method(id: u16) -> crate::Error {
    crate::Error::Unsupported(format!(
        "archive: compression method {id} is recognised but not supported"
    ))
}

fn encrypted_method() -> crate::Error {
    crate::Error::Unsupported(
        "archive: member is encrypted — fstool has no passphrase handling".into(),
    )
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
        Method::Encrypted => Err(encrypted_method()),
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
