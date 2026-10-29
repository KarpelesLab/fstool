//! Per-entry readers for the archive core: a bounded view over the
//! device's compressed byte range, plus codec dispatch.

use std::io::{self, Read, Seek, SeekFrom};

use super::{Crypto, DataLocator, Method};
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

/// Open a streaming reader over an entry's body. Encrypted entries need
/// [`open_with_password`].
pub fn open<'a>(dev: &'a mut dyn BlockDevice, loc: DataLocator) -> Result<Box<dyn Read + 'a>> {
    open_with_password(dev, loc, None)
}

/// Open a streaming reader over one entry's body: the located byte
/// range, decrypted per `loc.crypto` when a `password` is given, then
/// decoded per `loc.method`. The returned reader borrows only `dev`.
///
/// Methods whose codec was compiled out return `Unsupported` naming the
/// feature to enable. The zip-specific methods that carry their
/// parameters out of band (in the central directory rather than the
/// stream) are re-framed here into the self-describing header the
/// compcol codec expects; parameters that live at the start of the
/// body (LZMA's property block) are read from the decrypted stream.
pub fn open_with_password<'a>(
    dev: &'a mut dyn BlockDevice,
    loc: DataLocator,
    password: Option<&[u8]>,
) -> Result<Box<dyn Read + 'a>> {
    let raw = BoundedDevReader::new(dev, loc.offset, loc.compressed_len);
    let body: Box<dyn Read + 'a> = match loc.crypto {
        Crypto::None => Box::new(raw),
        Crypto::ZipCrypto { check } => {
            let pw = password.ok_or_else(crate::fs::archive::zip::crypto::needs_password)?;
            Box::new(crate::fs::archive::zip::crypto::ZipCryptoReader::new(
                raw, pw, check,
            )?)
        }
        Crypto::Aes { key_bits, .. } => {
            let pw = password.ok_or_else(crate::fs::archive::zip::crypto::needs_password)?;
            aes_reader(raw, pw, key_bits, loc.compressed_len)?
        }
    };
    decode(body, &loc)
}

#[cfg(feature = "zip-aes")]
fn aes_reader<'a, R: Read + 'a>(
    r: R,
    pw: &[u8],
    key_bits: u16,
    total: u64,
) -> Result<Box<dyn Read + 'a>> {
    Ok(Box::new(crate::fs::archive::zip::crypto::AesReader::new(
        r, pw, key_bits, total,
    )?))
}

#[cfg(not(feature = "zip-aes"))]
fn aes_reader<'a, R: Read + 'a>(
    _r: R,
    _pw: &[u8],
    _key_bits: u16,
    _total: u64,
) -> Result<Box<dyn Read + 'a>> {
    Err(crate::fs::archive::zip::crypto::aes_disabled())
}

/// Wrap the (decrypted) compressed body in the method's decoder.
fn decode<'a>(body: Box<dyn Read + 'a>, loc: &DataLocator) -> Result<Box<dyn Read + 'a>> {
    match loc.method {
        Method::Stored => Ok(body),
        Method::Deflate => deflate_reader(body),
        Method::Deflate64 => deflate64_reader(body),
        Method::Codec(algo) => crate::compression::make_reader(algo, body),
        Method::ZipLzma { eos } => zip_lzma_reader(body, loc, eos),
        Method::ZipPpmd => Err(zip_ppmd_unsupported()),
        Method::ZipShrink => {
            let hdr = legacy_len(loc)?.to_le_bytes().to_vec();
            zip_shrink_reader(io::Cursor::new(hdr).chain(body))
        }
        Method::ZipReduce(factor) => {
            let mut hdr = vec![factor];
            hdr.extend_from_slice(&legacy_len(loc)?.to_le_bytes());
            zip_reduce_reader(io::Cursor::new(hdr).chain(body))
        }
        Method::ZipImplode {
            large_window,
            lit_tree,
        } => {
            let mut hdr = vec![(large_window as u8) | ((lit_tree as u8) << 1)];
            hdr.extend_from_slice(&legacy_len(loc)?.to_le_bytes());
            zip_implode_reader(io::Cursor::new(hdr).chain(body))
        }
        Method::Unsupported(id) => Err(unsupported_method(id)),
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
    mut body: Box<dyn Read + 'a>,
    loc: &DataLocator,
    eos: bool,
) -> Result<Box<dyn Read + 'a>> {
    use compcol::Algorithm;
    let mut zh = [0u8; 4];
    body.read_exact(&mut zh).map_err(|_| {
        crate::Error::InvalidImage("zip: LZMA member shorter than its 4-byte header".into())
    })?;
    let props_len = u16::from_le_bytes([zh[2], zh[3]]) as usize;
    if props_len != 5 {
        return Err(crate::Error::InvalidImage(format!(
            "zip: LZMA member declares a {props_len}-byte properties block (expected 5)"
        )));
    }
    let mut hdr = vec![0u8; 5];
    body.read_exact(&mut hdr).map_err(|_| {
        crate::Error::InvalidImage("zip: LZMA member shorter than its properties block".into())
    })?;
    let size = if eos { u64::MAX } else { loc.uncompressed_len };
    hdr.extend_from_slice(&size.to_le_bytes());
    Ok(Box::new(compcol::io::DecoderReader::new(
        io::Cursor::new(hdr).chain(body),
        compcol::lzma::Lzma::decoder(),
    )))
}

#[cfg(not(feature = "lzma"))]
fn zip_lzma_reader<'a>(
    _body: Box<dyn Read + 'a>,
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
        Method::Stored if loc.crypto == Crypto::None => Ok(Box::new(StoredHandle {
            dev,
            start: loc.offset,
            len: loc.compressed_len,
            pos: 0,
        })),
        Method::Unsupported(id) => Err(unsupported_method(id)),
        _ if loc.crypto != Crypto::None => Err(crate::Error::Unsupported(
            "archive: member is encrypted; only forward reads are supported \
             (use read_file / open_file_reader)"
                .into(),
        )),
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
