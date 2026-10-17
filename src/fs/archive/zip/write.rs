//! ZIP writer.
//!
//! Each `create_*` writes a local file header then streams the body at
//! a bumping cursor, computing the CRC-32 and compressed size on the
//! fly and back-patching them into the header afterwards (the device is
//! seekable). `flush` appends the central directory and the EOCD,
//! emitting ZIP64 structures only when an entry, offset, or count
//! crosses the 32-bit limit.
//!
//! Per the universal-zip technique we set the UTF-8 flag (bit 11) only
//! for non-ASCII names; because non-ASCII names are therefore never
//! unflagged, declaring host-OS = Unix (so we can carry POSIX mode bits
//! and symlinks for round-tripping) does not risk the Windows
//! mangling the note warns about.

#[cfg(any(
    feature = "gzip",
    feature = "deflate64",
    feature = "bzip2",
    feature = "lzma",
    feature = "xz",
    feature = "zstd"
))]
use std::io::Write;

use super::encoding;
use super::{
    Compression, SIG_CENTRAL, SIG_EOCD, SIG_LOCAL, SIG_ZIP64_EOCD, SIG_ZIP64_LOCATOR, ZipFormatOpts,
};
use crate::block::BlockDevice;
use crate::fs::archive::ArchiveBuilder;
use crate::fs::archive::tree;
use crate::fs::archive::writer::Cursor;
use crate::fs::{DeviceKind, FileMeta};
use crate::{Error, Result};

const U32_MAX: u64 = 0xffff_ffff;
const HOST_UNIX: u16 = 3;
const S_IFLNK: u32 = 0o120000;

/// One central-directory record, accumulated until `finish`.
struct CdRec {
    name: String,
    /// General-purpose flags as written in the local header: bit 11 for
    /// a UTF-8 name, bit 1 for an LZMA end-of-stream marker.
    gp_flags: u16,
    /// "Version needed to extract" as written in the local header.
    version_needed: u16,
    method: u16,
    crc: u32,
    comp_size: u64,
    uncomp_size: u64,
    local_offset: u64,
    dos_date: u16,
    dos_time: u16,
    /// Full Unix `st_mode` (type bits included) for the external attrs.
    unix_mode: u32,
    is_dir: bool,
}

pub struct ZipWriter {
    cursor: Cursor,
    opts: ZipFormatOpts,
    central: Vec<CdRec>,
}

/// `Write` sink that appends to the device through the shared cursor and
/// counts the bytes (the compressed size). Only the compressed paths
/// use it, so it's gated on the codec features.
#[cfg(any(
    feature = "gzip",
    feature = "deflate64",
    feature = "bzip2",
    feature = "lzma",
    feature = "xz",
    feature = "zstd"
))]
struct CursorSink<'a> {
    cursor: &'a mut Cursor,
    dev: &'a mut dyn BlockDevice,
    written: u64,
}

#[cfg(any(
    feature = "gzip",
    feature = "deflate64",
    feature = "bzip2",
    feature = "lzma",
    feature = "xz",
    feature = "zstd"
))]
impl Write for CursorSink<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.cursor
            .write(self.dev, buf)
            .map_err(std::io::Error::other)?;
        self.written += buf.len() as u64;
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Ceiling on what DEFLATE can emit for `n` input bytes: worst case
/// every block is stored, which costs a 5-byte block header per 65535
/// bytes, plus slack for the final block and any encoder framing.
///
/// The local file header is written *before* the body, so the ZIP64
/// decision has to be made on this bound rather than on the real
/// compressed size — an input just under 4 GiB can deflate to just
/// over it, and a truncated 32-bit size in the local header is a
/// corrupt member.
fn deflate_max_output(n: u64) -> u64 {
    n.saturating_add(n / 65535 * 5).saturating_add(64)
}

/// The same ceiling for every method the writer offers. DEFLATE and
/// Deflate64 have the tight bound above; the others are given a quarter
/// again plus framing, which no LZ or block-sort codec exceeds on
/// incompressible input (LZMA's range coder is the worst at ~1.14×).
/// Only the ZIP64 decision near 4 GiB depends on it, so generosity
/// costs at most a ZIP64 extra on a member that didn't need one.
fn compressed_max_output(method: Compression, n: u64) -> u64 {
    match method {
        Compression::Stored => n,
        Compression::Deflate | Compression::Deflate64 => deflate_max_output(n),
        _ => n.saturating_add(n / 4).saturating_add(4096),
    }
}

fn push_u16(v: &mut Vec<u8>, n: u16) {
    v.extend_from_slice(&n.to_le_bytes());
}
fn push_u32(v: &mut Vec<u8>, n: u32) {
    v.extend_from_slice(&n.to_le_bytes());
}
fn push_u64(v: &mut Vec<u8>, n: u64) {
    v.extend_from_slice(&n.to_le_bytes());
}

impl ZipWriter {
    pub fn new(dev: &dyn BlockDevice, opts: ZipFormatOpts) -> Self {
        Self {
            cursor: Cursor::new(dev),
            opts,
            central: Vec::new(),
        }
    }

    fn norm(path: &str) -> String {
        tree::normalise_path(path)
            .trim_start_matches('/')
            .to_string()
    }

    /// Pick the body method: honour the option, but force `Stored` for
    /// empty bodies and when the default DEFLATE isn't compiled in (a
    /// `gzip`-less build still produces valid archives). Any other
    /// method reaches here only if `apply_options` found it enabled.
    fn body_method(&self, len: u64) -> Compression {
        if len == 0 {
            return Compression::Stored;
        }
        match self.opts.method {
            Compression::Deflate if !cfg!(feature = "gzip") => Compression::Stored,
            m => m,
        }
    }

    /// Write a local file header + body and record the central entry.
    /// `body` streams `len` bytes; `inline` provides an in-memory body
    /// (symlink targets, empty dirs).
    #[allow(clippy::too_many_arguments)]
    fn write_entry(
        &mut self,
        dev: &mut dyn BlockDevice,
        name: &str,
        unix_mode: u32,
        meta: &FileMeta,
        is_dir: bool,
        mut body: Option<(&mut dyn std::io::Read, u64)>,
        inline: &[u8],
    ) -> Result<()> {
        let uncomp = body
            .as_ref()
            .map(|(_, n)| *n)
            .unwrap_or(inline.len() as u64);
        let method = if body.is_some() {
            self.body_method(uncomp)
        } else if inline.is_empty() {
            Compression::Stored
        } else {
            // small in-memory bodies stored verbatim
            Compression::Stored
        };
        let method_id = method.method_id();
        // Bit 11: the name is UTF-8. Bit 1: for LZMA, the stream ends
        // with an end-of-stream marker (compcol's encoder always writes
        // one, and leaves the size field unknown).
        let mut gp_flags = if encoding::needs_utf8_flag(name) {
            0x0800
        } else {
            0
        };
        if method == Compression::Lzma {
            gp_flags |= 0x0002;
        }
        let (dos_date, dos_time) = super::unix_to_dos(u64::from(meta.mtime));
        let worst_comp = compressed_max_output(method, uncomp);
        let entry_zip64 = uncomp >= U32_MAX || worst_comp >= U32_MAX;
        let version_needed = method
            .version_needed()
            .max(if entry_zip64 { 45 } else { 20 });
        let local_offset = self.cursor.position();
        let name_bytes = name.as_bytes();

        // --- local file header (30 bytes + name + optional zip64 extra) ---
        let mut hdr = Vec::with_capacity(30 + name_bytes.len() + 20);
        push_u32(&mut hdr, SIG_LOCAL);
        push_u16(&mut hdr, version_needed);
        push_u16(&mut hdr, gp_flags);
        push_u16(&mut hdr, method_id);
        push_u16(&mut hdr, dos_time);
        push_u16(&mut hdr, dos_date);
        push_u32(&mut hdr, 0); // crc — patched
        push_u32(&mut hdr, if entry_zip64 { U32_MAX as u32 } else { 0 }); // comp — patched
        push_u32(
            &mut hdr,
            if entry_zip64 {
                U32_MAX as u32
            } else {
                uncomp as u32
            },
        );
        push_u16(&mut hdr, name_bytes.len() as u16);
        push_u16(&mut hdr, if entry_zip64 { 20 } else { 0 }); // extra len
        hdr.extend_from_slice(name_bytes);
        if entry_zip64 {
            push_u16(&mut hdr, 0x0001);
            push_u16(&mut hdr, 16);
            push_u64(&mut hdr, uncomp);
            push_u64(&mut hdr, 0); // comp — patched
        }
        self.cursor.write(dev, &hdr)?;

        // --- body ---
        let (crc, comp_size) = match body.take() {
            Some((reader, len)) => self.stream_body(dev, reader, len, method)?,
            None => {
                let crc = crate::crc::crc32(inline);
                self.cursor.write(dev, inline)?;
                (crc, inline.len() as u64)
            }
        };

        // --- back-patch crc + sizes ---
        dev.write_at(local_offset + 14, &crc.to_le_bytes())?;
        if entry_zip64 {
            // comp lives in the zip64 extra (after id+size+uncomp = +8).
            let extra_data = local_offset + 30 + name_bytes.len() as u64 + 4;
            dev.write_at(extra_data + 8, &comp_size.to_le_bytes())?;
        } else {
            dev.write_at(local_offset + 18, &(comp_size as u32).to_le_bytes())?;
            dev.write_at(local_offset + 22, &(uncomp as u32).to_le_bytes())?;
        }

        self.central.push(CdRec {
            name: name.to_string(),
            gp_flags,
            version_needed,
            method: method_id,
            crc,
            comp_size,
            uncomp_size: uncomp,
            local_offset,
            dos_date,
            dos_time,
            unix_mode,
            is_dir,
        });
        Ok(())
    }

    fn stream_body(
        &mut self,
        dev: &mut dyn BlockDevice,
        reader: &mut dyn std::io::Read,
        len: u64,
        method: Compression,
    ) -> Result<(u32, u64)> {
        // The running CRC is just its state; `crc32_append` composes, so
        // there is nothing to hold but a `u32`.
        let mut crc = 0u32;
        let mut buf = vec![0u8; 64 * 1024];
        match method {
            Compression::Stored => {
                let mut remaining = len;
                while remaining > 0 {
                    let want = remaining.min(buf.len() as u64) as usize;
                    reader.read_exact(&mut buf[..want]).map_err(Error::from)?;
                    crc = crate::crc::crc32_append(crc, &buf[..want]);
                    self.cursor.write(dev, &buf[..want])?;
                    remaining -= want as u64;
                }
                Ok((crc, len))
            }
            Compression::Deflate => self.stream_deflate(dev, reader, len, &mut crc, &mut buf),
            Compression::Deflate64 => self.stream_deflate64(dev, reader, len, &mut crc, &mut buf),
            Compression::Bzip2 => self.stream_bzip2(dev, reader, len, &mut crc, &mut buf),
            Compression::Lzma => self.stream_lzma(dev, reader, len, &mut crc, &mut buf),
            Compression::Xz => self.stream_xz(dev, reader, len, &mut crc, &mut buf),
            Compression::Zstd => self.stream_zstd(dev, reader, len, &mut crc, &mut buf),
        }
    }

    /// Codec level in the encoder's own 1-based scale: zip level 0
    /// (meaning "store") maps up to 1.
    #[cfg(any(
        feature = "gzip",
        feature = "deflate64",
        feature = "bzip2",
        feature = "lzma",
        feature = "xz",
        feature = "zstd"
    ))]
    fn codec_level(&self) -> u8 {
        self.opts.level.clamp(1, 9) as u8
    }

    #[cfg(feature = "gzip")]
    fn stream_deflate(
        &mut self,
        dev: &mut dyn BlockDevice,
        reader: &mut dyn std::io::Read,
        len: u64,
        crc: &mut u32,
        buf: &mut [u8],
    ) -> Result<(u32, u64)> {
        use compcol::Algorithm;
        let cfg = compcol::deflate::EncoderConfig::default().with_level(self.codec_level());
        let sink = CursorSink {
            cursor: &mut self.cursor,
            dev,
            written: 0,
        };
        let sink = stream_encode(
            sink,
            compcol::deflate::Deflate::encoder_with(cfg),
            reader,
            len,
            crc,
            buf,
        )?;
        Ok((*crc, sink.written))
    }

    #[cfg(not(feature = "gzip"))]
    fn stream_deflate(
        &mut self,
        _dev: &mut dyn BlockDevice,
        _reader: &mut dyn std::io::Read,
        _len: u64,
        _crc: &mut u32,
        _buf: &mut [u8],
    ) -> Result<(u32, u64)> {
        Err(disabled(Compression::Deflate))
    }

    #[cfg(feature = "deflate64")]
    fn stream_deflate64(
        &mut self,
        dev: &mut dyn BlockDevice,
        reader: &mut dyn std::io::Read,
        len: u64,
        crc: &mut u32,
        buf: &mut [u8],
    ) -> Result<(u32, u64)> {
        use compcol::Algorithm;
        let cfg = compcol::deflate64::EncoderConfig {
            level: self.codec_level(),
        };
        let sink = CursorSink {
            cursor: &mut self.cursor,
            dev,
            written: 0,
        };
        let sink = stream_encode(
            sink,
            compcol::deflate64::Deflate64::encoder_with(cfg),
            reader,
            len,
            crc,
            buf,
        )?;
        Ok((*crc, sink.written))
    }

    #[cfg(not(feature = "deflate64"))]
    fn stream_deflate64(
        &mut self,
        _dev: &mut dyn BlockDevice,
        _reader: &mut dyn std::io::Read,
        _len: u64,
        _crc: &mut u32,
        _buf: &mut [u8],
    ) -> Result<(u32, u64)> {
        Err(disabled(Compression::Deflate64))
    }

    #[cfg(feature = "bzip2")]
    fn stream_bzip2(
        &mut self,
        dev: &mut dyn BlockDevice,
        reader: &mut dyn std::io::Read,
        len: u64,
        crc: &mut u32,
        buf: &mut [u8],
    ) -> Result<(u32, u64)> {
        use compcol::Algorithm;
        let cfg = compcol::bzip2::EncoderConfig {
            level: self.codec_level(),
        };
        let sink = CursorSink {
            cursor: &mut self.cursor,
            dev,
            written: 0,
        };
        let sink = stream_encode(
            sink,
            compcol::bzip2::Bzip2::encoder_with(cfg),
            reader,
            len,
            crc,
            buf,
        )?;
        Ok((*crc, sink.written))
    }

    #[cfg(not(feature = "bzip2"))]
    fn stream_bzip2(
        &mut self,
        _dev: &mut dyn BlockDevice,
        _reader: &mut dyn std::io::Read,
        _len: u64,
        _crc: &mut u32,
        _buf: &mut [u8],
    ) -> Result<(u32, u64)> {
        Err(disabled(Compression::Bzip2))
    }

    /// LZMA: compcol emits the `.lzma` "alone" framing (5 property bytes
    /// and an 8-byte size, left unknown so an end-of-stream marker closes
    /// the body). The zip framing wants a 2-byte version, a 2-byte
    /// property length, the 5 property bytes, and no size —
    /// [`ZipLzmaSink`] does that rewrite on the way to the device.
    #[cfg(feature = "lzma")]
    fn stream_lzma(
        &mut self,
        dev: &mut dyn BlockDevice,
        reader: &mut dyn std::io::Read,
        len: u64,
        crc: &mut u32,
        buf: &mut [u8],
    ) -> Result<(u32, u64)> {
        use compcol::Algorithm;
        let cfg = compcol::lzma::EncoderConfig {
            level: self.codec_level(),
        };
        let sink = ZipLzmaSink {
            inner: CursorSink {
                cursor: &mut self.cursor,
                dev,
                written: 0,
            },
            head: [0u8; 13],
            seen: 0,
        };
        let sink = stream_encode(
            sink,
            compcol::lzma::Lzma::encoder_with(cfg),
            reader,
            len,
            crc,
            buf,
        )?;
        if sink.seen < sink.head.len() {
            return Err(Error::Io(std::io::Error::other(
                "zip: LZMA encoder produced no stream header",
            )));
        }
        Ok((*crc, sink.inner.written))
    }

    #[cfg(not(feature = "lzma"))]
    fn stream_lzma(
        &mut self,
        _dev: &mut dyn BlockDevice,
        _reader: &mut dyn std::io::Read,
        _len: u64,
        _crc: &mut u32,
        _buf: &mut [u8],
    ) -> Result<(u32, u64)> {
        Err(disabled(Compression::Lzma))
    }

    #[cfg(feature = "xz")]
    fn stream_xz(
        &mut self,
        dev: &mut dyn BlockDevice,
        reader: &mut dyn std::io::Read,
        len: u64,
        crc: &mut u32,
        buf: &mut [u8],
    ) -> Result<(u32, u64)> {
        use compcol::Algorithm;
        let cfg = compcol::xz::EncoderConfig {
            level: self.codec_level(),
        };
        let sink = CursorSink {
            cursor: &mut self.cursor,
            dev,
            written: 0,
        };
        let sink = stream_encode(
            sink,
            compcol::xz::Xz::encoder_with(cfg),
            reader,
            len,
            crc,
            buf,
        )?;
        Ok((*crc, sink.written))
    }

    #[cfg(not(feature = "xz"))]
    fn stream_xz(
        &mut self,
        _dev: &mut dyn BlockDevice,
        _reader: &mut dyn std::io::Read,
        _len: u64,
        _crc: &mut u32,
        _buf: &mut [u8],
    ) -> Result<(u32, u64)> {
        Err(disabled(Compression::Xz))
    }

    #[cfg(feature = "zstd")]
    fn stream_zstd(
        &mut self,
        dev: &mut dyn BlockDevice,
        reader: &mut dyn std::io::Read,
        len: u64,
        crc: &mut u32,
        buf: &mut [u8],
    ) -> Result<(u32, u64)> {
        use compcol::Algorithm;
        let cfg = compcol::zstd::EncoderConfig {
            level: self.codec_level(),
        };
        let sink = CursorSink {
            cursor: &mut self.cursor,
            dev,
            written: 0,
        };
        let sink = stream_encode(
            sink,
            compcol::zstd::Zstd::encoder_with(cfg),
            reader,
            len,
            crc,
            buf,
        )?;
        Ok((*crc, sink.written))
    }

    #[cfg(not(feature = "zstd"))]
    fn stream_zstd(
        &mut self,
        _dev: &mut dyn BlockDevice,
        _reader: &mut dyn std::io::Read,
        _len: u64,
        _crc: &mut u32,
        _buf: &mut [u8],
    ) -> Result<(u32, u64)> {
        Err(disabled(Compression::Zstd))
    }
}

#[allow(dead_code)]
fn disabled(method: Compression) -> Error {
    Error::Unsupported(format!(
        "zip: {} compression is disabled — rebuild with `--features {}`",
        method.name(),
        method.feature().unwrap_or_default()
    ))
}

/// Pump `len` bytes from `reader` through `enc` into `sink`, folding the
/// plaintext into `crc`, and hand the sink back once the encoder has
/// flushed its trailer.
#[cfg(any(
    feature = "gzip",
    feature = "deflate64",
    feature = "bzip2",
    feature = "lzma",
    feature = "xz",
    feature = "zstd"
))]
fn stream_encode<W: Write, E: compcol::Encoder>(
    sink: W,
    enc: E,
    reader: &mut dyn std::io::Read,
    len: u64,
    crc: &mut u32,
    buf: &mut [u8],
) -> Result<W> {
    let mut enc = compcol::io::EncoderWriter::new(sink, enc);
    let mut remaining = len;
    while remaining > 0 {
        let want = remaining.min(buf.len() as u64) as usize;
        reader.read_exact(&mut buf[..want]).map_err(Error::from)?;
        *crc = crate::crc::crc32_append(*crc, &buf[..want]);
        enc.write_all(&buf[..want]).map_err(Error::from)?;
        remaining -= want as u64;
    }
    enc.finish().map_err(Error::from)
}

/// Rewrites compcol's 13-byte `.lzma` header into zip's: `09 14`
/// (LZMA SDK 9.20, the version 7-Zip and Info-ZIP write), `05 00`
/// (property length), then the 5 property bytes. The 8-byte size that
/// follows in `.lzma` is dropped — zip keeps the size in its own
/// headers and bit 1 announces the end-of-stream marker.
#[cfg(feature = "lzma")]
struct ZipLzmaSink<'a> {
    inner: CursorSink<'a>,
    head: [u8; 13],
    seen: usize,
}

#[cfg(feature = "lzma")]
impl Write for ZipLzmaSink<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = buf.len();
        let mut rest = buf;
        if self.seen < self.head.len() {
            let take = (self.head.len() - self.seen).min(rest.len());
            self.head[self.seen..self.seen + take].copy_from_slice(&rest[..take]);
            self.seen += take;
            rest = &rest[take..];
            if self.seen == self.head.len() {
                let mut zip_hdr = [0u8; 9];
                zip_hdr[..4].copy_from_slice(&[0x09, 0x14, 0x05, 0x00]);
                zip_hdr[4..].copy_from_slice(&self.head[..5]);
                self.inner.write_all(&zip_hdr)?;
            }
        }
        if !rest.is_empty() {
            self.inner.write_all(rest)?;
        }
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

impl ArchiveBuilder for ZipWriter {
    fn add_file_streaming(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &str,
        body: &mut dyn std::io::Read,
        len: u64,
        meta: FileMeta,
    ) -> Result<()> {
        let name = Self::norm(path);
        if name.is_empty() {
            return Err(Error::InvalidArgument("zip: empty file path".into()));
        }
        let unix_mode = 0o100000 | u32::from(meta.mode);
        self.write_entry(dev, &name, unix_mode, &meta, false, Some((body, len)), &[])
    }

    fn add_dir(&mut self, dev: &mut dyn BlockDevice, path: &str, meta: FileMeta) -> Result<()> {
        let mut name = Self::norm(path);
        if name.is_empty() {
            return Ok(()); // root is implicit
        }
        name.push('/'); // ZIP marks directories with a trailing slash
        let unix_mode = 0o040000 | u32::from(meta.mode);
        self.write_entry(dev, &name, unix_mode, &meta, true, None, &[])
    }

    fn add_symlink(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &str,
        target: &str,
        meta: FileMeta,
    ) -> Result<()> {
        let name = Self::norm(path);
        let unix_mode = S_IFLNK | u32::from(meta.mode);
        self.write_entry(dev, &name, unix_mode, &meta, false, None, target.as_bytes())
    }

    fn add_device(
        &mut self,
        _dev: &mut dyn BlockDevice,
        path: &str,
        _kind: DeviceKind,
        _major: u32,
        _minor: u32,
        _meta: FileMeta,
    ) -> Result<()> {
        Err(Error::Unsupported(format!(
            "zip: cannot store device/special node {path:?} — ZIP has no such record"
        )))
    }

    fn finish(&mut self, dev: &mut dyn BlockDevice) -> Result<()> {
        let cd_start = self.cursor.position();
        let records = std::mem::take(&mut self.central);

        for r in &records {
            // The ZIP64 extra carries the fields whose fixed slot holds
            // 0xFFFFFFFF, in a fixed order — so when only the
            // compressed size overflows, the uncompressed one has to
            // move with it or a reader would mis-assign the first u64.
            let sizes_zip64 = r.uncomp_size >= U32_MAX || r.comp_size >= U32_MAX;
            let offset_zip64 = r.local_offset >= U32_MAX;
            let mut zip64 = Vec::new();
            if sizes_zip64 {
                push_u64(&mut zip64, r.uncomp_size);
                push_u64(&mut zip64, r.comp_size);
            }
            if offset_zip64 {
                push_u64(&mut zip64, r.local_offset);
            }
            let name_bytes = r.name.as_bytes();
            let external_attr = (r.unix_mode << 16) | if r.is_dir { 0x10 } else { 0 };

            let mut rec = Vec::with_capacity(46 + name_bytes.len() + zip64.len());
            push_u32(&mut rec, SIG_CENTRAL);
            push_u16(&mut rec, (HOST_UNIX << 8) | 63); // version made by
            push_u16(
                &mut rec,
                r.version_needed.max(if zip64.is_empty() { 20 } else { 45 }),
            );
            push_u16(&mut rec, r.gp_flags);
            push_u16(&mut rec, r.method);
            push_u16(&mut rec, r.dos_time);
            push_u16(&mut rec, r.dos_date);
            push_u32(&mut rec, r.crc);
            let fixed = |v: u64, overflowed: bool| {
                if overflowed { U32_MAX as u32 } else { v as u32 }
            };
            push_u32(&mut rec, fixed(r.comp_size, sizes_zip64));
            push_u32(&mut rec, fixed(r.uncomp_size, sizes_zip64));
            push_u16(&mut rec, name_bytes.len() as u16);
            push_u16(
                &mut rec,
                if zip64.is_empty() {
                    0
                } else {
                    zip64.len() as u16 + 4
                },
            );
            push_u16(&mut rec, 0); // comment len
            push_u16(&mut rec, 0); // disk start
            push_u16(&mut rec, 0); // internal attrs
            push_u32(&mut rec, external_attr);
            push_u32(&mut rec, fixed(r.local_offset, offset_zip64));
            rec.extend_from_slice(name_bytes);
            if !zip64.is_empty() {
                push_u16(&mut rec, 0x0001);
                push_u16(&mut rec, zip64.len() as u16);
                rec.extend_from_slice(&zip64);
            }
            self.cursor.write(dev, &rec)?;
        }

        let cd_end = self.cursor.position();
        let cd_size = cd_end - cd_start;
        let count = records.len() as u64;
        let need_zip64 = count > 0xffff || cd_size > U32_MAX || cd_start > U32_MAX;

        if need_zip64 {
            let z64_pos = self.cursor.position();
            let mut z = Vec::with_capacity(56);
            push_u32(&mut z, SIG_ZIP64_EOCD);
            push_u64(&mut z, 44); // size of remaining record
            push_u16(&mut z, (HOST_UNIX << 8) | 63);
            push_u16(&mut z, 45);
            push_u32(&mut z, 0); // disk
            push_u32(&mut z, 0); // disk w/ cd
            push_u64(&mut z, count);
            push_u64(&mut z, count);
            push_u64(&mut z, cd_size);
            push_u64(&mut z, cd_start);
            self.cursor.write(dev, &z)?;

            let mut loc = Vec::with_capacity(20);
            push_u32(&mut loc, SIG_ZIP64_LOCATOR);
            push_u32(&mut loc, 0); // disk of zip64 eocd
            push_u64(&mut loc, z64_pos);
            push_u32(&mut loc, 1); // total disks
            self.cursor.write(dev, &loc)?;
        }

        let mut eocd = Vec::with_capacity(22);
        push_u32(&mut eocd, SIG_EOCD);
        push_u16(&mut eocd, 0); // disk
        push_u16(&mut eocd, 0); // disk w/ cd
        push_u16(&mut eocd, count.min(0xffff) as u16);
        push_u16(&mut eocd, count.min(0xffff) as u16);
        push_u32(&mut eocd, cd_size.min(U32_MAX) as u32);
        push_u32(&mut eocd, cd_start.min(U32_MAX) as u32);
        push_u16(&mut eocd, 0); // comment len
        self.cursor.write(dev, &eocd)?;

        dev.sync()?;
        Ok(())
    }

    fn position(&self) -> u64 {
        self.cursor.position()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// DEFLATE can grow an incompressible body, so an input a little
    /// under 4 GiB can produce a compressed size above it. The local
    /// file header commits to 32-bit sizes before the body is written,
    /// so the bound has to leave that room.
    #[test]
    fn deflate_bound_crosses_u32_before_the_input_does() {
        // Worst-case expansion is ~5 bytes per 65535-byte stored block.
        let n = U32_MAX - 1024;
        assert!(n < U32_MAX);
        assert!(
            deflate_max_output(n) >= U32_MAX,
            "a {n}-byte body must be treated as ZIP64"
        );
        // Well clear of the limit, the bound stays 32-bit.
        assert!(deflate_max_output(1 << 20) < U32_MAX);
        // And it never wraps.
        assert_eq!(deflate_max_output(u64::MAX), u64::MAX);
    }

    // ─── round trips through our own reader ─────────────────────────

    use crate::block::MemoryBackend;
    use crate::fs::Filesystem;
    use std::path::Path;

    /// Build a zip holding a compressible text and an incompressible
    /// blob, trim the device to the archive's length (the scanner wants
    /// the EOCD at the very end, as a file on disk has it), and hand the
    /// bytes back.
    fn build(method: Compression, level: u32) -> Vec<u8> {
        let text = b"the quick brown fox jumps over the lazy dog\n".repeat(400);
        let mut noise = Vec::with_capacity(20_000);
        let mut x = 0x2545_f491_4f6c_dd1du64;
        while noise.len() < 20_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            noise.extend_from_slice(&x.to_le_bytes());
        }
        let mut dev = MemoryBackend::new(256 * 1024);
        let mut fs =
            super::super::ZipFs::format(&mut dev, &ZipFormatOpts { method, level }).unwrap();
        let meta = FileMeta {
            mode: 0o644,
            mtime: 1_700_000_000,
            ..Default::default()
        };
        fs.create_dir(&mut dev, Path::new("/d"), meta).unwrap();
        fs.create_file_streaming(
            &mut dev,
            Path::new("/d/text.txt"),
            &mut &text[..],
            text.len() as u64,
            meta,
        )
        .unwrap();
        fs.create_file_streaming(
            &mut dev,
            Path::new("/noise.bin"),
            &mut &noise[..],
            noise.len() as u64,
            meta,
        )
        .unwrap();
        fs.create_file_streaming(&mut dev, Path::new("/empty"), &mut &[][..], 0, meta)
            .unwrap();
        fs.flush(&mut dev).unwrap();
        let len = fs.image_len().unwrap() as usize;
        dev.as_slice()[..len].to_vec()
    }

    fn read_back(arc: &[u8], path: &str) -> (Vec<u8>, crate::fs::archive::Method) {
        let mut dev = MemoryBackend::new(arc.len() as u64);
        dev.write_at(0, arc).unwrap();
        let idx = super::super::scan::scan(&mut dev).unwrap();
        let method = idx.lookup(path).unwrap().data.as_ref().unwrap().method;
        let mut fs = super::super::ZipFs::open(&mut dev).unwrap();
        let mut r = fs.read_file(&mut dev, Path::new(path)).unwrap();
        let mut out = Vec::new();
        std::io::Read::read_to_end(&mut r, &mut out).unwrap();
        (out, method)
    }

    fn round_trip(method: Compression, want: crate::fs::archive::Method) {
        let arc = build(method, 6);
        let text = b"the quick brown fox jumps over the lazy dog\n".repeat(400);
        let (got, m) = read_back(&arc, "/d/text.txt");
        assert_eq!(m, want, "{method:?}: method id written");
        assert_eq!(got, text, "{method:?}: text body");
        let (noise, _) = read_back(&arc, "/noise.bin");
        assert_eq!(noise.len(), 20_000, "{method:?}: noise body");
        // Empty bodies are always Stored, whatever the option says.
        let (empty, m) = read_back(&arc, "/empty");
        assert!(empty.is_empty());
        assert_eq!(m, crate::fs::archive::Method::Stored);
        // The compressible member must actually have shrunk.
        if method != Compression::Stored {
            let mut dev = MemoryBackend::new(arc.len() as u64);
            dev.write_at(0, &arc).unwrap();
            let idx = super::super::scan::scan(&mut dev).unwrap();
            let loc = idx.lookup("/d/text.txt").unwrap().data.clone().unwrap();
            assert!(
                loc.compressed_len < loc.uncompressed_len / 4,
                "{method:?}: {} -> {} bytes",
                loc.uncompressed_len,
                loc.compressed_len
            );
        }
    }

    #[test]
    fn round_trip_stored() {
        round_trip(Compression::Stored, crate::fs::archive::Method::Stored);
    }

    #[cfg(feature = "gzip")]
    #[test]
    fn round_trip_deflate() {
        round_trip(Compression::Deflate, crate::fs::archive::Method::Deflate);
    }

    #[cfg(feature = "deflate64")]
    #[test]
    fn round_trip_deflate64() {
        round_trip(
            Compression::Deflate64,
            crate::fs::archive::Method::Deflate64,
        );
    }

    #[cfg(feature = "bzip2")]
    #[test]
    fn round_trip_bzip2() {
        round_trip(
            Compression::Bzip2,
            crate::fs::archive::Method::Codec(crate::compression::Algo::Bzip2),
        );
    }

    /// The header rewrite: 4 zip bytes + 5 property bytes replace
    /// compcol's 13-byte `.lzma` header, and bit 1 announces the EOS
    /// marker.
    #[cfg(feature = "lzma")]
    #[test]
    fn round_trip_lzma() {
        round_trip(
            Compression::Lzma,
            crate::fs::archive::Method::ZipLzma { eos: true },
        );
        let arc = build(Compression::Lzma, 6);
        let mut dev = MemoryBackend::new(arc.len() as u64);
        dev.write_at(0, &arc).unwrap();
        let idx = super::super::scan::scan(&mut dev).unwrap();
        let loc = idx.lookup("/d/text.txt").unwrap().data.clone().unwrap();
        let body = &arc[loc.offset as usize..][..9];
        assert_eq!(&body[..4], &[0x09, 0x14, 0x05, 0x00]);
        // Properties byte: lc=3 lp=0 pb=2 is 0x5d, the universal default.
        assert_eq!(body[4], 0x5d);
    }

    #[cfg(feature = "xz")]
    #[test]
    fn round_trip_xz() {
        round_trip(
            Compression::Xz,
            crate::fs::archive::Method::Codec(crate::compression::Algo::Xz),
        );
    }

    #[cfg(feature = "zstd")]
    #[test]
    fn round_trip_zstd() {
        round_trip(
            Compression::Zstd,
            crate::fs::archive::Method::Codec(crate::compression::Algo::Zstd),
        );
    }

    /// `compression=` names every method; one this build lacks is an
    /// error naming the feature, not a silent Stored.
    #[test]
    fn option_parsing() {
        let mut bag = crate::format_opts::OptionMap::new();
        bag.insert("compression", "bogus");
        let mut o = ZipFormatOpts::default();
        assert!(o.apply_options(&mut bag).is_err());

        for (name, method) in [
            ("stored", Compression::Stored),
            ("deflate", Compression::Deflate),
            ("deflate64", Compression::Deflate64),
            ("bzip2", Compression::Bzip2),
            ("lzma", Compression::Lzma),
            ("xz", Compression::Xz),
            ("zstd", Compression::Zstd),
        ] {
            let mut bag = crate::format_opts::OptionMap::new();
            bag.insert("compression", name);
            let mut o = ZipFormatOpts::default();
            let r = o.apply_options(&mut bag);
            if method.enabled() {
                r.unwrap();
                assert_eq!(o.method, method);
            } else {
                let err = r.unwrap_err();
                assert!(
                    matches!(&err, Error::Unsupported(m) if m.contains(method.feature().unwrap())),
                    "{name}: {err:?}"
                );
            }
        }
    }
}
