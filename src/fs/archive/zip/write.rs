//! ZIP writer.
//!
//! Each `create_*` writes a local file header then streams the body at
//! a bumping cursor, computing the CRC-32 and compressed size on the
//! fly and back-patching them into the header afterwards (the device is
//! seekable). `flush` appends the central directory and the EOCD,
//! emitting ZIP64 structures only when an entry, offset, or count
//! crosses the 32-bit limit.
//!
//! Every member carries the Info-ZIP extras other tools expect: `UT`
//! (0x5455) with the Unix mtime (and atime in the local copy) and `ux`
//! (0x7875) with the 32-bit uid / gid.
//!
//! With a passphrase, file bodies are encrypted — traditional PKWARE
//! (general-purpose bit 0, plus bit 3 and a data descriptor since the
//! check byte must be known before the CRC is) or WinZip AES (method 99,
//! AE-1 with the real CRC, the real method in the 0x9901 extra).
//!
//! With `split`, volumes are laid out back to back in the device: a
//! header never straddles a volume boundary (the writer starts the next
//! volume instead, as PKZIP does), bodies may, offsets in the central
//! directory are volume-relative, and the first volume opens with the
//! split signature. [`ZipWriter::volume_layout`] reports the cuts.
//!
//! Per the universal-zip technique we set the UTF-8 flag (bit 11) only
//! for non-ASCII names; because non-ASCII names are therefore never
//! unflagged, declaring host-OS = Unix (so we can carry POSIX mode bits
//! and symlinks for round-tripping) does not risk the Windows
//! mangling the note warns about.

use std::io::{self, Write};

use super::crypto::ZipCryptoWriter;
use super::encoding;
use super::{
    Compression, Encryption, METHOD_AES, SIG_CENTRAL, SIG_EOCD, SIG_LOCAL, SIG_SPLIT,
    SIG_ZIP64_EOCD, SIG_ZIP64_LOCATOR, ZipFormatOpts,
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
/// "Version made by" / the ceiling we may need: 6.3 (APPNOTE 6.3.x
/// methods).
const VERSION_MADE_BY: u16 = 63;
/// Version needed for a WinZip AES member.
const VERSION_AES: u16 = 51;
const SIG_DESCRIPTOR: u32 = 0x0807_4b50;

/// One central-directory record, accumulated until `finish`.
struct CdRec {
    name: String,
    /// General-purpose flags as written in the local header.
    gp_flags: u16,
    /// "Version needed to extract" as written in the local header.
    version_needed: u16,
    /// Method id as written (99 for AES; the real one is in `aes`).
    method: u16,
    crc: u32,
    comp_size: u64,
    uncomp_size: u64,
    /// Linear offset of the local header in the device.
    local_offset: u64,
    dos_date: u16,
    dos_time: u16,
    /// Full Unix `st_mode` (type bits included) for the external attrs.
    unix_mode: u32,
    is_dir: bool,
    uid: u32,
    gid: u32,
    mtime: u32,
    /// WinZip AES: (strength byte, real method id).
    aes: Option<(u8, u16)>,
}

pub struct ZipWriter {
    cursor: Cursor,
    opts: ZipFormatOpts,
    central: Vec<CdRec>,
    /// Linear start offset of each volume; `[0]` is always `0`. One
    /// element unless `opts.split` is set and the archive outgrew it.
    disk_starts: Vec<u64>,
    /// Whether the first bytes (the split signature, when splitting)
    /// have been written.
    started: bool,
    /// Linear end of the archive once `finish` has run.
    end: Option<u64>,
}

/// `Write` sink that appends to the device through the shared cursor.
struct CursorSink<'a> {
    cursor: &'a mut Cursor,
    dev: &'a mut dyn BlockDevice,
}

impl Write for CursorSink<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.cursor.write(self.dev, buf).map_err(io::Error::other)?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A body sink that may owe a trailer (AES's authentication code).
trait BodySink: Write {
    fn finish(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl BodySink for CursorSink<'_> {}
impl<W: Write> BodySink for ZipCryptoWriter<W> {}
#[cfg(feature = "zip-aes")]
impl<W: Write> BodySink for super::crypto::AesWriter<W> {
    fn finish(&mut self) -> io::Result<()> {
        super::crypto::AesWriter::finish(self)
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

/// The Info-ZIP `UT` and `ux` extras. The local copy of `UT` carries
/// mtime and atime; the central copy mtime alone (its flags still say
/// what the local one holds, as Info-ZIP writes it).
fn push_unix_extras(v: &mut Vec<u8>, local: bool, mtime: u32, atime: u32, uid: u32, gid: u32) {
    push_u16(v, 0x5455);
    push_u16(v, if local { 9 } else { 5 });
    v.push(0x03);
    push_u32(v, mtime);
    if local {
        push_u32(v, atime);
    }
    push_u16(v, 0x7875);
    push_u16(v, 11);
    v.push(1);
    v.push(4);
    push_u32(v, uid);
    v.push(4);
    push_u32(v, gid);
}

/// The WinZip AES extra: AE-1 (CRC present), vendor "AE", key strength,
/// the real compression method.
fn push_aes_extra(v: &mut Vec<u8>, strength: u8, method: u16) {
    push_u16(v, 0x9901);
    push_u16(v, 7);
    push_u16(v, 1);
    v.extend_from_slice(b"AE");
    v.push(strength);
    push_u16(v, method);
}

/// What `write_entry` is asked to put in a body.
enum Body<'a> {
    /// Stream `len` bytes from the reader, through the chosen method.
    Stream(&'a mut dyn io::Read, u64),
    /// A small in-memory body (symlink target), always Stored.
    Inline(&'a [u8]),
}

impl ZipWriter {
    pub fn new(dev: &dyn BlockDevice, opts: ZipFormatOpts) -> Self {
        Self {
            cursor: Cursor::new(dev),
            opts,
            central: Vec::new(),
            disk_starts: vec![0],
            started: false,
            end: None,
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

    /// The split signature opens the first volume of a split archive.
    fn begin(&mut self, dev: &mut dyn BlockDevice) -> Result<()> {
        if !self.started {
            self.started = true;
            if self.opts.split.is_some() {
                self.cursor.write(dev, &SIG_SPLIT.to_le_bytes())?;
            }
        }
        Ok(())
    }

    /// Called before each header: account for the volume boundaries the
    /// preceding body ran through (a body spans volumes freely, cut
    /// every `limit` bytes), then start a new volume if the `n`-byte
    /// header would straddle the current one's limit — a volume may end
    /// short, never long. A header larger than the volume size on an
    /// otherwise empty volume simply overruns, as it must.
    fn ensure_room(&mut self, n: u64) {
        let Some(limit) = self.opts.split else {
            return;
        };
        let pos = self.cursor.position();
        loop {
            let start = *self.disk_starts.last().expect("disk 0");
            if pos - start >= limit {
                self.disk_starts.push(start + limit);
            } else {
                break;
            }
        }
        let start = *self.disk_starts.last().expect("disk 0");
        if pos > start && pos - start + n > limit {
            self.disk_starts.push(pos);
        }
    }

    /// Volume index holding linear offset `off`.
    fn disk_of(&self, off: u64) -> usize {
        self.disk_starts.partition_point(|&s| s <= off) - 1
    }

    /// Codec level in the encoder's own 1-based scale: zip level 0
    /// (meaning "store") maps up to 1.
    #[allow(dead_code)]
    fn codec_level(&self) -> u8 {
        self.opts.level.clamp(1, 9) as u8
    }

    /// Write a local file header + body and record the central entry.
    #[allow(clippy::too_many_arguments)]
    fn write_entry(
        &mut self,
        dev: &mut dyn BlockDevice,
        name: &str,
        unix_mode: u32,
        meta: &FileMeta,
        is_dir: bool,
        body: Body<'_>,
        encrypt: bool,
    ) -> Result<()> {
        self.begin(dev)?;
        let uncomp = match &body {
            Body::Stream(_, n) => *n,
            Body::Inline(b) => b.len() as u64,
        };
        let method = match &body {
            Body::Stream(..) => self.body_method(uncomp),
            // Small in-memory bodies are stored verbatim.
            Body::Inline(_) => Compression::Stored,
        };
        let real_method_id = method.method_id();
        let encryption = if encrypt && self.opts.password.is_some() {
            Some(self.opts.encryption)
        } else {
            None
        };
        let aes = encryption
            .and_then(|e| e.key_bits())
            .map(|bits| match bits {
                128 => 1u8,
                192 => 2,
                _ => 3,
            });
        let method_id = if aes.is_some() {
            METHOD_AES
        } else {
            real_method_id
        };

        // Bit 11: the name is UTF-8. Bit 1: for LZMA, the stream ends
        // with an end-of-stream marker (compcol's encoder always writes
        // one, and leaves the size field unknown). Bit 0: encrypted.
        // Bit 3: sizes and CRC follow the body in a data descriptor —
        // needed by ZipCrypto, whose check byte then derives from the
        // DOS time rather than the CRC we don't know yet.
        let mut gp_flags = if encoding::needs_utf8_flag(name) {
            0x0800
        } else {
            0
        };
        if method == Compression::Lzma {
            gp_flags |= 0x0002;
        }
        let descriptor = matches!(encryption, Some(Encryption::ZipCrypto));
        if encryption.is_some() {
            gp_flags |= 0x0001;
        }
        if descriptor {
            gp_flags |= 0x0008;
        }
        let (dos_date, dos_time) = super::unix_to_dos(u64::from(meta.mtime));
        let worst_comp = compressed_max_output(method, uncomp).saturating_add(
            encryption.map_or(0, |e| e.key_bits().map_or(12, |b| b as u64 / 16 + 12)),
        );
        let entry_zip64 = uncomp >= U32_MAX || worst_comp >= U32_MAX;
        let mut version_needed = method
            .version_needed()
            .max(if entry_zip64 { 45 } else { 20 });
        if aes.is_some() {
            version_needed = version_needed.max(VERSION_AES);
        }
        let name_bytes = name.as_bytes();

        // --- local file header (30 bytes + name + extras) ---
        let mut extra = Vec::with_capacity(48);
        if entry_zip64 {
            push_u16(&mut extra, 0x0001);
            push_u16(&mut extra, 16);
            push_u64(&mut extra, if descriptor { 0 } else { uncomp });
            push_u64(&mut extra, 0); // comp — patched
        }
        push_unix_extras(&mut extra, true, meta.mtime, meta.atime, meta.uid, meta.gid);
        if let Some(strength) = aes {
            push_aes_extra(&mut extra, strength, real_method_id);
        }
        let mut hdr = Vec::with_capacity(30 + name_bytes.len() + extra.len());
        push_u32(&mut hdr, SIG_LOCAL);
        push_u16(&mut hdr, version_needed);
        push_u16(&mut hdr, gp_flags);
        push_u16(&mut hdr, method_id);
        push_u16(&mut hdr, dos_time);
        push_u16(&mut hdr, dos_date);
        push_u32(&mut hdr, 0); // crc — patched (left 0 with a descriptor)
        push_u32(&mut hdr, if entry_zip64 { U32_MAX as u32 } else { 0 }); // comp — patched
        push_u32(
            &mut hdr,
            if entry_zip64 {
                U32_MAX as u32
            } else if descriptor {
                0
            } else {
                uncomp as u32
            },
        );
        push_u16(&mut hdr, name_bytes.len() as u16);
        push_u16(&mut hdr, extra.len() as u16);
        hdr.extend_from_slice(name_bytes);
        hdr.extend_from_slice(&extra);
        self.ensure_room(hdr.len() as u64);
        let local_offset = self.cursor.position();
        self.cursor.write(dev, &hdr)?;

        // --- body: [encrypt(] compress(plain) [)] ---
        let body_start = self.cursor.position();
        let check = (dos_time >> 8) as u8;
        let crc = {
            let raw = CursorSink {
                cursor: &mut self.cursor,
                dev,
            };
            let pw = self.opts.password.as_deref().unwrap_or("").as_bytes();
            let mut sink: Box<dyn BodySink + '_> = match encryption {
                None => Box::new(raw),
                Some(Encryption::ZipCrypto) => {
                    Box::new(ZipCryptoWriter::new(raw, pw, check).map_err(Error::from)?)
                }
                Some(e) => aes_sink(raw, pw, e.key_bits().expect("aes"))?,
            };
            let crc = encode_body(&mut *sink, method, self.opts.level, body)?;
            sink.finish().map_err(Error::from)?;
            crc
        };
        let comp_size = self.cursor.position() - body_start;

        // --- sizes: a data descriptor after the body, or back-patched
        // into the header ---
        if descriptor {
            let mut d = Vec::with_capacity(24);
            push_u32(&mut d, SIG_DESCRIPTOR);
            push_u32(&mut d, crc);
            if entry_zip64 {
                push_u64(&mut d, comp_size);
                push_u64(&mut d, uncomp);
            } else {
                push_u32(&mut d, comp_size as u32);
                push_u32(&mut d, uncomp as u32);
            }
            self.cursor.write(dev, &d)?;
        } else {
            dev.write_at(local_offset + 14, &crc.to_le_bytes())?;
            if entry_zip64 {
                // comp lives in the zip64 extra (after id+size+uncomp = +8).
                let extra_data = local_offset + 30 + name_bytes.len() as u64 + 4;
                dev.write_at(extra_data + 8, &comp_size.to_le_bytes())?;
            } else {
                dev.write_at(local_offset + 18, &(comp_size as u32).to_le_bytes())?;
                dev.write_at(local_offset + 22, &(uncomp as u32).to_le_bytes())?;
            }
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
            uid: meta.uid,
            gid: meta.gid,
            mtime: meta.mtime,
            aes: aes.map(|s| (s, real_method_id)),
        });
        Ok(())
    }

    /// The volume cuts, once `finish` has run on a split archive.
    pub fn volume_layout(&self) -> Option<Vec<(u64, u64)>> {
        let end = self.end?;
        self.opts.split?;
        Some(
            self.disk_starts
                .iter()
                .enumerate()
                .map(|(i, &s)| (s, self.disk_starts.get(i + 1).copied().unwrap_or(end)))
                .collect(),
        )
    }
}

#[cfg(feature = "zip-aes")]
fn aes_sink<'a>(raw: CursorSink<'a>, pw: &[u8], key_bits: u16) -> Result<Box<dyn BodySink + 'a>> {
    Ok(Box::new(
        super::crypto::AesWriter::new(raw, pw, key_bits).map_err(Error::from)?,
    ))
}

#[cfg(not(feature = "zip-aes"))]
fn aes_sink<'a>(
    _raw: CursorSink<'a>,
    _pw: &[u8],
    _key_bits: u16,
) -> Result<Box<dyn BodySink + 'a>> {
    Err(super::crypto::aes_disabled())
}

/// Compress `body` with `method` into `sink`, returning the CRC-32 of
/// the plaintext.
fn encode_body(
    sink: &mut dyn Write,
    method: Compression,
    level: u32,
    body: Body<'_>,
) -> Result<u32> {
    match body {
        Body::Inline(b) => {
            sink.write_all(b).map_err(Error::from)?;
            Ok(crate::crc::crc32(b))
        }
        Body::Stream(reader, len) => {
            // The running CRC is just its state; `crc32_append` composes,
            // so there is nothing to hold but a `u32`.
            let mut crc = 0u32;
            let mut buf = vec![0u8; 64 * 1024];
            let level = level.clamp(1, 9) as u8;
            match method {
                Compression::Stored => {
                    let mut remaining = len;
                    while remaining > 0 {
                        let want = remaining.min(buf.len() as u64) as usize;
                        reader.read_exact(&mut buf[..want]).map_err(Error::from)?;
                        crc = crate::crc::crc32_append(crc, &buf[..want]);
                        sink.write_all(&buf[..want]).map_err(Error::from)?;
                        remaining -= want as u64;
                    }
                }
                Compression::Deflate => {
                    stream_deflate(sink, reader, len, &mut crc, &mut buf, level)?
                }
                Compression::Deflate64 => {
                    stream_deflate64(sink, reader, len, &mut crc, &mut buf, level)?
                }
                Compression::Bzip2 => stream_bzip2(sink, reader, len, &mut crc, &mut buf, level)?,
                Compression::Lzma => stream_lzma(sink, reader, len, &mut crc, &mut buf, level)?,
                Compression::Xz => stream_xz(sink, reader, len, &mut crc, &mut buf, level)?,
                Compression::Zstd => stream_zstd(sink, reader, len, &mut crc, &mut buf, level)?,
            }
            Ok(crc)
        }
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
    reader: &mut dyn io::Read,
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

macro_rules! codec_stream {
    ($name:ident, $feature:literal, $method:expr, $enc:expr) => {
        #[cfg(feature = $feature)]
        fn $name(
            sink: &mut dyn Write,
            reader: &mut dyn io::Read,
            len: u64,
            crc: &mut u32,
            buf: &mut [u8],
            level: u8,
        ) -> Result<()> {
            use compcol::Algorithm;
            let _ = level;
            stream_encode(sink, $enc(level), reader, len, crc, buf)?;
            Ok(())
        }

        #[cfg(not(feature = $feature))]
        fn $name(
            _sink: &mut dyn Write,
            _reader: &mut dyn io::Read,
            _len: u64,
            _crc: &mut u32,
            _buf: &mut [u8],
            _level: u8,
        ) -> Result<()> {
            Err(disabled($method))
        }
    };
}

codec_stream!(stream_deflate, "gzip", Compression::Deflate, |level| {
    compcol::deflate::Deflate::encoder_with(
        compcol::deflate::EncoderConfig::default().with_level(level),
    )
});
codec_stream!(
    stream_deflate64,
    "deflate64",
    Compression::Deflate64,
    |level| {
        compcol::deflate64::Deflate64::encoder_with(compcol::deflate64::EncoderConfig { level })
    }
);
codec_stream!(stream_bzip2, "bzip2", Compression::Bzip2, |level| {
    compcol::bzip2::Bzip2::encoder_with(compcol::bzip2::EncoderConfig { level })
});
codec_stream!(stream_xz, "xz", Compression::Xz, |level| {
    compcol::xz::Xz::encoder_with(compcol::xz::EncoderConfig { level })
});
codec_stream!(stream_zstd, "zstd", Compression::Zstd, |level| {
    compcol::zstd::Zstd::encoder_with(compcol::zstd::EncoderConfig {
        level: i32::from(level),
    })
});

/// LZMA: compcol emits the `.lzma` "alone" framing (5 property bytes
/// and an 8-byte size, left unknown so an end-of-stream marker closes
/// the body). The zip framing wants a 2-byte version, a 2-byte
/// property length, the 5 property bytes, and no size —
/// [`ZipLzmaSink`] does that rewrite on the way out.
#[cfg(feature = "lzma")]
fn stream_lzma(
    sink: &mut dyn Write,
    reader: &mut dyn io::Read,
    len: u64,
    crc: &mut u32,
    buf: &mut [u8],
    level: u8,
) -> Result<()> {
    use compcol::Algorithm;
    let cfg = compcol::lzma::EncoderConfig { level };
    let wrapped = ZipLzmaSink {
        inner: sink,
        head: [0u8; 13],
        seen: 0,
    };
    let wrapped = stream_encode(
        wrapped,
        compcol::lzma::Lzma::encoder_with(cfg),
        reader,
        len,
        crc,
        buf,
    )?;
    if wrapped.seen < wrapped.head.len() {
        return Err(Error::Io(io::Error::other(
            "zip: LZMA encoder produced no stream header",
        )));
    }
    Ok(())
}

#[cfg(not(feature = "lzma"))]
fn stream_lzma(
    _sink: &mut dyn Write,
    _reader: &mut dyn io::Read,
    _len: u64,
    _crc: &mut u32,
    _buf: &mut [u8],
    _level: u8,
) -> Result<()> {
    Err(disabled(Compression::Lzma))
}

/// Rewrites compcol's 13-byte `.lzma` header into zip's: `09 14`
/// (LZMA SDK 9.20, the version 7-Zip and Info-ZIP write), `05 00`
/// (property length), then the 5 property bytes. The 8-byte size that
/// follows in `.lzma` is dropped — zip keeps the size in its own
/// headers and bit 1 announces the end-of-stream marker.
#[cfg(feature = "lzma")]
struct ZipLzmaSink<W: Write> {
    inner: W,
    head: [u8; 13],
    seen: usize,
}

#[cfg(feature = "lzma")]
impl<W: Write> Write for ZipLzmaSink<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
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
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl ArchiveBuilder for ZipWriter {
    fn add_file_streaming(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &str,
        body: &mut dyn io::Read,
        len: u64,
        meta: FileMeta,
    ) -> Result<()> {
        let name = Self::norm(path);
        if name.is_empty() {
            return Err(Error::InvalidArgument("zip: empty file path".into()));
        }
        let unix_mode = 0o100000 | u32::from(meta.mode);
        self.write_entry(
            dev,
            &name,
            unix_mode,
            &meta,
            false,
            Body::Stream(body, len),
            true,
        )
    }

    fn add_dir(&mut self, dev: &mut dyn BlockDevice, path: &str, meta: FileMeta) -> Result<()> {
        let mut name = Self::norm(path);
        if name.is_empty() {
            return Ok(()); // root is implicit
        }
        name.push('/'); // ZIP marks directories with a trailing slash
        let unix_mode = 0o040000 | u32::from(meta.mode);
        self.write_entry(dev, &name, unix_mode, &meta, true, Body::Inline(&[]), false)
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
        self.write_entry(
            dev,
            &name,
            unix_mode,
            &meta,
            false,
            Body::Inline(target.as_bytes()),
            false,
        )
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
        self.begin(dev)?;
        let records = std::mem::take(&mut self.central);

        // Central directory: one record per member, none straddling a
        // volume boundary. Remember where each landed for the per-disk
        // entry count in the EOCD.
        let mut cd_start = None;
        let mut rec_positions = Vec::with_capacity(records.len());
        for r in &records {
            let disk = self.disk_of(r.local_offset);
            let rel_offset = r.local_offset - self.disk_starts[disk];
            // The ZIP64 extra carries the fields whose fixed slot holds
            // the sentinel, in a fixed order — so when only the
            // compressed size overflows, the uncompressed one has to
            // move with it or a reader would mis-assign the first u64.
            let sizes_zip64 = r.uncomp_size >= U32_MAX || r.comp_size >= U32_MAX;
            let offset_zip64 = rel_offset >= U32_MAX;
            let disk_zip64 = disk >= 0xffff;
            let mut zip64 = Vec::new();
            if sizes_zip64 {
                push_u64(&mut zip64, r.uncomp_size);
                push_u64(&mut zip64, r.comp_size);
            }
            if offset_zip64 {
                push_u64(&mut zip64, rel_offset);
            }
            if disk_zip64 {
                push_u32(&mut zip64, disk as u32);
            }
            let mut extra = Vec::with_capacity(zip64.len() + 4 + 32);
            if !zip64.is_empty() {
                push_u16(&mut extra, 0x0001);
                push_u16(&mut extra, zip64.len() as u16);
                extra.extend_from_slice(&zip64);
            }
            push_unix_extras(&mut extra, false, r.mtime, 0, r.uid, r.gid);
            if let Some((strength, method)) = r.aes {
                push_aes_extra(&mut extra, strength, method);
            }
            let name_bytes = r.name.as_bytes();
            let external_attr = (r.unix_mode << 16) | if r.is_dir { 0x10 } else { 0 };

            let mut rec = Vec::with_capacity(46 + name_bytes.len() + extra.len());
            push_u32(&mut rec, SIG_CENTRAL);
            push_u16(&mut rec, (HOST_UNIX << 8) | VERSION_MADE_BY);
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
            push_u16(&mut rec, extra.len() as u16);
            push_u16(&mut rec, 0); // comment len
            push_u16(&mut rec, if disk_zip64 { 0xffff } else { disk as u16 });
            push_u16(&mut rec, 0); // internal attrs
            push_u32(&mut rec, external_attr);
            push_u32(&mut rec, fixed(rel_offset, offset_zip64));
            rec.extend_from_slice(name_bytes);
            rec.extend_from_slice(&extra);
            self.ensure_room(rec.len() as u64);
            let pos = self.cursor.position();
            cd_start.get_or_insert(pos);
            rec_positions.push(pos);
            self.cursor.write(dev, &rec)?;
        }

        let cd_end = self.cursor.position();
        let cd_start = cd_start.unwrap_or(cd_end);
        let cd_size = cd_end - cd_start;
        let count = records.len() as u64;
        let cd_disk = self.disk_of(cd_start);
        let cd_rel = cd_start - self.disk_starts[cd_disk];

        // The trailer stays on one volume: ZIP64 record + locator + EOCD.
        let need_zip64 = count > 0xffff
            || cd_size > U32_MAX
            || cd_rel > U32_MAX
            || self.disk_starts.len() > 0xffff;
        self.ensure_room(if need_zip64 { 56 + 20 + 22 } else { 22 });
        let this_disk = self.disk_starts.len() - 1;
        let this_start = self.disk_starts[this_disk];
        let entries_this_disk = rec_positions.iter().filter(|&&p| p >= this_start).count() as u64;
        let need_zip64 = need_zip64 || entries_this_disk > 0xffff;

        if need_zip64 {
            let z64_pos = self.cursor.position();
            let mut z = Vec::with_capacity(56);
            push_u32(&mut z, SIG_ZIP64_EOCD);
            push_u64(&mut z, 44); // size of remaining record
            push_u16(&mut z, (HOST_UNIX << 8) | VERSION_MADE_BY);
            push_u16(&mut z, 45);
            push_u32(&mut z, this_disk as u32);
            push_u32(&mut z, cd_disk as u32);
            push_u64(&mut z, entries_this_disk);
            push_u64(&mut z, count);
            push_u64(&mut z, cd_size);
            push_u64(&mut z, cd_rel);
            self.cursor.write(dev, &z)?;

            let mut loc = Vec::with_capacity(20);
            push_u32(&mut loc, SIG_ZIP64_LOCATOR);
            push_u32(&mut loc, this_disk as u32); // disk of zip64 eocd
            push_u64(&mut loc, z64_pos - this_start);
            push_u32(&mut loc, self.disk_starts.len() as u32); // total disks
            self.cursor.write(dev, &loc)?;
        }

        let cap16 = |v: u64| v.min(0xffff) as u16;
        let mut eocd = Vec::with_capacity(22);
        push_u32(&mut eocd, SIG_EOCD);
        push_u16(&mut eocd, cap16(this_disk as u64));
        push_u16(&mut eocd, cap16(cd_disk as u64));
        push_u16(&mut eocd, cap16(entries_this_disk));
        push_u16(&mut eocd, cap16(count));
        push_u32(&mut eocd, cd_size.min(U32_MAX) as u32);
        push_u32(&mut eocd, cd_rel.min(U32_MAX) as u32);
        push_u16(&mut eocd, 0); // comment len
        self.cursor.write(dev, &eocd)?;

        self.end = Some(self.cursor.position());
        dev.sync()?;
        Ok(())
    }

    fn position(&self) -> u64 {
        self.cursor.position()
    }

    fn volume_layout(&self) -> Option<Vec<(u64, u64)>> {
        ZipWriter::volume_layout(self)
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

    fn text() -> Vec<u8> {
        b"the quick brown fox jumps over the lazy dog\n".repeat(400)
    }

    fn noise(n: usize) -> Vec<u8> {
        let mut noise = Vec::with_capacity(n + 8);
        let mut x = 0x2545_f491_4f6c_dd1du64;
        while noise.len() < n {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            noise.extend_from_slice(&x.to_le_bytes());
        }
        noise.truncate(n);
        noise
    }

    fn meta() -> FileMeta {
        FileMeta {
            mode: 0o640,
            uid: 1000,
            gid: 2000,
            mtime: 1_700_000_000,
            atime: 1_600_000_000,
            ctime: 1_650_000_000,
        }
    }

    /// Build a zip holding a compressible text, an incompressible blob
    /// (`noise_len` bytes), an empty file, a directory and a symlink;
    /// trim the device to the archive's length (the scanner wants the
    /// EOCD at the very end, as a file on disk has it) and hand the
    /// bytes back with the handle's volume layout.
    fn build_with(opts: ZipFormatOpts, noise_len: usize) -> (Vec<u8>, Option<Vec<(u64, u64)>>) {
        let text = text();
        let noise = noise(noise_len);
        let mut dev = MemoryBackend::new((noise_len as u64 + 256 * 1024).max(512 * 1024));
        let mut fs = super::super::ZipFs::format(&mut dev, &opts).unwrap();
        let meta = meta();
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
        fs.create_symlink(&mut dev, Path::new("/link"), Path::new("d/text.txt"), meta)
            .unwrap();
        fs.flush(&mut dev).unwrap();
        let len = fs.image_len().unwrap() as usize;
        let layout = fs.volume_layout();
        (dev.as_slice()[..len].to_vec(), layout)
    }

    fn build(method: Compression, level: u32) -> Vec<u8> {
        build_with(
            ZipFormatOpts {
                method,
                level,
                ..ZipFormatOpts::default()
            },
            20_000,
        )
        .0
    }

    fn dev_of(arc: &[u8]) -> MemoryBackend {
        let mut dev = MemoryBackend::new(arc.len() as u64);
        dev.write_at(0, arc).unwrap();
        dev
    }

    fn read_back_pw(
        arc: &[u8],
        path: &str,
        pw: Option<&str>,
    ) -> crate::Result<(Vec<u8>, crate::fs::archive::DataLocator)> {
        let mut dev = dev_of(arc);
        let idx = super::super::scan::scan(&mut dev, None)?;
        let loc = idx.lookup(path).unwrap().data.clone().unwrap();
        let mut fs = super::super::ZipFs::open_with_password(&mut dev, pw)?;
        let mut r = fs.read_file(&mut dev, Path::new(path))?;
        let mut out = Vec::new();
        std::io::Read::read_to_end(&mut r, &mut out)?;
        Ok((out, loc))
    }

    fn read_back(arc: &[u8], path: &str) -> (Vec<u8>, crate::fs::archive::Method) {
        let (out, loc) = read_back_pw(arc, path, None).unwrap();
        (out, loc.method)
    }

    fn round_trip(method: Compression, want: crate::fs::archive::Method) {
        let arc = build(method, 6);
        let (got, m) = read_back(&arc, "/d/text.txt");
        assert_eq!(m, want, "{method:?}: method id written");
        assert_eq!(got, text(), "{method:?}: text body");
        let (noise, _) = read_back(&arc, "/noise.bin");
        assert_eq!(noise.len(), 20_000, "{method:?}: noise body");
        // Empty bodies are always Stored, whatever the option says.
        let (empty, m) = read_back(&arc, "/empty");
        assert!(empty.is_empty());
        assert_eq!(m, crate::fs::archive::Method::Stored);
        // The compressible member must actually have shrunk.
        if method != Compression::Stored {
            let (_, loc) = read_back_pw(&arc, "/d/text.txt", None).unwrap();
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
        let (_, loc) = read_back_pw(&arc, "/d/text.txt", None).unwrap();
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

        let mut bag = crate::format_opts::OptionMap::new();
        bag.insert("split", "1k");
        assert!(ZipFormatOpts::default().apply_options(&mut bag).is_err());
        let mut bag = crate::format_opts::OptionMap::new();
        bag.insert("split", "64k");
        bag.insert("password", "pw");
        bag.insert("encryption", "zipcrypto");
        let mut o = ZipFormatOpts::default();
        o.apply_options(&mut bag).unwrap();
        assert_eq!(o.split, Some(64 * 1024));
        assert_eq!(o.password.as_deref(), Some("pw"));
        assert_eq!(o.encryption, Encryption::ZipCrypto);
    }

    /// uid / gid / atime travel in the `ux` and `UT` extras; the
    /// symlink target survives too.
    #[test]
    fn unix_extras_round_trip() {
        let arc = build(Compression::Stored, 6);
        let mut dev = dev_of(&arc);
        let idx = super::super::scan::scan(&mut dev, None).unwrap();
        for path in ["/d", "/d/text.txt", "/noise.bin", "/link"] {
            let e = idx.lookup(path).unwrap();
            assert_eq!((e.uid, e.gid), (1000, 2000), "{path}");
            assert_eq!(e.mtime, 1_700_000_000, "{path}");
            assert_eq!(e.atime, 1_600_000_000, "{path}");
        }
        assert_eq!(idx.lookup("/d/text.txt").unwrap().mode, 0o640);
        assert_eq!(
            idx.lookup("/link").unwrap().link_target.as_deref(),
            Some("d/text.txt")
        );
    }

    fn encrypted_round_trip(
        encryption: Encryption,
        want_crypto: impl Fn(&crate::fs::archive::Crypto) -> bool,
    ) {
        let (arc, _) = build_with(
            ZipFormatOpts {
                method: Compression::Stored,
                password: Some("secret".into()),
                encryption,
                ..ZipFormatOpts::default()
            },
            20_000,
        );
        for (path, want) in [
            ("/d/text.txt", text()),
            ("/noise.bin", noise(20_000)),
            ("/empty", vec![]),
        ] {
            let (got, loc) = read_back_pw(&arc, path, Some("secret")).unwrap();
            assert!(
                want_crypto(&loc.crypto),
                "{encryption:?} {path}: {:?}",
                loc.crypto
            );
            assert_eq!(got, want, "{encryption:?} {path}");
            assert_eq!(
                loc.compressed_len,
                want.len() as u64 + loc.crypto.overhead()
            );
            let err = read_back_pw(&arc, path, Some("wrong")).unwrap_err();
            assert!(
                matches!(&err, Error::InvalidArgument(m) if m.contains("wrong passphrase")),
                "{encryption:?} {path}: {err:?}"
            );
            assert!(read_back_pw(&arc, path, None).is_err());
        }
        // Directories and symlink targets stay in the clear.
        let mut dev = dev_of(&arc);
        let idx = super::super::scan::scan(&mut dev, None).unwrap();
        assert_eq!(
            idx.lookup("/link").unwrap().link_target.as_deref(),
            Some("d/text.txt")
        );
    }

    #[test]
    fn zipcrypto_round_trip() {
        encrypted_round_trip(Encryption::ZipCrypto, |c| {
            matches!(c, crate::fs::archive::Crypto::ZipCrypto { .. })
        });
        // The ZipCrypto members use a data descriptor, so the local
        // header carries zero sizes and the flag says so.
        let (arc, _) = build_with(
            ZipFormatOpts {
                method: Compression::Stored,
                password: Some("secret".into()),
                encryption: Encryption::ZipCrypto,
                ..ZipFormatOpts::default()
            },
            100,
        );
        let mut dev = dev_of(&arc);
        let idx = super::super::scan::scan(&mut dev, None).unwrap();
        let loc = idx.lookup("/noise.bin").unwrap().data.clone().unwrap();
        // Body = 12-byte header + 100 bytes, then the descriptor.
        let desc = (loc.offset + loc.compressed_len) as usize;
        assert_eq!(&arc[desc..desc + 4], &SIG_DESCRIPTOR.to_le_bytes());
        assert_eq!(&arc[desc + 8..desc + 12], &112u32.to_le_bytes());
        assert_eq!(&arc[desc + 12..desc + 16], &100u32.to_le_bytes());
    }

    #[cfg(feature = "zip-aes")]
    #[test]
    fn aes_round_trip() {
        for (enc, bits) in [
            (Encryption::Aes128, 128u16),
            (Encryption::Aes192, 192),
            (Encryption::Aes256, 256),
        ] {
            encrypted_round_trip(enc, |c| {
                *c == crate::fs::archive::Crypto::Aes {
                    key_bits: bits,
                    vendor_version: 1,
                }
            });
        }
    }

    /// `split`: headers never straddle a volume, the first volume opens
    /// with the split signature, offsets are volume-relative, and the
    /// volumes read back as a set.
    #[test]
    fn split_round_trip() {
        let limit = 64 * 1024;
        let (arc, layout) = build_with(
            ZipFormatOpts {
                method: Compression::Stored,
                split: Some(limit as u64),
                ..ZipFormatOpts::default()
            },
            200_000,
        );
        let layout = layout.expect("split layout");
        assert!(layout.len() >= 4, "{layout:?}");
        assert_eq!(layout[0].0, 0);
        assert_eq!(layout.last().unwrap().1, arc.len() as u64);
        for w in layout.windows(2) {
            assert_eq!(w[0].1, w[1].0, "contiguous: {layout:?}");
        }
        assert!(
            layout.iter().all(|(s, e)| e - s <= limit as u64),
            "{layout:?}"
        );
        assert_eq!(&arc[..4], &SIG_SPLIT.to_le_bytes());

        // Read back through a volume set, as the CLI does after cutting.
        let parts: Vec<Box<dyn BlockDevice>> = layout
            .iter()
            .map(|&(s, e)| Box::new(dev_of(&arc[s as usize..e as usize])) as Box<dyn BlockDevice>)
            .collect();
        let mut set = crate::block::SplitBackend::new(parts).unwrap();
        let idx = super::super::scan::scan(&mut set, None).unwrap();
        let noise_loc = idx.lookup("/noise.bin").unwrap().data.clone().unwrap();
        assert_eq!(noise_loc.uncompressed_len, 200_000);
        // The 200 000-byte body runs through several volumes; the headers
        // around it each sit inside one.
        assert!(noise_loc.offset + noise_loc.compressed_len > 3 * limit as u64);
        let mut fs = super::super::ZipFs::open(&mut set).unwrap();
        for (path, want) in [("/d/text.txt", text()), ("/noise.bin", noise(200_000))] {
            let mut r = fs.read_file(&mut set, Path::new(path)).unwrap();
            let mut out = Vec::new();
            std::io::Read::read_to_end(&mut r, &mut out).unwrap();
            assert_eq!(out, want, "{path}");
        }
        // The linear file alone is also a valid (merged) archive — offsets
        // are volume-relative, so this must fail cleanly, not misread.
        assert!(super::super::ZipFs::open(&mut dev_of(&arc)).is_err());
    }
}
