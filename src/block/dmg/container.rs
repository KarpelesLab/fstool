//! Opening a UDIF image as a *container*: its trailer(s), segments,
//! resource plist and `blkx` tables, without decoding any data.
//!
//! [`inspect_udif`] returns the result as a [`UdifInfo`]; [`DmgBackend`]
//! is built on the same parse and adds the chunk decoder.
//!
//! ## Segmented images
//!
//! `hdiutil segment` splits an image's *data fork* across several files:
//! `name.dmg`, `name.002.dmgpart`, `name.003.dmgpart`, … Each file is a
//! data-fork slice, a plist and a koly trailer. The first carries the full
//! resource plist; the others an empty one. Every trailer records the
//! segment number (1-based), the segment count, a 16-byte segment ID
//! shared by the set, and `running_data_fork_offset` — where its slice
//! starts in the logical data fork the chunk tables address. The master
//! checksum and sector count are the same in every segment; each
//! segment's data-fork checksum covers its own slice.
//!
//! Opening the first segment finds the others by that naming
//! ([`udif_segment_path`]) and checks, before anything is read, that each
//! one exists, is a UDIF trailer of the same set (ID, count, sector
//! count), is numbered in order and continues the data fork exactly where
//! the previous one ended.
//!
//! [`DmgBackend`]: super::DmgBackend

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use super::mish::{self, Chunk, ChunkType};
use super::pvalue::Value;
use super::resources::{BLKX_RESOURCE, UdifResources};
use super::{KOLY_SIZE, KolyTrailer, MAX_CHUNK_SECTORS, plist, pvalue};
use crate::Result;
use crate::block::imageops::ChecksumAlgorithm;

/// Largest resource plist read (it is held in memory to be parsed).
const MAX_PLIST_BYTES: u64 = 128 * 1024 * 1024;
/// Most segments accepted in one set.
pub const MAX_SEGMENTS: u32 = 9_999;

/// Byte offsets of the code-signature fields in the koly trailer
/// (`CodeSignatureOffset`, `CodeSignatureLength`), which
/// [`KolyTrailer`] does not decode.
const KOLY_CODESIGN_OFFSET: usize = 0x128;
const KOLY_CODESIGN_LENGTH: usize = 0x130;

/// A random-access byte source a segment is read from.
///
/// The auto-trait bounds keep [`DmgBackend`](super::DmgBackend) `Send`,
/// `Sync` and unwind-safe, as it was when it held a plain `File`.
pub(crate) trait Source:
    Read + Seek + Send + Sync + std::panic::UnwindSafe + std::panic::RefUnwindSafe
{
}
impl<T> Source for T where
    T: Read + Seek + Send + Sync + std::panic::UnwindSafe + std::panic::RefUnwindSafe
{
}

/// The embedded code signature `codesign` adds to a disk image: a blob
/// between the plist and the trailer, located by two trailer fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct CodeSignature {
    /// Absolute byte offset of the signature blob in the (first) segment.
    pub offset: u64,
    /// Length of the blob.
    pub length: u64,
}

/// A checksum as a UDIF structure stores it: a type code, a size in bits
/// and up to 128 bytes of value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct StoredChecksum {
    /// The UDIF checksum type: 0 none, 2 CRC-32, 4 MD5; others exist
    /// (Apple's engine knows more) but fstool cannot compute them.
    pub kind: u32,
    /// The value's size in bits.
    pub bits: u32,
    /// The value, zero padded.
    pub data: [u8; 128],
}

impl StoredChecksum {
    pub(crate) fn new(kind: u32, bits: u32, data: [u8; 128]) -> Self {
        Self { kind, bits, data }
    }

    pub(crate) fn from_mish(m: &[u8]) -> Self {
        let mut data = [0u8; 128];
        data.copy_from_slice(&m[0x48..0xC8]);
        Self {
            kind: u32::from_be_bytes(m[0x40..0x44].try_into().unwrap()),
            bits: u32::from_be_bytes(m[0x44..0x48].try_into().unwrap()),
            data,
        }
    }

    /// No checksum recorded (type 0).
    pub fn is_none(&self) -> bool {
        self.kind == 0
    }

    /// The algorithm, when fstool can compute it.
    pub fn algorithm(&self) -> Option<ChecksumAlgorithm> {
        ChecksumAlgorithm::from_udif_type(self.kind)
    }

    /// The value bytes (`bits / 8` of them, at most 128).
    pub fn value(&self) -> &[u8] {
        let n = ((self.bits / 8) as usize).min(self.data.len());
        &self.data[..n]
    }

    /// Lower-case hex of [`Self::value`].
    pub fn hex(&self) -> String {
        crate::block::imageops::to_hex(self.value())
    }
}

/// One file of a (possibly single-file) UDIF image.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct UdifSegment {
    /// The file, when the image was opened from a path.
    pub path: Option<PathBuf>,
    /// Its decoded trailer.
    pub trailer: KolyTrailer,
    /// The file's length.
    pub file_length: u64,
    /// The embedded code signature, if the trailer records one.
    pub code_signature: Option<CodeSignature>,
}

impl UdifSegment {
    /// This segment's data-fork checksum.
    pub fn data_checksum(&self) -> StoredChecksum {
        let t = &self.trailer;
        StoredChecksum::new(t.data_checksum_type, t.data_checksum_size, t.data_checksum)
    }

    /// Where this segment's slice starts in the logical data fork.
    pub fn fork_start(&self) -> u64 {
        self.trailer.running_data_fork_offset
    }
}

/// One `blkx` entry: a run of sectors with its own chunk table and
/// partition checksum.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct BlkxEntry {
    /// `Name`.
    pub name: String,
    /// `CFName`, when present.
    pub cf_name: Option<String>,
    /// `ID`.
    pub id: i32,
    /// `Attributes`.
    pub attributes: u16,
    /// First sector the entry covers.
    pub first_sector: u64,
    /// Sectors it covers.
    pub sector_count: u64,
    /// The mish `data_offset` (where the entry's chunk offsets count
    /// from in the logical data fork).
    pub data_offset: u64,
    /// The mish `buffers_needed`.
    pub buffers_needed: u32,
    /// The mish `block_descriptor`.
    pub descriptor: i32,
    /// The partition checksum (over the entry's sectors, excluding
    /// "ignore" chunks).
    pub checksum: StoredChecksum,
    /// The chunks, in table order. Offsets are absolute in the logical
    /// data fork; comment and terminator entries are dropped.
    pub chunks: Vec<Chunk>,
}

impl BlkxEntry {
    /// Whether every chunk of the entry is "ignore" (free space), as in
    /// the `Apple_Free` regions `hdiutil` writes.
    pub fn is_free_space(&self) -> bool {
        !self.chunks.is_empty() && self.chunks.iter().all(|c| c.kind == ChunkType::Ignored)
    }
}

/// Everything a UDIF image says about itself, decoded from its trailers
/// and resource plist. Returned by [`inspect_udif`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct UdifInfo {
    /// The image's files, in order (one, unless segmented).
    pub segments: Vec<UdifSegment>,
    /// The `blkx` entries, in plist order.
    pub blkx: Vec<BlkxEntry>,
    /// Every resource of the plist, `blkx` included. Empty when the plist
    /// could only be scanned for `blkx` (see
    /// [`Self::resources_complete`]).
    pub resources: UdifResources,
    /// False when the plist was not a well-formed property list fstool
    /// could fully parse, and only the `blkx` payloads were recovered;
    /// operations that rewrite the plist then refuse the image.
    pub resources_complete: bool,
    /// Virtual size, in 512-byte sectors.
    pub sector_count: u64,
    /// Length of the logical data fork (all segments).
    pub fork_length: u64,
    /// The master checksum (over the partition checksums).
    pub master_checksum: StoredChecksum,
    /// The parsed plist root, for rewriting it with its other keys.
    #[cfg_attr(not(feature = "dmg-write"), allow(dead_code))]
    pub(crate) plist_root: Option<Value>,
}

impl UdifInfo {
    /// The first segment's trailer.
    pub fn trailer(&self) -> &KolyTrailer {
        &self.segments[0].trailer
    }

    /// Whether the image is split across several files.
    pub fn is_segmented(&self) -> bool {
        self.segments.len() > 1
    }

    /// The embedded code signature of any segment, if there is one.
    pub fn code_signature(&self) -> Option<CodeSignature> {
        self.segments.iter().find_map(|s| s.code_signature)
    }

    /// The trailer's binary resource fork `(offset, length)` — a legacy
    /// structure separate from the XML resource map — if one is recorded.
    pub fn legacy_resource_fork(&self) -> Option<(u64, u64)> {
        let t = self.trailer();
        (t.rsrc_fork_length != 0).then_some((t.rsrc_fork_offset, t.rsrc_fork_length))
    }

    /// The format code the chunk codecs suggest (`"UDZO"`, `"UDRO"`, …):
    /// the codec of the data chunks, `UDRO` when they are all raw. An
    /// image whose chunks mix codecs reports the most frequent one.
    pub fn format_hint(&self) -> &'static str {
        let mut counts = [0usize; 6];
        let mut zero_chunks = 0usize;
        for c in self.blkx.iter().flat_map(|b| &b.chunks) {
            let i = match c.kind {
                ChunkType::Raw => 0,
                ChunkType::Adc => 1,
                ChunkType::Zlib => 2,
                ChunkType::Bz2 => 3,
                ChunkType::Lzfse => 4,
                ChunkType::Lzma => 5,
                _ => {
                    zero_chunks += 1;
                    continue;
                }
            };
            counts[i] += 1;
        }
        let compressed = counts[1..].iter().enumerate().max_by_key(|(_, n)| **n);
        match compressed {
            Some((i, n)) if *n > 0 => ["UDCO", "UDZO", "UDBZ", "ULFO", "ULMO"][i],
            _ if zero_chunks == 0 && self.master_checksum.kind == 4 => "UFBI",
            _ => "UDRO",
        }
    }
}

/// The path of segment `number` (1-based) of the set whose first file is
/// `first`: `first` itself for 1, otherwise `first` without its `.dmg`
/// extension plus `.NNN.dmgpart` — `hdiutil segment`'s naming
/// (`out.dmg`, `out.002.dmgpart`, `out.003.dmgpart`, …).
pub fn udif_segment_path(first: &Path, number: u32) -> PathBuf {
    if number <= 1 {
        return first.to_path_buf();
    }
    let name = first
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let stem = match name.len().checked_sub(4) {
        Some(i) if name.is_char_boundary(i) && name[i..].eq_ignore_ascii_case(".dmg") => &name[..i],
        _ => name.as_str(),
    };
    first.with_file_name(format!("{stem}.{number:03}.dmgpart"))
}

/// Decode a trailer and its code-signature fields from 512 raw bytes.
fn decode_trailer(raw: &[u8], file_length: u64) -> Result<(KolyTrailer, Option<CodeSignature>)> {
    let trailer = KolyTrailer::decode(raw)?;
    let off = u64::from_be_bytes(
        raw[KOLY_CODESIGN_OFFSET..KOLY_CODESIGN_OFFSET + 8]
            .try_into()
            .unwrap(),
    );
    let len = u64::from_be_bytes(
        raw[KOLY_CODESIGN_LENGTH..KOLY_CODESIGN_LENGTH + 8]
            .try_into()
            .unwrap(),
    );
    let sig = if len == 0 {
        None
    } else {
        if off.checked_add(len).is_none_or(|e| e > file_length) {
            return Err(crate::Error::InvalidImage(format!(
                "dmg: code signature (offset {off} + length {len}) exceeds the file length \
                 {file_length}"
            )));
        }
        Some(CodeSignature {
            offset: off,
            length: len,
        })
    };
    Ok((trailer, sig))
}

/// Read and decode the trailer at the end of a source of `len` bytes.
fn read_trailer(src: &mut dyn Source, len: u64) -> Result<UdifSegment> {
    if len < KOLY_SIZE {
        return Err(crate::Error::InvalidImage(
            "dmg: file smaller than the 512-byte koly trailer".into(),
        ));
    }
    src.seek(SeekFrom::Start(len - KOLY_SIZE))?;
    let mut raw = [0u8; KOLY_SIZE as usize];
    src.read_exact(&mut raw)?;
    let (trailer, code_signature) = decode_trailer(&raw, len)?;
    let fork_end = trailer
        .data_fork_offset
        .checked_add(trailer.data_fork_length)
        .ok_or_else(|| crate::Error::InvalidImage("dmg: data fork extent overflows u64".into()))?;
    if fork_end > len {
        return Err(crate::Error::InvalidImage(format!(
            "dmg: data fork (offset {} + length {} = {fork_end}) exceeds file length {len}",
            trailer.data_fork_offset, trailer.data_fork_length
        )));
    }
    Ok(UdifSegment {
        path: None,
        trailer,
        file_length: len,
        code_signature,
    })
}

/// A segment's open source and where its slice sits.
pub(crate) struct OpenSegment {
    pub(crate) src: Box<dyn Source>,
    /// Offset of the slice in the logical data fork.
    pub(crate) fork_start: u64,
    /// Offset of the slice in the segment's own file.
    pub(crate) file_offset: u64,
    pub(crate) len: u64,
}

/// A parsed image with its segments open.
pub(crate) struct Container {
    pub(crate) info: UdifInfo,
    pub(crate) segs: Vec<OpenSegment>,
}

impl std::fmt::Debug for Container {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Container")
            .field("segments", &self.segs.len())
            .field("sector_count", &self.info.sector_count)
            .finish_non_exhaustive()
    }
}

impl Container {
    /// Open the image whose first (or only) file is `path`.
    pub(crate) fn open(path: &Path) -> Result<Self> {
        let mut file = File::open(path)?;
        let len = file.metadata()?.len();
        let mut first = read_trailer(&mut file, len)?;
        first.path = Some(path.to_path_buf());
        let t = &first.trailer;
        if t.segment_number > 1 {
            return Err(crate::Error::InvalidArgument(format!(
                "dmg: {} is segment {} of {} of a segmented image; open the first segment \
                 (the .dmg file) instead",
                path.display(),
                t.segment_number,
                t.segment_count
            )));
        }
        let count = t.segment_count.max(1);
        if count > MAX_SEGMENTS {
            return Err(crate::Error::InvalidImage(format!(
                "dmg: implausible segment count {count}"
            )));
        }
        let mut segments = vec![first];
        let mut srcs: Vec<Box<dyn Source>> = vec![Box::new(file)];
        for n in 2..=count {
            let p = udif_segment_path(path, n);
            let mut f = File::open(&p).map_err(|e| {
                crate::Error::InvalidImage(format!(
                    "dmg: segment {n} of {count} ({}) cannot be opened: {e}",
                    p.display()
                ))
            })?;
            let flen = f.metadata()?.len();
            let mut seg = read_trailer(&mut f, flen).map_err(|e| {
                crate::Error::InvalidImage(format!("dmg: segment {} : {e}", p.display()))
            })?;
            seg.path = Some(p);
            segments.push(seg);
            srcs.push(Box::new(f));
        }
        Self::build(segments, srcs)
    }

    /// Parse a single-file image from any seekable source of `len` bytes
    /// (a decrypted `encrcdsa` stream, an in-memory image, …).
    pub(crate) fn from_source(mut src: Box<dyn Source>, len: u64) -> Result<Self> {
        let seg = read_trailer(src.as_mut(), len)?;
        if seg.trailer.segment_count > 1 {
            return Err(crate::Error::Unsupported(
                "dmg: a segmented image can only be opened from its files".into(),
            ));
        }
        Self::build(vec![seg], vec![src])
    }

    fn build(segments: Vec<UdifSegment>, mut srcs: Vec<Box<dyn Source>>) -> Result<Self> {
        validate_segment_set(&segments)?;
        let first = &segments[0];
        let t = first.trailer.clone();
        let mut fork_length = 0u64;
        let mut segs = Vec::with_capacity(segments.len());
        for (s, src) in segments.iter().zip(srcs.drain(..)) {
            segs.push(OpenSegment {
                src,
                fork_start: s.fork_start(),
                file_offset: s.trailer.data_fork_offset,
                len: s.trailer.data_fork_length,
            });
            fork_length = s.fork_start() + s.trailer.data_fork_length;
        }

        // The plist lives in the first segment.
        if t.xml_length == 0 {
            return Err(crate::Error::InvalidImage(
                "dmg: koly trailer has empty XML resource fork (xml_length = 0)".into(),
            ));
        }
        if t.xml_length > MAX_PLIST_BYTES {
            return Err(crate::Error::InvalidImage(format!(
                "dmg: resource-fork plist is implausibly large ({} bytes)",
                t.xml_length
            )));
        }
        if t.xml_offset
            .checked_add(t.xml_length)
            .is_none_or(|e| e > first.file_length)
        {
            return Err(crate::Error::InvalidImage(
                "dmg: resource-fork plist lies outside the file".into(),
            ));
        }
        let src0 = segs[0].src.as_mut();
        src0.seek(SeekFrom::Start(t.xml_offset))?;
        let mut plist_bytes = vec![0u8; t.xml_length as usize];
        src0.read_exact(&mut plist_bytes)?;
        let plist_str = std::str::from_utf8(&plist_bytes).map_err(|e| {
            crate::Error::InvalidImage(format!("dmg: resource-fork plist isn't UTF-8: {e}"))
        })?;

        // A full parse keeps every resource; an image whose plist is not
        // quite a well-formed property list still opens for reading via
        // the lenient blkx scanner.
        let parsed = pvalue::parse_document(plist_str).and_then(|root| {
            let map = root.get("resource-fork").ok_or_else(|| {
                crate::Error::InvalidImage("dmg: plist has no resource-fork".into())
            })?;
            let res = UdifResources::from_value(map)?;
            Ok((root, res))
        });
        let (plist_root, resources, raw_blkx) = match parsed {
            Ok((root, res)) => {
                let blkx: Vec<_> = res
                    .of_kind(BLKX_RESOURCE)
                    .map(|r| {
                        (
                            r.name.clone(),
                            r.cf_name.clone(),
                            r.id,
                            r.attributes,
                            r.data.clone(),
                        )
                    })
                    .collect();
                (Some(root), res, blkx)
            }
            Err(_) => {
                let entries = plist::extract_blkx_data_entries(plist_str)?;
                let mut blkx = Vec::with_capacity(entries.len());
                for (i, e) in entries.iter().enumerate() {
                    let compact: String = e.chars().filter(|c| !c.is_ascii_whitespace()).collect();
                    blkx.push((
                        String::new(),
                        None,
                        i as i32,
                        0,
                        crate::base64::decode(&compact)?,
                    ));
                }
                (None, UdifResources::default(), blkx)
            }
        };
        if raw_blkx.is_empty() {
            return Err(crate::Error::InvalidImage(
                "dmg: blkx array is empty — no chunks to map".into(),
            ));
        }

        let mut blkx = Vec::with_capacity(raw_blkx.len());
        for (name, cf_name, id, attributes, raw) in raw_blkx {
            let m = mish::decode_mish(&raw)?;
            let checksum = StoredChecksum::from_mish(&raw);
            let buffers_needed = u32::from_be_bytes(raw[0x20..0x24].try_into().unwrap());
            let descriptor = i32::from_be_bytes(raw[0x24..0x28].try_into().unwrap());
            let chunks = resolve_offsets(&m, fork_length)?;
            blkx.push(BlkxEntry {
                name,
                cf_name,
                id,
                attributes,
                first_sector: m.first_sector,
                sector_count: m.sector_count,
                data_offset: m.data_offset,
                buffers_needed,
                descriptor,
                checksum,
                chunks,
            });
        }
        let master_checksum = StoredChecksum::new(
            t.master_checksum_type,
            t.master_checksum_size,
            t.master_checksum,
        );
        let info = UdifInfo {
            sector_count: t.sector_count,
            segments,
            blkx,
            resources_complete: plist_root.is_some(),
            resources,
            fork_length,
            master_checksum,
            plist_root,
        };
        Ok(Self { info, segs })
    }

    /// Read `buf.len()` bytes of the logical data fork at `off`, across
    /// segment boundaries.
    pub(crate) fn read_fork(&mut self, mut off: u64, buf: &mut [u8]) -> Result<()> {
        let mut done = 0usize;
        while done < buf.len() {
            let i = self.segs.partition_point(|s| s.fork_start <= off);
            let seg = i
                .checked_sub(1)
                .map(|i| &mut self.segs[i])
                .filter(|s| off < s.fork_start + s.len)
                .ok_or_else(|| {
                    crate::Error::InvalidImage(format!(
                        "dmg: data-fork offset {off} lies outside every segment"
                    ))
                })?;
            let local = off - seg.fork_start;
            let n = ((seg.len - local) as usize).min(buf.len() - done);
            seg.src.seek(SeekFrom::Start(seg.file_offset + local))?;
            seg.src.read_exact(&mut buf[done..done + n])?;
            done += n;
            off += n as u64;
        }
        Ok(())
    }
}

/// Check that a set of trailers forms one coherent image.
fn validate_segment_set(segments: &[UdifSegment]) -> Result<()> {
    let first = &segments[0].trailer;
    let count = segments.len() as u32;
    let name = |s: &UdifSegment| {
        s.path
            .as_ref()
            .map_or_else(|| "segment".to_string(), |p| p.display().to_string())
    };
    if first.running_data_fork_offset != 0 {
        return Err(crate::Error::InvalidImage(format!(
            "dmg: the first segment's data fork starts at logical offset {}, not 0",
            first.running_data_fork_offset
        )));
    }
    let mut expect_start = 0u64;
    for (i, s) in segments.iter().enumerate() {
        let t = &s.trailer;
        let n = i as u32 + 1;
        if count > 1 {
            if t.segment_number != n || t.segment_count != count {
                return Err(crate::Error::InvalidImage(format!(
                    "dmg: {} says it is segment {} of {}, expected {n} of {count}",
                    name(s),
                    t.segment_number,
                    t.segment_count
                )));
            }
            if t.segment_id != first.segment_id {
                return Err(crate::Error::InvalidImage(format!(
                    "dmg: {} belongs to another segment set (ID {} ≠ {})",
                    name(s),
                    uuid::Uuid::from_bytes(t.segment_id),
                    uuid::Uuid::from_bytes(first.segment_id)
                )));
            }
            if t.sector_count != first.sector_count {
                return Err(crate::Error::InvalidImage(format!(
                    "dmg: {} records {} sectors, the first segment {}",
                    name(s),
                    t.sector_count,
                    first.sector_count
                )));
            }
            if t.master_checksum_type != first.master_checksum_type
                || t.master_checksum != first.master_checksum
            {
                return Err(crate::Error::InvalidImage(format!(
                    "dmg: {} records a different master checksum than the first segment",
                    name(s)
                )));
            }
        }
        if t.running_data_fork_offset != expect_start {
            return Err(crate::Error::InvalidImage(format!(
                "dmg: {} continues the data fork at {}, expected {expect_start} \
                 (a segment is missing, repeated or out of order)",
                name(s),
                t.running_data_fork_offset
            )));
        }
        expect_start = expect_start
            .checked_add(t.data_fork_length)
            .ok_or_else(|| crate::Error::InvalidImage("dmg: data fork overflows u64".into()))?;
    }
    first
        .sector_count
        .checked_mul(512)
        .ok_or_else(|| crate::Error::InvalidImage("dmg: sector_count overflows u64".into()))?;
    Ok(())
}

/// Resolve a mish table's chunk offsets into the logical data fork and
/// bound them.
///
/// A chunk's payload sits at `mish.data_offset + chunk offset`. `hdiutil`
/// writes `data_offset` 0 and absolute chunk offsets for an ordinary image,
/// and a per-entry base with entry-relative chunk offsets for a segmented
/// one, so the sum is right for both. Should a writer have recorded a base
/// *and* absolute offsets, the sum overruns the fork; the absolute reading
/// is then used if it fits.
fn resolve_offsets(m: &mish::Mish, fork_length: u64) -> Result<Vec<Chunk>> {
    let carries_data = |c: &Chunk| {
        !matches!(
            c.kind,
            ChunkType::Zero | ChunkType::Ignored | ChunkType::Comment | ChunkType::Terminator
        )
    };
    let fits = |base: u64| {
        m.chunks.iter().filter(|c| carries_data(c)).all(|c| {
            base.checked_add(c.compressed_offset_in_fork)
                .and_then(|o| o.checked_add(c.compressed_length))
                .is_some_and(|e| e <= fork_length)
        })
    };
    let base = if fits(m.data_offset) {
        m.data_offset
    } else if m.data_offset != 0 && fits(0) {
        0
    } else {
        let c = m
            .chunks
            .iter()
            .find(|c| {
                carries_data(c)
                    && m.data_offset
                        .checked_add(c.compressed_offset_in_fork)
                        .and_then(|o| o.checked_add(c.compressed_length))
                        .is_none_or(|e| e > fork_length)
            })
            .copied();
        let (o, l) = c.map_or((0, 0), |c| {
            (c.compressed_offset_in_fork, c.compressed_length)
        });
        return Err(crate::Error::InvalidImage(format!(
            "dmg: chunk compressed extent (offset {} + {o} + length {l}) exceeds data fork \
             length {fork_length}",
            m.data_offset
        )));
    };
    let mut out = Vec::with_capacity(m.chunks.len());
    for c in &m.chunks {
        if c.sector_count > MAX_CHUNK_SECTORS {
            return Err(crate::Error::InvalidImage(format!(
                "dmg: chunk sector_count {} exceeds maximum {MAX_CHUNK_SECTORS}",
                c.sector_count
            )));
        }
        let mut c = *c;
        if carries_data(&c) {
            c.compressed_offset_in_fork += base;
        }
        out.push(c);
    }
    Ok(out)
}

/// Inspect the UDIF image whose first (or only) file is `path`: trailers,
/// segments, resources, `blkx` tables, checksums and code signature. Reads
/// no data.
pub fn inspect_udif(path: &Path) -> Result<UdifInfo> {
    Ok(Container::open(path)?.info)
}

/// The bytes of the legacy binary resource fork the trailer of `path`
/// records (see [`UdifInfo::legacy_resource_fork`]), or `None`.
pub fn read_legacy_resource_fork(path: &Path) -> Result<Option<Vec<u8>>> {
    let mut c = Container::open(path)?;
    let Some((off, len)) = c.info.legacy_resource_fork() else {
        return Ok(None);
    };
    if off
        .checked_add(len)
        .is_none_or(|e| e > c.info.segments[0].file_length)
        || len > MAX_PLIST_BYTES
    {
        return Err(crate::Error::InvalidImage(
            "dmg: legacy resource fork lies outside the file".into(),
        ));
    }
    let src = c.segs[0].src.as_mut();
    src.seek(SeekFrom::Start(off))?;
    let mut buf = vec![0u8; len as usize];
    src.read_exact(&mut buf)?;
    Ok(Some(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segment_paths_follow_hdiutil() {
        let p = Path::new("/x/out.dmg");
        assert_eq!(udif_segment_path(p, 1), p);
        assert_eq!(udif_segment_path(p, 2), Path::new("/x/out.002.dmgpart"));
        assert_eq!(udif_segment_path(p, 12), Path::new("/x/out.012.dmgpart"));
        assert_eq!(
            udif_segment_path(Path::new("a.DMG"), 3),
            Path::new("a.003.dmgpart")
        );
        assert_eq!(
            udif_segment_path(Path::new("img"), 2),
            Path::new("img.002.dmgpart")
        );
    }
}
