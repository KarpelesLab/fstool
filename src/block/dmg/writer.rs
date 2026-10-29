//! UDIF (`.dmg`) writer — encode a sector stream into a single-segment,
//! read-only Apple disk image.
//!
//! The writer is deliberately *only* a container encoder. It takes
//! 512-byte sectors from the caller (directly through
//! [`UdifWriter::write_sectors`], or pulled from a [`BlockDevice`] / a
//! [`Read`] of known length by [`write_udif`] / [`write_udif_from_reader`])
//! and writes the image into a caller-owned [`Write`] + [`Seek`] sink. It
//! never creates, renames, syncs or publishes files: a caller building a
//! release artefact writes into a temporary file, gets the sink back from
//! [`UdifWriter::finish`], syncs/closes it, signs it, and only then moves
//! it into place.
//!
//! ## What gets written
//!
//! ```text
//!   [ data fork: chunk payloads in sector order ]
//!   [ XML plist: resource-fork → blkx[0]        ]   one whole-device mish
//!   [ 512-byte koly trailer                     ]
//! ```
//!
//! The plist mirrors what `hdiutil` emits for a single-partition
//! (`-layout NONE`) image: one `blkx` entry named
//! `whole disk (Apple_HFS : 0)` (configurable), `ID` 0, attributes
//! `0x0050`. Each chunk covers at most
//! [`UdifWriteOptions::chunk_sectors`] sectors. All-zero sectors are never
//! compressed — runs of them become zero-fill (`0x00000000`) or, on
//! request, "ignore" (`0x00000002`) entries. A data chunk whose encoding
//! would not be smaller than its plaintext is stored raw (`0x00000001`),
//! as `hdiutil` does.
//!
//! ## Checksums
//!
//! With [`UdifChecksum::Crc32`] (the default) the writer records, exactly
//! as `hdiutil` does:
//!
//! - the partition checksum in the mish header — CRC-32 over the
//!   partition's plaintext sectors, *excluding* sectors carried by
//!   "ignore" entries;
//! - the data-fork checksum in the trailer — CRC-32 over the data-fork
//!   bytes as stored;
//! - the master checksum in the trailer — CRC-32 over the concatenated
//!   big-endian partition checksums.
//!
//! ## Formats
//!
//! | [`UdifFormat`] | chunk codec | Cargo feature |
//! |---|---|---|
//! | `Udro` | raw | `dmg-write` |
//! | `Udco` | ADC (built in) | `dmg-write` |
//! | `Udzo` | zlib | `dmg-write-zlib` |
//! | `Udbz` | bzip2 | `dmg-write-bzip2` |
//! | `Ulmo` | LZMA (XZ-framed, as current `hdiutil` writes) | `dmg-write-lzma` |
//! | `Ulfo` | LZFSE | — not writable: `compcol`'s LZFSE is decode-only |
//!
//! A format whose codec feature is compiled out is refused by
//! [`UdifWriter::new`] with [`crate::Error::Unsupported`] naming the
//! feature, before anything is written.

use std::io::{Read, Seek, Write};

use super::mish::{CHUNK_LEN, ChunkType, MISH_HEADER_LEN, MISH_MAGIC};
use super::{KOLY_MAGIC, KOLY_SIZE, KolyTrailer, MAX_CHUNK_SECTORS};
use crate::Result;
use crate::block::BlockDevice;

/// Sector size UDIF counts in. Fixed by the format.
const SECTOR: usize = 512;

/// UDIF checksum type code for CRC-32 (`kUDIFChecksumCRC32`).
const CHECKSUM_TYPE_CRC32: u32 = 2;
/// Checksum width in bits for CRC-32.
const CHECKSUM_BITS_CRC32: u32 = 32;

/// Koly `flags` bit 0: the image is "flattened" (data + resource fork in
/// one file). Every `hdiutil` UDIF has it set.
const KOLY_FLAG_FLATTENED: u32 = 1;
/// Koly `image_variant` that `hdiutil` writes for device images.
const KOLY_IMAGE_VARIANT_DEVICE: u32 = 2;
/// Mish `block_descriptor` value `hdiutil` uses for a whole-disk entry.
const BLKX_DESCRIPTOR_WHOLE_DISK: u32 = 0xFFFF_FFFE;
/// Default chunk span: 2048 sectors (1 MiB), `hdiutil`'s own.
const DEFAULT_CHUNK_SECTORS: u32 = 2048;
/// Upper bound on [`UdifWriteOptions::chunk_sectors`]. Bounds the
/// writer's per-chunk buffers (8 MiB of plaintext) while staying far below
/// the reader's own cap.
pub const MAX_WRITE_CHUNK_SECTORS: u32 = 16_384;
/// Longest zero / ignore run one descriptor carries. Kept well inside the
/// reader's [`MAX_CHUNK_SECTORS`] so a writer-produced image always
/// re-opens.
const MAX_ZERO_RUN_SECTORS: u64 = 1 << 20;
const _: () = assert!(MAX_ZERO_RUN_SECTORS <= MAX_CHUNK_SECTORS);
const _: () = assert!(MAX_WRITE_CHUNK_SECTORS as u64 <= MAX_CHUNK_SECTORS);

/// Chunk encoding of a UDIF image, named by its `hdiutil -format` code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum UdifFormat {
    /// `UDRO` — read-only, uncompressed (raw chunks).
    Udro,
    /// `UDCO` — ADC-compressed. Always available with `dmg-write`.
    Udco,
    /// `UDZO` — zlib-compressed. Needs `dmg-write-zlib`.
    #[default]
    Udzo,
    /// `UDBZ` — bzip2-compressed. Needs `dmg-write-bzip2`.
    Udbz,
    /// `ULFO` — LZFSE-compressed. Recognised but **not writable**: the
    /// `compcol` LZFSE codec fstool uses can only decode.
    Ulfo,
    /// `ULMO` — LZMA-compressed (each chunk an XZ stream, as current
    /// `hdiutil` writes). Needs `dmg-write-lzma`.
    Ulmo,
}

impl UdifFormat {
    /// The `hdiutil -format` code (`"UDZO"`, …).
    pub fn name(self) -> &'static str {
        match self {
            Self::Udro => "UDRO",
            Self::Udco => "UDCO",
            Self::Udzo => "UDZO",
            Self::Udbz => "UDBZ",
            Self::Ulfo => "ULFO",
            Self::Ulmo => "ULMO",
        }
    }

    /// Parse an `hdiutil -format` code, case-insensitively.
    pub fn from_name(s: &str) -> Option<Self> {
        Some(match s.to_ascii_uppercase().as_str() {
            "UDRO" => Self::Udro,
            "UDCO" => Self::Udco,
            "UDZO" => Self::Udzo,
            "UDBZ" => Self::Udbz,
            "ULFO" => Self::Ulfo,
            "ULMO" => Self::Ulmo,
            _ => return None,
        })
    }

    /// Whether this build can write the format (its codec feature is on).
    pub fn writable(self) -> bool {
        self.check_writable().is_ok()
    }

    fn check_writable(self) -> Result<()> {
        let missing = |feature: &str| {
            Err(crate::Error::Unsupported(format!(
                "dmg: writing {} needs the `{feature}` Cargo feature",
                self.name()
            )))
        };
        match self {
            Self::Udro | Self::Udco => Ok(()),
            Self::Udzo if cfg!(feature = "dmg-write-zlib") => Ok(()),
            Self::Udzo => missing("dmg-write-zlib"),
            Self::Udbz if cfg!(feature = "dmg-write-bzip2") => Ok(()),
            Self::Udbz => missing("dmg-write-bzip2"),
            Self::Ulmo if cfg!(feature = "dmg-write-lzma") => Ok(()),
            Self::Ulmo => missing("dmg-write-lzma"),
            Self::Ulfo => Err(crate::Error::Unsupported(
                "dmg: writing ULFO is not supported — the LZFSE codec fstool uses \
                 (compcol) can decode but not encode"
                    .into(),
            )),
        }
    }

    /// Valid range for [`UdifWriteOptions::level`], or `None` for formats
    /// without a level.
    fn level_range(self) -> Option<core::ops::RangeInclusive<u8>> {
        match self {
            Self::Udzo | Self::Udbz => Some(1..=9),
            Self::Ulmo => Some(0..=9),
            Self::Udro | Self::Udco | Self::Ulfo => None,
        }
    }

    /// The mish `buffers_needed` field: the scratch buffer, in sectors,
    /// a reader must allocate to decode any chunk.
    ///
    /// `hdiutil` writes `chunk + 8` for UDZO, `chunk + 1` for the other
    /// compressed formats and 0 for UDRO — but Apple's engine apparently
    /// decodes some codecs (seen with ULMO) in place, with the compressed
    /// bytes parked at the end of that buffer, so a chunk whose
    /// `sectors + ceil(compressed / 512)` exceeds the field is rejected as
    /// corrupt. `max_in_place` is that sum over this image's compressed
    /// chunks; the field is never smaller.
    fn buffers_needed(self, chunk_sectors: u32, max_in_place: u64) -> u32 {
        let hdiutil = match self {
            Self::Udro => return 0,
            Self::Udzo => u64::from(chunk_sectors) + 8,
            _ => u64::from(chunk_sectors) + 1,
        };
        // chunk_sectors ≤ MAX_WRITE_CHUNK_SECTORS and a compressed chunk is
        // stored only when smaller than its plaintext, so this fits.
        u32::try_from(hdiutil.max(max_in_place)).unwrap_or(u32::MAX)
    }
}

/// How runs of all-zero sectors are recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum ZeroRunEncoding {
    /// Zero-fill entries (`0x00000000`); the zeros count towards the
    /// partition checksum. What `hdiutil create` writes for zero sectors.
    #[default]
    ZeroFill,
    /// "Ignore" / free-space entries (`0x00000002`); excluded from the
    /// partition checksum. What `hdiutil convert` writes for space the
    /// filesystem marks free. Reads back as zeros either way.
    Ignore,
}

/// Which checksums the writer records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum UdifChecksum {
    /// No checksums (type 0). `hdiutil verify` then has nothing to check.
    None,
    /// CRC-32 partition, data-fork and master checksums.
    #[default]
    Crc32,
}

/// Options for [`UdifWriter`]. Construct with `Default` and assign fields.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UdifWriteOptions {
    /// Chunk encoding. Default [`UdifFormat::Udzo`], which needs the
    /// `dmg-write-zlib` feature; a slimmer build must pick UDRO or UDCO.
    pub format: UdifFormat,
    /// Codec level: zlib and bzip2 `1..=9` (bzip2's is the block size in
    /// 100 kB units), LZMA/XZ `0..=9`. `None` uses the codec's default
    /// (6). Must be `None` for UDRO / UDCO.
    pub level: Option<u8>,
    /// Maximum sectors per data chunk, `1..=`[`MAX_WRITE_CHUNK_SECTORS`].
    /// Default 2048 (1 MiB), as `hdiutil`. Sets the writer's buffer size.
    pub chunk_sectors: u32,
    /// How all-zero sector runs are recorded. Default
    /// [`ZeroRunEncoding::ZeroFill`].
    pub zero_runs: ZeroRunEncoding,
    /// Checksums to record. Default [`UdifChecksum::Crc32`].
    pub checksum: UdifChecksum,
    /// `Name` / `CFName` of the whole-device `blkx` entry. Default
    /// `whole disk (Apple_HFS : 0)`, what `hdiutil` writes for an
    /// unpartitioned HFS+ volume; the parenthesised hint is informational.
    pub partition_name: String,
    /// The 16-byte segment identifier in the trailer. `None` draws a
    /// random (v4 UUID) one; set it for reproducible output.
    pub segment_id: Option<[u8; 16]>,
}

impl Default for UdifWriteOptions {
    fn default() -> Self {
        Self {
            format: UdifFormat::default(),
            level: None,
            chunk_sectors: DEFAULT_CHUNK_SECTORS,
            zero_runs: ZeroRunEncoding::default(),
            checksum: UdifChecksum::default(),
            partition_name: "whole disk (Apple_HFS : 0)".into(),
            segment_id: None,
        }
    }
}

impl UdifWriteOptions {
    /// Check the options against this build and the format's limits,
    /// without writing anything. [`UdifWriter::new`] runs the same check.
    pub fn validate(&self) -> Result<()> {
        self.format.check_writable()?;
        if self.chunk_sectors == 0 || self.chunk_sectors > MAX_WRITE_CHUNK_SECTORS {
            return Err(crate::Error::InvalidArgument(format!(
                "dmg: chunk_sectors must be 1..={MAX_WRITE_CHUNK_SECTORS} (got {})",
                self.chunk_sectors
            )));
        }
        match (self.level, self.format.level_range()) {
            (None, _) => {}
            (Some(l), Some(r)) if r.contains(&l) => {}
            (Some(l), Some(r)) => {
                return Err(crate::Error::InvalidArgument(format!(
                    "dmg: {} level must be {}..={} (got {l})",
                    self.format.name(),
                    r.start(),
                    r.end()
                )));
            }
            (Some(_), None) => {
                return Err(crate::Error::InvalidArgument(format!(
                    "dmg: {} has no compression level",
                    self.format.name()
                )));
            }
        }
        if self.partition_name.is_empty() {
            return Err(crate::Error::InvalidArgument(
                "dmg: partition_name must not be empty".into(),
            ));
        }
        if self.partition_name.chars().any(|c| c.is_control()) {
            return Err(crate::Error::InvalidArgument(
                "dmg: partition_name must not contain control characters".into(),
            ));
        }
        Ok(())
    }
}

/// What [`UdifWriter::finish`] wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UdifSummary {
    /// Virtual size in 512-byte sectors.
    pub sector_count: u64,
    /// Bytes of chunk payload in the data fork.
    pub data_fork_length: u64,
    /// Bytes of the XML plist.
    pub plist_length: u64,
    /// Total bytes written to the sink (data fork + plist + trailer).
    pub bytes_written: u64,
    /// Chunk descriptors in the mish table (excluding the terminator).
    pub chunk_count: usize,
    /// Partition (blkx) CRC-32, when checksums were recorded.
    pub partition_crc32: Option<u32>,
    /// Data-fork CRC-32, when checksums were recorded.
    pub data_fork_crc32: Option<u32>,
    /// Master CRC-32, when checksums were recorded.
    pub master_crc32: Option<u32>,
}

/// One descriptor queued for the mish table.
#[derive(Debug, Clone, Copy)]
struct Entry {
    kind: ChunkType,
    sector: u64,
    count: u64,
    offset: u64,
    length: u64,
}

/// Streaming UDIF encoder over a caller-owned sink.
///
/// Feed sectors with [`write_sectors`](Self::write_sectors), then call
/// [`finish`](Self::finish) to emit the plist and trailer and get the
/// sink back. Memory use is bounded by one chunk of plaintext plus its
/// encoding, plus 40 bytes per emitted chunk descriptor.
///
/// Errors from the sink or a codec are returned as they happen; after
/// one, the writer is poisoned and every later call fails, so a
/// half-written image is never finished into something that looks
/// valid. (A call rejected up front — a length that isn't whole
/// sectors — writes nothing and does not poison.) Dropping an unfinished
/// writer leaves the sink holding an incomplete image with no trailer —
/// discard it.
pub struct UdifWriter<W: Write + Seek> {
    out: W,
    opts: UdifWriteOptions,
    /// Absolute sink position where the data fork starts.
    base: u64,
    /// Bytes of data fork written so far.
    fork_len: u64,
    /// Sectors accepted so far.
    sectors: u64,
    /// Plaintext of the data run being accumulated (< one chunk).
    pending: Vec<u8>,
    /// First sector of `pending`.
    pending_start: u64,
    /// Open zero run: (first sector, count).
    zero_run: Option<(u64, u64)>,
    entries: Vec<Entry>,
    part_crc: u32,
    fork_crc: u32,
    poisoned: bool,
}

impl<W: Write + Seek> std::fmt::Debug for UdifWriter<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdifWriter")
            .field("format", &self.opts.format)
            .field("base", &self.base)
            .field("sectors", &self.sectors)
            .field("fork_len", &self.fork_len)
            .field("chunks", &self.entries.len())
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}

impl<W: Write + Seek> UdifWriter<W> {
    /// Validate `opts` and start an image at the sink's current position
    /// (normally 0; the trailer records it as the data-fork offset).
    pub fn new(mut out: W, opts: &UdifWriteOptions) -> Result<Self> {
        opts.validate()?;
        let base = out.stream_position()?;
        let chunk_bytes = opts.chunk_sectors as usize * SECTOR;
        Ok(Self {
            out,
            opts: opts.clone(),
            base,
            fork_len: 0,
            sectors: 0,
            pending: Vec::with_capacity(chunk_bytes),
            pending_start: 0,
            zero_run: None,
            entries: Vec::new(),
            part_crc: 0,
            fork_crc: 0,
            poisoned: false,
        })
    }

    /// Sectors accepted so far.
    pub fn sectors_written(&self) -> u64 {
        self.sectors
    }

    /// Append whole sectors. `data.len()` must be a multiple of 512.
    pub fn write_sectors(&mut self, data: &[u8]) -> Result<()> {
        self.check_live()?;
        if !data.len().is_multiple_of(SECTOR) {
            return Err(crate::Error::InvalidArgument(format!(
                "dmg: write_sectors needs whole 512-byte sectors (got {} bytes)",
                data.len()
            )));
        }
        let r = self.write_sectors_inner(data);
        self.poison_on_err(r)
    }

    /// Flush the last chunk, write the plist and koly trailer, flush the
    /// sink, and return it with a summary. Nothing is renamed, synced to
    /// disk or published — that remains the caller's job.
    pub fn finish(mut self) -> Result<(W, UdifSummary)> {
        self.check_live()?;
        let r = self.finish_inner();
        let summary = self.poison_on_err(r)?;
        Ok((self.out, summary))
    }

    fn check_live(&self) -> Result<()> {
        if self.poisoned {
            return Err(crate::Error::InvalidArgument(
                "dmg: UDIF writer already failed; the image is incomplete".into(),
            ));
        }
        Ok(())
    }

    fn poison_on_err<T>(&mut self, r: Result<T>) -> Result<T> {
        if r.is_err() {
            self.poisoned = true;
        }
        r
    }

    fn write_sectors_inner(&mut self, data: &[u8]) -> Result<()> {
        let chunk_bytes = self.opts.chunk_sectors as usize * SECTOR;
        for sector in data.as_chunks::<SECTOR>().0 {
            let lba = self.sectors;
            if is_zero(sector) {
                self.flush_pending()?;
                match &mut self.zero_run {
                    Some((_, n)) if *n < MAX_ZERO_RUN_SECTORS => *n += 1,
                    _ => {
                        self.close_zero_run();
                        self.zero_run = Some((lba, 1));
                    }
                }
                if self.opts.zero_runs == ZeroRunEncoding::ZeroFill {
                    self.part_crc = crate::crc::crc32_append(self.part_crc, sector);
                }
            } else {
                self.close_zero_run();
                if self.pending.is_empty() {
                    self.pending_start = lba;
                }
                self.pending.extend_from_slice(sector);
                self.part_crc = crate::crc::crc32_append(self.part_crc, sector);
                if self.pending.len() >= chunk_bytes {
                    self.flush_pending()?;
                }
            }
            self.sectors = lba.checked_add(1).ok_or_else(|| {
                crate::Error::InvalidArgument("dmg: sector count overflows u64".into())
            })?;
        }
        Ok(())
    }

    fn close_zero_run(&mut self) {
        if let Some((sector, count)) = self.zero_run.take() {
            let kind = match self.opts.zero_runs {
                ZeroRunEncoding::ZeroFill => ChunkType::Zero,
                ZeroRunEncoding::Ignore => ChunkType::Ignored,
            };
            self.entries.push(Entry {
                kind,
                sector,
                count,
                offset: self.fork_len,
                length: 0,
            });
        }
    }

    /// Encode and write the accumulated data run as one chunk.
    fn flush_pending(&mut self) -> Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let count = (self.pending.len() / SECTOR) as u64;
        let encoded = encode_chunk(self.opts.format, self.opts.level, &self.pending)?;
        let (kind, payload): (ChunkType, &[u8]) = match &encoded {
            Some((kind, bytes)) if bytes.len() < self.pending.len() => (*kind, bytes),
            _ => (ChunkType::Raw, &self.pending),
        };
        self.out.write_all(payload)?;
        self.fork_crc = crate::crc::crc32_append(self.fork_crc, payload);
        let length = payload.len() as u64;
        self.entries.push(Entry {
            kind,
            sector: self.pending_start,
            count,
            offset: self.fork_len,
            length,
        });
        self.fork_len += length;
        self.pending.clear();
        Ok(())
    }

    fn finish_inner(&mut self) -> Result<UdifSummary> {
        self.flush_pending()?;
        self.close_zero_run();
        if self.sectors == 0 {
            return Err(crate::Error::InvalidArgument(
                "dmg: refusing to finish an empty image (no sectors written)".into(),
            ));
        }
        if self.entries.len() >= u32::MAX as usize {
            return Err(crate::Error::Unsupported(
                "dmg: too many chunks for one mish table; raise chunk_sectors".into(),
            ));
        }
        let crc = self.opts.checksum == UdifChecksum::Crc32;
        let part_crc = crc.then_some(self.part_crc);
        let fork_crc = crc.then_some(self.fork_crc);
        let master_crc = part_crc.map(|c| crate::crc::crc32(&c.to_be_bytes()));

        let mish = self.encode_mish(part_crc);
        let plist = build_plist(&self.opts.partition_name, &mish);
        self.out.write_all(plist.as_bytes())?;

        let data_fork_offset = self.base;
        let xml_offset = self
            .base
            .checked_add(self.fork_len)
            .ok_or_else(|| crate::Error::InvalidArgument("dmg: image too large".into()))?;
        let trailer = KolyTrailer {
            signature: KOLY_MAGIC,
            version: 4,
            header_size: KOLY_SIZE as u32,
            flags: KOLY_FLAG_FLATTENED,
            running_data_fork_offset: 0,
            data_fork_offset,
            data_fork_length: self.fork_len,
            rsrc_fork_offset: 0,
            rsrc_fork_length: 0,
            segment_number: 1,
            segment_count: 1,
            segment_id: self
                .opts
                .segment_id
                .unwrap_or_else(|| *uuid::Uuid::new_v4().as_bytes()),
            data_checksum_type: checksum_type(fork_crc),
            data_checksum_size: checksum_bits(fork_crc),
            data_checksum: checksum_bytes(fork_crc),
            xml_offset,
            xml_length: plist.len() as u64,
            master_checksum_type: checksum_type(master_crc),
            master_checksum_size: checksum_bits(master_crc),
            master_checksum: checksum_bytes(master_crc),
            image_variant: KOLY_IMAGE_VARIANT_DEVICE,
            sector_count: self.sectors,
        };
        self.out.write_all(&trailer.encode())?;
        self.out.flush()?;

        Ok(UdifSummary {
            sector_count: self.sectors,
            data_fork_length: self.fork_len,
            plist_length: plist.len() as u64,
            bytes_written: self.fork_len + plist.len() as u64 + KOLY_SIZE,
            chunk_count: self.entries.len(),
            partition_crc32: part_crc,
            data_fork_crc32: fork_crc,
            master_crc32: master_crc,
        })
    }

    /// Serialise the whole-device BLKX table, terminator included.
    fn encode_mish(&self, part_crc: Option<u32>) -> Vec<u8> {
        let n = self.entries.len() + 1;
        let mut b = vec![0u8; MISH_HEADER_LEN + n * CHUNK_LEN];
        b[0x000..0x004].copy_from_slice(&MISH_MAGIC.to_be_bytes());
        b[0x004..0x008].copy_from_slice(&1u32.to_be_bytes()); // version
        b[0x008..0x010].copy_from_slice(&0u64.to_be_bytes()); // first sector
        b[0x010..0x018].copy_from_slice(&self.sectors.to_be_bytes());
        b[0x018..0x020].copy_from_slice(&0u64.to_be_bytes()); // data offset
        let max_in_place = self
            .entries
            .iter()
            .filter(|e| {
                !matches!(
                    e.kind,
                    ChunkType::Raw | ChunkType::Zero | ChunkType::Ignored
                )
            })
            .map(|e| e.count + e.length.div_ceil(SECTOR as u64))
            .max()
            .unwrap_or(0);
        let buffers = self
            .opts
            .format
            .buffers_needed(self.opts.chunk_sectors, max_in_place);
        b[0x020..0x024].copy_from_slice(&buffers.to_be_bytes());
        b[0x024..0x028].copy_from_slice(&BLKX_DESCRIPTOR_WHOLE_DISK.to_be_bytes());
        // reserved[6] stays zero; then the UDIFChecksum (type, bits, data).
        b[0x040..0x044].copy_from_slice(&checksum_type(part_crc).to_be_bytes());
        b[0x044..0x048].copy_from_slice(&checksum_bits(part_crc).to_be_bytes());
        b[0x048..0x0C8].copy_from_slice(&checksum_bytes(part_crc));
        b[0x0C8..0x0CC].copy_from_slice(&(n as u32).to_be_bytes());
        let terminator = Entry {
            kind: ChunkType::Terminator,
            sector: self.sectors,
            count: 0,
            offset: self.fork_len,
            length: 0,
        };
        for (i, e) in self.entries.iter().chain([&terminator]).enumerate() {
            let o = MISH_HEADER_LEN + i * CHUNK_LEN;
            b[o..o + 4].copy_from_slice(&e.kind.to_u32().to_be_bytes());
            // comment (o+4..o+8) stays zero.
            b[o + 0x08..o + 0x10].copy_from_slice(&e.sector.to_be_bytes());
            b[o + 0x10..o + 0x18].copy_from_slice(&e.count.to_be_bytes());
            b[o + 0x18..o + 0x20].copy_from_slice(&e.offset.to_be_bytes());
            b[o + 0x20..o + 0x28].copy_from_slice(&e.length.to_be_bytes());
        }
        b
    }
}

fn checksum_type(c: Option<u32>) -> u32 {
    if c.is_some() { CHECKSUM_TYPE_CRC32 } else { 0 }
}

fn checksum_bits(c: Option<u32>) -> u32 {
    if c.is_some() { CHECKSUM_BITS_CRC32 } else { 0 }
}

fn checksum_bytes(c: Option<u32>) -> [u8; 128] {
    let mut b = [0u8; 128];
    if let Some(c) = c {
        b[..4].copy_from_slice(&c.to_be_bytes());
    }
    b
}

fn is_zero(sector: &[u8]) -> bool {
    let (words, tail) = sector.as_chunks::<8>();
    words.iter().all(|w| u64::from_ne_bytes(*w) == 0) && tail.iter().all(|&b| b == 0)
}

/// Encode one data run with the format's codec. `None` means "store raw"
/// (UDRO). The caller falls back to raw when the result isn't smaller.
fn encode_chunk(
    format: UdifFormat,
    level: Option<u8>,
    plain: &[u8],
) -> Result<Option<(ChunkType, Vec<u8>)>> {
    #[cfg(not(any(
        feature = "dmg-write-zlib",
        feature = "dmg-write-bzip2",
        feature = "dmg-write-lzma"
    )))]
    let _ = level;
    Ok(match format {
        UdifFormat::Udro => None,
        UdifFormat::Udco => Some((ChunkType::Adc, super::codec::encode_adc(plain))),
        #[cfg(feature = "dmg-write-zlib")]
        UdifFormat::Udzo => {
            let mut cfg = compcol::zlib::EncoderConfig::default();
            if let Some(l) = level {
                cfg.level = l;
            }
            Some((
                ChunkType::Zlib,
                cc_encode::<compcol::zlib::Zlib>(plain, cfg)?,
            ))
        }
        #[cfg(feature = "dmg-write-bzip2")]
        UdifFormat::Udbz => {
            let mut cfg = compcol::bzip2::EncoderConfig::default();
            if let Some(l) = level {
                cfg.level = l;
            }
            Some((
                ChunkType::Bz2,
                cc_encode::<compcol::bzip2::Bzip2>(plain, cfg)?,
            ))
        }
        #[cfg(feature = "dmg-write-lzma")]
        UdifFormat::Ulmo => {
            let mut cfg = compcol::xz::EncoderConfig::default();
            if let Some(l) = level {
                cfg.level = l;
            }
            Some((ChunkType::Lzma, cc_encode::<compcol::xz::Xz>(plain, cfg)?))
        }
        // Formats whose codec is compiled out were refused by `validate`.
        #[allow(unreachable_patterns)]
        other => {
            other.check_writable()?;
            unreachable!("writable format without an encoder arm")
        }
    })
}

#[cfg(any(
    feature = "dmg-write-zlib",
    feature = "dmg-write-bzip2",
    feature = "dmg-write-lzma"
))]
fn cc_encode<A: compcol::Algorithm>(plain: &[u8], cfg: A::EncoderConfig) -> Result<Vec<u8>> {
    compcol::vec::compress_to_vec_with::<A>(plain, cfg).map_err(|e| {
        crate::Error::Io(std::io::Error::other(format!(
            "dmg: {} chunk encode failed: {e}",
            A::NAME
        )))
    })
}

/// Escape the five XML-significant characters for a `<string>` body.
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

/// The resource-fork plist, in the shape `hdiutil` writes for a
/// single-partition image.
fn build_plist(name: &str, mish: &[u8]) -> String {
    let name = xml_escape(name);
    let data = crate::base64::encode(mish);
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
         \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
         \t<key>resource-fork</key>\n\
         \t<dict>\n\
         \t\t<key>blkx</key>\n\
         \t\t<array>\n\
         \t\t\t<dict>\n\
         \t\t\t\t<key>Attributes</key>\n\
         \t\t\t\t<string>0x0050</string>\n\
         \t\t\t\t<key>CFName</key>\n\
         \t\t\t\t<string>{name}</string>\n\
         \t\t\t\t<key>Data</key>\n\
         \t\t\t\t<data>{data}</data>\n\
         \t\t\t\t<key>ID</key>\n\
         \t\t\t\t<string>0</string>\n\
         \t\t\t\t<key>Name</key>\n\
         \t\t\t\t<string>{name}</string>\n\
         \t\t\t</dict>\n\
         \t\t</array>\n\
         \t</dict>\n\
         </dict>\n\
         </plist>\n"
    )
}

/// Encode every sector of `src` into a UDIF image written to `out`.
///
/// `src.total_size()` must be a non-zero multiple of 512. The device is
/// read in chunk-sized pieces, so memory stays bounded by
/// [`UdifWriteOptions::chunk_sectors`]. Returns the sink (positioned after
/// the trailer) and a summary; see [`UdifWriter::finish`].
pub fn write_udif<W: Write + Seek>(
    src: &mut dyn BlockDevice,
    out: W,
    opts: &UdifWriteOptions,
) -> Result<(W, UdifSummary)> {
    let total = src.total_size();
    check_length(total)?;
    let mut w = UdifWriter::new(out, opts)?;
    let mut buf = vec![0u8; opts.chunk_sectors as usize * SECTOR];
    let mut off = 0u64;
    while off < total {
        let n = buf.len().min((total - off) as usize);
        src.read_at(off, &mut buf[..n])?;
        w.write_sectors(&buf[..n])?;
        off += n as u64;
    }
    w.finish()
}

/// Encode exactly `len` bytes read from `src` into a UDIF image written
/// to `out`. `len` must be a non-zero multiple of 512; a source that
/// ends early is an error (`UnexpectedEof`), and nothing past `len` is
/// read.
pub fn write_udif_from_reader<R: Read, W: Write + Seek>(
    mut src: R,
    len: u64,
    out: W,
    opts: &UdifWriteOptions,
) -> Result<(W, UdifSummary)> {
    check_length(len)?;
    let mut w = UdifWriter::new(out, opts)?;
    let mut buf = vec![0u8; opts.chunk_sectors as usize * SECTOR];
    let mut off = 0u64;
    while off < len {
        let n = buf.len().min((len - off) as usize);
        src.read_exact(&mut buf[..n])?;
        w.write_sectors(&buf[..n])?;
        off += n as u64;
    }
    w.finish()
}

fn check_length(len: u64) -> Result<()> {
    if len == 0 || !len.is_multiple_of(SECTOR as u64) {
        return Err(crate::Error::InvalidArgument(format!(
            "dmg: source length {len} is not a non-zero multiple of 512 bytes"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::DmgBackend;
    use std::io::Cursor;

    /// A small disk with every kind of region: leading zeros, text,
    /// noise, a long zero gap, a data run longer than one chunk, and a
    /// trailing lone data sector.
    fn sample_disk() -> Vec<u8> {
        let mut d = vec![0u8; 3 * SECTOR];
        let mut text = Vec::new();
        for i in 0..1500 {
            text.extend_from_slice(format!("line {i} of a compressible text\n").as_bytes());
        }
        d.extend_from_slice(&text);
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        for _ in 0..40_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            d.push(x as u8);
        }
        d.resize(d.len().next_multiple_of(SECTOR), 0x5A);
        d.extend_from_slice(&vec![0u8; 300 * SECTOR]);
        for i in 0..(70 * SECTOR) {
            d.push((i / 700) as u8 | 1);
        }
        d.extend_from_slice(&vec![0u8; 2 * SECTOR]);
        d.extend_from_slice(&[0xEE; SECTOR]);
        d
    }

    fn opts(format: UdifFormat) -> UdifWriteOptions {
        UdifWriteOptions {
            format,
            chunk_sectors: 32,
            segment_id: Some([7; 16]),
            ..Default::default()
        }
    }

    fn roundtrip(o: &UdifWriteOptions, disk: &[u8]) -> (Vec<u8>, UdifSummary) {
        let (cur, summary) = write_udif_from_reader(
            Cursor::new(disk),
            disk.len() as u64,
            Cursor::new(Vec::new()),
            o,
        )
        .unwrap();
        let img = cur.into_inner();
        assert_eq!(img.len() as u64, summary.bytes_written);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rt.dmg");
        std::fs::write(&path, &img).unwrap();
        let mut dmg = DmgBackend::open(&path).unwrap();
        assert_eq!(dmg.total_size(), disk.len() as u64);
        let mut back = vec![0u8; disk.len()];
        dmg.read_at(0, &mut back).unwrap();
        assert!(back == disk, "{} round trip differs", o.format.name());
        let t = dmg.trailer();
        assert_eq!(t.sector_count, summary.sector_count);
        assert_eq!(t.segment_id, [7; 16]);
        (img, summary)
    }

    fn all_writable() -> Vec<UdifFormat> {
        [
            UdifFormat::Udro,
            UdifFormat::Udco,
            UdifFormat::Udzo,
            UdifFormat::Udbz,
            UdifFormat::Ulmo,
        ]
        .into_iter()
        .filter(|f| f.writable())
        .collect()
    }

    #[test]
    fn every_writable_format_roundtrips() {
        let disk = sample_disk();
        for f in all_writable() {
            // Reading back needs the matching decoder; each write feature
            // implies it.
            let (_, s) = roundtrip(&opts(f), &disk);
            assert!(s.chunk_count > 4, "{}: expected several chunks", f.name());
            if f != UdifFormat::Udro {
                assert!(s.data_fork_length < disk.len() as u64 / 2, "{}", f.name());
            }
        }
    }

    #[test]
    fn checksums_match_hdiutil_definitions() {
        let disk = sample_disk();
        for zero_runs in [ZeroRunEncoding::ZeroFill, ZeroRunEncoding::Ignore] {
            let mut o = opts(UdifFormat::Udro);
            o.zero_runs = zero_runs;
            let (img, s) = roundtrip(&o, &disk);
            let t = KolyTrailer::decode(&img[img.len() - 512..]).unwrap();
            // Data fork CRC over the stored bytes.
            let fork = &img[..t.data_fork_length as usize];
            assert_eq!(s.data_fork_crc32, Some(crate::crc::crc32(fork)));
            assert_eq!(t.data_checksum_type, 2);
            assert_eq!(t.data_checksum[..4], crate::crc::crc32(fork).to_be_bytes());
            // Partition CRC: plaintext, minus "ignore" sectors.
            let expect = match zero_runs {
                ZeroRunEncoding::ZeroFill => crate::crc::crc32(&disk),
                ZeroRunEncoding::Ignore => {
                    let nz: Vec<u8> = disk
                        .chunks(SECTOR)
                        .filter(|s| !is_zero(s))
                        .flatten()
                        .copied()
                        .collect();
                    crate::crc::crc32(&nz)
                }
            };
            assert_eq!(s.partition_crc32, Some(expect));
            // Master CRC over the big-endian partition checksums.
            assert_eq!(
                t.master_checksum[..4],
                crate::crc::crc32(&expect.to_be_bytes()).to_be_bytes()
            );
        }
    }

    #[test]
    fn zero_sectors_are_never_compressed() {
        let mut disk = vec![0u8; 100 * SECTOR];
        disk[50 * SECTOR] = 1;
        let mut o = opts(UdifFormat::Udco);
        o.zero_runs = ZeroRunEncoding::Ignore;
        let (img, s) = roundtrip(&o, &disk);
        // zero(50) + data(1) + zero(49)
        assert_eq!(s.chunk_count, 3);
        // One stored sector of ADC payload at most.
        assert!(s.data_fork_length < 64, "{}", s.data_fork_length);
        let t = KolyTrailer::decode(&img[img.len() - 512..]).unwrap();
        let plist = std::str::from_utf8(
            &img[t.xml_offset as usize..(t.xml_offset + t.xml_length) as usize],
        )
        .unwrap();
        let raw = crate::base64::decode(
            &super::super::plist::extract_blkx_data_entries(plist).unwrap()[0],
        )
        .unwrap();
        let m = super::super::mish::decode_mish(&raw).unwrap();
        let kinds: Vec<ChunkType> = m.chunks.iter().map(|c| c.kind).collect();
        assert_eq!(
            kinds,
            [ChunkType::Ignored, ChunkType::Adc, ChunkType::Ignored]
        );
    }

    #[test]
    fn incompressible_chunks_are_stored_raw() {
        let mut x: u64 = 1;
        let disk: Vec<u8> = (0..16 * SECTOR)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect();
        for f in all_writable() {
            let (_, s) = roundtrip(&opts(f), &disk);
            assert_eq!(s.data_fork_length, disk.len() as u64, "{}", f.name());
        }
    }

    #[test]
    fn checksum_none_writes_type_zero() {
        let disk = sample_disk();
        let mut o = opts(UdifFormat::Udro);
        o.checksum = UdifChecksum::None;
        let (img, s) = roundtrip(&o, &disk);
        let t = KolyTrailer::decode(&img[img.len() - 512..]).unwrap();
        assert_eq!((t.data_checksum_type, t.master_checksum_type), (0, 0));
        assert_eq!(s.master_crc32, None);
    }

    #[test]
    fn nonzero_start_offset_is_recorded() {
        let disk = sample_disk();
        let mut cur = Cursor::new(vec![0xCCu8; 1000]);
        cur.seek(std::io::SeekFrom::End(0)).unwrap();
        let (cur, _) =
            write_udif_from_reader(&disk[..], disk.len() as u64, cur, &opts(UdifFormat::Udco))
                .unwrap();
        let img = cur.into_inner();
        let t = KolyTrailer::decode(&img[img.len() - 512..]).unwrap();
        assert_eq!(t.data_fork_offset, 1000);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("off.dmg");
        std::fs::write(&path, &img).unwrap();
        let mut dmg = DmgBackend::open(&path).unwrap();
        let mut back = vec![0u8; disk.len()];
        dmg.read_at(0, &mut back).unwrap();
        assert!(back == disk);
    }

    #[test]
    fn block_device_source() {
        let disk = sample_disk();
        let mut dev = crate::block::MemoryBackend::new(disk.len() as u64);
        dev.write_at(0, &disk).unwrap();
        let (cur, s) =
            write_udif(&mut dev, Cursor::new(Vec::new()), &opts(UdifFormat::Udco)).unwrap();
        assert_eq!(s.sector_count, (disk.len() / SECTOR) as u64);
        assert!(!cur.into_inner().is_empty());
    }

    #[test]
    fn options_are_checked() {
        let bad = |f: &dyn Fn(&mut UdifWriteOptions)| {
            let mut o = UdifWriteOptions {
                format: UdifFormat::Udco,
                ..Default::default()
            };
            f(&mut o);
            o.validate().unwrap_err()
        };
        assert!(matches!(
            bad(&|o| o.chunk_sectors = 0),
            crate::Error::InvalidArgument(_)
        ));
        assert!(matches!(
            bad(&|o| o.chunk_sectors = MAX_WRITE_CHUNK_SECTORS + 1),
            crate::Error::InvalidArgument(_)
        ));
        assert!(matches!(
            bad(&|o| o.level = Some(3)),
            crate::Error::InvalidArgument(_)
        ));
        assert!(matches!(
            bad(&|o| o.partition_name = String::new()),
            crate::Error::InvalidArgument(_)
        ));
        assert!(matches!(
            bad(&|o| o.format = UdifFormat::Ulfo),
            crate::Error::Unsupported(_)
        ));
        if UdifFormat::Udzo.writable() {
            let mut o = UdifWriteOptions {
                level: Some(10),
                ..Default::default()
            };
            assert!(o.validate().is_err());
            o.level = Some(9);
            o.validate().unwrap();
        } else {
            assert!(matches!(
                UdifWriteOptions::default().validate(),
                Err(crate::Error::Unsupported(_))
            ));
        }
        // Geometry of the source.
        let e = write_udif_from_reader(
            &[0u8; 100][..],
            100,
            Cursor::new(Vec::new()),
            &opts(UdifFormat::Udro),
        );
        assert!(matches!(e, Err(crate::Error::InvalidArgument(_))));
        let e =
            write_udif_from_reader(&[][..], 0, Cursor::new(Vec::new()), &opts(UdifFormat::Udro));
        assert!(matches!(e, Err(crate::Error::InvalidArgument(_))));
        let mut w = UdifWriter::new(Cursor::new(Vec::new()), &opts(UdifFormat::Udro)).unwrap();
        assert!(w.write_sectors(&[1u8; 513]).is_err());
        // A rejected argument writes nothing, so the writer stays usable.
        w.write_sectors(&[1u8; 512]).unwrap();
        w.finish().unwrap();
        // A sink failure, by contrast, poisons it.
        let sink = FailingSink {
            inner: Cursor::new(Vec::new()),
            budget: 0,
        };
        let mut o = opts(UdifFormat::Udro);
        o.chunk_sectors = 1;
        let mut w = UdifWriter::new(sink, &o).unwrap();
        assert!(matches!(
            w.write_sectors(&[1u8; 512]),
            Err(crate::Error::Io(_))
        ));
        assert!(w.write_sectors(&[1u8; 512]).is_err());
        assert!(w.finish().is_err());
    }

    #[test]
    fn short_source_is_an_error() {
        let e = write_udif_from_reader(
            &[1u8; 1024][..],
            4096,
            Cursor::new(Vec::new()),
            &opts(UdifFormat::Udro),
        );
        assert!(
            matches!(e, Err(crate::Error::Io(ref io)) if io.kind() == std::io::ErrorKind::UnexpectedEof)
        );
    }

    /// A sink that fails once `budget` bytes have been accepted.
    #[derive(Debug)]
    struct FailingSink {
        inner: Cursor<Vec<u8>>,
        budget: usize,
    }
    impl Write for FailingSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if self.inner.get_ref().len() + buf.len() > self.budget {
                return Err(std::io::Error::other("disk full"));
            }
            self.inner.write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl Seek for FailingSink {
        fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
            self.inner.seek(pos)
        }
    }

    #[test]
    fn sink_errors_propagate_at_every_stage() {
        let disk = sample_disk();
        // Full size of a successful image, to place failures in the data
        // fork, the plist and the trailer.
        let (cur, s) = write_udif_from_reader(
            &disk[..],
            disk.len() as u64,
            Cursor::new(Vec::new()),
            &opts(UdifFormat::Udro),
        )
        .unwrap();
        let total = cur.into_inner().len();
        for budget in [
            0,
            1000,
            s.data_fork_length as usize + 10,
            total - 100,
            total - 1,
        ] {
            let sink = FailingSink {
                inner: Cursor::new(Vec::new()),
                budget,
            };
            let e =
                write_udif_from_reader(&disk[..], disk.len() as u64, sink, &opts(UdifFormat::Udro))
                    .unwrap_err();
            assert!(matches!(e, crate::Error::Io(_)), "budget {budget}: {e}");
        }
    }

    #[test]
    fn source_errors_propagate() {
        struct FailingRead(usize);
        impl Read for FailingRead {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.0 == 0 {
                    return Err(std::io::Error::other("read failed"));
                }
                let n = buf.len().min(self.0);
                buf[..n].fill(0x11);
                self.0 -= n;
                Ok(n)
            }
        }
        let e = write_udif_from_reader(
            FailingRead(64 * SECTOR),
            1024 * SECTOR as u64,
            Cursor::new(Vec::new()),
            &opts(UdifFormat::Udro),
        )
        .unwrap_err();
        assert!(matches!(e, crate::Error::Io(ref io) if io.to_string() == "read failed"));
    }

    #[test]
    fn partition_name_is_escaped() {
        let disk = vec![1u8; 4 * SECTOR];
        let mut o = opts(UdifFormat::Udro);
        o.partition_name = "a <b> & 'c'".into();
        let (img, _) = roundtrip(&o, &disk);
        let s = String::from_utf8_lossy(&img);
        assert!(s.contains("<string>a &lt;b&gt; &amp; &apos;c&apos;</string>"));
    }

    #[test]
    fn format_names_roundtrip() {
        for f in [
            UdifFormat::Udro,
            UdifFormat::Udco,
            UdifFormat::Udzo,
            UdifFormat::Udbz,
            UdifFormat::Ulfo,
            UdifFormat::Ulmo,
        ] {
            assert_eq!(UdifFormat::from_name(&f.name().to_lowercase()), Some(f));
        }
        assert_eq!(UdifFormat::from_name("UDRW"), None);
    }
}
