//! In-memory inspection and conversion — the byte-in / byte-out surface.
//!
//! Everything here operates on `Vec<u8>` and [`MemoryBackend`] rather than
//! host paths, so it works where there is no filesystem at all. That is what
//! powers the browser/WebAssembly build (`crates/fstool-wasm`): an uploaded
//! file is probed, browsed, individual files extracted, and the whole thing
//! converted to another format entirely in RAM, then handed back for
//! download.
//!
//! The three entry points:
//!
//! - [`probe`] — cheap first look at a blob: outer compression, partition
//!   table (with each partition's filesystem), or the top-level filesystem.
//! - [`MemImage`] — an opened image/archive you can `list`, `read_file`, and
//!   `convert`. Reuses the exact same device-oriented walkers
//!   ([`crate::repack::walk_anyfs`]) and filesystem writers
//!   ([`crate::fs::FilesystemFactory`]) as the CLI — the only difference is
//!   the backing store is a [`MemoryBackend`].
//! - [`supported_targets`] — the list of conversion targets the UI offers.

use std::io::Read;

use crate::block::{BlockDevice, MemoryBackend};
use crate::compression::{self, Algo};
use crate::fs::{EntryKind, Filesystem, FilesystemFactory};
use crate::inspect::{self, AnyFs};
use crate::repack::{FsSink, TarStreamSink, walk_anyfs};
use crate::{Error, Result};

/// Block size used to seed the ext build plan when sizing a destination.
const PLAN_BLOCK_SIZE: u32 = 4096;

// ======================================================================
// Probe — first look at an uploaded blob.
// ======================================================================

/// What a first pass over a blob revealed. Serializable so the wasm layer
/// can hand it to JavaScript as JSON.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
pub struct ProbeReport {
    /// Outer compression codec, if the blob is a single compressed stream
    /// (`"gzip"`, `"zstd"`, …). The inner content is what everything else
    /// in this report describes.
    pub compression: Option<String>,
    /// Partition table, when the blob is a whole-disk image.
    pub partition_table: Option<PartitionTableReport>,
    /// Top-level filesystem / archive kind, when the blob is not a
    /// partitioned disk (a bare FS, a tar/zip/…, a container).
    pub filesystem: Option<String>,
    /// Uncompressed size in bytes of the content being described.
    pub content_size: u64,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
pub struct PartitionTableReport {
    /// `"gpt"`, `"mbr"`, or `"apm"`.
    pub label: String,
    pub partitions: Vec<PartitionReport>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
pub struct PartitionReport {
    /// 1-indexed partition number, matching `disk.img:N` and `sgdisk -p`.
    pub index: usize,
    pub name: Option<String>,
    /// Semantic partition kind (`"linux"`, `"esp"`, …).
    pub kind: String,
    /// Byte offset of the partition within the disk.
    pub start: u64,
    /// Partition length in bytes.
    pub size: u64,
    /// Filesystem detected inside the partition, if fstool recognises one.
    pub fs: Option<String>,
}

/// Probe `bytes` without fully opening anything expensive. Detects outer
/// compression, then either a partition table (listing each partition's
/// filesystem) or the top-level filesystem/archive kind.
pub fn probe(bytes: &[u8]) -> Result<ProbeReport> {
    let (raw, compression) = maybe_decompress(bytes)?;
    let content_size = raw.len() as u64;
    let mut dev = MemoryBackend::from_bytes(raw);

    if let Some(table) = inspect::detect_partition_table(&mut dev)? {
        let label = table.label().to_string();
        let mut partitions = Vec::new();
        // Snapshot partition geometry first so we can drop the borrow on
        // `table` before copying slices out of `dev`.
        let geom: Vec<(usize, Option<String>, String, u64, u64)> = table
            .partitions()
            .iter()
            .enumerate()
            .map(|(i, p)| {
                (
                    i + 1,
                    p.name.clone(),
                    format!("{:?}", p.kind).to_ascii_lowercase(),
                    p.start_lba.saturating_mul(512),
                    p.size_lba.saturating_mul(512),
                )
            })
            .collect();
        for (index, name, kind, start, size) in geom {
            let fs = partition_fs_kind(&mut dev, start, size);
            partitions.push(PartitionReport {
                index,
                name,
                kind,
                start,
                size,
                fs,
            });
        }
        return Ok(ProbeReport {
            compression,
            partition_table: Some(PartitionTableReport { label, partitions }),
            filesystem: None,
            content_size,
        });
    }

    let filesystem = match AnyFs::open(&mut dev) {
        Ok(fs) => Some(fs.kind_string().to_string()),
        Err(_) => None,
    };
    Ok(ProbeReport {
        compression,
        partition_table: None,
        filesystem,
        content_size,
    })
}

/// Best-effort filesystem kind for the partition at `[start, start+size)`
/// of `dev`. Returns `None` if the slice is out of range or carries no
/// recognised filesystem.
fn partition_fs_kind(dev: &mut MemoryBackend, start: u64, size: u64) -> Option<String> {
    let end = start.checked_add(size)?;
    let buf = dev.as_slice();
    if end > buf.len() as u64 || size == 0 {
        return None;
    }
    let slice = buf[start as usize..end as usize].to_vec();
    let mut sub = MemoryBackend::from_bytes(slice);
    AnyFs::open(&mut sub)
        .ok()
        .map(|fs| fs.kind_string().to_string())
}

// ======================================================================
// MemImage — an opened image/archive you can browse and convert.
// ======================================================================

/// An image or archive held entirely in memory, opened as a filesystem.
///
/// Construct with [`open`](Self::open) (or [`open_partition`] to pick a
/// partition of a whole-disk image). Then `list` / `read_file` to browse,
/// or `convert` to transcode.
///
/// [`open_partition`]: Self::open_partition
pub struct MemImage {
    dev: MemoryBackend,
    fs: AnyFs,
    kind: &'static str,
}

impl MemImage {
    /// Open `bytes` as whatever it contains. Transparently decompresses an
    /// outer codec (`.gz` / `.zst` / …). For a whole-disk image the first
    /// partition that carries a recognised filesystem is opened; use
    /// [`open_partition`](Self::open_partition) to choose another.
    pub fn open(bytes: Vec<u8>) -> Result<Self> {
        Self::open_partition(bytes, None)
    }

    /// Like [`open`](Self::open) but, for a partitioned disk, opens the
    /// given 1-indexed partition. `part` is ignored for a bare filesystem
    /// or archive.
    pub fn open_partition(bytes: Vec<u8>, part: Option<usize>) -> Result<Self> {
        let (raw, _compression) = maybe_decompress(&bytes)?;
        drop(bytes);
        let mut probe_dev = MemoryBackend::from_bytes(raw);

        if let Some(table) = inspect::detect_partition_table(&mut probe_dev)? {
            // Collect candidate byte ranges, then pick one that opens.
            let ranges: Vec<(usize, u64, u64)> = table
                .partitions()
                .iter()
                .enumerate()
                .map(|(i, p)| {
                    (
                        i + 1,
                        p.start_lba.saturating_mul(512),
                        p.size_lba.saturating_mul(512),
                    )
                })
                .collect();
            let buf = probe_dev.into_bytes();

            let candidates: Vec<(usize, u64, u64)> = match part {
                Some(want) => ranges.into_iter().filter(|(i, ..)| *i == want).collect(),
                None => ranges,
            };
            if candidates.is_empty() {
                return Err(Error::InvalidArgument(format!(
                    "partition {} not found",
                    part.unwrap_or(0)
                )));
            }
            let mut last_err = None;
            for (_idx, start, size) in candidates {
                let end = match start.checked_add(size) {
                    Some(e) if e <= buf.len() as u64 && size > 0 => e,
                    _ => continue,
                };
                let slice = buf[start as usize..end as usize].to_vec();
                let mut dev = MemoryBackend::from_bytes(slice);
                match AnyFs::open(&mut dev) {
                    Ok(fs) => {
                        let kind = fs.kind_string();
                        return Ok(Self { dev, fs, kind });
                    }
                    Err(e) => last_err = Some(e),
                }
            }
            return Err(last_err.unwrap_or_else(|| {
                Error::Unsupported("no partition carried a recognised filesystem".into())
            }));
        }

        let mut dev = probe_dev;
        let fs = AnyFs::open(&mut dev)?;
        let kind = fs.kind_string();
        Ok(Self { dev, fs, kind })
    }

    /// The filesystem kind (`"ext4"`, `"tar"`, `"iso9660"`, …).
    pub fn kind(&self) -> &'static str {
        self.kind
    }

    /// List the directory at `path` (`"/"` for the root).
    pub fn list(&mut self, path: &str) -> Result<Vec<EntryInfo>> {
        let entries = self.fs.list(&mut self.dev, path)?;
        Ok(entries
            .into_iter()
            .map(|e| EntryInfo {
                name: e.name,
                kind: entry_kind_str(e.kind).to_string(),
                size: e.size,
            })
            .collect())
    }

    /// Read a whole regular file out of the image into a `Vec<u8>`.
    pub fn read_file(&mut self, path: &str) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.fs.copy_file_to(&mut self.dev, path, &mut out)?;
        Ok(out)
    }

    /// Read a symlink's target.
    pub fn read_symlink(&mut self, path: &str) -> Result<String> {
        self.fs.read_symlink(&mut self.dev, path)
    }

    /// Convert the whole image/archive into `target` format, returning the
    /// finished bytes. `target` is a format id from [`supported_targets`]
    /// (e.g. `"tar"`, `"tar.gz"`, `"ext4"`, `"zip"`, `"squashfs"`).
    ///
    /// The conversion is *lossy-tolerant*: an entry the destination can't
    /// represent (a symlink into FAT, a device node into zip, …) is dropped
    /// with a `log::warn!` rather than failing the whole convert.
    pub fn convert(&mut self, target: &str) -> Result<Vec<u8>> {
        let t = target.trim().to_ascii_lowercase();

        // tar / tar.<codec> — streaming archive, no pre-sized device.
        if t == "tar" {
            return self.convert_tar(None);
        }
        if let Some(codec_name) = t.strip_prefix("tar.") {
            let algo = tar_codec(codec_name).ok_or_else(|| {
                Error::InvalidArgument(format!("unknown tar codec {codec_name:?}"))
            })?;
            return self.convert_tar(Some(algo));
        }

        match t.as_str() {
            "ext2" | "ext3" | "ext4" => self.convert_ext(&t),
            "fat32" | "vfat" => self.convert_fat32(),
            "hfs+" | "hfsplus" => {
                let sz = self.geometry_size()?;
                self.build_generic::<crate::fs::hfs_plus::HfsPlus>(
                    &crate::fs::hfs_plus::FormatOpts::default(),
                    sz,
                )
            }
            "hfs" => {
                let sz = self.geometry_size()?;
                self.build_generic::<crate::fs::hfs::Hfs>(
                    &crate::fs::hfs::HfsFormatOpts::default(),
                    sz,
                )
            }
            "ntfs" => {
                let sz = self.geometry_size()?;
                self.build_generic::<crate::fs::ntfs::Ntfs>(
                    &crate::fs::ntfs::format::FormatOpts::default(),
                    sz,
                )
            }
            "f2fs" => {
                // f2fs needs enough main-area segments to lay out its 6
                // cursegs; below ~50 MiB its flush indexes past a 1-segment
                // main area and panics. Floor generously.
                // TODO(sizing): size fixed-geometry targets via each FS's
                // `FsSizePlan` for an exact content fit instead of heuristics.
                let sz = self.geometry_size()?.max(64 << 20);
                self.build_generic::<crate::fs::f2fs::F2fs>(
                    &crate::fs::f2fs::FormatOpts::default(),
                    sz,
                )
            }
            "xfs" => {
                let sz = self.geometry_size()?;
                self.build_generic::<crate::fs::xfs::Xfs>(
                    &crate::fs::xfs::format::FormatOpts::default(),
                    sz,
                )
            }
            "affs" | "ofs" | "ffs" => {
                let sz = self.geometry_size()?;
                self.build_generic::<crate::fs::affs::Affs>(
                    &crate::fs::affs::AffsFormatOpts::default(),
                    sz,
                )
            }
            "littlefs" | "lfs" => {
                // littlefs reserves nothing up front, so a content-fit size
                // from its own size plan is enough; keep a floor so tiny
                // sources still leave room to edit the result afterwards.
                let sz = self.geometry_size()?;
                self.build_generic::<crate::fs::littlefs::LittleFs>(
                    &crate::fs::littlefs::LittleFsFormatOpts::default(),
                    sz,
                )
            }
            "apfs" => {
                let sz = self.geometry_size()?;
                self.build_generic::<crate::fs::apfs::Apfs>(
                    &crate::fs::apfs::ApfsFormatOpts::default(),
                    sz,
                )
            }
            "squashfs" => {
                let sz = self.geometry_size()?;
                self.build_generic::<crate::fs::squashfs::Squashfs>(
                    &crate::fs::squashfs::FormatOpts::default(),
                    sz,
                )
            }
            "iso" | "iso9660" => {
                let opts = crate::fs::iso9660::FormatOpts {
                    volume_id: "FSTOOL".into(),
                    application_id: "fstool".into(),
                    ..crate::fs::iso9660::FormatOpts::default()
                };
                let sz = self.archive_size(32 << 20)?;
                self.build_generic::<crate::fs::iso9660::Iso9660>(&opts, sz)
            }
            "grf" => {
                let sz = self.archive_size(64 << 10)?;
                self.build_generic::<crate::fs::grf::Grf>(
                    &crate::fs::grf::FormatOpts::default(),
                    sz,
                )
            }
            "zip" => {
                let sz = self.archive_size(16 << 20)?;
                self.build_generic::<crate::fs::archive::zip::ZipFs>(
                    &crate::fs::archive::zip::ZipFormatOpts::default(),
                    sz,
                )
            }
            "cpio" => {
                let sz = self.archive_size(16 << 20)?;
                self.build_generic::<crate::fs::archive::cpio::CpioFs>(
                    &crate::fs::archive::cpio::CpioFormatOpts,
                    sz,
                )
            }
            "ar" => {
                let sz = self.archive_size(16 << 20)?;
                self.build_generic::<crate::fs::archive::ar::ArFs>(
                    &crate::fs::archive::ar::ArFormatOpts,
                    sz,
                )
            }
            other => Err(Error::InvalidArgument(format!(
                "unknown conversion target {other:?}"
            ))),
        }
    }

    // -- convert helpers ------------------------------------------------

    fn convert_tar(&mut self, codec: Option<Algo>) -> Result<Vec<u8>> {
        use crate::repack::RepackSink;
        let out = MemWriter::default();
        let handle = out.clone();
        let inner: Box<dyn std::io::Write> = match codec {
            Some(algo) => compression::make_writer(algo, Box::new(out))?,
            None => Box::new(out),
        };
        let mut sink = TarStreamSink::new(inner);
        walk_anyfs(&mut self.fs, &mut self.dev, &mut sink)?;
        sink.finish()?;
        drop(sink);
        Ok(handle.into_bytes())
    }

    fn convert_ext(&mut self, flavour: &str) -> Result<Vec<u8>> {
        use crate::fs::ext::{Ext, FsKind};
        let kind = match flavour {
            "ext2" => FsKind::Ext2,
            "ext3" => FsKind::Ext3,
            _ => FsKind::Ext4,
        };
        let mut opts = crate::analyze::analyze_fs(&mut self.fs, &mut self.dev, PLAN_BLOCK_SIZE)?
            .ext_format_opts(kind);
        // The source reader emits zeros over holes and the ext writer
        // re-sparsifies all-zero blocks; a fresh MemoryBackend is already
        // zero, so the formatter can skip its upfront zero pass.
        opts.sparse = true;
        opts.prezeroed = true;
        let dst_size = opts.blocks_count as u64 * opts.block_size as u64;
        let mut dst = MemoryBackend::new(dst_size);
        let mut ext = Ext::format_with(&mut dst, &opts)?;
        {
            let mut sink = FsSink::new(&mut ext, &mut dst).lossy();
            walk_anyfs(&mut self.fs, &mut self.dev, &mut sink)?;
        }
        ext.flush(&mut dst)?;
        Ok(dst.into_bytes())
    }

    fn convert_fat32(&mut self) -> Result<Vec<u8>> {
        use crate::fs::fat::{Fat32, FatFormatOpts};
        let dst_size = crate::analyze::analyze_fs(&mut self.fs, &mut self.dev, PLAN_BLOCK_SIZE)?
            .recommended_size("fat32")
            .ok_or_else(|| Error::Unsupported("fat32 sizing unavailable".into()))?;
        let total_sectors: u32 = (dst_size / 512)
            .try_into()
            .map_err(|_| Error::InvalidArgument("fat32 image too large for the browser".into()))?;
        let opts = FatFormatOpts {
            total_sectors,
            volume_id: 0,
            volume_label: *b"FSTOOL     ",
            ..Default::default()
        };
        let mut dst = MemoryBackend::new(dst_size);
        let mut fat = Fat32::format(&mut dst, &opts)?;
        {
            let mut sink = FsSink::new(&mut fat, &mut dst).lossy();
            walk_anyfs(&mut self.fs, &mut self.dev, &mut sink)?;
        }
        fat.flush(&mut dst)?;
        Ok(dst.into_bytes())
    }

    /// Generic builder for any [`FilesystemFactory`] whose geometry comes
    /// from the destination device size. The device is pre-grown to
    /// `dst_size` (so the formatter sees room), but stays growable so a
    /// streaming writer can exceed it; the result is truncated to the FS's
    /// reported `image_len`.
    fn build_generic<F: FilesystemFactory>(
        &mut self,
        opts: &F::FormatOpts,
        dst_size: u64,
    ) -> Result<Vec<u8>> {
        let mut dst = MemoryBackend::growable();
        dst.zero_range(0, dst_size)?;
        let mut fs = F::format(&mut dst, opts)?;
        {
            let mut sink = FsSink::new(&mut fs, &mut dst).lossy();
            walk_anyfs(&mut self.fs, &mut self.dev, &mut sink)?;
        }
        fs.flush(&mut dst)?;
        let image_len = Filesystem::image_len(&fs);
        drop(fs);
        let mut bytes = dst.into_bytes();
        if let Some(n) = image_len {
            bytes.truncate(n as usize);
        }
        Ok(bytes)
    }

    /// Destination size for a fixed-geometry filesystem whose writer takes
    /// its layout from the device size (xfs / hfs+ / ntfs / f2fs / apfs /
    /// affs). Generous: at least the source image size, and always enough
    /// for the smallest of these formats.
    fn geometry_size(&mut self) -> Result<u64> {
        let src_total = self.dev.total_size();
        let tfb = self.total_file_bytes()?;
        let want = src_total
            .max(tfb.saturating_mul(2).saturating_add(16 << 20))
            .max(16 << 20);
        Ok(round_up(want, 512))
    }

    /// Destination size for a streaming archive writer: file bytes plus a
    /// fixed `headroom` for headers / descriptors. The buffer is truncated
    /// to the real length afterwards, so over-provisioning only costs
    /// transient RAM.
    fn archive_size(&mut self, headroom: u64) -> Result<u64> {
        let tfb = self.total_file_bytes()?;
        Ok(round_up(tfb.saturating_add(headroom), 512))
    }

    fn total_file_bytes(&mut self) -> Result<u64> {
        Ok(
            crate::analyze::analyze_fs(&mut self.fs, &mut self.dev, PLAN_BLOCK_SIZE)?
                .total_file_bytes,
        )
    }
}

/// One entry in a directory listing.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
pub struct EntryInfo {
    pub name: String,
    /// `"file"`, `"dir"`, `"symlink"`, `"char"`, `"block"`, `"fifo"`,
    /// `"socket"`, or `"unknown"`.
    pub kind: String,
    pub size: u64,
}

// ======================================================================
// Supported conversion targets.
// ======================================================================

/// A conversion target offered to the UI.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
pub struct TargetInfo {
    /// Format id passed to [`MemImage::convert`].
    pub id: &'static str,
    /// Human label.
    pub label: &'static str,
    /// Suggested output file extension (no leading dot).
    pub ext: &'static str,
    /// True for streaming archive/container outputs; false for
    /// fixed-geometry block filesystem images.
    pub streaming: bool,
}

/// The conversion targets the UI can offer. Every id is accepted by
/// [`MemImage::convert`]. Availability of the compressed-tar variants
/// tracks the codec Cargo features that are compiled in.
pub fn supported_targets() -> Vec<TargetInfo> {
    let mut v = vec![TargetInfo {
        id: "tar",
        label: "tar",
        ext: "tar",
        streaming: true,
    }];
    for (id, label, ext, algo) in [
        ("tar.gz", "tar + gzip", "tar.gz", Algo::Gzip),
        ("tar.xz", "tar + xz", "tar.xz", Algo::Xz),
        ("tar.zst", "tar + zstd", "tar.zst", Algo::Zstd),
        ("tar.lz4", "tar + lz4", "tar.lz4", Algo::Lz4),
    ] {
        if algo.enabled() {
            v.push(TargetInfo {
                id,
                label,
                ext,
                streaming: true,
            });
        }
    }
    v.extend([
        TargetInfo {
            id: "zip",
            label: "zip",
            ext: "zip",
            streaming: true,
        },
        TargetInfo {
            id: "cpio",
            label: "cpio (newc)",
            ext: "cpio",
            streaming: true,
        },
        TargetInfo {
            id: "ar",
            label: "ar",
            ext: "a",
            streaming: true,
        },
        TargetInfo {
            id: "ext4",
            label: "ext4",
            ext: "img",
            streaming: false,
        },
        TargetInfo {
            id: "ext3",
            label: "ext3",
            ext: "img",
            streaming: false,
        },
        TargetInfo {
            id: "ext2",
            label: "ext2",
            ext: "img",
            streaming: false,
        },
        TargetInfo {
            id: "fat32",
            label: "FAT32",
            ext: "img",
            streaming: false,
        },
        TargetInfo {
            id: "xfs",
            label: "XFS",
            ext: "img",
            streaming: false,
        },
        TargetInfo {
            id: "hfs+",
            label: "HFS+",
            ext: "img",
            streaming: false,
        },
        TargetInfo {
            id: "hfs",
            label: "HFS",
            ext: "img",
            streaming: false,
        },
        TargetInfo {
            id: "ntfs",
            label: "NTFS",
            ext: "img",
            streaming: false,
        },
        TargetInfo {
            id: "f2fs",
            label: "F2FS",
            ext: "img",
            streaming: false,
        },
        TargetInfo {
            id: "apfs",
            label: "APFS",
            ext: "img",
            streaming: false,
        },
        TargetInfo {
            id: "affs",
            label: "Amiga FFS",
            ext: "adf",
            streaming: false,
        },
        TargetInfo {
            id: "littlefs",
            label: "littlefs",
            ext: "img",
            streaming: false,
        },
        TargetInfo {
            id: "squashfs",
            label: "SquashFS",
            ext: "sqsh",
            streaming: true,
        },
        TargetInfo {
            id: "iso",
            label: "ISO 9660",
            ext: "iso",
            streaming: true,
        },
        TargetInfo {
            id: "grf",
            label: "GRF",
            ext: "grf",
            streaming: true,
        },
    ]);
    v
}

// ======================================================================
// Helpers.
// ======================================================================

/// Decompress a single outer compression layer if `bytes` is one. Returns
/// the (possibly unchanged) content and the codec name that was stripped.
fn maybe_decompress(bytes: &[u8]) -> Result<(Vec<u8>, Option<String>)> {
    let prefix_len = bytes.len().min(512);
    match compression::detect_magic(&bytes[..prefix_len]) {
        Some(algo) if algo.enabled() => {
            let mut out = Vec::new();
            let mut r = compression::make_reader(algo, bytes)?;
            r.read_to_end(&mut out)?;
            Ok((out, Some(algo.name().to_string())))
        }
        // Detected a codec that isn't compiled in, or nothing recognised —
        // treat the bytes as the content itself.
        _ => Ok((bytes.to_vec(), None)),
    }
}

pub(crate) fn entry_kind_str(k: EntryKind) -> &'static str {
    match k {
        EntryKind::Regular => "file",
        EntryKind::Dir => "dir",
        EntryKind::Symlink => "symlink",
        EntryKind::Char => "char",
        EntryKind::Block => "block",
        EntryKind::Fifo => "fifo",
        EntryKind::Socket => "socket",
        EntryKind::Unknown => "unknown",
    }
}

fn tar_codec(name: &str) -> Option<Algo> {
    let algo = match name {
        "gz" | "gzip" => Algo::Gzip,
        "xz" => Algo::Xz,
        "zst" | "zstd" => Algo::Zstd,
        "lz4" => Algo::Lz4,
        "lzma" => Algo::Lzma,
        "lzo" => Algo::Lzo,
        _ => return None,
    };
    algo.enabled().then_some(algo)
}

fn round_up(v: u64, to: u64) -> u64 {
    v.div_ceil(to).saturating_mul(to)
}

/// A `Write` sink that accumulates into a shared `Vec<u8>`, cloneable so a
/// codec wrapper can own the writer while we keep a handle to recover the
/// bytes. Single-threaded (wasm/CLI); the `Rc`/`RefCell` never crosses a
/// thread boundary.
#[derive(Clone, Default)]
struct MemWriter(std::rc::Rc<std::cell::RefCell<Vec<u8>>>);

impl MemWriter {
    fn into_bytes(self) -> Vec<u8> {
        // The tar sink + any codec writer have been dropped by now, so this
        // is the sole strong reference; unwrap back to the owned Vec.
        match std::rc::Rc::try_unwrap(self.0) {
            Ok(cell) => cell.into_inner(),
            Err(rc) => rc.borrow().clone(),
        }
    }
}

impl std::io::Write for MemWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repack::RepackSink;

    /// Build a small in-memory tar archive to use as a conversion source,
    /// without depending on any external fixture.
    fn tar_fixture() -> Vec<u8> {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("readme.txt"), b"hello from fstool").unwrap();
        std::fs::create_dir(tmp.path().join("sub")).unwrap();
        std::fs::write(tmp.path().join("sub/blob.bin"), vec![0x5au8; 5000]).unwrap();

        let src = crate::repack::Source::HostDir(tmp.path().to_path_buf());
        let mut dev = MemoryBackend::growable();
        let mut ram = AnyFs::new_ramfs_from(&mut dev, &src).unwrap();

        let handle = MemWriter::default();
        let mut sink = TarStreamSink::new(Box::new(handle.clone()));
        walk_anyfs(&mut ram, &mut dev, &mut sink).unwrap();
        sink.finish().unwrap();
        drop(sink);
        handle.into_bytes()
    }

    #[test]
    fn probe_and_browse_tar() {
        let tar = tar_fixture();
        let report = probe(&tar).unwrap();
        assert_eq!(report.filesystem.as_deref(), Some("tar"));
        assert!(report.partition_table.is_none());

        let mut img = MemImage::open(tar).unwrap();
        assert_eq!(img.kind(), "tar");
        let root = img.list("/").unwrap();
        assert!(
            root.iter()
                .any(|e| e.name == "readme.txt" && e.kind == "file")
        );
        assert!(root.iter().any(|e| e.name == "sub" && e.kind == "dir"));

        let body = img.read_file("/readme.txt").unwrap();
        assert_eq!(body, b"hello from fstool");
    }

    #[test]
    fn convert_tar_to_zip_ext4_squashfs_roundtrips() {
        for target in ["zip", "ext4", "squashfs", "cpio", "tar"] {
            let mut img = MemImage::open(tar_fixture()).unwrap();
            let out = img
                .convert(target)
                .unwrap_or_else(|e| panic!("convert to {target} failed: {e}"));
            assert!(!out.is_empty(), "{target} produced empty output");

            let mut re = MemImage::open(out)
                .unwrap_or_else(|e| panic!("re-open {target} output failed: {e}"));
            let names: Vec<_> = re.list("/").unwrap().into_iter().map(|e| e.name).collect();
            assert!(
                names.iter().any(|n| n == "readme.txt"),
                "{target} lost readme.txt; got {names:?}"
            );
        }
    }

    #[test]
    fn convert_compressed_tar_roundtrips() {
        // A gzip-compressed source is transparently decompressed on open.
        let tar = tar_fixture();
        let gz = compression::compress(Algo::Gzip, &tar).unwrap();
        let report = probe(&gz).unwrap();
        assert_eq!(report.compression.as_deref(), Some("gzip"));
        assert_eq!(report.filesystem.as_deref(), Some("tar"));

        let mut img = MemImage::open(gz).unwrap();
        assert_eq!(img.read_file("/readme.txt").unwrap(), b"hello from fstool");
    }

    #[test]
    fn supported_targets_nonempty_and_valid() {
        let targets = supported_targets();
        assert!(targets.iter().any(|t| t.id == "tar"));
        assert!(targets.iter().any(|t| t.id == "ext4"));
        // Every advertised streaming/tar target should at least be a known id.
        for t in &targets {
            assert!(!t.id.is_empty() && !t.ext.is_empty());
        }
    }
}
